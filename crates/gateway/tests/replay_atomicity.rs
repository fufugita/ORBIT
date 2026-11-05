use orbit_adapter::ProviderAdapter;
use orbit_adapter::adapters::{identity, text_capabilities};
use orbit_adapter::conformance::canonical_request;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::error::AdapterError;
use orbit_adapter::types::{
    AdapterIdentity, AdapterKind, DeploymentId, EndpointScheme, ProviderCapabilities, ProviderId,
    ProviderRequest, ProviderResult, ProviderRouteBinding, RegionId, Sha256Digest,
};
use orbit_egress::{EgressAllowlist, EgressTuple, SpkiPin};
use orbit_gateway::dispatch::{DispatchEngine, DispatchError, DispatchOutcome};
use orbit_gateway::{ModelRef, ProviderRegistry, new_decision_id, new_session_id};
use orbit_ledger::event::LedgerEvent;
use orbit_provider_http::{AsyncProviderAdapter, AsyncProviderEventStream, CancelToken};
use std::path::PathBuf;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(10);
const REFUSAL: &str = "fixture provider refusal";

struct OwnedDir(PathBuf);

impl OwnedDir {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("orbit-replay-{}", new_session_id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}

impl Drop for OwnedDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Rendezvous {
    arrivals: Mutex<usize>,
    changed: Condvar,
}

impl Rendezvous {
    fn wait(&self) -> Result<(), AdapterError> {
        let deadline = Instant::now() + DEADLINE;
        let mut arrivals = self.arrivals.lock().unwrap();
        *arrivals += 1;
        self.changed.notify_all();
        while *arrivals < 2 {
            let (next, timeout) = self
                .changed
                .wait_timeout(arrivals, deadline.saturating_duration_since(Instant::now()))
                .unwrap();
            arrivals = next;
            if timeout.timed_out() && *arrivals < 2 {
                return Err(AdapterError::CapacityUnavailableExhausted(
                    "fixture rendezvous timed out".into(),
                ));
            }
        }
        Ok(())
    }
}

struct RacingAdapter {
    capabilities: ProviderCapabilities,
    routes: Rendezvous,
    calls: AtomicUsize,
    provider_rounds: Option<Rendezvous>,
}

impl RacingAdapter {
    fn validate(&self) -> Result<(), AdapterError> {
        // Both calls have already passed the advisory replay check here.
        self.routes.wait()
    }

    fn invoke_once(&self) -> Result<(), AdapterError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(rounds) = &self.provider_rounds {
            // A round-long ledger lock would prevent the other call arriving.
            rounds.wait()?;
        }
        Err(AdapterError::CapacityUnavailableExhausted(REFUSAL.into()))
    }
}

impl ProviderAdapter for RacingAdapter {
    fn identity(&self) -> AdapterIdentity {
        fixture_identity()
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn validate_route(&self, _: &ProviderRouteBinding) -> Result<(), AdapterError> {
        self.validate()
    }

    fn invoke(
        &self,
        _: &ProviderRequest,
        _: Option<&SecretBytes>,
    ) -> Result<ProviderResult, AdapterError> {
        self.invoke_once()?;
        unreachable!("the fixture always refuses after counting the invocation")
    }
}

#[async_trait::async_trait]
impl AsyncProviderAdapter for RacingAdapter {
    fn identity(&self) -> AdapterIdentity {
        fixture_identity()
    }

    fn capabilities(&self) -> &ProviderCapabilities {
        &self.capabilities
    }

    fn validate_route(&self, _: &ProviderRouteBinding) -> Result<(), AdapterError> {
        self.validate()
    }

    async fn invoke(
        &self,
        _: &ProviderRequest,
        _: Option<&SecretBytes>,
        _: &CancelToken,
    ) -> Result<AsyncProviderEventStream, AdapterError> {
        self.invoke_once()?;
        unreachable!("the fixture always refuses after counting the invocation")
    }
}

fn fixture_identity() -> AdapterIdentity {
    identity(
        AdapterKind::DeterministicTestV1,
        &"i".repeat(64),
        &"p".repeat(64),
    )
}

fn route() -> ProviderRouteBinding {
    let identity = fixture_identity();
    ProviderRouteBinding {
        provider_id: ProviderId("fixture-provider".into()),
        deployment_id: DeploymentId("fixture-deployment".into()),
        region_id: RegionId("fixture-region".into()),
        adapter_kind: identity.kind,
        adapter_implementation_digest: identity.implementation_digest,
        adapter_profile_digest: identity.profile_digest,
        endpoint_digest: Sha256Digest("e".repeat(64)),
        expected_model: "fixture-model".into(),
        pricing_digest: Sha256Digest("c".repeat(64)),
        endpoint_host: "127.0.0.1".into(),
        endpoint_port: 12345,
        endpoint_scheme: EndpointScheme::HttpLoopback,
        endpoint_path: "/v1".into(),
        endpoint_query: None,
    }
}

fn race(asynchronous: bool, same_session: bool) {
    let directory = OwnedDir::new();
    let route = route();
    let tuple = EgressTuple {
        scheme: "http".into(),
        host: route.endpoint_host.clone(),
        port: route.endpoint_port,
        path_prefix: route.endpoint_path.clone(),
        provider_id: route.provider_id.0.clone(),
        region_id: route.region_id.0.clone(),
    };
    let adapter = Arc::new(RacingAdapter {
        capabilities: text_capabilities(),
        routes: Rendezvous::default(),
        calls: AtomicUsize::new(0),
        provider_rounds: (!same_session).then(Rendezvous::default),
    });
    let mut registry = ProviderRegistry::new();
    registry.register_model(ModelRef("fixture-model".into()), route.clone());
    registry.register_adapter(route.adapter_kind, adapter.clone());
    registry.register_async_adapter(route.adapter_kind, adapter.clone());
    let engine = Arc::new(DispatchEngine::new(
        registry,
        directory.0.clone(),
        EgressAllowlist::new(vec![tuple.clone()]),
        vec![tuple],
        vec![SpkiPin {
            provider_id: route.provider_id.0.clone(),
            region_id: route.region_id.0.clone(),
            spki_sha256: "fixture-pin".into(),
        }],
    ));
    let decision = new_decision_id().0;
    let first_session = new_session_id();
    let sessions = [
        first_session.clone(),
        if same_session {
            first_session
        } else {
            new_session_id()
        },
    ];
    let results: Vec<Result<DispatchOutcome, DispatchError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = sessions
            .iter()
            .map(|session| {
                let engine = engine.clone();
                let request = canonical_request(&route, b"fixture request");
                let ledger = &directory.0;
                let decision = &decision;
                scope.spawn(move || {
                    if asynchronous {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap()
                            .block_on(engine.dispatch_async_detailed(
                                "fixture-model",
                                session,
                                decision,
                                &request,
                                None,
                                ledger,
                                &CancelToken::new(),
                                Default::default(),
                            ))
                            .map(|(outcome, _)| outcome.into_legacy())
                    } else {
                        engine
                            .dispatch("fixture-model", session, decision, &request, None, ledger)
                            .map(|(outcome, _)| outcome)
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });

    let expected_calls = if same_session { 1 } else { 2 };
    assert_eq!(adapter.calls.load(Ordering::SeqCst), expected_calls);
    let (records, _) = orbit_ledger::verify_ledger(&directory.0).unwrap();
    let intents = records
        .iter()
        .filter(|record| {
            matches!(&record.record.event, LedgerEvent::EgressIntent(intent)
            if intent.decision_id == decision && sessions.contains(&intent.session_id))
        })
        .count();
    assert_eq!(intents, expected_calls);
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        expected_calls
    );
    for result in results {
        match result {
            Ok(DispatchOutcome::AdapterRefused { message, .. }) => {
                assert!(
                    message.contains(REFUSAL),
                    "unexpected adapter result: {message}"
                );
            }
            Err(error) if same_session => assert_eq!(error.code, "E0701"),
            other => panic!("unexpected dispatch result: {other:?}"),
        }
    }
}

#[test]
fn sync_same_decision_is_reserved_once_before_provider_invocation() {
    race(false, true);
}

#[test]
fn async_same_decision_is_reserved_once_before_provider_invocation() {
    race(true, true);
}

#[test]
fn sync_distinct_sessions_can_invoke_while_another_provider_round_is_open() {
    race(false, false);
}

#[test]
fn async_distinct_sessions_can_invoke_while_another_provider_round_is_open() {
    race(true, false);
}
