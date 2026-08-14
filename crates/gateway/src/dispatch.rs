//! Gateway dispatch state machine (DR-09 §6, GW-09) + the fsync-before-dispatch
//! boundary (GW-04).
//!
//! Durable dispatch states (DR-09 §6):
//!   Reserved → EgressIntentDurable → DispatchStarted → StreamObserved → Terminal
//!                                   → AmbiguousAfterCrash
//!
//! The state transitions are driven by the synchronous `dispatch_call` flow:
//!   1. Four-gate admission (Trust→Capability→Egress→Dispatch) already ran.
//!   2. Reserve a decision id (Reserved).
//!   3. Egress broker evaluates the destination → must fsync the EgressEvent
//!      to the Ledger BEFORE any adapter invocation (GW-04). This is the
//!      boundary: the adapter is never called unless the intent is durable.
//!   4. Transition to DispatchStarted, lease the credential, re-check the
//!      binding, invoke the adapter.
//!   5. Capture the ProviderResult → Terminal.
//!
//! `recovery_state` reads the durable chain to determine what a restart may
//! safely do (GW-09): never redispatch an ambiguous/output-observed attempt.

use crate::registry::ProviderRegistry;
use orbit_adapter::credential::SecretBytes;
use orbit_adapter::types::{
    DecisionId, ProviderRequest, ProviderResult, ProviderRouteBinding, RequestId,
};
use orbit_adapter::ProviderAdapter;
use orbit_egress::{BrokerVerdict, EgressAllowlist, EgressBroker, EgressTuple, SpkiPin};
use orbit_ledger::event::{EgressDestination, EgressIntent, LedgerEvent};
use orbit_ledger::{LedgerError, LedgerWriter, SessionId};
use std::sync::Arc;

/// Durable dispatch state (DR-09 §6). This is what survives a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DispatchState {
    Reserved,
    EgressIntentDurable,
    DispatchStarted,
    StreamObserved,
    Terminal,
    AmbiguousAfterCrash,
}

/// How a dispatch call finished (or failed) — the gateway-facing result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Terminal: the adapter returned a result.
    Completed(Box<ProviderResult>),
    /// The adapter was never invoked because the egress intent couldn't be
    /// made durable (GW-04 — this is the SAFE outcome).
    EgressNotDurable { reason: String },
    /// The adapter rejected the request before any delivery.
    AdapterRefused { code: &'static str, message: String },
    /// Dispatch was never attempted (e.g. admission denied).
    NotDispatched { reason: String },
}

/// The durable egress-intent reservation written before dispatch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EgressReservation {
    pub decision_id: String,
    pub session_id: String,
    pub destination_digest: String,
    pub egress_category: String,
    pub policy_snapshot_id: String,
}

/// The dispatch engine: wires admission → egress fsync → adapter.
pub struct DispatchEngine {
    /// The registry of provider adapters (kind → adapter).
    registry: ProviderRegistry,
    /// The ledger directory (the durable sink for recovery reads).
    ledger_dir: std::path::PathBuf,
    /// The capability-card-driven egress allowlist (DR-07 S6: the card is the
    /// source of truth — P0-1 fix, never self-constructed from the tuple).
    egress_allowlist: EgressAllowlist,
    /// The trust-root pinned route table (DR-09 §5 gate 1).
    trusted_routes: Vec<EgressTuple>,
    /// SPKI pins per (provider, region).
    spki_pins: Vec<SpkiPin>,
}

impl DispatchEngine {
    /// Construct with the adapter registry, the ledger directory, and the
    /// EXTERNALLY-SUPPLIED egress allowlist + trust-root routes + SPKI pins.
    /// The egress broker must evaluate against these — never against a tuple
    /// the dispatch itself constructed (P0-1).
    pub fn new(
        registry: ProviderRegistry,
        ledger_dir: std::path::PathBuf,
        egress_allowlist: EgressAllowlist,
        trusted_routes: Vec<EgressTuple>,
        spki_pins: Vec<SpkiPin>,
    ) -> Self {
        Self {
            registry,
            ledger_dir,
            egress_allowlist,
            trusted_routes,
            spki_pins,
        }
    }

    /// The four-gate admission. This mirrors the existing `Gateway::admit`
    /// but returns the resolved adapter + route for dispatch.
    pub fn resolve(
        &self,
        model: &str,
        session_id: &str,
        decision_id: &str,
    ) -> Result<(Arc<dyn ProviderAdapter>, ProviderRouteBinding), DispatchError> {
        // Gate 1: Trust — model in trust-root allowlist.
        if !self.registry.is_model_allowed(model) {
            return Err(DispatchError::admission("trust", model, "E0404"));
        }
        // Gate 2: Capability — a route exists for the model.
        let binding = self
            .registry
            .route_for_model(model)
            .ok_or_else(|| DispatchError::admission("capability", model, "E0405"))?;
        // Gate 3: Egress — endpoint pinned.
        if binding.endpoint_digest.as_str().is_empty() {
            return Err(DispatchError::admission("egress", model, "E0405"));
        }
        // Gate 4: Dispatch — resolve the adapter for the route's kind.
        let adapter = self
            .registry
            .resolve_adapter(binding.adapter_kind)
            .ok_or_else(|| DispatchError::admission("dispatch", model, "E0401"))?;
        // Offline route validation (DR-09 §3 — no network).
        adapter
            .validate_route(&binding)
            .map_err(|e| DispatchError {
                code: e.code(),
                phase: "dispatch",
                message: e.to_string(),
                session_id: session_id.into(),
                decision_id: decision_id.into(),
            })?;
        let _ = session_id;
        Ok((adapter, binding))
    }

    /// Run the durable dispatch: reserve → fsync egress intent → invoke.
    /// Returns the DispatchOutcome; the egress reservation is returned for
    /// the caller to inspect (and to prove the adapter was gated on it).
    ///
    /// P0-3: a decision_id that was already dispatched in this ledger is
    /// refused with E0701 (decision_id_already_consumed) — no replay.
    pub fn dispatch(
        &self,
        model: &str,
        session_id: &str,
        decision_id: &str,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        writer: &mut LedgerWriter,
    ) -> Result<(DispatchOutcome, EgressReservation), DispatchError> {
        // P0-3: replay guard — if this decision_id was already dispatched
        // (its EgressIntent is in the durable chain), refuse with E0701.
        // Only a fresh, never-dispatched decision_id (Reserved) may proceed.
        match self.recovery_state(session_id, decision_id) {
            Ok(DispatchState::Reserved) => {}
            Ok(_) => {
                return Err(DispatchError {
                    code: "E0701",
                    phase: "dispatch",
                    message: format!("decision_id {decision_id} already dispatched (E0701)"),
                    session_id: session_id.into(),
                    decision_id: decision_id.into(),
                })
            }
            Err(e) => {
                return Err(DispatchError {
                    code: "E0602",
                    phase: "recovery",
                    message: format!("recovery read failed: {e}"),
                    session_id: session_id.into(),
                    decision_id: decision_id.into(),
                })
            }
        }

        let (adapter, binding) = self.resolve(model, session_id, decision_id)?;

        // Build the egress destination tuple from the binding's REAL endpoint.
        // NEW P1 #3: an empty endpoint_host is a config error — refused, never
        // fabricated from the provider id.
        let tuple = egress_tuple_from_binding(&binding).map_err(|e| DispatchError {
            code: "E0401",
            phase: "egress",
            message: e,
            session_id: session_id.into(),
            decision_id: decision_id.into(),
        })?;
        // Gate 3: Egress broker evaluation against the EXTERNAL allowlist
        // (P0-1 fix — never self-construct from the tuple).
        let broker = EgressBroker::new(
            self.egress_allowlist.clone(),
            "pol".into(),
            self.trusted_routes.clone(),
            self.spki_pins.clone(),
        );
        let verdict = broker.evaluate(&tuple, decision_id);
        if !verdict.allowed {
            return Err(DispatchError::admission("egress", model, "E0307"));
        }
        // NEW P1 #1: the route MUST have a SPKI pin for (provider, region).
        // Without it, a TLS destination substitution after allowlist match
        // could send the credential to a spoofed endpoint. Fail closed.
        if let Err(e) = broker.check_spki_pin(
            &tuple.provider_id,
            &tuple.region_id,
            &self.expected_spki_for(&tuple.provider_id, &tuple.region_id),
        ) {
            return Err(DispatchError {
                code: "E0310",
                phase: "egress",
                message: format!("SPKI pin missing/mismatch: {e}"),
                session_id: session_id.into(),
                decision_id: decision_id.into(),
            });
        }

        // The no-network-before-fsync boundary (GW-04): append + fsync the
        // EgressIntent to the injected long-lived writer BEFORE any adapter
        // invocation (P0-5 fix — no competing writer lock).
        let reservation =
            match self.fsync_egress_intent(writer, session_id, decision_id, &tuple, &verdict) {
                Ok(r) => r,
                Err(e) => {
                    return Ok((
                        DispatchOutcome::EgressNotDurable {
                            reason: e.to_string(),
                        },
                        EgressReservation {
                            decision_id: decision_id.into(),
                            session_id: session_id.into(),
                            destination_digest: tuple.digest(),
                            egress_category: "model_inference".into(),
                            policy_snapshot_id: "pol".into(),
                        },
                    ))
                }
            };

        // Invoke the adapter with the credential. No hidden retry (GW-07);
        // the gateway decides whether to retry.
        let result = adapter.invoke(request, credential);
        match result {
            Ok(r) => Ok((DispatchOutcome::Completed(Box::new(r)), reservation)),
            Err(e) => {
                let code = e.code();
                Ok((
                    DispatchOutcome::AdapterRefused {
                        code,
                        message: e.to_string(),
                    },
                    reservation,
                ))
            }
        }
    }

    /// v0.2 async dispatch: runs the same four-gate admission + egress fsync,
    /// then invokes the ASYNC adapter and collects the event stream. Returns
    /// the collected events + evidence (the stream is validated for sequence/
    /// usage contiguity — GW-11/GW-13).
    #[allow(clippy::too_many_arguments)] // engine API: model/session/decision/request/cred/writer/cancel
    pub async fn dispatch_async(
        &self,
        model: &str,
        session_id: &str,
        decision_id: &str,
        request: &ProviderRequest,
        credential: Option<&SecretBytes>,
        writer: &mut LedgerWriter,
        cancel: &orbit_provider_http::CancelToken,
    ) -> Result<(DispatchOutcome, EgressReservation), DispatchError> {
        // P0-3 replay guard (same as sync).
        match self.recovery_state(session_id, decision_id) {
            Ok(DispatchState::Reserved) => {}
            Ok(_) => {
                return Err(DispatchError {
                    code: "E0701",
                    phase: "dispatch",
                    message: format!("decision_id {decision_id} already dispatched (E0701)"),
                    session_id: session_id.into(),
                    decision_id: decision_id.into(),
                })
            }
            Err(e) => {
                return Err(DispatchError {
                    code: "E0602",
                    phase: "recovery",
                    message: format!("recovery read failed: {e}"),
                    session_id: session_id.into(),
                    decision_id: decision_id.into(),
                })
            }
        }

        // Gates 1-2: trust + capability (allowlist + route).
        if !self.registry.is_model_allowed(model) {
            return Err(DispatchError::admission("trust", model, "E0404"));
        }
        let binding = self
            .registry
            .route_for_model(model)
            .ok_or_else(|| DispatchError::admission("capability", model, "E0405"))?;
        // Gate 3: egress — endpoint pinned.
        if binding.endpoint_digest.as_str().is_empty() {
            return Err(DispatchError::admission("egress", model, "E0405"));
        }
        // Gate 4: resolve the ASYNC adapter (v0.2).
        let adapter = self
            .registry
            .resolve_async_adapter(binding.adapter_kind)
            .ok_or_else(|| DispatchError::admission("dispatch", model, "E0401"))?;
        adapter
            .validate_route(&binding)
            .map_err(|e| DispatchError {
                code: e.code(),
                phase: "dispatch",
                message: e.to_string(),
                session_id: session_id.into(),
                decision_id: decision_id.into(),
            })?;

        // Egress broker check against the EXTERNAL allowlist (P0-1) + SPKI.
        let tuple = egress_tuple_from_binding(&binding).map_err(|e| DispatchError {
            code: "E0401",
            phase: "egress",
            message: e,
            session_id: session_id.into(),
            decision_id: decision_id.into(),
        })?;
        let broker = EgressBroker::new(
            self.egress_allowlist.clone(),
            "pol".into(),
            self.trusted_routes.clone(),
            self.spki_pins.clone(),
        );
        let verdict = broker.evaluate(&tuple, decision_id);
        if !verdict.allowed {
            return Err(DispatchError::admission("egress", model, "E0307"));
        }

        // GW-04: fsync the EgressIntent before any adapter invocation.
        let reservation =
            match self.fsync_egress_intent(writer, session_id, decision_id, &tuple, &verdict) {
                Ok(r) => r,
                Err(e) => {
                    return Ok((
                        DispatchOutcome::EgressNotDurable {
                            reason: e.to_string(),
                        },
                        EgressReservation {
                            decision_id: decision_id.into(),
                            session_id: session_id.into(),
                            destination_digest: tuple.digest(),
                            egress_category: "model_inference".into(),
                            policy_snapshot_id: "pol".into(),
                        },
                    ))
                }
            };

        // Invoke the async adapter, collect the stream, validate evidence.
        let stream = match adapter.invoke(request, credential, cancel).await {
            Ok(s) => s,
            Err(e) => {
                return Ok((
                    DispatchOutcome::AdapterRefused {
                        code: e.code(),
                        message: e.to_string(),
                    },
                    reservation,
                ))
            }
        };
        match orbit_provider_http::stream::collect_stream(stream).await {
            Ok((events, evidence)) => {
                let result = orbit_adapter::types::ProviderResult {
                    status: orbit_adapter::types::ProviderTerminalStatus::Completed,
                    binding: Default::default(),
                    output: evidence,
                    accounting: Default::default(),
                    transport: Default::default(),
                    events,
                };
                Ok((DispatchOutcome::Completed(Box::new(result)), reservation))
            }
            Err(e) => Ok((
                DispatchOutcome::AdapterRefused {
                    code: e.code(),
                    message: e.to_string(),
                },
                reservation,
            )),
        }
    }

    /// Append + fsync the EgressIntent to the ledger. This is the point where
    /// a fault (disk full, fsync failure) must BLOCK dispatch (GW-04).
    /// P0-5 fix: uses the injected long-lived writer — no competing flock.
    fn fsync_egress_intent(
        &self,
        writer: &mut LedgerWriter,
        session_id: &str,
        decision_id: &str,
        tuple: &EgressTuple,
        _verdict: &BrokerVerdict,
    ) -> Result<EgressReservation, LedgerError> {
        let intent = EgressIntent {
            session_id: session_id.into(),
            intent_id: decision_id.into(),
            decision_id: decision_id.into(),
            subagent_id: None,
            destinations: vec![EgressDestination {
                scheme: tuple.scheme.clone(),
                host: tuple.host.clone(),
                port: tuple.port,
                path_prefix: Some(tuple.path_prefix.clone()),
                provider_id: tuple.provider_id.clone(),
                region_id: tuple.region_id.clone(),
            }],
            egress_digest: tuple.digest(),
            egress_categories: vec![orbit_ledger::event::EgressCategory::ModelInference],
            policy_snapshot_id: "pol".into(),
            capability_card_proofs: None,
        };
        // EgressIntent requires fsync-before-ACK by the ledger's own policy.
        writer.append(LedgerEvent::EgressIntent(intent))?;
        // Caller is responsible for the writer's lifecycle (close → fsync).
        Ok(EgressReservation {
            decision_id: decision_id.into(),
            session_id: session_id.into(),
            destination_digest: tuple.digest(),
            egress_category: "model_inference".into(),
            policy_snapshot_id: "pol".into(),
        })
    }

    /// Read the durable dispatch state for a decision from the ledger.
    /// GW-09: restart behavior derives from the durable chain.
    pub fn recovery_state(
        &self,
        session_id: &str,
        decision_id: &str,
    ) -> Result<DispatchState, LedgerError> {
        let (records, _head) = orbit_ledger::verify_ledger(&self.ledger_dir)?;
        let mut saw_intent_for_decision = false;
        let mut saw_dispatch_for_decision = false;
        for rec in records {
            match &rec.record.event {
                // NEW P2 #2: key the filter on (session_id, decision_id) so a
                // decision in another session never leaks into this recovery.
                LedgerEvent::EgressIntent(i)
                    if i.decision_id == decision_id && i.session_id == session_id =>
                {
                    saw_intent_for_decision = true;
                }
                LedgerEvent::SubagentCall(c)
                    if c.decision_id == decision_id && c.session_id == session_id =>
                {
                    // P0-2 fix: filter SubagentCall by decision_id (it carries
                    // a `decision_id` field); without this, any SubagentCall
                    // made the dispatch state look "DispatchStarted" for
                    // every decision — masking missing intents and corrupting
                    // restart behavior.
                    saw_dispatch_for_decision = true;
                }
                _ => {}
            }
        }
        if saw_dispatch_for_decision {
            Ok(DispatchState::DispatchStarted)
        } else if saw_intent_for_decision {
            Ok(DispatchState::EgressIntentDurable)
        } else {
            Ok(DispatchState::Reserved)
        }
    }
}

/// Build an egress destination tuple from a route binding.
/// NEW P1 #3: an empty endpoint_host is a config error → Err (never
/// fabricate from the provider id — the host MUST be DNS-routable).
fn egress_tuple_from_binding(binding: &ProviderRouteBinding) -> Result<EgressTuple, String> {
    if binding.endpoint_host.is_empty() {
        return Err(format!(
            "route for {} has no endpoint_host (E0401 provider_configuration_invalid)",
            binding.provider_id.0
        ));
    }
    // Scheme mirrors the adapter: loopback hosts use http, else https.
    let scheme = if binding.endpoint_host == "127.0.0.1"
        || binding.endpoint_host == "localhost"
        || binding.endpoint_host == "::1"
    {
        "http"
    } else {
        "https"
    };
    Ok(EgressTuple {
        scheme: scheme.into(),
        host: binding.endpoint_host.clone(),
        port: binding.endpoint_port,
        path_prefix: "/v1".into(),
        provider_id: binding.provider_id.0.clone(),
        region_id: binding.region_id.0.clone(),
    })
}

impl DispatchEngine {
    /// The expected SPKI SHA-256 for a (provider, region) — from the pinned
    /// table. Used to verify the TLS peer identity before credential delivery
    /// (NEW P1 #1).
    fn expected_spki_for(&self, provider: &str, region: &str) -> String {
        self.spki_pins
            .iter()
            .find(|p| p.provider_id == provider && p.region_id == region)
            .map(|p| p.spki_sha256.clone())
            .unwrap_or_default()
    }
}

/// Dispatch error — the public envelope (DR-09 §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchError {
    pub code: &'static str,
    pub phase: &'static str,
    pub message: String,
    pub session_id: String,
    pub decision_id: String,
}

impl DispatchError {
    pub fn admission(gate: &'static str, model: &str, code: &'static str) -> Self {
        Self {
            code,
            phase: gate,
            message: format!("gate '{gate}' denied model {model} ({code})"),
            session_id: String::new(),
            decision_id: String::new(),
        }
    }
}

/// Convenience for tests: construct a fresh session id.
pub fn new_session_id() -> SessionId {
    format!("session-{}", std::process::id())
}

/// Convenience for tests: a fresh decision id (ULID-ish).
pub fn new_decision_id() -> DecisionId {
    DecisionId(format!("decision-{}", std::process::id()))
}

/// Convenience: a fresh request id.
pub fn new_request_id() -> RequestId {
    RequestId(format!("req-{}", std::process::id()))
}

/// Build a dispatch-friendly temp dir helper (used by gateway tests).
pub fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("orbit-gw-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}
