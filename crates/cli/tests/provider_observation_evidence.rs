#![cfg(target_os = "linux")]
#![deny(unsafe_code)]

use orbit_adapter::provider_credentials::ProviderAuthIdentity;
use orbit_cli::config::{ProviderConfig, ProvidersConfig};
use orbit_cli::provider_discovery::{
    DiscoveredModel, DiscoveryCompleteness, DiscoveryProfile, DiscoverySession, ModelProvenance,
    load_model_provenance, merge_discovered_model, save_model_provenance,
};
use orbit_provider_http::CancelToken;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MODEL: &str = "evidence-model";
const CONTEXT: u64 = 2000;
const OUTPUT: u64 = 200;
const HISTORICAL_TIME: u64 = 1_700_000_000;
const MAX_HEADERS: usize = 16 * 1024;
const MAX_REQUESTS: usize = 4;

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("orbit-evidence-oldapi-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn publish(&self, provider: &ProviderConfig) {
        let config = ProvidersConfig {
            provider: vec![provider.clone()],
            ..Default::default()
        };
        write_private(
            &self.0.join("providers.toml"),
            toml::to_string(&config).unwrap().as_bytes(),
        );
    }
    fn sidecar(&self, provider: &ProviderConfig) -> PathBuf {
        self.0
            .join("metadata/providers")
            .join(format!("{}.json", identity(provider).binding_id()))
    }
    fn seed_document(&self, provider: &ProviderConfig, document: &Value) {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(self.0.join("metadata"))
            .unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(self.0.join("metadata/providers"))
            .unwrap();
        write_private(
            &self.sidecar(provider),
            &serde_json::to_vec(document).unwrap(),
        );
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

struct Captured {
    target: String,
    headers: Vec<(String, String)>,
}

// Owned IPv4 only; finite listener/read/write/watchdog and joined Drop cleanup.
struct Fixture {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Captured>>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<Result<(), &'static str>>>,
    watchdog: Option<std::sync::mpsc::Sender<()>>,
    watchdog_join: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(responses: Vec<Value>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (watchdog, wait) = std::sync::mpsc::channel();
        let watchdog_join = thread::spawn(move || {
            if matches!(
                wait.recv_timeout(Duration::from_secs(15)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                eprintln!("owned observation fixture exceeded independent watchdog");
                std::process::exit(91);
            }
        });
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(12);
            let mut responses = responses.into_iter();
            loop {
                if Instant::now() >= deadline {
                    return Err("owned listener deadline");
                }
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        if accepted.fetch_add(1, Ordering::SeqCst) >= MAX_REQUESTS {
                            return Err("unexpected request count");
                        }
                        socket
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .map_err(|_| "read timeout")?;
                        socket
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .map_err(|_| "write timeout")?;
                        captured
                            .lock()
                            .map_err(|_| "capture lock")?
                            .push(read_request(&mut socket)?);
                        let response = responses.next().ok_or("unexpected provider request")?;
                        let body =
                            serde_json::to_vec(&response).map_err(|_| "response serialization")?;
                        if body.len() >= 16 * 1024 {
                            return Err("fixture response exceeds bound");
                        }
                        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).map_err(|_| "response header write")?;
                        socket.write_all(&body).map_err(|_| "response body write")?;
                        socket.flush().map_err(|_| "response flush")?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        // Drain queued connections before acknowledging stop.
                        if stopped.load(Ordering::SeqCst) {
                            return Ok(());
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return Err("owned accept"),
                }
            }
        });
        Self {
            addr,
            requests,
            connections,
            stop,
            join: Some(join),
            watchdog: Some(watchdog),
            watchdog_join: Some(watchdog_join),
        }
    }
    fn provider(&self, populated: bool) -> ProviderConfig {
        let mut value = json!({
            "name":"fixture", "kind":"anthropic",
            "url":format!("http://{}/tenant/v1?scope=evidence-fixture", self.addr),
            "env":null,"models":[{"id":MODEL}]
        });
        if populated {
            value["models"][0]["context_window"] = json!(CONTEXT);
            value["models"][0]["max_output_tokens"] = json!(OUTPUT);
        }
        serde_json::from_value(value).unwrap()
    }
    fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            join.join()
                .expect("owned fixture thread")
                .expect("owned fixture I/O");
        }
        if let Some(done) = self.watchdog.take() {
            let _ = done.send(());
        }
        if let Some(join) = self.watchdog_join.take() {
            join.join().expect("owned watchdog thread");
        }
    }
    fn assert_requests(&self, targets: &[&str]) {
        assert_eq!(self.connections.load(Ordering::SeqCst), targets.len());
        let requests = self.requests.lock().unwrap();
        assert_eq!(requests.len(), targets.len());
        for (request, target) in requests.iter().zip(targets) {
            assert_eq!(request.target, *target);
            assert!(
                !request
                    .headers
                    .iter()
                    .any(|(name, _)| name == "authorization" || name == "x-api-key")
            );
            assert_eq!(
                request
                    .headers
                    .iter()
                    .filter_map(|(name, value)| (name == "host").then_some(value.as_str()))
                    .collect::<Vec<_>>(),
                [self.addr.to_string().as_str()]
            );
            assert_eq!(
                request
                    .headers
                    .iter()
                    .filter_map(
                        |(name, value)| (name == "anthropic-version").then_some(value.as_str())
                    )
                    .collect::<Vec<_>>(),
                ["2023-06-01"]
            );
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.finish();
    }
}

fn read_request(socket: &mut TcpStream) -> Result<Captured, &'static str> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        if bytes.len() >= MAX_HEADERS || Instant::now() >= deadline {
            return Err("bounded request header");
        }
        let mut byte = [0];
        match socket.read(&mut byte) {
            Ok(1) => bytes.push(byte[0]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            _ => return Err("incomplete request header"),
        }
    }
    let head = String::from_utf8(bytes).map_err(|_| "header UTF8")?;
    let mut lines = head.split("\r\n");
    let target = lines.next().ok_or("request target")?.to_owned();
    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("request header syntax")?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
    if !target.starts_with("GET ")
        || headers.iter().any(|(name, value)| {
            name == "transfer-encoding" || (name == "content-length" && value != "0")
        })
    {
        return Err("unexpected request shape");
    }
    Ok(Captured { target, headers })
}

fn identity(provider: &ProviderConfig) -> ProviderAuthIdentity {
    ProviderAuthIdentity::new(
        &provider.name,
        &provider.kind,
        &provider.url,
        provider.env.as_deref(),
    )
    .unwrap()
}
fn session(home: &Home, provider: &ProviderConfig) -> DiscoverySession {
    DiscoverySession::new_with_lookup(
        &home.0,
        provider,
        DiscoveryProfile::Anthropic,
        None,
        CancelToken::new(),
        |_| panic!("no-auth discovery must not consult ENV"),
    )
    .unwrap()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn model_response() -> Value {
    json!({"id":MODEL,"type":"model","display_name":"Evidence fixture","max_input_tokens":CONTEXT,"max_tokens":OUTPUT})
}
fn catalog_response() -> Value {
    json!({"data":[model_response()],"has_more":false,"last_id":MODEL})
}
fn observed_json(with_evidence: bool) -> Value {
    let mut value = json!({"id":MODEL,"label":null,"context_window":CONTEXT,"max_output_tokens":OUTPUT,"source":"anthropic_models","metadata_valid":true,"unrecognized_fields":[]});
    if with_evidence {
        value["evidence"] = evidence_json(HISTORICAL_TIME);
    }
    value
}
fn evidence_json(time: u64) -> Value {
    json!({
        "context_limit":{"value":CONTEXT,"observed_at_unix":time,"source":"anthropic_models","schema":"anthropic_models_2023_06_01","semantics":"input_tokens","confidence":"documented_limit"},
        "output_limit":{"value":OUTPUT,"observed_at_unix":time,"source":"anthropic_models","schema":"anthropic_models_2023_06_01","semantics":"output_tokens","confidence":"documented_limit"}
    })
}
fn record_json(provider: &ProviderConfig, version: u32, evidence: bool) -> Value {
    json!({"schema_version":version,"provider_binding":identity(provider).binding_id(),"model_id":MODEL,"observed":observed_json(evidence),"last_applied_context_window":CONTEXT,"last_applied_max_output_tokens":OUTPUT,"last_applied_label":null})
}
fn document_json(provider: &ProviderConfig, version: u32, evidence: bool) -> Value {
    json!({"schema_version":version,"provider_binding":identity(provider).binding_id(),"models":[record_json(provider,version,evidence)]})
}
fn assert_fetched_evidence(model: &DiscoveredModel, source: &str, started: u64, finished: u64) {
    let model = serde_json::to_value(model).unwrap();
    let evidence = model
        .get("evidence")
        .expect("validated actual fetch must carry observation evidence");
    for (name, value, semantics) in [
        ("context_limit", CONTEXT, "input_tokens"),
        ("output_limit", OUTPUT, "output_tokens"),
    ] {
        let component = &evidence[name];
        assert_eq!(component["value"], value);
        assert_eq!(component["source"], source);
        assert_eq!(component["schema"], "anthropic_models_2023_06_01");
        assert_eq!(component["semantics"], semantics);
        assert_eq!(component["confidence"], "documented_limit");
        let time = component["observed_at_unix"]
            .as_u64()
            .expect("actual observation time must be a bounded integer");
        assert!(
            time >= started && time <= finished,
            "stamp must describe this actual fetch, not model release time or save time"
        );
    }
}

#[test]
fn evidence_oldapi_json_roundtrip_retains_per_component_observation() {
    let input = observed_json(true);
    let model: DiscoveredModel = serde_json::from_value(input.clone()).unwrap();
    let serialized = serde_json::to_value(model).unwrap();
    assert_eq!(
        serialized["evidence"], input["evidence"],
        "the existing public serde path must not silently discard observation age/semantics"
    );
}

#[tokio::test]
async fn evidence_oldapi_actual_catalog_records_observation_time() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![catalog_response()]);
    let provider = fixture.provider(false);
    let session = session(&home, &provider);
    let started = now();
    let catalog = session.catalog().await;
    let finished = now();
    fixture.finish();
    fixture.assert_requests(&["GET /tenant/v1/models?scope=evidence-fixture HTTP/1.1"]);
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Complete);
    assert_eq!(catalog.models.len(), 1);
    assert!(
        fs::read_dir(&home.0).unwrap().next().is_none(),
        "construction/fetch cannot publish credentials or metadata"
    );
    assert_fetched_evidence(&catalog.models[0], "anthropic_models", started, finished);
}

#[tokio::test]
async fn evidence_oldapi_actual_detail_records_its_own_observation_time() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![model_response()]);
    let provider = fixture.provider(false);
    let selected: DiscoveredModel = serde_json::from_value(observed_json(false)).unwrap();
    let session = session(&home, &provider);
    let started = now();
    let details = session.details(&[selected], true).await;
    let finished = now();
    fixture.finish();
    fixture
        .assert_requests(&["GET /tenant/v1/models/evidence-model?scope=evidence-fixture HTTP/1.1"]);
    assert_eq!(details.completeness, DiscoveryCompleteness::Complete);
    assert_eq!((details.considered, details.attempted), (1, 1));
    assert_fetched_evidence(
        &details.models[0],
        "anthropic_model_detail",
        started,
        finished,
    );
}

#[tokio::test]
async fn evidence_oldapi_actual_fetch_merge_save_reload_publishes_v2() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![catalog_response()]);
    let mut provider = fixture.provider(false);
    let session = session(&home, &provider);
    let catalog = session.catalog().await;
    fixture.finish();
    fixture.assert_requests(&["GET /tenant/v1/models?scope=evidence-fixture HTTP/1.1"]);
    assert_eq!(catalog.completeness, DiscoveryCompleteness::Complete);
    let observed = &catalog.models[0];
    let merged = merge_discovered_model(&provider.models[0], observed, None, &identity(&provider));
    provider.models[0] = merged.model;
    let record = merged.provenance.unwrap();
    home.publish(&provider);
    save_model_provenance(&home.0, &provider, &[record]).unwrap();
    let bytes = fs::read(home.sidecar(&provider)).unwrap();
    assert!(bytes.len() < 128 * 1024);
    let document: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        document["schema_version"], 2,
        "public publication must preserve evidence in the strict v2 format"
    );
    assert!(!String::from_utf8(bytes).unwrap().contains(&provider.url));
    let loaded = load_model_provenance(&home.0, &provider).unwrap();
    assert_eq!(loaded.len(), 1);
    let actual = serde_json::to_value(&loaded[0]).unwrap();
    let expected = serde_json::to_value(observed).unwrap();
    assert!(expected["evidence"].is_object());
    assert_eq!(actual["observed"]["evidence"], expected["evidence"]);
}

#[test]
fn evidence_oldapi_private_v2_load_retains_old_component_times() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![]);
    let provider = fixture.provider(true);
    home.publish(&provider);
    home.seed_document(&provider, &document_json(&provider, 2, true));
    let loaded = load_model_provenance(&home.0, &provider).unwrap();
    fixture.finish();
    fixture.assert_requests(&[]);
    assert_eq!(
        loaded.len(),
        1,
        "strict v2 evidence must not be discarded as an unsupported future document"
    );
    let loaded = serde_json::to_value(&loaded[0]).unwrap();
    assert_eq!(
        loaded["observed"]["evidence"],
        evidence_json(HISTORICAL_TIME)
    );
}

#[test]
fn evidence_oldapi_pure_merge_carries_prior_component_age_without_renewal() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![]);
    let provider = fixture.provider(true);
    let previous: ModelProvenance =
        serde_json::from_value(record_json(&provider, 2, true)).unwrap();
    let observed: DiscoveredModel = serde_json::from_value(observed_json(false)).unwrap();
    let merged = merge_discovered_model(
        &provider.models[0],
        &observed,
        Some(&previous),
        &identity(&provider),
    );
    let record = merged.provenance.unwrap();
    fixture.finish();
    fixture.assert_requests(&[]);
    assert!(fs::read_dir(&home.0).unwrap().next().is_none());
    assert_eq!(
        serde_json::to_value(&record).unwrap()["observed"]["evidence"],
        evidence_json(HISTORICAL_TIME),
        "a pure unchanged merge keeps the old age rather than erasing or renewing it"
    );
}

#[test]
fn evidence_oldapi_v1_load_remains_ownership_only_without_network() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![]);
    let provider = fixture.provider(true);
    home.publish(&provider);
    home.seed_document(&provider, &document_json(&provider, 1, false));
    let loaded = load_model_provenance(&home.0, &provider).unwrap();
    fixture.finish();
    fixture.assert_requests(&[]);
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].schema_version, 1);
    assert_eq!(loaded[0].last_applied_context_window, Some(CONTEXT));
    assert_eq!(
        loaded[0].last_applied_max_output_tokens,
        Some(OUTPUT as u32)
    );
    assert!(serde_json::to_value(&loaded[0]).unwrap()["observed"]["evidence"].is_null());
}

#[test]
fn evidence_oldapi_pure_v1_save_does_not_invent_observation_time() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![]);
    let provider = fixture.provider(true);
    home.publish(&provider);
    home.seed_document(&provider, &document_json(&provider, 1, false));
    let loaded = load_model_provenance(&home.0, &provider).unwrap();
    save_model_provenance(&home.0, &provider, &loaded).unwrap();
    let again = load_model_provenance(&home.0, &provider).unwrap();
    fixture.finish();
    fixture.assert_requests(&[]);
    assert_eq!(again.len(), 1);
    let saved = serde_json::to_value(&again[0]).unwrap();
    assert!(
        saved["observed"]["evidence"].is_null(),
        "save may upgrade format but cannot fabricate a fetch"
    );
    assert_eq!(saved["last_applied_context_window"], CONTEXT);
    assert_eq!(saved["last_applied_max_output_tokens"], OUTPUT);
}

#[test]
fn evidence_oldapi_v1_wrong_query_never_inherits_binding_or_calls_provider() {
    let home = Home::new();
    let mut fixture = Fixture::new(vec![]);
    let provider = fixture.provider(true);
    home.publish(&provider);
    home.seed_document(&provider, &document_json(&provider, 1, false));
    let mut changed = provider.clone();
    changed.url.push_str("&different=1");
    assert_ne!(
        identity(&provider).binding_id(),
        identity(&changed).binding_id()
    );
    assert!(load_model_provenance(&home.0, &changed).unwrap().is_empty());
    fixture.finish();
    fixture.assert_requests(&[]);
    assert_eq!(
        fs::read_dir(home.0.join("metadata/providers"))
            .unwrap()
            .count(),
        1
    );
}

mod observation_clock_regressions {
    use super::*;
    use orbit_cli::provider_discovery::{DiscoveryIssueKind, ObservationClock};
    use std::collections::VecDeque;

    struct Clock {
        values: Mutex<VecDeque<Option<u64>>>,
        calls: AtomicUsize,
    }
    impl Clock {
        fn new(values: impl IntoIterator<Item = Option<u64>>) -> Arc<Self> {
            Arc::new(Self {
                values: Mutex::new(values.into_iter().collect()),
                calls: AtomicUsize::new(0),
            })
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl ObservationClock for Clock {
        fn unix_seconds(&self) -> Option<u64> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.values
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected observation clock read")
        }
    }
    fn selected() -> DiscoveredModel {
        serde_json::from_value(observed_json(true)).unwrap()
    }
    fn assert_no_publication(home: &Home) {
        assert!(fs::read_dir(&home.0).unwrap().next().is_none());
    }

    #[test]
    fn evidence_clock_constructor_does_not_read_time_or_create_paths() {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![]);
        let provider = fixture.provider(false);
        let clock = Clock::new([]);
        let _session = session(&home, &provider).with_observation_clock(clock.clone());
        assert_eq!(clock.calls(), 0);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[]);
    }

    #[tokio::test]
    async fn evidence_clock_same_value_catalog_refetch_renews_but_merge_save_does_not() {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![catalog_response(), catalog_response()]);
        let mut provider = fixture.provider(false);
        let clock = Clock::new([Some(100), Some(250)]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let first = session.catalog().await;
        let second = session.catalog().await;
        assert_eq!(first.completeness, DiscoveryCompleteness::Complete);
        assert_eq!(second.completeness, DiscoveryCompleteness::Complete);
        assert_fetched_evidence(&first.models[0], "anthropic_models", 100, 100);
        assert_fetched_evidence(&second.models[0], "anthropic_models", 250, 250);
        let applied = merge_discovered_model(
            &provider.models[0],
            &first.models[0],
            None,
            &identity(&provider),
        );
        let refreshed = merge_discovered_model(
            &applied.model,
            &second.models[0],
            applied.provenance.as_ref(),
            &identity(&provider),
        );
        let record = refreshed.provenance.unwrap();
        assert_eq!(refreshed.model, applied.model);
        assert_eq!(record.observed.evidence, second.models[0].evidence);
        provider.models[0] = refreshed.model;
        assert_no_publication(&home);
        home.publish(&provider);
        save_model_provenance(&home.0, &provider, std::slice::from_ref(&record)).unwrap();
        let loaded = load_model_provenance(&home.0, &provider).unwrap();
        assert_eq!(loaded, [record]);
        save_model_provenance(&home.0, &provider, &loaded).unwrap();
        assert_eq!(clock.calls(), 2);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models?scope=evidence-fixture HTTP/1.1",
            "GET /tenant/v1/models?scope=evidence-fixture HTTP/1.1",
        ]);
    }

    #[tokio::test]
    async fn evidence_clock_same_value_explicit_detail_refetch_renews_its_source() {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![model_response()]);
        let provider = fixture.provider(true);
        let clock = Clock::new([Some(500)]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let old = selected();
        let details = session.details(std::slice::from_ref(&old), true).await;
        assert_eq!(details.completeness, DiscoveryCompleteness::Complete);
        assert_eq!(details.models[0].context_window, old.context_window);
        assert_eq!(details.models[0].max_output_tokens, old.max_output_tokens);
        assert_fetched_evidence(&details.models[0], "anthropic_model_detail", 500, 500);
        assert_eq!(clock.calls(), 1);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models/evidence-model?scope=evidence-fixture HTTP/1.1",
        ]);
    }

    #[tokio::test]
    async fn evidence_clock_missing_detail_slot_does_not_refresh_other_selected_model() {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![model_response()]);
        let provider = fixture.provider(true);
        let clock = Clock::new([Some(700)]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let mut missing = selected();
        missing.max_output_tokens = None;
        missing.evidence.as_mut().unwrap().output_limit = None;
        let mut untouched = selected();
        untouched.id = "unfetched-model".into();
        let details = session.details(&[missing, untouched.clone()], false).await;
        assert_eq!(details.completeness, DiscoveryCompleteness::Complete);
        assert_eq!((details.considered, details.attempted), (2, 1));
        assert_fetched_evidence(&details.models[0], "anthropic_model_detail", 700, 700);
        assert_eq!(details.models[1], untouched);
        assert_eq!(clock.calls(), 1);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models/evidence-model?scope=evidence-fixture HTTP/1.1",
        ]);
    }

    #[tokio::test]
    async fn evidence_clock_complete_unfetched_detail_keeps_historical_age() {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![]);
        let provider = fixture.provider(true);
        let clock = Clock::new([]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let old = selected();
        let details = session.details(std::slice::from_ref(&old), false).await;
        assert_eq!(details.models, [old]);
        assert_eq!(details.completeness, DiscoveryCompleteness::Complete);
        assert_eq!(details.attempted, 0);
        assert_eq!(clock.calls(), 0);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[]);
    }

    #[tokio::test]
    async fn evidence_clock_wrong_detail_id_preserves_selected_and_does_not_read_time() {
        let home = Home::new();
        let mut wrong = model_response();
        wrong["id"] = "different-model".into();
        let mut fixture = Fixture::new(vec![wrong]);
        let provider = fixture.provider(true);
        let clock = Clock::new([]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let old = selected();
        let details = session.details(std::slice::from_ref(&old), true).await;
        assert_eq!(details.models, [old]);
        assert_eq!(details.completeness, DiscoveryCompleteness::Incomplete);
        assert!(
            details
                .issues
                .iter()
                .any(|issue| issue.kind == DiscoveryIssueKind::DetailIdentityMismatch)
        );
        assert_eq!(clock.calls(), 0);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models/evidence-model?scope=evidence-fixture HTTP/1.1",
        ]);
    }

    #[tokio::test]
    async fn evidence_clock_invalid_numeric_catalog_and_detail_never_gain_evidence() {
        let home = Home::new();
        let mut malformed = model_response();
        malformed["max_tokens"] = "200".into();
        let mut fixture = Fixture::new(vec![
            json!({"data":[malformed.clone()],"has_more":false}),
            malformed,
        ]);
        let provider = fixture.provider(true);
        let clock = Clock::new([]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let catalog = session.catalog().await;
        let details = session.details(&[selected()], true).await;
        for model in [&catalog.models[0], &details.models[0]] {
            assert!(!model.metadata_valid);
            assert!(model.evidence.is_none());
        }
        assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
        assert_eq!(details.completeness, DiscoveryCompleteness::Incomplete);
        assert_eq!(clock.calls(), 0);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models?scope=evidence-fixture HTTP/1.1",
            "GET /tenant/v1/models/evidence-model?scope=evidence-fixture HTTP/1.1",
        ]);
    }

    #[tokio::test]
    async fn evidence_clock_pre_cancelled_calls_preserve_age_and_read_no_time() {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![]);
        let provider = fixture.provider(true);
        let clock = Clock::new([]);
        let cancel = CancelToken::new();
        cancel.cancel();
        let session = DiscoverySession::new_with_lookup(
            &home.0,
            &provider,
            DiscoveryProfile::Anthropic,
            None,
            cancel,
            |_| panic!("unexpected ENV lookup"),
        )
        .unwrap()
        .with_observation_clock(clock.clone());
        let catalog = session.catalog().await;
        let old = selected();
        let details = session.details(std::slice::from_ref(&old), true).await;
        assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
        assert_eq!(details.completeness, DiscoveryCompleteness::Incomplete);
        assert_eq!(details.models, [old]);
        assert_eq!(details.attempted, 0);
        assert_eq!(clock.calls(), 0);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[]);
    }

    #[tokio::test]
    async fn evidence_clock_failure_is_explicit_and_cannot_renew_selected_age() {
        let home = Home::new();
        let mut fixture = Fixture::new(vec![catalog_response(), model_response()]);
        let provider = fixture.provider(true);
        let clock = Clock::new([None, None]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let catalog = session.catalog().await;
        let old = selected();
        let details = session.details(std::slice::from_ref(&old), true).await;
        assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
        assert!(catalog.models[0].metadata_valid);
        assert_eq!(catalog.models[0].context_window, Some(CONTEXT));
        assert!(catalog.models[0].evidence.is_none());
        assert_eq!(details.completeness, DiscoveryCompleteness::Incomplete);
        assert_eq!(details.models, [old]);
        for issues in [&catalog.issues, &details.issues] {
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.kind == DiscoveryIssueKind::ObservationTimeUnavailable)
            );
        }
        assert_eq!(clock.calls(), 2);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models?scope=evidence-fixture HTTP/1.1",
            "GET /tenant/v1/models/evidence-model?scope=evidence-fixture HTTP/1.1",
        ]);
    }

    #[tokio::test]
    async fn evidence_clock_identical_page_duplicate_uses_actual_later_stamp_even_backwards() {
        let home = Home::new();
        let mut first = catalog_response();
        first["has_more"] = true.into();
        let mut fixture = Fixture::new(vec![first, catalog_response()]);
        let provider = fixture.provider(true);
        let clock = Clock::new([Some(300), Some(200)]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let catalog = session.catalog().await;
        assert_eq!(catalog.completeness, DiscoveryCompleteness::Complete);
        assert_eq!(catalog.models.len(), 1);
        assert_fetched_evidence(&catalog.models[0], "anthropic_models", 200, 200);
        assert_eq!(clock.calls(), 2);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models?scope=evidence-fixture HTTP/1.1",
            "GET /tenant/v1/models?scope=evidence-fixture&after_id=evidence-model HTTP/1.1",
        ]);
    }

    #[tokio::test]
    async fn evidence_clock_conflicting_page_duplicate_clears_disputed_fresh_evidence() {
        let home = Home::new();
        let mut first = catalog_response();
        first["has_more"] = true.into();
        let mut second = catalog_response();
        second["data"][0]["max_input_tokens"] = (CONTEXT + 1).into();
        let mut fixture = Fixture::new(vec![first, second]);
        let provider = fixture.provider(true);
        let clock = Clock::new([Some(100), Some(200)]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let catalog = session.catalog().await;
        assert_eq!(catalog.completeness, DiscoveryCompleteness::Incomplete);
        assert!(
            catalog
                .issues
                .iter()
                .any(|issue| issue.kind == DiscoveryIssueKind::ConflictingDuplicate)
        );
        assert_eq!(catalog.models.len(), 1);
        assert!(catalog.models[0].evidence.is_none());
        assert_eq!(clock.calls(), 2);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models?scope=evidence-fixture HTTP/1.1",
            "GET /tenant/v1/models?scope=evidence-fixture&after_id=evidence-model HTTP/1.1",
        ]);
    }

    #[tokio::test]
    async fn evidence_clock_partial_detail_stamps_only_returned_numeric_component() {
        let home = Home::new();
        let mut response = model_response();
        response["max_input_tokens"] = Value::Null;
        let mut fixture = Fixture::new(vec![response]);
        let provider = fixture.provider(true);
        let clock = Clock::new([Some(900)]);
        let session = session(&home, &provider).with_observation_clock(clock.clone());
        let details = session.details(&[selected()], true).await;
        assert_eq!(details.completeness, DiscoveryCompleteness::Complete);
        assert_eq!(details.models[0].context_window, None);
        let evidence = details.models[0].evidence.as_ref().unwrap();
        assert!(evidence.context_limit.is_none());
        let output = evidence.output_limit.as_ref().unwrap();
        assert_eq!(output.value, OUTPUT);
        assert_eq!(output.observed_at_unix, 900);
        assert_eq!(clock.calls(), 1);
        assert_no_publication(&home);
        fixture.finish();
        fixture.assert_requests(&[
            "GET /tenant/v1/models/evidence-model?scope=evidence-fixture HTTP/1.1",
        ]);
    }
}
