use orbit_adapter::types::EffortValue;
use orbit_engine::{ProviderKind, TurnConfig};

fn config() -> TurnConfig {
    TurnConfig {
        provider_id: "fixture".into(),
        gate: "http://127.0.0.1:1".into(),
        model: "fixture-model".into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 64,
        sampling: None,
        effort: None,
        supported_efforts: None,
        first_byte_timeout_ms: None,
        idle_timeout_ms: None,
    }
}

#[test]
fn unknown_unsupported_and_exact_typed_capabilities_are_distinct() {
    let mut cfg = config();
    assert!(cfg.validate_effort().is_ok());
    cfg.effort = Some(EffortValue::Level("high".into()));
    assert!(cfg.validate_effort().unwrap_err().contains("unknown"));
    cfg.supported_efforts = Some(vec![]);
    assert!(cfg.validate_effort().unwrap_err().contains("unsupported"));
    cfg.supported_efforts = Some(vec![EffortValue::Level("low".into())]);
    assert!(cfg.validate_effort().unwrap_err().contains("not supported"));
    cfg.supported_efforts = Some(vec![EffortValue::Level("high".into())]);
    assert!(cfg.validate_effort().is_ok());
    cfg.kind = ProviderKind::Ollama;
    cfg.effort = Some(EffortValue::Bool(false));
    cfg.supported_efforts = Some(vec![EffortValue::Level("false".into())]);
    assert!(cfg.validate_effort().is_err());
    cfg.supported_efforts = Some(vec![EffortValue::Bool(false)]);
    assert!(cfg.validate_effort().is_ok());
}

#[test]
fn malformed_or_duplicate_metadata_and_wrong_wire_types_reject() {
    let mut cfg = config();
    cfg.supported_efforts = Some(vec![EffortValue::Level(" high".into())]);
    assert!(cfg.validate_effort().is_err());
    cfg.supported_efforts = Some(vec![EffortValue::Level("high".into()); 2]);
    assert!(cfg.validate_effort().unwrap_err().contains("duplicate"));
    cfg.supported_efforts = Some(vec![EffortValue::Bool(false)]);
    assert!(cfg.validate_effort().is_err());
    cfg.kind = ProviderKind::Anthropic;
    cfg.supported_efforts = Some(vec![EffortValue::Level("none".into())]);
    assert!(cfg.validate_effort().is_err());
}

#[test]
fn invalid_dispatch_is_rejected_before_url_or_ledger_work() {
    let home = std::env::temp_dir().join(format!("orbit-invalid-effort-{}", ulid::Ulid::new()));
    let mut cfg = config();
    cfg.gate = "not a URL".into();
    cfg.effort = Some(EffortValue::Level("high".into()));
    let error = orbit_engine::run_dispatch(
        &home,
        &cfg,
        "hello",
        None,
        None,
        orbit_provider_http::CancelToken::new(),
        vec![],
        "fixture",
        "fixture",
    )
    .unwrap_err();
    assert!(error.1.contains("unknown"));
    assert!(!home.exists());
}

#[test]
fn effort_reaches_every_dispatch_and_reset_omits_it() {
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (addr, state, handle) = orbit_mock_provider::spawn().await.unwrap();
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            tx.send((addr, state, stop_tx)).unwrap();
            let _ = stop_rx.await;
            handle.abort();
        });
    });
    let (addr, state, stop) = rx.recv().unwrap();
    let home = std::env::temp_dir().join(format!("orbit-effort-dispatch-{}", ulid::Ulid::new()));
    std::fs::create_dir_all(&home).unwrap();
    let mut cfg = config();
    cfg.gate = format!("http://{addr}");
    cfg.effort = Some(EffortValue::Level("high".into()));
    cfg.supported_efforts = Some(vec![EffortValue::Level("high".into())]);
    for _ in 0..2 {
        orbit_engine::run_dispatch(
            &home,
            &cfg,
            "hello",
            None,
            None,
            orbit_provider_http::CancelToken::new(),
            vec![],
            "fixture",
            "fixture",
        )
        .unwrap();
        assert_eq!(
            state.last_body.lock().unwrap().as_ref().unwrap()["reasoning_effort"],
            "high"
        );
    }
    cfg.effort = None;
    orbit_engine::run_dispatch(
        &home,
        &cfg,
        "hello",
        None,
        None,
        orbit_provider_http::CancelToken::new(),
        vec![],
        "fixture",
        "fixture",
    )
    .unwrap();
    assert!(
        state
            .last_body
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .get("reasoning_effort")
            .is_none()
    );
    assert_eq!(state.requests.load(std::sync::atomic::Ordering::SeqCst), 3);
    stop.send(()).unwrap();
    worker.join().unwrap();
    std::fs::remove_dir_all(home).unwrap();
}
