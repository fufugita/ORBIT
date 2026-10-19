#![cfg(target_os = "linux")]
#![deny(unsafe_code)]
use orbit_cli::provider_policies::{PolicyError, load_for_config};
use orbit_engine::retry::{FinalRejectionSelector, RetryPolicyBinding, adapter_identity_digest};
use orbit_engine::{ProviderKind, TurnConfig};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

fn require_private_system_fixture() {
    // Check descriptors/namespace identity BEFORE opening managed content,
    // creating a fixture, spawning a provider or starting any caller.
    let descriptor = |name: &str| {
        let value: u32 = std::env::var(name)
            .expect("isolated runner descriptor missing")
            .parse()
            .unwrap();
        assert!(value < 4096);
        fs::metadata(format!("/proc/self/fd/{value}")).unwrap()
    };
    let parent_mount = descriptor("ORBIT_ACTIVATION_PARENT_MOUNT_FD");
    let parent_user = descriptor("ORBIT_ACTIVATION_PARENT_USER_FD");
    let own_mount = fs::metadata("/proc/self/ns/mnt").unwrap();
    let own_user = fs::metadata("/proc/self/ns/user").unwrap();
    assert_ne!(
        (parent_mount.dev(), parent_mount.ino()),
        (own_mount.dev(), own_mount.ino())
    );
    assert_ne!(
        (parent_user.dev(), parent_user.ino()),
        (own_user.dev(), own_user.ino())
    );
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        mounts.lines().any(
            |line| line.split_whitespace().nth(4) == Some("/etc") && line.contains(" - tmpfs ")
        )
    );
    let expected = std::env::var("ORBIT_ACTIVATION_MANAGED_MARKER").unwrap();
    assert!(expected.starts_with("ORBIT_ACTIVATION_MANAGED_") && expected.len() <= 128);
    assert!(
        expected
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    let path = Path::new("/etc/orbit/ORBIT.md");
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert!(metadata.len() <= 128);
    assert_eq!(fs::read(path).unwrap(), expected.as_bytes());
    assert_eq!(fs::read_dir("/etc/orbit").unwrap().count(), 1);
    let root =
        PathBuf::from(std::env::var_os("ORBIT_ACTIVATION_ROOT").expect("private root missing"));
    assert!(root.is_absolute());
    assert_eq!(root.canonicalize().unwrap(), root);
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("oc-")
    );
    assert_eq!(fs::symlink_metadata(&root).unwrap().mode() & 0o777, 0o700);
    for name in [
        "HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "TMPDIR",
    ] {
        let path = PathBuf::from(std::env::var_os(name).expect("private user path missing"));
        assert!(path.is_absolute() && path.starts_with(&root) && path != root);
        assert_eq!(path.canonicalize().unwrap(), path);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.mode() & 0o777, 0o700);
    }
    assert!(std::env::current_dir().unwrap().starts_with(&root));
    for name in [
        "ORBIT_HOME",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_BASE_URL",
        "OPENAI_BASE_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        assert!(
            std::env::var_os(name).is_none(),
            "runner did not clear an inherited provider setting"
        );
    }
}

struct Home {
    root: PathBuf,
    home: PathBuf,
}
impl Home {
    fn new() -> Self {
        assert_eq!(
            std::env::var("ORBIT_ACTIVATION_ISOLATED").as_deref(),
            Ok("1")
        );
        assert_eq!(
            std::env::var("ORBIT_ACTIVATION_RUNNER_DEPTH").as_deref(),
            Ok("1")
        );
        require_private_system_fixture();
        let root = std::env::temp_dir().join(format!("orbit-policy-loader-{}", ulid::Ulid::new()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let home = root.join("home");
        fs::DirBuilder::new().mode(0o700).create(&home).unwrap();
        private_file(
            &home.join("providers.toml"),
            b"# preserved provider fixture\n",
        );
        Self { root, home }
    }
    fn load(&self, config: &TurnConfig) -> Result<Option<RetryPolicyBinding>, PolicyError> {
        let providers = fs::read(self.home.join("providers.toml")).unwrap();
        let files = inventory(&self.home);
        let result = load_for_config(&self.home, config);
        assert_eq!(
            fs::read(self.home.join("providers.toml")).unwrap(),
            providers
        );
        assert_eq!(inventory(&self.home), files);
        result
    }
    fn path(&self) -> PathBuf {
        self.home.join("provider-policies.toml")
    }
    fn write(&self, bytes: &[u8]) {
        let path = self.path();
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        private_file(&path, bytes);
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn config() -> TurnConfig {
    TurnConfig {
        provider_id: "fixture-provider".into(),
        model: "fixture/raw".into(),
        gate: "http://127.0.0.1:9/v1?a=1&b=%2F".into(),
        kind: ProviderKind::OpenAiCompatible,
        credential_env: None,
        pricing: None,
        max_output_tokens: 73,
        sampling: None,
        effort: None,
        supported_efforts: None,
    }
}
fn entry(config: &TurnConfig, id: &str) -> Value {
    json!({"id":id,"provider":config.provider_id,"model":config.model,"endpoint":config.gate,
        "adapter_identity_sha256":adapter_identity_digest(&orbit_provider_http::openai::openai_identity()),
        "statuses":[429,500,502,503,504,529],"scope":"ordinary","generation":"final_rejection","billing":"unknown","allow_uncapped_retry":true,"max_attempts":2})
}
fn document(entries: Vec<Value>) -> Vec<u8> {
    toml::to_string(&json!({"version":1,"final_rejection":entries}))
        .unwrap()
        .into_bytes()
}
fn inventory(path: &Path) -> Vec<(String, u64, u32)> {
    let mut values: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let m = fs::symlink_metadata(entry.path()).unwrap();
            (
                entry.file_name().to_str().unwrap().to_owned(),
                m.len(),
                m.mode(),
            )
        })
        .collect();
    values.sort();
    values
}
fn selector(entry: &Value) -> FinalRejectionSelector {
    FinalRejectionSelector::new(
        entry["provider"].as_str().unwrap().into(),
        entry["model"].as_str().unwrap().into(),
        entry["endpoint"].as_str().unwrap().into(),
        entry["adapter_identity_sha256"].as_str().unwrap().into(),
    )
    .unwrap()
}

#[test]
fn absent_and_empty_policy_documents_do_not_create_state() {
    let f = Home::new();
    let c = config();
    let absent = f.root.join("absent");
    let before = inventory(&f.root);
    assert!(load_for_config(&absent, &c).unwrap().is_none());
    assert_eq!(inventory(&f.root), before);
    assert!(!absent.exists());
    let nested = f.root.join("normal-missing/nested/home");
    let before = inventory(&f.root);
    assert!(load_for_config(&nested, &c).unwrap().is_none());
    assert_eq!(inventory(&f.root), before);
    assert!(!f.root.join("normal-missing").exists());
    for kind in [
        "symlink-ancestor",
        "dangling-ancestor",
        "parent-component",
        "dot-component",
    ] {
        let path = match kind {
            "symlink-ancestor" => {
                let link = f.root.join("link-existing");
                symlink(&f.home, &link).unwrap();
                link.join("missing")
            }
            "dangling-ancestor" => {
                let link = f.root.join("link-dangling");
                symlink(f.root.join("absent-target"), &link).unwrap();
                link.join("missing")
            }
            "parent-component" => f.root.join("missing/../leaf"),
            "dot-component" => PathBuf::from("./missing-policy-home"),
            _ => unreachable!(),
        };
        let before = inventory(&f.root);
        assert_eq!(
            load_for_config(&path, &c).unwrap_err(),
            PolicyError::UnsafeStorage
        );
        assert_eq!(inventory(&f.root), before);
    }
    let before = inventory(&f.home);
    assert!(f.load(&c).unwrap().is_none());
    assert_eq!(inventory(&f.home), before);
    for bytes in [
        b"version=1\n".as_slice(),
        b"version=1\nfinal_rejection=[]\n".as_slice(),
    ] {
        f.write(bytes);
        let before = inventory(&f.home);
        assert!(f.load(&c).unwrap().is_none());
        assert_eq!(inventory(&f.home), before);
        assert_eq!(fs::read(f.path()).unwrap(), bytes);
    }
    for bytes in [b"".as_slice(), b"final_rejection=[]\n".as_slice()] {
        f.write(bytes);
        assert_eq!(f.load(&c).unwrap_err(), PolicyError::InvalidDocument);
    }
}

#[test]
fn exact_selection_uses_actual_provider_model_endpoint_and_identity() {
    let f = Home::new();
    let c = config();
    let e = entry(&c, "selected");
    f.write(&document(vec![e.clone()]));
    let bound = f.load(&c).unwrap().unwrap();
    assert_eq!(bound.max_attempts(), 2);
    for field in ["provider", "model", "endpoint", "adapter_identity_sha256"] {
        let mut changed = e.clone();
        changed[field] = json!(match field {
            "provider" => "Fixture-provider",
            "model" => "Fixture/raw",
            "endpoint" => "http://127.0.0.1:9/other?a=1&b=%2F",
            _ => "0",
        });
        if field == "adapter_identity_sha256" {
            changed[field] = json!("0".repeat(64));
        }
        f.write(&document(vec![changed]));
        assert!(f.load(&c).unwrap().is_none());
    }
    f.write(&document(vec![e]));
    for kind in [ProviderKind::Anthropic, ProviderKind::Ollama] {
        let mut selected = c.clone();
        selected.kind = kind;
        assert!(f.load(&selected).unwrap().is_none());
    }
}

#[test]
fn canonical_endpoints_preserve_raw_query_and_reject_overlap() {
    let f = Home::new();
    let mut c = config();
    c.gate = "http://127.0.0.1:9".into();
    let a = entry(&c, "a");
    let mut b = a.clone();
    b["id"] = json!("b");
    b["endpoint"] = json!("http://127.0.0.1:9/v1/");
    assert_eq!(
        selector(&a).canonical_endpoint().unwrap(),
        selector(&b).canonical_endpoint().unwrap()
    );
    f.write(&document(vec![a.clone(), b.clone()]));
    assert_eq!(f.load(&c).unwrap_err(), PolicyError::DuplicateSelector);
    let mut stale_a = a.clone();
    stale_a["adapter_identity_sha256"] = json!("0".repeat(64));
    let mut stale_b = b.clone();
    stale_b["adapter_identity_sha256"] = json!("0".repeat(64));
    f.write(&document(vec![stale_a.clone(), stale_b]));
    assert_eq!(f.load(&c).unwrap_err(), PolicyError::DuplicateSelector);
    f.write(&document(vec![stale_a, b.clone()]));
    assert!(f.load(&c).unwrap().is_some());
    let mut q = a.clone();
    q["endpoint"] = json!("http://127.0.0.1:9/v1?a=1&b=%2F");
    for endpoint in [
        "http://127.0.0.1:9/v1?b=%2F&a=1",
        "http://127.0.0.1:9/v1?a=1&b=%2f",
    ] {
        let mut other = q.clone();
        other["id"] = json!("other");
        other["endpoint"] = json!(endpoint);
        assert_ne!(
            selector(&q).canonical_endpoint().unwrap(),
            selector(&other).canonical_endpoint().unwrap()
        );
        f.write(&document(vec![q.clone(), other]));
        assert!(f.load(&c).unwrap().is_none());
    }
}

#[test]
fn whole_file_validation_includes_inactive_declarations() {
    let f = Home::new();
    let c = config();
    let active = entry(&c, "active");
    for (field, value) in [
        ("statuses", json!([501])),
        ("scope", json!("summary")),
        ("generation", json!("maybe")),
        ("billing", json!("free")),
        ("allow_uncapped_retry", json!(false)),
        ("max_attempts", json!(1)),
        ("max_attempts", json!(9)),
        ("adapter_identity_sha256", json!("BAD")),
    ] {
        let mut inactive = entry(&c, "inactive");
        inactive["provider"] = json!("inactive-provider");
        inactive[field] = value;
        f.write(&document(vec![active.clone(), inactive]));
        assert!(f.load(&c).is_err(), "invalid inactive {field}");
        let mut unsupported = c.clone();
        unsupported.kind = ProviderKind::Anthropic;
        assert!(f.load(&unsupported).is_err());
    }
}

#[test]
fn duplicate_keys_ids_and_unknown_fields_are_errors() {
    let f = Home::new();
    let c = config();
    let a = entry(&c, "same");
    let mut b = a.clone();
    b["model"] = json!("different/raw");
    f.write(&document(vec![a.clone(), b]));
    assert_eq!(f.load(&c).unwrap_err(), PolicyError::InvalidDocument);
    for bytes in [
        b"version=1\nversion=1\n".to_vec(),
        b"version=2\n".to_vec(),
        b"version='1'\n".to_vec(),
        b"version=1\nunknown=true\n".to_vec(),
        b"version=1\nfinal_rejection='wrong'\n".to_vec(),
    ] {
        f.write(&bytes);
        assert!(f.load(&c).is_err());
    }
    for field in a.as_object().unwrap().keys() {
        let mut missing = a.clone();
        missing.as_object_mut().unwrap().remove(field);
        f.write(&document(vec![missing]));
        assert!(f.load(&c).is_err(), "missing required {field}");
    }
    for (field, value) in [
        ("unknown", json!("wrong-type")),
        ("statuses", json!("wrong-type")),
        ("max_attempts", json!("wrong-type")),
        ("model", json!(false)),
    ] {
        let mut bad = a.clone();
        bad[field] = value;
        f.write(&document(vec![bad]));
        assert!(f.load(&c).is_err(), "invalid field type or key: {field}");
    }
    let mut bytes = document(vec![a]);
    bytes.extend_from_slice(b"id='duplicate'\n");
    f.write(&bytes);
    assert!(f.load(&c).is_err());
}

#[test]
fn document_and_declaration_bounds_are_exact() {
    let f = Home::new();
    let c = config();
    let declarations: Vec<_> = (0..128)
        .map(|index| {
            let mut e = entry(&c, &format!("id-{index}"));
            e["provider"] = json!(format!("provider-{index}"));
            e
        })
        .collect();
    let bytes = document(declarations.clone());
    assert!(bytes.len() < 131072);
    f.write(&bytes);
    assert!(f.load(&c).unwrap().is_none());
    let mut too_many = declarations;
    let mut extra = entry(&c, "extra");
    extra["provider"] = json!("provider-extra");
    too_many.push(extra);
    f.write(&document(too_many));
    assert!(f.load(&c).is_err());
    let mut exact = b"version=1\n#".to_vec();
    exact.resize(131072, b'x');
    f.write(&exact);
    assert!(f.load(&c).unwrap().is_none());
    exact.push(b'x');
    f.write(&exact);
    assert_eq!(f.load(&c).unwrap_err(), PolicyError::TooLarge);
    f.write(&[0xff, 0xfe]);
    assert_eq!(f.load(&c).unwrap_err(), PolicyError::InvalidEncoding);
    for (field, limit) in [("id", 128), ("provider", 128), ("model", 256)] {
        let mut e = entry(&c, "bounds");
        e[field] = json!("a".repeat(limit));
        f.write(&document(vec![e.clone()]));
        assert!(f.load(&c).is_ok());
        e[field] = json!("a".repeat(limit + 1));
        f.write(&document(vec![e]));
        assert!(f.load(&c).is_err());
    }
    let mut endpoint = entry(&c, "endpoint-bound");
    let prefix = "http://127.0.0.1:9/";
    endpoint["endpoint"] = json!(format!("{prefix}{}", "a".repeat(2048 - prefix.len())));
    f.write(&document(vec![endpoint.clone()]));
    assert!(f.load(&c).is_ok());
    endpoint["endpoint"] = json!(format!("{prefix}{}", "a".repeat(2049 - prefix.len())));
    f.write(&document(vec![endpoint]));
    assert!(f.load(&c).is_err());
    let mut maximum = entry(&c, "maximum-attempts");
    maximum["max_attempts"] = json!(8);
    f.write(&document(vec![maximum]));
    assert_eq!(f.load(&c).unwrap().unwrap().max_attempts(), 8);
    for statuses in [
        json!([]),
        json!([503, 503]),
        json!([503, 500]),
        json!([200]),
    ] {
        let mut e = entry(&c, "statuses");
        e["statuses"] = statuses;
        f.write(&document(vec![e]));
        assert!(f.load(&c).is_err());
    }
}

#[test]
fn unsafe_policy_storage_is_not_absent() {
    for kind in [
        "symlink",
        "dangling",
        "hardlink",
        "directory",
        "socket",
        "mode",
        "home-mode",
        "home-symlink",
    ] {
        let f = Home::new();
        let c = config();
        let bytes = document(vec![entry(&c, "selected")]);
        let target = f.root.join("owned-target");
        private_file(&target, &bytes);
        let socket = if kind == "socket" {
            let short = f.root.join("s");
            let socket = UnixListener::bind(&short).unwrap();
            fs::rename(short, f.path()).unwrap();
            Some(socket)
        } else {
            None
        };
        match kind {
            "symlink" => symlink(&target, f.path()).unwrap(),
            "dangling" => symlink(f.root.join("missing"), f.path()).unwrap(),
            "hardlink" => fs::hard_link(&target, f.path()).unwrap(),
            "directory" => fs::DirBuilder::new().mode(0o700).create(f.path()).unwrap(),
            "socket" => {}
            "mode" => {
                f.write(&bytes);
                fs::set_permissions(f.path(), fs::Permissions::from_mode(0o644)).unwrap();
            }
            "home-mode" => {
                f.write(&bytes);
                fs::set_permissions(&f.home, fs::Permissions::from_mode(0o755)).unwrap();
            }
            "home-symlink" => {
                let retained = f.root.join("retained");
                fs::rename(&f.home, &retained).unwrap();
                symlink(&retained, &f.home).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(f.load(&c).is_err(), "unsafe {kind} treated as absent");
        drop(socket);
    }
}

#[test]
fn errors_are_nonsecret_and_providers_file_is_unchanged() {
    let f = Home::new();
    let c = config();
    let marker = "POLICY_SECRET_MARKER";
    let providers = f.home.join("providers.toml");
    let before = fs::read(&providers).unwrap();
    let mut bad = entry(&c, "bad");
    bad["endpoint"] = json!(format!("http://127.0.0.1:9/{marker}"));
    bad["scope"] = json!(marker);
    let mut bytes = document(vec![bad]);
    bytes.extend_from_slice(format!("# {marker}\n").as_bytes());
    f.write(&bytes);
    let files = inventory(&f.home);
    let error = f.load(&c).unwrap_err();
    for visible in [error.to_string(), format!("{error:?}")] {
        assert!(!visible.contains(marker));
        assert!(!visible.contains("127.0.0.1"));
        assert!(!visible.contains(f.root.to_str().unwrap()));
        assert!(visible.len() < 256);
    }
    assert_eq!(fs::read(&providers).unwrap(), before);
    assert_eq!(fs::read(f.path()).unwrap(), bytes);
    assert_eq!(inventory(&f.home), files);
}
