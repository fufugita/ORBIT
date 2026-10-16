//! Offline, validated, idempotent initialization using ORBIT's existing identity formats.
use crate::config::{ProviderConfig, ProvidersConfig};
use crate::customization::{Directory, Error, Lock, io_error, publish, read_regular};
use ed25519_dalek::{Signer, SigningKey};
use orbit_ledger::event::SessionStart;
use orbit_ledger::{LedgerEvent, LedgerWriter};
use orbit_pib::{PibIdentity, PibRegistry};
use orbit_trust::manifest::{MANIFEST_SCHEMA, TrustRootManifestBody};
use orbit_trust::{RootPublicKey, TrustRootManifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SetupRequest {
    pub provider: Option<ProviderConfig>,
    pub routing: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SetupPlan {
    pub initialize: bool,
    pub config_changed: bool,
    pub actions: Vec<String>,
    pub revision: String,
    #[serde(skip)]
    home: PathBuf,
    #[serde(skip)]
    request: SetupRequest,
    #[serde(skip)]
    main: Option<String>,
    #[serde(skip)]
    config: Vec<u8>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SetupReceipt {
    pub initialized: bool,
    pub reused: bool,
    pub config_changed: bool,
    pub pib_id: String,
    pub providers_configured: Vec<String>,
    pub trust_root_verified: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct RepairReport {
    pub missing: Vec<String>,
    pub repairable: Vec<String>,
    pub refuses_identity_regeneration: bool,
}
pub fn valid_env(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && (name.as_bytes()[0].is_ascii_alphabetic() || name.starts_with('_'))
}
fn env_name(name: &str) -> bool {
    valid_env(name) && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
pub fn validate_provider(provider: &ProviderConfig) -> Result<(), Error> {
    let invalid = |s: &str| Error::Invalid(s.into());
    if provider.name.is_empty()
        || provider.name.len() > 128
        || provider.name.trim() != provider.name
        || provider.name.contains('/')
        || provider.name.chars().any(char::is_control)
    {
        return Err(invalid(
            "provider name must be a bounded printable identity without a slash",
        ));
    }
    crate::config::validate_provider_endpoint(&provider.url).map_err(Error::Invalid)?;
    if !["openai-compatible", "anthropic", "ollama"].contains(&provider.kind.as_str()) {
        return Err(invalid("provider kind is unsupported"));
    }
    if provider.env.as_ref().is_some_and(|n| !env_name(n)) {
        return Err(invalid("credential ENV name is invalid"));
    }
    if provider.models.is_empty() || provider.models.len() > 128 {
        return Err(invalid("provider requires 1..128 explicit models"));
    }
    let mut ids = BTreeSet::new();
    for model in &provider.models {
        if model.id.is_empty()
            || model.id.len() > 256
            || model.id.chars().any(char::is_control)
            || !ids.insert(&model.id)
        {
            return Err(invalid(
                "model IDs must be unique printable strings of 1..256 bytes",
            ));
        }
        model
            .validate_effort(orbit_engine::ProviderKind::from_config(&provider.kind))
            .map_err(|_| invalid("model effort capability is invalid"))?;
    }
    Ok(())
}
fn exists(path: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(e)),
    }
}
pub(crate) fn optional_file(home: &Path, name: &str, max: usize) -> Result<Option<Vec<u8>>, Error> {
    if !exists(home)? {
        return Ok(None);
    }
    let root = Directory::open(home, true)?;
    let mut parent = Directory::open(home, true)?;
    let parts: Vec<_> = name.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        if !exists(&parent.io()?.join(part))? {
            return Ok(None);
        }
        parent = parent.child(part, false)?;
    }
    let file = parent.io()?.join(parts[parts.len() - 1]);
    if !exists(&file)? {
        return Ok(None);
    }
    // Older initialization wrote public PIB/config metadata with the process
    // umask. Preserve those bytes; only the signing key contains private key data.
    let bytes = read_regular(&file, max, name == "trust/operator.key")?;
    parent.check()?;
    root.check()?;
    Ok(Some(bytes))
}
pub fn verify_bounded_ledger(home: &Path) -> Result<(usize, String), Error> {
    let root = Directory::open(home, true)?;
    let ledger = root.child("ledger", false)?;
    let segments = ledger.child("segments", false)?;
    let mut names = Vec::new();
    for entry in std::fs::read_dir(segments.io()?).map_err(io_error)? {
        let e = entry.map_err(io_error)?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| Error::Invalid("ledger entry name is invalid".into()))?;
        if name.ends_with(".log") {
            if name.len() != 20 || u64::from_str_radix(&name[..16], 16).is_err() {
                return Err(Error::Invalid("ledger segment ordinal is invalid".into()));
            }
            names.push(name);
            if names.len() > 1024 {
                return Err(Error::Invalid("ledger exceeds 1024 segments".into()));
            }
        }
    }
    names.sort();
    let (mut total, mut records) = (0, 0);
    let mut prev = "0".repeat(64);
    for name in &names {
        let bytes = read_regular(&segments.io()?.join(name), 64 * 1024 * 1024, true)?;
        total += bytes.len();
        if total > 128 * 1024 * 1024 {
            return Err(Error::Invalid("ledger exceeds 128 MiB".into()));
        }
        let mut off = 0;
        while off < bytes.len() {
            if bytes.len() - off < 4 {
                return Err(Error::Invalid("ledger has a torn frame".into()));
            }
            let n = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if n > 1024 * 1024 || n > bytes.len() - off {
                return Err(Error::Invalid(
                    "ledger frame is torn or exceeds 1 MiB".into(),
                ));
            }
            let record: orbit_ledger::LedgerRecord =
                serde_json::from_slice(&bytes[off..off + n])
                    .map_err(|_| Error::Invalid("ledger record is invalid".into()))?;
            off += n;
            prev = orbit_ledger::validate_record(&record, &prev)
                .map_err(|_| Error::Invalid("ledger chain is invalid".into()))?;
            records += 1;
        }
    }
    segments.check()?;
    ledger.check()?;
    root.check()?;
    if records == 0 {
        return Err(Error::Invalid(
            "ledger has no identity initialization record".into(),
        ));
    }
    Ok((records, prev))
}
pub fn verify_identity(home: &Path) -> Result<PibIdentity, Error> {
    let key = optional_file(home, "trust/operator.key", 128)?
        .ok_or_else(|| Error::Invalid("missing trust/operator.key".into()))?;
    let key =
        hex::decode(key).map_err(|_| Error::Invalid("operator key encoding is invalid".into()))?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| Error::Invalid("operator key length is invalid".into()))?;
    let signing = SigningKey::from_bytes(&key);
    let root = RootPublicKey(hex::encode(signing.verifying_key().to_bytes()));
    let manifest: TrustRootManifest = serde_json::from_slice(
        &optional_file(home, "trust/manifest.json", 128 * 1024)?
            .ok_or_else(|| Error::Invalid("missing trust/manifest.json".into()))?,
    )
    .map_err(|_| Error::Invalid("trust manifest is invalid".into()))?;
    manifest
        .verify(std::slice::from_ref(&root))
        .map_err(|_| Error::Invalid("trust manifest signature is invalid".into()))?;
    let pib: PibIdentity = serde_json::from_slice(
        &optional_file(home, "pib.json", 128 * 1024)?
            .ok_or_else(|| Error::Invalid("missing pib.json".into()))?,
    )
    .map_err(|_| Error::Invalid("PIB identity is invalid".into()))?;
    if pib.public_key != root.0
        || !pib.pib_id.starts_with("pib-")
        || ulid::Ulid::from_string(&pib.pib_id[4..]).is_err()
    {
        return Err(Error::Invalid(
            "PIB identity does not match the operator key".into(),
        ));
    }
    verify_bounded_ledger(home)?;
    Ok(pib)
}
pub fn repair_dry_run(home: &Path) -> Result<RepairReport, Error> {
    if exists(home)? {
        let root = Directory::open(home, true)?;
        for name in ["trust", "ledger"] {
            if exists(&root.io()?.join(name))? {
                root.child(name, false)?;
            }
        }
    }
    let mut missing = Vec::new();
    for name in [
        "trust/operator.key",
        "trust/manifest.json",
        "pib.json",
        "ledger",
    ] {
        if !exists(&home.join(name))? {
            missing.push(name.into());
        }
    }
    Ok(RepairReport {
        missing,
        repairable: ["sessions", "projects", "mods"]
            .into_iter()
            .filter(|name| !home.join(name).exists())
            .map(str::to_string)
            .collect(),
        refuses_identity_regeneration: true,
    })
}
fn identity_state(home: &Path) -> Result<bool, Error> {
    if !exists(home)? {
        return Ok(false);
    }
    let _root = Directory::open(home, true)?;
    for name in ["trust", "ledger"] {
        if exists(&_root.io()?.join(name))? {
            _root.child(name, false)?;
        }
    }
    let mut count = 0;
    for name in [
        "trust/operator.key",
        "trust/manifest.json",
        "pib.json",
        "ledger",
    ] {
        if exists(&home.join(name))? {
            count += 1;
        }
    }
    if count == 0 {
        return Ok(false);
    }
    if count != 4 {
        return Err(Error::Invalid(format!(
            "partial identity; missing {}; use setup repair --dry-run; identity is never regenerated",
            repair_dry_run(home)?.missing.join(", ")
        )));
    }
    verify_identity(home)?;
    Ok(true)
}
fn revision(home: &Path) -> Result<String, Error> {
    let mut h = Sha256::new();
    for name in [
        "trust/operator.key",
        "trust/manifest.json",
        "pib.json",
        "providers.toml",
    ] {
        h.update(name);
        if let Some(bytes) = optional_file(home, name, 128 * 1024)? {
            h.update((bytes.len() as u64).to_be_bytes());
            h.update(bytes);
        } else {
            h.update(0u64.to_be_bytes());
        }
    }
    if exists(&home.join("ledger"))? {
        h.update(verify_bounded_ledger(home)?.1);
    }
    Ok(hex::encode(h.finalize()))
}
fn validate_main_patch(main: Option<&str>) -> Result<(), Error> {
    if let Some(main) = main
        && (main.is_empty()
            || main.len() > 641
            || main.trim() != main
            || main.chars().any(char::is_control)
            || !main
                .split_once('/')
                .is_some_and(|(provider, raw)| !provider.is_empty() && !raw.is_empty()))
    {
        return Err(Error::Invalid(
            "main default requires an exact qualified provider/model identity".into(),
        ));
    }
    Ok(())
}

fn merge_model_metadata(old: &toml::Value, new: &mut toml::Value) -> Result<(), Error> {
    let old = old
        .as_table()
        .ok_or_else(|| Error::Invalid("model entry must be a table".into()))?;
    let new = new
        .as_table_mut()
        .ok_or_else(|| Error::Invalid("model serialization must be a table".into()))?;
    let mut merged = old.clone();
    for key in [
        "id",
        "label",
        "pricing",
        "max_output_tokens",
        "context_window",
        "context_limits",
        "sampling",
        "supported_efforts",
        "default_effort",
    ] {
        merged.remove(key);
    }
    let mut pricing = old
        .get("pricing")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();
    for key in [
        "input_per_million_microdollars",
        "output_per_million_microdollars",
        "cache_read_per_million_microdollars",
        "cache_write_per_million_microdollars",
        "reasoning_per_million_microdollars",
        "request_flat_microdollars",
        "input_per_million_microcents",
        "output_per_million_microcents",
        "cache_read_per_million_microcents",
        "cache_write_per_million_microcents",
        "reasoning_per_million_microcents",
        "request_flat_microcents",
    ] {
        pricing.remove(key);
    }
    if let Some(incoming) = new.get("pricing").and_then(toml::Value::as_table) {
        pricing.extend(incoming.clone());
    }
    if !pricing.is_empty() {
        new.insert("pricing".into(), toml::Value::Table(pricing));
    }
    if let Some(incoming) = new.get("sampling").and_then(toml::Value::as_table) {
        let mut sampling = old
            .get("sampling")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        sampling.remove("temperature");
        sampling.remove("top_p");
        sampling.extend(incoming.clone());
        new.insert("sampling".into(), toml::Value::Table(sampling));
    }
    merged.extend(new.clone());
    *new = merged;
    Ok(())
}

fn merge_provider_models(old: &toml::Value, new: &mut toml::Value) -> Result<(), Error> {
    let Some(old_models) = old.get("models").and_then(toml::Value::as_array) else {
        return Ok(());
    };
    let new_models = new
        .get_mut("models")
        .and_then(toml::Value::as_array_mut)
        .ok_or_else(|| Error::Invalid("provider models must serialize as an array".into()))?;
    for model in new_models {
        let raw_id = model
            .get("id")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| Error::Invalid("model serialization requires an ID".into()))?;
        if let Some(existing) = old_models
            .iter()
            .find(|old| old.get("id").and_then(toml::Value::as_str) == Some(raw_id))
        {
            merge_model_metadata(existing, model)?;
        }
    }
    Ok(())
}

fn candidate(home: &Path, request: &SetupRequest, main: Option<&str>) -> Result<Vec<u8>, Error> {
    validate_main_patch(main)?;
    if let Some(p) = &request.provider {
        validate_provider(p)?;
    }
    let original = optional_file(home, "providers.toml", 128 * 1024)?;
    let text = std::str::from_utf8(original.as_deref().unwrap_or(b""))
        .map_err(|_| Error::Invalid("providers.toml is not UTF-8".into()))?;
    let mut value: toml::Value =
        toml::from_str(text).map_err(|_| Error::Invalid("providers.toml is invalid".into()))?;
    if let Some(provider) = &request.provider {
        let table = value
            .as_table_mut()
            .ok_or_else(|| Error::Invalid("provider config must be a table".into()))?;
        let list = table
            .entry("provider")
            .or_insert_with(|| toml::Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| Error::Invalid("provider config must be an array".into()))?;
        let mut new = toml::Value::try_from(provider)
            .map_err(|_| Error::Invalid("provider serialization failed".into()))?;
        if let Some(old) = list
            .iter_mut()
            .find(|p| p.get("name").and_then(toml::Value::as_str) == Some(provider.name.as_str()))
        {
            merge_provider_models(old, &mut new)?;
            let old = old
                .as_table_mut()
                .ok_or_else(|| Error::Invalid("provider entry must be a table".into()))?;
            for key in ["name", "kind", "url", "env", "models"] {
                old.remove(key);
            }
            old.extend(
                new.as_table()
                    .ok_or_else(|| Error::Invalid("provider serialization must be a table".into()))?
                    .clone(),
            );
        } else {
            list.push(new);
        }
    }
    if !request.routing.is_empty() {
        let table = value
            .as_table_mut()
            .ok_or_else(|| Error::Invalid("config must be a table".into()))?;
        let routing = table
            .entry("routing")
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .ok_or_else(|| Error::Invalid("routing must be a table".into()))?;
        for (key, target) in &request.routing {
            if !["easy", "hard"].contains(&key.as_str()) {
                return Err(Error::Invalid(
                    "setup routing keys are easy and hard".into(),
                ));
            }
            routing.insert(key.clone(), toml::Value::String(target.clone()));
        }
    }
    if let Some(main) = main {
        let roles = value
            .as_table_mut()
            .ok_or_else(|| Error::Invalid("config must be a table".into()))?
            .entry("roles")
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .ok_or_else(|| Error::Invalid("roles must be a table".into()))?;
        roles.insert("main".into(), toml::Value::String(main.to_owned()));
    }
    let output = if request.provider.is_none() && request.routing.is_empty() && main.is_none() {
        text.to_string()
    } else {
        toml::to_string_pretty(&value)
            .map_err(|_| Error::Invalid("configuration serialization failed".into()))?
    };
    if output.len() > 128 * 1024 {
        return Err(Error::Invalid("configuration exceeds 128 KiB".into()));
    }
    let cfg = ProvidersConfig::load_from_str(&output)
        .map_err(|_| Error::Invalid("complete provider configuration is invalid".into()))?;
    for p in &cfg.provider {
        validate_provider(p)?;
    }
    if let Some(main) = main {
        let resolved = crate::phase_routing::resolve_model(&cfg, main, None).map_err(|_| {
            Error::Invalid("main default must select an exact declared provider/model".into())
        })?;
        if resolved.qualified() != main {
            return Err(Error::Invalid(
                "main default must select an exact declared provider/model".into(),
            ));
        }
    }
    let mut names = BTreeSet::new();
    for p in &cfg.provider {
        if !names.insert(&p.name) {
            return Err(Error::Invalid("provider names are duplicated".into()));
        }
    }
    let routing = crate::phase_routing::parse_settings(&output)
        .map_err(|_| Error::Invalid("routing configuration is invalid".into()))?;
    crate::phase_routing::validate_settings(&cfg, &routing).map_err(|_| {
        Error::Invalid("configured provider, role or phase target is invalid or ambiguous".into())
    })?;
    Ok(output.into_bytes())
}
pub fn plan_setup(home: &Path, request: &SetupRequest) -> Result<SetupPlan, Error> {
    plan_setup_with_main(home, request, None)
}

/// Plan one provider/routing update and optional exact main-role patch together.
pub fn plan_setup_with_main(
    home: &Path,
    request: &SetupRequest,
    main: Option<&str>,
) -> Result<SetupPlan, Error> {
    // Request validation occurs before inspecting or creating storage.
    validate_main_patch(main)?;
    if let Some(p) = &request.provider {
        validate_provider(p)?;
    }
    if home.as_os_str().len() > 4096 {
        return Err(Error::UnsafePath("home path is too long".into()));
    }
    let config = candidate(home, request, main)?;
    let initialize = !identity_state(home)?;
    let old = optional_file(home, "providers.toml", 128 * 1024)?.unwrap_or_default();
    let config_changed = old != config;
    let mut actions = Vec::new();
    if initialize {
        actions.push(
            "Initialize local signing key, signed trust manifest, PIB and ledger once".into(),
        );
    }
    if config_changed {
        actions.push("Publish validated provider configuration with ENV references".into());
    }
    Ok(SetupPlan {
        initialize,
        config_changed,
        actions,
        revision: revision(home)?,
        home: home.to_path_buf(),
        request: request.clone(),
        main: main.map(str::to_owned),
        config,
    })
}
fn initialize(home: &Directory) -> Result<String, Error> {
    let stage_name = format!(".setup-stage-{}", ulid::Ulid::new());
    let stage = home.child(&stage_name, true)?;
    let mut published = false;
    let result = (|| {
        let trust = stage.child("trust", true)?;
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let root = RootPublicKey(hex::encode(key.verifying_key().to_bytes()));
        let body = TrustRootManifestBody {
            schema: MANIFEST_SCHEMA.into(),
            version: "0.1.0".into(),
            issuer_allowlist: vec![],
            routes: vec![],
            lifecycle: vec![],
            model_allowlist: BTreeSet::new(),
        };
        let signature = key.sign(
            &orbit_trust::canonical::canonical_bytes(&body)
                .map_err(|_| Error::Invalid("trust canonicalization failed".into()))?,
        );
        let manifest = TrustRootManifest {
            body,
            signature: hex::encode(signature.to_bytes()),
        };
        manifest
            .verify(std::slice::from_ref(&root))
            .map_err(|_| Error::Invalid("generated trust manifest failed verification".into()))?;
        publish(
            &trust,
            "operator.key",
            hex::encode(key.to_bytes()).as_bytes(),
            true,
        )?;
        publish(
            &trust,
            "manifest.json",
            &serde_json::to_vec_pretty(&manifest)
                .map_err(|_| Error::Invalid("manifest serialization failed".into()))?,
            true,
        )?;
        let mut registry = PibRegistry::new();
        let id = format!("pib-{}", ulid::Ulid::new());
        registry.register(
            id.clone(),
            "local".into(),
            root.0,
            hex::encode(Sha256::digest(b"local-host")),
            "root-1".into(),
        );
        publish(
            &stage,
            "pib.json",
            &serde_json::to_vec_pretty(registry.identity().unwrap())
                .map_err(|_| Error::Invalid("PIB serialization failed".into()))?,
            true,
        )?;
        let mut ledger = LedgerWriter::open(
            &stage.path().join("ledger"),
            "writer-init".into(),
            env!("CARGO_PKG_VERSION"),
        )
        .map_err(|_| Error::Io("initialize ledger".into()))?;
        ledger
            .append(LedgerEvent::SessionStart(SessionStart {
                session_id: "session-example".into(),
                restricted: false,
                pib_id: Some(id.clone()),
                policy_snapshot_id: manifest
                    .policy_snapshot_digest()
                    .map_err(|_| Error::Invalid("policy digest failed".into()))?,
                operator_principal: "local-user".into(),
            }))
            .map_err(|_| Error::Io("append identity ledger record".into()))?;
        ledger
            .close()
            .map_err(|_| Error::Io("close identity ledger".into()))?;
        private_tree(&stage.path().join("ledger"), 0)?;
        stage.sync()?;
        // Folder trust can exist before identity initialization. Preserve that
        // directory and all unrelated trust data, publishing only missing
        // identity files with no-replace semantics.
        let existing_trust = if exists(&home.io()?.join("trust"))? {
            Some(home.child("trust", false)?)
        } else {
            None
        };
        let entries: Vec<(&Directory, &Directory, &str)> = if let Some(target) = &existing_trust {
            vec![
                (&trust, target, "operator.key"),
                (&trust, target, "manifest.json"),
                (&stage, home, "pib.json"),
                (&stage, home, "ledger"),
            ]
        } else {
            vec![
                (&stage, home, "trust"),
                (&stage, home, "pib.json"),
                (&stage, home, "ledger"),
            ]
        };
        for (from, to, name) in entries {
            let operation = (|| rename_new(&from.io()?.join(name), &to.io()?.join(name)))();
            if let Err(error) = operation {
                return Err(if published {
                    Error::PublicationUncertain(format!(
                        "partial identity publication; staged artifacts retained: {error}"
                    ))
                } else {
                    error
                });
            }
            published = true;
            to.sync()
                .map_err(|e| Error::PublicationUncertain(e.to_string()))?;
            home.sync()
                .map_err(|e| Error::PublicationUncertain(e.to_string()))?;
        }
        Ok(id)
    })();
    if (!published || result.is_ok()) && stage.check().is_ok() && home.check().is_ok() {
        let _ = std::fs::remove_dir_all(stage.path());
    }
    result
}
fn rename_new(from: &Path, to: &Path) -> Result<(), Error> {
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(from.as_os_str().as_bytes())
        .map_err(|_| Error::UnsafePath("NUL path".into()))?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes())
        .map_err(|_| Error::UnsafePath("NUL path".into()))?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(())
}
fn private_tree(path: &Path, depth: usize) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    if depth > 4 {
        return Err(Error::Invalid(
            "initial ledger tree is unexpectedly deep".into(),
        ));
    }
    let m = std::fs::symlink_metadata(path).map_err(io_error)?;
    if m.file_type().is_symlink() {
        return Err(Error::UnsafePath("initial ledger symlink".into()));
    }
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if m.is_dir() { 0o700 } else { 0o600 }),
    )
    .map_err(io_error)?;
    if m.is_dir() {
        for e in std::fs::read_dir(path).map_err(io_error)? {
            private_tree(&e.map_err(io_error)?.path(), depth + 1)?;
        }
        Directory::open(path, true)?.sync()?;
    } else {
        std::fs::File::open(path)
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)?;
    }
    Ok(())
}
pub fn apply_setup(plan: &SetupPlan) -> Result<SetupReceipt, Error> {
    // Plan fields are not mutation authority: revalidate all captured input and state.
    let current = plan_setup_with_main(&plan.home, &plan.request, plan.main.as_deref())?;
    if current.revision != plan.revision || current.config != plan.config {
        return Err(Error::Busy);
    }
    if !current.initialize && !current.config_changed {
        return Ok(SetupReceipt {
            initialized: false,
            reused: true,
            config_changed: false,
            pib_id: verify_identity(&plan.home)?.pib_id,
            providers_configured: plan
                .request
                .provider
                .as_ref()
                .map(|p| vec![p.name.clone()])
                .unwrap_or_default(),
            trust_root_verified: true,
        });
    }
    let home = Directory::create(&plan.home)?;
    let _lock = Lock::acquire(&home, ".setup.lock")?;
    // Route/model/config writers share this lock; setup always takes setup
    // before config, while ordinary config changes take only config.
    let _config_lock = Lock::acquire(&home, ".config.lock")?;
    let current = plan_setup_with_main(&plan.home, &plan.request, plan.main.as_deref())?;
    if current.revision != plan.revision || current.config != plan.config {
        return Err(Error::Busy);
    }
    let initialized = current.initialize;
    let mut published = false;
    let result = (|| {
        let id = if initialized {
            let id = initialize(&home)?;
            published = true;
            id
        } else {
            verify_identity(&plan.home)?.pib_id
        };
        if current.config_changed {
            // publish already reports uncertainty after its own rename point.
            publish(&home, "providers.toml", &current.config, false)?;
            published = true;
        }
        home.check()?;
        let pib = verify_identity(&plan.home)?;
        home.check()?;
        if pib.pib_id != id {
            return Err(Error::Invalid("identity changed after setup".into()));
        }
        Ok(SetupReceipt {
            initialized,
            reused: !initialized,
            config_changed: current.config_changed,
            pib_id: id,
            providers_configured: plan
                .request
                .provider
                .as_ref()
                .map(|p| vec![p.name.clone()])
                .unwrap_or_default(),
            trust_root_verified: true,
        })
    })();
    result.map_err(|error| {
        if published && !matches!(error, Error::PublicationUncertain(_)) {
            Error::PublicationUncertain(format!(
                "setup publication may have committed; inspect before retrying: {error}"
            ))
        } else {
            error
        }
    })
}
