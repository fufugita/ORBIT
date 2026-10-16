use orbit_adapter::SecretBytes;
use orbit_adapter::provider_credentials::{
    ExpectedRevision, MAX_PROVIDER_KEY_BYTES, MAX_PROVIDER_RECORD_BYTES, MAX_PROVIDER_RECORDS,
    ProviderAuthIdentity, ProviderCredentialError as Error, ProviderCredentialRemoveResult,
    ProviderCredentialSource as Source, ProviderCredentialStatus as Status,
    ProviderCredentialStore,
};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_HOME: AtomicU64 = AtomicU64::new(0);
const KEY: &str = "synthetic-provider-secret-apple";
const SECOND_KEY: &str = "synthetic-provider-secret-orange";
const ENDPOINT: &str = "https://provider.invalid/v1/";

struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "orbit-provider-store-test-{}-{}",
                std::process::id(),
                NEXT_HOME.fetch_add(1, Ordering::Relaxed),
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("disposable home creation failed: {error}"),
            }
        }
        panic!("disposable home name limit reached")
    }

    fn store(&self) -> ProviderCredentialStore {
        ProviderCredentialStore::new(&self.0).unwrap()
    }

    fn directory(&self) -> PathBuf {
        self.0.join("auth/providers")
    }

    fn record(&self, identity: &ProviderAuthIdentity) -> PathBuf {
        self.directory()
            .join(format!("{}.credential", identity.binding_id()))
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn id() -> ProviderAuthIdentity {
    identity(
        "provider",
        "openai-compatible",
        ENDPOINT,
        Some("ORBIT_TEST_TOKEN"),
    )
}

fn identity(provider: &str, kind: &str, endpoint: &str, env: Option<&str>) -> ProviderAuthIdentity {
    ProviderAuthIdentity::new(provider, kind, endpoint, env).unwrap()
}

fn key(value: &str) -> SecretBytes {
    SecretBytes::new(value.as_bytes().to_vec())
}

fn absent(_: &str) -> Result<Option<SecretBytes>, Error> {
    Ok(None)
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn assert_saved(home: &Home, identity: &ProviderAuthIdentity, expected: &str) {
    let resolved = home.store().resolve_with(identity, absent).unwrap();
    assert_eq!(resolved.source(), Source::Saved);
    assert_eq!(
        resolved.into_secret().unwrap().expose(),
        expected.as_bytes()
    );
}

#[test]
fn exact_saved_binding_resolves_with_safe_status_and_private_modes() {
    let home = Home::new();
    let saved = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    assert!(saved.changed);
    assert_saved(&home, &id(), KEY);
    assert_eq!(
        home.store().status_with(&id(), absent),
        Status::Available {
            source: Source::Saved,
            revision: Some(saved.revision),
        }
    );
    for path in [home.0.join("auth"), home.directory()] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o7777,
            0o700
        );
    }
    assert_eq!(
        fs::metadata(home.record(&id()))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn each_identity_field_is_isolated_including_path_query_and_reference() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    for changed in [
        identity(
            "other",
            "openai-compatible",
            ENDPOINT,
            Some("ORBIT_TEST_TOKEN"),
        ),
        identity("provider", "anthropic", ENDPOINT, Some("ORBIT_TEST_TOKEN")),
        identity(
            "provider",
            "openai-compatible",
            "https://elsewhere.invalid/v1/",
            Some("ORBIT_TEST_TOKEN"),
        ),
        identity(
            "provider",
            "openai-compatible",
            "https://provider.invalid/v2/",
            Some("ORBIT_TEST_TOKEN"),
        ),
        identity(
            "provider",
            "openai-compatible",
            "https://provider.invalid/v1/?scope=other",
            Some("ORBIT_TEST_TOKEN"),
        ),
        identity(
            "provider",
            "openai-compatible",
            ENDPOINT,
            Some("OTHER_TEST_TOKEN"),
        ),
    ] {
        assert_ne!(id().binding_id(), changed.binding_id());
        assert_eq!(
            home.store().resolve_with(&changed, absent).unwrap_err(),
            Error::Missing
        );
    }
    assert_saved(&home, &id(), KEY);
}

#[test]
fn identity_hash_uses_field_boundaries() {
    let first = identity("ab", "c", ENDPOINT, Some("TOKEN"));
    let second = identity("a", "bc", ENDPOINT, Some("TOKEN"));
    assert_ne!(first.binding_id(), second.binding_id());
    assert_eq!(first.binding_id().len(), 64);
}

#[test]
fn printable_provider_names_with_spaces_and_unicode_save_and_resolve_exactly() {
    let home = Home::new();
    for name in [
        "My Gateway",
        "café",
        "My  Gateway",
        "provider\\name",
        ".",
        "..",
    ] {
        let candidate = identity(
            name,
            "openai-compatible",
            ENDPOINT,
            Some("ORBIT_TEST_TOKEN"),
        );
        home.store()
            .save(&candidate, key(KEY), ExpectedRevision::Absent)
            .unwrap();
        assert_saved(&home, &candidate, KEY);
        let no_auth = identity(name, "openai-compatible", ENDPOINT, None);
        assert_eq!(
            home.store()
                .resolve_with(&no_auth, |_| panic!("no-auth ENV lookup"))
                .unwrap()
                .source(),
            Source::None
        );
    }
}

#[test]
fn provider_name_edge_whitespace_slash_and_controls_are_rejected() {
    for name in [
        "",
        " My Gateway",
        "My Gateway ",
        "\u{00a0}café",
        "café\u{2003}",
        "provider/name",
        "provider\nname",
        "provider\tname",
        "provider\0name",
        "provider\u{0085}name",
    ] {
        let error = ProviderAuthIdentity::new(name, "openai-compatible", ENDPOINT, Some("TOKEN"))
            .unwrap_err();
        assert_eq!(error, Error::InvalidIdentity);
        if !name.is_empty() {
            assert!(!format!("{error:?} {error}").contains(name));
        }
    }
}

#[test]
fn provider_names_use_the_existing_utf8_byte_limit() {
    for name in ["a".repeat(128), "é".repeat(64)] {
        ProviderAuthIdentity::new(&name, "openai-compatible", ENDPOINT, Some("TOKEN")).unwrap();
    }
    for name in ["a".repeat(129), "é".repeat(65)] {
        assert_eq!(
            ProviderAuthIdentity::new(&name, "openai-compatible", ENDPOINT, Some("TOKEN"))
                .unwrap_err(),
            Error::InvalidIdentity
        );
    }
}

#[test]
fn provider_name_unicode_composition_and_interior_spaces_do_not_collapse_bindings() {
    let home = Home::new();
    let composed = identity("café", "openai-compatible", ENDPOINT, Some("TOKEN"));
    let decomposed = identity("cafe\u{0301}", "openai-compatible", ENDPOINT, Some("TOKEN"));
    let one_space = identity("My Gateway", "openai-compatible", ENDPOINT, Some("TOKEN"));
    let two_spaces = identity("My  Gateway", "openai-compatible", ENDPOINT, Some("TOKEN"));
    for (first, second) in [(composed, decomposed), (one_space, two_spaces)] {
        assert_ne!(first.binding_id(), second.binding_id());
        home.store()
            .save(&first, key(KEY), ExpectedRevision::Absent)
            .unwrap();
        assert_eq!(
            home.store().resolve_with(&second, absent).unwrap_err(),
            Error::Missing
        );
        home.store()
            .save(&second, key(SECOND_KEY), ExpectedRevision::Absent)
            .unwrap();
        assert_saved(&home, &first, KEY);
        assert_saved(&home, &second, SECOND_KEY);
    }
}

#[test]
fn declared_environment_precedes_saved_value() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let resolved = home
        .store()
        .resolve_with(&id(), |name| {
            assert_eq!(name, "ORBIT_TEST_TOKEN");
            Ok(Some(key(SECOND_KEY)))
        })
        .unwrap();
    assert_eq!(resolved.source(), Source::Environment);
    assert_eq!(resolved.revision(), None);
    assert_eq!(
        resolved.into_secret().unwrap().expose(),
        SECOND_KEY.as_bytes()
    );
    assert_saved(&home, &id(), KEY);
}

#[test]
fn empty_environment_falls_back_to_exact_saved_binding() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let resolved = home
        .store()
        .resolve_with(&id(), |_| Ok(Some(key(""))))
        .unwrap();
    assert_eq!(resolved.source(), Source::Saved);
    assert_eq!(resolved.into_secret().unwrap().expose(), KEY.as_bytes());
}

#[test]
fn no_declaration_never_calls_lookup_or_reads_saved_storage() {
    let home = Home::new();
    fs::write(home.0.join("auth"), b"unrelated-file").unwrap();
    let no_auth = identity("provider", "openai-compatible", ENDPOINT, None);
    let resolved = home
        .store()
        .resolve_with(&no_auth, |_| panic!("no-auth must not look up ENV"))
        .unwrap();
    assert_eq!(resolved.source(), Source::None);
    assert!(resolved.into_secret().is_none());
    assert_eq!(
        home.store()
            .status_with(&no_auth, |_| panic!("no-auth ENV lookup")),
        Status::NoAuth
    );
    assert_eq!(fs::read(home.0.join("auth")).unwrap(), b"unrelated-file");
}

#[test]
fn missing_required_auth_does_not_create_storage() {
    let home = Home::new();
    assert_eq!(
        home.store().resolve_with(&id(), absent).unwrap_err(),
        Error::Missing
    );
    assert_eq!(home.store().status_with(&id(), absent), Status::Missing);
    assert!(!home.0.join("auth").exists());
}

#[test]
fn invalid_nonempty_environment_refuses_without_saved_fallback() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    assert_eq!(
        home.store()
            .resolve_with(&id(), |_| Ok(Some(key("bad\r\nvalue"))))
            .unwrap_err(),
        Error::InvalidKey
    );
    assert_saved(&home, &id(), KEY);
}

#[test]
fn environment_lookup_error_is_typed_and_does_not_fall_back() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    assert_eq!(
        home.store()
            .resolve_with(&id(), |_| Err(Error::EnvironmentUnavailable))
            .unwrap_err(),
        Error::EnvironmentUnavailable
    );
}

#[test]
fn active_environment_does_not_require_healthy_unused_saved_storage() {
    let home = Home::new();
    fs::write(home.0.join("auth"), b"unrelated-file").unwrap();
    let resolved = home
        .store()
        .resolve_with(&id(), |_| Ok(Some(key(KEY))))
        .unwrap();
    assert_eq!(resolved.source(), Source::Environment);
    assert_eq!(resolved.into_secret().unwrap().expose(), KEY.as_bytes());
    assert_eq!(fs::read(home.0.join("auth")).unwrap(), b"unrelated-file");
}

#[test]
fn candidate_environment_precedes_matching_draft_and_saved_sources() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let draft = key("synthetic-draft-secret");
    let resolved = home
        .store()
        .resolve_with_draft(&id(), Some((&id(), &draft)), |_| Ok(Some(key(SECOND_KEY))))
        .unwrap();
    assert_eq!(resolved.source(), Source::Environment);
    assert_eq!(
        resolved.into_secret().unwrap().expose(),
        SECOND_KEY.as_bytes()
    );
}

#[test]
fn exact_matching_draft_precedes_saved_without_publication() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let before = fs::read(home.record(&id())).unwrap();
    let draft = key(SECOND_KEY);
    let resolved = home
        .store()
        .resolve_with_draft(&id(), Some((&id(), &draft)), absent)
        .unwrap();
    assert_eq!(resolved.source(), Source::Draft);
    assert_eq!(
        resolved.into_secret().unwrap().expose(),
        SECOND_KEY.as_bytes()
    );
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
}

#[test]
fn mismatched_draft_is_never_used_for_candidate() {
    let home = Home::new();
    let other = identity("other", "openai-compatible", ENDPOINT, Some("OTHER_TOKEN"));
    let draft = key(KEY);
    assert_eq!(
        home.store()
            .resolve_with_draft(&id(), Some((&other, &draft)), absent)
            .unwrap_err(),
        Error::Missing
    );
    assert!(!home.0.join("auth").exists());
}

#[test]
fn fresh_private_reference_does_not_query_old_environment() {
    let home = Home::new();
    let candidate = identity(
        "provider",
        "openai-compatible",
        ENDPOINT,
        Some("ORBIT_AUTH_TEST_NEW"),
    );
    let draft = key(KEY);
    let resolved = home
        .store()
        .resolve_with_draft(&candidate, Some((&candidate, &draft)), |name| {
            assert_eq!(name, "ORBIT_AUTH_TEST_NEW");
            Ok(None)
        })
        .unwrap();
    assert_eq!(resolved.source(), Source::Draft);
    assert_eq!(resolved.into_secret().unwrap().expose(), KEY.as_bytes());
}

#[test]
fn no_auth_cannot_save_a_binding() {
    let home = Home::new();
    let no_auth = identity("provider", "openai-compatible", ENDPOINT, None);
    assert_eq!(
        home.store()
            .save(&no_auth, key(KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::InvalidIdentity
    );
    assert!(!home.0.join("auth").exists());
}

#[test]
fn expected_absence_cannot_replace_existing_binding() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let before = fs::read(home.record(&id())).unwrap();
    assert_eq!(
        home.store()
            .save(&id(), key(SECOND_KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::StaleRevision
    );
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
}

#[test]
fn exact_revision_replaces_and_stale_save_preserves_bytes() {
    let home = Home::new();
    let first = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let second = home
        .store()
        .save(
            &id(),
            key(SECOND_KEY),
            ExpectedRevision::Exact(first.revision),
        )
        .unwrap();
    assert_ne!(first.revision, second.revision);
    let before = fs::read(home.record(&id())).unwrap();
    assert_eq!(
        home.store()
            .save(
                &id(),
                key("synthetic-stale-value"),
                ExpectedRevision::Exact(first.revision)
            )
            .unwrap_err(),
        Error::StaleRevision
    );
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
    assert_saved(&home, &id(), SECOND_KEY);
}

#[test]
fn identical_save_requires_expected_revision_and_is_idempotent() {
    let home = Home::new();
    let first = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let before = fs::read(home.record(&id())).unwrap();
    let again = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Exact(first.revision))
        .unwrap();
    assert!(!again.changed);
    assert_eq!(first.revision, again.revision);
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
}

#[test]
fn returning_to_previous_key_does_not_revive_old_revision() {
    let home = Home::new();
    let first = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let second = home
        .store()
        .save(
            &id(),
            key(SECOND_KEY),
            ExpectedRevision::Exact(first.revision),
        )
        .unwrap();
    let third = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Exact(second.revision))
        .unwrap();
    assert_ne!(first.revision, third.revision);
    assert_eq!(
        home.store()
            .remove(&id(), ExpectedRevision::Exact(first.revision))
            .unwrap_err(),
        Error::StaleRevision
    );
    assert_saved(&home, &id(), KEY);
}

#[test]
fn removal_requires_revision_and_preserves_other_binding() {
    let home = Home::new();
    let first = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let other = identity("other", "openai-compatible", ENDPOINT, Some("OTHER_TOKEN"));
    home.store()
        .save(&other, key(SECOND_KEY), ExpectedRevision::Absent)
        .unwrap();
    let before = fs::read(home.record(&id())).unwrap();
    assert_eq!(
        home.store()
            .remove(&id(), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::StaleRevision
    );
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
    assert_eq!(
        home.store()
            .remove(&id(), ExpectedRevision::Exact(first.revision))
            .unwrap(),
        ProviderCredentialRemoveResult::Removed
    );
    assert_eq!(
        home.store()
            .remove(&id(), ExpectedRevision::Absent)
            .unwrap(),
        ProviderCredentialRemoveResult::Absent
    );
    assert_saved(&home, &other, SECOND_KEY);
}

#[test]
fn absent_removal_does_not_create_a_store() {
    let home = Home::new();
    assert_eq!(
        home.store()
            .remove(&id(), ExpectedRevision::Absent)
            .unwrap(),
        ProviderCredentialRemoveResult::Absent
    );
    assert!(!home.0.join("auth").exists());
}

#[test]
fn diagnostic_surfaces_never_contain_keys() {
    let home = Home::new();
    let saved = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let resolved = home.store().resolve_with(&id(), absent).unwrap();
    let diagnostics = format!(
        "{saved:?} {resolved:?} {:?} {:?} {}",
        id(),
        home.store().status_with(&id(), absent),
        Error::InvalidKey
    );
    assert!(!diagnostics.contains(KEY));
    assert!(!diagnostics.contains(SECOND_KEY));
    assert!(!diagnostics.contains(ENDPOINT));
}

#[test]
fn invalid_keys_refuse_before_creating_storage() {
    let home = Home::new();
    for bytes in [
        vec![],
        vec![b'x'; MAX_PROVIDER_KEY_BYTES + 1],
        b"bad\r\nkey".to_vec(),
        b"bad\tkey".to_vec(),
        vec![0xff],
        b"bad\0key".to_vec(),
        b"  ".to_vec(),
        "bad\u{0085}key".as_bytes().to_vec(),
    ] {
        assert_eq!(
            home.store()
                .save(&id(), SecretBytes::new(bytes), ExpectedRevision::Absent)
                .unwrap_err(),
            Error::InvalidKey
        );
    }
    assert!(!home.0.join("auth").exists());
}

#[test]
fn maximum_key_size_is_accepted() {
    let home = Home::new();
    let value = "x".repeat(MAX_PROVIDER_KEY_BYTES);
    home.store()
        .save(&id(), key(&value), ExpectedRevision::Absent)
        .unwrap();
    assert_saved(&home, &id(), &value);
}

#[test]
fn malformed_identity_never_echoes_supplied_content() {
    for endpoint in [
        "https://user:synthetic-secret@provider.invalid/",
        "https://provider.invalid/#secret",
        "https://provider.invalid/\nsecret",
        "https://provider.invalid/%0dsecret",
        "file:///secret",
        "https:///secret",
        "https://provider.invalid:bogus/",
        "https://[::1]garbage/",
        "https://provider.invalid/%xx",
    ] {
        let error =
            ProviderAuthIdentity::new("provider", "openai-compatible", endpoint, Some("TOKEN"))
                .unwrap_err();
        assert_eq!(error, Error::InvalidIdentity);
        assert!(!format!("{error:?} {error}").contains(endpoint));
    }
    for (provider, kind, env) in [
        ("../bad", "openai-compatible", "TOKEN"),
        ("provider", "bad/kind", "TOKEN"),
        ("provider", "openai-compatible", "1TOKEN"),
        ("provider", "openai-compatible", ""),
    ] {
        assert_eq!(
            ProviderAuthIdentity::new(provider, kind, ENDPOINT, Some(env)).unwrap_err(),
            Error::InvalidIdentity
        );
    }
}

#[test]
fn unsafe_home_permissions_are_refused_without_chmod() {
    let home = Home::new();
    fs::set_permissions(&home.0, fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        home.store()
            .save(&id(), key(KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::UnsafeDirectory
    );
    assert_eq!(
        fs::metadata(&home.0).unwrap().permissions().mode() & 0o777,
        0o777
    );
    assert!(!home.0.join("auth").exists());
}

#[test]
fn safe_existing_home_mode_is_preserved() {
    let home = Home::new();
    fs::set_permissions(&home.0, fs::Permissions::from_mode(0o755)).unwrap();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    assert_eq!(
        fs::metadata(&home.0).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn unsafe_auth_directory_is_refused_without_repair_or_overwrite() {
    let home = Home::new();
    fs::create_dir(home.0.join("auth")).unwrap();
    fs::set_permissions(home.0.join("auth"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(home.0.join("auth/unrelated"), b"keep").unwrap();
    assert_eq!(
        home.store()
            .save(&id(), key(KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::UnsafeDirectory
    );
    assert_eq!(fs::read(home.0.join("auth/unrelated")).unwrap(), b"keep");
    assert_eq!(
        fs::metadata(home.0.join("auth"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[test]
fn symlink_home_or_auth_directory_never_follows_target() {
    let home = Home::new();
    let target = Home::new();
    let alias = home.0.join("alias");
    symlink(&target.0, &alias).unwrap();
    assert_eq!(
        ProviderCredentialStore::new(&alias)
            .unwrap()
            .save(&id(), key(KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::UnsafeDirectory
    );
    symlink(&target.0, home.0.join("auth")).unwrap();
    assert_eq!(
        home.store()
            .save(&id(), key(KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::UnsafeDirectory
    );
    assert!(!target.0.join("auth").exists());
    assert!(!target.0.join("providers").exists());
}

#[test]
fn providers_directory_symlink_is_refused() {
    let home = Home::new();
    let target = Home::new();
    DirBuilder::new()
        .mode(0o700)
        .create(home.0.join("auth"))
        .unwrap();
    symlink(&target.0, home.directory()).unwrap();
    assert_eq!(
        home.store()
            .save(&id(), key(KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::UnsafeDirectory
    );
    assert_eq!(fs::read_dir(&target.0).unwrap().count(), 0);
}

#[test]
fn record_symlink_is_refused_and_target_is_preserved() {
    let home = Home::new();
    let revision = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap()
        .revision;
    fs::remove_file(home.record(&id())).unwrap();
    let target = home.0.join("unrelated");
    write_private(&target, b"keep-target-bytes");
    symlink(&target, home.record(&id())).unwrap();
    assert_eq!(
        home.store().resolve_with(&id(), absent).unwrap_err(),
        Error::UnsafeFile
    );
    assert_eq!(
        home.store()
            .save(&id(), key(SECOND_KEY), ExpectedRevision::Exact(revision))
            .unwrap_err(),
        Error::UnsafeFile
    );
    assert_eq!(fs::read(target).unwrap(), b"keep-target-bytes");
}

#[test]
fn hardlinked_record_is_refused_and_alias_preserved() {
    let home = Home::new();
    let revision = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap()
        .revision;
    let before = fs::read(home.record(&id())).unwrap();
    let alias = home.0.join("record-alias");
    fs::hard_link(home.record(&id()), &alias).unwrap();
    assert_eq!(
        home.store().resolve_with(&id(), absent).unwrap_err(),
        Error::UnsafeFile
    );
    assert_eq!(
        home.store()
            .remove(&id(), ExpectedRevision::Exact(revision))
            .unwrap_err(),
        Error::UnsafeFile
    );
    assert_eq!(fs::read(alias).unwrap(), before);
}

#[test]
fn unsafe_record_modes_are_refused_without_repair() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    for mode in [0o644, 0o400, 0o1600, 0o700] {
        fs::set_permissions(home.record(&id()), fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            home.store().resolve_with(&id(), absent).unwrap_err(),
            Error::UnsafeFile
        );
        assert_eq!(
            fs::metadata(home.record(&id()))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            mode
        );
    }
}

#[test]
fn embedded_identity_mismatch_is_refused_without_disclosing_key() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let other = identity("other", "openai-compatible", ENDPOINT, Some("OTHER_TOKEN"));
    fs::copy(home.record(&id()), home.record(&other)).unwrap();
    let before = fs::read(home.record(&other)).unwrap();
    let error = home.store().resolve_with(&other, absent).unwrap_err();
    assert_eq!(error, Error::IdentityMismatch);
    assert!(!error.to_string().contains(KEY));
    assert_eq!(fs::read(home.record(&other)).unwrap(), before);
    assert_saved(&home, &id(), KEY);
}

#[test]
fn truncated_and_trailing_records_are_refused() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let original = fs::read(home.record(&id())).unwrap();
    for length in [0, 7, 20, original.len() - 1] {
        fs::write(home.record(&id()), &original[..length]).unwrap();
        assert_eq!(
            home.store().resolve_with(&id(), absent).unwrap_err(),
            Error::InvalidRecord
        );
    }
    let mut trailing = original;
    trailing.push(0);
    fs::write(home.record(&id()), trailing).unwrap();
    assert_eq!(
        home.store().resolve_with(&id(), absent).unwrap_err(),
        Error::InvalidRecord
    );
}

#[test]
fn oversized_record_is_refused_without_replacement() {
    let home = Home::new();
    let revision = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap()
        .revision;
    let bytes = vec![b'x'; MAX_PROVIDER_RECORD_BYTES + 1];
    fs::write(home.record(&id()), &bytes).unwrap();
    assert_eq!(
        home.store().resolve_with(&id(), absent).unwrap_err(),
        Error::LimitExceeded
    );
    assert_eq!(
        home.store()
            .save(&id(), key(SECOND_KEY), ExpectedRevision::Exact(revision))
            .unwrap_err(),
        Error::LimitExceeded
    );
    assert_eq!(fs::read(home.record(&id())).unwrap(), bytes);
}

#[test]
fn record_count_limit_refuses_new_binding_and_preserves_existing() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let bytes = fs::read(home.record(&id())).unwrap();
    // Existing private records count even if they belong to another identity.
    for index in 1..MAX_PROVIDER_RECORDS {
        write_private(
            &home.directory().join(format!("{index:064x}.credential")),
            &bytes,
        );
    }
    let extra = identity("extra", "openai-compatible", ENDPOINT, Some("EXTRA_TOKEN"));
    assert_eq!(
        home.store()
            .save(&extra, key(SECOND_KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::LimitExceeded
    );
    assert!(!home.record(&extra).exists());
    assert_eq!(fs::read(home.record(&id())).unwrap(), bytes);
    assert_saved(&home, &id(), KEY);
    write_private(
        &home
            .directory()
            .join(format!("{:064x}.credential", MAX_PROVIDER_RECORDS)),
        &bytes,
    );
    assert_eq!(
        home.store().resolve_with(&id(), absent).unwrap_err(),
        Error::LimitExceeded
    );
}

#[test]
fn unrelated_store_file_is_preserved_on_refusal() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let before = fs::read(home.record(&id())).unwrap();
    write_private(&home.directory().join("unrelated"), b"do-not-touch");
    assert_eq!(
        home.store()
            .save(&id(), key(SECOND_KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::UnsafeFile
    );
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
    assert_eq!(
        fs::read(home.directory().join("unrelated")).unwrap(),
        b"do-not-touch"
    );
}

#[test]
fn unsafe_lock_is_refused_without_touching_valid_record() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let before = fs::read(home.record(&id())).unwrap();
    fs::set_permissions(
        home.directory().join("store.lock"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_eq!(
        home.store().resolve_with(&id(), absent).unwrap_err(),
        Error::UnsafeFile
    );
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
}

#[test]
fn store_requires_normal_absolute_home_and_does_not_create_it() {
    for path in [
        Path::new("relative"),
        Path::new("/"),
        Path::new("/tmp/../unsafe"),
    ] {
        assert_eq!(
            ProviderCredentialStore::new(path).unwrap_err(),
            Error::UnsafeDirectory
        );
    }
    let home = Home::new();
    let missing = home.0.join("missing");
    let store = ProviderCredentialStore::new(&missing).unwrap();
    assert_eq!(
        store
            .save(&id(), key(KEY), ExpectedRevision::Absent)
            .unwrap_err(),
        Error::UnsafeDirectory
    );
    assert!(!missing.exists());
}

#[test]
fn read_only_status_missing_store_never_creates_directories() {
    let home = Home::new();
    assert_eq!(
        home.store().status_read_only_with(&id(), absent),
        Status::Missing
    );
    assert!(!home.0.join("auth").exists());
    let no_auth = identity("provider", "openai-compatible", ENDPOINT, None);
    assert_eq!(
        home.store()
            .status_read_only_with(&no_auth, |_| panic!("no-auth lookup")),
        Status::NoAuth
    );
    assert!(!home.0.join("auth").exists());
}

#[test]
fn read_only_status_does_not_recreate_missing_lock_or_change_records() {
    let home = Home::new();
    home.store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let before = fs::read(home.record(&id())).unwrap();
    fs::remove_file(home.directory().join("store.lock")).unwrap();
    assert_eq!(
        home.store().status_read_only_with(&id(), absent),
        Status::Invalid(Error::UnsafeFile)
    );
    assert!(!home.directory().join("store.lock").exists());
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
    assert_eq!(fs::read_dir(home.directory()).unwrap().count(), 1);
}

#[test]
fn read_only_status_uses_validated_environment_and_saved_source_without_writes() {
    let home = Home::new();
    let saved = home
        .store()
        .save(&id(), key(KEY), ExpectedRevision::Absent)
        .unwrap();
    let before = fs::read(home.record(&id())).unwrap();
    assert_eq!(
        home.store().status_read_only_with(&id(), absent),
        Status::Available {
            source: Source::Saved,
            revision: Some(saved.revision)
        }
    );
    assert_eq!(
        home.store()
            .status_read_only_with(&id(), |_| Ok(Some(key("synthetic-read-only-env-631024")))),
        Status::Available {
            source: Source::Environment,
            revision: None
        }
    );
    assert_eq!(
        home.store()
            .status_read_only_with(&id(), |_| Ok(Some(key("invalid\r\nvalue")))),
        Status::Invalid(Error::InvalidKey)
    );
    assert_eq!(fs::read(home.record(&id())).unwrap(), before);
    assert_eq!(fs::read_dir(home.directory()).unwrap().count(), 2);
}
