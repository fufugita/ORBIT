use orbit_plugin_compat::{InspectOptions, PluginId, PluginStore, StoreScope};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

fn write(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, bytes).unwrap();
}

fn package(root: &Path, name: &str) {
    write(
        root,
        "plugin.json",
        serde_json::to_vec(&json!({
            "$schema":"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
            "name":name,"version":"1.2.3","license":"MIT","description":"Managed package"
        }))
        .unwrap(),
    );
    write(root, "LICENSE", "Preserved license text\n");
    write(
        root,
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: Review the selected change\nallowed-tools: [Read]\n---\nPreserve the original instruction body.\n",
    );
    write(
        root,
        "scripts/never-run.sh",
        "#!/bin/sh\ntouch execution-marker\n",
    );
    fs::set_permissions(
        root.join("scripts/never-run.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
}

fn roots(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let home = root.join("home");
    let project = root.join("project");
    let source = root.join("source");
    fs::create_dir(&project).unwrap();
    fs::create_dir(&source).unwrap();
    package(&source, "sample");
    (home, project, source)
}

fn index(home: &Path) -> PathBuf {
    home.join("plugins/portable/index.json")
}
fn id(scope: StoreScope) -> PluginId {
    PluginId {
        name: "sample".into(),
        scope,
    }
}

fn files(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
    fn walk(root: &Path, current: &Path, found: &mut BTreeMap<PathBuf, (Vec<u8>, u32)>) {
        if !current.exists() {
            return;
        }
        for entry in fs::read_dir(current).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                walk(root, &path, found);
            } else {
                found.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    (fs::read(&path).unwrap(), metadata.mode() & 0o7777),
                );
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(root, root, &mut found);
    found
}

#[test]
fn read_only_missing_store_creates_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let before = files(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    assert!(store.list().unwrap().entries.is_empty());
    assert!(store.status(&id(StoreScope::User)).unwrap().is_none());
    assert!(store.active().unwrap().plugins.is_empty());
    assert!(!home.exists());
    assert!(!project.join(".orbit").exists());
    assert_eq!(before, files(temp.path()));
    assert!(!source.join("execution-marker").exists());
}

#[test]
fn import_preserves_source_license_modes_and_unrelated_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    write(&home, "providers.toml", "preserve provider configuration\n");
    let source_before = files(&source);
    let receipt = PluginStore::open(&home, &project, true)
        .unwrap()
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    assert!(!receipt.reused);
    assert!(receipt.plugin.enabled);
    assert_eq!(receipt.plugin.manifest.license.as_deref(), Some("MIT"));
    assert_eq!(receipt.plugin.id, id(StoreScope::User));
    let reopened = PluginStore::open(&home, &project, true).unwrap();
    assert_eq!(reopened.list().unwrap(), receipt.snapshot);
    assert_eq!(
        reopened.status(&id(StoreScope::User)).unwrap().unwrap(),
        receipt.plugin
    );
    let active = reopened.active().unwrap();
    assert_eq!(active.plugins.len(), 1);
    assert_eq!(active.revision, receipt.snapshot.revision);
    let managed = &active.plugins[0].root;
    assert_eq!(
        fs::read(managed.join("LICENSE")).unwrap(),
        b"Preserved license text\n"
    );
    assert_eq!(
        fs::metadata(managed.join("LICENSE")).unwrap().mode() & 0o7777,
        0o400
    );
    assert_eq!(
        fs::metadata(managed.join("scripts/never-run.sh"))
            .unwrap()
            .mode()
            & 0o7777,
        0o500
    );
    assert_eq!(fs::metadata(managed).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(fs::metadata(index(&home)).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(
        fs::read(home.join("providers.toml")).unwrap(),
        b"preserve provider configuration\n"
    );
    assert_eq!(source_before, files(&source));
    assert!(!active.plugins[0].data_root.exists());
    assert!(!source.join("execution-marker").exists());
    assert!(!managed.join("execution-marker").exists());
}

#[test]
fn project_container_readable_settings_do_not_disable_user_content() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    write(
        &project,
        ".orbit/settings.toml",
        "preserve project settings\n",
    );
    fs::set_permissions(project.join(".orbit"), fs::Permissions::from_mode(0o755)).unwrap();
    let before = files(temp.path());
    let active = store.active().unwrap();
    assert_eq!(active.plugins.len(), 1);
    assert_eq!(active.plugins[0].plugin.id, id(StoreScope::User));
    assert_eq!(files(temp.path()), before);
    assert_eq!(
        fs::metadata(project.join(".orbit")).unwrap().mode() & 0o7777,
        0o755
    );
}

#[test]
fn project_container_import_preserves_settings_and_keeps_store_private() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    write(
        &project,
        ".orbit/settings.toml",
        "preserve project settings\n",
    );
    fs::set_permissions(project.join(".orbit"), fs::Permissions::from_mode(0o755)).unwrap();
    let store = PluginStore::open(&home, &project, true).unwrap();
    let receipt = store
        .import(
            &source,
            &InspectOptions::default(),
            StoreScope::Project,
            true,
        )
        .unwrap();
    assert_eq!(receipt.plugin.id, id(StoreScope::Project));
    assert_eq!(store.active().unwrap().plugins.len(), 1);
    // Mutations coordinate both scopes even when only the project changes.
    assert!(!index(&home).exists());
    for path in [&home, &home.join("plugins"), &home.join("plugins/portable")] {
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o700);
    }
    assert_eq!(
        fs::read(project.join(".orbit/settings.toml")).unwrap(),
        b"preserve project settings\n"
    );
    assert_eq!(
        fs::metadata(project.join(".orbit")).unwrap().mode() & 0o7777,
        0o755
    );
    for path in [".orbit/plugins", ".orbit/plugins/portable"] {
        assert_eq!(
            fs::metadata(project.join(path)).unwrap().mode() & 0o7777,
            0o700
        );
    }
    assert_eq!(
        fs::metadata(project.join(".orbit/plugins/portable/index.json"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(!source.join("execution-marker").exists());
}

#[test]
fn project_container_refuses_writable_linked_and_special_mode_roots() {
    for mode in [0o775, 0o777, 0o1755] {
        let temp = tempfile::tempdir().unwrap();
        let (home, project, source) = roots(temp.path());
        write(
            &project,
            ".orbit/settings.toml",
            "preserve project settings\n",
        );
        fs::set_permissions(project.join(".orbit"), fs::Permissions::from_mode(mode)).unwrap();
        let before = files(temp.path());
        let store = PluginStore::open(&home, &project, true).unwrap();
        assert!(
            store
                .import(
                    &source,
                    &InspectOptions::default(),
                    StoreScope::Project,
                    true
                )
                .is_err()
        );
        assert_eq!(files(temp.path()), before);
        assert_eq!(
            fs::metadata(project.join(".orbit")).unwrap().mode() & 0o7777,
            mode
        );
    }
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&outside, project.join(".orbit")).unwrap();
    let store = PluginStore::open(&home, &project, true).unwrap();
    assert!(
        store
            .import(
                &source,
                &InspectOptions::default(),
                StoreScope::Project,
                true
            )
            .is_err()
    );
    assert!(fs::read_dir(outside).unwrap().next().is_none());
    assert!(!home.exists());
}

#[test]
fn staging_is_disabled_and_identical_import_is_byte_for_byte_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    let first = store
        .import(&source, &InspectOptions::default(), StoreScope::User, false)
        .unwrap();
    let before = files(&home);
    let second = store
        .import(&source, &InspectOptions::default(), StoreScope::User, false)
        .unwrap();
    assert!(second.reused);
    assert_eq!(first.snapshot, second.snapshot);
    assert_eq!(first.plugin, second.plugin);
    assert_eq!(before, files(&home));
    assert!(store.active().unwrap().plugins.is_empty());
    assert_eq!(
        store
            .import(&source, &InspectOptions::default(), StoreScope::User, true)
            .unwrap_err()
            .code,
        "store_state_conflict"
    );
    assert_eq!(before, files(&home));
}

#[test]
fn lifecycle_enable_disable_remove_reloads_and_retains_owned_content() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    let staged = store
        .import(&source, &InspectOptions::default(), StoreScope::User, false)
        .unwrap();
    let enabled = store
        .enable(&id(StoreScope::User), &staged.snapshot.revision)
        .unwrap();
    assert!(enabled.entries[0].enabled);
    assert_ne!(enabled.revision, staged.snapshot.revision);
    let reopened = PluginStore::open(&home, &project, true).unwrap();
    let active = reopened.active().unwrap();
    assert_eq!(active.revision, enabled.revision);
    let managed = active.plugins[0].root.clone();
    let data = active.plugins[0].data_root.clone();
    write(&data, "user-state.json", b"preserve user state\n");
    let managed_before = files(&managed);
    let source_before = files(&source);
    let unchanged = files(&home);
    assert_eq!(
        reopened
            .enable(&id(StoreScope::User), &enabled.revision)
            .unwrap(),
        enabled
    );
    assert_eq!(unchanged, files(&home));
    let disabled = reopened
        .disable(&id(StoreScope::User), &enabled.revision)
        .unwrap();
    assert!(!disabled.entries[0].enabled);
    assert!(
        PluginStore::open(&home, &project, true)
            .unwrap()
            .active()
            .unwrap()
            .plugins
            .is_empty()
    );
    let removed = reopened
        .remove(&id(StoreScope::User), &disabled.revision)
        .unwrap();
    assert!(removed.entries.is_empty());
    assert!(
        PluginStore::open(&home, &project, true)
            .unwrap()
            .status(&id(StoreScope::User))
            .unwrap()
            .is_none()
    );
    assert_eq!(managed_before, files(&managed));
    assert_eq!(
        fs::read(data.join("user-state.json")).unwrap(),
        b"preserve user state\n"
    );
    assert_eq!(source_before, files(&source));
    assert!(!managed.join("execution-marker").exists());
}

#[test]
fn lifecycle_upgrade_is_explicit_preserves_enabled_state_and_previous_tree() {
    for enabled in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (home, project, source) = roots(temp.path());
        let store = PluginStore::open(&home, &project, true).unwrap();
        let initial = store
            .import(
                &source,
                &InspectOptions::default(),
                StoreScope::User,
                enabled,
            )
            .unwrap();
        let previous_index = fs::read(index(&home)).unwrap();
        let previous_root = home
            .join("plugins/portable/packages/sample")
            .join(&initial.plugin.digest);
        let previous_bytes = files(&previous_root);
        write(&source, "LICENSE", b"Updated preserved license\n");
        assert_eq!(
            store
                .import(
                    &source,
                    &InspectOptions::default(),
                    StoreScope::User,
                    enabled
                )
                .unwrap_err()
                .code,
            "store_upgrade_required"
        );
        let receipt = store
            .upgrade(
                &id(StoreScope::User),
                &source,
                &InspectOptions::default(),
                &initial.snapshot.revision,
            )
            .unwrap();
        assert!(!receipt.reused);
        assert_eq!(receipt.plugin.enabled, enabled);
        assert_ne!(receipt.plugin.digest, initial.plugin.digest);
        assert_ne!(receipt.snapshot.revision, initial.snapshot.revision);
        assert_eq!(previous_bytes, files(&previous_root));
        assert_eq!(
            previous_index,
            fs::read(home.join("plugins/portable/index.previous.json")).unwrap()
        );
        let reopened = PluginStore::open(&home, &project, true).unwrap();
        assert_eq!(
            reopened.status(&id(StoreScope::User)).unwrap().unwrap(),
            receipt.plugin
        );
        assert_eq!(
            reopened.active().unwrap().plugins.len(),
            usize::from(enabled)
        );
        let before = files(&home);
        let repeated = reopened
            .upgrade(
                &id(StoreScope::User),
                &source,
                &InspectOptions::default(),
                &receipt.snapshot.revision,
            )
            .unwrap();
        assert!(repeated.reused);
        assert_eq!(repeated.snapshot, receipt.snapshot);
        assert_eq!(before, files(&home));
    }
}

#[test]
fn lifecycle_stale_revision_rejects_every_mutator_without_writes() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    let initial = store
        .import(&source, &InspectOptions::default(), StoreScope::User, false)
        .unwrap();
    let current = store
        .enable(&id(StoreScope::User), &initial.snapshot.revision)
        .unwrap();
    write(&source, "LICENSE", "Updated source\n");
    let before = files(&home);
    for result in [
        store
            .enable(&id(StoreScope::User), &initial.snapshot.revision)
            .map(|_| ()),
        store
            .disable(&id(StoreScope::User), &initial.snapshot.revision)
            .map(|_| ()),
        store
            .remove(&id(StoreScope::User), &initial.snapshot.revision)
            .map(|_| ()),
        store
            .upgrade(
                &id(StoreScope::User),
                &source,
                &InspectOptions::default(),
                &initial.snapshot.revision,
            )
            .map(|_| ()),
    ] {
        assert_eq!(result.unwrap_err().code, "store_revision_changed");
    }
    assert_eq!(before, files(&home));
    assert_eq!(current, store.list().unwrap());
}

#[test]
fn lifecycle_failed_publication_keeps_current_index_package_and_external_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    let initial = store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let active = store.active().unwrap();
    let previous = home.join("plugins/portable/index.previous.json");
    fs::remove_file(&previous).unwrap();
    let outside = temp.path().join("outside-index");
    fs::write(&outside, b"external sentinel\n").unwrap();
    symlink(&outside, &previous).unwrap();
    let index_before = fs::read(index(&home)).unwrap();
    let package_before = files(&active.plugins[0].root);
    write(&source, "LICENSE", "Candidate upgrade\n");
    assert!(
        store
            .disable(&id(StoreScope::User), &initial.snapshot.revision)
            .is_err()
    );
    assert!(
        store
            .remove(&id(StoreScope::User), &initial.snapshot.revision)
            .is_err()
    );
    assert!(
        store
            .upgrade(
                &id(StoreScope::User),
                &source,
                &InspectOptions::default(),
                &initial.snapshot.revision
            )
            .is_err()
    );
    assert_eq!(index_before, fs::read(index(&home)).unwrap());
    assert_eq!(package_before, files(&active.plugins[0].root));
    assert_eq!(fs::read(outside).unwrap(), b"external sentinel\n");
    assert_eq!(
        PluginStore::open(&home, &project, true)
            .unwrap()
            .active()
            .unwrap(),
        active
    );
}

#[test]
fn lifecycle_refuses_tampered_activation_wrong_upgrade_identity_and_untrusted_project() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    let initial = store
        .import(
            &source,
            &InspectOptions::default(),
            StoreScope::Project,
            false,
        )
        .unwrap();
    let managed = project
        .join(".orbit/plugins/portable/packages/sample")
        .join(&initial.plugin.digest);
    fs::set_permissions(managed.join("LICENSE"), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        store
            .enable(&id(StoreScope::Project), &initial.snapshot.revision)
            .unwrap_err()
            .code,
        "store_file_unsafe"
    );
    fs::set_permissions(managed.join("LICENSE"), fs::Permissions::from_mode(0o400)).unwrap();
    let wrong = temp.path().join("other-package");
    package(&wrong, "other");
    let before = files(temp.path());
    assert_eq!(
        store
            .upgrade(
                &id(StoreScope::Project),
                &wrong,
                &InspectOptions::default(),
                &initial.snapshot.revision
            )
            .unwrap_err()
            .code,
        "store_identity_mismatch"
    );
    let untrusted = PluginStore::open(&home, &project, false).unwrap();
    for result in [
        untrusted.enable(&id(StoreScope::Project), &initial.snapshot.revision),
        untrusted.disable(&id(StoreScope::Project), &initial.snapshot.revision),
        untrusted.remove(&id(StoreScope::Project), &initial.snapshot.revision),
    ] {
        assert_eq!(result.unwrap_err().code, "store_project_untrusted");
    }
    assert_eq!(before, files(temp.path()));
}

#[test]
fn lifecycle_concurrent_mutators_accept_only_one_observed_revision() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    let initial = store
        .import(
            &source,
            &InspectOptions::default(),
            StoreScope::Project,
            false,
        )
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for remove in [false, true] {
        let contender = PluginStore::open(&home, &project, true).unwrap();
        let revision = initial.snapshot.revision.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            let result = if remove {
                contender.remove(&id(StoreScope::Project), &revision)
            } else {
                contender.enable(&id(StoreScope::Project), &revision)
            };
            (remove, result)
        }));
    }
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    let winner = results
        .iter()
        .find_map(|(_, result)| result.as_ref().ok())
        .unwrap();
    let (remove, error) = results
        .iter()
        .find_map(|(remove, result)| result.as_ref().err().map(|error| (*remove, error)))
        .unwrap();
    assert!(["store_busy", "store_revision_changed"].contains(&error.code.as_str()));
    let retry = if remove {
        store.remove(&id(StoreScope::Project), &initial.snapshot.revision)
    } else {
        store.enable(&id(StoreScope::Project), &initial.snapshot.revision)
    };
    assert_eq!(retry.unwrap_err().code, "store_revision_changed");
    let fresh = PluginStore::open(&home, &project, true)
        .unwrap()
        .list()
        .unwrap();
    assert_eq!(&fresh, winner);
}

#[test]
fn lifecycle_damaged_or_missing_package_can_be_disabled_removed_or_replaced() {
    for missing in [false, true] {
        for action in ["disable", "remove", "upgrade"] {
            let temp = tempfile::tempdir().unwrap();
            let (home, project, source) = roots(temp.path());
            let store = PluginStore::open(&home, &project, true).unwrap();
            let imported = store
                .import(&source, &InspectOptions::default(), StoreScope::User, true)
                .unwrap();
            let active = store.active().unwrap();
            let original_root = active.plugins[0].root.clone();
            let data = active.plugins[0].data_root.clone();
            write(&data, "state.json", "preserve state\n");
            write(&home, "providers.toml", "preserve settings\n");
            let retained = if missing {
                let archived = temp.path().join("retained-old-package");
                fs::rename(&original_root, &archived).unwrap();
                archived
            } else {
                fs::set_permissions(
                    original_root.join("LICENSE"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                fs::write(original_root.join("LICENSE"), b"damaged old content\n").unwrap();
                fs::set_permissions(
                    original_root.join("LICENSE"),
                    fs::Permissions::from_mode(0o400),
                )
                .unwrap();
                original_root.clone()
            };
            let retained_before = files(&retained);
            let damaged = store.list().unwrap();
            assert!(damaged.entries.is_empty());
            assert_eq!(damaged.revision, imported.snapshot.revision);
            assert!(!damaged.diagnostics.is_empty());
            assert!(
                store
                    .enable(&id(StoreScope::User), &damaged.revision)
                    .is_err()
            );
            assert!(
                store
                    .upgrade(
                        &id(StoreScope::User),
                        &source,
                        &InspectOptions::default(),
                        &damaged.revision
                    )
                    .is_err()
            );
            let old_index = fs::read(index(&home)).unwrap();
            if action == "upgrade" {
                write(&source, "LICENSE", "verified replacement\n");
            }
            let source_before = files(&source);
            let snapshot = match action {
                "disable" => store
                    .disable(&id(StoreScope::User), &damaged.revision)
                    .unwrap(),
                "remove" => store
                    .remove(&id(StoreScope::User), &damaged.revision)
                    .unwrap(),
                _ => {
                    store
                        .upgrade(
                            &id(StoreScope::User),
                            &source,
                            &InspectOptions::default(),
                            &damaged.revision,
                        )
                        .unwrap()
                        .snapshot
                }
            };
            assert_ne!(snapshot.revision, damaged.revision);
            assert_eq!(
                old_index,
                fs::read(home.join("plugins/portable/index.previous.json")).unwrap()
            );
            let persisted: serde_json::Value =
                serde_json::from_slice(&fs::read(index(&home)).unwrap()).unwrap();
            let reopened = PluginStore::open(&home, &project, true).unwrap();
            match action {
                "disable" => {
                    assert_eq!(persisted["entries"][0]["enabled"], json!(false));
                    assert!(reopened.active().unwrap().plugins.is_empty());
                    let before = files(&home);
                    assert_eq!(
                        reopened
                            .disable(&id(StoreScope::User), &snapshot.revision)
                            .unwrap(),
                        snapshot
                    );
                    assert_eq!(before, files(&home));
                }
                "remove" => {
                    assert_eq!(persisted["entries"], json!([]));
                    assert!(reopened.status(&id(StoreScope::User)).unwrap().is_none());
                    assert!(reopened.active().unwrap().plugins.is_empty());
                }
                _ => {
                    let replacement = reopened.active().unwrap();
                    assert_eq!(replacement.plugins.len(), 1);
                    assert_ne!(replacement.plugins[0].plugin.digest, imported.plugin.digest);
                    assert_eq!(
                        fs::read(replacement.plugins[0].root.join("LICENSE")).unwrap(),
                        b"verified replacement\n"
                    );
                }
            }
            assert_eq!(reopened.list().unwrap(), snapshot);
            assert_eq!(retained_before, files(&retained));
            assert_eq!(source_before, files(&source));
            assert_eq!(
                fs::read(data.join("state.json")).unwrap(),
                b"preserve state\n"
            );
            assert_eq!(
                fs::read(home.join("providers.toml")).unwrap(),
                b"preserve settings\n"
            );
        }
    }
}

#[test]
fn lifecycle_safe_mutation_ignores_unrelated_damaged_content() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let other = temp.path().join("other");
    package(&other, "other");
    let imported = store
        .import(&other, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let damaged_root = home
        .join("plugins/portable/packages/other")
        .join(imported.plugin.digest);
    fs::remove_file(damaged_root.join("LICENSE")).unwrap();
    let before = files(&damaged_root);
    let observed = store.list().unwrap();
    assert_eq!(observed.entries.len(), 1);
    assert!(!observed.diagnostics.is_empty());
    let disabled = store
        .disable(&id(StoreScope::User), &observed.revision)
        .unwrap();
    assert!(!disabled.entries[0].enabled);
    let enabled = store
        .enable(&id(StoreScope::User), &disabled.revision)
        .unwrap();
    assert!(enabled.entries[0].enabled);
    let removed = store
        .remove(&id(StoreScope::User), &enabled.revision)
        .unwrap();
    assert!(removed.entries.is_empty());
    assert!(!removed.diagnostics.is_empty());
    assert_eq!(
        PluginStore::open(&home, &project, true)
            .unwrap()
            .list()
            .unwrap(),
        removed
    );
    assert_eq!(before, files(&damaged_root));
}

#[test]
fn different_digest_requires_upgrade_and_retains_original_enabled_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    let first = store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let home_before = files(&home);
    write(&source, "LICENSE", "A changed version\n");
    assert_eq!(
        store
            .import(&source, &InspectOptions::default(), StoreScope::User, true)
            .unwrap_err()
            .code,
        "store_upgrade_required"
    );
    assert_eq!(home_before, files(&home));
    assert_eq!(store.active().unwrap().plugins[0].plugin, first.plugin);
}

#[test]
fn compact_index_contains_no_component_instructions_or_literal_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    write(&source, "mcp.json", serde_json::to_vec(&json!({
        "$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers":{"fixture":{"type":"stdio","command":"fixture-never-run","env":{"TOKEN":"fixture-secret-only-in-original-package"}}}
    })).unwrap());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, false)
        .unwrap();
    let bytes = fs::read(index(&home)).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    for prohibited in [
        "fixture-secret-only-in-original-package",
        "Preserve the original instruction body",
        "source_metadata",
        "components",
        "mcpServers",
    ] {
        assert!(
            !text.contains(prohibited),
            "Raw source data leaked into the compact index"
        );
    }
    let status = store.status(&id(StoreScope::User)).unwrap().unwrap();
    assert_eq!(status.components.len(), 2);
}

#[test]
fn corrupt_index_fails_closed_without_repair_or_package_execution() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    fs::write(index(&home), b"{broken-index").unwrap();
    let before = files(&home);
    assert_eq!(store.list().unwrap_err().code, "store_index_corrupt");
    assert_eq!(store.active().unwrap_err().code, "store_index_corrupt");
    assert_eq!(
        store
            .import(&source, &InspectOptions::default(), StoreScope::User, true)
            .unwrap_err()
            .code,
        "store_index_corrupt"
    );
    assert_eq!(before, files(&home));
}

#[test]
fn tampered_package_is_excluded_with_a_diagnostic_without_namespace_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let root = store.active().unwrap().plugins[0].root.clone();
    let license = root.join("LICENSE");
    fs::set_permissions(&license, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&license, b"Tampered bytes\n").unwrap();
    fs::set_permissions(&license, fs::Permissions::from_mode(0o400)).unwrap();
    let before = files(&home);
    let active = store.active().unwrap();
    assert!(active.plugins.is_empty());
    assert!(
        active
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "store_package_tampered")
    );
    assert_eq!(
        store.status(&id(StoreScope::User)).unwrap_err().code,
        "store_package_tampered"
    );
    assert_eq!(before, files(&home));
}

#[test]
fn untrusted_project_is_never_read_activated_or_mutated() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let trusted = PluginStore::open(&home, &project, true).unwrap();
    trusted
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let fake_project_store = project.join(".orbit/plugins/portable");
    fs::create_dir_all(&fake_project_store).unwrap();
    fs::write(
        fake_project_store.join("index.json"),
        b"malformed untrusted index",
    )
    .unwrap();
    let before = files(temp.path());
    let untrusted = PluginStore::open(&home, &project, false).unwrap();
    let active = untrusted.active().unwrap();
    assert_eq!(active.plugins.len(), 1);
    assert!(
        active
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "store_project_untrusted")
    );
    assert_eq!(
        untrusted
            .import(
                &source,
                &InspectOptions::default(),
                StoreScope::Project,
                true
            )
            .unwrap_err()
            .code,
        "store_project_untrusted"
    );
    assert_eq!(
        untrusted.status(&id(StoreScope::Project)).unwrap_err().code,
        "store_project_untrusted"
    );
    assert_eq!(before, files(temp.path()));
}

#[test]
fn trusted_project_import_survives_reopen_but_is_absent_without_trust() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let receipt = PluginStore::open(&home, &project, true)
        .unwrap()
        .import(
            &source,
            &InspectOptions::default(),
            StoreScope::Project,
            true,
        )
        .unwrap();
    assert_eq!(receipt.plugin.id.scope, StoreScope::Project);
    let reopened = PluginStore::open(&home, &project, true).unwrap();
    assert_eq!(reopened.active().unwrap().plugins[0].plugin, receipt.plugin);
    assert!(
        PluginStore::open(&home, &project, false)
            .unwrap()
            .active()
            .unwrap()
            .plugins
            .is_empty()
    );
}

#[test]
fn same_name_across_scopes_is_a_collision_even_when_staged() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, false)
        .unwrap();
    let before = files(temp.path());
    assert_eq!(
        store
            .import(
                &source,
                &InspectOptions::default(),
                StoreScope::Project,
                false
            )
            .unwrap_err()
            .code,
        "store_namespace_collision"
    );
    assert_eq!(before, files(temp.path()));
}

#[test]
fn manifestless_original_identity_survives_digest_directory_reinspection() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let project = temp.path().join("project");
    let source = temp.path().join("plain-plugin");
    fs::create_dir(&project).unwrap();
    write(
        &source,
        "skills/review/SKILL.md",
        "---\nname: review\ndescription: Read a patch\n---\nOriginal body\n",
    );
    let store = PluginStore::open(&home, &project, true).unwrap();
    let receipt = store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    assert_eq!(receipt.plugin.id.name, "plain-plugin");
    assert_eq!(receipt.plugin.source.manifest_path, None);
    assert_eq!(
        receipt.plugin.source.inferred_name.as_deref(),
        Some("plain-plugin")
    );
    assert_eq!(
        PluginStore::open(&home, &project, true)
            .unwrap()
            .active()
            .unwrap()
            .plugins[0]
            .plugin,
        receipt.plugin
    );
}

#[test]
fn refuses_linked_or_public_store_entries_without_touching_targets() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    write(&outside, "sentinel", "preserve me");
    symlink(&outside, &home).unwrap();
    assert!(PluginStore::open(&home, &project, true).is_err());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"preserve me");
    fs::remove_file(&home).unwrap();
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(PluginStore::open(&home, &project, true).is_err());
    assert!(!home.join("plugins").exists());
    assert!(!source.join("execution-marker").exists());
}

#[test]
fn hardlinked_index_and_mutable_package_mode_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let root = store.active().unwrap().plugins[0].root.clone();
    fs::set_permissions(root.join("LICENSE"), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.active().unwrap().plugins.is_empty());
    fs::set_permissions(root.join("LICENSE"), fs::Permissions::from_mode(0o400)).unwrap();
    fs::hard_link(index(&home), temp.path().join("index-alias")).unwrap();
    let before = fs::read(index(&home)).unwrap();
    assert_eq!(store.list().unwrap_err().code, "store_file_unsafe");
    assert_eq!(before, fs::read(index(&home)).unwrap());
}

#[test]
fn replacing_actual_project_invalidates_existing_store_handle() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, _) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    fs::rename(&project, temp.path().join("previous-project")).unwrap();
    fs::create_dir(&project).unwrap();
    assert_eq!(store.list().unwrap_err().code, "store_path_changed");
    assert!(!home.exists());
    assert!(!project.join(".orbit").exists());
}

#[test]
fn duplicate_nested_index_keys_are_corruption_without_repair() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, false)
        .unwrap();
    let original = fs::read_to_string(index(&home)).unwrap();
    let duplicated = original.replace(
        "\"model_map\":{}",
        "\"model_map\":{\"source\":\"first\",\"source\":\"second\"}",
    );
    assert_ne!(original, duplicated);
    fs::write(index(&home), &duplicated).unwrap();
    assert_eq!(store.list().unwrap_err().code, "store_index_corrupt");
    assert_eq!(fs::read_to_string(index(&home)).unwrap(), duplicated);
}

#[test]
fn index_size_summary_cannot_hide_large_or_changed_owned_content() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(index(&home)).unwrap()).unwrap();
    value["entries"][0]["source_bytes"] = json!(0);
    fs::write(index(&home), serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(store.active().unwrap().plugins.is_empty());
    assert_eq!(
        store.status(&id(StoreScope::User)).unwrap_err().code,
        "store_package_tampered"
    );
    value["entries"][0]["source_bytes"] = json!(u64::MAX);
    fs::write(index(&home), serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(store.active().unwrap_err().code, "store_index_corrupt");
}

#[test]
fn shared_project_lock_serializes_imports_from_same_and_different_homes() {
    for same_home in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let (home, project, source) = roots(temp.path());
        let second_home = if same_home {
            home.clone()
        } else {
            temp.path().join("second-home")
        };
        let baseline = PluginStore::open(&home, &project, true).unwrap();
        baseline
            .import(
                &source,
                &InspectOptions::default(),
                StoreScope::Project,
                true,
            )
            .unwrap();
        let project_store = project.join(".orbit/plugins/portable");
        let project_index = project_store.join("index.json");
        let project_previous = project_store.join("index.previous.json");
        let main_before = fs::read(&project_index).unwrap();
        let previous_before = fs::read(&project_previous).ok();
        let user_before = fs::read(index(&home)).ok();
        let second_user_before = fs::read(index(&second_home)).ok();
        let lock_path = project_store.join("mutation.lock");
        let held_lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        rustix::fs::flock(&held_lock, rustix::fs::FlockOperation::LockExclusive).unwrap();
        let lock_before = held_lock.metadata().unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let (ready_tx, ready_rx) = mpsc::sync_channel(2);
        let (done_tx, done_rx) = mpsc::sync_channel(2);
        let mut handles = Vec::new();
        let homes = [home.clone(), second_home.clone()];
        let sources = [temp.path().join("alpha"), temp.path().join("beta")];
        for (position, (contender_home, contender_source)) in homes.iter().zip(&sources).enumerate()
        {
            package(contender_source, ["alpha", "beta"][position]);
            let contender = PluginStore::open(contender_home, &project, true).unwrap();
            let contender_source = contender_source.clone();
            let barrier = barrier.clone();
            let ready_tx = ready_tx.clone();
            let done_tx = done_tx.clone();
            handles.push(std::thread::spawn(move || {
                ready_tx.send(()).unwrap();
                barrier.wait();
                let result = contender
                    .import(
                        &contender_source,
                        &InspectOptions::default(),
                        StoreScope::Project,
                        true,
                    )
                    .map(|_| ())
                    .map_err(|error| error.code);
                done_tx.send(result).unwrap();
            }));
        }
        drop(ready_tx);
        drop(done_tx);
        for _ in 0..2 {
            ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        }
        barrier.wait();
        for _ in 0..2 {
            assert_eq!(
                done_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
                Err("store_busy".to_owned()),
                "The actual project scope must serialize every writer, same_home={same_home}"
            );
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(fs::read(&project_index).unwrap(), main_before);
        assert_eq!(fs::read(&project_previous).ok(), previous_before);
        assert_eq!(fs::read(index(&home)).ok(), user_before);
        assert_eq!(fs::read(index(&second_home)).ok(), second_user_before);
        assert_eq!(baseline.active().unwrap().plugins.len(), 1);
        drop(held_lock);

        for (contender_home, contender_source) in homes.iter().zip(&sources) {
            PluginStore::open(contender_home, &project, true)
                .unwrap()
                .import(
                    contender_source,
                    &InspectOptions::default(),
                    StoreScope::Project,
                    true,
                )
                .unwrap();
        }
        for contender_home in homes {
            let active = PluginStore::open(&contender_home, &project, true)
                .unwrap()
                .active()
                .unwrap();
            let names: Vec<_> = active
                .plugins
                .iter()
                .map(|plugin| plugin.plugin.id.name.as_str())
                .collect();
            assert_eq!(names, ["alpha", "beta", "sample"]);
            assert!(active.diagnostics.is_empty());
            assert!(
                active
                    .plugins
                    .iter()
                    .all(|plugin| plugin.plugin.id.scope == StoreScope::Project)
            );
        }
        let lock_after = fs::metadata(&lock_path).unwrap();
        assert_eq!(
            (lock_before.dev(), lock_before.ino()),
            (lock_after.dev(), lock_after.ino())
        );
    }
}

fn mapped_options(entries: usize) -> InspectOptions {
    InspectOptions {
        model_map: (0..entries)
            .map(|entry| (format!("k{entry:04}"), "v".to_owned()))
            .collect(),
        ..InspectOptions::default()
    }
}

#[test]
fn index_node_limit_is_rejected_before_any_package_or_index_publication() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let second_source = temp.path().join("second");
    package(&second_source, "second");
    let options = mapped_options(4200);
    let store = PluginStore::open(&home, &project, true).unwrap();
    let first = store
        .import(&source, &options, StoreScope::User, true)
        .unwrap();
    assert_eq!(first.plugin.options.model_map.len(), 4200);
    let before = files(&home);
    let active_before = store.active().unwrap();

    assert_eq!(
        store
            .import(&second_source, &options, StoreScope::User, true)
            .unwrap_err()
            .code,
        "store_index_limit"
    );
    assert_eq!(files(&home), before);
    assert!(!home.join("plugins/portable/packages/second").exists());
    let reopened = PluginStore::open(&home, &project, true).unwrap();
    assert_eq!(reopened.list().unwrap(), first.snapshot);
    assert_eq!(reopened.active().unwrap(), active_before);
}

#[test]
fn near_limit_index_round_trips_through_a_fresh_reader() {
    fn nodes(value: &serde_json::Value) -> usize {
        1 + match value {
            serde_json::Value::Array(values) => values.iter().map(nodes).sum(),
            serde_json::Value::Object(values) => values.values().map(nodes).sum(),
            _ => 0,
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let second_source = temp.path().join("second");
    package(&second_source, "second");
    let options = mapped_options(4000);
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&source, &options, StoreScope::User, true)
        .unwrap();
    let second = store
        .import(&second_source, &options, StoreScope::User, true)
        .unwrap();
    let bytes = fs::read(index(&home)).unwrap();
    assert!(bytes.len() < 256 * 1024);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!((8000..=8192).contains(&nodes(&value)));
    assert_eq!(value["entries"].as_array().unwrap().len(), 2);
    for entry in value["entries"].as_array().unwrap() {
        assert_eq!(
            entry["options"]["model_map"].as_object().unwrap().len(),
            4000
        );
    }
    let reopened = PluginStore::open(&home, &project, true).unwrap();
    assert_eq!(reopened.list().unwrap(), second.snapshot);
    let active = reopened.active().unwrap();
    assert_eq!(active.plugins.len(), 2);
    assert!(active.diagnostics.is_empty());
    assert!(
        active
            .plugins
            .iter()
            .all(|plugin| plugin.plugin.options == options)
    );
}

#[test]
fn trusted_user_import_of_actual_project_preserves_the_entire_source_tree() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let project = temp.path().join("source-project");
    package(&project, "sample");
    let before = files(&project);
    let store = PluginStore::open(&home, &project, true).unwrap();
    store
        .import(&project, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    assert_eq!(before, files(&project));
    assert!(!project.join(".orbit").exists());
    let active = store.active().unwrap();
    assert_eq!(active.plugins.len(), 1);
    assert_eq!(active.plugins[0].plugin.id.scope, StoreScope::User);
    assert_ne!(active.plugins[0].root, project);
}

#[test]
fn fresh_read_rejects_cross_scope_collision_introduced_by_another_home() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let first = PluginStore::open(&home, &project, true).unwrap();
    first
        .import(&source, &InspectOptions::default(), StoreScope::User, true)
        .unwrap();
    let user_index = fs::read(index(&home)).unwrap();
    let other_home = temp.path().join("other-home");
    let other = PluginStore::open(&other_home, &project, true).unwrap();
    other
        .import(
            &source,
            &InspectOptions::default(),
            StoreScope::Project,
            true,
        )
        .unwrap();
    assert_eq!(fs::read(index(&home)).unwrap(), user_index);
    assert_eq!(first.list().unwrap_err().code, "store_namespace_collision");
    assert_eq!(
        first.active().unwrap_err().code,
        "store_namespace_collision"
    );
    assert_eq!(other.active().unwrap().plugins.len(), 1);
}

#[test]
fn known_invalid_project_candidate_creates_neither_scope_nor_lock() {
    let temp = tempfile::tempdir().unwrap();
    let (home, project, source) = roots(temp.path());
    let before = files(temp.path());
    let store = PluginStore::open(&home, &project, true).unwrap();
    assert_eq!(
        store
            .import(&source, &mapped_options(8400), StoreScope::Project, true)
            .unwrap_err()
            .code,
        "store_index_limit"
    );
    assert_eq!(files(temp.path()), before);
    assert!(!home.exists());
    assert!(!project.join(".orbit").exists());
}
