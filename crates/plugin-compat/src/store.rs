use crate::fs::{Directory, MutationLocks, absolute, failure, temp_name};
use crate::inspect::SourceTree;
use crate::{
    CompatError, Diagnostic, DiagnosticSeverity, InspectOptions, Inspection, PluginComponent,
    PluginFormat, PluginManifest, PluginSource, Requirement,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const MAX_INDEX_BYTES: usize = 256 * 1024;
const MAX_PLUGINS: usize = 256;
const MAX_STORE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreScope {
    User,
    Project,
}

/// A name is never resolved across scopes implicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginId {
    pub name: String,
    pub scope: StoreScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPlugin {
    pub id: PluginId,
    pub manifest: PluginManifest,
    pub source: PluginSource,
    pub enabled: bool,
    pub digest: String,
    pub options: InspectOptions,
    pub components: Vec<PluginComponent>,
    pub requirements: Vec<Requirement>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSnapshot {
    pub revision: String,
    pub entries: Vec<StoredPlugin>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePlugin {
    pub plugin: StoredPlugin,
    pub root: PathBuf,
    /// A reserved private state location; querying never creates it.
    pub data_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationSnapshot {
    pub revision: String,
    pub plugins: Vec<ActivePlugin>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportReceipt {
    pub snapshot: StoreSnapshot,
    pub plugin: StoredPlugin,
    pub reused: bool,
}

/// The persisted index has no component instructions, raw metadata or credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    schema_version: u32,
    generation: u64,
    entries: Vec<Record>,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            schema_version: 1,
            generation: 0,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    name: String,
    format: PluginFormat,
    manifest_path: Option<String>,
    inferred_name: Option<String>,
    digest: String,
    source_bytes: u64,
    enabled: bool,
    options: InspectOptions,
}

impl Record {
    fn inspected(inspection: &Inspection, options: &InspectOptions, enabled: bool) -> Self {
        Self {
            name: inspection.manifest.id.clone(),
            format: inspection.source.format,
            manifest_path: inspection.source.manifest_path.clone(),
            inferred_name: inspection.source.inferred_name.clone(),
            digest: inspection.source.source_digest.clone(),
            source_bytes: source_bytes(&inspection.source),
            enabled,
            options: options.clone(),
        }
    }
}

struct IndexView {
    directory: Option<Directory>,
    bytes: Option<Vec<u8>>,
    index: Index,
}

enum ImportCandidate {
    Existing(Record),
    New { record: Record, bytes: Vec<u8> },
}

pub struct PluginStore {
    home: PathBuf,
    project: PathBuf,
    project_anchor: Directory,
    project_trusted: bool,
}

impl PluginStore {
    /// Capture the actual project path without creating either scope's state.
    pub fn open(home: &Path, project: &Path, project_trusted: bool) -> Result<Self, CompatError> {
        let home = absolute(home)?;
        let project = absolute(project)?;
        Directory::open_optional(&home, false, true)?;
        let project_anchor = Directory::open_optional(&project, false, false)?
            .ok_or_else(|| failure("store_path_invalid"))?;
        if home == project.join(".orbit") {
            return Err(error("store_scope_alias"));
        }
        Ok(Self {
            home,
            project,
            project_anchor,
            project_trusted,
        })
    }

    pub fn list(&self) -> Result<StoreSnapshot, CompatError> {
        let (revision, user, project) = self.stable_indices()?;
        let mut entries = Vec::new();
        let mut diagnostics = self.trust_diagnostics();
        for (scope, view) in [(StoreScope::User, &user), (StoreScope::Project, &project)] {
            for record in &view.index.entries {
                match self.load(view, scope, record) {
                    Ok(plugin) => entries.push(plugin),
                    Err(error) => diagnostics.push(package_diagnostic(record, &error)),
                }
            }
        }
        self.assert_revision(&revision)?;
        Ok(StoreSnapshot {
            revision,
            entries,
            diagnostics,
        })
    }

    pub fn status(&self, id: &PluginId) -> Result<Option<StoredPlugin>, CompatError> {
        validate_id(&id.name)?;
        if id.scope == StoreScope::Project && !self.project_trusted {
            return Err(error("store_project_untrusted"));
        }
        let (revision, user, project) = self.stable_indices()?;
        let view = if id.scope == StoreScope::User {
            &user
        } else {
            &project
        };
        let result = view
            .index
            .entries
            .iter()
            .find(|record| record.name == id.name)
            .map(|record| self.load(view, id.scope, record))
            .transpose()?;
        self.assert_revision(&revision)?;
        Ok(result)
    }

    pub fn active(&self) -> Result<ActivationSnapshot, CompatError> {
        let (revision, user, project) = self.stable_indices()?;
        let mut plugins = Vec::new();
        let mut diagnostics = self.trust_diagnostics();
        for (scope, view) in [(StoreScope::User, &user), (StoreScope::Project, &project)] {
            for record in view.index.entries.iter().filter(|record| record.enabled) {
                match self.load(view, scope, record) {
                    Ok(plugin) => {
                        let root = view
                            .directory
                            .as_ref()
                            .ok_or_else(|| error("store_index_corrupt"))?
                            .path()
                            .join("packages")
                            .join(&record.name)
                            .join(&record.digest);
                        let data_root = view
                            .directory
                            .as_ref()
                            .ok_or_else(|| error("store_index_corrupt"))?
                            .path()
                            .join("data")
                            .join(&record.name);
                        plugins.push(ActivePlugin {
                            plugin,
                            root,
                            data_root,
                        });
                    }
                    Err(error) => diagnostics.push(package_diagnostic(record, &error)),
                }
            }
        }
        self.assert_revision(&revision)?;
        Ok(ActivationSnapshot {
            revision,
            plugins,
            diagnostics,
        })
    }

    /// Read only captured inventory bytes through a currently verified owned root.
    pub fn read_asset(
        &self,
        id: &PluginId,
        expected_digest: &str,
        relative: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, CompatError> {
        validate_id(&id.name)?;
        if max_bytes == 0
            || max_bytes > 8 * 1024 * 1024
            || relative.is_empty()
            || relative.len() > 1024
            || relative
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".." || part.contains('\\'))
            || Path::new(relative)
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(error("store_asset_invalid"));
        }
        let (revision, user, project) = self.stable_indices()?;
        let view = scoped_view(id.scope, &user, &project);
        let record = &view.index.entries[record_position(view, id)?];
        if !record.enabled || record.digest != expected_digest {
            return Err(error("store_asset_stale"));
        }
        self.load(view, id.scope, record)?;
        let root = view
            .directory
            .as_ref()
            .ok_or_else(|| error("store_package_missing"))?
            .child("packages", false)?
            .ok_or_else(|| error("store_package_missing"))?
            .child(&id.name, false)?
            .ok_or_else(|| error("store_package_missing"))?
            .child(expected_digest, false)?
            .ok_or_else(|| error("store_package_missing"))?;
        let tree = SourceTree::read_named(&root.held_path()?, record.inferred_name.as_deref())?;
        check_private_tree(&root, &tree)?;
        if tree.source_digest != expected_digest {
            return Err(error("store_package_tampered"));
        }
        let bytes = tree
            .bytes
            .get(relative)
            .ok_or_else(|| error("store_asset_missing"))?;
        if bytes.len() > max_bytes {
            return Err(error("store_asset_limit"));
        }
        let bytes = bytes.clone();
        root.check()?;
        self.assert_revision(&revision)?;
        Ok(bytes)
    }

    /// Enable only the verified package observed by the caller.
    pub fn enable(
        &self,
        id: &PluginId,
        expected_revision: &str,
    ) -> Result<StoreSnapshot, CompatError> {
        self.set_enabled(id, expected_revision, true)
    }

    pub fn disable(
        &self,
        id: &PluginId,
        expected_revision: &str,
    ) -> Result<StoreSnapshot, CompatError> {
        self.set_enabled(id, expected_revision, false)
    }

    /// Remove the active index entry, retaining immutable versions and user data.
    pub fn remove(
        &self,
        id: &PluginId,
        expected_revision: &str,
    ) -> Result<StoreSnapshot, CompatError> {
        let (locks, user, project) = self.lock_mutation(id, expected_revision)?;
        let view = scoped_view(id.scope, &user, &project);
        let position = record_position(view, id)?;
        let mut index = view.index.clone();
        index.entries.remove(position);
        self.publish_index(id.scope, view, expected_revision, &locks, index, None)
    }

    /// Replace one explicit identity without changing its enabled state.
    pub fn upgrade(
        &self,
        id: &PluginId,
        source: &Path,
        options: &InspectOptions,
        expected_revision: &str,
    ) -> Result<ImportReceipt, CompatError> {
        self.check_mutation_scope(id)?;
        self.assert_revision(expected_revision)?;
        let tree = SourceTree::read_named(source, None)?;
        let inspection = crate::formats::normalize(&tree, options)?;
        if inspection.manifest.id != id.name {
            return Err(error("store_identity_mismatch"));
        }
        let (locks, user, project) = self.lock_mutation(id, expected_revision)?;
        let view = scoped_view(id.scope, &user, &project);
        let position = record_position(view, id)?;
        let previous = &view.index.entries[position];
        if previous.digest == tree.source_digest && previous.options == *options {
            let plugin = self.load(view, id.scope, previous)?;
            locks.check()?;
            let snapshot = self.list()?;
            if !snapshot.entries.contains(&plugin) {
                return Err(error("store_package_tampered"));
            }
            return Ok(ImportReceipt {
                snapshot,
                plugin,
                reused: true,
            });
        }
        let total = user
            .index
            .entries
            .iter()
            .chain(&project.index.entries)
            .try_fold(0u64, |total, record| total.checked_add(record.source_bytes))
            .and_then(|total| total.checked_sub(previous.source_bytes))
            .and_then(|total| total.checked_add(source_bytes(&inspection.source)))
            .ok_or_else(|| error("store_plugin_limit"))?;
        if total > MAX_STORE_BYTES {
            return Err(error("store_plugin_limit"));
        }
        let mut index = view.index.clone();
        index.entries[position] = Record::inspected(&inspection, options, previous.enabled);
        // Reject an unreadable candidate before retaining any new package files.
        index_bytes(&next_generation(index.clone())?)?;
        self.capture_package(&tree, &inspection, options, id.scope)?;
        let snapshot = self.publish_index(
            id.scope,
            view,
            expected_revision,
            &locks,
            index,
            Some(&id.name),
        )?;
        let plugin = snapshot
            .entries
            .iter()
            .find(|plugin| plugin.id == *id)
            .cloned()
            .ok_or_else(|| failure("store_publication_uncertain"))?;
        Ok(ImportReceipt {
            snapshot,
            plugin,
            reused: false,
        })
    }

    fn set_enabled(
        &self,
        id: &PluginId,
        expected_revision: &str,
        enabled: bool,
    ) -> Result<StoreSnapshot, CompatError> {
        let (locks, user, project) = self.lock_mutation(id, expected_revision)?;
        let view = scoped_view(id.scope, &user, &project);
        let position = record_position(view, id)?;
        let record = &view.index.entries[position];
        let verified = enabled
            .then(|| self.load(view, id.scope, record))
            .transpose()?;
        if record.enabled == enabled {
            locks.check()?;
            let snapshot = self.list()?;
            if verified.is_some_and(|plugin| !snapshot.entries.contains(&plugin)) {
                return Err(error("store_package_tampered"));
            }
            return Ok(snapshot);
        }
        let mut index = view.index.clone();
        index.entries[position].enabled = enabled;
        self.publish_index(
            id.scope,
            view,
            expected_revision,
            &locks,
            index,
            enabled.then_some(id.name.as_str()),
        )
    }

    fn check_mutation_scope(&self, id: &PluginId) -> Result<(), CompatError> {
        validate_id(&id.name)?;
        if id.scope == StoreScope::Project && !self.project_trusted {
            return Err(error("store_project_untrusted"));
        }
        self.project_anchor.check()
    }

    fn lock_mutation(
        &self,
        id: &PluginId,
        expected_revision: &str,
    ) -> Result<(MutationLocks, IndexView, IndexView), CompatError> {
        self.check_mutation_scope(id)?;
        let (revision, user, project) = self.stable_indices()?;
        if revision != expected_revision {
            return Err(error("store_revision_changed"));
        }
        record_position(scoped_view(id.scope, &user, &project), id)?;
        let mut directories = vec![
            self.scope_directory(StoreScope::User, true)?
                .ok_or_else(|| failure("store_write_failed"))?,
        ];
        if id.scope == StoreScope::Project {
            directories.push(
                self.scope_directory(StoreScope::Project, false)?
                    .ok_or_else(|| error("store_plugin_missing"))?,
            );
        }
        let locks = MutationLocks::acquire(&directories)?;
        let (revision, user, project) = self.stable_indices()?;
        if revision != expected_revision {
            return Err(error("store_revision_changed"));
        }
        record_position(scoped_view(id.scope, &user, &project), id)?;
        Ok((locks, user, project))
    }

    fn publish_index(
        &self,
        scope: StoreScope,
        view: &IndexView,
        expected_revision: &str,
        locks: &MutationLocks,
        index: Index,
        verify_name: Option<&str>,
    ) -> Result<StoreSnapshot, CompatError> {
        let index = next_generation(index)?;
        let bytes = index_bytes(&index)?;
        let directory = view
            .directory
            .as_ref()
            .ok_or_else(|| error("store_index_corrupt"))?;
        let previous = view
            .bytes
            .as_ref()
            .ok_or_else(|| error("store_index_corrupt"))?;
        locks.check()?;
        self.assert_revision(expected_revision)?;
        directory.atomic_write("index.previous.json", previous)?;
        locks.check()?;
        self.assert_revision(expected_revision)?;
        directory.atomic_write("index.json", &bytes)?;
        locks
            .check()
            .map_err(|_| failure("store_publication_uncertain"))?;
        let snapshot = self
            .list()
            .map_err(|_| failure("store_publication_uncertain"))?;
        let published = read_index(self.scope_directory(scope, false)?)
            .map_err(|_| failure("store_publication_uncertain"))?;
        if published.bytes.as_deref() != Some(bytes.as_slice()) {
            return Err(failure("store_publication_uncertain"));
        }
        // The exact index bytes confirm disable/remove even when damaged
        // content is deliberately absent from list. Only newly accepted content
        // must also survive fresh reinspection before reporting success.
        if let Some(name) = verify_name {
            let record = index
                .entries
                .iter()
                .find(|record| record.name == name)
                .ok_or_else(|| failure("store_publication_uncertain"))?;
            let verified = snapshot.entries.iter().any(|plugin| {
                plugin.id.scope == scope
                    && plugin.id.name == record.name
                    && plugin.digest == record.digest
                    && plugin.enabled == record.enabled
                    && plugin.options == record.options
            });
            if !verified {
                return Err(failure("store_publication_uncertain"));
            }
        }
        self.assert_revision(&snapshot.revision)
            .map_err(|_| failure("store_publication_uncertain"))?;
        Ok(snapshot)
    }

    fn capture_package(
        &self,
        tree: &SourceTree,
        inspection: &Inspection,
        options: &InspectOptions,
        scope: StoreScope,
    ) -> Result<(), CompatError> {
        let directory = self
            .scope_directory(scope, true)?
            .ok_or_else(|| failure("store_write_failed"))?;
        let packages = directory
            .child("packages", true)?
            .ok_or_else(|| failure("store_write_failed"))?;
        let names = packages
            .child(&inspection.manifest.id, true)?
            .ok_or_else(|| failure("store_write_failed"))?;
        if let Some(existing) = names.child(&tree.source_digest, false)? {
            verify_tree(&existing, &inspection.source, options)?;
        } else {
            let stage_name = temp_name("package");
            let stage = names
                .child(&stage_name, true)?
                .ok_or_else(|| failure("store_write_failed"))?;
            copy_snapshot(tree, &stage)?;
            verify_tree(&stage, &inspection.source, options)?;
            stage.sync()?;
            names.publish_directory(&stage_name, &tree.source_digest)?;
        }
        Ok(())
    }

    /// Import the captured source bytes only; never execute package code.
    pub fn import(
        &self,
        source: &Path,
        options: &InspectOptions,
        scope: StoreScope,
        enable: bool,
    ) -> Result<ImportReceipt, CompatError> {
        if scope == StoreScope::Project && !self.project_trusted {
            return Err(error("store_project_untrusted"));
        }
        let tree = SourceTree::read_named(source, None)?;
        let inspection = crate::formats::normalize(&tree, options)?;
        validate_id(&inspection.manifest.id)?;
        self.project_anchor.check()?;
        // Reject known invalid candidates before creating either scope or lock.
        // This preflight is advisory; fresh locked validation below is required.
        let (_, preflight_user, preflight_project) = self.stable_indices()?;
        prepare_import(
            &preflight_user,
            &preflight_project,
            &inspection,
            options,
            scope,
            enable,
        )?;
        let user_directory = self
            .scope_directory(StoreScope::User, true)?
            .ok_or_else(|| failure("store_write_failed"))?;
        // A writer locks each index it can mutate. The actual project lock is
        // shared by different homes; a user import never creates project state.
        let mut lock_directories = vec![user_directory];
        if scope == StoreScope::Project {
            lock_directories.push(
                self.scope_directory(StoreScope::Project, true)?
                    .ok_or_else(|| failure("store_write_failed"))?,
            );
        }
        let locks = MutationLocks::acquire(&lock_directories)?;
        let (revision, user, project) = self.stable_indices()?;
        let view = if scope == StoreScope::User {
            &user
        } else {
            &project
        };
        let (record, bytes) =
            match prepare_import(&user, &project, &inspection, options, scope, enable)? {
                ImportCandidate::Existing(existing) => {
                    let plugin = self.load(view, scope, &existing)?;
                    locks.check()?;
                    return Ok(ImportReceipt {
                        snapshot: self.list()?,
                        plugin,
                        reused: true,
                    });
                }
                ImportCandidate::New { record, bytes } => (record, bytes),
            };
        let directory = self
            .scope_directory(scope, true)?
            .ok_or_else(|| failure("store_write_failed"))?;
        self.capture_package(&tree, &inspection, options, scope)?;
        locks.check()?;
        self.assert_revision(&revision)?;
        let previous = view
            .bytes
            .clone()
            .unwrap_or_else(|| b"{\"schema_version\":1,\"generation\":0,\"entries\":[]}".to_vec());
        directory.atomic_write("index.previous.json", &previous)?;
        locks.check()?;
        self.assert_revision(&revision)?;
        directory.atomic_write("index.json", &bytes)?;
        locks
            .check()
            .map_err(|_| failure("store_publication_uncertain"))?;
        let snapshot = self
            .list()
            .map_err(|_| failure("store_publication_uncertain"))?;
        let plugin = snapshot
            .entries
            .iter()
            .find(|plugin| plugin.id.name == record.name && plugin.id.scope == scope)
            .cloned()
            .ok_or_else(|| failure("store_publication_uncertain"))?;
        Ok(ImportReceipt {
            snapshot,
            plugin,
            reused: false,
        })
    }

    fn scope_directory(
        &self,
        scope: StoreScope,
        create: bool,
    ) -> Result<Option<Directory>, CompatError> {
        self.project_anchor.check()?;
        if scope == StoreScope::Project && !self.project_trusted {
            return Ok(None);
        }
        let base = if scope == StoreScope::User {
            Directory::open_optional(&self.home, create, true)?
        } else {
            Directory::open_project_container(&self.project.join(".orbit"), create)?
        };
        let Some(base) = base else {
            return Ok(None);
        };
        let Some(plugins) = base.child("plugins", create)? else {
            return Ok(None);
        };
        plugins.child("portable", create)
    }

    fn indices(&self) -> Result<(IndexView, IndexView), CompatError> {
        self.project_anchor.check()?;
        let user = read_index(self.scope_directory(StoreScope::User, false)?)?;
        let project = read_index(self.scope_directory(StoreScope::Project, false)?)?;
        let mut names = BTreeSet::new();
        let mut source_bytes = 0u64;
        for record in user.index.entries.iter().chain(&project.index.entries) {
            if !names.insert(record.name.to_ascii_lowercase()) {
                return Err(error("store_namespace_collision"));
            }
            source_bytes = source_bytes
                .checked_add(record.source_bytes)
                .ok_or_else(|| error("store_index_corrupt"))?;
            if source_bytes > MAX_STORE_BYTES {
                return Err(error("store_index_corrupt"));
            }
        }
        Ok((user, project))
    }

    fn revision(&self, user: &IndexView, project: &IndexView) -> Result<String, CompatError> {
        let mut digest = Sha256::new();
        digest.update(b"orbit-plugin-store-v1\0");
        digest.update(self.project.as_os_str().as_encoded_bytes());
        let (device, inode) = self.project_anchor.identity()?;
        digest.update(device.to_be_bytes());
        digest.update(inode.to_be_bytes());
        digest.update([u8::from(self.project_trusted)]);
        for view in [user, project] {
            digest.update([u8::from(view.bytes.is_some())]);
            if let Some(bytes) = &view.bytes {
                digest.update((bytes.len() as u64).to_be_bytes());
                digest.update(bytes);
            }
        }
        Ok(hex::encode(digest.finalize()))
    }

    fn stable_indices(&self) -> Result<(String, IndexView, IndexView), CompatError> {
        for _ in 0..3 {
            let (user, project) = self.indices()?;
            let revision = self.revision(&user, &project)?;
            let (again_user, again_project) = self.indices()?;
            if revision == self.revision(&again_user, &again_project)? {
                return Ok((revision, user, project));
            }
        }
        Err(error("store_revision_changed"))
    }

    fn assert_revision(&self, expected: &str) -> Result<(), CompatError> {
        let (user, project) = self.indices()?;
        if self.revision(&user, &project)? != expected {
            return Err(error("store_revision_changed"));
        }
        Ok(())
    }

    fn load(
        &self,
        view: &IndexView,
        scope: StoreScope,
        record: &Record,
    ) -> Result<StoredPlugin, CompatError> {
        let directory = view
            .directory
            .as_ref()
            .ok_or_else(|| error("store_index_corrupt"))?;
        let packages = directory
            .child("packages", false)?
            .ok_or_else(|| error("store_package_missing"))?;
        let names = packages
            .child(&record.name, false)?
            .ok_or_else(|| error("store_package_missing"))?;
        let root = names
            .child(&record.digest, false)?
            .ok_or_else(|| error("store_package_missing"))?;
        let tree = SourceTree::read_named(&root.held_path()?, record.inferred_name.as_deref())?;
        check_private_tree(&root, &tree)?;
        if tree.source_digest != record.digest
            || tree.files.iter().map(|file| file.size).sum::<u64>() != record.source_bytes
        {
            return Err(error("store_package_tampered"));
        }
        let mut options = record.options.clone();
        if options.format.is_some_and(|format| format != record.format) {
            return Err(error("store_index_corrupt"));
        }
        options.format = Some(record.format);
        let inspection = crate::formats::normalize(&tree, &options)?;
        if inspection.manifest.id != record.name
            || inspection.source.manifest_path != record.manifest_path
            || inspection.source.inferred_name != record.inferred_name
        {
            return Err(error("store_package_tampered"));
        }
        root.check()?;
        Ok(StoredPlugin {
            id: PluginId {
                name: record.name.clone(),
                scope,
            },
            manifest: inspection.manifest,
            source: inspection.source,
            enabled: record.enabled,
            digest: record.digest.clone(),
            options: record.options.clone(),
            components: inspection.components,
            requirements: inspection.requirements,
            diagnostics: inspection.diagnostics,
        })
    }

    fn trust_diagnostics(&self) -> Vec<Diagnostic> {
        if self.project_trusted {
            return Vec::new();
        }
        vec![Diagnostic {
            code: "store_project_untrusted".into(),
            severity: DiagnosticSeverity::Info,
            component_id: None,
            source_path: None,
            message: "Project plugins are excluded until this project is trusted".into(),
            action: Some(
                "Trust the actual project before importing or activating project plugins".into(),
            ),
        }]
    }
}

/// Pure validation is shared by read-only preflight and locked publication.
fn scoped_view<'a>(
    scope: StoreScope,
    user: &'a IndexView,
    project: &'a IndexView,
) -> &'a IndexView {
    if scope == StoreScope::User {
        user
    } else {
        project
    }
}

fn record_position(view: &IndexView, id: &PluginId) -> Result<usize, CompatError> {
    view.index
        .entries
        .iter()
        .position(|record| record.name == id.name)
        .ok_or_else(|| error("store_plugin_missing"))
}

fn next_generation(mut index: Index) -> Result<Index, CompatError> {
    index.generation = index
        .generation
        .checked_add(1)
        .ok_or_else(|| error("store_index_corrupt"))?;
    Ok(index)
}

fn index_bytes(index: &Index) -> Result<Vec<u8>, CompatError> {
    let bytes = serde_json::to_vec(index).map_err(|_| error("store_index_limit"))?;
    if decode_index(&bytes).map_err(|_| failure("store_index_limit"))? != *index {
        return Err(failure("store_index_limit"));
    }
    Ok(bytes)
}

fn prepare_import(
    user: &IndexView,
    project: &IndexView,
    inspection: &Inspection,
    options: &InspectOptions,
    scope: StoreScope,
    enable: bool,
) -> Result<ImportCandidate, CompatError> {
    let (view, other) = if scope == StoreScope::User {
        (user, project)
    } else {
        (project, user)
    };
    if other
        .index
        .entries
        .iter()
        .any(|record| record.name.eq_ignore_ascii_case(&inspection.manifest.id))
    {
        return Err(error("store_namespace_collision"));
    }
    if let Some(existing) = view
        .index
        .entries
        .iter()
        .find(|record| record.name.eq_ignore_ascii_case(&inspection.manifest.id))
    {
        if existing.name != inspection.manifest.id {
            return Err(error("store_namespace_collision"));
        }
        if existing.digest != inspection.source.source_digest {
            return Err(error("store_upgrade_required"));
        }
        if existing.options != *options || existing.enabled != enable {
            return Err(error("store_state_conflict"));
        }
        return Ok(ImportCandidate::Existing(existing.clone()));
    }
    if view.index.entries.len() >= MAX_PLUGINS {
        return Err(error("store_plugin_limit"));
    }
    let existing_bytes = user
        .index
        .entries
        .iter()
        .chain(&project.index.entries)
        .try_fold(0u64, |total, record| total.checked_add(record.source_bytes))
        .ok_or_else(|| error("store_index_corrupt"))?;
    if existing_bytes
        .checked_add(source_bytes(&inspection.source))
        .is_none_or(|total| total > MAX_STORE_BYTES)
    {
        return Err(error("store_plugin_limit"));
    }
    let mut index = view.index.clone();
    index.generation = index
        .generation
        .checked_add(1)
        .ok_or_else(|| error("store_index_corrupt"))?;
    let record = Record::inspected(inspection, options, enable);
    index.entries.push(record.clone());
    index.entries.sort_by(|a, b| a.name.cmp(&b.name));
    let bytes = index_bytes(&index)?;
    Ok(ImportCandidate::New { record, bytes })
}

fn read_index(directory: Option<Directory>) -> Result<IndexView, CompatError> {
    let bytes = directory
        .as_ref()
        .map(|directory| directory.read("index.json", MAX_INDEX_BYTES))
        .transpose()?
        .flatten();
    let index = bytes
        .as_deref()
        .map(decode_index)
        .transpose()?
        .unwrap_or_default();
    Ok(IndexView {
        directory,
        bytes,
        index,
    })
}

/// Both persisted reads and prospective writes use this exact validation path.
fn decode_index(bytes: &[u8]) -> Result<Index, CompatError> {
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(failure("store_index_limit"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| error("store_index_corrupt"))?;
    let value = crate::formats::parse_json(text).map_err(|_| error("store_index_corrupt"))?;
    let index: Index = serde_json::from_value(value).map_err(|_| error("store_index_corrupt"))?;
    if index.schema_version != 1 || index.entries.len() > MAX_PLUGINS {
        return Err(error("store_index_corrupt"));
    }
    let mut names = BTreeSet::new();
    for record in &index.entries {
        validate_id(&record.name).map_err(|_| error("store_index_corrupt"))?;
        if record.digest.len() != 64
            || !record
                .digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || record.source_bytes > 32 * 1024 * 1024
            || !names.insert(record.name.to_ascii_lowercase())
        {
            return Err(error("store_index_corrupt"));
        }
    }
    Ok(index)
}

fn copy_snapshot(tree: &SourceTree, root: &Directory) -> Result<(), CompatError> {
    for path in &tree.directories {
        if !path.is_empty() {
            descend(root, path, true)?;
        }
    }
    for file in &tree.files {
        let (parent, name) = file
            .path
            .rsplit_once('/')
            .unwrap_or(("", file.path.as_str()));
        let parent = descend(root, parent, true)?;
        parent.write_new(
            name,
            tree.bytes
                .get(&file.path)
                .ok_or_else(|| error("store_package_tampered"))?,
            file.executable,
        )?;
        parent.sync()?;
    }
    Ok(())
}

fn descend(root: &Directory, path: &str, create: bool) -> Result<Directory, CompatError> {
    let mut directory = root.clone();
    if !path.is_empty() {
        for name in path.split('/') {
            directory = directory
                .child(name, create)?
                .ok_or_else(|| error("store_package_missing"))?;
        }
    }
    Ok(directory)
}

fn check_private_tree(root: &Directory, tree: &SourceTree) -> Result<(), CompatError> {
    if tree.scm_excluded {
        return Err(error("store_package_tampered"));
    }
    for path in &tree.directories {
        descend(root, path, false)?.check()?;
    }
    for file in &tree.files {
        let (parent, name) = file
            .path
            .rsplit_once('/')
            .unwrap_or(("", file.path.as_str()));
        let parent = descend(root, parent, false)?;
        parent.verify_package_mode(name, file.executable)?;
        let bytes = parent
            .read(name, 8 * 1024 * 1024)?
            .ok_or_else(|| error("store_package_missing"))?;
        if bytes
            != *tree
                .bytes
                .get(&file.path)
                .ok_or_else(|| error("store_package_tampered"))?
        {
            return Err(error("store_package_tampered"));
        }
    }
    Ok(())
}

fn verify_tree(
    root: &Directory,
    expected: &PluginSource,
    options: &InspectOptions,
) -> Result<(), CompatError> {
    let tree = SourceTree::read_named(&root.held_path()?, expected.inferred_name.as_deref())?;
    check_private_tree(root, &tree)?;
    let mut options = options.clone();
    options.format = Some(expected.format);
    let inspection = crate::formats::normalize(&tree, &options)?;
    if &inspection.source != expected {
        return Err(error("store_package_tampered"));
    }
    root.check()
}

fn validate_id(name: &str) -> Result<(), CompatError> {
    crate::formats::validate_legacy_id(name)
}

fn source_bytes(source: &PluginSource) -> u64 {
    source.files.iter().map(|file| file.size).sum()
}

fn package_diagnostic(record: &Record, error: &CompatError) -> Diagnostic {
    Diagnostic {
        code: error.code.clone(),
        severity: DiagnosticSeverity::Error,
        component_id: Some(record.name.clone()),
        source_path: None,
        message: "Managed plugin content failed fresh verification and is excluded".into(),
        action: Some(
            "Inspect the owned package and index before explicitly restoring a verified version"
                .into(),
        ),
    }
}

fn error(code: &'static str) -> CompatError {
    CompatError::new(
        code,
        match code {
            "store_project_untrusted" => {
                "Project plugin mutation requires trust in the actual project"
            }
            "store_scope_alias" => {
                "User and project plugin scopes must have distinct storage roots"
            }
            "store_namespace_collision" => {
                "A plugin name collides with an existing managed namespace"
            }
            "store_upgrade_required" => {
                "A different source digest requires an explicit revision-checked upgrade"
            }
            "store_state_conflict" => {
                "The package is already imported with different options or enabled state; use an explicit mutation"
            }
            "store_plugin_limit" => "The plugin count exceeds the bounded store limit",
            "store_revision_changed" => {
                "The plugin index changed concurrently; read a fresh snapshot before retrying"
            }
            "store_package_missing" => "An indexed immutable plugin package is missing",
            "store_plugin_missing" => {
                "No plugin with this exact identity is installed in the selected scope"
            }
            "store_identity_mismatch" => "An upgrade must preserve the selected plugin identity",
            "store_package_tampered" => {
                "Managed plugin content no longer matches its recorded identity and digest"
            }
            "store_asset_invalid" => "Plugin assets require a bounded safe relative inventory path",
            "store_asset_stale" => {
                "Plugin assets require an enabled package with the expected digest"
            }
            "store_asset_missing" => {
                "The requested asset is absent from the immutable source inventory"
            }
            "store_asset_limit" => "The requested asset exceeds the explicit byte limit",
            _ => {
                "The managed plugin index is corrupt; no portable content was activated or rewritten"
            }
        },
    )
}
