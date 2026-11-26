//! Validated portable profiles and inert, policy-scoped pane content.
use crate::tool_runtime::PermissionScope;
use orbit_frontend_protocol::customization::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub use orbit_frontend_protocol::customization::CustomizationError as Error;
const PROFILE: &str = "customization.json";
pub(crate) fn io_error(error: std::io::Error) -> Error {
    Error::Io(error.kind().to_string())
}

/// A held, checked directory descriptor. Names are resolved through this descriptor.
pub(crate) struct Directory {
    path: PathBuf,
    file: File,
}
#[cfg(unix)]
fn same(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino() && a.uid() == b.uid()
}
impl Directory {
    pub(crate) fn open(path: &Path, private: bool) -> Result<Self, Error> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (path, private);
            return Err(Error::UnsafePath(
                "checked local storage requires Linux".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::{
                fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
                io::AsRawFd,
            };
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                std::env::current_dir().map_err(io_error)?.join(path)
            };
            let mut checked = PathBuf::from("/");
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/")
                .map_err(io_error)?;
            for component in path.components() {
                match component {
                    Component::RootDir => {}
                    Component::Normal(part) => checked.push(part),
                    _ => {
                        return Err(Error::UnsafePath(
                            "path contains non-normal components".into(),
                        ));
                    }
                }
                let m = std::fs::symlink_metadata(&checked).map_err(io_error)?;
                if !m.is_dir() || m.file_type().is_symlink() {
                    return Err(Error::UnsafePath(
                        "directory symlink or special entry".into(),
                    ));
                }
                if let Component::Normal(part) = component {
                    // Traversal needs search permission, not permission to list
                    // each ancestor. Held descriptors still prevent a rename or
                    // symlink swap from redirecting a later component.
                    let next =
                        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())).join(part);
                    file = OpenOptions::new()
                        .read(true)
                        .custom_flags(
                            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                        .open(next)
                        .map_err(io_error)?;
                    if !same(&m, &file.metadata().map_err(io_error)?) {
                        return Err(Error::UnsafePath("directory ancestor changed".into()));
                    }
                }
            }
            let m = file.metadata().map_err(io_error)?;
            // Only the final directory needs a readable descriptor for fsync.
            // Reopen the held directory itself, including when the path is `/`.
            let readable = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())).join("."))
                .map_err(io_error)?;
            let opened = readable.metadata().map_err(io_error)?;
            if !same(&m, &opened) {
                return Err(Error::UnsafePath("directory identity changed".into()));
            }
            file = readable;
            let m = opened;
            if private
                && (m.uid() != unsafe { libc::geteuid() } || m.permissions().mode() & 0o077 != 0)
            {
                return Err(Error::UnsafePath(
                    "directory must be owned and private (0700)".into(),
                ));
            }
            let _ = file.as_raw_fd();
            let result = Self { path, file };
            result.check()?;
            Ok(result)
        }
    }
    pub(crate) fn create(path: &Path) -> Result<Self, Error> {
        if !path.try_exists().map_err(io_error)? {
            let parent = path
                .parent()
                .ok_or_else(|| Error::UnsafePath("directory has no parent".into()))?;
            let parent = Self::open(parent, false)?;
            let name = path
                .file_name()
                .ok_or_else(|| Error::UnsafePath("directory has no name".into()))?;
            let target = parent.io()?.join(name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                match std::fs::DirBuilder::new().mode(0o700).create(&target) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(io_error(e)),
                }
            }
            parent.sync()?;
        }
        Self::open(path, true)
    }
    pub(crate) fn child(&self, name: &str, create: bool) -> Result<Self, Error> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(Error::UnsafePath("invalid child name".into()));
        }
        self.check()?;
        let path = self.path.join(name);
        let child = if create {
            Self::create(&path)
        } else {
            Self::open(&path, true)
        }?;
        self.check()?;
        Ok(child)
    }
    pub(crate) fn io(&self) -> Result<PathBuf, Error> {
        self.check()?;
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            Ok(PathBuf::from(format!(
                "/proc/self/fd/{}",
                self.file.as_raw_fd()
            )))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::UnsafePath("unsupported descriptor storage".into()))
        }
    }
    pub(crate) fn check(&self) -> Result<(), Error> {
        let now = std::fs::symlink_metadata(&self.path).map_err(io_error)?;
        if !now.is_dir() || !same(&now, &self.file.metadata().map_err(io_error)?) {
            return Err(Error::UnsafePath("directory identity changed".into()));
        }
        Ok(())
    }
    pub(crate) fn sync(&self) -> Result<(), Error> {
        self.check()?;
        self.file.sync_all().map_err(io_error)?;
        self.check()
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
pub(crate) fn read_regular(path: &Path, max: usize, private: bool) -> Result<Vec<u8>, Error> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let before = std::fs::symlink_metadata(path).map_err(io_error)?;
    #[cfg(unix)]
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != unsafe { libc::geteuid() }
        || (private && before.permissions().mode() & 0o077 != 0)
    {
        return Err(Error::UnsafePath(
            "file must be owned, regular, unlinked and private when required".into(),
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(io_error)?;
    let opened = file.metadata().map_err(io_error)?;
    if !same(&before, &opened) || opened.len() > max as u64 {
        return Err(Error::Invalid(
            "file identity changed or size limit exceeded".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let after = std::fs::symlink_metadata(path).map_err(io_error)?;
    if bytes.len() > max || !same(&before, &after) {
        return Err(Error::UnsafePath("file changed during read".into()));
    }
    Ok(bytes)
}
pub(crate) struct Lock {
    file: File,
}
impl Lock {
    /// Share the existing writer lock without creating or modifying its inode.
    pub(crate) fn read_existing(dir: &Directory, name: &str) -> Result<Self, Error> {
        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err(Error::UnsafePath("invalid lock name".into()));
        }
        let path = dir.io()?.join(name);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(io_error)?;
        let result = Self { file };
        result.check_existing(dir, name)?;
        if unsafe { libc::flock(result.file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return Err(Error::Busy);
        }
        result.check_existing(dir, name)?;
        Ok(result)
    }

    pub(crate) fn check_existing(&self, dir: &Directory, name: &str) -> Result<(), Error> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path = dir.io()?.join(name);
        let held = self.file.metadata().map_err(io_error)?;
        let current = std::fs::symlink_metadata(path).map_err(io_error)?;
        for metadata in [&held, &current] {
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(Error::UnsafePath("lock file is unsafe".into()));
            }
        }
        if !same(&held, &current) {
            return Err(Error::UnsafePath("lock file identity changed".into()));
        }
        dir.check()?;
        Directory::open(dir.path(), true)?;
        dir.check()
    }

    pub(crate) fn acquire(dir: &Directory, name: &str) -> Result<Self, Error> {
        use std::os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            io::AsRawFd,
        };
        let path = dir.io()?.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(io_error)?;
        let m = file.metadata().map_err(io_error)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.permissions().mode() & 0o077 != 0
            || !same(&m, &std::fs::symlink_metadata(path).map_err(io_error)?)
        {
            return Err(Error::UnsafePath("lock file is unsafe".into()));
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Busy);
        }
        dir.check()?;
        Ok(Self { file })
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationPoint {
    Staged,
    Published,
}
#[cfg(test)]
type Hook = Box<dyn FnMut(PublicationPoint, &Path)>;
#[cfg(test)]
std::thread_local! {static HOOK:std::cell::RefCell<Option<Hook>>=const{std::cell::RefCell::new(None)};}
#[cfg(test)]
pub fn with_test_hook<T>(
    hook: impl FnMut(PublicationPoint, &Path) + 'static,
    work: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<Hook>);
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with(|h| {
                h.replace(self.0.take());
            });
        }
    }
    let _reset = Reset(HOOK.with(|h| h.replace(Some(Box::new(hook)))));
    work()
}
fn point(p: PublicationPoint, path: &Path) {
    #[cfg(test)]
    HOOK.with(|h| {
        let mut hook = h.borrow_mut().take();
        if let Some(ref mut f) = hook {
            f(p, path);
        }
        h.replace(hook);
    });
    #[cfg(not(test))]
    let _ = (p, path);
}
pub(crate) fn publish(
    dir: &Directory,
    name: &str,
    bytes: &[u8],
    create_only: bool,
) -> Result<(), Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let target = dir.io()?.join(name);
    if target.try_exists().map_err(io_error)? {
        read_regular(&target, MAX_PROFILE_BYTES, true)?;
        if create_only {
            return Err(Error::Busy);
        }
    }
    let temp_name = format!(".stage-{}", ulid::Ulid::new());
    let temp = dir.io()?.join(&temp_name);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)
            .map_err(io_error)?;
        f.write_all(bytes).map_err(io_error)?;
        f.sync_all().map_err(io_error)?;
        point(PublicationPoint::Staged, dir.path());
        dir.check()?;
        if create_only {
            use std::os::unix::ffi::OsStrExt;
            let a = std::ffi::CString::new(temp.as_os_str().as_bytes())
                .map_err(|_| Error::UnsafePath("NUL path".into()))?;
            let b = std::ffi::CString::new(target.as_os_str().as_bytes())
                .map_err(|_| Error::UnsafePath("NUL path".into()))?;
            if unsafe {
                libc::renameat2(
                    libc::AT_FDCWD,
                    a.as_ptr(),
                    libc::AT_FDCWD,
                    b.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err(io_error(std::io::Error::last_os_error()));
            }
        } else {
            std::fs::rename(&temp, &target).map_err(io_error)?;
        }
        point(PublicationPoint::Published, dir.path());
        dir.sync()
            .map_err(|e| Error::PublicationUncertain(e.to_string()))?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temp);
    result
}

pub fn validate(bytes: &[u8]) -> Result<Profile, Error> {
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(Error::Invalid("profile exceeds 128 KiB".into()));
    }
    let profile: Profile = serde_json::from_slice(bytes).map_err(|e| {
        Error::Invalid(format!(
            "JSON at line {} column {}: {:?}",
            e.line(),
            e.column(),
            e.classify()
        ))
    })?;
    profile.validate()?;
    Ok(profile)
}
fn optional(dir: &Directory, name: &str, private: bool) -> Result<Option<Vec<u8>>, Error> {
    let path = dir.io()?.join(name);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => read_regular(&path, MAX_PROFILE_BYTES, private).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_error(e)),
    }
}
const FIELDS: [&str; 12] = [
    "name",
    "theme",
    "token_overrides",
    "density",
    "glyphs",
    "reduced_motion",
    "reactor_art",
    "color_mode",
    "browser.font_family",
    "browser.font_size_px",
    "layout",
    "panes",
];
fn legacy(bytes: Option<&[u8]>) -> Result<(Profile, BTreeMap<String, EffectiveSource>), Error> {
    let mut profile = Profile::default();
    let mut sources = FIELDS
        .into_iter()
        .map(|k| (k.into(), EffectiveSource::Default))
        .collect::<BTreeMap<_, _>>();
    let Some(bytes) = bytes else {
        return Ok((profile, sources));
    };
    let value: toml::Value = toml::from_str(
        std::str::from_utf8(bytes)
            .map_err(|_| Error::Invalid("legacy tui.toml is not UTF-8".into()))?,
    )
    .map_err(|_| {
        Error::Invalid(
            "legacy tui.toml is malformed; choose explicit session defaults or repair it".into(),
        )
    })?;
    if let Some(colors) = value.get("colors") {
        let colors = colors
            .as_table()
            .ok_or_else(|| Error::Invalid("legacy colors must be a table".into()))?;
        for (key, value) in colors {
            if canonical_token(key).is_some() {
                let color = value
                    .as_str()
                    .ok_or_else(|| Error::Invalid("legacy color must be #RRGGBB".into()))?;
                profile.token_overrides.insert(key.clone(), color.into());
                sources.insert("token_overrides".into(), EffectiveSource::Legacy);
            }
        }
    }
    if let Some(color) = value.get("color") {
        let color = color
            .as_table()
            .ok_or_else(|| Error::Invalid("legacy color must be a table".into()))?;
        if let Some(v) = color.get("mode") {
            profile.color_mode = match v.as_str() {
                Some("auto") => ColorMode::Auto,
                Some("truecolor") => ColorMode::Truecolor,
                Some("256") => ColorMode::Ansi256,
                Some("16") => ColorMode::Ansi16,
                Some("mono") => ColorMode::Mono,
                _ => return Err(Error::Invalid("legacy color.mode is invalid".into())),
            };
            sources.insert("color_mode".into(), EffectiveSource::Legacy);
        }
        if let Some(v) = color.get("glyphs") {
            profile.glyphs = match v.as_str() {
                Some("auto") => Glyphs::Auto,
                Some("unicode") => Glyphs::Unicode,
                Some("ascii") => Glyphs::Ascii,
                _ => return Err(Error::Invalid("legacy color.glyphs is invalid".into())),
            };
            sources.insert("glyphs".into(), EffectiveSource::Legacy);
        }
        if let Some(v) = color.get("reduced") {
            profile.reduced_motion = v
                .as_bool()
                .ok_or_else(|| Error::Invalid("legacy color.reduced is invalid".into()))?;
            sources.insert("reduced_motion".into(), EffectiveSource::Legacy);
        }
    }
    if let Some(layout) = value.get("layout") {
        let layout = layout
            .as_table()
            .ok_or_else(|| Error::Invalid("legacy layout must be a table".into()))?;
        if let Some(tree) = layout.get("tree") {
            profile.layout.tree = tree
                .clone()
                .try_into()
                .map_err(|_| Error::Invalid("legacy layout.tree is invalid".into()))?;
            sources.insert("layout".into(), EffectiveSource::Legacy);
        }
    }
    profile.validate()?;
    Ok((profile, sources))
}
pub fn load(home: &Path, _workspace: &Path) -> Result<ResolvedProfile, Error> {
    let (saved, old) = match std::fs::symlink_metadata(home) {
        Ok(_) => {
            let dir = Directory::open(home, true)?;
            let a = optional(&dir, PROFILE, true)?;
            let b = optional(&dir, "tui.toml", false)?;
            dir.check()?;
            (a, b)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(e) => return Err(io_error(e)),
    };
    let (mut profile, mut sources) = legacy(old.as_deref())?;
    if let Some(bytes) = saved.as_deref() {
        profile = validate(bytes)?;
        for source in sources.values_mut() {
            *source = EffectiveSource::Profile;
        }
    }
    let mut hash = Sha256::new();
    for value in [&saved, &old] {
        hash.update((value.as_ref().map(Vec::len).unwrap_or(0) as u64).to_be_bytes());
        hash.update(value.as_deref().unwrap_or(b""));
    }
    Ok(ResolvedProfile {
        profile,
        sources,
        revision: hex::encode(hash.finalize()),
        capabilities: CustomizationCapabilities::default(),
    })
}
/// Visible session-only fallback; callers must explicitly select this after an error.
pub fn safe_session_defaults() -> ResolvedProfile {
    ResolvedProfile {
        profile: Profile::default(),
        sources: FIELDS
            .into_iter()
            .map(|s| (s.into(), EffectiveSource::Session))
            .collect(),
        revision: "session-defaults".into(),
        capabilities: CustomizationCapabilities::default(),
    }
}
pub fn replace(home: &Path, workspace: &Path, profile: &Profile) -> Result<ResolvedProfile, Error> {
    let revision = load(home, workspace)?.revision;
    replace_checked(home, workspace, profile, &revision)
}
pub fn replace_checked(
    home: &Path,
    workspace: &Path,
    profile: &Profile,
    expected_revision: &str,
) -> Result<ResolvedProfile, Error> {
    profile.validate()?;
    let bytes = serde_json::to_vec_pretty(profile)
        .map_err(|_| Error::Invalid("profile serialization".into()))?;
    validate(&bytes)?;
    // Validate existing files before creating even the stable lock.
    if load(home, workspace)?.revision != expected_revision {
        return Err(Error::Busy);
    }
    let dir = Directory::create(home)?;
    let _lock = Lock::acquire(&dir, ".customization.lock")?;
    if load(home, workspace)?.revision != expected_revision {
        return Err(Error::Busy);
    }
    // Backup-on-write: the previous profile survives a bad write
    // as customization.json.bak. Only the profile path does this — the
    // history journals reject unexpected directory entries, so their
    // shared publish stays untouched. A failed backup does not block
    // the save.
    let target = dir.io()?.join(PROFILE);
    if target.try_exists().map_err(io_error)? {
        let _ = std::fs::copy(&target, target.with_extension("json.bak"));
    }
    publish(&dir, PROFILE, &bytes, false)?;
    load(home, workspace)
}
pub fn reset(home: &Path, workspace: &Path) -> Result<ResolvedProfile, Error> {
    let revision = load(home, workspace)?.revision;
    reset_checked(home, workspace, &revision)
}
pub fn reset_checked(
    home: &Path,
    workspace: &Path,
    expected_revision: &str,
) -> Result<ResolvedProfile, Error> {
    if load(home, workspace)?.revision != expected_revision {
        return Err(Error::Busy);
    }
    if !home.try_exists().map_err(io_error)? {
        return load(home, workspace);
    }
    let dir = Directory::open(home, true)?;
    let _lock = Lock::acquire(&dir, ".customization.lock")?;
    if load(home, workspace)?.revision != expected_revision {
        return Err(Error::Busy);
    }
    if optional(&dir, PROFILE, true)?.is_some() {
        std::fs::remove_file(dir.io()?.join(PROFILE)).map_err(io_error)?;
        dir.sync()
            .map_err(|e| Error::PublicationUncertain(e.to_string()))?;
    }
    load(home, workspace)
}
pub fn export(profile: &Profile) -> Result<Vec<u8>, Error> {
    profile.validate()?;
    fn checked(field: &str, text: &str) -> Result<(), Error> {
        let scanned = orbit_tools::scan::scan_result(text);
        if !scanned.redactions.is_empty()
            || scanned
                .text
                .split_inclusive(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .any(|span| !orbit_tools::scan::scan_result(span).redactions.is_empty())
        {
            return Err(Error::Invalid(format!(
                "{field} contains secret data; export refused"
            )));
        }
        Ok(())
    }
    checked("name", &profile.name)?;
    checked("browser.font_family", &profile.browser.font_family)?;
    checked("layout.preset", &profile.layout.preset)?;
    fn layout(node: &LayoutNode) -> Result<(), Error> {
        match node {
            LayoutNode::Panel { agent, .. } => checked("layout.tree.agent", agent),
            LayoutNode::Split { children, .. } => {
                for child in children {
                    layout(child)?;
                }
                Ok(())
            }
            LayoutNode::Custom { .. } => Ok(()),
        }
    }
    layout(&profile.layout.tree)?;
    for (index, pane) in profile.panes.iter().enumerate() {
        checked(&format!("panes[{index}].id"), &pane.id)?;
        checked(&format!("panes[{index}].title"), &pane.title)?;
        match &pane.source {
            PaneSource::Text { text } => checked(&format!("panes[{index}].source.text"), text)?,
            PaneSource::MarkdownFile { path } => {
                checked(&format!("panes[{index}].source.path"), path)?
            }
            _ => {}
        }
        for (action_index, action) in pane.actions.iter().enumerate() {
            if let PaneAction::InsertPrompt { text } = action {
                checked(
                    &format!("panes[{index}].actions[{action_index}].text"),
                    text,
                )?;
            }
        }
    }
    let bytes = serde_json::to_vec_pretty(profile)
        .map_err(|_| Error::Invalid("profile serialization".into()))?;
    validate(&bytes)?;
    Ok(bytes)
}

pub struct LocalProfileHost {
    pub home: PathBuf,
    pub workspace: PathBuf,
    pub scope: PermissionScope,
}
impl ProfileHost for LocalProfileHost {
    fn command(
        &self,
        command: orbit_frontend_protocol::customization::ProfileCommand,
    ) -> Result<orbit_frontend_protocol::customization::ProfileCommandResult, Error> {
        crate::profile_commands::execute_paths(&self.home, &self.workspace, &self.scope, command)
    }
    fn command_checked(
        &self,
        command: orbit_frontend_protocol::customization::ProfileCommand,
        expected_revision: &str,
    ) -> Result<orbit_frontend_protocol::customization::ProfileCommandResult, Error> {
        crate::profile_commands::execute_paths_checked(
            &self.home,
            &self.workspace,
            &self.scope,
            command,
            expected_revision,
        )
    }
    fn load(&self) -> Result<ResolvedProfile, Error> {
        load(&self.home, &self.workspace)
    }
    fn replace(&self, p: Profile, revision: &str) -> Result<ResolvedProfile, Error> {
        replace_checked(&self.home, &self.workspace, &p, revision)
    }
    fn reset(&self, revision: &str) -> Result<ResolvedProfile, Error> {
        reset_checked(&self.home, &self.workspace, revision)
    }
    fn read_pane(&self, id: &str, context: &PaneContext) -> Result<PaneOutput, Error> {
        let mut scope = self.scope.clone();
        if let Some(mode) = &context.permission_mode {
            scope.mode = orbit_tools::permissions::PermissionMode::from_config(mode)
                .ok_or_else(|| Error::Invalid("pane context permission mode is invalid".into()))?;
        }
        read_pane_scoped(&self.home, &self.workspace, id, context, &scope)
    }
}
pub fn read_pane(
    home: &Path,
    workspace: &Path,
    id: &str,
    context: &PaneContext,
) -> Result<PaneOutput, Error> {
    read_pane_scoped(home, workspace, id, context, &PermissionScope::default())
}
fn authorized(
    home: &Path,
    workspace: &Path,
    path: &Path,
    argument: &str,
    scope: &PermissionScope,
) -> Result<(), Error> {
    use orbit_tools::permissions::{
        RuleEffect, RuleEffectSerde, RuleSet, parse_rule, rule_matches, rule_tool_matches,
    };
    if orbit_tools::is_deny_read(path) {
        return Err(Error::UnsafePath(
            "pane read is denied by inherited scope".into(),
        ));
    }
    let sourced = orbit_tools::executor::load_sourced_rules_in(home, workspace)
        .map_err(|_| Error::Invalid("permission settings are invalid".into()))?;
    let mut rules = RuleSet {
        rules: sourced
            .into_iter()
            .filter(|r| !r.shadowed)
            .map(|r| r.rule)
            .collect(),
    };
    let allowed = scope
        .allowlist
        .as_ref()
        .map(|selectors| {
            selectors
                .iter()
                .map(|selector| {
                    parse_rule(selector, RuleEffectSerde::Allow).ok_or_else(|| {
                        Error::Invalid("inherited permission selector is invalid".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    if let Some(allowed) = &allowed {
        rules.rules.extend(allowed.iter().cloned());
    }
    for selector in &scope.disallowlist {
        rules
            .rules
            .push(parse_rule(selector, RuleEffectSerde::Deny).ok_or_else(|| {
                Error::Invalid("inherited permission selector is invalid".into())
            })?);
    }
    let workspace = Directory::open(workspace, false)?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(io_error)?.join(path)
    };
    let relative = absolute
        .strip_prefix(workspace.path())
        .map_err(|_| Error::UnsafePath("pane read is outside workspace".into()))?;
    let candidates = [
        argument,
        &path.to_string_lossy(),
        &absolute.to_string_lossy(),
        &relative.to_string_lossy(),
    ];
    if allowed.as_ref().is_some_and(|allowed| {
        !allowed.iter().any(|rule| {
            rule_tool_matches(rule, "Read", None)
                && candidates.iter().any(|path| rule_matches(rule, path))
        })
    }) {
        return Err(Error::UnsafePath(
            "pane Read is outside the operator's allowlist".into(),
        ));
    }
    if candidates.iter().any(|p| {
        matches!(
            rules.evaluate("Read", p),
            Some(RuleEffect::Deny | RuleEffect::Ask)
        )
    }) {
        return Err(Error::UnsafePath(
            "pane read is denied or requires explicit approval; refresh cannot grant access".into(),
        ));
    }
    if scope.mode == orbit_tools::permissions::PermissionMode::DontAsk
        && !candidates
            .iter()
            .any(|path| rules.evaluate("Read", path) == Some(RuleEffect::Allow))
    {
        return Err(Error::UnsafePath(
            "pane Read requires an explicit allow rule in dontAsk mode".into(),
        ));
    }
    Ok(())
}
fn workspace_file(
    home: &Path,
    workspace: &Path,
    relative: &str,
    scope: &PermissionScope,
) -> Result<Option<Vec<u8>>, Error> {
    let root = Directory::open(workspace, false)?;
    let path = workspace.join(relative);
    authorized(home, workspace, &path, relative, scope)?;
    let mut parent = Directory::open(workspace, false)?;
    let parts: Vec<_> = Path::new(relative).components().collect();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(Error::UnsafePath("pane path escapes workspace".into()));
        };
        let name = name
            .to_str()
            .ok_or_else(|| Error::UnsafePath("non-UTF-8 pane path".into()))?;
        if index + 1 == parts.len() {
            let target = parent.io()?.join(name);
            match std::fs::symlink_metadata(&target) {
                Ok(_) => {
                    let bytes = read_regular(&target, 64 * 1024, false)?;
                    parent.check()?;
                    root.check()?;
                    return Ok(Some(bytes));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(io_error(e)),
            }
        }
        parent = Directory::open(&parent.path().join(name), false)?;
    }
    Err(Error::UnsafePath("empty pane path".into()))
}
fn safe_output(text: &str) -> (String, bool) {
    let plain: String = text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    let scanned = orbit_tools::scan::scan_result(&plain).text;
    // Retain assignment/PEM context, then scan each token span so a short
    // harmless prefix cannot hide a later token of the same family.
    let mut rescanned = String::with_capacity(scanned.len());
    for span in
        scanned.split_inclusive(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    {
        rescanned.push_str(&orbit_tools::scan::scan_result(span).text);
    }
    let scanned = rescanned;
    let scanned = orbit_hud::display_safe(&scanned)
        .unwrap_or_else(|_| "[content withheld by display policy]".into());
    let mut out = String::new();
    let mut truncated = false;
    for (index, line) in scanned.split_inclusive('\n').enumerate() {
        if index >= MAX_PANE_LINES {
            truncated = true;
            break;
        }
        for c in line.chars() {
            if out.len() + c.len_utf8() > MAX_PANE_OUTPUT_BYTES {
                truncated = true;
                break;
            }
            out.push(c);
        }
        if truncated {
            break;
        }
    }
    (out, truncated)
}
pub fn read_pane_scoped(
    home: &Path,
    workspace: &Path,
    id: &str,
    context: &PaneContext,
    scope: &PermissionScope,
) -> Result<PaneOutput, Error> {
    let resolved = load(home, workspace)?;
    let pane = resolved
        .profile
        .pane_def(id)
        .ok_or_else(|| Error::Invalid("unknown pane id".into()))?;
    let (mut state, mut text, mut truncated) = (PaneState::Ready, String::new(), false);
    let mut council = None;
    match &pane.source {
        PaneSource::Text { text: content } => text = content.clone(),
        PaneSource::MarkdownFile { path } => match workspace_file(home, workspace, path, scope)? {
            Some(bytes) => text = String::from_utf8_lossy(&bytes).into_owned(),
            None => {
                state = PaneState::Missing;
                text = "File is missing".into();
            }
        },
        PaneSource::Snapshot { snapshot } => match snapshot {
            SnapshotKind::Routing => {
                for line in context.routing.iter().take(128) {
                    if text.len().saturating_add(line.len()).saturating_add(1) > 64 * 1024 {
                        truncated = true;
                        break;
                    }
                    text.push_str(line);
                    text.push('\n');
                }
                truncated |= context.routing.len() > 128;
            }
            SnapshotKind::Usage => {
                text = format!(
                    "Input tokens: {}\nOutput tokens: {}\nCost (microcents): {}",
                    context.input_tokens, context.output_tokens, context.cost_microcents
                )
            }
            SnapshotKind::Agents => {
                for agent in context.agents.iter().take(128) {
                    if text
                        .len()
                        .saturating_add(agent.id.len())
                        .saturating_add(agent.name.len())
                        .saturating_add(agent.state.len())
                        .saturating_add(6)
                        > 64 * 1024
                    {
                        truncated = true;
                        break;
                    }
                    text.push_str(&format!("{}: {} ({})\n", agent.id, agent.name, agent.state));
                }
                truncated |= context.agents.len() > 128;
            }
            SnapshotKind::Scope => match workspace_file(home, workspace, "scope.toml", scope)? {
                Some(bytes) => text = String::from_utf8_lossy(&bytes).into_owned(),
                None => {
                    state = PaneState::Missing;
                    text = "Scope file is missing; no targets are inferred".into();
                }
            },
            SnapshotKind::Evidence | SnapshotKind::Findings => {
                let relative = if *snapshot == SnapshotKind::Evidence {
                    "evidence"
                } else {
                    "findings"
                };
                let counts = count_workspace(home, workspace, relative, scope)?;
                state = if counts.missing {
                    PaneState::Missing
                } else if counts.files == 0 {
                    PaneState::Empty
                } else {
                    PaneState::Ready
                };
                text = format!(
                    "Files: {}\n{}",
                    counts.files,
                    if counts.missing {
                        "Directory is missing"
                    } else {
                        "Local file count; contents are not verified proof"
                    }
                );
                truncated = counts.truncated;
            }
            SnapshotKind::Council => {
                // Native state belongs to this bound session. The external
                // bridge is consulted only when native state is absent.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0.0, |elapsed| elapsed.as_secs_f64());
                council = context
                    .council
                    .as_ref()
                    .map(sanitize_council_snapshot)
                    .or_else(|| {
                        council_from_state_file_for_session(context.session_id.as_deref(), now)
                            .as_ref()
                            .map(sanitize_council_snapshot)
                    });
                (state, text) = match &council {
                    Some(snapshot) => {
                        council_text_snapshot(snapshot, resolved.profile.glyphs == Glyphs::Ascii)
                    }
                    None => (PaneState::Missing, "No council has run".into()),
                };
            }
            SnapshotKind::Reactor => {
                text = reactor_snapshot(context, resolved.profile.glyphs == Glyphs::Ascii);
                council = context.council.as_ref().map(sanitize_council_snapshot);
            }
            // The terminal lists the saved sessions from its own state; only a
            // caption comes from here.
            SnapshotKind::Sessions => {
                text = "Saved sessions of this folder. Pick one to resume it.".into();
            }
        },
    }
    if text.is_empty() {
        state = PaneState::Empty;
        text = "No data available".into();
    }
    let (text, cut) = safe_output(&text);
    truncated |= cut;
    Ok(PaneOutput {
        id: pane.id.clone(),
        title: safe_output(&pane.title).0,
        state,
        text,
        truncated,
        council,
        actions: pane
            .actions
            .iter()
            .filter(|a| context.controller || !matches!(a, PaneAction::OwnerCancel))
            .cloned()
            .collect(),
    })
}
/// Largest MAGI state file the built-in `council` pane reads.
const COUNCIL_STATE_MAX_BYTES: u64 = 64 * 1024;
/// A state older than this means the council engine is idle. The engine may
/// pause up to seven minutes between the phases of a trial council, so this
/// must outlast the longest quiet stretch, not just one model call.
const COUNCIL_STALE_SECS: f64 = 420.0;
const COUNCIL_SEATS: [&str; 4] = ["KARINA", "GISELLE", "WINTER", "NINGNING"];

/// Where the MAGI engine publishes its state. The location comes from the
/// process environment or this default only; profile data cannot move it.
///
/// The engine scopes every file to one session: when the pane knows its
/// session (ORBIT_SESSION_ID, same id the engine's hook writes under), the
/// state lives at `sessions/<id>/state.json`. The legacy root file is only
/// the fallback for runs without a session, and is never preferred.
fn council_state_path() -> Option<PathBuf> {
    council_state_path_for_session(None)
}

fn council_state_path_for_session(session_id: Option<&str>) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("ORBIT_COUNCIL_STATE").filter(|p| !p.is_empty()) {
        let path = PathBuf::from(path);
        return path.is_absolute().then_some(path);
    }
    let home = PathBuf::from(std::env::var_os("HOME").filter(|home| !home.is_empty())?);
    let root = home.join(".local/share/magi");
    let ambient = std::env::var("ORBIT_SESSION_ID").ok();
    if let Some(session) = session_id.or(ambient.as_deref()) {
        if session.is_empty()
            || session.len() > 64
            || !session
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        {
            return None;
        }
        return Some(root.join("sessions").join(session).join("state.json"));
    }
    Some(root.join("state.json"))
}

/// One bounded, read-only, no-follow read of the council state file.
pub fn council_snapshot_at(path: &Path, now: f64, ascii: bool) -> (PaneState, String) {
    let error = |text: &str| (PaneState::Error, text.to_string());
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (PaneState::Missing, "No council has run".into());
        }
        Err(_) => return error("Council state cannot be opened"),
    };
    match file.metadata() {
        Ok(meta) if !meta.is_file() => return error("Council state is not a regular file"),
        Ok(meta) if meta.len() > COUNCIL_STATE_MAX_BYTES => {
            return error("Council state exceeds 64 KiB");
        }
        Ok(_) => {}
        Err(_) => return error("Council state cannot be inspected"),
    }
    let mut bytes = Vec::new();
    if file
        .take(COUNCIL_STATE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return error("Council state cannot be read");
    }
    if bytes.len() as u64 > COUNCIL_STATE_MAX_BYTES {
        return error("Council state exceeds 64 KiB");
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return error("Council state is not valid JSON");
    };
    let stale = value
        .get("ts")
        .and_then(serde_json::Value::as_f64)
        .is_some_and(|ts| now - ts > COUNCIL_STALE_SECS);
    let Some(mut text) = council_text(&value, stale, ascii) else {
        return error("Council state has no phase");
    };
    // Like the MAGI pane, a quiet council shows its last conclusion.
    let phase = value.get("phase").and_then(serde_json::Value::as_str);
    if (stale || matches!(phase, Some("IDLE" | "TRIAGE" | "TRIAGED" | "FAIL")))
        && let Some(last) = council_last_final(&path.with_file_name("history.jsonl"))
    {
        text.push_str(&format!(
            "{}  {last}\n",
            if ascii { "last" } else { "최근" }
        ));
    }
    // An idle council is its normal resting state, not a failed read.
    (PaneState::Ready, text)
}

/// The council as text. Labels, phase names and the narration line follow
/// the MAGI pane (`magi-pane.py`); `ascii` swaps them for English.
fn council_text(state: &serde_json::Value, stale: bool, ascii: bool) -> Option<String> {
    // State text is foreign input: printable characters only, bounded.
    let clean = |value: Option<&serde_json::Value>, max: usize| -> String {
        safe_council_text(value.and_then(serde_json::Value::as_str).unwrap_or(""), max)
    };
    let phase = clean(state.get("phase"), 16);
    if phase.is_empty() {
        return None;
    }
    // The pane treats a state older than two minutes as an idle council.
    let phase = if stale { "IDLE".to_string() } else { phase };
    let seats: &[serde_json::Value] = state
        .get("seats")
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice);
    let phase_en = match phase.as_str() {
        "SYNC" => "SYNK",
        "DELIBERATING" => "DELIBERATE",
        "JUDGING" => "JUDGE",
        other => other,
    };
    let mut text = if ascii {
        format!("MAGI - {phase_en}\n")
    } else {
        let phase_kr = match phase.as_str() {
            "TRIAGE" => "분석중",
            "TRIAGED" => "선별",
            "SYNC" => "기동",
            "DELIBERATING" => "심의",
            "VOTING" => "표결",
            "VOTED" => "투표완료",
            "JUDGING" => "판정",
            "VERDICT" => "결론도달",
            "IDLE" => "대기",
            "FAIL" => "고장",
            _ => "",
        };
        format!("MAGI · {phase_kr} {phase_en}\n")
    };
    const ROLES: [&str; 4] = ["LEAD", "EDGE", "EXACT", "BOLD"];
    let mut votes: Vec<String> = Vec::new();
    let mut answered = 0usize;
    for (index, seat) in seats.iter().take(16).enumerate() {
        let name = COUNCIL_SEATS
            .get(index)
            .map_or_else(|| "AE".to_string(), |name| (*name).to_string());
        let role = ROLES.get(index).copied().unwrap_or("");
        let model = clean(seat.get("model"), 40);
        // Same order as the MAGI pane's `lab()`: gateway aliases such as
        // `claude-glm-5.3-flash` name the lab after the prefix.
        let lower = model.to_lowercase();
        let provider = [
            ("opus", "ANTHROPIC"),
            ("haiku", "ANTHROPIC"),
            ("sonnet", "ANTHROPIC"),
            ("deepseek", "DEEPSEEK"),
            ("glm", "ZHIPU"),
            ("minimax", "MINIMAX"),
            ("qwen", "ALIBABA"),
            ("gemini", "GOOGLE"),
            ("gpt", "OPENAI"),
            ("kimi", "MOONSHOT"),
            ("mistral", "MISTRAL"),
            ("claude", "ANTHROPIC"),
        ]
        .into_iter()
        .find(|(key, _)| lower.contains(key))
        .map_or("ae", |(_, lab)| lab);
        let short = model
            .strip_prefix("claude-")
            .or_else(|| model.strip_prefix("or-"))
            .unwrap_or(&model);
        let verdict = clean(seat.get("verdict"), 16);
        let status = clean(seat.get("status"), 16);
        if status == "online" {
            answered += 1;
        }
        let (done, label) = match (verdict.as_str(), status.as_str(), ascii) {
            ("APPROVE", _, false) => (true, "승인 YES"),
            ("APPROVE", _, true) => (true, "APPROVE"),
            ("REJECT", _, false) => (true, "거부 NO"),
            ("REJECT", _, true) => (true, "REJECT"),
            ("CONDITIONAL", _, false) => (true, "보류 HOLD"),
            ("CONDITIONAL", _, true) => (true, "HOLD"),
            (_, "computing", false) => (false, "심의중"),
            (_, "computing", true) => (false, "deliberating"),
            (_, "syncing", _) => (false, "SYNK"),
            (_, "error", false) => (false, "신호없음"),
            (_, "error", true) => (false, "SIGNAL LOST"),
            (_, "online" | "reported", false) => (false, "응답완료"),
            (_, "online" | "reported", true) => (false, "answered"),
            (_, _, false) => (false, "대기"),
            (_, _, true) => (false, "idle"),
        };
        if done {
            votes.push(verdict);
        }
        let mark = match (done, ascii) {
            (true, false) => "●",
            (false, false) => "◌",
            (true, true) => "*",
            (false, true) => ".",
        };
        let seat_name = if ascii {
            format!("{name}-{:02}", index + 1)
        } else {
            format!("{name}·{:02}", index + 1)
        };
        text.push_str(&format!(
            "{seat_name:<12} {role:<5} {provider:<10} {short:<18} {mark} {label}\n"
        ));
    }
    if seats.len() > 16 {
        text.push_str(&format!("+{} more seats\n", seats.len() - 16));
    }
    // The narration strip under the seats.
    let note = clean(state.get("note"), 120);
    let judge = if ascii { "naevis" } else { "nævis" };
    match phase.as_str() {
        "VERDICT" => {
            let count = |verdict: &str| votes.iter().filter(|vote| *vote == verdict).count();
            let top = ["APPROVE", "CONDITIONAL", "REJECT"]
                .into_iter()
                .map(count)
                .max()
                .unwrap_or(0);
            let lead: Vec<&str> = ["APPROVE", "CONDITIONAL", "REJECT"]
                .into_iter()
                .filter(|verdict| top > 0 && count(verdict) == top)
                .collect();
            let word = |verdict: &str| match (verdict, ascii) {
                ("APPROVE", false) => "승인 YES",
                ("APPROVE", true) => "APPROVE",
                ("REJECT", false) => "거부 NO",
                ("REJECT", true) => "REJECT",
                (_, false) => "보류 HOLD",
                (_, true) => "HOLD",
            };
            match (lead.as_slice(), ascii) {
                ([], _) => {}
                ([only], false) => {
                    text.push_str(&format!("다수결  {} · {top}/{}\n", word(only), votes.len()))
                }
                ([only], true) => text.push_str(&format!(
                    "majority  {} - {top}/{}\n",
                    word(only),
                    votes.len()
                )),
                (tied, _) => {
                    let names: Vec<&str> = tied.iter().map(|verdict| word(verdict)).collect();
                    text.push_str(&if ascii {
                        format!(
                            "tie  {} - {top}/{} - naevis decides\n",
                            names.join(" = "),
                            votes.len()
                        )
                    } else {
                        format!(
                            "동률  {} · {top}/{} · nævis 결정\n",
                            names.join(" = "),
                            votes.len()
                        )
                    });
                }
            }
            let decision = note.trim_start();
            let decision = decision.strip_prefix("FINAL:").unwrap_or(decision).trim();
            let fallback = if ascii {
                "a conclusion was reached."
            } else {
                "결론에 도달했습니다."
            };
            text.push_str(&format!(
                "{judge}  {}\n",
                if decision.is_empty() {
                    fallback
                } else {
                    decision
                }
            ));
        }
        "JUDGING" => text.push_str(&if ascii {
            format!("{judge}  judging\n")
        } else {
            format!("{judge}  판정 중\n")
        }),
        "VOTING" | "VOTED" => {
            let body = if phase == "VOTED" && !note.is_empty() {
                note.as_str()
            } else if ascii {
                "anonymous peer review"
            } else {
                "익명 상호 평가"
            };
            text.push_str(&format!(
                "{}  {body}\n",
                if ascii { "vote" } else { "표결" }
            ));
        }
        "DELIBERATING" => {
            text.push_str(&if ascii {
                format!("deliberate  {answered}/{} answered", seats.len())
            } else {
                format!("심의  {answered}/{} 응답", seats.len())
            });
            if !votes.is_empty() {
                text.push_str(&if ascii {
                    format!(" - votes {}", votes.len())
                } else {
                    format!(" · 표 {}", votes.len())
                });
            }
            text.push('\n');
        }
        "SYNC" => text.push_str(&format!(
            "SYNK  DIVE {} seats {}\n",
            if ascii { "-" } else { "·" },
            seats.len()
        )),
        "TRIAGE" => text.push_str(if ascii {
            "triage  analysing\n"
        } else {
            "선별  분석 중\n"
        }),
        "TRIAGED" => {
            let class = note.to_uppercase();
            text.push_str(&format!(
                "{}  {} {}\n",
                if ascii { "triage" } else { "선별" },
                if ascii { "->" } else { "→" },
                if class.is_empty() {
                    "?"
                } else {
                    class.as_str()
                }
            ));
        }
        "FAIL" => text.push_str(&format!(
            "{}  {}\n",
            if ascii { "fail" } else { "고장" },
            if note.is_empty() {
                "council failed"
            } else {
                note.as_str()
            }
        )),
        _ => {}
    }
    Some(text)
}

/// The newest finished council's conclusion, from the tail of the engine's
/// append-only `history.jsonl`. At most the last 256 KiB are read.
fn council_last_final(path: &Path) -> Option<String> {
    use std::io::{Seek, SeekFrom};
    const TAIL_BYTES: u64 = 256 * 1024;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let cut = meta.len() > TAIL_BYTES;
    if cut {
        file.seek(SeekFrom::Start(meta.len() - TAIL_BYTES)).ok()?;
    }
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes).ok()?;
    let tail = String::from_utf8_lossy(&bytes);
    // After a cut the first line is partial; it never parses as a record.
    for line in tail.lines().rev() {
        let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(conclusion) = row.get("final").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let first = conclusion.lines().next().unwrap_or("").trim_start();
        let first = first.strip_prefix("FINAL:").unwrap_or(first).trim();
        if first.is_empty() {
            continue;
        }
        return Some(safe_council_text(first, 120));
    }
    None
}

fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn compact(value: u64) -> String {
    if value >= 1_000_000 {
        let tenths = value / 100_000;
        if tenths.is_multiple_of(10) {
            format!("{}M", tenths / 10)
        } else {
            format!("{}.{}M", tenths / 10, tenths % 10)
        }
    } else if value >= 1_000 {
        format!("{}k", value / 1_000)
    } else {
        value.to_string()
    }
}

/// The session's own token flow. Values the frontend did not report print
/// as a dash, never as zero.
pub fn reactor_snapshot(context: &PaneContext, ascii: bool) -> String {
    let dash = if ascii { "-" } else { "—" };
    let count = |value: Option<u64>| value.map_or_else(|| dash.to_string(), grouped);
    let model = if context.model.is_empty() {
        dash
    } else {
        context.model.as_str()
    };
    let phase = context
        .phase
        .as_deref()
        .map_or_else(|| dash.to_string(), str::to_uppercase);
    let mut text = format!(
        "REACTOR {} {model}  {phase}\n",
        if ascii { "-" } else { "·" }
    );
    let rate = |value: u64| format!("{}.{}", value / 1_000, value % 1_000 / 100);
    let current = match (context.live_rate_milli, context.rate_milli) {
        // A streaming estimate (about four characters per token) is marked.
        (Some(live), _) => format!("{}{} live", if ascii { "~" } else { "≈" }, rate(live)),
        (None, Some(settled)) => rate(settled),
        (None, None) => dash.to_string(),
    };
    text.push_str(&format!(
        "tok/s   {current:<12} peak {}\n",
        context
            .peak_rate_milli
            .map_or_else(|| dash.to_string(), rate)
    ));
    // Recent turns as a sparkline, scaled to the fastest of them.
    let history = &context.rate_history[context.rate_history.len().saturating_sub(40)..];
    if let Some(max) = history
        .iter()
        .copied()
        .max()
        .filter(|max| !ascii && *max > 0)
    {
        const SPARK: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        let line: String = history
            .iter()
            .map(|value| SPARK[(value.saturating_mul(7) / max).min(7) as usize])
            .collect();
        text.push_str(&format!("rate    {line}\n"));
    }
    text.push_str(&format!(
        "out     {:<10} in  {}\n",
        grouped(context.output_tokens),
        grouped(context.input_tokens)
    ));
    // Cache and reasoning counts cover this run only: they are observed by
    // the worker and not kept in the saved session.
    if context.cache_read_tokens.is_some()
        || context.cache_write_tokens.is_some()
        || context.reasoning_tokens.is_some()
    {
        text.push_str(&format!(
            "cache   read {}  write {}  reason {}  (this run)\n",
            count(context.cache_read_tokens),
            count(context.cache_write_tokens),
            count(context.reasoning_tokens)
        ));
    } else {
        text.push_str(&format!("cache   {dash}\n"));
    }
    match (context.used_tokens, context.window_tokens) {
        (Some(used), Some(window)) if window > 0 => {
            let filled = (used.saturating_mul(20) / window).min(20) as usize;
            let (full, empty) = if ascii { ("#", ".") } else { ("█", "░") };
            text.push_str(&format!(
                "ctx     {}{}  {} / {}  {}%\n",
                full.repeat(filled),
                empty.repeat(20 - filled),
                compact(used),
                compact(window),
                used.saturating_mul(100) / window
            ));
        }
        _ => text.push_str(&format!("ctx     {dash}\n")),
    }
    text.push_str(&format!(
        "cost    ${:.4}{}  turns {}  tools {}\n",
        context.cost_microcents as f64 / 1_000_000.0,
        if context.cost_uncertain {
            " (uncertain)"
        } else {
            ""
        },
        count(context.turns),
        count(context.turn_tools)
    ));
    text
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WorkspaceCount {
    pub files: usize,
    pub missing: bool,
    pub truncated: bool,
}
pub fn count_workspace(
    home: &Path,
    workspace: &Path,
    relative: &str,
    scope: &PermissionScope,
) -> Result<WorkspaceCount, Error> {
    let path = workspace.join(relative);
    authorized(home, workspace, &path, relative, scope)?;
    if !path.try_exists().map_err(io_error)? {
        return Ok(WorkspaceCount {
            missing: true,
            ..Default::default()
        });
    }
    let root = Directory::open(&path, false)?;
    let mut result = WorkspaceCount::default();
    let mut visited = 0;
    fn walk(
        home: &Path,
        workspace: &Path,
        dir: &Directory,
        scope: &PermissionScope,
        depth: usize,
        visited: &mut usize,
        out: &mut WorkspaceCount,
    ) -> Result<(), Error> {
        for entry in std::fs::read_dir(dir.io()?).map_err(io_error)? {
            if *visited >= 1024 {
                out.truncated = true;
                break;
            }
            *visited += 1;
            let entry = entry.map_err(io_error)?;
            let path = dir.path().join(entry.file_name());
            authorized(home, workspace, &path, &path.to_string_lossy(), scope)?;
            let m = std::fs::symlink_metadata(entry.path()).map_err(io_error)?;
            if m.file_type().is_symlink() || (!m.is_file() && !m.is_dir()) {
                return Err(Error::UnsafePath(
                    "snapshot contains a symlink or special entry".into(),
                ));
            }
            if m.is_file() {
                out.files += 1;
            } else if depth >= 4 {
                out.truncated = true;
            } else {
                walk(
                    home,
                    workspace,
                    &Directory::open(&path, false)?,
                    scope,
                    depth + 1,
                    visited,
                    out,
                )?;
            }
        }
        dir.check()?;
        Ok(())
    }
    walk(home, workspace, &root, scope, 0, &mut visited, &mut result)?;
    Ok(result)
}

#[cfg(all(test, target_os = "linux"))]
mod directory_tests {
    use super::{Directory, Error};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    struct Tree {
        root: PathBuf,
        ancestor: PathBuf,
        target: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("orbit-directory-{}", ulid::Ulid::new()));
            let ancestor = root.join("search-only");
            let target = ancestor.join("private");
            for path in [&root, &ancestor, &target] {
                std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
            }
            std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o111)).unwrap();
            Self {
                root,
                ancestor,
                target,
            }
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ =
                std::fs::set_permissions(&self.ancestor, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn directory_open_traverses_search_only_ancestors_and_syncs_final_directory() {
        let tree = Tree::new();
        let directory = Directory::open(&tree.target, true).unwrap();
        directory.sync().unwrap();
        let child = directory.child("created", true).unwrap();
        child.sync().unwrap();
        assert!(tree.target.join("created").is_dir());
        assert!(
            !rustix::fs::fcntl_getfl(&directory.file)
                .unwrap()
                .contains(rustix::fs::OFlags::PATH)
        );
    }

    #[test]
    fn directory_open_keeps_symlink_and_private_mode_checks() {
        let tree = Tree::new();
        let alias = tree.root.join("alias");
        symlink(&tree.ancestor, &alias).unwrap();
        assert!(matches!(
            Directory::open(&alias.join("private"), true),
            Err(Error::UnsafePath(_))
        ));

        std::fs::set_permissions(&tree.target, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            Directory::open(&tree.target, true),
            Err(Error::UnsafePath(_))
        ));
    }

    #[test]
    fn directory_open_root_returns_readable_final_descriptor() {
        let directory = Directory::open(Path::new("/"), false).unwrap();
        assert!(
            !rustix::fs::fcntl_getfl(&directory.file)
                .unwrap()
                .contains(rustix::fs::OFlags::PATH)
        );
        directory.check().unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod existing_read_lock_tests {
    use super::{Directory, Error, Lock};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::path::PathBuf;

    struct Tree(PathBuf);
    impl Tree {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("orbit-existing-read-lock-{}", ulid::Ulid::new()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn directory(&self) -> Directory {
            Directory::open(&self.0, true).unwrap()
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_existing_read_lock_never_creates_an_inode() {
        let tree = Tree::new();
        assert!(matches!(
            Lock::read_existing(&tree.directory(), ".history.lock"),
            Err(Error::Io(_))
        ));
        assert_eq!(std::fs::read_dir(&tree.0).unwrap().count(), 0);
    }

    #[test]
    fn existing_read_locks_share_and_exclude_the_actual_writer_inode() {
        let tree = Tree::new();
        let dir = tree.directory();
        drop(Lock::acquire(&dir, ".history.lock").unwrap());
        let writer = Lock::acquire(&dir, ".history.lock").unwrap();
        assert!(matches!(
            Lock::read_existing(&dir, ".history.lock"),
            Err(Error::Busy)
        ));
        drop(writer);
        let first = Lock::read_existing(&dir, ".history.lock").unwrap();
        let second = Lock::read_existing(&dir, ".history.lock").unwrap();
        assert!(
            !rustix::fs::fcntl_getfl(&first.file)
                .unwrap()
                .intersects(rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR)
        );
        assert!(matches!(
            Lock::acquire(&dir, ".history.lock"),
            Err(Error::Busy)
        ));
        drop(first);
        assert!(matches!(
            Lock::acquire(&dir, ".history.lock"),
            Err(Error::Busy)
        ));
        second.check_existing(&dir, ".history.lock").unwrap();
        drop(second);
        drop(Lock::acquire(&dir, ".history.lock").unwrap());
        assert!(
            std::fs::read(tree.0.join(".history.lock"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn existing_read_lock_rejects_links_special_entries_and_public_permissions() {
        for kind in ["dangling", "symlink", "directory", "hardlink", "public"] {
            let tree = Tree::new();
            let dir = tree.directory();
            let path = tree.0.join(".history.lock");
            match kind {
                "dangling" => symlink(tree.0.join("absent"), &path).unwrap(),
                "directory" => std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .unwrap(),
                "symlink" | "hardlink" => {
                    let target = tree.0.join("target");
                    std::fs::write(&target, b"retained").unwrap();
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                    if kind == "symlink" {
                        symlink(&target, &path).unwrap();
                    } else {
                        std::fs::hard_link(&target, &path).unwrap();
                    }
                }
                "public" => {
                    std::fs::write(&path, b"retained").unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                Lock::read_existing(&dir, ".history.lock").is_err(),
                "{kind}"
            );
            assert!(!tree.0.join("absent").exists());
        }
    }

    #[test]
    fn existing_read_lock_rechecks_private_directory_and_original_inode_identity() {
        let tree = Tree::new();
        let dir = tree.directory();
        drop(Lock::acquire(&dir, ".history.lock").unwrap());
        let reader = Lock::read_existing(&dir, ".history.lock").unwrap();
        std::fs::set_permissions(&tree.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            reader.check_existing(&dir, ".history.lock"),
            Err(Error::UnsafePath(_))
        ));
        std::fs::set_permissions(&tree.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = tree.0.join(".history.lock");
        let retained = tree.0.join("retained");
        std::fs::rename(&path, &retained).unwrap();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            reader.check_existing(&dir, ".history.lock"),
            Err(Error::UnsafePath(_))
        ));
        assert!(std::fs::read(retained).unwrap().is_empty());
    }
}

// ── the council, parsed once for the panes that draw it ─────────────

/// Parsed-state cache, keyed by path identity and file metadata: the pane
/// beat runs several times a second and the files change only when the
/// engine writes them. A failed stat disables caching for that read.
fn cached_parse<T: Clone + Send + 'static>(
    path: &Path,
    parse: impl FnOnce() -> Option<T>,
) -> Option<T> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::UNIX_EPOCH;
    type CacheValue = (u128, u64, Box<dyn std::any::Any + Send>);
    static CACHE: std::sync::OnceLock<Mutex<HashMap<PathBuf, CacheValue>>> =
        std::sync::OnceLock::new();
    let key = path.to_path_buf();
    let stamp = fs::metadata(path).ok().and_then(|meta| {
        let modified = meta
            .modified()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos();
        Some((modified, meta.len()))
    });
    let Some((modified, len)) = stamp else {
        return parse();
    };
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().ok()?;
    if let Some((seen_modified, seen_len, value)) = guard.get(&key)
        && *seen_modified == modified
        && *seen_len == len
        && let Some(value) = value.downcast_ref::<T>()
    {
        return Some(value.clone());
    }
    let parsed = parse()?;
    guard.insert(key, (modified, len, Box::new(parsed.clone())));
    Some(parsed)
}

/// Read the council state and parse it into the shape a pane draws: the
/// phase, the seats with what each is doing, the verdicts they carried, the
/// winner, and the newest finished council from the record. Every list is
/// bounded here; nothing from the file is passed on unbounded.
///
/// Callers that only have a `PaneContext` use [`council_from_state_file`].
pub fn council_snapshot_state(path: &Path, now: f64) -> Option<CouncilSnapshot> {
    let value = cached_parse::<serde_json::Value>(path, || read_council_state(path))?;
    let mut snapshot = council_parse(&value, now);
    // A quiet council shows its last conclusion: the record is the only
    // place the seats' verdicts survive the state file being rewritten.
    let history_path = path.with_file_name("history.jsonl");
    if let Some((history, last_at)) =
        cached_parse::<(CouncilHistoryRecord, Option<f64>)>(&history_path, || {
            council_last_record(&history_path)
        })
    {
        snapshot.last_final = history.last_final;
        snapshot.last_seats = history.last_seats;
        snapshot.finished = history.finished;
        snapshot.seen = history.seen;
        snapshot.last_at = last_at;
        if snapshot.winner_seats.is_empty() {
            snapshot.winner_seats = history.winner_names;
        }
        snapshot.last_tie = history.tie;
        if snapshot.seats.is_empty() {
            snapshot.seats = snapshot.last_seats.clone();
        }
    }
    Some(snapshot)
}

/// The council state of the default location, cached by file metadata.
pub fn council_from_state_file(now: f64) -> Option<CouncilSnapshot> {
    council_state_cached(now)
}

/// Resolve external state against the current frontend session, never an
/// unrelated legacy file. Explicit ORBIT_COUNCIL_STATE remains intentional.
pub fn council_from_state_file_for_session(
    session_id: Option<&str>,
    now: f64,
) -> Option<CouncilSnapshot> {
    let path = council_state_path_for_session(session_id)?;
    council_snapshot_state(&path, now)
}

/// Typed Council transport uses the same secret/content gate as pane text.
pub fn sanitize_council_snapshot(snapshot: &CouncilSnapshot) -> CouncilSnapshot {
    snapshot.sanitized_with(|text| safe_output(&orbit_hud::strip_cot(text)).0)
}

fn safe_council_text(text: &str, maximum: usize) -> String {
    CouncilSnapshot::sanitized_text_with(text, maximum, |text| {
        safe_output(&orbit_hud::strip_cot(text)).0
    })
}

fn council_state_cached(now: f64) -> Option<CouncilSnapshot> {
    let path = council_state_path()?;
    // Cache only the parsed files below: the assembled snapshot depends on
    // elapsed time and independent history updates. Wrapping it in cached_parse
    // would also hold the cache mutex while its nested file reads lock it again.
    council_snapshot_state(&path, now)
}

/// The bounded text fallback, from a parsed state: the phase line, one
/// line per seat, and the record's last conclusion on a quiet council.
fn council_text_snapshot(snapshot: &CouncilSnapshot, ascii: bool) -> (PaneState, String) {
    let phase = if snapshot.phase.is_empty() {
        return (PaneState::Missing, "No council has run".into());
    } else {
        snapshot.phase.clone()
    };
    let phase_en = match phase.as_str() {
        "SYNC" => "SYNK",
        "DELIBERATING" => "DELIBERATE",
        "JUDGING" => "JUDGE",
        other => other,
    };
    let mut text = if ascii {
        format!("MAGI - {phase_en}\n")
    } else {
        format!("MAGI · {} {phase_en}\n", council_phase_hangul(&phase))
    };
    const ROLES: [&str; 4] = ["LEAD", "EDGE", "EXACT", "BOLD"];
    for (index, seat) in snapshot.seats.iter().take(4).enumerate() {
        let short = seat
            .model
            .strip_prefix("claude-")
            .or_else(|| seat.model.strip_prefix("or-"))
            .unwrap_or(&seat.model);
        let label = match (seat.verdict.as_deref(), seat.activity.as_str(), ascii) {
            (Some("approve"), _, false) => "승인 YES",
            (Some("approve"), _, true) => "APPROVE",
            (Some("reject"), _, false) => "거부 NO",
            (Some("reject"), _, true) => "REJECT",
            (Some(_), _, false) => "보류 HOLD",
            (Some(_), _, true) => "HOLD",
            (None, "working", false) => "심의중",
            (None, "working", true) => "deliberating",
            (None, "wiring", _) => "SYNK",
            (None, "lost", false) => "신호없음",
            (None, "lost", true) => "SIGNAL LOST",
            (None, "answered", false) => "응답완료",
            (None, "answered", true) => "answered",
            (_, _, false) => "대기",
            (_, _, true) => "idle",
        };
        let mark = if seat.verdict.is_some() {
            if ascii { "*" } else { "●" }
        } else if ascii {
            "."
        } else {
            "◌"
        };
        let name = if ascii {
            format!("{}-{:02}", seat.name, index + 1)
        } else {
            format!("{}·{:02}", seat.name, index + 1)
        };
        let role = ROLES.get(index).copied().unwrap_or("");
        text.push_str(&format!(
            "{name:<12} {role:<5} {:<10} {short:<18} {mark} {label}\n",
            seat.lab
        ));
    }
    if matches!(
        snapshot.phase.as_str(),
        "IDLE" | "TRIAGE" | "TRIAGED" | "FAIL"
    ) && !snapshot.last_final.is_empty()
    {
        text.push_str(&format!(
            "{}  {}\n",
            if ascii { "last" } else { "최근" },
            snapshot.last_final
        ));
    }
    (PaneState::Ready, text)
}

/// The state document, read the same bounded, no-follow way the text pane
/// reads it. `None` when there is no readable state.
fn read_council_state(path: &Path) -> Option<serde_json::Value> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > COUNCIL_STATE_MAX_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(COUNCIL_STATE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > COUNCIL_STATE_MAX_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// The bench definitions, in order. Names are the engine's seat calls.
const BENCH: [(&str, &str); 4] = [
    ("KARINA", "LEAD"),
    ("GISELLE", "EDGE"),
    ("WINTER", "EXACT"),
    ("NINGNING", "BOLD"),
];

fn council_parse(value: &serde_json::Value, now: f64) -> CouncilSnapshot {
    let clean = |value: Option<&serde_json::Value>, max: usize| -> String {
        safe_council_text(value.and_then(serde_json::Value::as_str).unwrap_or(""), max)
    };
    let published_at = value.get("ts").and_then(serde_json::Value::as_f64);
    // The engine's own quiet rule: a state older than two minutes is idle.
    let stale = published_at.is_none_or(|ts| now - ts > COUNCIL_STALE_SECS);
    let mut phase = clean(value.get("phase"), 16);
    if stale {
        phase = "IDLE".into();
    }
    let raw_seats: &[serde_json::Value] = value
        .get("seats")
        .and_then(serde_json::Value::as_array)
        .map_or(&[], Vec::as_slice);
    let seats = raw_seats
        .iter()
        .take(COUNCIL_SEATS.len())
        .enumerate()
        .map(|(index, seat)| parse_seat(index, seat, &phase, &clean))
        .collect::<Vec<_>>();
    let extra_seats = raw_seats
        .iter()
        .skip(COUNCIL_SEATS.len())
        .take(12)
        .enumerate()
        .map(|(offset, seat)| CouncilChip {
            name: format!("ae·{:02}", COUNCIL_SEATS.len() + offset + 1),
            lab: council_lab(&clean(seat.get("model"), 40)),
            activity: match clean(seat.get("status"), 16).as_str() {
                "online" | "reported" => "answered".into(),
                "error" => "lost".into(),
                _ => "resting".into(),
            },
        })
        .collect();
    // The winner, as the engine names it (`winner.seats`).
    let winner_seats = value
        .get("winner")
        .and_then(|winner| winner.get("seats"))
        .and_then(serde_json::Value::as_array)
        .map(|seats| {
            seats
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(|name| safe_council_text(name, 24))
                .take(COUNCIL_SEATS.len())
                .collect()
        })
        .unwrap_or_default();
    CouncilSnapshot {
        phase,
        note: clean(value.get("note"), 240),
        seats,
        extra_seats,
        winner_seats,
        last_seats: Vec::new(),
        last_final: String::new(),
        finished: 0,
        seen: 0,
        last_at: None,
        published_at,
        last_tie: false,
    }
}

fn parse_seat(
    index: usize,
    seat: &serde_json::Value,
    phase: &str,
    clean: &dyn Fn(Option<&serde_json::Value>, usize) -> String,
) -> CouncilSeat {
    let (name, role) = BENCH
        .get(index)
        .map_or(("AE", ""), |(name, role)| (*name, *role));
    let model = clean(seat.get("model"), 40);
    let status = clean(seat.get("status"), 16);
    let verdict = match clean(seat.get("verdict"), 16).to_uppercase().as_str() {
        "APPROVE" => Some("approve".to_string()),
        "REJECT" => Some("reject".to_string()),
        "CONDITIONAL" => Some("hold".to_string()),
        _ => None,
    };
    // What the seat is doing, in the pane's terms. A quiet council rests
    // whatever the last run left behind.
    let quiet = matches!(phase, "IDLE" | "TRIAGE" | "TRIAGED" | "FAIL");
    let activity = if quiet {
        "resting"
    } else {
        match status.as_str() {
            "error" => "lost",
            "syncing" => "wiring",
            "online" | "reported" => "answered",
            "computing" => "working",
            _ if verdict.is_some() => "answered",
            _ => "working",
        }
    };
    CouncilSeat {
        name: name.into(),
        number: format!("{:02}", index + 1),
        role: role.into(),
        lab: council_lab(&model),
        model,
        activity: activity.into(),
        verdict,
        confidence: None,
    }
}

/// The engine's phase word in Hangul, as the panes label it.
fn council_phase_hangul(name: &str) -> &str {
    match name {
        "TRIAGE" => "분석중",
        "TRIAGED" => "선별",
        "SYNC" => "기동",
        "DELIBERATING" => "심의",
        "VOTING" => "표결",
        "VOTED" => "투표완료",
        "JUDGING" => "판정",
        "VERDICT" => "결론도달",
        "FAIL" => "고장",
        _ => "대기",
    }
}

/// The provider a model name implies, spelled the way the panes spell it.
fn council_lab(model: &str) -> String {
    let lower = model.to_lowercase();
    [
        ("opus", "ANTHROPIC"),
        ("haiku", "ANTHROPIC"),
        ("sonnet", "ANTHROPIC"),
        ("deepseek", "DEEPSEEK"),
        ("glm", "ZHIPU"),
        ("minimax", "MINIMAX"),
        ("qwen", "ALIBABA"),
        ("gemini", "GOOGLE"),
        ("gpt", "OPENAI"),
        ("kimi", "MOONSHOT"),
        ("mistral", "MISTRAL"),
        ("claude", "ANTHROPIC"),
    ]
    .into_iter()
    .find(|(key, _)| lower.contains(key))
    .map_or_else(|| "ae".to_string(), |(_, lab)| lab.to_string())
}

/// The newest finished council from the append-only record: its seats with
/// the verdict and confidence each answer carried, its conclusion, and how
/// many of the recent records finished.
fn council_last_record(path: &Path) -> Option<(CouncilHistoryRecord, Option<f64>)> {
    use std::io::{Seek, SeekFrom};
    const TAIL_BYTES: u64 = 256 * 1024;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let cut = meta.len() > TAIL_BYTES;
    if cut {
        file.seek(SeekFrom::Start(meta.len() - TAIL_BYTES)).ok()?;
    }
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes).ok()?;
    let tail = String::from_utf8_lossy(&bytes);
    // After a cut the first line is partial; it never parses as a record.
    let records: Vec<serde_json::Value> = tail
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect();
    let recent = &records[records.len().saturating_sub(20)..];
    let finished = recent
        .iter()
        .filter(|row| {
            row.get("final")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|final_text| !final_text.trim().is_empty())
        })
        .count() as u32;
    let last = records.iter().rev().find(|row| {
        row.get("final")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|final_text| !final_text.trim().is_empty())
    })?;
    let last_at = last.get("ts").and_then(serde_json::Value::as_f64);
    let answers = last.get("answers").and_then(serde_json::Value::as_object);
    let models = last.get("models").and_then(serde_json::Value::as_object);
    let winner = last.get("winner");
    let winner_names: Vec<String> = winner
        .and_then(|winner| winner.get("seats"))
        .and_then(serde_json::Value::as_array)
        .map(|seats| {
            seats
                .iter()
                .filter_map(serde_json::Value::as_str)
                .take(4)
                .map(|name| safe_council_text(name, 32))
                .collect()
        })
        .unwrap_or_default();
    let last_seats: Vec<CouncilSeat> = BENCH
        .iter()
        .enumerate()
        .map(|(index, (name, role))| {
            let answer = answers
                .and_then(|answers| answers.get(*name))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let model = models
                .and_then(|models| models.get(*name))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let model = safe_council_text(model, 96);
            CouncilSeat {
                name: (*name).into(),
                number: format!("{:02}", index + 1),
                role: (*role).into(),
                lab: council_lab(&model),
                model,
                activity: "resting".into(),
                verdict: verdict_word(answer),
                confidence: confidence_value(answer),
            }
        })
        .collect();
    let final_text = last
        .get("final")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let first = final_text.lines().next().unwrap_or("");
    let first = first.trim_start();
    let first = first.strip_prefix("FINAL:").unwrap_or(first).trim();
    let any_verdict = last_seats.iter().any(|seat| seat.verdict.is_some());
    Some((
        CouncilHistoryRecord {
            finished,
            seen: recent.len() as u32,
            last_seats,
            last_final: safe_council_text(first, 160),
            tie: winner_names.is_empty() && any_verdict,
            winner_names,
        },
        last_at,
    ))
}

#[derive(Clone)]
struct CouncilHistoryRecord {
    finished: u32,
    seen: u32,
    last_seats: Vec<CouncilSeat>,
    last_final: String,
    winner_names: Vec<String>,
    /// The newest finished council named no winner: every verdict split.
    tie: bool,
}

/// The verdict an answer text states, if it states one.
fn verdict_word(answer: &str) -> Option<String> {
    let upper = answer.to_uppercase();
    let at = upper.find("VERDICT:")?;
    let rest = upper[at + "VERDICT:".len()..].trim_start();
    for (word, verdict) in [
        ("APPROVE", "approve"),
        ("REJECT", "reject"),
        ("CONDITIONAL", "hold"),
    ] {
        if rest.starts_with(word) {
            return Some(verdict.to_string());
        }
    }
    None
}

/// The confidence an answer text states, if it states one.
fn confidence_value(answer: &str) -> Option<u8> {
    let upper = answer.to_uppercase();
    let at = upper.find("CONFIDENCE:")?;
    let digits: String = upper[at + "CONFIDENCE:".len()..]
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .take(3)
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod backup_tests {
    use super::*;

    /// a second write keeps the first generation as a .bak sibling.
    #[test]
    fn profile_replace_keeps_the_previous_generation_as_bak() {
        let home = std::env::temp_dir().join(format!("orbit-g6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let workspace = home.join("ws");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(&workspace).unwrap();
        let first = Profile {
            name: "First".into(),
            ..Profile::default()
        };
        let saved = replace(&home, &workspace, &first).expect("first save");
        let second = Profile {
            name: "Second".into(),
            ..Profile::default()
        };
        replace(&home, &workspace, &second).expect("second save");
        let bak = home.join("customization.json.bak");
        assert!(bak.exists(), "backup written");
        let text = std::fs::read_to_string(&bak).unwrap();
        assert!(
            text.contains("\"First\""),
            "bak holds the first generation: {text}"
        );
        let live = std::fs::read_to_string(home.join("customization.json")).unwrap();
        assert!(live.contains("\"Second\""));
        let _ = saved;
        let _ = std::fs::remove_dir_all(&home);
    }
}
