//! Validated portable profiles and inert, policy-scoped pane content.
use crate::tool_runtime::PermissionScope;
use orbit_frontend_protocol::customization::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
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
const FIELDS: [&str; 11] = [
    "name",
    "theme",
    "token_overrides",
    "density",
    "glyphs",
    "reduced_motion",
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
        .panes
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| Error::Invalid("unknown pane id".into()))?;
    let (mut state, mut text, mut truncated) = (PaneState::Ready, String::new(), false);
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
        actions: pane
            .actions
            .iter()
            .filter(|a| context.controller || !matches!(a, PaneAction::OwnerCancel))
            .cloned()
            .collect(),
    })
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
