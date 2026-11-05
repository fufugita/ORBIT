//! Resolve the same immutable runtime for the sandbox probe and command runner.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(crate) struct LinuxRuntimeLayout {
    pub bash: PathBuf,
    pub bubblewrap: PathBuf,
    pub read_roots: Vec<PathBuf>,
    pub path: OsString,
}

impl LinuxRuntimeLayout {
    pub fn discover() -> Result<Self, String> {
        Self::resolve(
            &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"],
            Path::new("/nix/store"),
            std::env::var_os("PATH").as_deref(),
            std::env::var_os("ORBIT_RUNTIME_PATH").as_deref(),
        )
    }

    fn resolve(
        fhs: &[&str],
        store: &Path,
        ambient: Option<&OsStr>,
        explicit: Option<&OsStr>,
    ) -> Result<Self, String> {
        let mut read_roots = Vec::new();
        for root in fhs {
            let root = PathBuf::from(root);
            if root.is_dir() && !read_roots.contains(&root) {
                read_roots.push(root);
            }
        }
        let store = if store.is_dir() {
            let canonical = store
                .canonicalize()
                .map_err(|e| format!("Nix store: {e}"))?;
            if canonical != store {
                return Err("Nix store must be a real directory, not an alias".into());
            }
            read_roots.push(canonical.clone());
            Some(canonical)
        } else {
            None
        };
        let mut directories = Vec::new();
        let mut add = |path: &Path, strict: bool| -> Result<(), String> {
            if !path.is_absolute() {
                return if strict {
                    Err("runtime PATH entries must be absolute and nonempty".into())
                } else {
                    Ok(())
                };
            }
            let canonical = match path.canonicalize() {
                Ok(value) if value.is_dir() => value,
                _ if !strict => return Ok(()),
                _ => {
                    return Err(format!(
                        "runtime PATH directory is missing: {}",
                        path.display()
                    ));
                }
            };
            let trusted = store
                .as_ref()
                .is_some_and(|root| canonical.starts_with(root))
                || read_roots
                    .iter()
                    .filter(|root| Some(*root) != store.as_ref())
                    .any(|root| canonical.starts_with(root));
            if !trusted {
                return if strict {
                    Err(format!(
                        "runtime PATH escapes mounted runtime: {}",
                        path.display()
                    ))
                } else {
                    Ok(())
                };
            }
            if !directories.contains(&canonical) {
                directories.push(canonical);
            }
            Ok(())
        };
        if let Some(paths) = explicit {
            if paths.is_empty() {
                return Err("runtime PATH must not be empty".into());
            }
            for path in std::env::split_paths(paths) {
                add(&path, true)?;
            }
        } else {
            // Ambient user/workspace programs are deliberately not imported.
            // Only canonical aliases into the immutable store supplement FHS.
            if let Some(paths) = ambient {
                for path in std::env::split_paths(paths) {
                    if path.is_absolute()
                        && path
                            .canonicalize()
                            .ok()
                            .as_ref()
                            .is_some_and(|p| store.as_ref().is_some_and(|s| p.starts_with(s)))
                    {
                        add(&path, false)?;
                    }
                }
            }
            for path in ["/usr/local/bin", "/usr/bin", "/bin"] {
                add(Path::new(path), false)?;
            }
        }
        let find = |name: &str| -> Result<PathBuf, String> {
            directories
                .iter()
                .find_map(|directory| {
                    let file = directory.join(name).canonicalize().ok()?;
                    if !read_roots.iter().any(|root| file.starts_with(root)) || !executable(&file) {
                        return None;
                    }
                    Some(file)
                })
                .ok_or_else(|| format!("{name} is missing from the mounted runtime"))
        };
        Ok(Self {
            bash: find("bash")?,
            bubblewrap: find("bwrap")?,
            path: std::env::join_paths(&directories).map_err(|e| format!("runtime PATH: {e}"))?,
            read_roots,
        })
    }
}

fn executable(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("orbit-runtime-{}", ulid::Ulid::new()));
            std::fs::create_dir_all(root.join("store/package/bin")).unwrap();
            for name in ["bash", "bwrap"] {
                let file = root.join("store/package/bin").join(name);
                std::fs::write(&file, "runtime fixture").unwrap();
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            Self(root)
        }
        fn resolve(&self, paths: &OsStr) -> Result<LinuxRuntimeLayout, String> {
            LinuxRuntimeLayout::resolve(&[], &self.0.join("store"), None, Some(paths))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn linux_runtime_store_only_and_profile_alias_are_resolved_and_deduplicated() {
        let f = Fixture::new();
        let bin = f.0.join("store/package/bin");
        let profile = f.0.join("profile");
        symlink(&bin, &profile).unwrap();
        let layout = f
            .resolve(&std::env::join_paths([&profile, &bin]).unwrap())
            .unwrap();
        assert_eq!(layout.bash, bin.join("bash"));
        assert_eq!(layout.bubblewrap, bin.join("bwrap"));
        assert_eq!(
            std::env::split_paths(&layout.path).collect::<Vec<_>>(),
            vec![bin]
        );
        assert_eq!(layout.read_roots, vec![f.0.join("store")]);
    }

    #[test]
    fn linux_runtime_rejects_relative_empty_missing_and_prefix_escape() {
        let f = Fixture::new();
        for path in [
            OsStr::new(""),
            OsStr::new("relative"),
            OsStr::new(":/missing"),
        ] {
            assert!(f.resolve(path).is_err());
        }
        let escape = f.0.join("store-escape/bin");
        std::fs::create_dir_all(&escape).unwrap();
        assert!(f.resolve(escape.as_os_str()).is_err());
    }

    #[test]
    fn linux_runtime_rejects_aliased_store_and_missing_tools() {
        let f = Fixture::new();
        let bin = f.0.join("store/package/bin");
        std::fs::remove_file(bin.join("bash")).unwrap();
        assert!(f.resolve(bin.as_os_str()).is_err());
        let alias = f.0.join("alias");
        symlink(f.0.join("store"), &alias).unwrap();
        assert!(LinuxRuntimeLayout::resolve(&[], &alias, None, Some(bin.as_os_str())).is_err());
    }

    #[test]
    fn linux_runtime_fhs_fixture_does_not_need_a_store() {
        let f = Fixture::new();
        let bin = f.0.join("store/package/bin");
        let layout = LinuxRuntimeLayout::resolve(
            &[f.0.to_str().unwrap()],
            &f.0.join("absent-store"),
            None,
            Some(bin.as_os_str()),
        )
        .unwrap();
        assert_eq!(layout.bash, bin.join("bash"));
        assert_eq!(layout.read_roots, vec![f.0.clone()]);
    }

    #[test]
    fn linux_runtime_ignores_mutable_ambient_search_directories() {
        let f = Fixture::new();
        let bin = f.0.join("store/package/bin");
        let paths = std::env::join_paths([f.0.join("mutable"), bin.clone()]).unwrap();
        let layout =
            LinuxRuntimeLayout::resolve(&[], &f.0.join("store"), Some(&paths), None).unwrap();
        assert_eq!(
            std::env::split_paths(&layout.path).collect::<Vec<_>>(),
            vec![bin]
        );
    }

    #[test]
    fn linux_runtime_rejects_tool_symlink_outside_mounts() {
        let f = Fixture::new();
        let bash = f.0.join("store/package/bin/bash");
        std::fs::remove_file(&bash).unwrap();
        symlink("/usr/bin/bash", bash).unwrap();
        assert!(
            f.resolve(f.0.join("store/package/bin").as_os_str())
                .is_err()
        );
    }
}
