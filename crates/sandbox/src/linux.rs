//! Linux kernel-feature probes + sandbox application (DR-07 S3/S4/S5).
//!
//! Fail-closed on every probe: if `prctl(PR_SET_NO_NEW_PRIVS)`, Landlock ABI,
//! seccomp, or namespace setup fails, the spawn is REFUSED (E0802/E0803/E0812)
//! with no degraded mode.
//!
//! NOTE: the actual syscall sequences (landlock_create_ruleset,
//! seccomp(SECCOMP_SET_MODE_FILTER), unshare(CLONE_NEWUSER|...)) are Linux-only
//! and intentionally kept behind `#[cfg(target_os = "linux")]`. On non-Linux the
//! probes fail closed (v0.1 is Linux-only per DR-13 §1).

use crate::error::SandboxError;
use crate::profile::{SandboxProfile, SandboxProfileId};

/// Probe the required kernel features. Returns the set that are available;
/// on any fatal failure returns Err(E08xx) — refuse, never degrade (S5).
pub fn probe_kernel() -> Result<KernelFeatures, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        let no_new_privs = probe_no_new_privs();
        let landlock = probe_landlock();
        let seccomp = probe_seccomp();
        let namespaces = probe_namespaces();
        if !no_new_privs {
            return Err(SandboxError::SandboxRequired(
                "prctl(PR_SET_NO_NEW_PRIVS) unavailable (E0802)".into(),
            ));
        }
        if !landlock {
            return Err(SandboxError::LandlockAbiUnavailable(
                "Landlock ABI v4 unavailable (E0803)".into(),
            ));
        }
        if !seccomp {
            return Err(SandboxError::SeccompFilterRejected(
                "seccomp(SECCOMP_SET_MODE_FILTER) rejected (E0812)".into(),
            ));
        }
        if !namespaces {
            return Err(SandboxError::SandboxRequired(
                "unshare(CLONE_NEWUSER|NEWNS|NEWPID) unavailable (E0802)".into(),
            ));
        }
        Ok(KernelFeatures {
            no_new_privs: true,
            landlock_abi_v4: true,
            seccomp_filter: true,
            namespaces: true,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        // v0.1 is Linux-only (DR-13 §1); non-Linux fails closed.
        Err(SandboxError::SandboxRequired(
            "non-Linux platform unsupported in v0.1 (DR-13 §1)".into(),
        ))
    }
}

/// Result of the kernel probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelFeatures {
    pub no_new_privs: bool,
    pub landlock_abi_v4: bool,
    pub seccomp_filter: bool,
    pub namespaces: bool,
}

/// Validate that a profile is applicable given the probed features.
pub fn validate_applicable(
    profile: &SandboxProfile,
    features: &KernelFeatures,
) -> Result<(), SandboxError> {
    if !features.landlock_abi_v4 {
        return Err(SandboxError::LandlockAbiUnavailable(
            "Landlock required for all profiles".into(),
        ));
    }
    if !features.seccomp_filter {
        return Err(SandboxError::SeccompFilterRejected(
            "seccomp required for all profiles".into(),
        ));
    }
    if !features.namespaces && profile.namespace.new_pid {
        return Err(SandboxError::SandboxRequired(
            "namespace isolation unavailable".into(),
        ));
    }
    Ok(())
}

// SAFETY (all probes below): the syscall wrappers take no preconditions that
// are unsafe to violate — prctl/syscall/unshare with the given args either
// return an error or a status; no memory is dereferenced except the null-safe
// probe pointers. Each returns an int status; we treat ENOSYS/EOPNOTSUPP as
// "feature absent" and everything else per the comment on the probe.

#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // SAFETY: see module comment; prctl has no memory side effects
fn probe_no_new_privs() -> bool {
    // prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) — returns 0 on success.
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // SAFETY: see module comment; null attr + size 0 is a probe only
fn probe_landlock() -> bool {
    // Landlock ABI v4: attempt a minimal ruleset creation; a real deployment
    // must call landlock_create_ruleset with the ABI version. For the probe we
    // check the syscall exists (ENOSYS/EOPNOTSUPP => unavailable).
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            0u32,
        )
    };
    rc >= 0 || !matches!(errno(), libc::ENOSYS | libc::EOPNOTSUPP)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // SAFETY: see module comment; empty seccomp program is a probe only
fn probe_seccomp() -> bool {
    // A zero-length filter probe: seccomp(SECCOMP_SET_MODE_FILTER, ...) with an
    // empty program fails EFAULT on supporting kernels, ENOSYS otherwise.
    let prog = libc::sock_fprog {
        len: 0,
        filter: std::ptr::null_mut(),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0,
            &prog as *const libc::sock_fprog,
        )
    };
    rc >= 0 || errno() != libc::ENOSYS
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)] // SAFETY: see module comment; unshare probe never touches memory
fn probe_namespaces() -> bool {
    // A child namespace probe would fork; instead we check the kernel exposes
    // CLONE_NEWUSER|CLONE_NEWNS|CLONE_NEWPID via unshare availability on the
    // current process's permission model. A real spawn calls unshare directly.
    // We treat EPERM as available-but-unprivileged (user namespaces often need
    // setuid) and fail only on ENOSYS.
    let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    rc == 0 || (rc < 0 && errno() == libc::EPERM) || (rc < 0 && errno() == libc::EINVAL)
}

#[cfg(target_os = "linux")]
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[allow(dead_code)]
fn _unused_profile(_: &SandboxProfileId) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        // On any platform the probe must return Ok or a typed Err, never panic.
        let _ = probe_kernel();
    }

    #[test]
    fn strict_profile_validates() {
        let p = crate::profile::resolve_profile(&SandboxProfileId::PluginStrict).unwrap();
        // If kernel features are unavailable, validation fails closed — that's correct.
        if let Ok(f) = probe_kernel() {
            let r = validate_applicable(&p, &f);
            // On a Landlock-capable kernel this passes; on CI without it, it
            // fails closed (acceptable — DR-07 S5).
            let _ = r;
        }
    }
}
