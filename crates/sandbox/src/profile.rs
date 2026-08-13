//! Sandbox profiles (DR-07 §3.3 — three concrete locked profiles, no default).
//!
//! Each profile is a deny-by-default layered cage:
//! Landlock ABI v4 filesystem → seccomp syscall/address-family filter →
//! WASI 0.2 host-import allowlist → egress broker (capability-driven).

use crate::error::SandboxError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The two distinct sandbox domains (DR-07 S2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxDomain {
    Plugin,
    LocalModel,
}

/// Sandbox profile id (built-in named profile, §3.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SandboxProfileId {
    #[serde(rename = "orbit/plugin/default-v0_1")]
    PluginDefault,
    #[serde(rename = "orbit/local-model/default-v0_1")]
    LocalModelDefault,
    #[serde(rename = "orbit/plugin/strict-v0_1")]
    PluginStrict,
}

/// Landlock path rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRule {
    pub path: PathBuf,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// Landlock rule set (DR-07 §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandlockRuleSet {
    pub read_paths: Vec<PathRule>,
    pub write_paths: Vec<PathRule>,
    pub fsync_paths: Vec<PathRule>, // includes ledger dir (S7)
}

/// Seccomp profile — filters syscall classes + address families, NEVER destinations (S4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeccompProfile {
    pub deny_process: bool, // clone/fork/execve outside mediated channel (S17)
    pub deny_filesystem: bool,
    pub deny_kernel: bool, // dmesg, module, etc.
    pub deny_time: bool,
    pub deny_privileged: bool,
    pub allow_af_inet: bool, // false unless broker-mediated loopback
    pub allow_af_unix: bool, // default false (S17)
    pub kill_on_violation: bool,
}

/// Namespace flags (S14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceFlags {
    pub new_user: bool,
    pub new_mount: bool,
    pub new_pid: bool,
    pub new_uts: bool,
    pub new_ipc: bool,
    pub new_net: bool, // false in v0.1 (broker mediates)
}

/// Resource limits (S15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub nproc: u64,
    pub nofile: u64,
    pub fsize_bytes: u64,
    pub cpu_seconds: u64,
    pub as_bytes: u64,
    pub memlock_bytes: u64,
    pub rtprio: u64,
}

/// WASI host-import allowlist (S8, S12, S13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasiImportAllowlist {
    pub allow_wasi_http_proxy: bool,
    pub allow_orbit_reactor_context_read: bool,
    pub allow_orbit_reactor_random: bool,
    pub allow_orbit_reactor_pipe: bool,
    pub allow_orbit_reactor_subagent_handle: bool,
    // Denied categories (S8/S12/S13): wasi:sockets, wasi:filesystem, orbit:audit/*,
    // orbit:ledger/*, orbit:replay/*, orbit:reactor/credentials/*.
}

/// A full sandbox profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub id: SandboxProfileId,
    pub domain: SandboxDomain,
    pub landlock: LandlockRuleSet,
    pub seccomp: SeccompProfile,
    pub namespace: NamespaceFlags,
    pub rlimits: ResourceLimits,
    pub wasi_imports: WasiImportAllowlist,
    pub instance_pool_max: usize, // WASI_INSTANCE_POOL_MAX = 64
    pub reclaim_budget_ms: u64,   // PLUGIN_RECLAIM_BUDGET_MS = 250
}

/// The three locked built-in profiles (DR-07 §3.3). No default exists.
pub fn builtin_profiles() -> [SandboxProfile; 3] {
    [plugin_default(), local_model_default(), plugin_strict()]
}

fn plugin_default() -> SandboxProfile {
    SandboxProfile {
        id: SandboxProfileId::PluginDefault,
        domain: SandboxDomain::Plugin,
        landlock: LandlockRuleSet {
            read_paths: vec![
                PathRule {
                    path: "/workspace".into(),
                    read: true,
                    write: false,
                    execute: false,
                },
                PathRule {
                    path: "/scratch".into(),
                    read: true,
                    write: false,
                    execute: false,
                },
            ],
            write_paths: vec![PathRule {
                path: "/scratch".into(),
                read: true,
                write: true,
                execute: false,
            }],
            fsync_paths: vec![PathRule {
                path: "/ledger".into(),
                read: false,
                write: true,
                execute: false,
            }],
        },
        seccomp: SeccompProfile {
            deny_process: true,
            deny_filesystem: true,
            deny_kernel: true,
            deny_time: true,
            deny_privileged: true,
            allow_af_inet: false,
            allow_af_unix: false,
            kill_on_violation: true,
        },
        namespace: NamespaceFlags {
            new_user: true,
            new_mount: true,
            new_pid: true,
            new_uts: false,
            new_ipc: true,
            new_net: false,
        },
        rlimits: ResourceLimits {
            nproc: 32,
            nofile: 128,
            fsize_bytes: 64 << 20,
            cpu_seconds: 120,
            as_bytes: 512 << 20,
            memlock_bytes: 0,
            rtprio: 0,
        },
        wasi_imports: WasiImportAllowlist {
            allow_wasi_http_proxy: true,
            allow_orbit_reactor_context_read: true,
            allow_orbit_reactor_random: true,
            allow_orbit_reactor_pipe: true,
            allow_orbit_reactor_subagent_handle: true,
        },
        instance_pool_max: 64,
        reclaim_budget_ms: 250,
    }
}

fn local_model_default() -> SandboxProfile {
    SandboxProfile {
        id: SandboxProfileId::LocalModelDefault,
        domain: SandboxDomain::LocalModel,
        landlock: LandlockRuleSet {
            read_paths: vec![
                PathRule {
                    path: "/model".into(),
                    read: true,
                    write: false,
                    execute: true,
                },
                PathRule {
                    path: "/tokenizer".into(),
                    read: true,
                    write: false,
                    execute: false,
                },
            ],
            write_paths: vec![PathRule {
                path: "/scratch".into(),
                read: true,
                write: true,
                execute: false,
            }],
            fsync_paths: vec![PathRule {
                path: "/ledger".into(),
                read: false,
                write: true,
                execute: false,
            }],
        },
        seccomp: SeccompProfile {
            deny_process: true,
            deny_filesystem: true,
            deny_kernel: true,
            deny_time: true,
            deny_privileged: true,
            allow_af_inet: false,
            allow_af_unix: false,
            kill_on_violation: true,
        },
        namespace: NamespaceFlags {
            new_user: true,
            new_mount: true,
            new_pid: true,
            new_uts: true,
            new_ipc: true,
            new_net: false,
        },
        rlimits: ResourceLimits {
            nproc: 8,
            nofile: 256,
            fsize_bytes: 2 << 30,
            cpu_seconds: 0,
            as_bytes: 8 << 30,
            memlock_bytes: 64 << 10,
            rtprio: 0,
        },
        wasi_imports: WasiImportAllowlist {
            allow_wasi_http_proxy: false,
            allow_orbit_reactor_context_read: true,
            allow_orbit_reactor_random: true,
            allow_orbit_reactor_pipe: false,
            allow_orbit_reactor_subagent_handle: false,
        },
        instance_pool_max: 64,
        reclaim_budget_ms: 250,
    }
}

fn plugin_strict() -> SandboxProfile {
    let mut base = plugin_default();
    base.id = SandboxProfileId::PluginStrict;
    base.landlock.read_paths.clear(); // scratch only, no workspace
    base.rlimits.nproc = 8;
    base.rlimits.nofile = 64;
    base.rlimits.cpu_seconds = 30;
    base.wasi_imports.allow_wasi_http_proxy = false; // no egress at all
    base
}

/// Resolve a profile by id; E0802 if unknown (no default).
pub fn resolve_profile(id: &SandboxProfileId) -> Result<SandboxProfile, SandboxError> {
    builtin_profiles()
        .into_iter()
        .find(|p| &p.id == id)
        .ok_or_else(|| SandboxError::SandboxRequired(format!("unknown profile {id:?}")))
}

/// Apply an override; refuse if it would WIDEN the profile (S4 → E0804).
pub fn apply_override(
    profile: &mut SandboxProfile,
    extra_read_paths: &BTreeSet<PathBuf>,
) -> Result<(), SandboxError> {
    for p in extra_read_paths {
        // Additive read-only paths only — cannot widen rlimits, seccomp, or egress.
        profile.landlock.read_paths.push(PathRule {
            path: p.clone(),
            read: true,
            write: false,
            execute: false,
        });
    }
    // The profile's deny-by-default posture must remain intact:
    if profile.seccomp.allow_af_inet {
        return Err(SandboxError::OverrideWidensProfile(
            "overrides cannot enable AF_INET".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_locked_profiles_no_default() {
        let ps = builtin_profiles();
        assert_eq!(ps.len(), 3);
        assert!(resolve_profile(&SandboxProfileId::PluginDefault).is_ok());
        assert_eq!(ps[0].instance_pool_max, 64);
        assert_eq!(ps[0].reclaim_budget_ms, 250);
    }

    #[test]
    fn strict_profile_denies_http() {
        let p = resolve_profile(&SandboxProfileId::PluginStrict).unwrap();
        assert!(!p.wasi_imports.allow_wasi_http_proxy);
        assert!(p.landlock.read_paths.is_empty(), "strict = scratch only");
    }

    #[test]
    fn domains_never_cross() {
        let plugin = resolve_profile(&SandboxProfileId::PluginDefault).unwrap();
        let local = resolve_profile(&SandboxProfileId::LocalModelDefault).unwrap();
        assert_ne!(plugin.domain, local.domain);
        // local model allows http? no — only via broker loopback
        assert!(!local.wasi_imports.allow_wasi_http_proxy);
    }
}
