# ORBIT v0.1 — Unsafe audit evidence

**Date:** 2026-08-12  
**Gate:** DR-03 §5 row 2  
**Verdict:** PASS (reviewed; Miri/ASan as applicable)

## Inventory

| Crate | Unsafe operation | Invariant / rationale | Dynamic coverage |
|---|---|---|---|
| `orbit-trust` | `libc::geteuid()` | No preconditions; no pointer dereference; returns effective UID. Scoped `#[allow(unsafe_code)]` and SAFETY comment at `crates/trust/src/acl.rs`. | Miri: 10/10 pass with `-Zmiri-disable-isolation`; ASan: pass. |
| `orbit-ledger` | `libc::flock(fd, LOCK_EX|LOCK_NB)` | `fd` comes from a live `File`; kept open for writer lifetime; no pointer dereference; rc==0 means lock acquired. Scoped allow + SAFETY comment at `crates/ledger/src/writer.rs`. | Miri: 8/8 pass with `-Zmiri-disable-isolation`; ASan: pass. |
| `orbit-sandbox` | `prctl(PR_SET_NO_NEW_PRIVS)` | Linux syscall probe; scalar args only; status checked; fail-closed. SAFETY comment at `crates/sandbox/src/linux.rs`. | Miri: syscall unsupported by interpreter; safe profile logic 3/3 pass. Native probe tests 2/2 pass. ASan probe tests 2/2 pass. |
| `orbit-sandbox` | `syscall(landlock_create_ruleset)` | Null attr + size 0 is feature probe only; no dereference; ENOSYS/EOPNOTSUPP interpreted fail-closed. | Miri: syscall unsupported; ASan 2/2 native probe tests pass. |
| `orbit-sandbox` | `syscall(seccomp, empty sock_fprog)` | Pointer points to live stack `sock_fprog`; empty filter is probe only; result checked; fail-closed. | Miri: syscall unsupported; ASan 2/2 native probe tests pass. |
| `orbit-sandbox` | `unshare(CLONE_NEWUSER)` | Scalar syscall; no memory dereference; ENOSYS fails; EPERM/EINVAL indicates feature exposed but unavailable to process. | Miri: syscall unsupported; ASan 2/2 native probe tests pass. |

## Commands and results

```console
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p orbit-trust
# 10 passed

MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p orbit-ledger
# 8 passed

MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test -p orbit-sandbox profile::tests
# 3 passed (syscall probes excluded: Miri does not emulate prctl/landlock/seccomp/unshare)

cargo test -p orbit-sandbox linux::tests
# 2 passed natively

RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -p orbit-sandbox --target x86_64-unknown-linux-gnu linux::tests
# 2 passed

RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -p orbit-trust -p orbit-ledger --target x86_64-unknown-linux-gnu
# 18 passed
```

## Conclusion

No unreviewed unsafe remains. Every block is scoped, documented with its invariant, and dynamically exercised under Miri or ASan where the interpreter supports the operation. Linux syscalls that Miri cannot emulate are covered natively and under AddressSanitizer.
