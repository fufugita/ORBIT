# Platform support

The GNU/Linux release bundles contain a matching `orbit` and `orbit-web` pair.
NixOS should use the source-built Nix package, which supplies its own immutable
runtime paths and does not require enabling `nix-ld` globally.

From a checkout containing the locked flake:

```sh
nix build --no-write-lock-file .#orbit
./result/bin/orbit
```

To add that checkout to the user's profile:

```sh
nix profile install .#orbit
```

The flake exposes packages and applications for `x86_64-linux` and
`aarch64-linux`. Architecture availability is separate from runtime validation.
The `native platforms` workflow runs the x86_64 source build and a booted NixOS
VM with an ordinary user:

```sh
nix build -L --no-write-lock-file .#checks.x86_64-linux.nixos-runtime
```

That check must execute setup, a local model response, session resume, approved
store-provided shell tools, write/read/network denials, environment isolation
and cancellation. Package evaluation or a version command alone is insufficient
to establish platform readiness. The build derivation does not run the existing
namespace tests inside Nix's builder; the booted VM exercises the installed pair.

The Nix wrappers set `ORBIT_RUNTIME_PATH` to explicit store directories containing
Bash, bubblewrap, coreutils, Git and ripgrep. Ambient profile aliases are accepted
only after resolution beneath the real `/nix/store` boundary. The store is mounted
read-only; workspace writes, private temporary storage, secret masks and the
default network denial still apply.

Native Windows support requires its own storage, console, PowerShell isolation
and installed-package acceptance. The GNU/Linux archives are not Windows packages.
