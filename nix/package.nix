{ lib, stdenv, makeRustPlatform, rust-bin, makeWrapper, pkg-config, writeShellScriptBin
, bash, bubblewrap, coreutils, git, ripgrep, util-linux }:
let
  toolchain = rust-bin.stable."1.99.0".minimal;
  rustPlatform = makeRustPlatform { cargo = toolchain; rustc = toolchain; };
  jailedCargo = writeShellScriptBin "cargo" ''
    exec ${bash}/bin/bash scripts/in-jail.sh ${toolchain}/bin/cargo "$@"
  '';
  runtimePath = lib.makeBinPath [ bash bubblewrap coreutils git ripgrep ];
in rustPlatform.buildRustPackage {
  pname = "orbit";
  version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version;
  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      lib.cleanSourceFilter path type
      && !(builtins.elem (builtins.baseNameOf path) [ "target" ".planning" "node_modules" "dist" ]);
  };
  cargoLock.lockFile = ../Cargo.lock;
  nativeBuildInputs = [ makeWrapper pkg-config util-linux ];
  CARGO_BUILD_JOBS = "1";
  cargoBuildFlags = [ "--locked" "-p" "orbit-cli" "-p" "orbit-web" ];
  preBuild = ''
    export NIX_BUILD_CORES=1
    test "$(${toolchain}/bin/rustc --version | cut -d ' ' -f 2)" = 1.99.0
    export PATH="${jailedCargo}/bin:$PATH"
  '';
  # Namespace and process-ownership tests need a booted kernel. The VM check
  # below exercises the installed package rather than treating a skipped build
  # sandbox test as runtime evidence.
  doCheck = false;
  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    install -m755 target/${stdenv.hostPlatform.rust.rustcTargetSpec}/release/orbit $out/bin/orbit
    install -m755 target/${stdenv.hostPlatform.rust.rustcTargetSpec}/release/orbit-web $out/bin/orbit-web
    for binary in orbit orbit-web; do
      wrapProgram $out/bin/$binary --set ORBIT_RUNTIME_PATH '${runtimePath}'
    done
    runHook postInstall
  '';
  meta = {
    description = "Terminal orchestration harness";
    homepage = "https://github.com/fufugita/ORBIT";
    license = lib.licenses.asl20;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "orbit";
  };
}
