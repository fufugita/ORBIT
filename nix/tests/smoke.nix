{ pkgs, orbit }:
pkgs.testers.runNixOSTest {
  name = "orbit-nixos-runtime";
  nodes.machine = { ... }: {
    virtualisation.memorySize = 3072;
    virtualisation.cores = 2;
    users.users.trial = { isNormalUser = true; createHome = true; };
    boot.kernel.sysctl."user.max_user_namespaces" = 1024;
    environment.systemPackages = [ orbit pkgs.python3 pkgs.bash pkgs.coreutils pkgs.git pkgs.ripgrep pkgs.bubblewrap pkgs.util-linux ];
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -m755 ${../../scripts/in-jail.sh} /tmp/orbit-in-jail")
    machine.succeed("install -m644 ${../../scripts/nixos_runtime_test.py} /tmp/orbit-nixos-runtime.py")
    machine.succeed("su - trial -c '/tmp/orbit-in-jail ${pkgs.python3}/bin/python3 /tmp/orbit-nixos-runtime.py --binary ${orbit}/bin/orbit --web-binary ${orbit}/bin/orbit-web'")
  '';
}
