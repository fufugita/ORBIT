{
  description = "ORBIT native Linux package and NixOS runtime checks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/1d060086d60cb76a40cf37109f979d88a5bd6396";
    rust-overlay = {
      url = "github:oxalica/rust-overlay/19e0e6c951a7a8a7d3232c64e58d26b89df44c60";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forSystems = f: builtins.listToAttrs (map (system: { name = system; value = f system; }) systems);
      pkgsFor = system: import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
    in {
      packages = forSystems (system:
        let orbit = (pkgsFor system).callPackage ./nix/package.nix { };
        in { inherit orbit; default = orbit; });
      apps = forSystems (system: {
        default = self.apps.${system}.orbit;
        orbit = { type = "app"; program = "${self.packages.${system}.orbit}/bin/orbit"; };
        orbit-web = { type = "app"; program = "${self.packages.${system}.orbit}/bin/orbit-web"; };
      });
      checks = forSystems (system: {
        package = self.packages.${system}.orbit;
      }) // {
        x86_64-linux = {
          package = self.packages.x86_64-linux.orbit;
          nixos-runtime = import ./nix/tests/smoke.nix {
            pkgs = pkgsFor "x86_64-linux";
            orbit = self.packages.x86_64-linux.orbit;
          };
        };
      };
    };
}
