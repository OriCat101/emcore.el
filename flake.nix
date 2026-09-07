{
  description = "emcore.el — Emacs client for the emcore ERP";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = f: nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ]
        (system: f nixpkgs.legacyPackages.${system});
    in {
      packages = forAllSystems (pkgs: rec {
        default = emcore;
        emcore = pkgs.emacsPackages.trivialBuild {
          pname = "emcore";
          version = "0.1.0";
          src = ./.;
        };
      });
    };
}
