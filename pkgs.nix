let
  pkgs = import <nixpkgs> { };

  pkgsJSON = pkgs.lib.importJSON ./nixpkgs.json;

  nixpkgs = with pkgs; (stdenv.mkDerivation {
    name = "nixpkgs";

    src = fetchurl {
      url = "https://github.com/nixos/nixpkgs-channels/archive/${pkgsJSON.rev}.tar.gz";
      sha256 = pkgsJSON.sha256;
    };

    installPhase = ''
      mkdir -p $out
      cp -a * $out
    '';

  });

in import nixpkgs
