with import ./pkgs.nix {};

let
  vulnixPre =
    vulnix.overrideAttrs(old: rec {
      name = "vulnix-${version}";
      version = "1.4.1-pre";

      src = fetchFromGitHub {
        owner = "flyingcircusio";
        repo = "vulnix";
        sha256 = "06v7mg3wg7mdaqbbb4pr2wz5k3ndwniqpx14fx3vzy186b11vsfz";
        rev = "b019904ad120802786c18da41466179fb6edcd4c";
      };

    });


in stdenv.mkDerivation rec {
  name = "nix-vuln-bot";
  env = buildEnv { name = name; paths = buildInputs; };

  buildInputs = [
    vulnixPre
    python3
    nix
  ];
}
