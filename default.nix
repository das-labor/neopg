let
   pkgs = import <nixpkgs> {};
in pkgs.stdenv.mkDerivation rec {
  name = "glutin-env";
  buildInputs = with pkgs; [ cmake gtest clang gcc boost ];
}
