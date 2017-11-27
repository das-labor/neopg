# http://stesie.github.io/2016/08/nixos-github-pages-env
# https://thisissavo.github.io/programming/2017/01/31/jekyll-setup-in-nixos.html

with import <nixpkgs> { };

let jekyll_env = bundlerEnv rec {
    name = "jekyll_env";
    inherit ruby;
    gemfile = ./Gemfile;
    lockfile = ./Gemfile.lock;
    gemset = ./gemset.nix;
  };
in
  stdenv.mkDerivation rec {
    name = "jekyll_env";
    buildInputs = [ jekyll_env ruby ];

    shellHook = ''
      exec ${jekyll_env}/bin/jekyll serve --watch --port 8088
    '';
  }
