{
  description = "A very basic flake";

  inputs = {
    assembler = {
      url = "github:synthead/timex-datalink-assembler";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, assembler }: let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    WIN6811IDE = let
      src = pkgs.fetchzip {
        url = "http://www.activesky.com/6811IDE.zip";
        hash = "sha256-AQMvn3Lb2IPUCNNzXMevILj/2o2bBdhfmPflsvHhgXc=";
        stripRoot = false;
      };
    in pkgs.writeShellScriptBin "6811ide" ''
      ${pkgs.wine}/bin/wine ${src}/SDK6811.exe
    '';
    COSMICHC05 = let
      src = pkgs.fetchurl {
        url = "https://cosmicsoftware.com/Kit05.exe";
        hash = "sha256-7J+EbfSN5So7VtT4qhNIiWIABhsYLNFFcIxG5/HYNM0=";
      };
    in pkgs.writeShellScriptBin "cosmichc05_setup" ''
      ${pkgs.wine}/bin/wine ${src}
    '';
    asm6805 = pkgs.writeShellScriptBin "asm6805" ''
      ${assembler}/asm6805 "$@"
    '';
  in {
    packages.x86_64-linux.WIN6811IDE = WIN6811IDE;
    packages.x86_64-linux.COSMICHC05 = COSMICHC05;
    packages.x86_64-linux.default = self.packages.x86_64-linux.WIN6811IDE;

    devShells.x86_64-linux.default = let
      initEnv = pkgs.writeShellScriptBin "init-environment" ''
        for i in ~/.wine/drive_c/Program\ Files/COSMIC/EVAL05/*.exe; do
          alias $(basename "$i")="wine \"$i\""
        done
      '';
    in pkgs.mkShell {
      buildInputs = [ initEnv asm6805 WIN6811IDE COSMICHC05 pkgs.wine ];
      shellHook = ''
        echo "Welcome to the 68HC05 development environment"
        echo ""
        echo "Run $ . init-environment to set up the environment"
        echo ""
      '';
    };
  };
}
