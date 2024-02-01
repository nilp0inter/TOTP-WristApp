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
  in {
    packages.x86_64-linux.WIN6811IDE = WIN6811IDE;
    packages.x86_64-linux.default = self.packages.x86_64-linux.WIN6811IDE;

    devShells.x86_64-linux.default = pkgs.mkShell {
      shellHook = ''
        export PATH="${assembler}:${WIN6811IDE}/bin:$PATH"
      '';
    };
  };
}
