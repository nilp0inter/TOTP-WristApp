{
  description = "A very basic flake";

  inputs = {
    assembler = {
      url = "github:synthead/timex-datalink-assembler";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, assembler }: {

    devShells.x86_64-linux.default = let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in pkgs.mkShell {
      shellHook = ''
        export PATH="${assembler}:$PATH"
      '';
    };
  };
}
