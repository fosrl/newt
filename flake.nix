{
  description = "newt - A tunneling client for Pangolin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = self.packages.${system}.pangolin-newt;
          pangolin-newt = pkgs.buildGoModule {
            pname = "pangolin-newt";
            version = "1.1.2";

            src = ./.;

            vendorHash = "sha256-sTtiBBkZ9cuhWnrn2VG20kv4nzNFfdzP5p+ewESCjyM=";

            meta = with pkgs.lib; {
              description = "A tunneling client for Pangolin";
              homepage = "https://github.com/fosrl/newt";
              license = licenses.gpl3;
              maintainers = [ ];
            };
          };
        }
      );
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              go
              gopls
              gotools
              go-outline
              gopkgs
              godef
              golint
            ];
          };
        }
      );
    };
}
