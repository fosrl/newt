{
  description = "newt - A tunneling client for Pangolin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
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
          inherit (pkgs) lib;

          # Update version when releasing
          version = "1.8.0";
        in
        {
          default = self.packages.${system}.pangolin-newt;

          pangolin-newt = pkgs.buildGoModule {
            pname = "pangolin-newt";
            inherit version;
            src = pkgs.nix-gitignore.gitignoreSource [ ] ./.;

            vendorHash = "sha256-5Xr6mwPtsqEliKeKv2rhhp6JC7u3coP4nnhIxGMqccU=";

            env = {
              CGO_ENABLED = 0;
            };

            ldflags = [
              "-X main.newtVersion=${version}"
            ];

            meta = {
              description = "A tunneling client for Pangolin";
              homepage = "https://github.com/fosrl/newt";
              license = lib.licenses.gpl3;
              maintainers = [
                lib.maintainers.water-sucks
              ];
            };
          };
        }
      );
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;

          inherit (pkgs)
            go
            gopls
            gotools
            go-outline
            gopkgs
            godef
            golint
            ;
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
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
