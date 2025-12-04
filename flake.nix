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

          # Update version when releasing
          version = "1.4.2";
        in
        {
          default = self.packages.${system}.pangolin-newt;

          pangolin-newt = pkgs.buildGoModule {
            pname = "pangolin-newt";
            inherit version;
            src = pkgs.nix-gitignore.gitignoreSource [ ] ./.;

            vendorHash = "sha256-Jbu0pz+okV4N9MHUXLcTqSr3s/k5OVZ09hNuS/+4LFY=";

            ldflags = [
              "-X main.newtVersion=${version}"
            ];

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
