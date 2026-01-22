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

            vendorHash = "sha256-bnSuTJVal4XwmRwuKDtbibURG4Sf1monXutCVqd+BFo=";

            nativeInstallCheckInputs = [ pkgs.versionCheckHook ];

            env = {
              CGO_ENABLED = 0;
            };

            ldflags = [
              "-s"
              "-w"
              "-X main.newtVersion=${version}"
            ];

            # Tests are broken due to a lack of Internet.
            # Disable running `go test`, and instead do
            # a simple version check instead.
            doCheck = false;
            doInstallCheck = true;

            versionCheckProgramArg = [ "-version" ];

            meta = {
              description = "A tunneling client for Pangolin";
              homepage = "https://github.com/fosrl/newt";
              license = lib.licenses.gpl3;
              maintainers = [
                lib.maintainers.water-sucks
              ];
              mainProgram = "newt";
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
