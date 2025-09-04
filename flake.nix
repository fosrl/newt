{
  description = "newt - A tunneling client for Pangolin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
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
          version = "1.4.4";

          # Update the version in a new source tree
          srcWithReplacedVersion = pkgs.runCommand "newt-src-with-version" { } ''
            cp -r ${./.} $out
            chmod -R +w $out
            rm -rf $out/.git $out/result $out/.envrc $out/.direnv
            sed -i "s/version_replaceme/${version}/g" $out/main.go
          '';
        in
        {
          default = self.packages.${system}.pangolin-newt;
          pangolin-newt = pkgs.buildGoModule {
            pname = "pangolin-newt";
            version = version;
            src = srcWithReplacedVersion;
            vendorHash = "sha256-XYj2hMsK7Gfrk25bRz/ooDkrXmuUdBQSF/ojF7OTQ4I=";
            preBuild = ''
              export GOTOOLCHAIN=auto
            '';
            patchPhase = ''
              sed -i 's/^go 1.25$/go 1.24/g' go.mod
            '';
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
