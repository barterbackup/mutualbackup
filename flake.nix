{
  description = "Mutual P2P backup development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.chutney = {
    url = "git+https://gitlab.torproject.org/tpo/core/chutney.git?rev=9ca2446f4837c1730d31cf9be8ebb7865ebe8fc3";
    flake = false;
  };
  # Chutney's authorities need the Tor release paired with the reviewed Arti
  # 2.6/0.46 line. Keep this independent of the product's Nixpkgs pin.
  inputs.tor-nixpkgs.url = "github:NixOS/nixpkgs/aff8a0b28396750446e5537a96461bc4facdb287";

  outputs = { nixpkgs, chutney, tor-nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      torPkgs = import tor-nixpkgs { inherit system; };
      sourceRoot = toString ./.;
      cleanSource = pkgs.lib.cleanSourceWith {
        name = "mutualbackup-source";
        src = ./.;
        filter = path: _type:
          let
            relative = pkgs.lib.removePrefix "${sourceRoot}/" (toString path);
            firstComponent = builtins.head (pkgs.lib.splitString "/" relative);
          in
          !(builtins.elem firstComponent [
            ".git"
            ".direnv"
            ".docker-lab"
            "dist"
            "result"
            "target"
          ] || pkgs.lib.hasPrefix "result-" firstComponent);
      };
      staticBinary = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
        pname = "mutualbackup";
        version = "0.1.0";
        src = cleanSource;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "mutualbackup" ];
        nativeBuildInputs = with pkgs; [ perl pkg-config ];
        doCheck = true;
      };
      labArtifacts = pkgs.runCommandNoCC "mutualbackup-lab-artifacts-0.1.0" { } ''
        install -Dm755 ${staticBinary}/bin/mutualbackup \
          $out/mutualbackup-x86_64-linux
        install -Dm755 ${staticBinary}/bin/mutualbackupd \
          $out/mutualbackupd-x86_64-linux
      '';
    in {
      packages.${system} = {
        default = staticBinary;
        lab-artifacts = labArtifacts;
      };
      checks.${system} = {
        default = staticBinary;
        lab-artifacts = labArtifacts;
      };

      devShells.${system} = {
        default = pkgs.mkShell {
          packages = with pkgs; [
            btrfs-progs
            cargo
            clang
            gnumake
            openssl
            perl
            pkg-config
            rustc
            rustfmt
            clippy
            sqlcipher
          ];

          RUST_BACKTRACE = "1";
        };

        # Host-side tools used by scripts/docker-lab.sh. This shell deliberately
        # does not depend on staticBinary: entering it must not build the project.
        docker-lab = pkgs.mkShell {
          packages = with pkgs; [
            btrfs-progs
            coreutils
            docker-client
            gawk
            gnugrep
            gnused
            util-linux
          ];

          shellHook = ''
            echo "MutualBackup Docker lab tools are available."
            echo "The host must still provide a Docker daemon, sudo/root access, and loop+Btrfs kernel support."
          '';
        };

        # Reproducible dependencies for the real onion-only acceptance gate.
        # Like docker-lab, this shell does not build MutualBackup on entry.
        private-tor = pkgs.mkShell {
          packages = with pkgs; [
            btrfs-progs
            cargo
            clang
            coreutils
            gawk
            gnumake
            openssl
            perl
            pkg-config
            rustc
            util-linux
            torPkgs.arti
            torPkgs.tor
            (python3.withPackages (pythonPackages: with pythonPackages; [
              cryptography
              paramiko
              tomli-w
              typeguard
              typing-extensions
            ]))
          ];

          CHUTNEY_PATH = toString chutney;
          RUST_BACKTRACE = "1";

          shellHook = ''
            echo "MutualBackup private-Tor acceptance tools are available."
            echo "Run scripts/private-tor-acceptance.sh against a disposable reflink filesystem."
          '';
        };
      };
    };
}
