{
  description = "Mutual P2P backup development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      staticBinary = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
        pname = "mutualbackup";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = [ "-p" "mutualbackup" ];
        nativeBuildInputs = with pkgs; [ perl pkg-config ];
        doCheck = false;
      };
    in {
      packages.${system}.default = staticBinary;

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
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
    };
}
