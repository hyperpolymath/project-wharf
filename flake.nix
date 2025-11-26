# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# Project Wharf - Nix Flake
# Reproducible development environment and builds

{
  description = "Wharf - The Sovereign Web Hypervisor";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "wasm32-unknown-unknown" ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain
            rustToolchain
            cargo-audit
            cargo-tarpaulin
            cargo-watch

            # Build tools
            just
            jq

            # DNS tools
            bind

            # Security tools
            nebula

            # Documentation
            asciidoctor

            # Linting
            codespell
            lychee

            # Container tools
            podman
          ];

          shellHook = ''
            echo "🚢 Wharf Development Environment"
            echo "Run 'just --list' for available commands"
          '';
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "wharf";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
        };

        checks = {
          format = pkgs.runCommand "check-format" {} ''
            cd ${self}
            ${pkgs.rustfmt}/bin/cargo fmt --check
            touch $out
          '';

          lint = pkgs.runCommand "check-lint" {} ''
            cd ${self}
            ${pkgs.clippy}/bin/cargo clippy -- -D warnings
            touch $out
          '';
        };
      }
    );
}
