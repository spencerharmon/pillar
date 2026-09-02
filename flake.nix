{
  # flake.nix — reproducible, infra-agnostic OCI image build for the `pillar`
  # binary (the `pillar node run` entrypoint, see crates/pillar-cli/src/run.rs).
  #
  # SUPERSEDES the former root Dockerfile: the container image is now assembled
  # by nix `dockerTools.streamLayeredImage` from a pinned nixpkgs, so the build
  # is reproducible and carries no compiler/toolchain surface in the shipped
  # image. The flake output is deliberately INFRA-AGNOSTIC — no registry,
  # hostname, tag, or credential is baked in. CI (GitHub Actions for the public
  # mirror, Gitea Actions where the registry creds live) supplies the registry
  # target + push credentials and applies the tag at push time.
  #
  # Outputs:
  #   packages.<system>.pillar           — the pillar binary (crate pillar-cli).
  #   packages.<system>.pillar-oci-image — a streamer script that writes the OCI
  #                                          image tarball to stdout
  #                                          (dockerTools.streamLayeredImage).
  #                                          `nix build .#pillar-oci-image` yields
  #                                          `result`, an executable that emits
  #                                          the image tar to load/push.
  #   packages.<system>.default          — alias of pillar-oci-image.

  description = "pillar node — reproducible OCI image via nix flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Build the workspace `pillar` binary (crate pillar-cli) reproducibly
        # from the vendored Cargo.lock. No network at build time.
        pillar = pkgs.rustPlatform.buildRustPackage {
          pname = "pillar";
          version = "0.0.0";
          src = self;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          # Only the pillar-cli `pillar` binary is shipped in the image.
          cargoBuildFlags = [ "-p" "pillar-cli" "--bin" "pillar" ];
          # Workspace-wide test run is out of scope for the image build; CI's
          # `ci` workflow owns fmt/clippy/test.
          doCheck = false;

          # pillar-cli pulls in pillar-crypto transitively (via pillar-core and
          # friends), whose hardware custody backends link native libraries:
          #   * tpm2-tss      — TpmCustody via tss-esapi (+ tss-esapi-sys bindgen)
          #   * hidapi/libusb — PasskeyCustody via ctap-hid-fido2
          #   * libclang      — bindgen build scripts (tss-esapi-sys, cryptoki-sys)
          # so the reproducible build needs them even though no hardware is
          # exercised at build time (only linked).
          nativeBuildInputs = [ pkgs.pkg-config pkgs.clang ];
          buildInputs = [ pkgs.tpm2-tss pkgs.hidapi pkgs.libusb1 ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          meta = {
            description = "pillar node run entrypoint";
            license = pkgs.lib.licenses.gpl3Plus;
          };
        };

        # Reproducible OCI image. streamLayeredImage produces a script that
        # streams the image tar to stdout — friendlier to CI (no giant store
        # path) and directly loadable/pushable. Image config mirrors the
        # retired Dockerfile's runtime contract (entrypoint + PILLAR_* env
        # defaults matching crates/pillar-cli/src/run.rs).
        pillar-oci-image = pkgs.dockerTools.streamLayeredImage {
          name = "pillar";
          tag = "latest";

          contents = [
            pillar
            pkgs.cacert
          ];

          config = {
            Entrypoint = [ "/bin/pillar" "node" "run" ];
            WorkingDir = "/var/lib/pillar";
            Env = [
              "PILLAR_DATA_DIR=/var/lib/pillar/data"
              "PILLAR_IDENTITY_KEY=/var/lib/pillar/data/identity.key"
              "PILLAR_LISTEN=/ip4/0.0.0.0/tcp/0"
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            ];
          };

          # Ensure the runtime data dir exists in the image.
          extraCommands = ''
            mkdir -p var/lib/pillar/data
          '';
        };
      in
      {
        packages = {
          inherit pillar pillar-oci-image;
          default = pillar-oci-image;
        };

        # Dev shell for CI's fmt/clippy/test (and local dev): the SAME native
        # inputs the reproducible `pillar` build uses, but exposed through
        # mkShell so their `.dev` outputs (headers + pkg-config `.pc` files)
        # are on the compiler / pkg-config search path. A bare nixery `shell`
        # image only carries a package's runtime output, so the bindgen build
        # scripts (tss-esapi-sys, cryptoki-sys) and pkg-config could not find
        # libclang / tss2 headers there; `nix develop` against this shell fixes
        # that reproducibly. The whole Rust toolchain (cargo/rustc/clippy/
        # rustfmt) comes from the flake-pinned nixpkgs, so every lint/test in
        # CI runs on one reproducible toolchain (flake.lock) — no version drift
        # between the formatter that shaped the tree and the one CI checks with.
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.pkg-config
            pkgs.clang
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.git
          ];
          buildInputs = [ pkgs.tpm2-tss pkgs.hidapi pkgs.libusb1 ];
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
      });
}
