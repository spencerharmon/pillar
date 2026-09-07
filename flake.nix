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
    # Pinned to a specific nixpkgs revision shipping rustc 1.89.0 + LLVM 19.1.7,
    # NOT the floating nixos-unstable ref. nixos-unstable had advanced to
    # rustc 1.97.1 + LLVM 21.1.8, whose ScalarEvolution/LoopIdiomRecognize
    # passes crash rustc with `SIGILL: illegal instruction` under
    # `-C opt-level=3` on an AVX2-only host — an intermittent, run-to-run
    # miscompile that broke `.#pillar-oci-image` (and every consumer that builds
    # a local image-under-test, incl. the pillar-integration scenario harness).
    # This pin picks the newest LLVM-19 nixpkgs whose rustc (1.89.0) still
    # satisfies the workspace's minimum-rustc requirements (aes 0.9 / time 0.3 /
    # ctap-hid-fido2 need >= 1.88/1.89); the older nixos-25.05 release (rustc
    # 1.86.0) is too old. LLVM 19.1.7 compiles the whole workspace cleanly on
    # AVX2, making the OCI image build deterministic again, and a fixed rev (not
    # a floating channel) keeps the toolchain stable across rebuilds. See
    # docs/pillar-oci-image-llvm21-sigill-fix-pillar-oci-image-llvm21-sigill-fix.md.
    nixpkgs.url = "github:NixOS/nixpkgs/5bf69abfad9feaa47ebc5cec0c7dc1029db8fb92";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # ---------------------------------------------------------------------
        # Stage 1 of the two-stage build: compile the Yew + WebAssembly portal
        # (crate pillar-frontend, EXCLUDED from the native workspace) to
        # `wasm32-unknown-unknown` with `trunk`, producing the static asset
        # bundle (wasm/js/css). NO npm/Node is used anywhere — trunk drives
        # cargo + wasm-bindgen, and stylist emits the CSS from Rust. Stage 2
        # (`pillar`, below) embeds `${pillar-frontend}` into the ONE binary via
        # include_bytes! (see crates/pillar-cli/src/web_serve.rs).
        pillar-frontend = pkgs.rustPlatform.buildRustPackage {
          pname = "pillar-frontend";
          version = "0.0.0";
          # Only the frontend crate — its OWN Cargo.lock (own dep closure).
          src = ./crates/pillar-frontend;

          cargoLock = {
            lockFile = ./crates/pillar-frontend/Cargo.lock;
          };

          # trunk (Node-free wasm bundler) + a wasm-bindgen-cli whose version
          # MUST equal the crate's `wasm-bindgen` (0.2.127, pinned in the
          # frontend Cargo.lock) or wasm-bindgen refuses the module.
          nativeBuildInputs = [
            pkgs.trunk
            pkgs.wasm-bindgen-cli
            pkgs.binaryen
            pkgs.lld
          ];

          # nixpkgs rustc ships the wasm32-unknown-unknown std; add the target
          # so cargo (invoked by trunk) can compile to it.
          buildPhase = ''
            runHook preBuild
            export CARGO_HOME=$PWD/.cargo-home
            # Trunk must NOT fetch its own wasm-bindgen/wasm-opt — use the ones
            # from nativeBuildInputs (offline, reproducible).
            trunk build \
              --release \
              --offline \
              --dist $PWD/dist \
              index.html
            runHook postBuild
          '';

          # There is no cargo-test surface for a wasm bundle; the frontend's
          # logic is exercised by the workspace crates that consume its assets.
          doCheck = false;

          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp -r dist/* $out/
            runHook postInstall
          '';

          meta = {
            description = "pillar web portal — Yew + WebAssembly static bundle";
            license = pkgs.lib.licenses.gpl3Plus;
          };
        };

        # Build the workspace `pillar` binary (crate pillar-cli) reproducibly
        # from the vendored Cargo.lock. No network at build time.
        pillar = pkgs.rustPlatform.buildRustPackage {
          pname = "pillar";
          version = "0.0.0";
          src = self;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          # The shipped `pillar` binary (pillar-cli) enables the `hsm` feature so
          # a deployed node carries EVERY popular hardware custody backend
          # (TPM / passkey / PKCS#11). The feature is off in the everyday build
          # (`cargo test --all`, local dev) so that common path skips the bindgen
          # crates and native libs below; the deployed node opts in here.
          cargoBuildFlags = [ "-p" "pillar-cli" "--bin" "pillar" "--features" "hsm" ];
          # Workspace-wide test run is out of scope for the image build; CI's
          # `ci` workflow owns fmt/clippy/test.
          doCheck = false;

          # The `hsm` feature (above) links native libraries for the hardware
          # custody backends in pillar-crypto:
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
          inherit pillar-frontend;
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
