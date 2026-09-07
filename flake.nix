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
        # crates.io started returning HTTP 403 on the legacy per-crate download
        # endpoint `https://crates.io/api/v1/crates/<name>/<ver>/download` for
        # curl-like User-Agents (an empty UA still 302-redirects; the static CDN
        # `https://static.crates.io/crates/<name>/<name>-<ver>.crate` serves the
        # byte-identical `.crate` with a plain 200). The pinned nixpkgs'
        # `importCargoLock` fetches every non-cached crate via that legacy URL
        # with a curl UA, so any crate NOT already in `cache.nixos.org` (e.g. a
        # freshly published `aes 0.9.3`, pulled by `ctap-hid-fido2`) fails the
        # image build with `error: cannot download crate-<name>.tar.gz`. This
        # overlay rewrites ONLY those legacy crates.io download URLs to the
        # static CDN. The tarball bytes are identical (verified: the static
        # `.crate` sha256 equals the `Cargo.lock` checksum), so every fixed-
        # output hash still validates and already-cached crates still substitute
        # unchanged (an FOD is content-addressed by its output hash + name, not
        # its URL). Independent of the LLVM-19 rustc pin below.
        cratesIoStaticCdnOverlay = final: prev: {
          fetchurl = args:
            if (args ? url)
              && prev.lib.hasPrefix "https://crates.io/api/v1/crates/" (toString args.url)
            then
              let
                parts = prev.lib.splitString "/" (toString args.url);
                # .../api/v1/crates/<name>/<version>/download
                crateName = builtins.elemAt parts 6;
                crateVersion = builtins.elemAt parts 7;
              in
              prev.fetchurl (args // {
                url = "https://static.crates.io/crates/${crateName}/${crateName}-${crateVersion}.crate";
              })
            else prev.fetchurl args;
        };

        pkgs = import nixpkgs {
          inherit system;
          overlays = [ cratesIoStaticCdnOverlay ];
        };

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
          # The frontend crate builds to `wasm32-unknown-unknown` from its OWN
          # Cargo.lock (own dep closure), but it PATH-depends on sibling crates
          # (`pillar-web-frontend`, and through it `pillar-web-api`,
          # `pillar-observability`, `pillar-manifest`, `pillar-crypto`, …), so
          # the build src must contain the whole `crates/` tree, not just
          # `pillar-frontend/`. `sourceRoot` then points cargo/trunk at the
          # frontend crate itself. (Filtered to `crates/` so a change elsewhere
          # in the repo — e.g. docs — does not needlessly bust this build.)
          src = builtins.path {
            path = ./.;
            name = "pillar-src";
            # The sibling path-deps (`pillar-web-frontend`, …) are workspace
            # members that inherit `edition`/`version` from the ROOT workspace
            # manifest, so cargo must see the repo-root `Cargo.toml` above them;
            # `pillar-frontend` stays `exclude`d there and drives its OWN lock.
            # Drop VCS / build detritus so this stays a clean, cache-stable src.
            filter = path: _type:
              let base = baseNameOf path;
              in base != ".git" && base != "target" && base != "result";
          };
          sourceRoot = "pillar-src/crates/pillar-frontend";

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

          # Embed the REAL Yew + WebAssembly portal bundle (stage 1 above) into
          # the one `pillar` binary. `crates/pillar-cli/build.rs` reads this env
          # var and `include_bytes!`s `${pillar-frontend}`'s wasm/js/css/html;
          # WITHOUT it, build.rs silently falls back to the committed
          # `src/frontend_dist/` bundle (only meant for a plain `cargo build`),
          # which is exactly how the deployed image shipped the pre-migration
          # PLACEHOLDER portal instead of the built one. Point it at the
          # freshly-built store path so the image can never embed a stale
          # fallback again.
          PILLAR_FRONTEND_DIST = pillar-frontend;

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
