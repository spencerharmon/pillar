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
    # Pinned to a specific nixpkgs revision shipping rustc 1.91.1, NOT the
    # floating nixos-unstable ref. Two distinct toolchain miscompiles bound the
    # acceptable window on this AVX2 host, and 1.91.1 is the release that clears
    # BOTH:
    #   * TOO NEW — nixos-unstable had advanced to rustc 1.97.1 + LLVM 21.1.8,
    #     whose ScalarEvolution/LoopIdiomRecognize passes crash rustc with
    #     `SIGILL: illegal instruction` under `-C opt-level=3` on an AVX2-only
    #     host — an intermittent, run-to-run miscompile that broke
    #     `.#pillar-oci-image` (and every consumer that builds a local
    #     image-under-test, incl. the pillar-integration scenario harness). See
    #     docs/pillar-oci-image-llvm21-sigill-fix-pillar-oci-image-llvm21-sigill-fix.md.
    #   * TOO OLD — the former pin (rustc 1.89.0 + LLVM 19.1.7,
    #     5bf69abfad9feaa47ebc5cec0c7dc1029db8fb92) was chosen to dodge that
    #     SIGILL, but rustc 1.89.0's OWN binary SIGSEGVs (signal 11, in the
    #     `mir_built`/`check_call_recursion` MIR frontend) compiling
    #     `proc-macro2` 1.0.107 on this host — a 100%-deterministic, stack-size-
    #     independent (unaffected by RUST_MIN_STACK up to 1 GiB) compiler crash
    #     that blocked EVERY workspace build (native `.#pillar` and the wasm
    #     `pillar-frontend` stage of `.#pillar-oci-image` alike). See
    #     docs/pillar-oci-image-frontend-wasm-stack-fix-... in the beehive layer.
    # nixos-25.11 (rustc 1.91.1) compiles `proc-macro2` cleanly (verified:
    # rustc 1.91.1 builds the exact 1.0.107 lib.rs to exit 0 where 1.89.0
    # SIGSEGVs 15/15) AND its LLVM predates the 21.x SIGILL — BUT its rustc
    # BINARY deterministically SIGSEGVs at process startup (a crash in the
    # dynamic linker's `_dl_relocate_object`, before rustc's own `main`) on
    # ANY info-query invocation `rustc -vV` / `rustc --version` (20/20 on this
    # AVX2 host). A plain `cargo build` never hits that path, so `.#pillar`'s
    # cargoBuildHook survives — but the `pillar-frontend` wasm stage drives
    # `trunk`, whose `cargo metadata` MUST run `rustc -vV` to detect the host,
    # and it crashes there, failing `.#pillar-oci-image` (and every
    # image-under-test the pillar-integration harness builds). See
    # docs/bee-flake-image-build-cargo-auditable-fix-flake-image-build-cargo-auditable-fix.md
    # in the beehive layer.
    #   rustc 1.86.0 (nixos-25.05) clears the `rustc -vV` crash and the SIGILL
    # but is TOO OLD for the flake's from-source `wasm-bindgen-cli` 0.2.121
    # (its `time` 0.3.47 dep requires rustc >= 1.88.0).
    #   nixos-unstable @ 140145fe (rustc 1.90.0 + LLVM 20) is the release that
    # clears ALL FOUR traps on this host, each re-verified here:
    #   * `rustc -vV` runs clean 8/8 (no startup SIGSEGV);
    #   * it compiles `proc-macro2` 1.0.107 at `-C opt-level=3` with no crash
    #     (only ordinary unresolved-dep errors, exit 1 — never signal 11);
    #   * LLVM 20 predates the 21.x ScalarEvolution SIGILL;
    #   * >= 1.88.0, so the from-source `wasm-bindgen-cli` builds.
    # cargo-auditable in this rev is still 0.6.5 (the version whose rustc
    # wrapper panics on this toolchain), so the `buildRustPackage` derivations
    # below disable it with `auditable = false;`.
    # A fixed rev (not a floating channel) keeps the toolchain stable across
    # rebuilds.
    nixpkgs.url = "github:NixOS/nixpkgs/140145fe45eedd76f30ad311a2623ca996ed706b";
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

        # Single source of truth for the release version: the workspace's
        # `[workspace.package].version` in Cargo.toml (also the tag build-image
        # stamps on the OCI image and what the binary reports as
        # CARGO_PKG_VERSION). Read it here so the nix derivation names never
        # drift from the crate version on a bump.
        cargoVersion =
          (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;

        # trunk's offline wasm-bindgen step must run the EXACT `wasm-bindgen-cli`
        # version matching the frontend crate's `wasm-bindgen` library
        # (=0.2.121, lockstep with web-sys/js-sys 0.3.98). The pinned nixpkgs
        # ships `wasm-bindgen-cli` 0.2.100 (paired with the older web-sys 0.3.77,
        # which lacks the WebAuthn bindings the portal uses), so build 0.2.121
        # from its crates.io source, vendoring its deps from its OWN bundled
        # Cargo.lock (fetched through the static-CDN overlay above). Verified the
        # crate's fetchCrate hash locally.
        wasmBindgenCliSrc = pkgs.fetchCrate {
          pname = "wasm-bindgen-cli";
          version = "0.2.121";
          hash = "sha256-ZOMgFNOcGkO66Jz/Z83eoIu+DIzo3Z/vq6Z5g6BDY/w=";
        };
        wasmBindgenCli = pkgs.wasm-bindgen-cli.overrideAttrs (_: {
          version = "0.2.121";
          src = wasmBindgenCliSrc;
          cargoDeps = pkgs.rustPlatform.importCargoLock {
            lockFile = "${wasmBindgenCliSrc}/Cargo.lock";
          };
        });

        # ---------------------------------------------------------------------
        # Stage 1 of the two-stage build: compile the Yew + WebAssembly portal
        # (crate pillar-frontend, a WORKSPACE MEMBER whose `start()` entrypoint
        # is `wasm32`-gated) to `wasm32-unknown-unknown` with `trunk`, producing
        # the static asset bundle (wasm/js/css). NO npm/Node is used anywhere —
        # trunk drives cargo + wasm-bindgen, and stylist emits the CSS from
        # Rust. Stage 2 (`pillar`, below) embeds `${pillar-frontend}` into the
        # ONE binary via include_bytes! (see crates/pillar-cli/src/web_serve.rs).
        pillar-frontend = pkgs.rustPlatform.buildRustPackage {
          pname = "pillar-frontend";
          version = cargoVersion;
          # Disable the cargo-auditable rustc wrapper: nixpkgs' pinned
          # cargo-auditable 0.6.5 panics (Option::unwrap on None at
          # cargo-auditable/src/rustc_wrapper.rs:109) against the pinned rustc
          # 1.98 — a known <0.6.6 incompatibility. The audit SBOM metadata it
          # embeds is not required for the reproducible image; turning it off
          # keeps the image contents otherwise identical.
          auditable = false;
          # Stamp the exact build commit into the UI footer. The frontend build
          # `src` (below) strips `.git` and the nix sandbox has no `git`, so the
          # commit cannot be read from the tree at build time — hand it in from
          # the flake's own source rev. `crates/pillar-web-frontend/build.rs`
          # reads this and re-emits it as the `PILLAR_GIT_SHA` compile env the
          # footer renders. `self.rev` is the clean-checkout commit (the CI
          # image + frontend-bundle builds both run from a fresh detached
          # checkout, so it is always set); a dirty local `nix build` falls back
          # to `self.dirtyRev` (`<sha>-dirty`) so the stamp stays honest and
          # never blank. If somehow neither is available build.rs fails loudly
          # rather than ship a placeholder sha.
          PILLAR_GIT_SHA = self.rev or self.dirtyRev or "";
          # pillar-frontend is a workspace member (so its host-native DoD is
          # `-p`-addressable from the repo root) and PATH-depends on sibling
          # members (`pillar-web-frontend`, and through it `pillar-web-api`,
          # `pillar-observability`, `pillar-manifest`, `pillar-crypto`, …), so
          # the build src is the whole repo. cargo/trunk are run from the
          # frontend crate dir in the build phase, but resolve against the ROOT
          # workspace `Cargo.toml`/`Cargo.lock` (one shared lockfile now — it
          # already pins this crate's whole closure: yew 0.21, wasm-bindgen
          # 0.2.121, gloo-net, stylist). The crate-scoped
          # `crates/pillar-frontend/.cargo/config.toml` still supplies the
          # `--cfg getrandom_backend="wasm_js"` wasm rustflag when cargo runs
          # from that dir.
          src = builtins.path {
            path = ./.;
            name = "pillar-src";
            # Drop VCS / build detritus so this stays a clean, cache-stable src.
            filter = path: _type:
              let base = baseNameOf path;
              in base != ".git" && base != "target" && base != "result";
          };

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          # trunk (Node-free wasm bundler) + a wasm-bindgen-cli whose version
          # MUST equal the crate's `wasm-bindgen` (=0.2.121, pinned in the root
          # Cargo.lock) or wasm-bindgen refuses the module. The pinned nixpkgs
          # ships 0.2.100, so `wasmBindgenCli` (above) builds 0.2.121.
          nativeBuildInputs = [
            pkgs.trunk
            wasmBindgenCli
            pkgs.binaryen
            pkgs.lld
          ];

          # nixpkgs rustc ships the wasm32-unknown-unknown std; add the target
          # so cargo (invoked by trunk) can compile to it. Run trunk from the
          # frontend crate dir (its index.html/Trunk.toml live there) while
          # cargo resolves the root workspace + shared Cargo.lock above it.
          buildPhase = ''
            runHook preBuild
            export CARGO_HOME=$PWD/.cargo-home
            cd crates/pillar-frontend
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
          # logic is exercised by the workspace crates that consume its assets
          # (and its host-native `--features acceptance` suite under `cargo
          # test`).
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
          version = cargoVersion;
          src = self;

          # Same cargo-auditable 0.6.5 rustc-wrapper panic as pillar-frontend
          # above; disable the auditable SBOM wrapper on the pinned toolchain.
          auditable = false;

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
            # `lld` is the wasm32 linker the nixpkgs rustc needs to build
            # `pillar-frontend` for `wasm32-unknown-unknown`. The frontend
            # PACKAGE build already carries it (nativeBuildInputs above); the
            # devShell needs it too because the `rust` CI lane's `cargo test
            # --all` includes portal tests that shell out to `cargo build
            # --target wasm32-unknown-unknown` at test time. Without it those
            # tests fail with `linker \`lld\` not found`.
            pkgs.lld
          ];
          buildInputs = [ pkgs.tpm2-tss pkgs.hidapi pkgs.libusb1 ];
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
      });
}
