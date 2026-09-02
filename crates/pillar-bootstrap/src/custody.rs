//! Per-key custody / encryption choice, applied uniformly to the cell, user,
//! and node keys the bootstrap sequence generates.
//!
//! Every bootstrap surface (CLI flags, the web form) lets the operator pick
//! how each key is held — the same four mechanisms the identity layer already
//! models ([`pillar_identity::CustodyKind`]) — plus free-form operator
//! labels. This is orthogonal to the admission/authority policy: the custody
//! choice only decides *where the private key lives and what unlocks it*, and
//! the identity model verifies the resulting public-key chain regardless.

pub use pillar_identity::login::{
    sign_with_backend, CustodyKind, CustodyRegistry, CustodySignError, FileKeyringBackend,
    PasskeyBackend, PasswordBackend, SignerBackend, TpmBackend,
};

/// The custody choice for a single generated key: which mechanism holds it and
/// the operator labels to attach.
///
/// Used identically for the cell key, the user key, and a node key — the
/// operator may, for example, hold the cell key in a TPM and the user key
/// behind a passkey.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyChoice {
    kind: CustodyKind,
    labels: Vec<String>,
}

impl CustodyChoice {
    /// A custody choice with the given mechanism and no labels.
    #[must_use]
    pub fn new(kind: CustodyKind) -> Self {
        CustodyChoice {
            kind,
            labels: Vec::new(),
        }
    }

    /// The operator-default custody: a password-derived key.
    ///
    /// Password is the interoperable, no-extra-hardware default the operator
    /// asked the CLI to fall back to; the identity layer flags it as NOT
    /// recommended relative to TPM/passkey, which callers may surface.
    #[must_use]
    pub fn password_default() -> Self {
        CustodyChoice::new(CustodyKind::Password)
    }

    /// Attach one label (builder-style). Labels are retained in insertion
    /// order and de-duplicated on read via [`Self::labels`] callers as needed;
    /// here we keep them verbatim so an operator's exact tags round-trip.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Attach several labels (builder-style).
    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.labels.extend(labels.into_iter().map(Into::into));
        self
    }

    /// The custody mechanism.
    #[must_use]
    pub fn kind(&self) -> CustodyKind {
        self.kind
    }

    /// The operator labels attached to this key.
    #[must_use]
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Whether this custody choice is operator-recommended (TPM/passkey/keyring
    /// yes, password no) — a straight passthrough to the identity layer's
    /// recommendation so the CLI/web can warn identically.
    #[must_use]
    pub fn is_recommended(&self) -> bool {
        !matches!(self.kind, CustodyKind::Password)
    }

    /// Build the REAL [`SignerBackend`] this choice names, bound to
    /// `key_id`. This is the wiring point that turns the operator's custody
    /// SELECTION into an actual signer — each [`CustodyKind`] maps onto its
    /// own real trait impl, never a single funneled backend:
    ///
    /// - [`CustodyKind::FileKeyring`] -> [`FileKeyringBackend`] (unlocked —
    ///   bootstrap runs with the freshly generated key already in hand).
    /// - [`CustodyKind::Tpm`] -> [`TpmBackend`], keyed on `key_id` as its
    ///   handle.
    /// - [`CustodyKind::Passkey`] -> [`PasskeyBackend`], `present = true`
    ///   (the authenticator that just performed the bootstrap ceremony).
    /// - [`CustodyKind::Password`] -> [`PasswordBackend`].
    #[must_use]
    pub fn build_backend(&self, key_id: &str) -> Box<dyn SignerBackend> {
        match self.kind {
            CustodyKind::FileKeyring => Box::new(FileKeyringBackend::new(key_id).unlocked()),
            CustodyKind::Tpm => Box::new(TpmBackend::new(key_id)),
            CustodyKind::Passkey => Box::new(PasskeyBackend::new(key_id, true)),
            CustodyKind::Password => Box::new(PasswordBackend::new(key_id)),
        }
    }

    /// Label `key_id` in `registry` for this choice's [`CustodyKind`], then
    /// build the matching backend and sign `challenge` with it through
    /// [`sign_with_backend`] — the same per-key labeled-backend enforcement
    /// path a login flow uses, so bootstrap and login share one custody
    /// contract instead of a bootstrap-only shortcut.
    ///
    /// # Errors
    ///
    /// [`CustodySignError`] if the freshly-labeled, freshly-built backend
    /// nonetheless declines to sign (e.g. a passkey ceremony that failed).
    pub fn label_and_sign(
        &self,
        registry: &mut CustodyRegistry,
        key_id: &str,
        challenge: &str,
    ) -> Result<String, CustodySignError> {
        registry.assign(key_id, self.kind);
        let backend = self.build_backend(key_id);
        sign_with_backend(registry, key_id, backend.as_ref(), challenge)
    }
}

impl Default for CustodyChoice {
    fn default() -> Self {
        // The keyring is the identity layer's default custody; the CLI opts
        // into `password_default()` explicitly where password is the intended
        // fallback.
        CustodyChoice::new(CustodyKind::FileKeyring)
    }
}

/// Parse a custody mechanism from a CLI token (`password` / `passkey` /
/// `tpm` / `keyring`). Returns `None` for an unrecognized value so the caller
/// can print the accepted set.
#[must_use]
pub fn parse_custody_kind(token: &str) -> Option<CustodyKind> {
    match token {
        "password" => Some(CustodyKind::Password),
        "passkey" => Some(CustodyKind::Passkey),
        "tpm" => Some(CustodyKind::Tpm),
        "keyring" | "file-keyring" | "filekeyring" => Some(CustodyKind::FileKeyring),
        _ => None,
    }
}

/// The accepted custody tokens, for help/usage text (kept in one place so the
/// CLI and web help never drift from [`parse_custody_kind`]).
pub const CUSTODY_KINDS_HELP: &str = "password | passkey | tpm | keyring";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_default_is_password_and_not_recommended() {
        let c = CustodyChoice::password_default();
        assert_eq!(c.kind(), CustodyKind::Password);
        assert!(!c.is_recommended());
    }

    #[test]
    fn labels_round_trip_in_order() {
        let c = CustodyChoice::new(CustodyKind::Tpm)
            .with_label("prod")
            .with_labels(["east", "cold"]);
        assert_eq!(c.labels(), &["prod", "east", "cold"]);
        assert!(c.is_recommended());
    }

    #[test]
    fn parse_covers_every_kind_and_rejects_garbage() {
        assert_eq!(parse_custody_kind("password"), Some(CustodyKind::Password));
        assert_eq!(parse_custody_kind("passkey"), Some(CustodyKind::Passkey));
        assert_eq!(parse_custody_kind("tpm"), Some(CustodyKind::Tpm));
        assert_eq!(
            parse_custody_kind("keyring"),
            Some(CustodyKind::FileKeyring)
        );
        assert_eq!(
            parse_custody_kind("file-keyring"),
            Some(CustodyKind::FileKeyring)
        );
        assert_eq!(parse_custody_kind("nope"), None);
    }

    /// Each `CustodyKind` builds its OWN real backend impl — not all
    /// funneling through one — and that backend actually signs.
    #[test]
    fn build_backend_produces_the_matching_real_impl() {
        assert!(CustodyChoice::new(CustodyKind::FileKeyring)
            .build_backend("k")
            .sign_challenge("c")
            .unwrap()
            .starts_with("file-keyring:"));
        assert!(CustodyChoice::new(CustodyKind::Tpm)
            .build_backend("k")
            .sign_challenge("c")
            .unwrap()
            .starts_with("tpm:"));
        assert!(CustodyChoice::new(CustodyKind::Passkey)
            .build_backend("k")
            .sign_challenge("c")
            .unwrap()
            .starts_with("passkey:"));
        assert!(CustodyChoice::new(CustodyKind::Password)
            .build_backend("k")
            .sign_challenge("c")
            .unwrap()
            .starts_with("password:"));
    }

    /// Labeling + signing through the registry actually enforces the label:
    /// a later mismatched backend for the same key is refused.
    #[test]
    fn label_and_sign_labels_the_key_and_a_later_mismatch_is_refused() {
        let mut registry = CustodyRegistry::new();
        let tpm_choice = CustodyChoice::new(CustodyKind::Tpm);
        let sig = tpm_choice
            .label_and_sign(&mut registry, "node-key", "genesis-challenge")
            .expect("tpm backend signs");
        assert!(sig.starts_with("tpm:"));
        assert_eq!(registry.kind_of("node-key"), Some(CustodyKind::Tpm));

        // A different backend for the SAME key id is refused.
        let password = PasswordBackend::new("node-key");
        assert_eq!(
            sign_with_backend(&registry, "node-key", &password, "genesis-challenge"),
            Err(CustodySignError::KindMismatch {
                expected: CustodyKind::Tpm,
                presented: CustodyKind::Password,
            })
        );
    }

    /// Two keys on one principal may carry different labels; each signs only
    /// through its own.
    #[test]
    fn two_keys_different_labels_both_sign_via_label_and_sign() {
        let mut registry = CustodyRegistry::new();
        let node_sig = CustodyChoice::new(CustodyKind::Tpm)
            .label_and_sign(&mut registry, "node-key", "chal")
            .expect("node key signs");
        let user_sig = CustodyChoice::new(CustodyKind::Password)
            .label_and_sign(&mut registry, "user-op-key", "chal")
            .expect("user key signs");
        assert!(node_sig.starts_with("tpm:"));
        assert!(user_sig.starts_with("password:"));
    }
}
