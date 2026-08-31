//! Per-key custody / encryption choice, applied uniformly to the cell, user,
//! and node keys the bootstrap sequence generates.
//!
//! Every bootstrap surface (CLI flags, the web form) lets the operator pick
//! how each key is held — the same four mechanisms the identity layer already
//! models ([`pillar_identity::CustodyKind`]) — plus free-form operator
//! labels. This is orthogonal to the admission/authority policy: the custody
//! choice only decides *where the private key lives and what unlocks it*, and
//! the identity model verifies the resulting public-key chain regardless.

pub use pillar_identity::login::CustodyKind;

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
}
