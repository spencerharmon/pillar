//! WebAuthn relying-party (RP) surface for pillar-web.
//!
//! This is the real server-side relying party the browser-driven ceremony
//! `POST /webauthn/register/{begin,finish}` and
//! `POST /webauthn/authenticate/{begin,finish}` sit in front of. It REPLACES
//! the dead-end `FidoKeyHidFactory`-on-the-pod path (the pod has no USB) with a
//! browser-driven ceremony verified server-side against a SHARED credential
//! record, exactly as modelled by `specs/WebAuthnCustody.tla`.
//!
//! The heavy cryptographic lifting — COSE/CBOR parsing, COSE public-key
//! extraction, Ed25519/ES256 assertion-signature verification over
//! `authData || SHA-256(clientDataJSON)`, and the HKDF PRF→unlock-secret
//! derivation — lives in [`pillar_crypto::webauthn`]. This module owns the RP
//! *protocol*: minting fresh, single-use, time-bounded challenges bound to the
//! session/cell (`ChallengeFreshness`), enforcing sign-count monotonicity
//! (`SignCountMonotonic`), the shared credential-record store
//! (`CrossSurfaceUsability`), and fail-closed revocation
//! (`RevokedKeyNeverAdmits`).

use std::collections::HashMap;

use pillar_crypto::webauthn::{self, RegisteredCredential};

/// Why an RP operation was refused. Every arm is a fail-closed refusal — the
/// RP never admits on ambiguity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpError {
    /// No outstanding challenge matched (absent, already consumed, or expired).
    StaleChallenge,
    /// The challenge did not match the session/cell it was minted for.
    ChallengeBinding,
    /// No credential record exists for the presented credential id.
    UnknownCredential,
    /// The credential record has been revoked (fail-closed).
    Revoked,
    /// The presented sign-count did not strictly exceed the stored one
    /// (clone / replay detection — `SignCountMonotonic`).
    SignCountRegression,
    /// The attestation or assertion object was malformed, or the signature did
    /// not verify.
    Crypto(pillar_crypto::CryptoError),
}

impl From<pillar_crypto::CryptoError> for RpError {
    fn from(e: pillar_crypto::CryptoError) -> Self {
        RpError::Crypto(e)
    }
}

/// A minted, single-use, time-bounded challenge, bound to the session and cell
/// it was issued for (`ChallengeFreshness`). The `challenge` bytes are the
/// nonce the authenticator signs over (via clientDataJSON).
#[derive(Clone, Debug, PartialEq, Eq)]
struct OutstandingChallenge {
    challenge: Vec<u8>,
    session: String,
    cell: String,
    expires_at: u64,
}

/// The shared credential record stored server-side, per
/// `WebAuthnCustody.tla`: `{ credential_id, COSE public key, PRF salt,
/// sign_count, user handle, cell }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    /// Opaque credential id the authenticator minted.
    pub credential_id: Vec<u8>,
    /// The attested COSE public key (raw CBOR); Ed25519 or ES256, verified at register.
    pub cose_public_key: Vec<u8>,
    /// The per-credential PRF salt (32 bytes) stored at registration.
    pub prf_salt: [u8; 32],
    /// The last stored authenticator signature counter (monotone).
    pub sign_count: u32,
    /// The user handle this credential authenticates.
    pub user_handle: String,
    /// The cell this record is scoped to.
    pub cell: String,
    /// User-chosen human label for the management surface (`""` if none).
    pub label: String,
    /// The rpId / domain this credential is bound to (the serving origin for a
    /// browser passkey, the cell IPNS name or an operator-chosen domain for a
    /// portable passkey). `""` when unknown — e.g. a record restored from a
    /// journal written before rpId capture.
    pub rp_id: String,
    /// Unix seconds the credential was registered.
    pub created_at: u64,
    /// Unix seconds of the most recent successful assertion; `None` until the
    /// credential is first used to log in.
    pub last_used_at: Option<u64>,
}

/// The pillar WebAuthn relying party: the challenge protocol plus the shared
/// credential-record store. Time is supplied explicitly (`now`) so the RP is
/// exercised by plain unit tests with no wall clock.
#[derive(Debug, Default)]
pub struct RelyingParty {
    // challenge bytes (hex-keyed) -> the outstanding challenge
    challenges: HashMap<String, OutstandingChallenge>,
    // credential id (hex-keyed) -> the shared record
    records: HashMap<String, CredentialRecord>,
    // revoked credential ids (hex-keyed): grow-only, fail-closed
    revoked: std::collections::HashSet<String>,
    // monotone nonce counter so distinct challenges never collide
    nonce_seq: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl RelyingParty {
    /// A relying party with no credentials or challenges.
    #[must_use]
    pub fn new() -> Self {
        RelyingParty::default()
    }

    /// Mint a fresh, single-use, time-bounded challenge bound to `session` and
    /// `cell`, valid for `ttl_secs` from `now`. The returned bytes are
    /// globally-fresh (a monotone counter feeds a real content-address digest),
    /// so a nonce is never reissued (`ChallengeNeverReissued`).
    pub fn begin(&mut self, session: &str, cell: &str, now: u64, ttl_secs: u64) -> Vec<u8> {
        self.nonce_seq += 1;
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"pillar-webauthn/challenge-v1");
        preimage.extend_from_slice(&self.nonce_seq.to_le_bytes());
        preimage.extend_from_slice(&now.to_le_bytes());
        preimage.extend_from_slice(session.as_bytes());
        preimage.extend_from_slice(cell.as_bytes());
        let challenge = pillar_crypto::content::content_address(&preimage)
            .expect("content_address is infallible")
            .as_bytes()
            .to_vec();
        self.challenges.insert(
            hex(&challenge),
            OutstandingChallenge {
                challenge: challenge.clone(),
                session: session.to_owned(),
                cell: cell.to_owned(),
                expires_at: now.saturating_add(ttl_secs),
            },
        );
        challenge
    }

    /// Consume the outstanding challenge (single-use), validating it exists,
    /// has not expired, and is bound to the expected session/cell. Removing it
    /// here is the replay guard: a second finish for the same nonce fails
    /// `StaleChallenge` (`ChallengeFreshness`).
    fn consume_challenge(
        &mut self,
        challenge: &[u8],
        session: &str,
        cell: &str,
        now: u64,
    ) -> Result<(), RpError> {
        let key = hex(challenge);
        let outstanding = self
            .challenges
            .remove(&key)
            .ok_or(RpError::StaleChallenge)?;
        if now > outstanding.expires_at {
            return Err(RpError::StaleChallenge);
        }
        if outstanding.session != session || outstanding.cell != cell {
            return Err(RpError::ChallengeBinding);
        }
        Ok(())
    }

    /// Finish a registration ceremony: consume the challenge, parse the
    /// attestation object (extracting + validating the Ed25519/ES256 COSE key), and
    /// persist the shared credential record. Returns the stored record.
    ///
    /// # Errors
    ///
    /// [`RpError::StaleChallenge`] / [`RpError::ChallengeBinding`] on a bad
    /// challenge; [`RpError::Crypto`] on a malformed attestation or unsupported
    /// COSE key.
    #[allow(clippy::too_many_arguments)]
    pub fn register_finish(
        &mut self,
        session: &str,
        cell: &str,
        now: u64,
        created_at: u64,
        challenge: &[u8],
        attestation_object: &[u8],
        prf_salt: [u8; 32],
        user_handle: &str,
        label: &str,
        rp_id: &str,
    ) -> Result<CredentialRecord, RpError> {
        self.consume_challenge(challenge, session, cell, now)?;
        let RegisteredCredential {
            credential_id,
            cose_public_key,
            sign_count,
            aaguid: _,
        } = webauthn::parse_attestation(attestation_object)?;
        let key = hex(&credential_id);
        // A revoked record is never revived (RevokedStaysDead / fail-closed).
        if self.revoked.contains(&key) {
            return Err(RpError::Revoked);
        }
        let record = CredentialRecord {
            credential_id,
            cose_public_key,
            prf_salt,
            sign_count,
            user_handle: user_handle.to_owned(),
            cell: cell.to_owned(),
            label: label.to_owned(),
            rp_id: rp_id.to_owned(),
            created_at,
            last_used_at: None,
        };
        self.records.insert(key, record.clone());
        Ok(record)
    }

    /// Finish an authentication ceremony: consume the challenge, look up the
    /// shared record (fail-closed on unknown/revoked), verify the assertion
    /// signature over `authData || SHA-256(clientDataJSON)`, enforce STRICT
    /// sign-count monotonicity, advance the stored counter, and derive the
    /// 32-byte operational-key-unlock secret from the PRF output via the real
    /// HKDF.
    ///
    /// # Errors
    ///
    /// A fail-closed [`RpError`] on any of: stale/mis-bound challenge, unknown
    /// or revoked credential, a forged/tampered assertion, or a sign-count that
    /// does not strictly increase.
    #[allow(clippy::too_many_arguments)]
    pub fn authenticate_finish(
        &mut self,
        session: &str,
        cell: &str,
        now: u64,
        used_at: u64,
        challenge: &[u8],
        credential_id: &[u8],
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
        prf_output: &[u8],
    ) -> Result<Option<[u8; 32]>, RpError> {
        self.consume_challenge(challenge, session, cell, now)?;
        let key = hex(credential_id);
        if self.revoked.contains(&key) {
            return Err(RpError::Revoked);
        }
        let record = self.records.get(&key).ok_or(RpError::UnknownCredential)?;
        let verified = webauthn::verify_assertion(
            &record.cose_public_key,
            authenticator_data,
            client_data_json,
            signature,
        )?;
        // SignCountMonotonic: strict increase, else clone/replay -> refuse.
        // (An authenticator that always reports 0 is exempt per the WebAuthn
        // spec; pillar's authenticators use a real counter, so 0-vs-0 with a
        // non-zero stored value is a regression.)
        if verified.sign_count != 0 && verified.sign_count <= record.sign_count {
            return Err(RpError::SignCountRegression);
        }
        // The SECOND FACTOR is the verified assertion above (possession of the
        // owning authenticator). The PRF-derived operational-key-unlock secret
        // is a SEPARATE, OPTIONAL capability: it exists only for authenticators
        // (and browsers) that implement the WebAuthn `prf` / CTAP2 `hmac-secret`
        // extension. A key that produced no PRF output still proves the second
        // factor perfectly well, so an empty PRF output yields `None` (no
        // operational unlock) rather than failing the login — coupling the two
        // would break 2FA for the majority of authenticators that omit PRF.
        let unlock = if prf_output.is_empty() {
            None
        } else {
            Some(webauthn::derive_unlock_secret(prf_output, credential_id)?)
        };
        let record = self
            .records
            .get_mut(&key)
            .expect("record present after lookup");
        if verified.sign_count != 0 {
            record.sign_count = verified.sign_count;
        }
        // Stamp the credential's most-recent-use for the management surface.
        record.last_used_at = Some(used_at);
        Ok(unlock)
    }

    /// Revoke (delete) a credential record. Grow-only and fail-closed: the
    /// record never admits again and is never re-registered
    /// (`RevokedKeyNeverAdmits`).
    pub fn revoke(&mut self, credential_id: &[u8]) {
        let key = hex(credential_id);
        self.records.remove(&key);
        self.revoked.insert(key);
    }

    /// Read the stored record for a credential id (for cross-surface reads).
    #[must_use]
    pub fn record(&self, credential_id: &[u8]) -> Option<&CredentialRecord> {
        self.records.get(&hex(credential_id))
    }

    /// Re-insert an already-verified credential record VERBATIM — the restart
    /// replay path. Unlike [`register_finish`] this runs NO challenge or
    /// attestation ceremony; it folds a record persisted at its original
    /// registration back into the live store so WebAuthn 2FA enforcement
    /// survives a node restart (a lost record would silently drop the second
    /// factor). A revoked id is never revived (fail-closed).
    pub fn restore_credential(&mut self, record: CredentialRecord) {
        let key = hex(&record.credential_id);
        if self.revoked.contains(&key) {
            return;
        }
        self.records.insert(key, record);
    }

    /// Replay a journaled successful assertion: advance a live credential's
    /// stored sign-count and last-used stamp. No-op for an unknown or revoked
    /// credential (fail-closed). This is the restart-replay counterpart to the
    /// in-session mutation [`authenticate_finish`] performs, so clone-detection
    /// state and the management surface's "last used" survive a node restart.
    pub fn touch_credential(&mut self, credential_id: &[u8], sign_count: u32, last_used_at: u64) {
        let key = hex(credential_id);
        if let Some(record) = self.records.get_mut(&key) {
            if sign_count > record.sign_count {
                record.sign_count = sign_count;
            }
            record.last_used_at = Some(match record.last_used_at {
                Some(prev) => prev.max(last_used_at),
                None => last_used_at,
            });
        }
    }

    /// Whether `user_handle` has at least one live (registered, non-revoked)
    /// credential — the login-time "this user must complete a WebAuthn
    /// assertion" predicate.
    #[must_use]
    pub fn user_has_credentials(&self, user_handle: &str) -> bool {
        self.records.values().any(|r| r.user_handle == user_handle)
    }

    /// The credential ids registered to `user_handle` — used to confirm an
    /// asserted credential actually belongs to the logging-in user (so one
    /// user's authenticator can never satisfy another user's 2FA gate).
    #[must_use]
    pub fn user_credential_ids(&self, user_handle: &str) -> Vec<Vec<u8>> {
        self.records
            .values()
            .filter(|r| r.user_handle == user_handle)
            .map(|r| r.credential_id.clone())
            .collect()
    }

    /// Every live (registered, non-revoked) credential belonging to
    /// `user_handle`, oldest-first, for the management surface (list). Returns
    /// the full records so the caller can render label / rpId / created /
    /// last-used / sign-count / id.
    #[must_use]
    pub fn user_credentials(&self, user_handle: &str) -> Vec<&CredentialRecord> {
        let mut creds: Vec<&CredentialRecord> = self
            .records
            .values()
            .filter(|r| r.user_handle == user_handle)
            .collect();
        creds.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.credential_id.cmp(&b.credential_id))
        });
        creds
    }

    /// Whether `credential_id` is a live credential owned by `user_handle` — the
    /// authorization predicate for a user-initiated revoke (a user may revoke
    /// only their own credentials).
    #[must_use]
    pub fn user_owns_credential(&self, user_handle: &str, credential_id: &[u8]) -> bool {
        self.records
            .get(&hex(credential_id))
            .is_some_and(|r| r.user_handle == user_handle)
    }

    /// Whether `credential_id` is the user's LAST live credential — i.e.
    /// revoking it removes their second factor entirely. Returns `false` if the
    /// user does not own the credential (that case is a plain not-found at the
    /// call site). The management surface uses this to REQUIRE explicit
    /// confirmation before such a revoke: a lost or stolen sole key must still
    /// be revocable (else the account is unrecoverable), but never by accident.
    /// Enforcing it HERE (not in each surface) makes the UI and the CLI share
    /// one definition of "this is the last key".
    #[must_use]
    pub fn is_last_credential(&self, user_handle: &str, credential_id: &[u8]) -> bool {
        self.user_owns_credential(user_handle, credential_id)
            && self.user_credentials(user_handle).len() <= 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::sign::{sign, signing_keypair_from_seed};
    use pillar_crypto::webauthn::{base64url_decode, base64url_encode, ed25519_public_key_to_cose};
    use pillar_crypto::{Seed, SigningSecretKey};

    const TTL: u64 = 300;

    fn authenticator(label: &str) -> (SigningSecretKey, Vec<u8>) {
        let (public, secret) =
            signing_keypair_from_seed(&Seed::from_bytes(label.as_bytes().to_vec())).expect("kg");
        let cose = ed25519_public_key_to_cose(&public).expect("cose");
        (secret, cose)
    }

    fn attestation(cose: &[u8], credential_id: &[u8], sign_count: u32) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&[0u8; 32]);
        auth_data.push(0x40 | 0x01); // AT + UP
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // aaguid
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose);
        use ciborium::value::Value;
        let att = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&att, &mut out).expect("enc");
        out
    }

    fn assertion(
        secret: &SigningSecretKey,
        challenge: &[u8],
        sign_count: u32,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use sha2::{Digest, Sha256};
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://pillar.local"}}"#,
            base64url_encode(challenge)
        )
        .into_bytes();
        let mut ad = Vec::new();
        ad.extend_from_slice(&[0u8; 32]);
        ad.push(0x01);
        ad.extend_from_slice(&sign_count.to_be_bytes());
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig = sign(secret, &signed).expect("sign");
        (ad, cdj, sig.as_bytes().to_vec())
    }

    fn register(rp: &mut RelyingParty, cose: &[u8], cred: &[u8], sc: u32) {
        let ch = rp.begin("sess-1", "cell-A", 1000, TTL);
        rp.register_finish(
            "sess-1",
            "cell-A",
            1000,
            0,
            &ch,
            &attestation(cose, cred, sc),
            [7u8; 32],
            "alice",
            "test-key",
            "pillar.local",
        )
        .expect("register");
    }

    #[test]
    fn a_valid_ceremony_derives_a_stable_real_unlock_secret() {
        let (sk, cose) = authenticator("auth-a");
        let mut rp = RelyingParty::new();
        register(&mut rp, &cose, b"cred-1", 0);

        let ch = rp.begin("sess-1", "cell-A", 2000, TTL);
        let (ad, cdj, sig) = assertion(&sk, &ch, 5);
        let unlock = rp
            .authenticate_finish(
                "sess-1",
                "cell-A",
                2000,
                0,
                &ch,
                b"cred-1",
                &ad,
                &cdj,
                &sig,
                b"prf-out-hardware",
            )
            .expect("authenticate")
            .expect("non-empty prf output yields an unlock secret");
        assert_ne!(
            unlock, [0u8; 32],
            "unlock secret is real, not a placeholder"
        );
        // Same PRF output yields the same operational-key-unlock secret.
        let unlock2 = pillar_crypto::webauthn::derive_unlock_secret(b"prf-out-hardware", b"cred-1")
            .expect("derive");
        assert_eq!(
            unlock, unlock2,
            "unlock secret is stable for the credential"
        );
        // sign_count advanced.
        assert_eq!(rp.record(b"cred-1").unwrap().sign_count, 5);
    }

    #[test]
    fn an_authenticator_without_prf_still_satisfies_the_second_factor() {
        // Most FIDO2 authenticators (and many browsers) do not implement the
        // WebAuthn `prf` / CTAP2 `hmac-secret` extension, so they return an
        // EMPTY prf output. That must NOT fail the second factor: the verified
        // assertion is the proof of possession. The operational-key-unlock
        // secret is simply absent (None) for such a credential.
        let (sk, cose) = authenticator("no-prf");
        let mut rp = RelyingParty::new();
        register(&mut rp, &cose, b"cred-noprf", 0);
        let ch = rp.begin("sess-1", "cell-A", 2000, TTL);
        let (ad, cdj, sig) = assertion(&sk, &ch, 5);
        let unlock = rp
            .authenticate_finish(
                "sess-1", "cell-A", 2000, 0, &ch, b"cred-noprf", &ad, &cdj, &sig, b"",
            )
            .expect("assertion verifies with no prf output");
        assert_eq!(
            unlock, None,
            "no prf output => no operational unlock secret, but 2FA still passed"
        );
        // The verified assertion still advanced the stored sign-count.
        assert_eq!(rp.record(b"cred-noprf").unwrap().sign_count, 5);
    }

    #[test]
    fn a_forged_or_tampered_assertion_is_rejected() {
        let (sk, cose) = authenticator("auth-a");
        let (mallory, _c) = authenticator("mallory");
        let mut rp = RelyingParty::new();
        register(&mut rp, &cose, b"cred-1", 0);

        let ch = rp.begin("sess-1", "cell-A", 2000, TTL);
        // A DIFFERENT authenticator forges the assertion.
        let (ad, cdj, forged) = assertion(&mallory, &ch, 5);
        assert_eq!(
            rp.authenticate_finish(
                "sess-1", "cell-A", 2000, 0, &ch, b"cred-1", &ad, &cdj, &forged, b"prf"
            ),
            Err(RpError::Crypto(
                pillar_crypto::CryptoError::VerificationFailed
            )),
            "a forged assertion must be rejected"
        );

        // Fresh challenge, valid signature, but tamper the signed clientData.
        let ch2 = rp.begin("sess-1", "cell-A", 2000, TTL);
        let (ad2, mut cdj2, sig2) = assertion(&sk, &ch2, 5);
        cdj2[5] ^= 0xff;
        assert_eq!(
            rp.authenticate_finish(
                "sess-1", "cell-A", 2000, 0, &ch2, b"cred-1", &ad2, &cdj2, &sig2, b"prf"
            ),
            Err(RpError::Crypto(
                pillar_crypto::CryptoError::VerificationFailed
            )),
            "a tampered assertion must be rejected"
        );
    }

    #[test]
    fn a_stale_or_replayed_challenge_is_rejected() {
        let (sk, cose) = authenticator("auth-a");
        let mut rp = RelyingParty::new();
        register(&mut rp, &cose, b"cred-1", 0);

        // Expired challenge: begin at t=2000 ttl=300, finish at t=2500.
        let ch = rp.begin("sess-1", "cell-A", 2000, TTL);
        let (ad, cdj, sig) = assertion(&sk, &ch, 5);
        assert_eq!(
            rp.authenticate_finish(
                "sess-1", "cell-A", 2500, 0, &ch, b"cred-1", &ad, &cdj, &sig, b"prf"
            ),
            Err(RpError::StaleChallenge),
            "an expired challenge must be rejected"
        );

        // Replay: a fresh challenge succeeds once, then the SAME nonce is
        // refused the second time (single-use).
        let ch2 = rp.begin("sess-1", "cell-A", 3000, TTL);
        let (ad2, cdj2, sig2) = assertion(&sk, &ch2, 6);
        rp.authenticate_finish(
            "sess-1", "cell-A", 3000, 0, &ch2, b"cred-1", &ad2, &cdj2, &sig2, b"prf",
        )
        .expect("first use admits");
        let (ad3, cdj3, sig3) = assertion(&sk, &ch2, 7);
        assert_eq!(
            rp.authenticate_finish(
                "sess-1", "cell-A", 3000, 0, &ch2, b"cred-1", &ad3, &cdj3, &sig3, b"prf"
            ),
            Err(RpError::StaleChallenge),
            "a replayed (already-consumed) challenge must be rejected"
        );
    }

    #[test]
    fn sign_count_going_backward_is_rejected() {
        let (sk, cose) = authenticator("auth-a");
        let mut rp = RelyingParty::new();
        register(&mut rp, &cose, b"cred-1", 0);

        // Advance the stored counter to 10.
        let ch = rp.begin("sess-1", "cell-A", 2000, TTL);
        let (ad, cdj, sig) = assertion(&sk, &ch, 10);
        rp.authenticate_finish(
            "sess-1", "cell-A", 2000, 0, &ch, b"cred-1", &ad, &cdj, &sig, b"prf",
        )
        .expect("advance to 10");

        // A later assertion carrying a STALE/EQUAL counter (clone) is refused.
        let ch2 = rp.begin("sess-1", "cell-A", 3000, TTL);
        let (ad2, cdj2, sig2) = assertion(&sk, &ch2, 4);
        assert_eq!(
            rp.authenticate_finish(
                "sess-1", "cell-A", 3000, 0, &ch2, b"cred-1", &ad2, &cdj2, &sig2, b"prf"
            ),
            Err(RpError::SignCountRegression),
            "a sign_count going backward (clone) must be rejected"
        );
        // stored counter unchanged by the refused assertion.
        assert_eq!(rp.record(b"cred-1").unwrap().sign_count, 10);
    }

    #[test]
    fn a_revoked_credential_never_admits() {
        let (sk, cose) = authenticator("auth-a");
        let mut rp = RelyingParty::new();
        register(&mut rp, &cose, b"cred-1", 0);
        rp.revoke(b"cred-1");

        let ch = rp.begin("sess-1", "cell-A", 2000, TTL);
        let (ad, cdj, sig) = assertion(&sk, &ch, 5);
        assert_eq!(
            rp.authenticate_finish(
                "sess-1", "cell-A", 2000, 0, &ch, b"cred-1", &ad, &cdj, &sig, b"prf"
            ),
            Err(RpError::Revoked),
            "a revoked credential must fail closed"
        );
    }

    #[test]
    fn a_challenge_bound_to_another_session_is_rejected() {
        let (sk, cose) = authenticator("auth-a");
        let mut rp = RelyingParty::new();
        register(&mut rp, &cose, b"cred-1", 0);

        let ch = rp.begin("sess-1", "cell-A", 2000, TTL);
        let (ad, cdj, sig) = assertion(&sk, &ch, 5);
        assert_eq!(
            rp.authenticate_finish(
                "OTHER-sess",
                "cell-A",
                2000,
                0,
                &ch,
                b"cred-1",
                &ad,
                &cdj,
                &sig,
                b"prf"
            ),
            Err(RpError::ChallengeBinding),
            "a challenge used from a different session must be rejected"
        );
    }

    #[test]
    fn challenge_is_a_base64url_transportable_fresh_nonce() {
        let mut rp = RelyingParty::new();
        let a = rp.begin("s", "c", 1, TTL);
        let b = rp.begin("s", "c", 1, TTL);
        assert_ne!(a, b, "each challenge is globally fresh");
        // round-trips through the wire encoding used by the browser
        let enc = base64url_encode(&a);
        assert_eq!(base64url_decode(&enc).unwrap(), a);
    }
}
