//! `pillar secrets-audit-rotation-mfa`: drives the ROI's
//! `pillar-integration` "secrets/audit/rotation/mfa" scenario as one real,
//! cross-crate CLI invocation — the same non-networked, in-process rig
//! pattern as [`crate::onboard`] (`onboard.rs`), but exercising the sealed-
//! secret-store escrow, the signed audit-log view, key rotation, and
//! step-up-gated MFA recovery.
//!
//! Every step prints one `ok: <step>` line on success; any step that
//! observes a violated invariant prints `FAIL: <step>: <why>` and the whole
//! command exits non-zero, so the pillar-integration harness's
//! `secrets-audit-rotation-mfa` scenario (`scripts/pillar-integration/
//! scenarios/secrets-audit-rotation-mfa.sh`) can drive the REAL published
//! image's binary through `driver_cli_exec` and assert every `ok:` line
//! appeared — the crypto-realness oracle pattern `oracle_crypto_realness`
//! already asserts for `pillar onboard`.
//!
//! Four steps, each a REAL cryptographic effect observed from outside the
//! primitive under test (never a stubbed return code):
//!
//! 1. **seal + read a secret** — [`pillar_key_distribution`]'s
//!    [`Escrow`] (via [`KeyCli`]) stores an operational secret under a
//!    client password with real argon2id+AEAD; the same password recovers
//!    the exact plaintext, while the wrong password fails closed
//!    (`Escrow::recover_plaintext` doc: "genuine argon2id+AEAD decryption").
//! 2. **every privileged action produces a real signed audit-log entry** —
//!    [`pillar_eventlog::EventLog`]'s `audit_view` surfaces a genuinely
//!    signed event as `AuditEntry::Verified` (real ed25519 signature
//!    verification), and a forged signature (signed by a DIFFERENT key,
//!    then relabelled) is surfaced as `AuditEntry::Rejected` — never
//!    rendered as legitimate.
//! 3. **key rotation revokes old-key access** — [`KeyCli::rotate`] mints a
//!    successor id and immediately marks the old id revoked;
//!    [`KeyCli::verify`] on the old id is `false` after rotation while the
//!    new id verifies `true`.
//! 4. **step-up MFA is required for a privileged action** —
//!    [`Escrow::recover_plaintext_for_signing`] refuses to release
//!    plaintext for signing without a fresh, unconsumed [`StepUpToken`]
//!    (a token that was never minted / already consumed is refused, fail
//!    closed), and succeeds only once a genuine fresh token is presented —
//!    consuming it, so it authorizes exactly one signing use.

use pillar_eventlog::{Author, Event, EventContent, EventLog, Signature};
use pillar_identity::global_identity::KeyId as IdentityKeyId;
use pillar_key_distribution::{Artifact, ArtifactId, ArtifactKind, Escrow, StepUpToken};

use crate::identity_trust_cli::KeyCli;

/// Runs the full secrets/audit/rotation/mfa sequence. Returns `Ok(())` if
/// every step's real effect holds, `Err(<diagnostic>)` naming the first
/// violated one.
pub fn run() -> Result<(), String> {
    step_seal_and_read_secret()?;
    step_audit_log_signed_and_forged_rejected()?;
    step_key_rotation_revokes_old_access()?;
    step_stepup_mfa_required_for_privileged_action()?;
    Ok(())
}

fn ok(step: &str) {
    println!("ok: {step}");
}

fn fail(step: &str, why: impl std::fmt::Display) -> String {
    format!("FAIL: {step}: {why}")
}

/// Step 1 — seal a secret into the escrow (real argon2id+AEAD) and read it
/// back through the SAME password; the wrong password must fail closed
/// (genuine decryption, not a bookkeeping flag).
fn step_seal_and_read_secret() -> Result<(), String> {
    const STEP: &str = "seal-and-read-secret";
    let mut keys = KeyCli::new();
    let artifact = ArtifactId("secrets-audit-demo-artifact".to_string());
    let secret = b"top-secret-operational-key-material".to_vec();
    let password = b"correct-horse-battery-staple";

    keys.escrow(artifact.clone(), password, &secret)
        .map_err(|e| fail(STEP, format!("escrow store refused: {e:?}")))?;

    let recovered = keys
        .recover(&artifact, password)
        .map_err(|e| fail(STEP, format!("recover with the correct password refused: {e:?}")))?;
    if recovered != secret {
        return Err(fail(
            STEP,
            "recovered plaintext does not match the sealed secret",
        ));
    }

    // A wrong password must never open the sealed envelope — real AEAD
    // authentication, not a stand-in check.
    if keys.recover(&artifact, b"wrong-password").is_ok() {
        return Err(fail(
            STEP,
            "recover with the WRONG password wrongly succeeded (sealed-secret-store is not real crypto)",
        ));
    }
    ok(STEP);
    Ok(())
}

/// Step 2 — a privileged action's audit entry is a REAL signed event: the
/// audit view verifies a genuinely signed one and rejects a forged one
/// (signed under a different author's key, then relabelled) rather than
/// rendering it as legitimate.
fn step_audit_log_signed_and_forged_rejected() -> Result<(), String> {
    const STEP: &str = "audit-log-signed-forged-rejected";
    let actor = Author("secrets-demo-actor".to_string());
    let attacker = Author("secrets-demo-attacker".to_string());
    let mut log = EventLog::new();

    // A genuine privileged action: recovering the escrowed secret above is
    // recorded as a signed audit fact.
    let genuine_record = pillar_eventlog::AuditRecord::new(
        "secrets-demo-actor",
        "secret-recovered",
        1,
        "secrets-audit-demo-artifact",
    );
    let genuine_id = log.append(&actor, genuine_record.to_payload());

    let view = log.audit_view();
    let genuine_verified = view
        .iter()
        .any(|e| e.event() == &genuine_id && e.is_verified() && e.verified() == Some(&genuine_record));
    if !genuine_verified {
        return Err(fail(
            STEP,
            "a genuinely signed privileged-action audit entry did not verify",
        ));
    }

    // Forge: a well-formed audit payload claiming to be `actor`'s privileged
    // escalation, but the signature bytes are genuinely produced by
    // `attacker`'s OWN secret key and merely relabelled as `actor`'s — the
    // classic impersonation the ed25519 signature check must refuse (the
    // actor's derived public key can never validate signature bytes it did
    // not produce).
    let forged_content = EventContent::for_fixture(
        actor.clone(),
        0,
        None,
        Default::default(),
        pillar_eventlog::AuditRecord::new("secrets-demo-actor", "escalate-privilege", 999, "root")
            .to_payload(),
    );
    let attacker_signature = Signature::sign(&attacker, &forged_content);
    let forged_signature = Signature::relabel_for_fixture(actor.clone(), &attacker_signature);
    let forged_event = Event::stamped(forged_content, forged_signature);
    if forged_event.is_authentic() {
        return Err(fail(
            STEP,
            "a forged (wrong-key) audit event was WRONGLY accepted as authentic",
        ));
    }

    // Even if a forged event slipped into a replica's store (bypassing
    // ingest), the audit view must still refuse to render it as legitimate.
    let mut fixture = EventLog::new();
    let genuine_content = EventContent::for_fixture(
        actor.clone(),
        0,
        None,
        Default::default(),
        genuine_record.to_payload(),
    );
    let genuine_signature = Signature::sign(&actor, &genuine_content);
    fixture.insert_unchecked(Event::stamped(genuine_content, genuine_signature));
    fixture.insert_unchecked(forged_event);

    let fixture_view = fixture.audit_view();
    let forged_rejected = fixture_view.iter().any(|e| {
        !e.is_verified()
            && matches!(e, pillar_eventlog::AuditEntry::Rejected { author, .. } if *author == actor)
    });
    if !forged_rejected {
        return Err(fail(
            STEP,
            "the audit view did not surface the forged privileged action as Rejected",
        ));
    }
    let forged_never_legitimate = fixture_view
        .iter()
        .filter_map(pillar_eventlog::AuditEntry::verified)
        .all(|r| r.action != "escalate-privilege");
    if !forged_never_legitimate {
        return Err(fail(
            STEP,
            "the forged privileged action was rendered as a legitimate audit line",
        ));
    }
    ok(STEP);
    Ok(())
}

/// Step 3 — rotating a key immediately revokes the old id's authority; the
/// new id is the only one that verifies afterward.
fn step_key_rotation_revokes_old_access() -> Result<(), String> {
    const STEP: &str = "key-rotation-revokes-old-access";
    let mut keys = KeyCli::new();
    let old_id = IdentityKeyId("secrets-demo-key-v1".to_string());
    let new_id = IdentityKeyId("secrets-demo-key-v2".to_string());

    keys.gen(old_id.clone());
    if !keys.verify(&old_id) {
        return Err(fail(STEP, "freshly generated key does not verify"));
    }

    keys.rotate(&old_id, new_id.clone())
        .map_err(|e| fail(STEP, format!("rotation refused: {e:?}")))?;

    if keys.verify(&old_id) {
        return Err(fail(
            STEP,
            "old key id still verifies after rotation (old-key access was NOT revoked)",
        ));
    }
    if !keys.verify(&new_id) {
        return Err(fail(
            STEP,
            "rotated-to key id does not verify (rotation did not grant the new key authority)",
        ));
    }
    ok(STEP);
    Ok(())
}

/// Step 4 — a privileged signing recovery is refused without a fresh,
/// unconsumed step-up (MFA) token, and succeeds once a genuine one is
/// presented — fail-closed exactly as the ROI mandates.
fn step_stepup_mfa_required_for_privileged_action() -> Result<(), String> {
    const STEP: &str = "stepup-mfa-required-for-privileged-action";
    let mut escrow = Escrow::new();
    let artifact = Artifact::new(
        ArtifactId("secrets-demo-signing-artifact".to_string()),
        ArtifactKind::Operational,
    );
    let password = b"stepup-demo-password";
    let secret = b"operational-signing-key-material".to_vec();
    escrow
        .store(&artifact, password, &secret)
        .map_err(|e| fail(STEP, format!("escrow store refused: {e:?}")))?;

    // No step-up: an already-consumed token must be refused before signing
    // recovery is granted — the privileged action is REJECTED without MFA.
    let mut spent_token = StepUpToken::fresh();
    assert!(spent_token.consume(), "freshly minted token must consume once");
    if escrow
        .recover_plaintext_for_signing(artifact.id(), password, &mut spent_token)
        .is_ok()
    {
        return Err(fail(
            STEP,
            "signing recovery was WRONGLY admitted without a fresh step-up token",
        ));
    }

    // A genuine fresh step-up token authorizes exactly one signing recovery.
    let mut fresh_token = StepUpToken::fresh();
    let recovered = escrow
        .recover_plaintext_for_signing(artifact.id(), password, &mut fresh_token)
        .map_err(|e| fail(STEP, format!("signing recovery with a fresh step-up token refused: {e:?}")))?;
    if recovered != secret {
        return Err(fail(
            STEP,
            "signing recovery returned the wrong plaintext",
        ));
    }

    // The SAME token cannot authorize a second signing use (single-use).
    if escrow
        .recover_plaintext_for_signing(artifact.id(), password, &mut fresh_token)
        .is_ok()
    {
        return Err(fail(
            STEP,
            "a CONSUMED step-up token wrongly authorized a second signing recovery",
        ));
    }
    ok(STEP);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_sequence_passes() {
        run().expect("secrets/audit/rotation/mfa sequence holds every invariant");
    }

    #[test]
    fn each_step_passes_individually() {
        step_seal_and_read_secret().unwrap();
        step_audit_log_signed_and_forged_rejected().unwrap();
        step_key_rotation_revokes_old_access().unwrap();
        step_stepup_mfa_required_for_privileged_action().unwrap();
    }
}
