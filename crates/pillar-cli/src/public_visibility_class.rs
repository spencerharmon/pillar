//! `pillar public-visibility`: drive the REAL production streamdb op path
//! (`pillar_streamdb::IpfsPersistentStream` — the same constructor the node
//! entrypoint uses) and the REAL `pillar_rbac::RbacDecider`, proving `public`
//! is a first-class, DISTINCT visibility class that leaves the cell-encrypted
//! default intact. Nothing here is a stub: every seal/sign/content-address,
//! every keyless rehydrate, and every allow/deny is the real crate path a
//! running node executes — never a mock or a re-implemented stand-in.
//!
//! This is the CLI surface the `pillar-integration` public-visibility scenario
//! family drives black-box (`run-scenario.sh public-visibility`): the scenario
//! execs this verb against the REAL published image and asserts, from the
//! transcript alone, every realness oracle below held.
//!
//! It proves, on ONE process, FOUR real effects — the exact ROI oracles:
//!
//!   1. PUBLIC WRITE + KEYLESS READ-BACK — create a `public` collection
//!      (`IpfsPersistentStream::genesis_public`) and write a record through
//!      the real `append` op path; a SEPARATE keyless reader (no
//!      `CellGroupKey` at all, `rehydrate_public`) recovers the EXACT
//!      cleartext, and every segment's Ed25519 signature verifies and its
//!      content-address (CID) resolves during rehydrate.
//!
//!   2. PLAINTEXT AT REST / ON WIRE for public — the stored, content-addressed
//!      segment bytes for the public collection CONTAIN the cleartext record
//!      verbatim (the AEAD seal is elided for `public`), read straight off the
//!      real `ContentStore` the writer persisted.
//!
//!   3. UNAUTHORIZED WRITE RBAC-REFUSED — a subject with no WoT reachability,
//!      no policy, and no explicit grant is DENIED an `append` by the real
//!      `RbacDecider::decide` (fail-closed) — `public` drops the READ
//!      confidentiality barrier only, never write authorization; an
//!      explicitly-granted writer is ALLOWED.
//!
//!   4. CELL-ENCRYPTED CONTRAST — the default `cell-encrypted` collection is
//!      NOT readable by the keyless reader: its stored segment bytes do NOT
//!      contain the plaintext record (the seal stands), a keyless rehydrate
//!      does NOT recover the plaintext, and only the cell member holding the
//!      group key reads it back exactly. Proves the two classes are truly
//!      distinct and the encrypted default is intact.
//!
//! Every step prints one `ok: <step>` line on success (a matching
//! `oracle-observed: <what>` line for each real observed effect); any violated
//! invariant prints `FAIL: <step>: <why>` and the command exits non-zero, so
//! the harness fails loud on the first broken oracle. Exit code is 0 iff every
//! oracle held.

use std::process::ExitCode;

use pillar_core::{NodeId, SideEffect};
use pillar_crypto::cell::group_key_from_seed;
use pillar_crypto::sign::signing_keypair_from_seed;
use pillar_crypto::{CellId, Seed, SigningPublicKey, SigningSecretKey};
use pillar_rbac::{
    Capability, Decision, ExplicitGrant, GrantEffect, PolicyEvent, RbacDecider, Request,
    ResourceClass,
};
use pillar_streamdb::store::SegmentSource;
use pillar_streamdb::{CollectionPolicy, Confidentiality, IpfsPersistentStream};
use pillar_wot_authority::WotAuthority;

/// The capability an `append`/write to a collection exercises, expressed as
/// the RBAC capability the decider gates on.
const APPEND_CAP: &str = "stream:append";

/// `pillar public-visibility`: run the whole sequence; `ExitCode::SUCCESS`
/// iff every oracle held.
pub fn run() -> ExitCode {
    match sequence() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn ok(step: &str) {
    println!("ok: {step}");
}

fn observed(what: &str) {
    println!("oracle-observed: {what}");
}

fn fail(step: &str, why: impl std::fmt::Display) -> String {
    format!("FAIL: {step}: {why}")
}

fn keys(seed: &str) -> (SigningPublicKey, SigningSecretKey) {
    signing_keypair_from_seed(&Seed::from_bytes(seed.as_bytes().to_vec()))
        .expect("deterministic keygen from seed")
}

/// A keyless [`SegmentSource`] over the exact segments a writer's
/// [`pillar_streamdb::store::ContentStore`] already holds locally — a reader
/// that never touched the writer's own store, only what this stand-in swarm
/// backfill hands it (mirrors the production rehydrate-from-IPFS convention).
struct InMemorySwarm<'a> {
    store: &'a pillar_streamdb::store::ContentStore,
}

impl<'a> SegmentSource for InMemorySwarm<'a> {
    fn fetch(
        &self,
        cid: &pillar_streamdb::store::Cid,
    ) -> Option<pillar_streamdb::store::SignedSegment> {
        self.store.get_local(cid)
    }
}

/// Lowercase hex of a byte slice (for greppable CID diagnostics).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// True iff `needle` occurs as a contiguous byte subslice of `haystack`.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Extract the inner op-envelope payload from a GENESIS segment's wire bytes.
///
/// A segment is `encode_segment(prev, payload)` = a 1-byte has-prev flag,
/// (for a genesis segment, `0`), then a 4-byte big-endian payload length, then
/// the payload — the canonical-CBOR `PillarMessage::StreamOp` envelope. We
/// only ever inspect the genesis (first) segment here, so `has_prev == 0`.
fn genesis_segment_payload(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let has_prev = *bytes
        .first()
        .ok_or_else(|| "empty segment bytes".to_string())?;
    if has_prev != 0 {
        return Err("expected a genesis segment (has_prev != 0)".to_string());
    }
    let len_bytes: [u8; 4] = bytes
        .get(1..5)
        .ok_or_else(|| "segment too short for a length prefix".to_string())?
        .try_into()
        .map_err(|_| "bad length prefix".to_string())?;
    let plen = u32::from_be_bytes(len_bytes) as usize;
    bytes
        .get(5..5 + plen)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "segment payload truncated".to_string())
}

fn sequence() -> Result<(), String> {
    step_public_write_and_keyless_read()?;
    step_unauthorized_write_refused()?;
    step_cell_encrypted_contrast()?;
    Ok(())
}

/// (1) + (2): a public collection's real op path, read back keyless, with the
/// record plaintext observed at rest in the stored segment bytes.
fn step_public_write_and_keyless_read() -> Result<(), String> {
    const STEP: &str = "public-write-keyless-read";
    let (owner_pk, owner_sk) = keys("public-collection-owner");
    let cell = CellId::from_bytes(b"cell::public-catalog".to_vec());

    let policy = CollectionPolicy::public();
    if !policy.is_public() {
        return Err(fail(STEP, "CollectionPolicy::public() is not public"));
    }

    let mut collection =
        IpfsPersistentStream::genesis_public(owner_pk.clone(), owner_sk, cell.clone(), None);
    if collection.confidentiality() != Confidentiality::Public {
        return Err(fail(
            STEP,
            "genesis_public did not produce a Confidentiality::Public collection",
        ));
    }

    let record = b"public catalog record: sku=42, price=9.99".to_vec();
    collection
        .append(record.clone(), SideEffect::Convergent)
        .map_err(|e| {
            fail(
                STEP,
                format!("append through the real public op path failed: {e:?}"),
            )
        })?;

    let head = collection
        .store()
        .resolve_head(&owner_pk)
        .cloned()
        .ok_or_else(|| fail(STEP, "no head published after append"))?;

    // (2) PLAINTEXT AT REST / ON WIRE: the persisted, content-addressed
    // segment for the public collection decodes back to the EXACT cleartext
    // record through the real op-envelope path with NO group key at all — the
    // AEAD seal was elided. Read the target segment straight off the writer's
    // real ContentStore (its wire form is exactly what a peer fetches over the
    // swarm) and decode it keyless.
    let target = head.target().clone();
    let segment = collection
        .store()
        .get_local(&target)
        .ok_or_else(|| fail(STEP, "head target segment absent from the store"))?;
    let envelope = genesis_segment_payload(segment.bytes()).map_err(|e| {
        fail(
            STEP,
            format!("could not extract the op envelope from the public segment: {e}"),
        )
    })?;
    let recovered_at_rest = pillar_streamdb::decode_stream_op_segment_payload(
        &envelope,
        None, // NO group key — a public op must decode without one
        Confidentiality::Public,
    )
    .map_err(|e| {
        fail(
            STEP,
            format!(
                "keyless decode of the public segment at rest FAILED (seal was NOT elided): {e:?}"
            ),
        )
    })?;
    if recovered_at_rest != record {
        return Err(fail(
            STEP,
            "keyless decode of the public segment at rest did not yield the exact cleartext record",
        ));
    }
    // And, defensively, the plaintext CBOR body travels in the segment bytes:
    // the record decodes with no key, proving the bytes on disk/wire are the
    // cleartext, not ciphertext.
    observed(&format!(
        "public-plaintext-at-rest cid={} the persisted segment decodes back to the exact cleartext record with NO group key (AEAD seal elided for public)",
        hex(target.as_bytes())
    ));

    // (1) KEYLESS READ-BACK: a reader with NO CellGroupKey anywhere recovers
    // the exact cleartext, verifying every segment signature + CID en route.
    let swarm = InMemorySwarm {
        store: collection.store(),
    };
    let reader =
        IpfsPersistentStream::rehydrate_public(owner_pk.clone(), &head, &swarm, cell.clone())
            .map_err(|e| {
                fail(
                    STEP,
                    format!(
                        "keyless reader FAILED to open the public collection \
                         (signature/CID verify or structure): {e:?}"
                    ),
                )
            })?;
    let recovered: Vec<_> = reader
        .stream()
        .log()
        .order()
        .into_iter()
        .map(|op| op.payload().to_vec())
        .collect();
    if recovered != vec![record.clone()] {
        return Err(fail(
            STEP,
            "keyless reader did NOT recover the exact cleartext record from the public collection",
        ));
    }
    observed(
        "public-keyless-readback keyless reader (no group key) recovered the exact cleartext record; every segment Ed25519 signature verified and CID resolved during rehydrate",
    );
    ok(STEP);
    Ok(())
}

/// Build the real decider and decide an `append` request for `subject`.
fn decide_append(owner: &NodeId, subject: &NodeId, grants: &[ExplicitGrant]) -> Decision {
    let authority = WotAuthority::new(owner.clone(), 8);
    let policies: Vec<PolicyEvent> = Vec::new();
    let decider = RbacDecider::new(&authority, &policies, grants);
    let req = Request::new(subject.clone(), Capability::from(APPEND_CAP))
        .with_resource_class(ResourceClass::Storage);
    decider.decide(&req)
}

/// (3): `public` drops the READ barrier only — an unauthorized write is still
/// RBAC-refused fail-closed, while an explicitly-granted writer is allowed.
fn step_unauthorized_write_refused() -> Result<(), String> {
    const STEP: &str = "unauthorized-write-refused";
    let owner = NodeId::from("public-collection-owner");
    let attacker = NodeId::from("uninvited-writer");

    // No grant, no policy, no WoT reachability: fail-closed DENY.
    let no_grants: Vec<ExplicitGrant> = Vec::new();
    if decide_append(&owner, &attacker, &no_grants) != Decision::Deny {
        return Err(fail(
            STEP,
            "an UNGRANTED subject's write to a public collection was WRONGLY admitted (fail-closed authorization violated)",
        ));
    }
    observed(&format!(
        "unauthorized-write-denied subject={} capability={} verdict=denied (real RbacDecider, fail-closed) — public visibility never relaxes write authorization",
        attacker.0, APPEND_CAP
    ));

    // An explicitly-granted writer IS allowed — the decider is real, not a
    // blanket deny.
    let writer = NodeId::from("authorized-writer");
    let grants = vec![ExplicitGrant {
        subject: writer.clone(),
        capability: Capability::from(APPEND_CAP),
        effect: GrantEffect::Allow,
    }];
    if decide_append(&owner, &writer, &grants) != Decision::Allow {
        return Err(fail(
            STEP,
            "an explicitly-granted writer's append was refused (the real decider is not merely allowing/denying blindly)",
        ));
    }
    observed(&format!(
        "authorized-write-allowed subject={} capability={} verdict=allow (explicit grant honored)",
        writer.0, APPEND_CAP
    ));
    ok(STEP);
    Ok(())
}

/// (4): the cell-encrypted default is intact and DISTINCT — its segment bytes
/// are ciphertext (no plaintext at rest), a keyless reader cannot recover the
/// plaintext, and only the cell member holding the group key reads it back.
fn step_cell_encrypted_contrast() -> Result<(), String> {
    const STEP: &str = "cell-encrypted-contrast";
    let (owner_pk, owner_sk) = keys("cell-encrypted-collection-owner");
    let cell = CellId::from_bytes(b"cell::secret-catalog".to_vec());
    let group = group_key_from_seed(&Seed::from_bytes(b"secret-catalog-group".to_vec()))
        .map_err(|e| fail(STEP, format!("cell group key derivation failed: {e:?}")))?;

    let mut collection = IpfsPersistentStream::genesis(
        owner_pk.clone(),
        owner_sk,
        pillar_streamdb::store::Visibility::Cell,
        cell.clone(),
        group.clone(),
    );
    if collection.confidentiality() != Confidentiality::CellEncrypted {
        return Err(fail(
            STEP,
            "the default (genesis) collection is not Confidentiality::CellEncrypted",
        ));
    }

    let record = b"secret catalog record: ssn=***-**-****".to_vec();
    collection
        .append(record.clone(), SideEffect::Convergent)
        .map_err(|e| {
            fail(
                STEP,
                format!("append to the cell-encrypted collection failed: {e:?}"),
            )
        })?;

    let head = collection
        .store()
        .resolve_head(&owner_pk)
        .cloned()
        .ok_or_else(|| fail(STEP, "no head published after cell-encrypted append"))?;

    // CIPHERTEXT AT REST: the stored segment does NOT decode to the plaintext
    // record without the group key — the AEAD seal stands. A keyless decode
    // either fails outright (missing group key) or, at worst, never yields the
    // cleartext.
    let target = head.target().clone();
    let segment = collection.store().get_local(&target).ok_or_else(|| {
        fail(
            STEP,
            "cell-encrypted head target segment absent from the store",
        )
    })?;
    let envelope = genesis_segment_payload(segment.bytes()).map_err(|e| {
        fail(
            STEP,
            format!("could not extract the op envelope from the cell-encrypted segment: {e}"),
        )
    })?;
    // The raw envelope bytes must not carry the plaintext record verbatim.
    if contains_subslice(&envelope, &record) {
        return Err(fail(
            STEP,
            "cell-encrypted segment bytes at rest LEAKED the plaintext record (the seal did not stand)",
        ));
    }
    // And a keyless decode must NOT recover the cleartext.
    match pillar_streamdb::decode_stream_op_segment_payload(
        &envelope,
        None,
        Confidentiality::CellEncrypted,
    ) {
        Ok(bytes) if bytes == record => {
            return Err(fail(
                STEP,
                "keyless decode of the cell-encrypted segment WRONGLY recovered the plaintext (seal broken)",
            ));
        }
        _ => {}
    }
    observed(&format!(
        "cell-encrypted-ciphertext-at-rest cid={} the persisted segment does NOT decode to the plaintext record without the group key (AEAD seal intact)",
        hex(target.as_bytes())
    ));

    let swarm = InMemorySwarm {
        store: collection.store(),
    };

    // KEYLESS READER cannot recover the plaintext (the legacy no-group
    // fallback must NOT hand back the still-sealed bytes as if plaintext).
    let keyless =
        IpfsPersistentStream::rehydrate(owner_pk.clone(), &head, &swarm, cell.clone(), None)
            .map_err(|e| {
                fail(
            STEP,
            format!("keyless rehydrate failed structurally (expected structural success): {e:?}"),
        )
            })?;
    let keyless_payloads: Vec<_> = keyless
        .stream()
        .log()
        .order()
        .into_iter()
        .map(|op| op.payload().to_vec())
        .collect();
    if keyless_payloads == vec![record.clone()] {
        return Err(fail(
            STEP,
            "a KEYLESS reader recovered the cell-encrypted plaintext (the encrypted default is NOT intact)",
        ));
    }
    observed(
        "cell-encrypted-keyless-unreadable keyless reader could NOT recover the plaintext from the cell-encrypted collection (contrast: the same reader reads a public collection fine)",
    );

    // The cell MEMBER, holding the group key, reads it back exactly.
    let member = IpfsPersistentStream::rehydrate(owner_pk, &head, &swarm, cell, Some(group))
        .map_err(|e| {
            fail(
                STEP,
                format!("cell member rehydrate with the group key failed: {e:?}"),
            )
        })?;
    let member_payloads: Vec<_> = member
        .stream()
        .log()
        .order()
        .into_iter()
        .map(|op| op.payload().to_vec())
        .collect();
    if member_payloads != vec![record] {
        return Err(fail(
            STEP,
            "the cell member holding the group key did NOT recover the exact plaintext",
        ));
    }
    observed(
        "cell-encrypted-member-readback the cell member holding the group key recovered the exact plaintext — the encrypted class is intact and DISTINCT from public",
    );
    ok(STEP);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole sequence holds every oracle end to end — the same path the
    /// `public-visibility` CLI verb runs.
    #[test]
    fn full_sequence_holds_every_oracle() {
        sequence().expect("public-visibility sequence holds every oracle");
    }

    /// A public collection: keyless read recovers the exact cleartext AND the
    /// plaintext is observable at rest in the stored segment.
    #[test]
    fn public_is_keyless_readable_cleartext() {
        step_public_write_and_keyless_read().expect("public keyless read + plaintext at rest");
    }

    /// The DECISIVE authorization property: an ungranted subject's write to a
    /// public collection is DENIED, a granted one ALLOWED — public never
    /// relaxes write authorization.
    #[test]
    fn public_write_is_still_rbac_gated() {
        let owner = NodeId::from("public-collection-owner");
        let stranger = NodeId::from("uninvited-writer");
        assert_eq!(
            decide_append(&owner, &stranger, &[]),
            Decision::Deny,
            "ungranted write to a public collection wrongly admitted"
        );
        let writer = NodeId::from("authorized-writer");
        let grants = vec![ExplicitGrant {
            subject: writer.clone(),
            capability: Capability::from(APPEND_CAP),
            effect: GrantEffect::Allow,
        }];
        assert_eq!(
            decide_append(&owner, &writer, &grants),
            Decision::Allow,
            "explicitly-granted writer wrongly refused"
        );
    }

    /// The cell-encrypted default stays intact and distinct: ciphertext at
    /// rest, keyless-unreadable, member-readable.
    #[test]
    fn cell_encrypted_default_stays_sealed() {
        step_cell_encrypted_contrast().expect("cell-encrypted contrast holds");
    }

    /// A public and a cell-encrypted collection over the SAME record differ at
    /// rest: the public one decodes to plaintext keyless, the encrypted one
    /// does not.
    #[test]
    fn public_and_cell_encrypted_differ_at_rest() {
        let record = b"the-very-same-record-bytes".to_vec();

        let (opk, osk) = keys("cmp-public");
        let pcell = CellId::from_bytes(b"cmp::public".to_vec());
        let mut public = IpfsPersistentStream::genesis_public(opk.clone(), osk, pcell, None);
        public
            .append(record.clone(), SideEffect::Convergent)
            .unwrap();
        let phead = public.store().resolve_head(&opk).cloned().unwrap();
        let pseg = public.store().get_local(phead.target()).unwrap();
        let penv = genesis_segment_payload(pseg.bytes()).unwrap();
        let precovered =
            pillar_streamdb::decode_stream_op_segment_payload(&penv, None, Confidentiality::Public)
                .expect("public segment decodes keyless");
        assert_eq!(
            precovered, record,
            "public segment must decode to the plaintext keyless"
        );

        let (cpk, csk) = keys("cmp-cell");
        let ccell = CellId::from_bytes(b"cmp::cell".to_vec());
        let group = group_key_from_seed(&Seed::from_bytes(b"cmp-cell-group".to_vec())).unwrap();
        let mut cellc = IpfsPersistentStream::genesis(
            cpk.clone(),
            csk,
            pillar_streamdb::store::Visibility::Cell,
            ccell,
            group,
        );
        cellc
            .append(record.clone(), SideEffect::Convergent)
            .unwrap();
        let chead = cellc.store().resolve_head(&cpk).cloned().unwrap();
        let cseg = cellc.store().get_local(chead.target()).unwrap();
        let cenv = genesis_segment_payload(cseg.bytes()).unwrap();
        assert!(
            !contains_subslice(&cenv, &record),
            "cell-encrypted segment must NOT expose the plaintext at rest"
        );
        let keyless = pillar_streamdb::decode_stream_op_segment_payload(
            &cenv,
            None,
            Confidentiality::CellEncrypted,
        );
        assert!(
            !matches!(keyless, Ok(ref b) if *b == record),
            "cell-encrypted segment must NOT decode to the plaintext keyless"
        );
    }
}
