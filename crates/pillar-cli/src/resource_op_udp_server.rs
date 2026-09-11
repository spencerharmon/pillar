//! The resource-op pillar-UDP tier (`cli-apply-over-pillar-message`,
//! 2026-09-11 ROI HEAD): a minimal, real UDP listener that lets a
//! `pillar-client` caller — `pillar apply -f`/`pillar delete` being the
//! first — mutate this cell's resource plane over the SAME sealed,
//! content-addressed [`pillar_wire::PillarMessage`] wire shape nodes already
//! use with each other, **superseding a privileged REST mutation call
//! entirely**: there is no HTTP framing anywhere in this module.
//!
//! Mirrors the [`crate::psl_udp_server`] skeleton (bind -> spawn a thread ->
//! loop `recv_from` -> decode -> respond), but unlike that read-only
//! `psl-message-api` tier, a datagram here carries a client-signed, cell-
//! sealed [`pillar_ops::ResourceOp`] (wrapped as [`Body::StreamOp`]) and its
//! processing MUTATES the node's live resource plane via
//! [`crate::web_serve::WebAuthContext::resource_op_apply`] — the identical
//! signed-apply/delete path a workload/cronjob HTTP mutation already rides
//! (see `crate::web_serve::WebAuthContext::resource_apply`). There is no
//! separate, weaker gate for this tier:
//!
//! 1. **Authenticate** — [`PillarMessage::verify_signature`] over the sealed
//!    body; a forged/tampered envelope is refused before anything is opened.
//! 2. **Open** — the sealed body is opened with this cell's group key
//!    (mirrors [`pillar_client::transport::open_resource_op`], reimplemented
//!    here node-side so this module needs no extra crate coupling beyond
//!    what it already re-exposes).
//! 3. **Decode** — the plaintext must be a [`Body::StreamOp`] whose payload
//!    decodes to a well-formed [`pillar_ops::ResourceOp`].
//! 4. **Authorize + apply** — [`crate::web_serve::WebAuthContext::resource_op_apply`]
//!    derives the requesting subject from the AUTHENTICATED signer (never
//!    from anything the producer merely claims) and runs the op through the
//!    SAME WoT/RBAC decider + signed event log every other resource act
//!    uses; an unauthorized signer is refused fail-closed exactly like an
//!    unauthorized HTTP mutation would be.
//!
//! Every step replies with a sealed, signed ack [`PillarMessage`] carrying a
//! [`Body::Control`] text — `"OK <event-cid>"` or `"ERR <reason>"` — so a
//! caller (see `pillar-client::transport::send_with_fallback`) always gets a
//! typed, decodable answer rather than silence. The ack's own signing key is
//! a dedicated, deterministic per-process keypair (see
//! [`ResourceOpServerKeys::derive`]): the ack carries no sensitive content
//! (only whether the op was admitted and its event id), so — unlike the
//! INBOUND op, which is the real security boundary this tier enforces — its
//! own authenticity is not load-bearing.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};

use pillar_crypto::cell::CellGroupKey;
use pillar_crypto::{CellId, Seed, SigningPublicKey, SigningSecretKey};
use pillar_wire::seal::{CellSeal, ContentSeal};
use pillar_wire::{Body, PillarMessage, Visibility};

use crate::web_serve::WebAuthContext;

/// The largest UDP datagram this tier accepts (mirrors
/// [`crate::psl_udp_server::MAX_DATAGRAM`]).
const MAX_DATAGRAM: usize = 60_000;

/// The domain separator this tier's ack seal uses — distinct from
/// [`pillar_client::transport::STREAM_OP_SEAL_DOMAIN`] (the INBOUND op's
/// seal domain) so an ack can never be replayed back in as if it were an
/// inbound op, or vice versa.
const ACK_SEAL_DOMAIN: &[u8] = b"pillar-cli/resource-op-udp-server/ack-v1";

/// The deterministic seed this tier's ack-signing keypair is derived from.
const ACK_SIGNER_SEED: &[u8] = b"pillar-cli/resource-op-udp-server/ack-signer/v1";

/// The cell-sealing material this tier needs to open an incoming client op
/// and sign+seal its reply: the SAME `cell_id`/`cell_group_key` the node's
/// streamdb segment signer derives at boot (see `crate::run::run`), plus a
/// dedicated ack-signing keypair.
#[derive(Clone)]
pub struct ResourceOpServerKeys {
    cell: CellId,
    group: CellGroupKey,
    ack_signer: SigningPublicKey,
    ack_secret: SigningSecretKey,
}

impl ResourceOpServerKeys {
    /// Derive this tier's keys: `cell`/`group` are the caller-supplied cell
    /// material (the SAME values the streamdb segment signer already
    /// derived); the ack-signing keypair is a fixed, deterministic
    /// per-process derivation (see the module docs — it carries no
    /// sensitive content, so it needs no fresh randomness).
    #[must_use]
    pub fn derive(cell: CellId, group: CellGroupKey) -> Self {
        let seed = Seed::from_bytes(ACK_SIGNER_SEED.to_vec());
        let (ack_signer, ack_secret) = pillar_crypto::sign::signing_keypair_from_seed(&seed)
            .expect("a signing seed always yields an ed25519 keypair");
        ResourceOpServerKeys {
            cell,
            group,
            ack_signer,
            ack_secret,
        }
    }
}

/// Bind the resource-op pillar-UDP tier on `bind` and serve requests against
/// `ctx` until the process exits. Blocking — run on a dedicated thread.
/// Returns the bound address so the caller can log/advertise it.
///
/// # Errors
/// Any [`std::io::Error`] binding the UDP socket.
pub fn spawn(
    bind: SocketAddr,
    ctx: Arc<Mutex<WebAuthContext>>,
    keys: ResourceOpServerKeys,
) -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind(bind)?;
    let local_addr = socket.local_addr()?;
    std::thread::spawn(move || serve(socket, ctx, keys));
    Ok(local_addr)
}

fn serve(socket: UdpSocket, ctx: Arc<Mutex<WebAuthContext>>, keys: ResourceOpServerKeys) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(reply) = handle_datagram(&buf[..n], &ctx, &keys) {
            if let Ok(bytes) = reply.to_canonical_cbor() {
                if bytes.len() <= MAX_DATAGRAM {
                    let _ = socket.send_to(&bytes, peer);
                }
            }
        }
    }
}

/// Build a sealed, signed ack [`PillarMessage`] carrying `"OK <detail>"` or
/// `"ERR <detail>"` as a [`Body::Control`] text payload.
fn ack_message(keys: &ResourceOpServerKeys, ok: bool, detail: &str) -> Option<PillarMessage> {
    let text = format!("{} {detail}", if ok { "OK" } else { "ERR" });
    let body = Body::Control(text.into_bytes());
    let plaintext = body.to_canonical_cbor().ok()?;
    let aad = PillarMessage::header_aad(Visibility::Cell, &keys.cell);
    let body_sealed = CellSeal
        .seal(&keys.group, &plaintext, ACK_SEAL_DOMAIN, &aad)
        .ok()?;
    let signature = pillar_crypto::sign::sign(
        &keys.ack_secret,
        &PillarMessage::signing_material(&body_sealed),
    )
    .ok()?;
    Some(PillarMessage::new(
        keys.ack_signer.clone(),
        signature,
        Visibility::Cell,
        keys.cell.clone(),
        body_sealed,
    ))
}

fn handle_datagram(
    bytes: &[u8],
    ctx: &Arc<Mutex<WebAuthContext>>,
    keys: &ResourceOpServerKeys,
) -> Option<PillarMessage> {
    let msg = match PillarMessage::from_canonical_cbor(bytes) {
        Ok(m) => m,
        Err(_) => return ack_message(keys, false, "MALFORMED-ENVELOPE"),
    };
    // 1. Authenticate FIRST — before any decode/authorization work, exactly
    //    the order `pillar_net::client_ingest::authorize_client_op` documents.
    if msg.verify_signature().is_err() {
        return ack_message(keys, false, "BAD-SIGNATURE");
    }
    // 2. Open the sealed body with this cell's group key.
    let aad = PillarMessage::header_aad(msg.visibility, &msg.cell);
    let plaintext = match CellSeal.open(&keys.group, &msg.body_sealed, &aad) {
        Ok(p) => p,
        Err(_) => return ack_message(keys, false, "UNSEAL-FAILED"),
    };
    let body = match Body::from_canonical_cbor(&plaintext) {
        Ok(b) => b,
        Err(_) => return ack_message(keys, false, "BAD-BODY"),
    };
    let payload = match body {
        Body::StreamOp(bytes) => bytes,
        _ => return ack_message(keys, false, "NOT-A-STREAM-OP"),
    };
    let op = match pillar_ops::ResourceOp::decode(&payload) {
        Ok(op) => op,
        Err(e) => return ack_message(keys, false, &format!("MALFORMED-OP {e}")),
    };
    // 3. Authorize + apply — the subject is the AUTHENTICATED signer (the
    //    exact same derivation `pillar_net::client_ingest::signer_subject`
    //    uses), never anything the producer merely claims.
    let actor = pillar_net::client_ingest::signer_subject(&msg);
    let mut guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return ack_message(keys, false, "POISONED-CONTEXT"),
    };
    match guard.resource_op_apply(&actor, &op) {
        Ok(event) => ack_message(keys, true, &event),
        Err(e) => ack_message(keys, false, &format!("{e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_crypto::cell::group_key_from_seed;
    use pillar_crypto::principal::principal_from_seed;
    use pillar_manifest::{Crd, Metadata, Value as CrdValue};
    use pillar_net::client_ingest::signer_subject;

    fn test_keys() -> (CellId, CellGroupKey) {
        let seed = Seed::from_bytes(b"resource-op-udp-server-test-cell".to_vec());
        let cell = CellId::from_bytes(b"resource-op-udp-server-test-cell-id".to_vec());
        let group = group_key_from_seed(&seed).expect("group key");
        (cell, group)
    }

    /// A client's sealed+signed `ResourceOp` message, built exactly the way
    /// `pillar-client::transport::seal_resource_op` does (reimplemented
    /// inline here so this crate's tests need no `pillar-client` dev-dep).
    fn seal_op(
        op: &pillar_ops::ResourceOp,
        cell: &CellId,
        group: &CellGroupKey,
        signer: SigningPublicKey,
        secret: &SigningSecretKey,
    ) -> PillarMessage {
        let payload = op.encode().expect("encode op");
        let body = Body::StreamOp(payload);
        let plaintext = body.to_canonical_cbor().expect("encode body");
        let aad = PillarMessage::header_aad(Visibility::Cell, cell);
        let body_sealed = CellSeal
            .seal(group, &plaintext, b"pillar-streamdb/stream-op-v1", &aad)
            .expect("seal");
        let signature = pillar_crypto::sign::sign(
            secret,
            &PillarMessage::signing_material(&body_sealed),
        )
        .expect("sign");
        PillarMessage::new(signer, signature, Visibility::Cell, cell.clone(), body_sealed)
    }

    #[test]
    fn a_bad_signature_is_refused_with_an_ack() {
        let keys = ResourceOpServerKeys::derive(test_keys().0, test_keys().1);
        let (cell, group) = test_keys();
        let (signer, secret) =
            principal_from_seed(&Seed::from_bytes(b"client-a".to_vec())).expect("principal");
        let op = pillar_ops::ResourceOp::Delete {
            kind: "RetentionPolicy".into(),
            name: "x".into(),
        };
        let mut msg = seal_op(&op, &cell, &group, signer.signing, &secret.signing);
        // Corrupt the signature.
        msg.signature = pillar_crypto::Signature::from_bytes(vec![0u8; 64]);
        let reply =
            handle_datagram(&msg.to_canonical_cbor().expect("encode"), &Arc::new(Mutex::new(
                WebAuthContext::new(
                    "https://test",
                    pillar_core::NodeId::from("pillar-node"),
                    "secret",
                    pillar_core::NodeId::from("pillar-node"),
                    16,
                ),
            )), &keys)
            .expect("an ack is always produced for a decodable envelope");
        let opened = CellSeal
            .open(&keys.group, &reply.body_sealed, &PillarMessage::header_aad(reply.visibility, &reply.cell))
            .expect("open ack");
        let Body::Control(text) = Body::from_canonical_cbor(&opened).expect("decode ack body") else {
            panic!("ack body must be Control");
        };
        let text = String::from_utf8(text).expect("utf8");
        assert!(text.starts_with("ERR BAD-SIGNATURE"), "{text}");
    }

    #[test]
    fn signer_subject_is_a_pure_function_of_the_verified_pubkey() {
        let (cell, group) = test_keys();
        let (signer, secret) =
            principal_from_seed(&Seed::from_bytes(b"client-b".to_vec())).expect("principal");
        let op = pillar_ops::ResourceOp::Apply {
            crd: Crd::new("pillar.dev/v1", "RetentionPolicy", Metadata::new("m"))
                .with_spec("signalKind", CrdValue::String("Metric".into())),
        };
        let msg = seal_op(&op, &cell, &group, signer.signing, &secret.signing);
        let subject_a = signer_subject(&msg);
        let subject_b = signer_subject(&msg);
        assert_eq!(subject_a, subject_b, "deterministic across calls");
    }
}
