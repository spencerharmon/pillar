//! The wire-op surface: every request/response protocol Pillar's transports
//! actually register — the libp2p `request_response` protocols
//! ([`crate::blob`], [`crate::antientropy`]) and the pillar-UDP session
//! protocol ([`crate::pillar_udp`]).
//!
//! [`WireOpRegistry`] mirrors [`pillar_manifest::SchemaRegistry`]'s shape
//! deliberately: a real, mutable registry (not a hand-maintained constant
//! list baked into a report generator) that production code populates with
//! the operations it actually wires up, and that a surface-inventory emitter
//! walks generically. [`registered_wire_ops`] returns the registry
//! pre-populated with every wire op THIS crate currently registers.

use crate::antientropy::ANTI_ENTROPY_PROTOCOL_NAME;
use crate::blob::BLOB_PROTOCOL_NAME;
use crate::pillar_udp::PROTOCOL_SURFACE;

/// One registered wire-protocol operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireOp {
    /// A stable identifier for this op (`protocol-name/verb`).
    pub id: String,
    /// A human-readable signature: the protocol name and request/response
    /// shape this op carries.
    pub signature: String,
}

impl WireOp {
    /// A new wire op with the given id and signature.
    #[must_use]
    pub fn new(id: impl Into<String>, signature: impl Into<String>) -> Self {
        WireOp {
            id: id.into(),
            signature: signature.into(),
        }
    }
}

/// A registry of wire-protocol operations — the real, currently-served wire
/// surface. Populated by [`registered_wire_ops`] with every op this crate's
/// transports register; a caller (e.g. a test build proving the emitter
/// reads the real surface) may [`WireOpRegistry::register`] additional ops
/// or build an empty registry to prove an op's absence is reflected too.
#[derive(Clone, Debug, Default)]
pub struct WireOpRegistry {
    ops: Vec<WireOp>,
}

impl WireOpRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        WireOpRegistry { ops: Vec::new() }
    }

    /// Register one more wire op.
    pub fn register(&mut self, op: WireOp) {
        self.ops.push(op);
    }

    /// Every currently-registered wire op.
    pub fn ops(&self) -> impl Iterator<Item = &WireOp> {
        self.ops.iter()
    }
}

/// The wire-op registry pre-populated with every request/response protocol
/// this crate actually wires up: the libp2p blob-fetch protocol
/// ([`BLOB_PROTOCOL_NAME`]), the libp2p anti-entropy sync protocol
/// ([`ANTI_ENTROPY_PROTOCOL_NAME`]), and the pillar-UDP session-negotiation
/// surface ([`PROTOCOL_SURFACE`]).
#[must_use]
pub fn registered_wire_ops() -> WireOpRegistry {
    let mut reg = WireOpRegistry::new();
    reg.register(WireOp::new(
        format!("wire:{BLOB_PROTOCOL_NAME}/fetch"),
        format!("libp2p request/response {BLOB_PROTOCOL_NAME}: BlobRequest{{digest}} -> BlobResponse"),
    ));
    reg.register(WireOp::new(
        format!("wire:{ANTI_ENTROPY_PROTOCOL_NAME}/sync"),
        format!(
            "libp2p request/response {ANTI_ENTROPY_PROTOCOL_NAME}: SyncRequest -> SyncResponse"
        ),
    ));
    reg.register(WireOp::new(
        format!("wire:{PROTOCOL_SURFACE}/handshake"),
        format!("{PROTOCOL_SURFACE} session negotiation: PeerHandshake{{protocol_version}}"),
    ));
    reg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_wire_ops_lists_every_real_protocol() {
        let reg = registered_wire_ops();
        let ids: Vec<&str> = reg.ops().map(|op| op.id.as_str()).collect();
        assert!(ids.iter().any(|id| id.contains(BLOB_PROTOCOL_NAME)));
        assert!(ids.iter().any(|id| id.contains(ANTI_ENTROPY_PROTOCOL_NAME)));
        assert!(ids.iter().any(|id| id.contains(PROTOCOL_SURFACE)));
    }

    #[test]
    fn a_registered_op_can_be_added_and_is_reflected() {
        let mut reg = registered_wire_ops();
        let before = reg.ops().count();
        reg.register(WireOp::new("wire:throwaway/test", "throwaway test op"));
        assert_eq!(reg.ops().count(), before + 1);
        assert!(reg.ops().any(|op| op.id == "wire:throwaway/test"));
    }

    #[test]
    fn an_empty_registry_lists_nothing() {
        let reg = WireOpRegistry::new();
        assert_eq!(reg.ops().count(), 0);
    }
}
