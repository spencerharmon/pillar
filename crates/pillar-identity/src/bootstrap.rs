//! Cell bootstrap and user-within-cell genesis, content-addressed.
//!
//! This is the deployment primitive behind ROI P2 "Deploy target:
//! spencer@pillar on flux, operator login test". It sits on top of the
//! [`crate::login`] hierarchy (cell key = cold root, node subkeys and user op
//! keys enrolled under it) and adds the one thing a real deployment needs that
//! the pure login model does not: a **deterministic, content-addressed
//! genesis identity** for a cell and for each user created within it.
//!
//! ## What "bootstrap" is
//!
//! Per the ROI, bootstrapping a deploy target is TWO steps, in order:
//!
//! 1. **Create the CELL first.** From a cell root key (an OpenPGP primary
//!    fingerprint) plus cell metadata (its human name), derive the cell's
//!    canonical **genesis CID** — the cold-root anchor of the entire
//!    hierarchy. Then derive the **node subkey** that chains the already-
//!    deployed node to that cell key (nodes are cell-owned, never user-owned).
//! 2. **Create the user WITHIN that cell.** From the cell CID plus a user's
//!    own root key and handle (`spencer@pillar`), derive the user's **genesis
//!    CID** — content-addressed and *scoped to the cell*, so the same user
//!    root key produces a different CID in a different cell.
//!
//! ## Content-addressing (the machine-checkable effect)
//!
//! Every CID is the [`pillar_streamdb::content_address`] of a canonical byte
//! encoding of the identity's fields — the SAME pure bytes→identity function
//! the op-log and manifest layers use, so nothing here reinvents hashing.
//! The two invariants the ROI names, which the tests below assert:
//!
//! - **Deterministic:** the same root key + metadata yields the same CID on
//!   every run and platform.
//! - **Content-addressed / scoped:** a different root key (or, for a user, a
//!   different enclosing cell) yields a different CID.
//!
//! As with the rest of this crate, no real key material or crypto is present:
//! a "root key" is its fingerprint string, standing in for the OpenPGP primary
//! whose packets a later layer will actually generate and verify. The
//! *addressing policy* — the part a deploy depends on being stable and
//! collision-distinct — is what is modelled and tested here.

use pillar_streamdb::content_address;

use crate::login::{ColdRoot, OpKey};
use crate::NodeSubkey;

/// Domain-separation tags mixed into each content address so a cell CID, a
/// node subkey, and a user CID derived from coincidentally-equal inputs can
/// never collide across kinds.
const CELL_TAG: &[u8] = b"pillar/cell-genesis/v1\0";
const NODE_TAG: &[u8] = b"pillar/node-subkey/v1\0";
const USER_TAG: &[u8] = b"pillar/user-genesis/v1\0";

/// Render a `u64` content address as the canonical CID string Pillar prints
/// for a genesis identity: a stable, lowercase, zero-padded hex digest with a
/// kind prefix, e.g. `cell:0000000000000000`.
fn cid(prefix: &str, addr: u64) -> String {
    format!("{prefix}:{addr:016x}")
}

/// Canonically encode a sequence of fields into bytes for content-addressing.
///
/// Each field is length-prefixed (`u64` LE) so no two distinct field lists can
/// encode to the same byte string (`["ab","c"]` ≠ `["a","bc"]`). Purely
/// deterministic and platform-independent.
fn canonical_bytes(tag: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(tag);
    for f in fields {
        out.extend_from_slice(&(f.len() as u64).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// A bootstrapped cell: its content-addressed genesis identity (the cold root)
/// plus the node subkey that chains the deployed node to it.
///
/// Constructing this IS bootstrap step 1. The `cell` field is the cold-root
/// anchor to enroll users and nodes under (via [`crate::login::IdentityStore`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellGenesis {
    /// The cell's canonical genesis CID, as a cold root. Its string IS its CID.
    pub cell: ColdRoot,
    /// The node subkey binding the deployed node to this cell.
    pub node: NodeSubkey,
}

impl CellGenesis {
    /// Bootstrap a cell from its root key and human name, and derive the node
    /// subkey chaining `node_root_key` to it.
    ///
    /// - `cell_root_key` — the cell primary key fingerprint (the cold root's
    ///   key material stand-in).
    /// - `cell_name` — the cell's human name (metadata folded into the CID).
    /// - `node_root_key` — the deployed node's own key fingerprint; the node
    ///   subkey CID is content-addressed over the cell CID + this key, so the
    ///   node is provably *this cell's* node.
    #[must_use]
    pub fn bootstrap(cell_root_key: &str, cell_name: &str, node_root_key: &str) -> Self {
        let cell_addr = content_address(&canonical_bytes(
            CELL_TAG,
            &[cell_root_key.as_bytes(), cell_name.as_bytes()],
        ));
        let cell_cid = cid("cell", cell_addr);

        let node_addr = content_address(&canonical_bytes(
            NODE_TAG,
            &[cell_cid.as_bytes(), node_root_key.as_bytes()],
        ));
        let node_cid = cid("node", node_addr);

        CellGenesis {
            cell: ColdRoot(cell_cid),
            node: NodeSubkey(node_cid),
        }
    }

    /// The cell's canonical genesis CID string.
    #[must_use]
    pub fn cell_cid(&self) -> &str {
        &self.cell.0
    }

    /// Create a user WITHIN this cell (bootstrap step 2): derive the user's
    /// genesis CID, content-addressed and scoped to this cell.
    ///
    /// - `user_root_key` — the user's own primary key fingerprint.
    /// - `handle` — the user's handle within the cell (e.g. `spencer@pillar`).
    ///
    /// The CID folds in `self.cell` so the SAME user root key yields a
    /// DIFFERENT CID in a different cell — the "scoped to that cell" property
    /// the ROI names. The returned [`OpKey`] is the user's op key to certify
    /// under the cell root via [`crate::login::IdentityStore::certify_op`].
    #[must_use]
    pub fn create_user(&self, user_root_key: &str, handle: &str) -> UserGenesis {
        let addr = content_address(&canonical_bytes(
            USER_TAG,
            &[
                self.cell.0.as_bytes(),
                user_root_key.as_bytes(),
                handle.as_bytes(),
            ],
        ));
        let user_cid = cid("user", addr);
        UserGenesis {
            handle: handle.to_owned(),
            cell: self.cell.clone(),
            op: OpKey(user_cid),
        }
    }
}

/// A user created within a bootstrapped cell: its handle, the enclosing cell,
/// and its content-addressed genesis CID (as the op key to enroll under the
/// cell root).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserGenesis {
    /// The user's handle within the cell (e.g. `spencer@pillar`).
    pub handle: String,
    /// The cell this user's genesis is scoped to.
    pub cell: ColdRoot,
    /// The user's genesis identity, as the op key to certify under the cell.
    pub op: OpKey,
}

impl UserGenesis {
    /// The user's canonical genesis CID string.
    #[must_use]
    pub fn user_cid(&self) -> &str {
        &self.op.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spencer@pillar deploy target fixture: the ROI's concrete case.
    const CELL_KEY: &str = "CELL-ROOT-FPR-AAAA";
    const CELL_NAME: &str = "pillar";
    const NODE_KEY: &str = "NODE-ROOT-FPR-BBBB";
    const USER_KEY: &str = "SPENCER-ROOT-FPR-CCCC";
    const HANDLE: &str = "spencer@pillar";

    #[test]
    fn cell_genesis_is_deterministic() {
        let a = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, NODE_KEY);
        let b = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, NODE_KEY);
        assert_eq!(a, b, "same root key + metadata must yield the same cell CID");
        assert!(
            a.cell_cid().starts_with("cell:"),
            "cell CID carries its kind prefix"
        );
        assert!(a.node.0.starts_with("node:"), "node subkey is content-addressed");
    }

    #[test]
    fn different_cell_root_key_yields_different_cid() {
        let a = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, NODE_KEY);
        let b = CellGenesis::bootstrap("CELL-ROOT-FPR-ZZZZ", CELL_NAME, NODE_KEY);
        assert_ne!(
            a.cell_cid(),
            b.cell_cid(),
            "a different cell root key must produce a different CID (content-addressed)"
        );
    }

    #[test]
    fn different_cell_name_yields_different_cid() {
        let a = CellGenesis::bootstrap(CELL_KEY, "pillar", NODE_KEY);
        let b = CellGenesis::bootstrap(CELL_KEY, "other-cell", NODE_KEY);
        assert_ne!(
            a.cell_cid(),
            b.cell_cid(),
            "cell metadata is folded into the CID"
        );
    }

    #[test]
    fn node_subkey_chains_to_cell_and_tracks_its_key() {
        let cell = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, NODE_KEY);
        // Same node key, different cell -> different node subkey (it chains to
        // the cell CID, so it is provably this cell's node).
        let other_cell = CellGenesis::bootstrap("CELL-ROOT-FPR-ZZZZ", CELL_NAME, NODE_KEY);
        assert_ne!(
            cell.node, other_cell.node,
            "node subkey is scoped to its cell"
        );
        // Same cell, different node key -> different subkey.
        let cell2 = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, "NODE-ROOT-FPR-DIFF");
        assert_ne!(cell.node, cell2.node, "node subkey tracks the node's key");
    }

    #[test]
    fn user_genesis_is_deterministic() {
        let cell = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, NODE_KEY);
        let a = cell.create_user(USER_KEY, HANDLE);
        let b = cell.create_user(USER_KEY, HANDLE);
        assert_eq!(a, b, "same user root key + handle in the same cell is stable");
        assert!(a.user_cid().starts_with("user:"), "user genesis CID prefix");
        assert_eq!(a.cell, cell.cell, "user genesis records its enclosing cell");
    }

    #[test]
    fn different_user_root_key_yields_different_cid() {
        let cell = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, NODE_KEY);
        let a = cell.create_user(USER_KEY, HANDLE);
        let b = cell.create_user("SPENCER-ROOT-FPR-DIFF", HANDLE);
        assert_ne!(
            a.user_cid(),
            b.user_cid(),
            "a different user root key must produce a different genesis CID"
        );
    }

    #[test]
    fn same_user_key_in_different_cell_yields_different_cid() {
        let cell_a = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, NODE_KEY);
        let cell_b = CellGenesis::bootstrap("CELL-ROOT-FPR-ZZZZ", "other", NODE_KEY);
        let ua = cell_a.create_user(USER_KEY, HANDLE);
        let ub = cell_b.create_user(USER_KEY, HANDLE);
        assert_ne!(
            ua.user_cid(),
            ub.user_cid(),
            "user genesis CID is scoped to its enclosing cell"
        );
    }

    #[test]
    fn bootstrapped_user_logs_in_through_the_cell() {
        use crate::login::{DeviceSubkey, IdentityStore};
        // End-to-end: bootstrap the cell, create spencer@pillar within it,
        // enroll the user op key under the cell cold root, grant a device, and
        // confirm the login guard admits it over the intact chain.
        let cell = CellGenesis::bootstrap(CELL_KEY, CELL_NAME, NODE_KEY);
        let user = cell.create_user(USER_KEY, HANDLE);

        let mut store = IdentityStore::new();
        store.certify_op(cell.cell.clone(), user.op.clone());
        let device = DeviceSubkey("spencer-laptop".into());
        store.grant_device(user.op.clone(), device.clone());

        let outcome = store.login(&device).expect("intact chain must log in");
        assert_eq!(
            outcome.root, cell.cell,
            "login chains back to the bootstrapped cell cold root"
        );
    }
}
