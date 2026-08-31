//! Shared **bootstrap** library for Pillar — the one place the cell/user/node
//! onboarding sequence lives, reused verbatim by both the web portal
//! ([`pillar_web`]) and the CLI (`pillar bootstrap …`). Factoring it here
//! guarantees the two surfaces can never diverge on the bootstrap contract:
//! the same name-uniqueness rule, the same combined cell+user step, the same
//! one-shot `cell_key_can_create_user` capability, the same request/approval
//! lifecycle.
//!
//! # Why a dedicated crate and not `pillar-core`
//!
//! The operator's intent was "a shared bootstrap library both web and CLI
//! use." It cannot literally live in [`pillar_core`]: that crate is
//! deliberately dependency-free (pure value types that "never reach the
//! network or the filesystem"), whereas the bootstrap sequence composes
//! [`pillar_identity`], [`pillar_wot_authority`], and [`pillar_rbac`].
//! Placing it in `pillar-core` would both violate that documented contract
//! and create a dependency cycle (`pillar-identity` already depends on
//! `pillar-core`). This crate is the honest home: it sits above the identity
//! /authority crates and below the two front-ends.
//!
//! # Modules
//!
//! - [`custody`] — the per-key custody/encryption choice (password, passkey,
//!   TPM, keyring) plus operator labels, applied uniformly to the cell, user,
//!   and node keys.
//! - [`name`] — the best-effort network cell-name uniqueness pre-check shared
//!   by every create-cell surface.
//! - [`keygen`] — the identity bootstrap primitives (user-primary keygen,
//!   node-subkey signing/admission) over [`pillar_identity::Registry`].
//! - [`cell`] — the one-shot `cell_key_can_create_user` capability and the
//!   **combined single-step** [`cell::bootstrap_cell_and_user`] that fixes the
//!   split-flow bug (create cell → sign user key → grant the user the
//!   add-users right → revoke the cell's add-users right, all atomically).
//! - [`request`] — the node/user bootstrap **request → approval** lifecycle:
//!   a fresh node/user submits identifying information; an existing cell
//!   member approves; on a node approval the cell key is sealed to the new
//!   node and its CID returned. Refines `specs/BootstrapRequest.tla`.
//! - [`token`] — the temporary login-token issuance a `pillar login` obtains
//!   (and a web portal forwards credentials to the key-distribution server to
//!   mint), surfaced to the CLI as `PILLAR_DOMAIN` / `PILLAR_TOKEN`.

#![forbid(unsafe_code)]

pub mod cell;
pub mod custody;
pub mod keygen;
pub mod name;
pub mod request;
pub mod token;

pub use cell::{
    bootstrap_cell_and_user, CellBootstrap, CellBootstrapOutcome, ADD_USERS_CAPABILITY,
};
pub use custody::{CustodyChoice, CustodyKind};
pub use keygen::Bootstrap;
pub use name::{
    check_cell_name_available, CellNameRegistry, CellNameStatus, InMemoryCellNameRegistry,
    CELL_NAME_IN_USE_MESSAGE,
};
pub use request::{
    BootstrapRequest, BootstrapRequestId, BootstrapRequestKind, BootstrapRequestQueue,
    NodeIdentity, RequestError, RequestState, SealedCellKey,
};
pub use token::{LoginToken, LoginTokenError, TokenIssuer, TokenStore};

/// Why any bootstrap step was refused. Shared by the CLI and the web UI so
/// both surfaces display identical wording for identical failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// The cell has already been created.
    CellAlreadyExists,
    /// The first user cannot be created before the cell exists.
    NoCellYet,
    /// The one-shot `cell_key_can_create_user` capability is spent — the first
    /// user already exists, so a cell-key create-user is refused; further
    /// user administration must route through the admin user key.
    CapabilitySpent,
    /// The proposed cell name is ALREADY CLAIMED on the network: the
    /// pre-create peer-sourced check resolved a cell-name pointer for this
    /// name served by some peer, so creating it here would collide. Surfaced
    /// as [`CELL_NAME_IN_USE_MESSAGE`]. Best-effort accidental-collision
    /// guard, not a global strong-uniqueness guarantee (a name no peer serves
    /// is treated as FREE — see [`name::CellNameRegistry`]).
    CellNameInUse,
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::CellAlreadyExists => f.write_str("cell already exists"),
            BootstrapError::NoCellYet => f.write_str("cell has not been created yet"),
            BootstrapError::CapabilitySpent => {
                f.write_str("the first user already exists; use the admin user key to add more")
            }
            BootstrapError::CellNameInUse => f.write_str(CELL_NAME_IN_USE_MESSAGE),
        }
    }
}

impl std::error::Error for BootstrapError {}
