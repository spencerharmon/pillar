//! `pillar-client` — the reusable Pillar **client** library.
//!
//! Pillar's nodes speak to each other over a libp2p swarm whose payloads are
//! [`pillar_wire::PillarMessage`] envelopes (version-stamped, cell-sealed,
//! signed, content-addressed) carried on the standard pillar transports:
//! pillar-UDP preferred, QUIC/TCP fallback. Historically the only things that
//! spoke that wire were *other nodes*. `pillar-cli` is the first real
//! **client** — an application that is not itself a cell node but needs to
//! authenticate to a cell and act on it (e.g. `pillar apply`).
//!
//! This crate is that client surface, factored out so it is NOT buried in the
//! CLI: it is the best-practices path every future pillar client (a GUI, a
//! CI runner, a third-party integration) reuses. It owns four concerns, each
//! landing as its own module as the vertical is built:
//!
//! 1. [`config`] — resolving *where* and *who*: the `config.yaml` schema,
//!    its standard search locations, layered merge, CLI/env overrides, and
//!    validation into a ready-to-connect [`config::ConnectParams`].
//! 2. [`discovery`] — resolving a cell name to its live ingest nodes and
//!    their published sealing keys via pillar-IPNS, so a client with only a
//!    cell name can find the nodes to talk to. **(this slice)**
//! 3. `transport` *(later)* — dialing a node over the standard pillar
//!    transports in preference order (pillar-UDP → QUIC → HTTPS) and
//!    exchanging sealed [`pillar_wire::PillarMessage`]s.
//! 4. `auth` *(later)* — unlocking the user's cell key with a credential
//!    (password / passkey / keyring / TPM) and carrying the resulting
//!    WoT-verified token, so every act is authenticated and authorized.
//!
//! The design contract this crate establishes: **a caller only ever needs to
//! supply a cell name, a username, and a credential to unlock that user's key
//! in the cell.** Everything else (which nodes, which keys, which transport)
//! is either discovered (the full IPNS path) or cached in `config.yaml` for a
//! faster direct reconnect. Private-swarm callers additionally supply their
//! swarm key and seed nodes.

pub mod auth;
pub mod config;
pub mod discovery;
pub mod transport;

pub use auth::{
    authenticate, cached_token_is_valid, issue_token, now_unix, signer_id_of, AuthError,
    Credential, NodeAuthority, SessionToken,
};
pub use config::{
    load, ClientConfig, ConfigDirs, ConfigError, ConnectParams, CredentialConfig, CredentialKind,
    IdentityMaterial, ResolveError, SwarmMode, TransportKind, DEFAULT_TRANSPORT_ORDER,
};
pub use discovery::{
    CellDiscovery, DiscoveryError, InMemoryCellDiscovery, IngestNode, ResolvedNodes,
};
pub use transport::{
    open_resource_op, seal_resource_op, send_op_with_fallback, send_with_fallback, SendOutcome,
    StreamOpMessageError, TierAddr, STREAM_OP_SEAL_DOMAIN,
};
