//! Optional intra-LAN BGP load-balancing / HA plugin for a [`Frontend`]'s VIP.
//!
//! This is a **MetalLB-style, purely intra-LAN** liveness convenience add-on:
//! it fails a [`Frontend`]'s VIP over between nodes *within one site* so that
//! the VIP stays reachable when its current advertiser goes unhealthy. It is
//! **explicitly NOT global public anycast** — advertisement never leaves the
//! configured site, pillar obtains **no ASN of its own**, and no core routing
//! path ever assumes this plugin exists.
//!
//! Design invariants (mirroring the ROI's stated success criteria):
//!
//! - **No hard dependency on core.** [`Frontend`], [`Route`], attachment and
//!   [`derive_routing_table`](crate::ingress::derive_routing_table) all behave
//!   identically whether or not any [`BgpLbPlugin`] exists. The plugin is a
//!   pure, out-of-band *observer/advertiser* of an already-typed Frontend; core
//!   never calls into it. (Enforced by construction: nothing in
//!   [`crate::ingress`] references this module.)
//! - **Failover stays same-site.** When the current advertiser is unhealthy the
//!   plugin re-elects an advertiser **only among healthy peers in the same
//!   site**; a peer in another site is never selected, so the VIP never
//!   escapes its LAN. If no healthy same-site peer exists the VIP is simply not
//!   advertised (fail-closed) rather than leaking to a remote site.
//! - **No pillar ASN; a user MAY bring their own.** The plugin never
//!   synthesizes, assumes, or defaults an ASN. Advertisement is only ever
//!   emitted with an ASN the *user explicitly configured* for their cell; when
//!   the user leaves the ASN unset the plugin refuses to advertise (it has no
//!   ASN to speak BGP with) rather than inventing one.
//!
//! Everything here is a dependency-free pure value type with deterministic
//! behaviour, so it can be unit-tested without any network.

use std::collections::BTreeMap;

use crate::ingress::Frontend;

/// A user-configured Autonomous System Number for a cell. There is **no
/// default** and no pillar-owned value: an ASN exists only because the operator
/// set one. Represented as a distinct newtype so an "unset" ASN can never be
/// silently coerced from a bare integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Asn(pub u32);

impl Asn {
    /// The raw AS number the user configured.
    #[must_use]
    pub fn value(self) -> u32 {
        self.0
    }
}

/// One BGP peer the plugin may advertise a VIP toward, pinned to the site it
/// lives in. A peer only ever participates in failover for VIPs whose
/// advertisement stays within `site` — the same-site constraint is carried on
/// the peer itself so a cross-site peer can never be elected by accident.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    /// The node identity of this peer (opaque address/id).
    pub node: String,
    /// The site (LAN / failure domain) this peer belongs to. Failover is
    /// confined to peers sharing this value.
    pub site: String,
}

impl Peer {
    /// A peer `node` located in `site`.
    #[must_use]
    pub fn new(node: impl Into<String>, site: impl Into<String>) -> Self {
        Peer {
            node: node.into(),
            site: site.into(),
        }
    }
}

/// The plugin's configuration for one cell. The plugin is **disabled** unless
/// explicitly enabled, and even when enabled it has no ASN unless the user
/// configured one — both are the ROI's "never assume a pillar-owned ASN"
/// guarantee expressed as types.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BgpLbConfig {
    /// Whether the plugin is active at all. Default `false`: absent
    /// configuration means the plugin does nothing and core is untouched.
    pub enabled: bool,
    /// The user-configured ASN for this cell, if any. `None` means the user
    /// did NOT set one; the plugin then refuses to advertise rather than
    /// inventing or assuming a pillar-owned ASN.
    pub asn: Option<Asn>,
    /// The site this cell's advertisement is confined to. Advertisement never
    /// leaves this site — the intra-LAN (not global-anycast) guarantee.
    pub site: String,
    /// The candidate peers, in preference order, that may advertise the VIP.
    pub peers: Vec<Peer>,
}

impl BgpLbConfig {
    /// A disabled config (the safe default): the plugin does nothing.
    #[must_use]
    pub fn disabled() -> Self {
        BgpLbConfig::default()
    }

    /// An enabled config for `site` with the user's `asn` (pass `None` to
    /// leave it unset — the plugin will then refuse to advertise).
    #[must_use]
    pub fn enabled(site: impl Into<String>, asn: Option<Asn>) -> Self {
        BgpLbConfig {
            enabled: true,
            asn,
            site: site.into(),
            peers: Vec::new(),
        }
    }

    /// Add a candidate peer, builder-style.
    #[must_use]
    pub fn with_peer(mut self, peer: Peer) -> Self {
        self.peers.push(peer);
        self
    }
}

/// A single BGP advertisement the plugin decided to emit: the VIP, the node
/// currently advertising it, and the ASN it is advertised under. An
/// advertisement can only exist with a concrete, user-configured [`Asn`] — the
/// type has no "unset ASN" state, so the no-pillar-ASN guarantee is structural.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertisement {
    /// The virtual IP being advertised.
    pub vip: String,
    /// The node currently advertising the VIP (always a healthy same-site peer).
    pub node: String,
    /// The ASN it is advertised under — always a user-configured value.
    pub asn: Asn,
}

/// The optional intra-LAN BGP LB plugin. Holds a [`BgpLbConfig`] and derives,
/// from a snapshot of peer health, which same-site healthy node should
/// advertise a Frontend's VIP. It touches nothing in core and is safe to omit
/// entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BgpLbPlugin {
    config: BgpLbConfig,
}

impl BgpLbPlugin {
    /// Construct the plugin around a config.
    #[must_use]
    pub fn new(config: BgpLbConfig) -> Self {
        BgpLbPlugin { config }
    }

    /// The plugin's config (borrowed).
    #[must_use]
    pub fn config(&self) -> &BgpLbConfig {
        &self.config
    }

    /// Whether the plugin is active. A disabled plugin never advertises.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Elect the node that should advertise `frontend`'s VIP, given the current
    /// per-node `health` snapshot (a node absent from the map is treated as
    /// unhealthy). Returns the elected advertisement, or `None` when the VIP
    /// must NOT be advertised.
    ///
    /// It returns `None` — refusing to advertise — in every case that would
    /// otherwise violate an invariant:
    ///
    /// - the plugin is disabled;
    /// - the user configured **no ASN** (there is nothing to speak BGP with,
    ///   and the plugin must never assume a pillar-owned ASN);
    /// - **no healthy peer in the plugin's own site** is available (failover
    ///   stays same-site — it never leaks the VIP to a remote site, and
    ///   fails closed if the whole site is down).
    ///
    /// When it does advertise, the elected node is guaranteed to be a healthy
    /// peer whose `site` equals the plugin's configured `site`, taken in the
    /// config's peer preference order (so failover deterministically moves to
    /// the next healthy same-site peer).
    #[must_use]
    pub fn elect_advertiser(
        &self,
        frontend: &Frontend,
        health: &BTreeMap<String, bool>,
    ) -> Option<Advertisement> {
        if !self.config.enabled {
            return None;
        }
        // No user ASN → never invent/assume a pillar-owned one → do not advertise.
        let asn = self.config.asn?;

        let node = self
            .config
            .peers
            .iter()
            .find(|p| p.site == self.config.site && *health.get(&p.node).unwrap_or(&false))
            .map(|p| p.node.clone())?;

        Some(Advertisement {
            vip: frontend.vip.clone(),
            node,
            asn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::{
        derive_routing_table, Frontend, Route, RouteKind, RouteStatus, ATTACH_ACTION,
    };
    use pillar_core::NodeId;
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig, TrustStore};

    fn fe() -> Frontend {
        Frontend::new("edge", "10.0.0.9")
    }

    fn health(pairs: &[(&str, bool)]) -> BTreeMap<String, bool> {
        pairs.iter().map(|(n, h)| ((*n).to_owned(), *h)).collect()
    }

    // ---- Property: core routing is unaffected by the plugin's presence ----

    #[test]
    fn frontend_route_and_attachment_work_with_the_plugin_disabled() {
        // Build a fully-authorized attachment and derive the routing table
        // WITHOUT ever constructing the plugin — proving core has no
        // dependency on it.
        let genesis = NodeId::from("genesis");
        let mut store = TrustStore::new(genesis.clone());
        let app = NodeId::from("app-a");
        store
            .issue_attest(Attest {
                issuer: genesis.clone(),
                capacity: Capacity::SelfCap,
                authority: None,
                subject: app.clone(),
                predicate: Predicate::new(ATTACH_ACTION, "edge"),
                scope: "default".to_owned(),
                epoch: store.epoch(),
                sig: Sig::by(genesis),
            })
            .expect("grant issues");
        let route = Route::new("r1", app, "edge", RouteKind::Udp);
        let table = derive_routing_table(&[fe()], &[route], &store);
        assert_eq!(table.status_of("r1"), Some(&RouteStatus::Attached));

        // A disabled plugin observing the SAME frontend advertises nothing and
        // changes nothing about the derivation above.
        let plugin = BgpLbPlugin::new(BgpLbConfig::disabled());
        assert!(!plugin.is_enabled());
        assert_eq!(
            plugin.elect_advertiser(&fe(), &health(&[("n1", true)])),
            None
        );
    }

    // ---- Failover stays same-site and moves to a healthy node ----

    #[test]
    fn enabled_plugin_advertises_from_a_healthy_same_site_node() {
        let plugin = BgpLbPlugin::new(
            BgpLbConfig::enabled("site-a", Some(Asn(64512)))
                .with_peer(Peer::new("n1", "site-a"))
                .with_peer(Peer::new("n2", "site-a")),
        );
        let ad = plugin
            .elect_advertiser(&fe(), &health(&[("n1", true), ("n2", true)]))
            .expect("advertises");
        assert_eq!(ad.node, "n1");
        assert_eq!(ad.vip, "10.0.0.9");
        assert_eq!(ad.asn, Asn(64512));
    }

    #[test]
    fn vip_failover_moves_advertisement_to_a_healthy_same_site_node_only() {
        // n1 (preferred) is down, n2 same-site is healthy, n3 is in ANOTHER
        // site and healthy. Failover must pick n2, never the remote n3.
        let plugin = BgpLbPlugin::new(
            BgpLbConfig::enabled("site-a", Some(Asn(64512)))
                .with_peer(Peer::new("n1", "site-a"))
                .with_peer(Peer::new("n3", "site-b"))
                .with_peer(Peer::new("n2", "site-a")),
        );
        let ad = plugin
            .elect_advertiser(
                &fe(),
                &health(&[("n1", false), ("n2", true), ("n3", true)]),
            )
            .expect("fails over");
        assert_eq!(ad.node, "n2", "failover stays within site-a");
    }

    #[test]
    fn a_healthy_peer_in_another_site_is_never_elected() {
        // The ONLY healthy peer is in a different site: fail closed, do not
        // leak the VIP off the LAN.
        let plugin = BgpLbPlugin::new(
            BgpLbConfig::enabled("site-a", Some(Asn(64512)))
                .with_peer(Peer::new("n1", "site-a"))
                .with_peer(Peer::new("remote", "site-b")),
        );
        assert_eq!(
            plugin.elect_advertiser(&fe(), &health(&[("n1", false), ("remote", true)])),
            None
        );
    }

    #[test]
    fn no_healthy_same_site_peer_means_no_advertisement() {
        let plugin = BgpLbPlugin::new(
            BgpLbConfig::enabled("site-a", Some(Asn(64512)))
                .with_peer(Peer::new("n1", "site-a")),
        );
        assert_eq!(
            plugin.elect_advertiser(&fe(), &health(&[("n1", false)])),
            None
        );
    }

    // ---- ASN: honor the user's, never assume a pillar-owned one ----

    #[test]
    fn a_configured_user_asn_is_honored() {
        let plugin = BgpLbPlugin::new(
            BgpLbConfig::enabled("site-a", Some(Asn(65001)))
                .with_peer(Peer::new("n1", "site-a")),
        );
        let ad = plugin
            .elect_advertiser(&fe(), &health(&[("n1", true)]))
            .expect("advertises with the user ASN");
        assert_eq!(ad.asn, Asn(65001));
    }

    #[test]
    fn the_plugin_never_assumes_a_pillar_asn_when_unset() {
        // Enabled, a healthy same-site peer is available — the ONLY thing
        // missing is a user ASN. The plugin must refuse to advertise rather
        // than synthesize one.
        let plugin = BgpLbPlugin::new(
            BgpLbConfig::enabled("site-a", None).with_peer(Peer::new("n1", "site-a")),
        );
        assert!(plugin.is_enabled());
        assert_eq!(plugin.config().asn, None);
        assert_eq!(
            plugin.elect_advertiser(&fe(), &health(&[("n1", true)])),
            None,
            "no ASN configured ⇒ no advertisement, never a synthesized pillar ASN"
        );
    }
}
