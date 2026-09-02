//! `pillar topology`/`topo` and `pillar node <placement>`: the CLI-side
//! topology command family (`cli-topology-impl`).
//!
//! Built directly over the proven [`pillar_topology`] engine
//! (`topology-label-hierarchy-impl`) and — for attested labels — the exact
//! [`pillar_trust_artifacts`] attest artifact it already reuses, never a
//! second trust primitive. Signed acts are recorded as ONE signed event on
//! the streaming DB ([`pillar_eventlog::EventLog`], the same signed-event
//! substrate `apply` emits into); views fold that log and sign nothing.
//!
//! # Views vs. acts (docs/cli-surface.md §1), enforced by construction
//!
//! Every method is exactly one kind, visible in its receiver:
//!
//! - **Views** take `&self` and NEVER append a signed event: `tree`, `tiers`
//!   (list), `ls`, `show`, `diff`, `rollup`, and `node locate`.
//! - **Acts** take `&mut self` and are the ONLY place a signed topology
//!   label/attestation event is recorded: `tiers set`/`add`/`rm`, `attest`,
//!   and `node label`/`place`/`move`. `attest` emits an attested topology
//!   label under the signer's declared capacity (verified through the shared
//!   [`TrustStore`]); the rest emit self-declared (advisory) label events.
//!
//! An act's event count strictly increases by exactly one; a view leaves it
//! untouched. That structural split — not a convention — is what the tests
//! below pin.

#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;

use pillar_core::NodeId;
use pillar_eventlog::{Author, EventId, EventLog};
use pillar_topology::{Assignment, Label, Mismatch, TierError, TierHierarchy, Topology};
use pillar_trust_artifacts::{Cid as TrustCid, TrustStore};

/// One rendered line of the derived tier nesting for `pillar topology tree`:
/// a tier value at its hierarchy depth (0 = coarsest), with the node ids that
/// land under it. A pure VIEW rendering — computing it signs nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeRow {
    /// The tier this value belongs to (e.g. `"rack"`).
    pub tier: String,
    /// The value at that tier (e.g. `"r12"`).
    pub value: String,
    /// The tier's depth in the active hierarchy (0 = coarsest failure domain).
    pub depth: usize,
}

/// Why a `pillar topology`/`node` act was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopologyCliError {
    /// A tier-hierarchy mutation was refused by the engine.
    Tier(TierError),
    /// An attested-label assignment could not be recorded (wrong action,
    /// malformed label, unknown tier, or an unverified attestation chain).
    Attest(pillar_topology::TopologyError),
    /// A referenced tier is not a member of the active hierarchy.
    UnknownTier(String),
}

impl From<TierError> for TopologyCliError {
    fn from(e: TierError) -> Self {
        TopologyCliError::Tier(e)
    }
}

impl From<pillar_topology::TopologyError> for TopologyCliError {
    fn from(e: pillar_topology::TopologyError) -> Self {
        TopologyCliError::Attest(e)
    }
}

/// `pillar topology …`/`topo …` and the `pillar node <placement>` verbs over
/// one [`Topology`] registry plus a streaming-DB [`EventLog`]: views fold the
/// registry and sign nothing; acts mutate the registry AND record exactly one
/// signed event.
pub struct TopologyCli {
    topo: Topology,
    log: EventLog,
}

impl TopologyCli {
    /// A fresh topology CLI over `hierarchy`, with no assignments and an empty
    /// signed-event log.
    #[must_use]
    pub fn new(hierarchy: TierHierarchy) -> Self {
        TopologyCli {
            topo: Topology::new(hierarchy),
            log: EventLog::new(),
        }
    }

    /// The number of signed events emitted so far — the streaming-DB log
    /// length. A view NEVER changes it; only an act does. Tests assert an act
    /// bumps this by exactly one and a view leaves it fixed.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.log.len()
    }

    /// Read access to the underlying [`Topology`] registry, for callers that
    /// drive placement (`spread`/`quorum_is_safe`) off the same derived state.
    #[must_use]
    pub fn topology(&self) -> &Topology {
        &self.topo
    }

    /// Emit exactly ONE signed event for an act, authored by `signer`, whose
    /// payload is the human-legible act description. Returns its id.
    fn emit(&mut self, signer: &NodeId, payload: String) -> EventId {
        let author = Author(signer.0.clone());
        self.log.append(&author, payload.into_bytes())
    }

    // -- tiers: the config-ordered hierarchy (set is an act; list a view) ---

    /// `pillar topology tiers set <t1,t2,…> --as <signer>` — an ACT: replace
    /// the hierarchy with an explicit ordered tier list (coarsest first),
    /// emitting one signed event. A reorder-only change should use the
    /// engine's permutation path; `set` installs a wholly new order.
    pub fn tiers_set(
        &mut self,
        signer: &NodeId,
        order: Vec<String>,
    ) -> Result<(), TopologyCliError> {
        let hierarchy = TierHierarchy::from_order(order.clone())
            .ok_or_else(|| TopologyCliError::UnknownTier(order.join(",")))?;
        *self.topo.hierarchy_mut() = hierarchy;
        self.emit(signer, format!("topology tiers set {}", order.join(",")));
        Ok(())
    }

    /// `pillar topology tiers add <tier> --after <anchor> --as <signer>` — an
    /// ACT: insert a custom tier immediately after `anchor` (e.g. `pdu` after
    /// `rack`), emitting one signed event. The new order is respected by every
    /// downstream nesting/rollup computation.
    pub fn tiers_add(
        &mut self,
        signer: &NodeId,
        after: &str,
        tier: &str,
    ) -> Result<(), TopologyCliError> {
        self.topo.hierarchy_mut().insert_after(after, tier)?;
        self.emit(signer, format!("topology tiers add {tier} after {after}"));
        Ok(())
    }

    /// `pillar topology tiers rm <tier> --as <signer>` — an ACT: drop a tier
    /// from the hierarchy (a reorder to the remaining tiers), emitting one
    /// signed event. Refused if `tier` is not a member.
    pub fn tiers_rm(&mut self, signer: &NodeId, tier: &str) -> Result<(), TopologyCliError> {
        if self.topo.hierarchy().rank(tier).is_none() {
            return Err(TopologyCliError::UnknownTier(tier.to_owned()));
        }
        let remaining: Vec<String> = self
            .topo
            .hierarchy()
            .tiers()
            .iter()
            .filter(|t| t.as_str() != tier)
            .cloned()
            .collect();
        let hierarchy = TierHierarchy::from_order(remaining)
            .ok_or_else(|| TopologyCliError::UnknownTier(tier.to_owned()))?;
        *self.topo.hierarchy_mut() = hierarchy;
        self.emit(signer, format!("topology tiers rm {tier}"));
        Ok(())
    }

    /// `pillar topology tiers` — a VIEW: the active hierarchy in canonical
    /// order (coarsest first). Signs nothing.
    #[must_use]
    pub fn tiers(&self) -> Vec<String> {
        self.topo.hierarchy().tiers().to_vec()
    }

    // -- attest: an attested topology label (reuses the attest artifact) ----

    /// `pillar topology attest <node> --at <tier>/<value> --as <role>@<scope>`
    /// — an ACT: record an attested topology label for `node`, VERIFYING the
    /// attestation's chain through `store` first (the exact
    /// [`pillar_trust_artifacts`] attest artifact, no new signing primitive).
    /// On success one signed event is emitted; on a verification failure
    /// NOTHING is mutated and no event is logged.
    ///
    /// The caller builds the [`Assignment::attested`] (naming the signer's
    /// held `capacity`, the authority proof, `scope`, and epoch) exactly as
    /// `pillar attest` does; this records it under the declared capacity.
    ///
    /// # Errors
    /// [`TopologyCliError::Attest`] if the assignment is not attested, carries
    /// the wrong action/label, names an unknown tier, or its chain does not
    /// verify.
    pub fn attest(
        &mut self,
        signer: &NodeId,
        assignment: &Assignment,
        store: &TrustStore,
    ) -> Result<(), TopologyCliError> {
        // Verify-and-record: the engine refuses an unverified chain, leaving
        // the registry untouched, so we emit the signed event only on success.
        self.topo.attest(assignment, store)?;
        let node = assignment.node().clone();
        self.emit(
            signer,
            format!("topology attest {} (attested label)", node.0),
        );
        Ok(())
    }

    /// Whether `assignment` verifies through `store` — a pure VIEW gating
    /// safety-critical placement on attested labels (signs nothing).
    #[must_use]
    pub fn verify_attested(&self, assignment: &Assignment, store: &TrustStore) -> bool {
        self.topo.verify_attested(assignment, store)
    }

    // -- diff / show / ls / tree / rollup: pure views -----------------------

    /// `pillar topology diff` — a VIEW: every declared-vs-attested
    /// [`Mismatch`] (where a node's self-declared value disagrees with the
    /// authority's attested one). Empty when a node self-declares only, or
    /// declared matches attested. Signs nothing.
    #[must_use]
    pub fn diff(&self) -> Vec<Mismatch> {
        self.topo.mismatches()
    }

    /// `pillar topology show <tier>/<value>` — a VIEW: the node ids whose
    /// resolved placement lands on `value` at `tier` among `nodes`
    /// (attested-then-declared). Signs nothing.
    #[must_use]
    pub fn show(&self, tier: &str, value: &str, nodes: &[NodeId]) -> Vec<NodeId> {
        nodes
            .iter()
            .filter(|n| self.topo.placement(n).at(tier) == Some(value))
            .cloned()
            .collect()
    }

    /// `pillar topology ls <tier>` — a VIEW: the distinct failure-domain
    /// values present at `tier` across `nodes`. Signs nothing.
    #[must_use]
    pub fn ls(&self, tier: &str, nodes: &[NodeId]) -> Vec<String> {
        self.topo.domains_at(tier, nodes).into_iter().collect()
    }

    /// `pillar topology tree [--tier <t>]` — a VIEW: the derived nesting of
    /// `nodes` as tier-value rows, ordered by the CONFIGURED hierarchy depth
    /// (coarsest first). With `only_tier` set, restrict to that one tier's
    /// values. Renders the config-ordered hierarchy — an operator sees the
    /// nesting the active order derives, not a hardcoded one. Signs nothing.
    #[must_use]
    pub fn tree(&self, nodes: &[NodeId], only_tier: Option<&str>) -> Vec<TreeRow> {
        let hierarchy = self.topo.hierarchy();
        let mut rows = Vec::new();
        for (depth, tier) in hierarchy.tiers().iter().enumerate() {
            if let Some(t) = only_tier {
                if t != tier {
                    continue;
                }
            }
            let mut values: Vec<String> = self.topo.domains_at(tier, nodes).into_iter().collect();
            values.sort();
            for value in values {
                rows.push(TreeRow {
                    tier: tier.clone(),
                    value,
                    depth,
                });
            }
        }
        rows
    }

    /// `pillar topology rollup <tier> --metric <m>` — a VIEW: aggregate a
    /// per-node metric up to `tier`, summing each node's value into the
    /// failure domain that contains it (config-ordered placement). Signs
    /// nothing.
    #[must_use]
    pub fn rollup(&self, tier: &str, values: &[(NodeId, u64)]) -> BTreeMap<String, u64> {
        self.topo.rollup(tier, values)
    }

    // -- node placement verbs ----------------------------------------------

    /// `pillar node label <node> <tier>=<value>[,…] --as <signer>` — an ACT:
    /// record self-declared (advisory) labels for `node`, emitting one signed
    /// event. Labels naming a tier outside the hierarchy are ignored by the
    /// engine.
    pub fn node_label(&mut self, signer: &NodeId, node: &NodeId, labels: &[Label]) {
        self.topo.declare(node.clone(), labels);
        let rendered = labels
            .iter()
            .map(Label::resource)
            .collect::<Vec<_>>()
            .join(",");
        self.emit(signer, format!("node label {} {rendered}", node.0));
    }

    /// `pillar node place <node> --under <tier>/<value> --as <signer>` — an
    /// ACT: place `node` under one failure domain (a single self-declared
    /// label), emitting one signed event.
    pub fn node_place(&mut self, signer: &NodeId, node: &NodeId, tier: &str, value: &str) {
        self.node_label(signer, node, &[Label::new(tier, value)]);
    }

    /// `pillar node move <node> --to <tier>/<value> --as <signer>` — an ACT:
    /// re-place `node` at a new value for `tier` (a self-declared relabel),
    /// emitting one signed event. Semantically identical to a re-`place`; the
    /// verb records operator intent (a move, not an initial placement) in the
    /// signed event payload.
    pub fn node_move(&mut self, signer: &NodeId, node: &NodeId, tier: &str, value: &str) {
        self.topo.declare(node.clone(), &[Label::new(tier, value)]);
        self.emit(signer, format!("node move {} to {tier}={value}", node.0));
    }

    /// `pillar node locate <node>` — a VIEW: the node's resolved placement as
    /// `<tier>=<value>` labels, coarsest-tier-first per the active hierarchy
    /// (attested-then-declared). Signs nothing — a pure view.
    #[must_use]
    pub fn locate(&self, node: &NodeId) -> Vec<Label> {
        self.topo.placement(node).path(self.topo.hierarchy())
    }

    /// The id of the trust artifact an attested assignment carries, for a
    /// caller that wants to cross-reference the label's attestation with
    /// `pillar audit` — a pure VIEW helper.
    #[must_use]
    pub fn attestation_cid(assignment: &Assignment) -> Option<TrustCid> {
        match assignment {
            Assignment::Attested { cid, .. } => Some(cid.clone()),
            Assignment::Declared { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pillar_trust_artifacts::{Attest, Capacity, Predicate, Sig};

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn hierarchy() -> TierHierarchy {
        TierHierarchy::from_order(["zone", "rack", "node"]).unwrap()
    }

    fn role(r: &str, s: &str) -> Capacity {
        Capacity::Role {
            role: r.to_owned(),
            scope: s.to_owned(),
        }
    }

    /// Build a verifiable attested topology label the same way
    /// `pillar attest` builds one: grant the authority the signing capacity
    /// from genesis, then attest the `<tier>=<value>` label.
    fn attested(
        store: &mut TrustStore,
        authority: &NodeId,
        node: &NodeId,
        label: &Label,
    ) -> Assignment {
        let grant = Attest {
            issuer: n("owner"),
            capacity: role("cell-authority", "cell-b"),
            authority: None,
            subject: authority.clone(),
            predicate: Predicate::new("topology:sign", "cell-b/*"),
            scope: "cell-b".to_owned(),
            epoch: store.epoch(),
            sig: Sig::sign_as(NodeId::from(""), b""),
        }
        .signed_by_issuer();
        let grant_cid = store.issue_attest(grant).unwrap();
        let a = Assignment::attested(
            authority.clone(),
            node.clone(),
            label,
            role("cell-authority", "cell-b"),
            Some(grant_cid),
            "cell-b",
            store.epoch(),
        );
        if let Assignment::Attested { attest, .. } = &a {
            store.issue_attest((**attest).clone()).unwrap();
        }
        a
    }

    // -- tree renders derived nesting per configured order + tiers add ------

    #[test]
    fn tree_renders_derived_nesting_per_configured_order_and_tiers_add_reflected() {
        let signer = n("op");
        let mut cli = TopologyCli::new(hierarchy());
        cli.node_label(
            &signer,
            &n("a"),
            &[Label::new("zone", "z1"), Label::new("rack", "r1")],
        );
        cli.node_label(
            &signer,
            &n("b"),
            &[Label::new("zone", "z1"), Label::new("rack", "r2")],
        );
        let nodes = [n("a"), n("b")];

        // Tree is ordered by the CONFIGURED hierarchy depth: zone(0) before
        // rack(1) — the derived nesting, not a hardcoded order.
        let rows = cli.tree(&nodes, None);
        let depths: Vec<usize> = rows.iter().map(|r| r.depth).collect();
        assert!(depths.windows(2).all(|w| w[0] <= w[1]), "coarsest-first");
        assert!(rows.iter().any(|r| r.tier == "zone" && r.value == "z1"));
        assert!(rows.iter().any(|r| r.tier == "rack" && r.value == "r1"));
        assert!(rows.iter().any(|r| r.tier == "rack" && r.value == "r2"));

        // `tiers add pdu after rack` is reflected in the tree ordering.
        let before = cli.event_count();
        cli.tiers_add(&signer, "rack", "pdu").unwrap();
        assert_eq!(cli.event_count(), before + 1, "an act emits one event");
        cli.node_label(&signer, &n("a"), &[Label::new("pdu", "p1")]);
        let rows = cli.tree(&[n("a"), n("b")], None);
        // pdu sits between rack and node in depth.
        let pdu_depth = rows.iter().find(|r| r.tier == "pdu").unwrap().depth;
        let rack_depth = rows.iter().find(|r| r.tier == "rack").unwrap().depth;
        assert!(rack_depth < pdu_depth, "pdu nests under rack after add");
    }

    // -- attest verifies against signer capacity + diff self-declared-only --

    #[test]
    fn attest_verifies_against_signer_capacity_and_diff_shows_none_then_mismatch() {
        let signer = n("cell-b-authority");
        let mut store = TrustStore::new(n("owner"));
        let mut cli = TopologyCli::new(hierarchy());

        // A node self-declares rack r1 — advisory only; with no attestation
        // diff shows no mismatch (self-declared-only).
        cli.node_label(&signer, &n("node-7"), &[Label::new("rack", "r1")]);
        assert!(cli.diff().is_empty(), "self-declared-only: no mismatch");

        // The authority attests the TRUTH: rack r7. verify_attested passes
        // against the signer's held capacity; the act emits one event.
        let assignment = attested(&mut store, &signer, &n("node-7"), &Label::new("rack", "r7"));
        assert!(cli.verify_attested(&assignment, &store));
        let before = cli.event_count();
        cli.attest(&signer, &assignment, &store).unwrap();
        assert_eq!(cli.event_count(), before + 1);

        // Now declared(r1) vs attested(r7) is a surfaced mismatch.
        let mm = cli.diff();
        assert_eq!(mm.len(), 1);
        assert_eq!(mm[0].tier, "rack");
        assert_eq!(mm[0].declared, "r1");
        assert_eq!(mm[0].attested, "r7");
    }

    #[test]
    fn attest_refuses_an_unverified_chain_and_emits_no_event() {
        let signer = n("rogue");
        let store = TrustStore::new(n("owner"));
        let mut cli = TopologyCli::new(hierarchy());
        // An attest whose authority chain was never issued into the store.
        let assignment = Assignment::attested(
            n("rogue"),
            n("node-9"),
            &Label::new("rack", "r9"),
            role("cell-authority", "cell-b"),
            Some(pillar_trust_artifacts::Cid("trust:phantom".to_owned())),
            "cell-b",
            0,
        );
        assert!(!cli.verify_attested(&assignment, &store));
        let err = cli.attest(&signer, &assignment, &store).unwrap_err();
        assert!(matches!(err, TopologyCliError::Attest(_)));
        // Nothing mutated: no signed event on an unverified attestation.
        assert_eq!(cli.event_count(), 0);
    }

    // -- rollup aggregates by rack ------------------------------------------

    #[test]
    fn rollup_rack_metric_power_aggregates_by_rack() {
        let signer = n("op");
        let mut cli = TopologyCli::new(hierarchy());
        cli.node_label(&signer, &n("a"), &[Label::new("rack", "r1")]);
        cli.node_label(&signer, &n("b"), &[Label::new("rack", "r1")]);
        cli.node_label(&signer, &n("c"), &[Label::new("rack", "r2")]);
        let before = cli.event_count();

        // rollup is a VIEW: it signs nothing.
        let power = vec![(n("a"), 100), (n("b"), 50), (n("c"), 70)];
        let by_rack = cli.rollup("rack", &power);
        assert_eq!(by_rack.get("r1"), Some(&150));
        assert_eq!(by_rack.get("r2"), Some(&70));
        assert_eq!(cli.event_count(), before, "a view emits no event");
    }

    // -- node place/move emit signed events + locate is a pure view ---------

    #[test]
    fn node_place_and_move_emit_signed_events_and_locate_is_a_pure_view() {
        let signer = n("op");
        let mut cli = TopologyCli::new(hierarchy());

        assert_eq!(cli.event_count(), 0);
        cli.node_place(&signer, &n("n1"), "rack", "r1");
        assert_eq!(cli.event_count(), 1, "place emits one signed event");
        cli.node_move(&signer, &n("n1"), "rack", "r2");
        assert_eq!(cli.event_count(), 2, "move emits one signed event");

        // The emitted events are authentic (signed by the actor).
        let tip = cli.log.tip(&Author("op".to_owned())).expect("has a tip");
        let ev = cli.log.get(&tip).expect("event exists");
        assert!(ev.is_authentic());
        assert_eq!(ev.content().author().0, "op");

        // locate is a pure view: reflects the move, signs nothing.
        let before = cli.event_count();
        let placement = cli.locate(&n("n1"));
        assert_eq!(placement, vec![Label::new("rack", "r2")]);
        assert_eq!(cli.event_count(), before, "locate emits no event");
    }

    // -- view verbs emit no signed event ------------------------------------

    #[test]
    fn view_verbs_emit_no_signed_event() {
        let signer = n("op");
        let mut cli = TopologyCli::new(hierarchy());
        cli.node_label(&signer, &n("a"), &[Label::new("rack", "r1")]);
        cli.node_label(&signer, &n("b"), &[Label::new("rack", "r2")]);
        let nodes = [n("a"), n("b")];
        let fixed = cli.event_count();

        // Every view leaves the signed-event log untouched.
        let _ = cli.tiers();
        let _ = cli.tree(&nodes, None);
        let _ = cli.tree(&nodes, Some("rack"));
        let _ = cli.ls("rack", &nodes);
        let _ = cli.show("rack", "r1", &nodes);
        let _ = cli.diff();
        let _ = cli.rollup("rack", &[(n("a"), 1), (n("b"), 2)]);
        let _ = cli.locate(&n("a"));
        assert_eq!(cli.event_count(), fixed, "no view signs anything");
    }

    #[test]
    fn tiers_set_and_rm_are_acts_reflected_in_the_hierarchy() {
        let signer = n("op");
        let mut cli = TopologyCli::new(hierarchy());
        cli.tiers_set(
            &signer,
            vec![
                "region".to_owned(),
                "zone".to_owned(),
                "rack".to_owned(),
                "node".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(cli.event_count(), 1);
        assert_eq!(cli.tiers(), vec!["region", "zone", "rack", "node"]);

        cli.tiers_rm(&signer, "region").unwrap();
        assert_eq!(cli.event_count(), 2);
        assert_eq!(cli.tiers(), vec!["zone", "rack", "node"]);

        // Removing an unknown tier is refused, nothing mutated.
        let err = cli.tiers_rm(&signer, "nope").unwrap_err();
        assert!(matches!(err, TopologyCliError::UnknownTier(_)));
        assert_eq!(cli.event_count(), 2);
    }

    #[test]
    fn ls_and_show_render_the_derived_domains() {
        let signer = n("op");
        let mut cli = TopologyCli::new(hierarchy());
        cli.node_label(&signer, &n("a"), &[Label::new("rack", "r1")]);
        cli.node_label(&signer, &n("b"), &[Label::new("rack", "r1")]);
        cli.node_label(&signer, &n("c"), &[Label::new("rack", "r2")]);
        let nodes = [n("a"), n("b"), n("c")];

        assert_eq!(cli.ls("rack", &nodes), vec!["r1", "r2"]);
        assert_eq!(cli.show("rack", "r1", &nodes), vec![n("a"), n("b")]);
        assert_eq!(cli.show("rack", "r2", &nodes), vec![n("c")]);
    }
}
