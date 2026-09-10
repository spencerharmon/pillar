//! Optional, off-by-default hop-minimizing placement optimizer — a MODE of the
//! single scheduler engine, NOT a second scheduler.
//!
//! # What it is
//!
//! An application declares `placement: { optimize: min-hops }` alongside the
//! existing spread / anti-affinity placement directives. When that mode is on,
//! this optimizer consumes the **traffic-weighted hop view** (per-backend, how
//! much traffic it exchanges with each ingest failure domain, and how many
//! topology hops separate two failure domains) and proposes moving backends
//! toward the failure domain where their traffic concentrates — pulling
//! backends toward ingest locality so aggregate traffic-weighted hop length
//! across the application falls.
//!
//! It is a **heuristic over topology failure domains** ([`TierHierarchy`]),
//! introducing NO new authority and NO new TLA gate. The hop distance between
//! two domains is the coarse structural distance the shared tier hierarchy
//! already defines (see [`hierarchy_hops`]); the traffic weights are supplied
//! by the caller (the `pillar_message_hops` metric view). Everything here is a
//! pure, deterministic value computation — nothing reaches the network or the
//! filesystem.
//!
//! # The bounds (never traded away)
//!
//! Hop minimization is **subordinate** to the failure-domain guarantees. A
//! proposed move is applied ONLY if it keeps the application within EVERY
//! declared constraint:
//!
//! - **spread / anti-affinity** — the count of distinct failure-domain values
//!   the application occupies at the spread tier may never drop below the
//!   declared minimum (never collapse a quorum into one rack);
//! - **capacity** — a target domain that is already at its declared capacity
//!   cannot receive another backend.
//!
//! A move that would violate any bound is rejected; the optimizer settles for
//! the best move that stays inside the envelope, or makes no move at all. So
//! `optimize: min-hops` can only ever *reduce* aggregate hops **without**
//! violating the declared spread/anti-affinity/capacity — the acceptance
//! contract of this task.
//!
//! # Throttled & reversible
//!
//! Real traffic oscillates; a naive optimizer would thrash a backend back and
//! forth every time the load shifts. Two guards prevent that:
//!
//! - **throttle** — each optimization round moves at most [`Plan::max_moves`]
//!   backends, so a burst cannot rip an application apart in one step;
//! - **hysteresis** — a move is proposed only if it improves aggregate hops by
//!   more than [`Plan::min_improvement`]. A trivial or oscillation-scale gain
//!   is ignored, so equal-and-opposite traffic swings do not ping-pong a
//!   backend (a move and its immediate reverse both fail the threshold).

use std::collections::BTreeMap;

use pillar_topology::TierHierarchy;

/// A failure-domain value at a fixed tier — e.g. the `rack` value `"r7"`. The
/// optimizer places backends onto these; the tier they belong to is fixed for
/// one optimization (the tier the application spreads/optimizes over).
pub type Domain = String;

/// A backend instance the optimizer may relocate, identified by an opaque id.
pub type Backend = String;

/// The traffic-weighted hop view the optimizer consumes: for each backend, how
/// much traffic (a weight, e.g. bytes or message count from the
/// `pillar_message_hops` metric) it exchanges with each ingest failure domain.
///
/// This is the ONLY traffic input; the optimizer never re-derives hop counts
/// itself — it reads this view plus the structural [`TierHierarchy`] distance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrafficView {
    /// `backend -> (ingest domain -> traffic weight)`.
    per_backend: BTreeMap<Backend, BTreeMap<Domain, u64>>,
}

impl TrafficView {
    /// An empty view.
    #[must_use]
    pub fn new() -> TrafficView {
        TrafficView {
            per_backend: BTreeMap::new(),
        }
    }

    /// Record that `backend` exchanges `weight` traffic with ingest `domain`.
    /// Additive: repeated calls for the same pair accumulate.
    pub fn observe(
        &mut self,
        backend: impl Into<Backend>,
        domain: impl Into<Domain>,
        weight: u64,
    ) {
        *self
            .per_backend
            .entry(backend.into())
            .or_default()
            .entry(domain.into())
            .or_insert(0) += weight;
    }

    /// The traffic a backend exchanges with each ingest domain.
    #[must_use]
    pub fn backend_traffic(&self, backend: &str) -> Option<&BTreeMap<Domain, u64>> {
        self.per_backend.get(backend)
    }
}

/// The current placement of an application's backends onto failure domains at a
/// single tier, plus the declared bounds the optimizer must respect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The tier the application spreads/optimizes over (e.g. `"rack"`). Both
    /// the placement domains and the ingest domains in the [`TrafficView`] are
    /// values at THIS tier.
    tier: String,
    /// `backend -> the domain it currently occupies`.
    assignment: BTreeMap<Backend, Domain>,
    /// The declared MINIMUM number of distinct domains the application must
    /// remain spread across at `tier` (the spread / anti-affinity floor). A
    /// move that would drop the occupied-domain count below this is rejected.
    min_spread: usize,
    /// `domain -> its capacity` (max backends it may hold). A domain absent
    /// from the map is treated as unbounded; the optimizer never overfills a
    /// bounded one.
    capacity: BTreeMap<Domain, usize>,
}

impl Placement {
    /// A placement over `tier` with the given backend assignment. `min_spread`
    /// is the spread/anti-affinity floor (clamped to at least 1); `capacity`
    /// caps how many backends each named domain may hold.
    #[must_use]
    pub fn new(
        tier: impl Into<String>,
        assignment: BTreeMap<Backend, Domain>,
        min_spread: usize,
        capacity: BTreeMap<Domain, usize>,
    ) -> Placement {
        Placement {
            tier: tier.into(),
            assignment,
            min_spread: min_spread.max(1),
            capacity,
        }
    }

    /// The tier this placement spreads/optimizes over.
    #[must_use]
    pub fn tier(&self) -> &str {
        &self.tier
    }

    /// The domain a backend currently occupies.
    #[must_use]
    pub fn domain_of(&self, backend: &str) -> Option<&str> {
        self.assignment.get(backend).map(String::as_str)
    }

    /// The set of distinct domains currently occupied.
    #[must_use]
    fn occupied_domains(&self) -> std::collections::BTreeSet<&str> {
        self.assignment.values().map(String::as_str).collect()
    }

    /// How many backends currently occupy `domain`.
    #[must_use]
    fn load_of(&self, domain: &str) -> usize {
        self.assignment.values().filter(|d| *d == domain).count()
    }

    /// Whether `domain` has room for one more backend (unbounded if it has no
    /// declared capacity).
    #[must_use]
    fn has_room(&self, domain: &str) -> bool {
        match self.capacity.get(domain) {
            Some(&cap) => self.load_of(domain) < cap,
            None => true,
        }
    }

    /// Whether moving `backend` OUT of its current domain would leave the
    /// application spread across fewer than `min_spread` distinct domains — the
    /// spread/anti-affinity guard. Moving INTO an already-occupied domain and
    /// vacating the only backend of its current domain is the only way spread
    /// shrinks.
    #[must_use]
    fn move_preserves_spread(&self, backend: &str, to: &str) -> bool {
        let mut after = self.assignment.clone();
        after.insert(backend.to_owned(), to.to_owned());
        let distinct = after
            .values()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        distinct >= self.min_spread
    }
}

/// The parameters that make the optimizer throttled and reversible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The MAX number of backends this round may relocate (throttle). One burst
    /// of shifting traffic can never move more than this at once.
    pub max_moves: usize,
    /// The MINIMUM aggregate-hop improvement a move must yield to be applied
    /// (hysteresis). A move whose gain does not exceed this is ignored, so
    /// equal-and-opposite traffic swings cannot ping-pong a backend.
    pub min_improvement: u64,
}

impl Plan {
    /// A plan with the given throttle and hysteresis.
    #[must_use]
    pub fn new(max_moves: usize, min_improvement: u64) -> Plan {
        Plan {
            max_moves,
            min_improvement,
        }
    }
}

impl Default for Plan {
    /// A conservative default: at most one move per round, requiring a strictly
    /// positive improvement.
    fn default() -> Plan {
        Plan {
            max_moves: 1,
            min_improvement: 1,
        }
    }
}

/// One relocation the optimizer decided to apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Move {
    /// The backend relocated.
    pub backend: Backend,
    /// The domain it left.
    pub from: Domain,
    /// The domain it moved to.
    pub to: Domain,
    /// The aggregate traffic-weighted hop reduction this move produced
    /// (strictly `> plan.min_improvement`).
    pub improvement: u64,
}

/// The coarse **structural hop distance** between two failure-domain values at
/// one tier, derived purely from the shared [`TierHierarchy`] — NO new
/// authority, NO metric re-derivation.
///
/// Two backends in the SAME domain are 0 hops apart. Two DISTINCT domains at
/// the same tier are separated by twice the tier's depth below the root: a
/// message climbs from a leaf domain up to the common ancestor and back down,
/// and the deeper (finer) the tier, the more structural hops distinct values at
/// it are apart. Concretely `distinct-domain hops = 2 * (rank + 1)` where
/// `rank` is the tier's position in the hierarchy (0 = coarsest). This gives a
/// deterministic, hierarchy-ordered distance: distinct racks (deep) are more
/// hops apart than distinct zones (shallow), matching real mesh locality.
#[must_use]
pub fn hierarchy_hops(hierarchy: &TierHierarchy, tier: &str, a: &str, b: &str) -> u64 {
    if a == b {
        return 0;
    }
    match hierarchy.rank(tier) {
        Some(rank) => 2 * (rank as u64 + 1),
        // A tier the hierarchy does not know contributes a flat unit distance
        // between distinct domains rather than pretending they are co-located.
        None => 2,
    }
}

/// The aggregate traffic-weighted hop length of the whole application under a
/// given assignment: for every backend, every ingest domain it exchanges
/// traffic with contributes `weight * hops(backend-domain, ingest-domain)`.
/// Lower is better; minimizing THIS is the optimizer's objective.
#[must_use]
fn aggregate_hops(
    hierarchy: &TierHierarchy,
    tier: &str,
    assignment: &BTreeMap<Backend, Domain>,
    traffic: &TrafficView,
) -> u64 {
    let mut total = 0u64;
    for (backend, domain) in assignment {
        if let Some(per_ingest) = traffic.backend_traffic(backend) {
            for (ingest_domain, weight) in per_ingest {
                total = total
                    .saturating_add(weight.saturating_mul(hierarchy_hops(
                        hierarchy,
                        tier,
                        domain,
                        ingest_domain,
                    )));
            }
        }
    }
    total
}

/// The public aggregate traffic-weighted hop length of a placement — the metric
/// the acceptance test asserts the optimizer reduces.
#[must_use]
pub fn aggregate_placement_hops(
    hierarchy: &TierHierarchy,
    placement: &Placement,
    traffic: &TrafficView,
) -> u64 {
    aggregate_hops(hierarchy, &placement.tier, &placement.assignment, traffic)
}

/// The hop-minimizing optimizer — the `optimize: min-hops` MODE. Off by default
/// (a placement without the directive simply never calls [`Optimizer::optimize`]);
/// bounded by the placement's spread/anti-affinity/capacity; throttled and
/// reversible by its [`Plan`].
#[derive(Clone, Debug)]
pub struct Optimizer {
    hierarchy: TierHierarchy,
    plan: Plan,
}

impl Optimizer {
    /// A new optimizer over `hierarchy` with the given throttle/hysteresis plan.
    #[must_use]
    pub fn new(hierarchy: TierHierarchy, plan: Plan) -> Optimizer {
        Optimizer { hierarchy, plan }
    }

    /// Run ONE optimization round: greedily relocate backends toward ingest
    /// locality to reduce aggregate traffic-weighted hops, applying the moves
    /// to `placement` in place and returning them in order.
    ///
    /// Every returned move is guaranteed to:
    /// - strictly reduce aggregate hops by MORE than `plan.min_improvement`
    ///   (hysteresis — no oscillation);
    /// - keep the application spread across at least `min_spread` distinct
    ///   domains (spread / anti-affinity bound — never collapses a quorum);
    /// - land only in a domain with capacity to spare (capacity bound).
    ///
    /// At most `plan.max_moves` moves are made (throttle). If no move clears the
    /// bounds and the hysteresis threshold, the placement is left untouched and
    /// an empty vec is returned.
    #[must_use]
    pub fn optimize(&self, placement: &mut Placement, traffic: &TrafficView) -> Vec<Move> {
        let mut moves = Vec::new();

        while moves.len() < self.plan.max_moves {
            let current = aggregate_hops(
                &self.hierarchy,
                &placement.tier,
                &placement.assignment,
                traffic,
            );

            // The candidate target domains are every domain currently occupied
            // by SOME backend (the failure domains the application already
            // spans) — we relocate toward ingest locality among those, never
            // inventing a brand-new domain the operator never declared.
            let target_domains: Vec<Domain> =
                placement.occupied_domains().iter().map(|d| (*d).to_owned()).collect();

            let mut best: Option<Move> = None;

            for backend in placement.assignment.keys().cloned().collect::<Vec<_>>() {
                let from = placement.assignment[&backend].clone();
                for to in &target_domains {
                    if *to == from {
                        continue;
                    }
                    // Capacity bound.
                    if !placement.has_room(to) {
                        continue;
                    }
                    // Spread / anti-affinity bound.
                    if !placement.move_preserves_spread(&backend, to) {
                        continue;
                    }
                    // Evaluate the aggregate-hop delta of this single move.
                    let mut trial = placement.assignment.clone();
                    trial.insert(backend.clone(), to.clone());
                    let after = aggregate_hops(&self.hierarchy, &placement.tier, &trial, traffic);
                    if after >= current {
                        continue; // not an improvement
                    }
                    let improvement = current - after;
                    // Hysteresis: only a MORE-than-threshold gain is worth a move.
                    if improvement <= self.plan.min_improvement {
                        continue;
                    }
                    let candidate = Move {
                        backend: backend.clone(),
                        from: from.clone(),
                        to: to.clone(),
                        improvement,
                    };
                    // Greedily keep the single best-improving move this pass.
                    let better = match &best {
                        None => true,
                        Some(b) => {
                            improvement > b.improvement
                                || (improvement == b.improvement && candidate < *b)
                        }
                    };
                    if better {
                        best = Some(candidate);
                    }
                }
            }

            match best {
                Some(m) => {
                    placement.assignment.insert(m.backend.clone(), m.to.clone());
                    moves.push(m);
                }
                None => break, // no bounded, above-threshold move remains
            }
        }

        moves
    }
}

// Make Move orderable so the greedy tie-break above is deterministic.
impl PartialOrd for Move {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Move {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.backend
            .cmp(&other.backend)
            .then_with(|| self.to.cmp(&other.to))
            .then_with(|| self.from.cmp(&other.from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hierarchy() -> TierHierarchy {
        TierHierarchy::default()
    }

    fn assignment(pairs: &[(&str, &str)]) -> BTreeMap<Backend, Domain> {
        pairs
            .iter()
            .map(|(b, d)| ((*b).to_owned(), (*d).to_owned()))
            .collect()
    }

    #[test]
    fn distinct_domains_are_farther_at_a_finer_tier() {
        let h = hierarchy();
        // rack (rank 5) is finer than zone (rank 1): distinct racks are more
        // structural hops apart than distinct zones.
        let rack = hierarchy_hops(&h, "rack", "r1", "r2");
        let zone = hierarchy_hops(&h, "zone", "z1", "z2");
        assert!(rack > zone, "rack {rack} should exceed zone {zone}");
        // Same domain is 0 hops.
        assert_eq!(hierarchy_hops(&h, "rack", "r1", "r1"), 0);
    }

    #[test]
    fn optimizer_pulls_a_backend_toward_concentrated_ingest_traffic() {
        // A backend on rack r2 whose traffic is concentrated on ingest rack r1
        // is pulled to r1, reducing aggregate hops.
        let h = hierarchy();
        let mut placement = Placement::new(
            "rack",
            assignment(&[("b1", "r2"), ("b2", "r1")]),
            1, // no spread floor to fight
            BTreeMap::new(),
        );
        let mut traffic = TrafficView::new();
        traffic.observe("b1", "r1", 100); // b1 talks heavily to r1
        traffic.observe("b2", "r1", 10);

        let before = aggregate_placement_hops(&h, &placement, &traffic);
        let opt = Optimizer::new(h.clone(), Plan::new(4, 0));
        let moves = opt.optimize(&mut placement, &traffic);
        let after = aggregate_placement_hops(&h, &placement, &traffic);

        assert!(!moves.is_empty(), "expected the backend to be relocated");
        assert_eq!(placement.domain_of("b1"), Some("r1"));
        assert!(after < before, "aggregate hops must fall: {before} -> {after}");
    }
}
