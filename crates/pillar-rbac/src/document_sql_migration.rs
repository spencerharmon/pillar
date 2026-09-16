//! `rbac-document-sql-migration`: rbac-decider's grant store on a
//! `pillar-keyedstore` Document collection, with a decider-facing SQL view
//! (`pillar-sqlviews`) folding the effective `(subject, capability)` grants.
//!
//! Per ROI Priority 1 data-layer doctrine, granting is ordinary AP data (a
//! Document put, folded/merged like any other collection row), but a
//! **revoke is a CP tombstone**: it rides
//! [`pillar_streamdb::cofold::StrictCofold`]'s co-partitioned, epoch-fenced
//! strict fold (`cp-viewpolicy-strict-cofold`) with a [`UniqueOnce`]
//! invariant, so a given grant key is admitted to revocation **at most
//! once, ever** — never a bare AP delete that a stale/concurrent grant
//! write could race back into effect (a revoke-then-stale-regrant would
//! otherwise leave a supposedly-revoked capability live again). The
//! decider's fail-closed precedence lattice
//! ([`RbacDecider`](crate::RbacDecider)) is UNCHANGED: this module only
//! supplies its `grants: &[ExplicitGrant]` input from the Document/SQL
//! layer instead of an in-memory `Vec` a caller assembled by hand.
//!
//! Query surface: `pillar sql`-queryable via the `effective_grants`
//! materialized view over the `rbac_grants` collection (created with
//! [`ensure_effective_grants_view`]), which any `pillar-sqlviews` consumer
//! (e.g. `pillar sql SELECT * FROM effective_grants`) can read directly —
//! no bespoke grant-store API to learn.

use std::collections::BTreeMap;

use pillar_coordination::LeaseRegister;
use pillar_core::{Epoch, NodeId};
use pillar_sqlviews::{create_view, materialize_view, Hlc, KeyedStore, Value, ViewDef};
use pillar_streamdb::cofold::{CoFoldError, StrictCofold, UniqueOnce};

use crate::{Capability, ExplicitGrant, GrantEffect};

/// The Document collection grants are stored in — one document per
/// `(subject, capability)` pair, keyed by [`grant_key`].
pub const GRANTS_COLLECTION: &str = "rbac_grants";

/// The decider-facing SQL view name folding every live grant document —
/// `pillar sql`-queryable, e.g. `SELECT * FROM effective_grants`.
pub const EFFECTIVE_GRANTS_VIEW: &str = "effective_grants";

const FIELD_SUBJECT: &str = "subject";
const FIELD_CAPABILITY: &str = "capability";
const FIELD_EFFECT: &str = "effect";

const EFFECT_ALLOW: &[u8] = b"allow";
const EFFECT_DENY: &[u8] = b"deny";

/// The stable Document id for a `(subject, capability)` grant: `"<subject>:<capability>"`.
/// Both a grant write and its eventual CP-tombstone revoke address the SAME
/// key, so a revoke always targets exactly the row it means to retire.
#[must_use]
pub fn grant_key(subject: &NodeId, capability: &Capability) -> String {
    format!("{}:{}", subject.0, capability.0)
}

fn effect_bytes(effect: GrantEffect) -> &'static [u8] {
    match effect {
        GrantEffect::Allow => EFFECT_ALLOW,
        GrantEffect::Deny => EFFECT_DENY,
    }
}

fn effect_from_bytes(b: &[u8]) -> Option<GrantEffect> {
    match b {
        EFFECT_ALLOW => Some(GrantEffect::Allow),
        EFFECT_DENY => Some(GrantEffect::Deny),
        _ => None,
    }
}

/// Write (or overwrite) an explicit grant as a Document row. Ordinary AP
/// data: the per-field LWW fold `pillar-keyedstore` already implements
/// resolves any concurrent write to the same key by highest HLC, exactly
/// like any other collection write — no CP coordination is needed to GRANT
/// a capability, only to REVOKE one (see [`revoke_grant`]).
pub fn put_grant(
    store: &mut KeyedStore,
    subject: &NodeId,
    capability: &Capability,
    effect: GrantEffect,
    hlc: Hlc,
) {
    let id = grant_key(subject, capability);
    store.doc_put_field(
        GRANTS_COLLECTION,
        &id,
        FIELD_SUBJECT,
        Value::Scalar(subject.0.to_string().into_bytes()),
        hlc.clone(),
    );
    store.doc_put_field(
        GRANTS_COLLECTION,
        &id,
        FIELD_CAPABILITY,
        Value::Scalar(capability.0.clone().into_bytes()),
        hlc.clone(),
    );
    store.doc_put_field(
        GRANTS_COLLECTION,
        &id,
        FIELD_EFFECT,
        Value::Scalar(effect_bytes(effect).to_vec()),
        hlc,
    );
}

/// Revoke a previously-granted `(subject, capability)`: admit the tombstone
/// through the co-partitioned [`StrictCofold<UniqueOnce>`] fence keyed by
/// [`grant_key`], so the SAME grant key can be revoked AT MOST ONCE ever
/// (uniqueness/exactly-once, `cp-viewpolicy-strict-cofold`). Only once the
/// cofold admits the tombstone does the Document row's fields actually get
/// deleted — a rejected admission (already revoked, or the caller does not
/// hold the fencing epoch) leaves the row entirely untouched, never a
/// partial/racing delete.
pub fn revoke_grant(
    cofold: &mut StrictCofold<UniqueOnce>,
    store: &mut KeyedStore,
    subject: &NodeId,
    capability: &Capability,
    epoch: Epoch,
    hlc: Hlc,
) -> Result<(), CoFoldError> {
    let id = grant_key(subject, capability);
    cofold.try_admit(id.as_bytes(), epoch, b"revoke".to_vec())?;

    store.doc_delete_field(GRANTS_COLLECTION, &id, FIELD_SUBJECT, hlc.clone());
    store.doc_delete_field(GRANTS_COLLECTION, &id, FIELD_CAPABILITY, hlc.clone());
    store.doc_delete_field(GRANTS_COLLECTION, &id, FIELD_EFFECT, hlc);
    Ok(())
}

/// Acquire the fencing epoch for a grant key's revoke partition through
/// `lease` (leaderless coordination core), recording it held on `cofold`.
/// A caller must acquire before [`revoke_grant`] admits a tombstone for the
/// same key/epoch — mirrors [`StrictCofold::acquire`] scoped to this
/// module's revoke keys.
pub fn acquire_revoke_epoch(
    cofold: &mut StrictCofold<UniqueOnce>,
    subject: &NodeId,
    capability: &Capability,
    lease: &mut LeaseRegister,
    candidate: &NodeId,
    epoch: Epoch,
) -> bool {
    let id = grant_key(subject, capability);
    cofold.acquire(id.as_bytes(), lease, candidate, epoch)
}

/// `CREATE MATERIALIZED VIEW effective_grants` over [`GRANTS_COLLECTION`] —
/// idempotent (re-creating with the identical, unfiltered/unprojected
/// [`ViewDef`] is harmless; `pillar-sqlviews` DDL is just a catalog write).
/// The view is folded fresh from the live rows on every read
/// (`materialize_view`), so a revoke's tombstone is reflected the instant
/// it lands — there is no separately-materialized copy to go stale.
pub fn ensure_effective_grants_view(store: &mut KeyedStore, hlc: Hlc) {
    create_view(
        store,
        EFFECTIVE_GRANTS_VIEW,
        ViewDef::over(GRANTS_COLLECTION),
        hlc,
    );
}

fn field_str(fields: &BTreeMap<String, Value>, field: &str) -> Option<String> {
    match fields.get(field) {
        Some(Value::Scalar(b)) => String::from_utf8(b.clone()).ok(),
        _ => None,
    }
}

/// Materialize the `effective_grants` SQL view and decode every complete
/// row back into an [`ExplicitGrant`] — the exact input shape
/// [`RbacDecider`](crate::RbacDecider) consumes, so a decider can be built
/// straight off this Document/SQL layer instead of an in-memory `Vec`
/// assembled by hand. A row missing any of `subject`/`capability`/`effect`
/// (e.g. a concurrently in-flight tombstone that removed some but not all
/// fields, or a malformed doc) is skipped rather than surfaced as garbage.
#[must_use]
pub fn effective_grants(store: &KeyedStore) -> Vec<ExplicitGrant> {
    let Some(rows) = materialize_view(store, EFFECTIVE_GRANTS_VIEW) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter_map(|row| {
            let subject = field_str(&row.fields, FIELD_SUBJECT)?;
            let capability = field_str(&row.fields, FIELD_CAPABILITY)?;
            let effect_bytes = match row.fields.get(FIELD_EFFECT) {
                Some(Value::Scalar(b)) => b.as_slice(),
                _ => return None,
            };
            let effect = effect_from_bytes(effect_bytes)?;
            Some(ExplicitGrant {
                subject: NodeId::from(subject.as_str()),
                capability: Capability::from(capability.as_str()),
                effect,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hlc(p: u64) -> Hlc {
        Hlc::new(p, 0, "n1")
    }

    fn n(s: &str) -> NodeId {
        NodeId::from(s)
    }

    fn cap(s: &str) -> Capability {
        Capability::from(s)
    }

    /// A granted capability is queryable through the SQL view exactly like
    /// any other `pillar-sqlviews` collection, and feeds
    /// [`RbacDecider`](crate::RbacDecider) unchanged.
    #[test]
    fn granted_capability_is_sql_queryable_and_feeds_the_decider() {
        let mut store = KeyedStore::new();
        ensure_effective_grants_view(&mut store, hlc(1));

        put_grant(
            &mut store,
            &n("alice"),
            &cap("read"),
            GrantEffect::Allow,
            hlc(2),
        );

        let grants = effective_grants(&store);
        assert_eq!(
            grants,
            vec![ExplicitGrant {
                subject: n("alice"),
                capability: cap("read"),
                effect: GrantEffect::Allow,
            }]
        );

        // The SAME collection is directly queryable via pillar-sqlviews'
        // generic materialize_view -- no bespoke read path.
        let rows = materialize_view(&store, EFFECTIVE_GRANTS_VIEW).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, grant_key(&n("alice"), &cap("read")));
    }

    /// Revoke is a CP tombstone: it must be admitted through the fenced,
    /// exactly-once cofold before the row is deleted, and a second revoke
    /// attempt for the same key is refused outright (uniqueness) -- never a
    /// bare AP delete a stale concurrent grant write could race back into
    /// effect.
    #[test]
    fn revoke_is_a_fenced_exactly_once_cp_tombstone() {
        let mut store = KeyedStore::new();
        ensure_effective_grants_view(&mut store, hlc(1));
        put_grant(
            &mut store,
            &n("alice"),
            &cap("delete-account"),
            GrantEffect::Allow,
            hlc(2),
        );
        assert_eq!(effective_grants(&store).len(), 1);

        let mut cofold = StrictCofold::new(UniqueOnce::new());
        let mut lease = LeaseRegister::new(1);
        let candidate = n("controller-1");
        lease
            .grant(n("voter-1"), candidate.clone(), Epoch(1))
            .unwrap();

        assert!(acquire_revoke_epoch(
            &mut cofold,
            &n("alice"),
            &cap("delete-account"),
            &mut lease,
            &candidate,
            Epoch(1)
        ));

        revoke_grant(
            &mut cofold,
            &mut store,
            &n("alice"),
            &cap("delete-account"),
            Epoch(1),
            hlc(3),
        )
        .expect("first revoke admits");

        // The row is gone from the effective view immediately.
        assert!(effective_grants(&store).is_empty());

        // A stale/concurrent AP "re-grant" written at an EARLIER hlc than
        // the tombstone must never resurrect the row (TombstoneWins per the
        // keyed-store fold) -- and a second revoke attempt for the same key
        // is refused outright by the cofold's uniqueness invariant,
        // regardless of the store's own fold semantics.
        let again = revoke_grant(
            &mut cofold,
            &mut store,
            &n("alice"),
            &cap("delete-account"),
            Epoch(1),
            hlc(4),
        );
        assert_eq!(
            again,
            Err(CoFoldError::DuplicateKey {
                key: grant_key(&n("alice"), &cap("delete-account")).into_bytes(),
            })
        );
    }

    /// A revoke attempted without first acquiring the fencing epoch is
    /// refused: only the recorded holder for the key's partition may admit
    /// a tombstone (no global lock, no unfenced writer).
    #[test]
    fn revoke_without_fenced_epoch_is_refused() {
        let mut store = KeyedStore::new();
        ensure_effective_grants_view(&mut store, hlc(1));
        put_grant(
            &mut store,
            &n("bob"),
            &cap("write"),
            GrantEffect::Allow,
            hlc(1),
        );

        let mut cofold = StrictCofold::new(UniqueOnce::new());
        let result = revoke_grant(
            &mut cofold,
            &mut store,
            &n("bob"),
            &cap("write"),
            Epoch(1),
            hlc(2),
        );
        assert!(matches!(result, Err(CoFoldError::NotFenced { .. })));

        // Refused revoke never touches the row.
        assert_eq!(effective_grants(&store).len(), 1);
    }

    /// Two independent grant keys revoke independently -- no cross-key
    /// coordination, matching `cp-viewpolicy-strict-cofold`'s per-key
    /// scoping.
    #[test]
    fn independent_grant_keys_revoke_independently() {
        let mut store = KeyedStore::new();
        ensure_effective_grants_view(&mut store, hlc(1));
        put_grant(
            &mut store,
            &n("alice"),
            &cap("read"),
            GrantEffect::Allow,
            hlc(2),
        );
        put_grant(
            &mut store,
            &n("bob"),
            &cap("read"),
            GrantEffect::Allow,
            hlc(2),
        );

        let mut cofold = StrictCofold::new(UniqueOnce::new());
        let mut lease = LeaseRegister::new(1);
        let candidate = n("controller-1");
        lease
            .grant(n("voter-1"), candidate.clone(), Epoch(1))
            .unwrap();

        assert!(acquire_revoke_epoch(
            &mut cofold,
            &n("alice"),
            &cap("read"),
            &mut lease,
            &candidate,
            Epoch(1)
        ));
        revoke_grant(
            &mut cofold,
            &mut store,
            &n("alice"),
            &cap("read"),
            Epoch(1),
            hlc(3),
        )
        .unwrap();

        let remaining = effective_grants(&store);
        assert_eq!(
            remaining,
            vec![ExplicitGrant {
                subject: n("bob"),
                capability: cap("read"),
                effect: GrantEffect::Allow,
            }]
        );
    }
}
