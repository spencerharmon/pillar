//! Regression suite for pillar-UDP DYNAMIC redundancy as the default
//! congestion-avoidance posture (ROI reconcile 2026-09-07, transport-posture
//! correction).
//!
//! These tests pin the behavioral change the task delivers: redundant delivery
//! is the PREFERRED posture on EVERY link (not a bad-link fallback), the
//! per-connection redundancy allowance scales DYNAMICALLY with the measured
//! reliability-mesh signal — down toward a single copy on a clean cheap path,
//! up toward the allowance ceiling as loss/latency rise — and the ceiling is
//! NEVER exceeded (preserving `BoundedTotalDatagrams` from the pillar-UDP
//! protocol spec). Each test fails without the `RedundancyController` /
//! `PathSignal` control loop and passes with it.

use pillar_net::pillar_udp::{PathSignal, RedundancyController};

/// The DEFAULT posture on a clean cheap path collapses to a SINGLE copy — a
/// healthy link pays almost nothing, yet redundancy is still the *mechanism*
/// (floor 1), not a mode that must be switched on.
#[test]
fn clean_cheap_path_collapses_to_a_single_copy() {
    let ctl = RedundancyController::new(1, 8, 50.0);
    assert_eq!(
        ctl.copies(PathSignal::PRISTINE),
        1,
        "a pristine path pays a single copy by default"
    );
    // A near-pristine, low-latency path stays at the floor.
    assert_eq!(ctl.copies(PathSignal::new(0.0, 2.0)), 1);
}

/// Rising measured loss REALLOCATES more redundancy (scales the copy count UP)
/// — the opposite of a single-window backoff, which would THROTTLE. The count
/// increases monotonically with loss.
#[test]
fn rising_loss_scales_redundancy_up_monotonically_not_a_backoff() {
    let ctl = RedundancyController::new(1, 9, 0.0); // loss-only (latency disabled)
    let clean = ctl.copies(PathSignal::new(0.00, 0.0));
    let mild = ctl.copies(PathSignal::new(0.10, 0.0));
    let bad = ctl.copies(PathSignal::new(0.40, 0.0));
    let hostile = ctl.copies(PathSignal::new(0.90, 0.0));

    assert_eq!(clean, 1, "clean path is a single copy");
    assert!(
        clean <= mild && mild <= bad && bad <= hostile,
        "redundancy scales UP with loss (never throttles): {clean} <= {mild} <= {bad} <= {hostile}"
    );
    assert!(
        hostile > clean,
        "a hostile link uses strictly more redundancy than a clean one"
    );
}

/// The config-bounded per-connection allowance (ceiling) is NEVER exceeded, for
/// ANY measured signal — this is exactly the BoundedTotalDatagrams safety
/// invariant the pillar-UDP protocol spec requires, preserved by the dynamic
/// scaling rather than broken by it.
#[test]
fn allowance_ceiling_is_never_exceeded_for_any_signal() {
    let ctl = RedundancyController::new(2, 5, 20.0);
    assert_eq!(ctl.allowance(), 5);

    // Sweep the whole (loss, latency) space, including maximally hostile and
    // deliberately out-of-range/garbage inputs.
    for loss_milli in 0..=1000u32 {
        let loss = f64::from(loss_milli) / 1000.0;
        for &lat in &[0.0, 5.0, 20.0, 100.0, 1.0e9] {
            let n = ctl.copies(PathSignal::new(loss, lat));
            assert!(
                (ctl.floor()..=ctl.allowance()).contains(&n),
                "copies {n} out of [floor {}, ceiling {}] for loss={loss} lat={lat}",
                ctl.floor(),
                ctl.allowance(),
            );
        }
    }
    // Even a bogus over-range signal is clamped, never blowing past the ceiling.
    assert!(ctl.copies(PathSignal::new(5.0, -3.0)) <= ctl.allowance());
    assert!(ctl.copies(PathSignal::new(f64::MAX, f64::MAX)) <= ctl.allowance());
}

/// A maximally hostile path drives redundancy all the way to — but not past —
/// the allowance ceiling, so a bad link is fully covered.
#[test]
fn maximally_hostile_path_reaches_the_full_allowance() {
    let ctl = RedundancyController::new(1, 6, 10.0);
    // Full loss + saturating latency = full pressure = ceiling.
    assert_eq!(ctl.copies(PathSignal::new(1.0, 1000.0)), ctl.allowance());
}

/// Latency contributes to redundancy pressure (a high-RTT path benefits from
/// spraying rather than serializing retransmit rounds), but loss dominates.
#[test]
fn latency_raises_redundancy_but_loss_dominates() {
    let ctl = RedundancyController::new(1, 11, 100.0);
    let low_lat = ctl.copies(PathSignal::new(0.0, 0.0));
    let high_lat = ctl.copies(PathSignal::new(0.0, 100.0));
    assert!(
        high_lat > low_lat,
        "a high-latency (but lossless) path still warrants more redundancy: {high_lat} > {low_lat}"
    );

    // With the latency term saturated, loss still adds strictly more pressure —
    // loss is the primary driver.
    let lat_only = ctl.copies(PathSignal::new(0.0, 100.0));
    let lat_plus_loss = ctl.copies(PathSignal::new(0.5, 100.0));
    assert!(
        lat_plus_loss > lat_only,
        "loss dominates: adding loss atop saturated latency raises copies further"
    );
}

/// The floor and ceiling are sanitized: a zero floor becomes a single copy
/// (a message is always sent at least once) and a ceiling below the floor is
/// raised to the floor (a degenerate allowance can never invert the bound).
#[test]
fn controller_sanitizes_degenerate_bounds() {
    let ctl = RedundancyController::new(0, 0, 10.0);
    assert_eq!(ctl.floor(), 1, "floor is at least one copy");
    assert_eq!(ctl.allowance(), 1, "ceiling is raised to the floor");
    // A single-copy allowance means redundancy is pinned at one for any signal.
    assert_eq!(ctl.copies(PathSignal::new(1.0, 1000.0)), 1);
}
