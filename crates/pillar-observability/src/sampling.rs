//! Metadata-sampling policy — property 2 of `specs/Observability.tla`:
//! a sample is never fabricated and never double-counted.
//!
//! Modeled over a grow-only ghost set of real occurrences (`happened`) and a
//! per-occurrence sample counter (`sampled`), exactly the spec's variables. A
//! sample is admitted ([`SamplingPolicy::emit_sample`]) only for an occurrence
//! that has genuinely `happened` (`NoFabricatedSample`) and at most
//! `SampleCap` times (`NoDoubleCountSample`).

use std::collections::BTreeMap;

/// A real-world occurrence a sample may reference (a request, a connection, a
/// config read). Its identity is opaque here — what matters is that it either
/// genuinely happened or did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Occurrence(pub u64);

/// Why a metadata-sample emission was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleError {
    /// The referenced occurrence never genuinely `happened` — refusing to
    /// fabricate a sample for a non-event (`NoFabricatedSample`).
    Fabricated,
    /// The occurrence has already been sampled the policy's configured
    /// `SampleCap` times — refusing to double-count (`NoDoubleCountSample`).
    RateExceeded {
        /// The configured per-occurrence cap.
        cap: u32,
    },
}

/// The metadata-sampling policy: a `SampleCap` plus the ghost `happened` set
/// and per-occurrence `sampled` counters.
#[derive(Clone, Debug)]
pub struct SamplingPolicy {
    cap: u32,
    happened: BTreeMap<Occurrence, ()>,
    sampled: BTreeMap<Occurrence, u32>,
}

impl SamplingPolicy {
    /// A fresh policy with the configured per-occurrence sample cap (the
    /// spec's `SampleCap`).
    #[must_use]
    pub fn new(cap: u32) -> Self {
        SamplingPolicy {
            cap,
            happened: BTreeMap::new(),
            sampled: BTreeMap::new(),
        }
    }

    /// The policy's configured per-occurrence sample cap.
    #[must_use]
    pub fn cap(&self) -> u32 {
        self.cap
    }

    /// Record that a real occurrence genuinely happened (grow-only ghost fact,
    /// independent of whether/how it is later sampled — the spec's `Occur`).
    pub fn occur(&mut self, occurrence: Occurrence) {
        self.happened.entry(occurrence).or_insert(());
    }

    /// Whether `occurrence` genuinely happened.
    #[must_use]
    pub fn happened(&self, occurrence: Occurrence) -> bool {
        self.happened.contains_key(&occurrence)
    }

    /// How many samples have been emitted for `occurrence` so far.
    #[must_use]
    pub fn sample_count(&self, occurrence: Occurrence) -> u32 {
        self.sampled.get(&occurrence).copied().unwrap_or(0)
    }

    /// Attempt to emit a metadata sample for `occurrence` (the spec's
    /// `EmitSample`).
    ///
    /// Admitted only when the occurrence has genuinely `happened` AND its
    /// count is still below the cap; on success bumps the count and returns
    /// the new count.
    ///
    /// # Errors
    ///
    /// [`SampleError::Fabricated`] if the occurrence never happened;
    /// [`SampleError::RateExceeded`] if it is already at the cap.
    pub fn emit_sample(&mut self, occurrence: Occurrence) -> Result<u32, SampleError> {
        if !self.happened(occurrence) {
            return Err(SampleError::Fabricated);
        }
        let count = self.sampled.entry(occurrence).or_insert(0);
        if *count >= self.cap {
            return Err(SampleError::RateExceeded { cap: self.cap });
        }
        *count += 1;
        Ok(*count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NoFabricatedSample`: a sample cannot be emitted for an occurrence that
    /// never genuinely happened.
    #[test]
    fn cannot_sample_an_occurrence_that_never_happened() {
        let mut policy = SamplingPolicy::new(3);
        assert_eq!(
            policy.emit_sample(Occurrence(1)),
            Err(SampleError::Fabricated)
        );
        assert_eq!(policy.sample_count(Occurrence(1)), 0);
    }

    /// A sample for a genuine occurrence is admitted and counted.
    #[test]
    fn a_real_occurrence_can_be_sampled() {
        let mut policy = SamplingPolicy::new(3);
        policy.occur(Occurrence(1));
        assert_eq!(policy.emit_sample(Occurrence(1)), Ok(1));
        assert_eq!(policy.sample_count(Occurrence(1)), 1);
    }

    /// `NoDoubleCountSample`: an occurrence is never sampled beyond the
    /// configured cap; the count never exceeds `cap`.
    #[test]
    fn an_occurrence_is_never_sampled_beyond_the_cap() {
        let mut policy = SamplingPolicy::new(2);
        policy.occur(Occurrence(7));
        assert_eq!(policy.emit_sample(Occurrence(7)), Ok(1));
        assert_eq!(policy.emit_sample(Occurrence(7)), Ok(2));
        assert_eq!(
            policy.emit_sample(Occurrence(7)),
            Err(SampleError::RateExceeded { cap: 2 })
        );
        // The invariant: count never exceeds the cap, no matter how many
        // emit attempts are made.
        for _ in 0..10 {
            let _ = policy.emit_sample(Occurrence(7));
        }
        assert!(policy.sample_count(Occurrence(7)) <= policy.cap());
        assert_eq!(policy.sample_count(Occurrence(7)), 2);
    }

    /// A cap of zero admits no samples at all — the degenerate rate limit.
    #[test]
    fn zero_cap_admits_no_samples() {
        let mut policy = SamplingPolicy::new(0);
        policy.occur(Occurrence(1));
        assert_eq!(
            policy.emit_sample(Occurrence(1)),
            Err(SampleError::RateExceeded { cap: 0 })
        );
    }

    /// Distinct occurrences are counted independently (sampling one does not
    /// consume another's budget).
    #[test]
    fn distinct_occurrences_are_counted_independently() {
        let mut policy = SamplingPolicy::new(1);
        policy.occur(Occurrence(1));
        policy.occur(Occurrence(2));
        assert_eq!(policy.emit_sample(Occurrence(1)), Ok(1));
        assert_eq!(policy.emit_sample(Occurrence(2)), Ok(1));
        assert_eq!(policy.sample_count(Occurrence(1)), 1);
        assert_eq!(policy.sample_count(Occurrence(2)), 1);
    }
}
