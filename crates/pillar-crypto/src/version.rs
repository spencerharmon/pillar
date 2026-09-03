//! Independent per-surface version stamps.
//!
//! ROI P1 "Versioning, compatibility & safe rollout" requires that every
//! independently-evolving wire/storage surface (event envelope, materialized
//! view, pillar message, HTTP ingest API, pillar-UDP protocol, trust
//! artifact, sealed-artifact envelope, manifest schema) carry an EXPLICIT,
//! independently-incrementable version field. This module provides the shared
//! stamp primitive so every surface stamps the same way and — critically —
//! distinguishes the two failure modes the ROI calls out:
//!
//! * a **parse error** (`VersionError::Malformed`): the bytes are not a
//!   well-formed stamped value at all (truncated, wrong tag, garbage), and
//!   * a **stamped-but-unknown-future version** (`VersionError::Unsupported`):
//!   the value parsed cleanly and carries a legible version number, but that
//!   number is newer than this build knows how to interpret.
//!
//! Keeping these distinct is what lets the later compatibility-negotiation and
//! migration work (`compat-negotiation-impl`, the cell/swarm migration tasks)
//! treat "I received something from a newer peer" differently from "I received
//! corruption" — the former is a negotiable, in-window/out-of-window decision;
//! the latter is a hard reject. This crate deliberately implements ONLY the
//! stamp + its bounds check; no negotiation or migration behavior lives here.
//!
//! The stamp lives in `pillar-crypto` because it is the one crate every other
//! surface crate already depends on (directly or transitively), so no new
//! dependency edge — and no dependency cycle — is introduced by sharing it.

use std::fmt;

/// An explicit, independently-incrementable version number for one surface.
///
/// A surface stamps its serialized form with a `SurfaceVersion` and, on read,
/// checks it against the range of versions THIS build understands with
/// [`SurfaceVersion::check_supported`]. The number space is per-surface: the
/// event-envelope's `v1` and the manifest schema's `v1` are unrelated and
/// advance independently (the very property `IndependentVersioning` proven in
/// `specs/VersioningCompat.tla`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SurfaceVersion(pub u16);

impl SurfaceVersion {
    /// Encode as a fixed 2-byte big-endian stamp for hand-rolled byte formats.
    pub fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Decode a fixed 2-byte big-endian stamp. A slice shorter than 2 bytes is
    /// a [`VersionError::Malformed`] (a parse error), NOT an unknown version.
    pub fn from_be_bytes(bytes: &[u8]) -> Result<SurfaceVersion, VersionError> {
        if bytes.len() < 2 {
            return Err(VersionError::Malformed);
        }
        Ok(SurfaceVersion(u16::from_be_bytes([bytes[0], bytes[1]])))
    }

    /// Verify this stamp is one this build can interpret, given the inclusive
    /// range `[min, max]` of versions the reader supports for its surface.
    ///
    /// * below `min` → [`VersionError::Unsupported`] (too old / retired), and
    /// * above `max` → [`VersionError::Unsupported`] (a stamped-but-unknown
    ///   FUTURE version — parsed fine, but newer than we know).
    ///
    /// Both carry the offending and supported numbers so a caller (and the
    /// later negotiation layer) can report or negotiate precisely. This is
    /// distinct from a malformed value, which never reaches this check.
    pub fn check_supported(
        self,
        min: SurfaceVersion,
        max: SurfaceVersion,
    ) -> Result<(), VersionError> {
        if self < min || self > max {
            Err(VersionError::Unsupported {
                found: self,
                min,
                max,
            })
        } else {
            Ok(())
        }
    }
}

impl fmt::Display for SurfaceVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// The two — deliberately distinct — ways reading a stamped surface can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionError {
    /// The bytes/value are not a well-formed stamped surface value at all:
    /// truncated, wrong magic/tag, or otherwise unparseable. A hard reject; it
    /// is never a version-negotiation candidate.
    Malformed,
    /// The value parsed cleanly and carries a legible version, but that version
    /// falls outside `[min, max]` — most importantly a version NEWER than this
    /// build understands. Reported separately from `Malformed` so the
    /// compatibility layer can negotiate / window-check it rather than treating
    /// a newer peer as corruption.
    Unsupported {
        /// The version actually found on the value.
        found: SurfaceVersion,
        /// The lowest version this build supports for the surface.
        min: SurfaceVersion,
        /// The highest version this build supports for the surface.
        max: SurfaceVersion,
    },
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionError::Malformed => f.write_str("malformed surface value (parse error)"),
            VersionError::Unsupported { found, min, max } => write!(
                f,
                "unsupported surface version {found} (this build supports {min}..={max})"
            ),
        }
    }
}

impl std::error::Error for VersionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_round_trips_through_be_bytes() {
        for v in [0u16, 1, 2, 255, 256, 65535] {
            let sv = SurfaceVersion(v);
            let bytes = sv.to_be_bytes();
            assert_eq!(SurfaceVersion::from_be_bytes(&bytes).unwrap(), sv);
        }
    }

    #[test]
    fn short_stamp_is_a_parse_error_not_an_unknown_version() {
        // The central distinction the ROI demands: truncation is Malformed,
        // never mistaken for an unknown version.
        assert_eq!(
            SurfaceVersion::from_be_bytes(&[]),
            Err(VersionError::Malformed)
        );
        assert_eq!(
            SurfaceVersion::from_be_bytes(&[0x00]),
            Err(VersionError::Malformed)
        );
    }

    #[test]
    fn a_known_version_is_supported() {
        let v = SurfaceVersion(1);
        assert_eq!(
            v.check_supported(SurfaceVersion(1), SurfaceVersion(1)),
            Ok(())
        );
    }

    #[test]
    fn stamped_but_unknown_future_version_is_rejected_distinctly() {
        // A cleanly-parsed value carrying a FUTURE version is Unsupported —
        // NOT Malformed. This is the exact case that lets the future
        // negotiation layer treat a newer peer as negotiable rather than
        // as corruption.
        let future = SurfaceVersion(9);
        let err = future
            .check_supported(SurfaceVersion(1), SurfaceVersion(2))
            .unwrap_err();
        assert_eq!(
            err,
            VersionError::Unsupported {
                found: SurfaceVersion(9),
                min: SurfaceVersion(1),
                max: SurfaceVersion(2),
            }
        );
        // And it is provably a different variant than a parse error.
        assert_ne!(err, VersionError::Malformed);
    }

    #[test]
    fn a_too_old_version_is_also_unsupported() {
        let old = SurfaceVersion(0);
        assert_eq!(
            old.check_supported(SurfaceVersion(1), SurfaceVersion(3)),
            Err(VersionError::Unsupported {
                found: SurfaceVersion(0),
                min: SurfaceVersion(1),
                max: SurfaceVersion(3),
            })
        );
    }
}
