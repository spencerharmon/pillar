//! The error type for the embeddable IPFS node.

/// A fault in the IPFS node: I/O against the on-disk store, or a content-address
/// integrity violation. Deliberately `Copy` (like the streaming DB's own store
/// error) so it threads through hot paths without allocation; the underlying
/// I/O detail is logged at the failing call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpfsError {
    /// An on-disk blockstore / marker-set operation failed. Carries the
    /// [`std::io::ErrorKind`] (the full error is logged where it occurs).
    Io(std::io::ErrorKind),
    /// A block's bytes do not hash to the [`pillar_crypto::ContentId`] it was
    /// filed/fetched under — a block can never be stored under an id its bytes
    /// do not produce.
    CidMismatch,
}

impl std::fmt::Display for IpfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpfsError::Io(kind) => write!(f, "IPFS node I/O error: {kind:?}"),
            IpfsError::CidMismatch => {
                write!(
                    f,
                    "block bytes do not hash to the CID they were filed under"
                )
            }
        }
    }
}

impl std::error::Error for IpfsError {}

/// Map a `std::io::Error` to an [`IpfsError::Io`], logging the full detail.
pub(crate) fn io_err(e: std::io::Error) -> IpfsError {
    tracing::warn!(error = %e, "pillar-ipfs on-disk store I/O error");
    IpfsError::Io(e.kind())
}
