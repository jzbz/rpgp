//! Backend for rpgp: everything that does not draw pixels.
//!
//! The GUI crate is expected to depend only on this crate's types, never on
//! `sequoia_openpgp` directly, so that the OpenPGP implementation stays
//! replaceable and so that no Sequoia type ends up in a Slint callback.

pub mod agent;
pub mod cert;
pub mod certify;
pub mod error;
pub mod keygen;
pub mod keyserver;
pub mod lifecycle;
pub mod ops;
pub mod revoke;
pub mod secret;
pub mod sha1;
pub mod store;
pub mod wot;

pub use cert::{CertSummary, Validity};
pub use error::{Error, Result};
pub use sha1::Sha1Policy;
pub use store::Store;
pub use wot::Authentication;

use sequoia_openpgp::policy::StandardPolicy;

/// The policy every operation in this crate is evaluated against.
///
/// Sequoia has no global policy: each call that interprets a certificate takes
/// one explicitly, so a single definition here keeps the whole app consistent.
pub fn policy() -> StandardPolicy<'static> {
    StandardPolicy::new()
}
