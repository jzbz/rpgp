//! Per-certificate acceptance of SHA-1, for verification only.
//!
//! Certificates made before roughly 2010 — and a few maintained since by
//! long-lived projects that never re-signed — carry self-signatures hashed with
//! SHA-1. Sequoia's [`StandardPolicy`] rejects those, so such a certificate has
//! no valid binding signature at all: no user ID, no subkey, nothing to verify
//! against. rPGP shows it as `unusable`, which is accurate but tells the reader
//! nothing about what to do, and leaves them unable to check a signature that
//! a project genuinely still publishes.
//!
//! The escape hatch here is deliberately narrow, in three separate ways.
//!
//! **Per issuer, not per operation.** The obvious implementation — swap in a
//! SHA-1-accepting policy for the whole verification — would relax the rules for
//! every certificate that operation touches, including ones the user never
//! opted into. Instead [`Sha1Policy`] wraps the standard policy and consults the
//! opt-in list for each signature it is asked about, keyed by that signature's
//! own issuer. Every other certificate is still judged strictly, in the very
//! same operation.
//!
//! **Verification only.** Nothing in this module is reachable from the web of
//! trust, from certification, or from trust-root selection; those construct
//! [`crate::policy`] directly. A SHA-1 certificate can therefore never become
//! an authenticated identity, never act as an introducer, and never lend its
//! authority to a third certificate — no matter what the user opts into. The
//! opt-in buys exactly one thing: the ability to check a signature and be told
//! what it says.
//!
//! **Only ever a widening of what verifies, never of what is trusted.** A
//! signature that fails for any other reason fails identically here.
//!
//! What the user gets back is still not a guarantee. SHA-1 collisions are
//! practical, so a signature that checks out under this policy proves the
//! signer's key was involved rather than that the signer approved this exact
//! document. Callers surface that distinction; see [`crate::ops::SignatureReport`].

use std::collections::BTreeSet;
use std::time::SystemTime;

use sequoia_openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use sequoia_openpgp::packet::{Packet, Signature, key};
use sequoia_openpgp::policy::{HashAlgoSecurity, Policy, StandardPolicy};
use sequoia_openpgp::types::{AEADAlgorithm, HashAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp::{Cert, KeyID};

/// A standard policy that additionally accepts SHA-1.
///
/// Not public: handing this out is how the relaxation escapes to the callers
/// that must not have it. It exists to be consulted by [`Sha1Policy`], and to
/// answer [`blocked`].
pub(crate) fn permissive() -> StandardPolicy<'static> {
    let mut policy = StandardPolicy::new();
    // Both properties, because both are needed and for different packets. A
    // user ID self-signature is judged on second-preimage resistance alone —
    // it binds a name the attacker would have to have chosen before the key
    // existed — while a subkey binding, and the data signature itself, need
    // collision resistance. Accepting only the weaker property leaves the
    // certificate exactly as unusable as before, because the subkey never
    // binds.
    policy.accept_hash(HashAlgorithm::SHA1);
    policy
}

/// Whether SHA-1, specifically, is what makes this certificate unusable.
///
/// True only when the certificate fails under the standard policy *and* passes
/// once SHA-1 is accepted, so it never fires for a certificate that is broken,
/// revoked into uselessness, or weak for some unrelated reason. That precision
/// is the point: it is what lets the UI say "this is SHA-1, here is the choice"
/// rather than offering a SHA-1 opt-in that would not have helped.
pub fn blocked(cert: &Cert) -> bool {
    let now = SystemTime::now();
    cert.with_policy(&crate::policy(), now).is_err() && cert.with_policy(&permissive(), now).is_ok()
}

/// Whether a signature made by this certificate would itself lean on SHA-1.
///
/// Distinguishes the two cases the user should not be asked to conflate: an old
/// certificate whose *bindings* are SHA-1 but which signs new messages with
/// SHA-256 (weak provenance, sound message), versus one still hashing the
/// message itself with SHA-1 (forgeable given a collision). Only the second
/// deserves the stronger warning.
pub fn hashed_with_sha1(sig: &Signature) -> bool {
    sig.hash_algo() == HashAlgorithm::SHA1
}

/// The standard policy, widened to accept SHA-1 for a named set of
/// certificates and for nothing else.
///
/// Build it with [`crate::Store::sha1_policy`], which reads the user's opt-in
/// list; [`Sha1Policy::strict`] gives an instance that accepts nothing, which
/// is what every caller gets when the list is empty.
#[derive(Debug)]
pub struct Sha1Policy {
    strict: StandardPolicy<'static>,
    permissive: StandardPolicy<'static>,
    /// Every key of every opted-in certificate, primary and subkeys alike,
    /// reduced to key IDs.
    ///
    /// Subkeys have to be in here and it is easy to miss why: a certificate is
    /// opted into by its *primary* fingerprint, but the data signature on a
    /// message is issued by a signing *subkey*, and a subkey's key ID is
    /// nothing like its primary's. Matching only the primary would let the
    /// certificate's own bindings validate and then reject the one signature
    /// the user was trying to read.
    ///
    /// Key IDs rather than fingerprints because a signature is only required to
    /// name its issuer by key ID, and old certificates — exactly the ones this
    /// module exists for — routinely do. The 64-bit handle is not doing any
    /// security work: it selects which certificate to relax the hash rule for,
    /// and the signature still has to verify cryptographically against that
    /// certificate's actual key.
    accepted: BTreeSet<KeyID>,
}

impl Sha1Policy {
    /// A policy that accepts SHA-1 for nothing — behaviourally the standard
    /// policy.
    pub fn strict() -> Self {
        Self {
            strict: crate::policy(),
            permissive: permissive(),
            accepted: BTreeSet::new(),
        }
    }

    /// Accept SHA-1 for signatures issued by any key of `cert`.
    pub fn accept(&mut self, cert: &Cert) {
        self.accepted.extend(cert.keys().map(|ka| ka.key().keyid()));
    }

    /// Whether anything at all has been opted in.
    pub fn is_strict(&self) -> bool {
        self.accepted.is_empty()
    }

    /// Whether this signature's issuer is one the user opted in.
    ///
    /// A signature can name several issuers; any one of them matching is
    /// enough, which mirrors how sequoia itself resolves an issuer to a
    /// certificate.
    fn opted_in(&self, sig: &Signature) -> bool {
        if self.accepted.is_empty() {
            return false;
        }
        sig.issuers().any(|id| self.accepted.contains(id))
            || sig
                .issuer_fingerprints()
                .any(|fp| self.accepted.contains(&KeyID::from(fp)))
    }
}

impl Policy for Sha1Policy {
    fn signature(&self, sig: &Signature, sec: HashAlgoSecurity) -> anyhow::Result<()> {
        // Strict first, always. The permissive policy is consulted only for a
        // signature the strict one has already refused, so opting a
        // certificate in can widen what verifies and can never narrow it — and
        // a signature that fails for a reason unrelated to SHA-1 fails with
        // the strict policy's own error rather than a rewritten one.
        match self.strict.signature(sig, sec) {
            Ok(()) => Ok(()),
            Err(strict_err) => {
                if self.opted_in(sig) {
                    self.permissive.signature(sig, sec)
                } else {
                    Err(strict_err)
                }
            }
        }
    }

    // The rest is the standard policy untouched. SHA-1 acceptance is a
    // statement about hashes and nothing else: an opted-in certificate gets no
    // relief from a weak public key algorithm, a broken cipher, or a packet
    // type sequoia refuses to parse.
    fn key(&self, ka: &ValidErasedKeyAmalgamation<key::PublicParts>) -> anyhow::Result<()> {
        self.strict.key(ka)
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm) -> anyhow::Result<()> {
        self.strict.symmetric_algorithm(algo)
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm) -> anyhow::Result<()> {
        self.strict.aead_algorithm(algo)
    }

    fn packet(&self, packet: &Packet) -> anyhow::Result<()> {
        self.strict.packet(packet)
    }
}
