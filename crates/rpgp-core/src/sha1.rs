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
//! **Per certificate, decided against the certificate that verified.** A
//! sequoia [`Policy`] is the obvious place to put this and it is the wrong
//! one: it is handed a signature and asked whether the rules allow it, with no
//! idea which key the signature is about to be checked against. The only thing
//! it could key on is the signature's own Issuer subpacket, and those are read
//! from the *unhashed* area too — bytes anyone can rewrite without disturbing
//! the signature — so a SHA-1 signature made by any certificate at all could
//! name an opted-in one and be judged by the relaxed rule. The policy handed
//! to the verifier therefore says only whether SHA-1 may be needed *at all*
//! ([`Sha1Policy::verification`]), and the decision that matters is made
//! afterwards in [`crate::ops`], against the certificate whose key actually
//! verified: SHA-1 load-bearing plus a certificate the user never named is a
//! bad signature. What the key list shows of a certificate is decided the same
//! way, by [`Sha1Policy::for_cert`], which relaxes the rules for the
//! certificate in hand and for no other.
//!
//! **Verification only.** Nothing in this module is reachable from the web of
//! trust, from certification, or from trust-root selection; those construct
//! [`crate::policy`] directly. A SHA-1 certificate can therefore never become
//! an authenticated identity, never act as an introducer, and never lend its
//! authority to a third certificate — no matter what the user opts into. The
//! opt-in buys exactly one thing: the ability to check a signature and be told
//! what it says.
//!
//! **Never a widening of anything but the hash rules.** A signature that fails
//! for some other reason fails here identically, and no opt-in has ever made a
//! signature good that was not: every question the relaxed policy answered
//! about the key that verified is put to the strict policy again afterwards,
//! which is what [`load_bearing`] is.
//!
//! What the relaxed policy does reach beyond the certificate it was granted
//! for is the *parser*, in one direction only: it can cost a third party a
//! verdict, and can never buy one. Sequoia reads a whole message under a
//! single policy and cannot be told which certificate a signature came from
//! until it has verified, so while anything is opted in, every certificate in
//! the message is read under the relaxed rules ([`Sha1Policy::verification`]).
//! A policy chooses *which* self-signature is in force rather than merely
//! whether one is, so a certificate whose newest self-signature is SHA-1 and
//! *worse* than the one it supersedes — an expiry that has since run out,
//! narrower key flags, a revocation the strict policy ignores — reads worse
//! than it strictly is, and its signatures can be refused where a strict
//! verifier would have accepted them. That fails closed and needs no attacker,
//! but it is real: closing it would mean verifying strictly first and
//! re-reading the message under the relaxed rules only where the strict pass
//! left something unverified, which the streaming decrypt path cannot do
//! because its plaintext has already gone to the caller.
//!
//! What the user gets back is still not a guarantee. SHA-1 collisions are
//! practical, so a signature that checks out under this policy proves the
//! signer's key was involved rather than that the signer approved this exact
//! document. Callers surface that distinction; see [`crate::ops::SignatureReport`].

use std::collections::BTreeSet;
use std::time::SystemTime;

use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::policy::{Policy, StandardPolicy};
use sequoia_openpgp::types::{HashAlgorithm, RevocationStatus};
use sequoia_openpgp::{Cert, Fingerprint, KeyHandle};

/// A standard policy that additionally accepts SHA-1.
///
/// Not public: handing this out is how the relaxation escapes to the callers
/// that must not have it. It exists to be consulted by [`Sha1Policy`], and to
/// answer [`blocked`].
///
/// Accepting SHA-1 is a statement about hashes and nothing else. What comes
/// back is the standard policy in every other respect, so an opted-in
/// certificate gets no relief from a weak public key algorithm, a broken
/// cipher, or a packet type sequoia refuses to parse.
pub(crate) fn permissive() -> StandardPolicy<'static> {
    let mut policy = StandardPolicy::new();
    // Both properties, and it is the message signature rather than the
    // certificate that needs the stronger one. In sequoia 2.x a key bundle
    // carries `HashAlgoSecurity::SecondPreImageResistance`, and binding
    // signatures, their embedded back signatures and ordinary user ID
    // self-signatures are all judged against that, so relaxing the weaker
    // property alone would already make an old certificate's user IDs and
    // subkeys bind. Collision resistance is what the stream verifier asks for
    // when it judges the *message* signature, and what an unusual user ID —
    // over 96 bytes, not valid UTF-8, or carrying a control character — and a
    // user attribute are judged by. Accepting it is therefore the deliberate
    // half of the opt-in: it is what lets a SHA-1 message hash verify, which
    // is the case `hashed_with_sha1` exists to disclose.
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
///
/// Here for callers asking that question of a certificate they hold, which
/// in-tree nothing does: the key list reads [`crate::CertSummary::sha1_blocked`]
/// instead, which is the same predicate answered from the validity the summary
/// has already computed, and therefore answers `false` once the user has opted
/// the certificate in and the offer is no longer open.
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

/// Whether SHA-1 is what made a good signature acceptable.
///
/// Two ways it can be, and both have to be asked. The message itself may be
/// hashed with SHA-1, which [`hashed_with_sha1`] answers. Or the message hash
/// may be modern and the *key* reach its certificate only through SHA-1: an
/// old signing subkey whose binding signature, or whose embedded back
/// signature, no policy but the relaxed one will accept.
///
/// Asked of `key` — the key that actually verified — rather than of the
/// certificate as a whole, because [`Cert::with_policy`] judges only the
/// primary key. A certificate whose user IDs a modern GnuPG re-signed with
/// SHA-256 while extending an expiry, leaving the signing-subkey binding at
/// SHA-1 where it was, passes the standard policy outright; every signature
/// from that subkey still stands on SHA-1 and has to say so.
///
/// The reference time is the signature's own creation time, which is the time
/// sequoia's verifier bound the key at. The hash cutoffs themselves are judged
/// against the present whatever that time is, so a strict failure here, on a
/// key the relaxed policy has already accepted, means SHA-1 and can mean
/// nothing else: the two policies are otherwise the same policy.
///
/// That equivalence is also what makes it safe to ask more than one question
/// here, and more than one has to be asked. A policy decides which binding
/// signature is in force, not merely whether one is, so everything read off
/// that binding — the key's flags, the key's expiry — changes with the choice.
/// Every check the verifier made under the policy it ran is therefore put to
/// the strict policy again.
pub(crate) fn load_bearing(sig: &Signature, cert: &Cert, key: KeyHandle) -> bool {
    if hashed_with_sha1(sig) {
        return true;
    }

    // The whole of what sequoia's stream verifier asked of this key under the
    // policy it ran under (`parse/stream.rs`, sequoia-openpgp 2.4.1), asked
    // again strictly: that the key binds at the signature's creation time,
    // that the certificate and the key are both live, that neither is
    // revoked, and that the key may sign. Anything the two passes answer
    // differently, they answer differently because of a SHA-1 signature, and
    // that is the definition of load-bearing.
    //
    // Asking only whether a binding exists is not enough, and the gap is
    // reachable: `find_binding_signature` falls back to an older binding when
    // the newest one fails the policy, so a subkey whose newest binding is
    // SHA-1 and unexpiring, over an older SHA-256 one that has since expired,
    // binds under both policies and is live under only the relaxed one. It
    // signs, it is good, and without the liveness questions here nothing in
    // the report would say SHA-1 had anything to do with it.
    //
    // The revocation questions cannot come out differently — a relaxed policy
    // accepts more revocation signatures, never fewer, so anything strict
    // would call revoked the verifier refused before it ever got here — but
    // they are asked anyway, so that this is a transcription of the
    // verifier's list rather than a shorter list that happens to agree with
    // it today.
    let strict = crate::policy();
    let Ok(valid) = cert.with_policy(&strict, sig.signature_creation_time()) else {
        return true;
    };
    if valid.alive().is_err() || matches!(valid.revocation_status(), RevocationStatus::Revoked(_)) {
        return true;
    }

    // `for_signing` rather than the bare amalgamation: a binding that does not
    // grant signing is no more use here than none, and the flags are read off
    // whichever binding the policy in hand put in force.
    valid
        .keys()
        .key_handle(key)
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .is_none()
}

/// The standard policy, widened to accept SHA-1 for a named set of
/// certificates and for nothing else.
///
/// Build it with [`crate::Store::sha1_policy`], which reads the user's opt-in
/// list; [`Sha1Policy::strict`] gives an instance that accepts nothing, which
/// is what every caller gets when the list is empty.
///
/// Deliberately not a [`Policy`] itself. A policy is asked about a signature
/// and knows nothing of the certificate the signature is about to be checked
/// against, so the only per-certificate answer it could give would come from
/// the signature's own issuer subpackets — unauthenticated bytes, half of
/// them in an area anyone may rewrite. This type hands out a policy per
/// question instead: [`Sha1Policy::for_cert`] to judge a certificate,
/// [`Sha1Policy::verification`] to read a message, and
/// [`Sha1Policy::accepts`] for the caller that has the verifying certificate
/// in hand and is deciding what to report.
#[derive(Debug)]
pub struct Sha1Policy {
    strict: StandardPolicy<'static>,
    permissive: StandardPolicy<'static>,
    /// The primary fingerprints the user opted in.
    ///
    /// Fingerprints rather than key IDs, and it is worth saying why the short
    /// handle went: every question asked of this set is now asked about a
    /// certificate already in hand — the one a signature verified against, or
    /// the one a key-list row is being built from — so there is no issuer
    /// handle left to resolve, nothing to be confused by a 64-bit collision,
    /// and no way for a claim made in a signature to pick which certificate
    /// gets the relaxed rule.
    accepted: BTreeSet<Fingerprint>,
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

    /// Accept SHA-1 for `cert`.
    pub fn accept(&mut self, cert: &Cert) {
        self.accepted.insert(cert.fingerprint());
    }

    /// Whether the opt-in list is empty, so that this accepts SHA-1 for
    /// nothing and behaves as the standard policy for every certificate.
    pub fn is_strict(&self) -> bool {
        self.accepted.is_empty()
    }

    /// Whether the user opted *this* certificate in.
    pub fn accepts(&self, cert: &Cert) -> bool {
        self.accepted.contains(&cert.fingerprint())
    }

    /// The policy to judge `cert` itself under.
    ///
    /// Relaxed for a certificate the user named and strict for every other
    /// one, in the very same operation. This is what makes the key list's
    /// account of a certificate — its validity, its user IDs, its subkeys —
    /// a statement about that certificate rather than about whatever its
    /// signatures happen to claim.
    pub fn for_cert(&self, cert: &Cert) -> &dyn Policy {
        if self.accepts(cert) {
            &self.permissive
        } else {
            &self.strict
        }
    }

    /// The policy sequoia's verifier reads a whole message under.
    ///
    /// Relaxed as soon as anything is opted in, because sequoia takes one
    /// policy for the message and which certificate a signature came from is
    /// not known until it has verified against a key. So this widens what the
    /// *parser* will consider and settles nothing: every good signature it
    /// yields goes back through [`Sha1Policy::accepts`] in [`crate::ops`],
    /// against the certificate that verified it, and one that leaned on SHA-1
    /// without being opted in is reported bad there. That last judgement is
    /// [`load_bearing`], which puts every question this policy answered to
    /// the strict one again, so no relaxation granted here survives into a
    /// verdict on its own. Strict while the list is empty, which is the
    /// ordinary case and leaves verification exactly as it was before this
    /// module existed.
    ///
    /// The relaxation is not free for the certificates it was not granted
    /// for, though, and this is where that cost is incurred: a policy decides
    /// which self-signature is in force, so a certificate whose newest one is
    /// SHA-1 and worse than the binding it supersedes is read here as the
    /// worse of the two. Nothing settled afterwards can put that back,
    /// because a signature refused for it never reaches [`crate::ops`]'s
    /// judgement at all. See the module documentation.
    pub fn verification(&self) -> &dyn Policy {
        if self.is_strict() {
            &self.strict
        } else {
            &self.permissive
        }
    }
}
