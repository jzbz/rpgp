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

use std::time::{Duration, SystemTime};

use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::policy::StandardPolicy;

/// The policy every operation in this crate is evaluated against.
///
/// Sequoia has no global policy: each call that interprets a certificate takes
/// one explicitly, so a single definition here keeps the whole app consistent.
pub fn policy() -> StandardPolicy<'static> {
    StandardPolicy::new()
}

/// How long [`signature_time`] waits for the moment it has to date a signature
/// at, before it refuses instead.
///
/// rPGP dates nothing ahead of the clock, so one of its own signatures makes
/// the next wait for the rest of the second it was made in and no more. Earlier
/// versions dated a withdrawal, and a certification made straight after one,
/// up to two seconds ahead, and two machines whose clocks nothing keeps in step
/// can disagree by a few seconds besides. Anything further ahead was dated by a
/// clock that is wrong, this one or the other, and waiting it out would hold
/// the busy indicator up, unexplained, over a question only the user can
/// settle. Past this, the refusal puts it to them.
const LONGEST_WAIT: Duration = Duration::from_secs(5);

/// The time to date a new signature at so that it takes precedence over every
/// one of `superseded`, having waited for that time if it has not come yet.
///
/// OpenPGP gives the newest signature of a kind the last word. A key's expiry,
/// flags and preferences are read off its newest binding; a soft revocation
/// stands only until a newer self-signature; sequoia-wot counts a certifier's
/// newest certification of a user ID, and a withdrawal only when it is newer
/// still. A signature dated by the local clock alone therefore lost to one
/// already dated later — made on a machine whose clock ran ahead, by GnuPG on
/// another machine, or by whoever made the key and handed it over — and lost
/// silently: it was stored, the operation reported success, and once real time
/// passed the other signature, the other one was what counted. That was a
/// revocation that stopped revoking, an expiry change that did not take, and a
/// re-certification that left the old one standing.
///
/// So the new signature is dated at least a second after the newest of
/// `superseded`. Not in the same second, because signature times are whole
/// seconds and a tie is not reliably the new signature's. Sequoia orders two
/// self-signatures of one second by comparing their MPIs, which are salted and
/// so effectively random, and does so separately for every component, so two
/// expiry changes in one second left a mix of both; sequoia-wot keeps every
/// certification from a certifier's newest second and walks the strongest, so
/// a change of mind within the second changed nothing. A tie does go a soft
/// revocation's way in sequoia, and a certification's way against a withdrawal
/// in sequoia-wot, but one rule that is right for every kind is easier to keep
/// true than one per kind, and it costs a second at most.
///
/// The caller chooses `superseded`, and chooses narrowly. Verified signatures
/// only — sequoia's `self_signatures` and `self_revocations`, which verify, or
/// a certification checked against the certifier's key — because anyone can
/// write a packet that merely names a key, and one that could set the date
/// would let a stranger hold rPGP's signatures back or have them refused. And
/// only the signatures the new one competes with: the same component's
/// bindings, the same certifier's word on the same user ID. A date taken from
/// anything else buys nothing, and a binding dated past a revocation it was
/// never meant to answer would undo it. A hard revocation of a key competes
/// with nothing, since sequoia holds one final whatever is dated after it, so
/// it passes nothing here and is never held up.
///
/// Waited for, rather than dated ahead. Sequoia reads a certificate as it
/// stands at a moment and counts only signatures made by then, so a signature
/// dated past the clock changes nothing until the clock gets there: the
/// certificate an operation returns, and the list reloaded after it, would read
/// as they did before the change being reported, and the check `revoke` makes
/// of the revocation it has just signed would reject it. Nor could every
/// signature be dated at all: sequoia's `set_expiration_time` dates what it
/// signs by the clock and takes no time from its caller, so for those waiting
/// is the only way past anything. The time returned is never earlier than the
/// one waited for, even where the clock is stepped back during the wait.
///
/// Past [`LONGEST_WAIT`] the answer is an error naming the date, rather than a
/// signature dated past it, which would count nowhere until that date came, or
/// one dated now, which would never count at all.
pub(crate) fn signature_time<'a>(
    superseded: impl IntoIterator<Item = &'a Signature>,
) -> Result<SystemTime> {
    let Some(newest) = superseded
        .into_iter()
        .filter_map(|signature| signature.signature_creation_time())
        .max()
    else {
        return Ok(SystemTime::now());
    };
    let floor = newest + Duration::from_secs(1);
    let now = SystemTime::now();
    let Ok(ahead) = floor.duration_since(now) else {
        return Ok(now);
    };
    if ahead > LONGEST_WAIT {
        return Err(Error::invalid(format!(
            "a signature already on this key is dated {}, ahead of this computer's clock, \
             and one made now would not supersede it: check the clock",
            chrono::DateTime::<chrono::Local>::from(newest).format("%Y-%m-%d %H:%M:%S")
        )));
    }
    std::thread::sleep(ahead);
    Ok(SystemTime::now().max(floor))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::packet::signature::SignatureBuilder;
    use sequoia_openpgp::types::SignatureType;

    use super::*;

    /// Signatures dated at each of `times`, which is all [`signature_time`]
    /// reads of one.
    fn dated(times: &[SystemTime]) -> Vec<Signature> {
        let (cert, _) = CertBuilder::new().generate().unwrap();
        let mut signer = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        times
            .iter()
            .map(|&time| {
                SignatureBuilder::new(SignatureType::Binary)
                    .set_signature_creation_time(time)
                    .unwrap()
                    .sign_message(&mut signer, b"")
                    .unwrap()
            })
            .collect()
    }

    /// A second ahead is the shape one of rPGP's own signatures takes for the
    /// next operation: made in the second that is still running. The date
    /// comes out after it, and has been waited for rather than set ahead of
    /// the clock, which is what lets whatever reads the certificate next see
    /// the new signature count.
    #[test]
    fn a_signature_is_dated_after_the_newest_it_supersedes_and_never_ahead_of_the_clock() {
        let now = SystemTime::now();
        let hour = Duration::from_secs(60 * 60);
        let signatures = dated(&[now - hour, now + Duration::from_secs(1)]);
        let newest = signatures[1].signature_creation_time().unwrap();

        let when = signature_time(&signatures).unwrap();
        assert!(
            when >= newest + Duration::from_secs(1),
            "{when:?} ties with or precedes the signature it has to supersede, {newest:?}"
        );
        assert!(
            when <= SystemTime::now(),
            "{when:?} is ahead of the clock, so nothing reading the certificate now would count it"
        );
    }

    /// A signature a day ahead was dated by a clock that is wrong, and neither
    /// answer that does not refuse is honest: one dated past it counts nowhere
    /// for a day, and one dated now never counts at all. The refusal comes at
    /// once, rather than after a wait, and names the date so that the user has
    /// something to compare the clock with.
    #[test]
    fn a_signature_dated_far_ahead_of_the_clock_is_refused_rather_than_waited_for() {
        let tomorrow = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
        let signatures = dated(&[tomorrow]);
        let newest = signatures[0].signature_creation_time().unwrap();

        let started = Instant::now();
        let refused = signature_time(&signatures)
            .map(|_| ())
            .expect_err("dated a signature past, or before, one a day ahead of the clock");
        assert!(
            started.elapsed() < LONGEST_WAIT,
            "the refusal must come at once, not after waiting"
        );
        let message = refused.to_string();
        let date = chrono::DateTime::<chrono::Local>::from(newest)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        assert!(
            message.contains(&date) && message.contains("clock"),
            "the refusal must name the date and the clock: {message}"
        );
    }
}
