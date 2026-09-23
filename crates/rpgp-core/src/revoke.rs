//! Revocation: retracting a certificate, or retracting a certification you
//! previously made.
//!
//! Revocation in OpenPGP is one-way and public. There is no un-revoke: the
//! revocation signature becomes part of the certificate and anyone who has the
//! certificate keeps it forever. Everything in this module is therefore
//! deliberately explicit about which of the two things is being retracted.

use std::path::Path;
use std::time::SystemTime;

use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::types::{
    ReasonForRevocation, RevocationStatus, RevocationType, SignatureType,
};
use sequoia_openpgp::{Cert, Packet, PacketPile};

use crate::error::{Error, Result};
use crate::policy;
use crate::store::Store;
use zeroize::Zeroizing;

/// Why something is being revoked.
///
/// OpenPGP's list is longer, but the extra codes are either user-ID specific or
/// private, and offering a user a choice they cannot evaluate is worse than
/// offering four they can.
///
/// The ordering, and the default, are load-bearing. "No reason given" is not
/// the neutral choice it sounds like: OpenPGP treats an unspecified reason as
/// a *hard* revocation, the same as a compromise, invalidating every signature
/// the key ever made. So the two soft reasons come first, the default is soft,
/// and the two hard ones sit together at the end where the dialogs can warn on
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reason {
    /// The key is simply out of service. Soft: past signatures stand.
    #[default]
    Retired,
    /// A replacement key has been issued. Soft.
    Superseded,
    /// The secret key may be in someone else's hands. Hard: it invalidates
    /// signatures made in the past as well, because there is no way to know
    /// which of them were really yours.
    Compromised,
    /// No reason. Hard, per the standard — the reader has no basis to trust
    /// anything the key did, so nothing it did is trusted.
    Unspecified,
}

impl Reason {
    /// Dialog order. The two hard reasons are last, and adjacent, so a dialog
    /// can warn on `index >= 2` and stay right if the labels change.
    pub const ALL: [Reason; 4] = [
        Reason::Retired,
        Reason::Superseded,
        Reason::Compromised,
        Reason::Unspecified,
    ];

    /// The dialog and details-pane label: capitalised, and standing alone.
    pub fn label(self) -> &'static str {
        match self {
            Reason::Retired => "No longer used",
            Reason::Superseded => "Replaced by a newer key",
            Reason::Compromised => "Secret key may be compromised",
            Reason::Unspecified => "No reason given (treated as compromised)",
        }
    }

    /// The same reason set inside a sentence, for [`Error::Revoked`].
    ///
    /// [`Reason::label`] cannot serve both: dropped mid-sentence it puts a
    /// capital letter where none belongs, and `Unspecified`'s parenthetical
    /// lands inside whatever punctuation the sentence already uses.
    pub(crate) fn clause(self) -> &'static str {
        match self {
            Reason::Retired => "no longer used",
            Reason::Superseded => "replaced by a newer key",
            Reason::Compromised => "the secret key may be compromised",
            Reason::Unspecified => "no reason given, which the standard treats as a compromise",
        }
    }

    /// A hard revocation also invalidates past signatures.
    ///
    /// Derived from sequoia's own classification rather than restated, so this
    /// cannot disagree with what the verifier will actually do.
    pub fn is_hard(self) -> bool {
        self.to_openpgp().revocation_type() == sequoia_openpgp::types::RevocationType::Hard
    }

    pub fn from_index(index: i32) -> Self {
        Reason::ALL
            .get(index.max(0) as usize)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) fn to_openpgp(self) -> ReasonForRevocation {
        match self {
            Reason::Unspecified => ReasonForRevocation::Unspecified,
            Reason::Superseded => ReasonForRevocation::KeySuperseded,
            Reason::Compromised => ReasonForRevocation::KeyCompromised,
            Reason::Retired => ReasonForRevocation::KeyRetired,
        }
    }

    fn from_openpgp(reason: ReasonForRevocation) -> Self {
        match reason {
            ReasonForRevocation::KeySuperseded => Reason::Superseded,
            ReasonForRevocation::KeyCompromised => Reason::Compromised,
            ReasonForRevocation::KeyRetired => Reason::Retired,
            _ => Reason::Unspecified,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RevokeRequest {
    pub fingerprint: String,
    pub reason: Reason,
    /// Free text stored in the revocation for whoever reads it later.
    pub message: String,
    pub password: Option<Zeroizing<String>>,
}

impl RevokeRequest {
    pub fn new(fingerprint: impl Into<String>) -> Self {
        RevokeRequest {
            fingerprint: fingerprint.into(),
            reason: Reason::default(),
            message: String::new(),
            password: None,
        }
    }
}

/// Revoke one of our own certificates, and store the result.
pub fn revoke_cert(store: &Store, request: &RevokeRequest) -> Result<Cert> {
    let cert = store.secret_cert(&request.fingerprint)?;

    // A soft revocation stands only until a newer self-signature on the
    // primary key: sequoia measures it against the newer of the direct-key
    // signature and the primary user ID's binding, and drops it if that one is
    // later. Dated by the clock alone, a revocation `apply` accepted, and the
    // GUI reported, stopped counting the moment real time passed a
    // self-signature dated after it — an expiry extended on a machine whose
    // clock ran ahead, say — here and for everyone the key was sent to. Every
    // user ID's bindings count, not only the primary one's, because which
    // identity is primary is itself settled by those bindings and can come out
    // differently at a later time or in another implementation. See
    // [`crate::signature_time`].
    //
    // Measured against both halves of the store, because `apply` writes the
    // revocation into cert-d as well, where a self-signature that arrived by
    // import or refresh, and never reached the secret key file, would
    // otherwise outrank it.
    //
    // A hard revocation is final whatever is dated after it — sequoia passes
    // `hard_revocations_are_final` for keys — so it supersedes nothing and is
    // dated now. A clock that disagrees with the key is no reason to hold up
    // revoking one whose secret is exposed, and a refusal there would be the
    // one place this rule did harm.
    let when = if request.reason.is_hard() {
        SystemTime::now()
    } else {
        let merged = store.full_cert(&request.fingerprint)?;
        crate::signature_time(
            merged
                .primary_key()
                .self_signatures()
                .chain(merged.userids().flat_map(|ua| ua.self_signatures())),
        )?
    };

    let mut signer = primary_signer(&cert, request.password.as_deref().map(String::as_str))?;
    let signature = CertRevocationBuilder::new()
        .set_signature_creation_time(when)?
        .set_reason_for_revocation(request.reason.to_openpgp(), request.message.as_bytes())?
        .build(&mut signer, &cert, None)?;

    apply(store, cert, signature)
}

/// Retract certifications we previously made over `target`'s user IDs.
///
/// This does not touch the target's own self-signatures; it only withdraws our
/// opinion of them.
pub fn revoke_certification(
    store: &Store,
    certifier: &str,
    target: &str,
    user_ids: &[String],
    reason: Reason,
    message: &str,
    password: Option<&str>,
) -> Result<Cert> {
    if user_ids.is_empty() {
        return Err(Error::invalid("select at least one user ID"));
    }

    // The certifier may be a card key, which has no local secret half; the
    // public certificate is enough for the agent to find it by keygrip. certify()
    // has always accepted one, and the GUI offers card keys as certifiers, so
    // refusing them here meant a certification the app let you make could not be
    // withdrawn from the app.
    let certifier = store
        .secret_cert(certifier)
        .or_else(|_| store.lookup(certifier))?;
    let target = store.lookup(target)?;
    let mut signer = certification_signer(&certifier, password)?;

    // Hoisted for the verification filter below, and invariant across user IDs.
    let certifier_key = certifier.primary_key().key();

    let mut signatures = Vec::new();
    for wanted in user_ids {
        // The mirror of certify()'s rule, which this path used to lack: the
        // first user ID whose lossy rendering matched was the one revoked, so a
        // withdrawal could be signed over a user ID this certifier never
        // certified while the real certification stood and the status bar said
        // it had been withdrawn. `cert::resolve_user_id` carries the reasoning.
        let amalgamation = crate::cert::resolve_user_id(&target, wanted)?;
        let userid = amalgamation.userid().clone();

        // A revocation only supersedes a certification made strictly earlier:
        // sequoia-wot ignores a withdrawal dated in the same second as the
        // certification or before it. Certifying and then changing your mind
        // within the same second — which is a normal thing for a person
        // clicking two buttons to do — would otherwise leave the certification
        // standing. So the revocation is dated at least a second past the
        // newest certification it retracts, by [`crate::signature_time`], which
        // waits for that second rather than dating it ahead of the clock.
        //
        // Only *this certifier's* certifications set the clock. Everyone's did,
        // once, which meant a single future-dated certification from some third
        // party pushed our revocation into the future — where it does not apply
        // yet, and our certification stood despite having been withdrawn.
        //
        // "This certifier's" means one that verifies against our key, not one
        // that merely names it. certifications() hands back packets exactly as
        // they were parsed, and an issuer subpacket is an unauthenticated hint
        // anyone can write — so filtering on the name alone let a planted
        // packet dated in the far future set `when` to that instant, producing
        // a revocation that is not yet valid and never takes effect, leaving
        // the certification the user asked to withdraw still standing. Were
        // this filter removed, a date that far ahead would now be refused
        // rather than signed, so the same packet would block the withdrawal
        // outright instead. certify.rs makes exactly
        // this check on the mirror path; this is the other half of it.
        let when = crate::signature_time(
            amalgamation
                .certifications()
                .filter(|sig| crate::cert::issued_by(sig, &certifier))
                .filter(|sig| {
                    (*sig)
                        .clone()
                        .verify_userid_binding(certifier_key, target.primary_key().key(), &userid)
                        .is_ok()
                }),
        )?;

        signatures.push(
            SignatureBuilder::new(SignatureType::CertificationRevocation)
                .set_signature_creation_time(when)?
                .set_reason_for_revocation(reason.to_openpgp(), message.as_bytes())?
                .sign_userid_binding(&mut signer, target.primary_key().key(), &userid)?,
        );
    }

    let revoked = target.insert_packets(signatures)?.0;
    store.insert(&revoked)?;
    Ok(revoked)
}

/// Armor a revocation signature for storage or publication.
///
/// Armored as a public key block rather than as a signature, because that is
/// what GnuPG writes for a revocation certificate and what other tools expect
/// to be handed. The payload is still a bare signature packet.
pub fn armor(signature: &Signature) -> Result<Vec<u8>> {
    let mut writer =
        sequoia_openpgp::armor::Writer::new(Vec::new(), sequoia_openpgp::armor::Kind::PublicKey)?;
    Packet::from(signature.clone()).serialize(&mut writer)?;
    Ok(writer.finalize()?)
}

/// Read a revocation certificate from disk and apply it to the certificate it
/// names.
///
/// This is the emergency path: it needs no secret key and no passphrase,
/// because the signature was made when the revocation certificate was created.
pub fn apply_revocation_file(store: &Store, path: &Path) -> Result<Cert> {
    // Read whole, so the size has to be settled before reading rather than
    // after: `PacketPile` holds every packet in the file at once, and this path
    // takes a file somebody else made. The network fetch has had a cap for the
    // same reason since it was written; a file simply arrives by a different
    // road.
    //
    // The number is generous by three orders of magnitude, which is what makes
    // it safe to apply here. A revocation certificate is one signature — GnuPG
    // writes about seven hundred bytes — and even a certificate carrying a
    // designated revoker adds only a handful more. Nor is this the door a large
    // keyring comes through: `import_file` streams and handles those, and this
    // function is only reached when it has already failed to find a single
    // certificate in the file.
    const MAX_REVOCATION: u64 = 1024 * 1024;
    if let Ok(metadata) = std::fs::metadata(path)
        && metadata.len() > MAX_REVOCATION
    {
        return Err(Error::invalid(format!(
            "{} is too large to be a revocation certificate",
            path.display()
        )));
    }

    let pile = PacketPile::from_file(path)
        .map_err(|_| Error::invalid(format!("{} is not an OpenPGP file", path.display())))?;

    let signatures: Vec<Signature> = pile
        .into_children()
        .filter_map(|packet| match packet {
            Packet::Signature(signature) => Some(signature),
            _ => None,
        })
        .collect();

    if signatures.is_empty() {
        return Err(Error::invalid(format!(
            "{} contains no revocation signature",
            path.display()
        )));
    }

    // A revocation names its target through the issuer subpackets.
    // Every issuer of every signature, not the first one that resolves. A
    // revocation names its target through the issuer subpackets, and a
    // designated-revoker certificate names the revoker as well — so the first
    // resolvable handle is often the wrong certificate to apply it to, and
    // returning on it meant the emergency path failed for exactly the
    // certificates it exists to retract. `apply` re-checks cryptographically,
    // so trying several costs nothing but a few merges that come to nothing.
    let mut last = None;
    for signature in &signatures {
        for handle in signature.get_issuers() {
            let Ok(cert) = store.lookup(&handle.to_string()) else {
                continue;
            };
            match apply(store, cert, signature.clone()) {
                Ok(revoked) => return Ok(revoked),
                Err(e) => last = Some(e),
            }
        }
    }
    if let Some(e) = last {
        return Err(e);
    }

    Err(Error::invalid(
        "the revocation is for a certificate that is not in this store",
    ))
}

/// Merge `signature` into `cert`, confirm it really did revoke it, and store.
fn apply(store: &Store, cert: Cert, signature: Signature) -> Result<Cert> {
    let fingerprint = cert.fingerprint().to_hex();
    let revoked = cert.insert_packets(signature.clone())?.0;

    // Guard against silently storing a signature that changed nothing — a
    // revocation from the wrong key, or one the policy rejects.
    //
    // The test is whether *this* signature was accepted, not whether the
    // certificate ends up revoked. Sequoia computes revocation_status from the
    // revocations it has already verified, so on a certificate that was
    // revoked before this call the status is Revoked whatever we just inserted
    // — the guard passed on its own history and wrote an arbitrary signature
    // packet into the secret key file. Asking whether the returned set
    // contains this signature keeps the verification sequoia already did, and
    // covers a designated revoker's signature as readily as a self-revocation.
    let accepted = match revoked.revocation_status(&policy(), None) {
        RevocationStatus::Revoked(verified) => verified.iter().any(|s| **s == signature),
        _ => false,
    };
    if !accepted {
        return Err(Error::invalid(format!(
            "that signature does not revoke {fingerprint}"
        )));
    }

    store.insert(&revoked)?;

    // Keep the secret copy in step, so the revocation survives a reload. The
    // signature has to be merged into the *secret* certificate: `revoked` may
    // have come from cert-d, which only ever holds the public half.
    if store.has_secret(&fingerprint) {
        let secret = store.secret_cert(&fingerprint)?;
        store.insert_secret(&secret.insert_packets(signature)?.0)?;
    }
    Ok(revoked)
}

/// Why a certificate was revoked, if it was.
pub fn revocation_reason(cert: &Cert) -> Option<(Reason, String)> {
    let RevocationStatus::Revoked(signatures) = cert.revocation_status(&policy(), None) else {
        return None;
    };

    // Newest first, and a hard revocation stays in the set whatever follows
    // it, because nothing undoes one. Reporting the newest would let a
    // KeyRetired — which anyone holding the stolen secret can issue — hide a
    // KeyCompromised behind "No longer used", so prefer the newest hard
    // revocation and fall back to the newest of any kind. A revocation
    // carrying no reason subpacket is hard (RFC 9580 §5.2.3.31), which is
    // also why the reason-less case reports Unspecified rather than blanking
    // the banner: returning None here left the certificate looking unrevoked.
    let signature = signatures
        .iter()
        .find(|s| {
            s.reason_for_revocation()
                .is_none_or(|(code, _)| code.revocation_type() == RevocationType::Hard)
        })
        .or_else(|| signatures.first())?;

    Some(match signature.reason_for_revocation() {
        Some((code, message)) => (
            Reason::from_openpgp(code),
            String::from_utf8_lossy(message).into_owned(),
        ),
        None => (Reason::Unspecified, String::new()),
    })
}

/// Refuse a certificate whose owner has withdrawn it.
///
/// Every operation that makes something *new* — a message encrypted to a key, a
/// signature, a certification, a fresh self-signature — asks this first.
/// Sequoia's key iterators cannot answer it. `revoked(false)` reports each
/// key's own revocation, and for a subkey that says nothing about the
/// certificate's: `ValidKeyAmalgamation::revocation_status` (sequoia-openpgp
/// 2.4.1) consults the certificate only for the primary key. A certificate
/// revoked as a whole therefore keeps offering healthy-looking signing and
/// encryption subkeys. `alive()` *does* consult the certificate, which is why
/// expiry was caught all along and revocation was not.
///
/// The soft reasons are refused with the hard ones. "Replaced by a newer key"
/// and "no longer used" still say the owner has stopped using this key, so a
/// message encrypted to it is as unreadable to them as one encrypted to a key
/// that was stolen, and a signature from it is one every verifier holding the
/// revocation rejects.
///
/// Two kinds of work are deliberately left out. Reading is one: [`crate::ops`]
/// decrypts and verifies through revoked certificates on purpose, because
/// revoking withdraws a key from future use and does not burn the archive.
/// Withdrawing is the other: [`revoke_certification`] takes back something the
/// key already said, which is the one thing its owner may still want to do with
/// it the day after revoking it, so its signer does not come through here.
///
/// `RevocationStatus::CouldBe` is not treated as a revocation. Sequoia puts
/// every signature in `other_revocations` there without verifying any of them
/// — `revocation_status_intern` (cert/bundle.rs, sequoia-openpgp 2.4.1) never
/// promotes one to `Revoked` — so it collects third-party packets in general
/// and not only the designated-revoker case. Anyone can write such a packet, so
/// acting on one would let a stranger take a key out of service. It also means
/// this agrees exactly with the Revoked pill [`crate::CertSummary`] already
/// draws, and no one meets a refusal for a certificate the app shows as valid.
pub(crate) fn refuse_if_revoked(cert: &Cert) -> Result<()> {
    refuse_if_revoked_as(cert, None)
}

/// [`refuse_if_revoked`] where the operation has two certificates in play and
/// the message has to say which of them it means.
///
/// `role` is a noun phrase parenthesised after the name — "Bob
/// <bob@example.org> (the certifier)" — because "Certification failed: Carol
/// has been revoked" leaves the reader to guess whether Carol was the one being
/// vouched for or the one vouching.
pub(crate) fn refuse_if_revoked_as(cert: &Cert, role: Option<&str>) -> Result<()> {
    let policy = policy();
    if !matches!(
        cert.revocation_status(&policy, None),
        RevocationStatus::Revoked(_)
    ) {
        return Ok(());
    }

    // `revocation_reason` reads the same status, so the only way it says
    // nothing here is a Revoked set with no signatures in it, which sequoia
    // does not build. Naming the harshest reading of a missing reason keeps the
    // message honest if that ever changes.
    let reason = revocation_reason(cert).map_or(Reason::Unspecified, |(reason, _)| reason);
    let valid = cert.with_policy(&policy, None).ok();
    // A certificate need carry no user ID at all — nothing on the import path
    // asks for one — and for such a certificate `primary_user_id` answers
    // "(no user ID)", which names nothing in a status bar that has room for
    // one identifier. The fingerprint is what the rest of the crate falls back
    // to when there is no name, as `Error::NoSecretKey` does.
    let name = match cert.userids().next() {
        Some(_) => crate::cert::primary_user_id(cert, valid.as_ref()),
        None => cert.fingerprint().to_hex(),
    };
    Err(Error::Revoked {
        name: match role {
            Some(role) => format!("{name} ({role})"),
            None => name,
        },
        reason: reason.clause().to_string(),
    })
}

fn primary_signer(cert: &Cert, password: Option<&str>) -> Result<sequoia_openpgp::crypto::KeyPair> {
    let key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| Error::NoSecretKey(cert.fingerprint().to_hex()))?;
    // Keeps its primary role: an RFC 9580 secret cannot be decrypted without
    // it. See crate::secret::unlock.
    crate::secret::keypair(key, password)
}

/// A signer for [`revoke_certification`].
///
/// Deliberately does not ask [`refuse_if_revoked`], and takes the agent's
/// withdrawal entry point rather than `certifier_for` so that the agent does
/// not ask on its behalf either. Retracting a certification is taking back
/// something already said, not making new use of the key, and someone who has
/// just revoked their own certificate is exactly the person who may now want to
/// withdraw what it vouched for.
fn certification_signer(
    cert: &Cert,
    password: Option<&str>,
) -> Result<Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync>> {
    let policy = policy();
    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| Error::NoSecretKey(cert.fingerprint().to_hex()))?;
    let ka = valid
        .keys()
        .secret()
        .alive()
        .revoked(false)
        .supported()
        .for_certification()
        .next();

    // No local secret half means a card key: hand the agent the certificate and
    // let it find the key by keygrip, as certify() does — but through the
    // withdrawal entry point, which alone among the agent's signing paths does
    // not refuse a revoked certificate.
    //
    // The filter above is a separate matter and predates that check: for the
    // primary key `revoked(false)` *is* the certificate's status, so a revoked
    // certificate whose primary key certifies — which is every key this app
    // generates — already falls through to the agent here and fails there
    // unless the agent happens to hold it. Withdrawing a certification made
    // with a key since revoked therefore still does not work in general; what
    // this entry point preserves is the case that did work, a card-held
    // certification subkey.
    match ka {
        Some(ka) => Ok(Box::new(crate::secret::keypair(
            ka.key().clone(),
            password,
        )?)),
        None => Ok(Box::new(crate::agent::certification_withdrawer_for(cert)?)),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::cert::Validity;
    use crate::certify::{CertifyRequest, certify};
    use crate::keygen::{KeyGenRequest, generate};
    use crate::{CertSummary, wot};

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    /// An already-revoked certificate must not accept an arbitrary signature.
    ///
    /// The guard used to read the certificate's revocation status, which
    /// sequoia computes from the revocations it has already verified. On a
    /// certificate revoked earlier that is Revoked no matter what was just
    /// inserted, so the check passed on the certificate's own history and any
    /// signature packet was written into the secret key file.
    ///
    /// Restore the status-only guard and this fails: apply returns Ok.
    #[test]
    fn an_already_revoked_certificate_still_refuses_a_foreign_signature() {
        let (_dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let other = generate(&KeyGenRequest::new("Other <other@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        store.insert_secret(&other).unwrap();

        let mut request = RevokeRequest::new(mine.fingerprint().to_hex());
        request.reason = Reason::Superseded;
        let revoked = revoke_cert(&store, &request).unwrap();
        assert!(
            revocation_reason(&revoked).is_some(),
            "it is revoked already"
        );

        // A signature that has nothing to do with revoking this certificate:
        // Other's certification of its own user ID.
        let foreign = other
            .userids()
            .next()
            .unwrap()
            .self_signatures()
            .next()
            .unwrap()
            .clone();

        let outcome = apply(&store, revoked, foreign);
        assert!(
            outcome.is_err(),
            "a signature that does not revoke this certificate must be refused, \
             even when the certificate is already revoked"
        );
    }

    #[test]
    fn revokes_our_own_certificate_with_a_reason() {
        let (_dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        let fingerprint = mine.fingerprint().to_hex();

        assert_eq!(CertSummary::from_cert(&mine).validity, Validity::Valid);
        assert!(revocation_reason(&mine).is_none());

        let mut request = RevokeRequest::new(&fingerprint);
        request.reason = Reason::Compromised;
        request.message = "laptop stolen".to_string();
        let revoked = revoke_cert(&store, &request).unwrap();

        assert_eq!(CertSummary::from_cert(&revoked).validity, Validity::Revoked);
        let (reason, message) = revocation_reason(&revoked).unwrap();
        assert_eq!(reason, Reason::Compromised);
        assert!(reason.is_hard());
        assert_eq!(message, "laptop stolen");

        // Both halves of the store must agree, or a reload would resurrect it.
        assert_eq!(
            CertSummary::from_cert(&store.lookup(&fingerprint).unwrap()).validity,
            Validity::Revoked
        );
        assert_eq!(
            CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap()).validity,
            Validity::Revoked
        );
    }

    /// The banner has to show the worst thing that has happened to a key, not
    /// the most recent. Anyone holding a stolen secret can issue a further
    /// revocation with a gentler reason; if the newest wins, "the secret is in
    /// someone else's hands" is replaced by "no longer used" by the very person
    /// who stole it, and the reader downgrades their response accordingly.
    #[test]
    fn a_later_retirement_cannot_soften_a_compromise() {
        let (_dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        let fingerprint = mine.fingerprint().to_hex();

        let mut compromise = RevokeRequest::new(&fingerprint);
        compromise.reason = Reason::Compromised;
        compromise.message = "laptop stolen".to_string();
        revoke_cert(&store, &compromise).unwrap();

        let mut retire = RevokeRequest::new(&fingerprint);
        retire.reason = Reason::Retired;
        retire.message = "just retiring this".to_string();
        let revoked = revoke_cert(&store, &retire).unwrap();

        // Both are on the certificate; the question is which one is reported.
        let (reason, message) = revocation_reason(&revoked).unwrap();
        assert_eq!(
            reason,
            Reason::Compromised,
            "a soft revocation issued later must not mask the hard one; got {message:?}"
        );
        assert!(reason.is_hard());
        assert_eq!(message, "laptop stolen");
    }

    /// "No reason given" is a hard revocation in OpenPGP, and it used to be
    /// the default. Pinned here so neither the default nor the classification
    /// can drift back without a test noticing.
    #[test]
    fn unspecified_is_hard_and_the_default_is_soft() {
        assert!(
            Reason::Unspecified.is_hard(),
            "the standard treats no-reason as compromise"
        );
        assert!(Reason::Compromised.is_hard());
        assert!(!Reason::Retired.is_hard());
        assert!(!Reason::Superseded.is_hard());

        assert!(
            !Reason::default().is_hard(),
            "the default must be a soft revocation"
        );
        assert!(
            !Reason::from_index(0).is_hard(),
            "the dialog's first entry must be soft"
        );
        assert!(
            !Reason::from_index(99).is_hard(),
            "an out-of-range index must not go hard"
        );

        // The two hard reasons are the last two of ALL: the dialogs warn on
        // index >= 2 and rely on this.
        let hard: Vec<bool> = Reason::ALL.iter().map(|r| r.is_hard()).collect();
        assert_eq!(hard, [false, false, true, true]);
    }

    /// The primary user ID's binding, re-issued from itself and dated `when`:
    /// what a key's owner leaves on it by changing its expiry on a machine
    /// whose clock runs ahead of this one.
    fn binding_dated(secret: &Cert, when: SystemTime) -> Signature {
        let policy = policy();
        let valid = secret.with_policy(&policy, None).unwrap();
        let primary = valid.primary_userid().unwrap();
        let mut signer = primary_signer(secret, None).unwrap();
        SignatureBuilder::from(primary.binding_signature().clone())
            .set_signature_creation_time(when)
            .unwrap()
            .sign_userid_binding(&mut signer, secret.primary_key().key(), primary.userid())
            .unwrap()
    }

    /// A soft revocation stands only until a newer self-signature, and one
    /// dated by the clock alone lost to a binding already dated after it.
    /// `apply` accepted it, because that binding was not in force yet, the GUI
    /// said the key was revoked, and once real time passed the binding the key
    /// read as live again, here and for everyone it had been sent to.
    ///
    /// The binding reaches this store as a public certificate, which is how a
    /// keyserver refresh brings in an expiry extended on another machine: in
    /// cert-d and not in the secret key file, which is what the revocation is
    /// signed over. The date has to come from both.
    #[test]
    fn a_soft_revocation_outranks_a_self_signature_dated_ahead_of_the_clock() {
        let (_dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        let fingerprint = mine.fingerprint().to_hex();

        let binding = binding_dated(&mine, SystemTime::now() + Duration::from_secs(2));
        let ahead = binding.signature_creation_time().unwrap();
        store
            .insert(&mine.insert_packets(vec![Packet::from(binding)]).unwrap().0)
            .unwrap();

        // Retired, the default, which is soft.
        let revoked = revoke_cert(&store, &RevokeRequest::new(&fingerprint)).unwrap();
        assert_eq!(CertSummary::from_cert(&revoked).validity, Validity::Revoked);

        // Read as of a minute past the binding, when it would have taken over.
        let later = ahead + Duration::from_secs(60);
        for reloaded in [
            store.lookup(&fingerprint).unwrap(),
            store.full_cert(&fingerprint).unwrap(),
        ] {
            assert!(
                matches!(
                    reloaded.revocation_status(&policy(), later),
                    RevocationStatus::Revoked(_)
                ),
                "a binding dated ahead of the clock undid the revocation once its time came"
            );
        }
    }

    /// Past what a clock that keeps time can explain, a soft revocation is
    /// refused rather than signed: dated past a binding a day ahead it would
    /// count nowhere for a day, and dated now it would never count at all. A
    /// hard one is not held up, because nothing dated after it undoes it, and a
    /// key whose secret is exposed is the last thing to leave unrevoked over a
    /// clock.
    #[test]
    fn a_self_signature_far_ahead_refuses_a_soft_revocation_but_not_a_hard_one() {
        let (_dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let fingerprint = mine.fingerprint().to_hex();
        let day = Duration::from_secs(24 * 60 * 60);
        let tomorrow = SystemTime::now() + day;
        let binding = binding_dated(&mine, tomorrow);
        store
            .insert_secret(&mine.insert_packets(vec![Packet::from(binding)]).unwrap().0)
            .unwrap();
        let revoked = |t: Option<SystemTime>| {
            matches!(
                store
                    .lookup(&fingerprint)
                    .unwrap()
                    .revocation_status(&policy(), t),
                RevocationStatus::Revoked(_)
            )
        };

        let refused = revoke_cert(&store, &RevokeRequest::new(&fingerprint))
            .map(|_| ())
            .expect_err("signed a soft revocation that a binding a day ahead would undo");
        assert!(
            refused.to_string().contains("clock"),
            "the refusal must point at the clock: {refused}"
        );
        assert!(
            !revoked(None),
            "a refused revocation must not reach the store"
        );

        let mut request = RevokeRequest::new(&fingerprint);
        request.reason = Reason::Compromised;
        revoke_cert(&store, &request).expect("a hard revocation must not wait on the clock");
        assert!(revoked(None));
        assert!(
            revoked(Some(tomorrow + day)),
            "a hard revocation stands whatever is dated after it"
        );
    }

    #[test]
    fn an_emergency_revocation_certificate_works_without_the_passphrase() {
        let (_dir, store) = scratch();
        let mut request = KeyGenRequest::new("Me <me@example.org>");
        request.password = Some(Zeroizing::new("correct horse".to_string()));
        let generated = generate(&request).unwrap();
        store.insert_secret(&generated.cert).unwrap();

        let fingerprint = generated.cert.fingerprint().to_hex();
        let armored = armor(&generated.revocation).unwrap();
        store.save_revocation(&fingerprint, &armored).unwrap();
        assert!(store.has_revocation(&fingerprint));
        assert!(armored.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        // Revoking normally would need the passphrase; the stored certificate
        // was signed at generation time and needs nothing.
        let path = store.revocation_path(&fingerprint);
        let revoked = apply_revocation_file(&store, &path).unwrap();
        assert_eq!(CertSummary::from_cert(&revoked).validity, Validity::Revoked);
    }

    /// A real revocation certificate is under a kilobyte, so the cap is only
    /// ever reached by something that is not one. Padding the genuine file is
    /// the point: the same bytes that worked above are refused once there are
    /// too many of them, which is the cap talking and not the parser.
    #[test]
    fn an_oversized_revocation_file_is_refused_before_it_is_parsed() {
        let (_dir, store) = scratch();
        let generated = generate(&KeyGenRequest::new("Me <me@example.org>")).unwrap();
        store.insert_secret(&generated.cert).unwrap();

        let fingerprint = generated.cert.fingerprint().to_hex();
        let armored = armor(&generated.revocation).unwrap();
        store.save_revocation(&fingerprint, &armored).unwrap();
        let path = store.revocation_path(&fingerprint);

        // Armor ignores trailing text, so the padding cannot be what breaks it.
        let mut padded = std::fs::read(&path).unwrap();
        padded.extend(std::iter::repeat_n(b'\n', 1024 * 1024 + 1));
        std::fs::write(&path, &padded).unwrap();

        let err = apply_revocation_file(&store, &path)
            .expect_err("an oversized file was read whole")
            .to_string();
        assert!(
            err.contains("too large to be a revocation certificate"),
            "refused for the wrong reason: {err}"
        );
        assert_eq!(
            CertSummary::from_cert(&store.lookup(&fingerprint).unwrap()).validity,
            Validity::Valid,
            "the refusal must leave the certificate alone"
        );
    }

    #[test]
    fn revoking_a_certification_withdraws_authentication() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();

        let mut request =
            CertifyRequest::new(me.fingerprint().to_hex(), them.fingerprint().to_hex());
        request.user_ids = vec!["Them <them@example.org>".to_string()];
        certify(&store, &request).unwrap();

        let authenticated = |store: &Store| {
            let certs = store.certs().unwrap();
            let roots: Vec<String> = store.effective_roots().unwrap().into_iter().collect();
            wot::for_user_id(
                &wot::authenticate_all(&certs, &roots),
                &them.fingerprint().to_hex(),
                "Them <them@example.org>",
            )
        };
        assert_eq!(authenticated(&store), crate::Authentication::Full);

        // No wait before withdrawing, and none after. The revocation is dated a
        // second past the certification it retracts, and `revoke_certification`
        // waits for that second itself rather than dating the revocation ahead
        // of the clock, so it counts as soon as the call returns.
        revoke_certification(
            &store,
            &me.fingerprint().to_hex(),
            &them.fingerprint().to_hex(),
            &["Them <them@example.org>".to_string()],
            Reason::Superseded,
            "checked the wrong fingerprint",
            None,
        )
        .unwrap();

        assert_eq!(authenticated(&store), crate::Authentication::Unknown);
        // The target itself is untouched: only our opinion was withdrawn.
        assert_eq!(
            CertSummary::from_cert(&store.lookup(&them.fingerprint().to_hex()).unwrap()).validity,
            Validity::Valid
        );
    }

    /// Withdraw, then change your mind again. The revocation is dated a
    /// second past the certification; a re-certification has to be dated
    /// past the revocation in turn, or it is born already superseded.
    /// A revocation retracts only certifications made by the same key. The
    /// GUI used to withdraw with whichever of the user's keys sorted first,
    /// leaving the other key's endorsement standing while reporting success —
    /// this pins the core semantics that made that a silent failure.
    #[test]
    fn a_revocation_only_retracts_its_own_certifiers_work() {
        let (_dir, store) = scratch();
        let a = generate(&KeyGenRequest::new("A <a@example.org>"))
            .unwrap()
            .cert;
        let b = generate(&KeyGenRequest::new("B <b@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&a).unwrap();
        store.insert_secret(&b).unwrap();
        store.insert(&them).unwrap();

        let user_id = "Them <them@example.org>".to_string();
        for certifier in [&a, &b] {
            let mut request = CertifyRequest::new(
                certifier.fingerprint().to_hex(),
                them.fingerprint().to_hex(),
            );
            request.user_ids = vec![user_id.clone()];
            certify(&store, &request).unwrap();
        }

        // Authentication under exactly one root, so each key's own opinion can
        // be read separately.
        let under = |root: &Cert| {
            let certs = store.certs().unwrap();
            wot::for_user_id(
                &wot::authenticate_all(&certs, &[root.fingerprint().to_hex()]),
                &them.fingerprint().to_hex(),
                &user_id,
            )
        };
        assert_eq!(under(&a), crate::Authentication::Full);
        assert_eq!(under(&b), crate::Authentication::Full);

        // A withdraws. B's endorsement is not A's to retract.
        revoke_certification(
            &store,
            &a.fingerprint().to_hex(),
            &them.fingerprint().to_hex(),
            std::slice::from_ref(&user_id),
            Reason::Superseded,
            "",
            None,
        )
        .unwrap();

        assert_eq!(
            under(&a),
            crate::Authentication::Unknown,
            "A withdrew its own"
        );
        assert_eq!(
            under(&b),
            crate::Authentication::Full,
            "A's revocation must not retract B's certification"
        );

        // Only withdrawing with B too clears it — which is what the GUI now
        // does, one call per certifier.
        revoke_certification(
            &store,
            &b.fingerprint().to_hex(),
            &them.fingerprint().to_hex(),
            std::slice::from_ref(&user_id),
            Reason::Superseded,
            "",
            None,
        )
        .unwrap();
        assert_eq!(under(&b), crate::Authentication::Unknown);
    }

    /// A certification that merely *names* our key cannot date our withdrawal.
    ///
    /// `certifications()` hands back packets exactly as parsed, and an issuer
    /// subpacket in the unhashed area is not covered by any signature — anyone
    /// can write one. Filtering on the name alone let a planted packet dated in
    /// the far future push `when` to that instant, so the revocation carried a
    /// date it had not reached, never took effect, and the certification the
    /// user asked to withdraw kept standing. certify.rs makes the same check on
    /// the mirror path; this is the other half.
    ///
    /// Delete the `verify_userid_binding` filter in revoke_certification and
    /// this fails: the planted packet would date the withdrawal five years out,
    /// which is now refused, so the withdrawal the user asked for is not made
    /// at all.
    #[test]
    fn a_planted_certification_cannot_date_the_withdrawal() {
        use sequoia_openpgp::packet::signature::subpacket::{Subpacket, SubpacketValue};

        let (_dir, store) = scratch();
        let a = generate(&KeyGenRequest::new("A <a@example.org>"))
            .unwrap()
            .cert;
        let b = generate(&KeyGenRequest::new("B <b@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&a).unwrap();
        store.insert(&b).unwrap();
        store.insert(&them).unwrap();

        let user_id = "Them <them@example.org>".to_string();

        // A genuinely certifies, so there is something to withdraw.
        let mut request =
            CertifyRequest::new(a.fingerprint().to_hex(), them.fingerprint().to_hex());
        request.user_ids = vec![user_id.clone()];
        certify(&store, &request).unwrap();

        // The planted packet: B signs, five years out, and the signature is
        // then relabelled to name A in its unhashed area. issued_by() accepts
        // it because get_issuers() reads that area; verifying it against A does
        // not, because A never signed it.
        let userid = them
            .userids()
            .find(|ua| String::from_utf8_lossy(ua.userid().value()) == user_id.as_str())
            .unwrap()
            .userid()
            .clone();
        let future = SystemTime::now() + Duration::from_secs(5 * 365 * 24 * 60 * 60);
        let mut signer = certification_signer(&b, None).unwrap();
        let mut planted = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(future)
            .unwrap()
            .sign_userid_binding(&mut signer, them.primary_key().key(), &userid)
            .unwrap();
        planted
            .unhashed_area_mut()
            .add(Subpacket::new(SubpacketValue::Issuer(a.keyid()), false).unwrap())
            .unwrap();
        assert!(
            crate::cert::issued_by(&planted, &a),
            "the planted packet must look like A's, or the test proves nothing"
        );
        let them = them.insert_packets(vec![Packet::from(planted)]).unwrap().0;
        store.insert(&them).unwrap();

        let under = |root: &Cert| {
            let certs = store.certs().unwrap();
            wot::for_user_id(
                &wot::authenticate_all(&certs, &[root.fingerprint().to_hex()]),
                &them.fingerprint().to_hex(),
                &user_id,
            )
        };
        assert_eq!(under(&a), crate::Authentication::Full, "A certified Them");

        revoke_certification(
            &store,
            &a.fingerprint().to_hex(),
            &them.fingerprint().to_hex(),
            std::slice::from_ref(&user_id),
            Reason::Superseded,
            "",
            None,
        )
        .unwrap();

        assert_eq!(
            under(&a),
            crate::Authentication::Unknown,
            "the withdrawal must take effect now; a packet A did not sign cannot date it into the future"
        );
    }

    /// `certify`'s rule, on the path that withdraws what `certify` made.
    ///
    /// The user ID is chosen by its lossy rendering, which is not injective,
    /// and sequoia orders user IDs by their raw bytes — so of two that display
    /// alike the lower-sorting one was always the one signed over. A
    /// CertificationRevocation over a user ID this certifier never certified
    /// asserts nothing and retracts nothing: the endorsement the user asked to
    /// withdraw kept authenticating while the status bar said it was withdrawn,
    /// and the GUI, keying its withdrawn set on the same rendering, then took
    /// the Withdraw button away so it could not be tried again.
    #[test]
    fn withdrawing_a_certification_refuses_a_name_that_matches_two_user_ids() {
        use sequoia_openpgp::packet::UserID;

        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();

        // Two user IDs on their key, different bytes, identical rendering:
        // 0xFE and 0xFF are both invalid UTF-8 and both display as U+FFFD.
        let mut theirs = certification_signer(&them, None).unwrap();
        let mut packets: Vec<Packet> = Vec::new();
        let mut user_ids: Vec<UserID> = Vec::new();
        for byte in [0xFEu8, 0xFF] {
            let userid = UserID::from([b"Them <them@", &[byte][..], b".example>"].concat());
            let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
                .sign_userid_binding(&mut theirs, them.primary_key().key(), &userid)
                .unwrap();
            packets.push(Packet::from(userid.clone()));
            packets.push(Packet::from(binding));
            user_ids.push(userid);
        }

        // The endorsement sits on the second of the two, which is the one the
        // first match never reaches. Signed here rather than through certify(),
        // which refuses the ambiguity this test is built on.
        let mut mine = certification_signer(&me, None).unwrap();
        packets.push(Packet::from(
            SignatureBuilder::new(SignatureType::GenericCertification)
                .sign_userid_binding(&mut mine, them.primary_key().key(), &user_ids[1])
                .unwrap(),
        ));
        let them = them.insert_packets(packets).unwrap().0;
        store.insert(&them).unwrap();

        let displayed = String::from_utf8_lossy(user_ids[0].value()).into_owned();
        let refused = revoke_certification(
            &store,
            &me.fingerprint().to_hex(),
            &them.fingerprint().to_hex(),
            std::slice::from_ref(&displayed),
            Reason::Superseded,
            "",
            None,
        )
        .map(|_| ())
        .expect_err("withdrew an endorsement of an identity that displays like another");
        assert!(
            refused.to_string().contains("more than one user ID"),
            "an ambiguous identity must be refused, not guessed at: {refused}"
        );

        let reloaded = store.lookup(&them.fingerprint().to_hex()).unwrap();
        assert!(
            reloaded
                .userids()
                .all(|ua| ua.other_revocations().count() == 0),
            "a refused withdrawal must not sign a revocation over the wrong identity"
        );
        // And the endorsement it was meant to retract is still there to retract.
        assert_eq!(
            reloaded
                .userids()
                .filter(|ua| ua
                    .certifications()
                    .any(|sig| crate::cert::issued_by(sig, &me)))
                .count(),
            1,
            "the certification must be untouched by a refused withdrawal"
        );
    }

    #[test]
    fn recertifying_after_a_withdrawal_takes_effect() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();

        let authenticated = |store: &Store| {
            let certs = store.certs().unwrap();
            let roots: Vec<String> = store.effective_roots().unwrap().into_iter().collect();
            wot::for_user_id(
                &wot::authenticate_all(&certs, &roots),
                &them.fingerprint().to_hex(),
                "Them <them@example.org>",
            )
        };
        let mut request =
            CertifyRequest::new(me.fingerprint().to_hex(), them.fingerprint().to_hex());
        request.user_ids = vec!["Them <them@example.org>".to_string()];

        certify(&store, &request).unwrap();
        // Withdraw immediately — no sleep. The revocation has to be dated in
        // the second after the certification, and the re-certification right
        // after it in the second after that, which is the case this guards.
        revoke_certification(
            &store,
            &me.fingerprint().to_hex(),
            &them.fingerprint().to_hex(),
            &["Them <them@example.org>".to_string()],
            Reason::Superseded,
            "oops",
            None,
        )
        .unwrap();
        certify(&store, &request).unwrap();

        // No wait for the stamps to arrive either: each call waits for its own
        // second rather than dating its signature ahead of the clock, so the
        // re-certification has to be the one that counts straight away.
        assert_eq!(
            authenticated(&store),
            crate::Authentication::Full,
            "the re-certification was born superseded by the revocation before it"
        );
    }

    #[test]
    fn refuses_a_revocation_for_someone_else() {
        let (dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let other = generate(&KeyGenRequest::new("Other <other@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        store.insert(&other).unwrap();

        // Write Other's revocation certificate, but hand it to the store while
        // only Mine is a plausible target.
        let generated = generate(&KeyGenRequest::new("Stranger <s@example.org>")).unwrap();
        let path = dir.path().join("stranger.rev");
        std::fs::write(&path, armor(&generated.revocation).unwrap()).unwrap();
        let _ = other;

        assert!(apply_revocation_file(&store, &path).is_err());
        assert_eq!(
            CertSummary::from_cert(&store.lookup(&mine.fingerprint().to_hex()).unwrap()).validity,
            Validity::Valid
        );
    }

    /// The refusal exists to tell the user which key was refused, and a
    /// certificate carrying no user ID has no name to tell them.
    #[test]
    fn the_refusal_names_a_certificate_with_no_user_id_by_its_fingerprint() {
        let (_dir, store) = scratch();
        // No `add_userid`: a certificate is a key and its self-signatures, and
        // a user ID is not required of one. `import_file` takes such a
        // certificate like any other.
        let (cert, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_signing_subkey()
            .generate()
            .unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        store.insert_secret(&cert).unwrap();
        revoke_cert(&store, &RevokeRequest::new(&fingerprint)).unwrap();

        let refused = refuse_if_revoked(&store.lookup(&fingerprint).unwrap())
            .expect_err("a revoked certificate must be refused for new use");
        let message = refused.to_string();
        assert!(
            message.contains(&fingerprint),
            "the refusal must identify the certificate it means: {message}"
        );
    }
}
