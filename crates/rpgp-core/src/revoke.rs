//! Revocation: retracting a certificate, or retracting a certification you
//! previously made.
//!
//! Revocation in OpenPGP is one-way and public. There is no un-revoke: the
//! revocation signature becomes part of the certificate and anyone who has the
//! certificate keeps it forever. Everything in this module is therefore
//! deliberately explicit about which of the two things is being retracted.

use std::path::Path;
use std::time::{Duration, SystemTime};

use sequoia_openpgp::cert::CertRevocationBuilder;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::types::{ReasonForRevocation, RevocationStatus, SignatureType};
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

    pub fn label(self) -> &'static str {
        match self {
            Reason::Retired => "No longer used",
            Reason::Superseded => "Replaced by a newer key",
            Reason::Compromised => "Secret key may be compromised",
            Reason::Unspecified => "No reason given (treated as compromised)",
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
    let mut signer = primary_signer(&cert, request.password.as_deref().map(String::as_str))?;

    let signature = CertRevocationBuilder::new()
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
        let amalgamation = target
            .userids()
            .find(|ua| String::from_utf8_lossy(ua.userid().value()) == wanted.as_str())
            .ok_or_else(|| Error::invalid(format!("{wanted} is not a user ID on this key")))?;
        let userid = amalgamation.userid().clone();

        // A revocation only supersedes a certification made strictly earlier.
        // Certifying and then changing your mind within the same second — which
        // is a normal thing for a person clicking two buttons to do — would
        // otherwise leave the certification standing. Date the revocation one
        // second past the newest certification it retracts.
        // Signature timestamps have one-second granularity, so this compares
        // `created + 1s` rather than `created`: a certification made 400ms ago
        // is stamped with the same second as `now`, and a naive `created > now`
        // test would never fire.
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
        // the certification the user asked to withdraw still standing.
        // certify.rs makes exactly this check on the mirror path; this is the
        // other half of it.
        let mut when = SystemTime::now();
        for existing in amalgamation
            .certifications()
            .filter(|sig| crate::cert::issued_by(sig, &certifier))
            .filter(|sig| {
                (*sig)
                    .clone()
                    .verify_userid_binding(certifier_key, target.primary_key().key(), &userid)
                    .is_ok()
            })
        {
            if let Some(created) = existing.signature_creation_time() {
                let after = created + Duration::from_secs(1);
                if after > when {
                    when = after;
                }
            }
        }

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

    let signature = signatures.first()?;
    let (code, message) = signature.reason_for_revocation()?;
    Some((
        Reason::from_openpgp(code),
        String::from_utf8_lossy(message).into_owned(),
    ))
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
    // let it find the key by keygrip, exactly as certify() does.
    match ka {
        Some(ka) => Ok(Box::new(crate::secret::keypair(
            ka.key().clone(),
            password,
        )?)),
        None => Ok(Box::new(crate::agent::certifier_for(cert)?)),
    }
}

#[cfg(test)]
mod tests {
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

        // The revocation is dated one second past the certification it
        // retracts, so it only takes effect once that second has passed. This
        // sleep is the semantics, not a flake: see `revoke_certification`.
        std::thread::sleep(std::time::Duration::from_millis(1300));

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
        std::thread::sleep(std::time::Duration::from_millis(1300));

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
        std::thread::sleep(std::time::Duration::from_millis(1300));
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
    /// this fails: A's authentication stays Full because the withdrawal is
    /// stamped five years out.
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
        std::thread::sleep(std::time::Duration::from_millis(1300));

        assert_eq!(
            under(&a),
            crate::Authentication::Unknown,
            "the withdrawal must take effect now; a packet A did not sign cannot date it into the future"
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
        // Withdraw immediately — no sleep. The revocation lands a second in
        // the future, and the re-certification right after it must clear that
        // second too, which is the case this guards.
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

        // Both stamps may sit up to two seconds ahead of the clock; let them
        // arrive, then the re-certification has to be the one that counts.
        std::thread::sleep(std::time::Duration::from_millis(2300));
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
}
