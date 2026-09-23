//! Certifying other people's certificates, and reading the certifications a
//! certificate already carries.
//!
//! A certification is a signature by one certificate over a *user ID* of
//! another — the OpenPGP way of saying "I checked, and this name and address
//! really do belong to this key". It is the raw material the web of trust in
//! [`crate::wot`] reasons over.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime};

use sequoia_openpgp::Cert;
use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::cert::amalgamation::UserIDAmalgamation;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::policy::HashAlgoSecurity;
use sequoia_openpgp::types::{RevocationStatus, SignatureType};
use sequoia_wot::CertificationError;

use crate::error::{Error, Result};
use crate::policy;
use crate::store::Store;
use zeroize::Zeroizing;

/// Full confidence, in OpenPGP's 0..=255 trust scale.
pub const FULL: u8 = 120;
/// Partial confidence: enough only in combination with other certifications.
pub const PARTIAL: u8 = 60;

#[derive(Debug, Clone)]
pub struct CertifyRequest {
    /// Fingerprint of our own certificate doing the certifying.
    pub certifier: String,
    /// Fingerprint of the certificate being certified.
    pub target: String,
    /// Which of the target's user IDs to sign. Certifying a certificate as a
    /// whole is not a thing OpenPGP can express; every certification names one
    /// user ID.
    pub user_ids: Vec<String>,
    /// Exportable certifications are meant to be published and shared; a local
    /// one stays in this store and is never written out by `export_file`.
    pub exportable: bool,
    /// 0 for an ordinary certification. 1 or more makes it a *trust signature*:
    /// the target becomes a trusted introducer whose own certifications this
    /// store will honour, up to `depth` hops away.
    pub depth: u8,
    /// How much this certification vouches for the binding: [`FULL`] or
    /// [`PARTIAL`].
    pub amount: u8,
    pub expires: Option<Duration>,
    pub password: Option<Zeroizing<String>>,
}

impl CertifyRequest {
    pub fn new(certifier: impl Into<String>, target: impl Into<String>) -> Self {
        CertifyRequest {
            certifier: certifier.into(),
            target: target.into(),
            user_ids: Vec::new(),
            exportable: true,
            depth: 0,
            amount: FULL,
            expires: None,
            password: None,
        }
    }
}

/// One certification already present on a certificate.
#[derive(Debug, Clone)]
pub struct Certification {
    pub user_id: String,
    /// The certifier's primary user ID when their certificate is in the store,
    /// otherwise their key handle.
    pub certifier: String,
    pub certifier_fingerprint: Option<String>,
    pub created: Option<SystemTime>,
    pub exportable: bool,
    pub depth: u8,
    pub amount: u8,
    /// Whether the signature checks out against the certifier's key. `None`
    /// when the certifier is not in the store and it could not be checked.
    pub verified: Option<bool>,
    /// Made by a certificate whose secret key this store holds.
    pub by_me: bool,
    /// This entry withdraws an earlier certification rather than making one.
    pub is_revocation: bool,
    /// Whether this certification counts, and if not, why not; see
    /// [`Standing`]. `None` for a withdrawal, which is not a certification to
    /// count; for a certification that did not verify, which counts for
    /// nothing whoever it names; and for one that could not be checked, its
    /// certifier not being in the store, which sequoia-wot, reading the same
    /// store, cannot count either.
    pub standing: Option<Standing>,
}

impl Certification {
    /// Whether this certification counts towards trust: whether sequoia-wot,
    /// which computes the authentication pill, uses it.
    ///
    /// This used to mean only that the signature verified and was not a
    /// withdrawal, so a certification its maker had since withdrawn or
    /// replaced, one past its expiry, one made by a subkey and one from a key
    /// its owner had declared compromised all kept the green tick while the
    /// pill beside them said the identity was unverified.
    pub fn is_good(&self) -> bool {
        self.standing == Some(Standing::Stands)
    }
}

/// Whether a certification counts, and if not, why not.
///
/// "Counts" means that sequoia-wot, which computes the authentication pill,
/// uses it; [`standing`] asks sequoia-wot's own rule rather than restating it.
/// Only a certification that verified against its certifier's key is judged at
/// all, so every reason here is about a signature that is genuinely the
/// certifier's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// It counts.
    Stands,
    /// The same key certified the same user ID again later. Only a certifier's
    /// newest word on a user ID counts, so this one is history.
    Superseded,
    /// The same key withdrew it later.
    Withdrawn,
    /// Dated ahead of this computer's clock, by a clock that ran fast here or
    /// where it was made, and sound for when that date comes. sequoia-wot
    /// counts it from that date and not before, so it can still be withdrawn,
    /// though only by a withdrawal dated after it, which
    /// [`crate::signature_time`] waits a few seconds for at most and past that
    /// refuses, naming the date. One dated ahead that will not count when its
    /// date comes, or that a withdrawal dated later still already takes back,
    /// is given the reason instead.
    NotYet,
    /// Past the expiry it was made with.
    Expired,
    /// The certifier's key has been revoked as compromised, or with no reason,
    /// which takes back everything the key ever signed; or it had already been
    /// revoked, for any reason, when this was made.
    CertifierRevoked,
    /// Made by one of the certifier's subkeys. sequoia-wot checks a
    /// certification against the certifier's primary key and nothing else.
    NotByPrimaryKey,
    /// Made with a hash the policy no longer accepts for a certification:
    /// SHA-1 above all, which GnuPG 1.x and 2.0 certified with unless told
    /// otherwise, and which the standard policy has refused here since 2013.
    /// sequoia-wot checks the hash after the dates and the certified key but
    /// before the signature itself and before any withdrawal, so this says
    /// nothing about whether the certification was since withdrawn.
    WeakHash,
    /// The key it certifies was not usable when it was made, or has been
    /// revoked as compromised or refused by the policy since. sequoia-wot
    /// judges the certified key as it stood when the certification was made,
    /// but by today's policy, so self-signatures the policy has come to reject
    /// since, SHA-1 ones after 2023 say, count against it then as well; it
    /// takes a revocation as compromised to have been in force from the start;
    /// and a key that is not valid now it does not consider at all.
    /// [`certify`] refuses to certify a key that has expired, been revoked or
    /// is not valid, so a certification that was made of one comes from
    /// elsewhere or from an older version of this app; but a certification it
    /// made can turn into one of these when the key is later revoked as
    /// compromised, or its self-signatures fall to the policy.
    TargetNotValid,
    /// Discounted for a reason with no wording of its own here: a certifier
    /// that had expired, or was not yet valid, when it was made, or whose own
    /// certificate the policy rejects; a critical subpacket the policy does
    /// not accept; or a user ID that is not UTF-8, which sequoia-wot does not
    /// consider at all.
    Rejected,
}

impl Standing {
    /// Whether a withdrawal would take this certification back: it counts,
    /// or will once the date it carries comes. [`withdrawable`] and
    /// `revoke_certification` both ask this, so that what is offered for
    /// withdrawal and what may be withdrawn are the same.
    pub fn is_withdrawable(self) -> bool {
        matches!(self, Standing::Stands | Standing::NotYet)
    }
}

/// Sign one or more of `target`'s user IDs with `certifier`'s key.
///
/// The updated certificate is written back to the store and returned. A
/// certification that could not count from the moment it was made, by
/// [`standing`]'s rule, is refused instead, before any key is unlocked, and so
/// is one that cannot be dated after the certifier's own last word on the user
/// ID ([`crate::signature_time`]).
pub fn certify(store: &Store, request: &CertifyRequest) -> Result<Cert> {
    if request.user_ids.is_empty() {
        return Err(Error::invalid("select at least one user ID to certify"));
    }
    if request.certifier == request.target {
        return Err(Error::invalid(
            "a certificate already vouches for itself; certify someone else's",
        ));
    }

    let policy = policy();
    // Both halves of the certifier: the secret one may be missing altogether,
    // since a card key has no local secret half and the public certificate is
    // enough for the agent to find it by keygrip — and where it is present it
    // can still be behind cert-d by a revocation the user imported or fetched,
    // which the guard below has to see.
    let certifier = store.full_cert(&request.certifier)?;
    let target = store.lookup(&request.target)?;

    // Neither end may be a certificate its owner has withdrawn, and both are
    // checked here so that a card is never asked for its PIN on behalf of a
    // certification that cannot count. sequoia-wot judges the target as it was
    // when the certification was made and discards the certification outright
    // if the target was revoked then (TargetHardRevoked, TargetSoftRevoked), and
    // it drops every certification of a revoked target at the reference time
    // besides — so what the status bar used to report as "Certified 1 user
    // ID(s)", with a green tick beside it, was a signature that could never move
    // the trust column. The reason the per-user-ID guard below gives, that a
    // claim its own subject has withdrawn is not ours to make, applies with more
    // force to a whole certificate revoked as compromised.
    //
    // Both are named by role, because this is the one operation where the
    // status bar shows two people's keys and "Certification failed: Carol has
    // been revoked" would leave the reader guessing which of them Carol was.
    crate::revoke::refuse_if_revoked_as(&certifier, Some("the certifier"))?;
    crate::revoke::refuse_if_revoked_as(&target, Some("the key being certified"))?;

    // The rest of what [`standing`] holds against a certification from the
    // moment it is made, refused here for the same reason and at the same
    // point: a key that is not valid under the policy, or that has expired
    // ([`Standing::TargetNotValid`]), and a user ID that is not UTF-8 (below).
    // These used to be signed, reported as made and listed, though they never
    // counted, and under standing's rules the app would now refuse to
    // withdraw them, although a published one could still be counted by an
    // implementation that does not share sequoia-wot's rules.
    let now = SystemTime::now();
    let target_named = || format!("{} (the key being certified)", primary_user_id(&target));
    match target.with_policy(&policy, now) {
        Err(_) => {
            return Err(Error::invalid(format!(
                "{} is not valid under the standard policy",
                target_named()
            )));
        }
        Ok(subject) if subject.alive().is_err() => {
            let expired = subject
                .primary_key()
                .key_expiration_time()
                .is_some_and(|expiry| expiry <= now);
            return Err(Error::invalid(format!(
                "{} {}",
                target_named(),
                if expired {
                    "has expired"
                } else {
                    "is not valid yet"
                }
            )));
        }
        Ok(_) => {}
    }

    // Every user ID is settled before anything is unlocked, as well, and so is
    // the date each certification will carry.
    let mut certifying = Vec::new();
    for wanted in &request.user_ids {
        // Exactly one user ID, or none. The displayed text is a lossy rendering
        // of bytes and two user IDs can share one, which is not a guess to make
        // on somebody's behalf; the rule and its history live in
        // `cert::resolve_user_id`, which the withdrawal paths ask as well.
        let amalgamation = crate::cert::resolve_user_id(&target, wanted)?;

        // A user ID its owner has retracted is not ours to vouch for. Signing
        // one publishes an attestation binding a name the holder has disowned
        // — usually an address that has since been reassigned to someone else,
        // which is precisely the claim a certification must not make.
        if matches!(
            amalgamation.revocation_status(&policy, None),
            RevocationStatus::Revoked(_)
        ) {
            return Err(Error::invalid(format!(
                "{wanted} has been revoked by its owner"
            )));
        }

        // sequoia-wot passes over a user ID that is not UTF-8 before it looks
        // at a single certification of it.
        if std::str::from_utf8(amalgamation.userid().value()).is_err() {
            return Err(Error::invalid(format!(
                "{wanted} is not valid UTF-8, and no certification of it would count"
            )));
        }

        // The mirror of revoke_certification's rule: a certification has to be
        // dated after every signature of ours on this user ID that it
        // replaces, and [`crate::signature_time`] does the dating. Our own
        // withdrawals are one kind. A certification dated before one is born
        // dead, as a re-certification made straight after a withdrawal dated
        // ahead of the clock would be — and withdraw-then-recertify within a
        // second is one person clicking twice. Our own earlier
        // certifications are the other, which this used to miss: sequoia-wot
        // counts only a certifier's newest certification of a user ID, but it
        // keeps every one sharing that newest second and walks the strongest of
        // them, so a change of mind within the second — Full to Partial, or a
        // trusted introducer demoted to a plain certification — changed
        // nothing, and the delegation the user meant to take back went on
        // vouching for everyone the introducer had certified. Only our own
        // signatures count, for the same reason only our own certifications
        // count over there.
        //
        // "Ours" means one that verifies against our key, not one that merely
        // names it; [`own_certifications`] and [`own_withdrawals`] say why.
        // revoke_certification dates its withdrawals by the first of them, the
        // same way.
        //
        // Dated here, not once the key is unlocked, because a date too far
        // ahead is refused, and that refusal should cost no passphrase or PIN
        // either. A date settled before the unlock is as good after it: it has
        // to follow what it replaces and not be ahead of the clock, and the
        // time the unlock takes changes neither.
        let certified = own_certifications(&amalgamation, &target, &certifier);
        let withdrawn = own_withdrawals(&amalgamation, &target, &certifier);
        let when = crate::signature_time(certified.chain(withdrawn))?;
        certifying.push((amalgamation, when));
    }

    // Signed with the primary key, and only the primary key. sequoia-wot checks
    // a certification against the certifier's primary key and nothing else
    // (`Certification::try_from_signature`, sequoia-wot 0.15.2), so one made by
    // a certification-capable subkey counts for nobody. That is what the first
    // `for_certification()` key used to be whenever the primary lacked the
    // certify flag or its secret was not here: the certification was reported
    // as made, listed with a tick, and authenticated no one. The primary's
    // certify flag is not asked for, since sequoia-wot does not ask it either,
    // and refusing a primary without one would refuse certifications that
    // count.
    //
    // A local secret that is only a GnuPG stub goes to the agent, as a card key
    // does: the stub is what GnuPG leaves where the key is on a card, and no
    // passphrase opens it. An expired primary, or one of an algorithm this
    // build cannot use, goes to the agent too, as it did when this was a key
    // filter, and the agent turns the first of those away.
    let valid = certifier
        .with_policy(&policy, None)
        .map_err(|_| Error::NoSecretKey(request.certifier.clone()))?;
    let primary = valid.primary_key();
    let local = primary
        .key()
        .clone()
        .parts_into_secret()
        .ok()
        .filter(|key| {
            primary.alive().is_ok()
                && key.pk_algo().is_supported()
                && crate::secret::is_usable(key.secret())
        });

    let mut signer: Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync> = match local {
        Some(key) => crate::secret::signer(key, request.password.as_deref().map(String::as_str))?,
        None => Box::new(crate::agent::certifier_for(&certifier)?),
    };

    let mut signatures: Vec<Signature> = Vec::new();
    for (amalgamation, when) in &certifying {
        let userid = amalgamation.userid().clone();
        let mut builder = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(*when)?
            .set_exportable_certification(request.exportable)?;

        // An ordinary certification already means "full confidence in this
        // binding". Anything else — a lower amount, or delegation to a trusted
        // introducer — has to be spelled out as a trust signature.
        if request.depth > 0 || request.amount != FULL {
            builder = builder.set_trust_signature(request.depth, request.amount)?;
        }
        if let Some(expires) = request.expires {
            builder = builder.set_signature_validity_period(expires)?;
        }

        signatures.push(builder.sign_userid_binding(
            &mut *signer,
            target.primary_key().key(),
            &userid,
        )?);
    }

    let certified = target.insert_packets(signatures)?.0;
    store.insert(&certified)?;
    Ok(certified)
}

/// The primary user ID under the standard policy, for naming a certifier.
///
/// The rule itself lives in [`crate::cert::primary_user_id`], called with the
/// `ValidCert` resolved here: this file used to carry a copy of it, kept in
/// step by hand, and the reason it gave for the copy — that reading one field
/// off a whole `CertSummary` costs a walk of every key — is answered by
/// sharing the rule rather than the summary.
pub(crate) fn primary_user_id(cert: &Cert) -> String {
    let policy = policy();
    let valid = cert.with_policy(&policy, SystemTime::now()).ok();
    crate::cert::primary_user_id(cert, valid.as_ref())
}

/// `certifier`'s certifications of `ua`: the ones that name it and verify
/// against its primary key.
///
/// Verified, not merely named. `certifications()` hands back packets exactly as
/// they were parsed, and an issuer subpacket is an unauthenticated hint anyone
/// can write, so a packet that only names a key is no evidence that the key
/// said anything. Filtering on the name alone once let a planted packet dated
/// in the far future date a new certification or withdrawal at that instant,
/// where it never took effect; refetching the target re-planted it, so every
/// retry was neutralised the same way, and with a date that far ahead now
/// refused the same packet would block the operation outright. Against the
/// primary key, because that is the key a certification counts from and the
/// one [`certify`] and a withdrawal sign with.
pub(crate) fn own_certifications<'a>(
    ua: &UserIDAmalgamation<'a>,
    target: &Cert,
    certifier: &Cert,
) -> impl Iterator<Item = &'a Signature> {
    let userid = ua.userid();
    ua.certifications()
        .filter(move |sig| crate::cert::issued_by(sig, certifier))
        .filter(move |sig| {
            (*sig)
                .clone()
                .verify_userid_binding(
                    certifier.primary_key().key(),
                    target.primary_key().key(),
                    userid,
                )
                .is_ok()
        })
}

/// `certifier`'s withdrawals of its certifications of `ua`, by the same test as
/// [`own_certifications`] and for the same reason.
pub(crate) fn own_withdrawals<'a>(
    ua: &UserIDAmalgamation<'a>,
    target: &Cert,
    certifier: &Cert,
) -> impl Iterator<Item = &'a Signature> {
    let userid = ua.userid();
    ua.other_revocations()
        .filter(move |sig| crate::cert::issued_by(sig, certifier))
        .filter(move |sig| {
            (*sig)
                .clone()
                .verify_userid_revocation(
                    certifier.primary_key().key(),
                    target.primary_key().key(),
                    userid,
                )
                .is_ok()
        })
}

/// Which of `certifier`'s certifications of `ua` stand as of `now`: the one
/// rule for whether a certification counts, asked by everything here that
/// lists, counts or withdraws certifications.
///
/// It is sequoia-wot's rule, because sequoia-wot computes the authentication
/// pill, and a tick that disagrees with the pill beside it is worse than none.
/// Each certification is put to `Certification::try_from_signature`, the
/// function sequoia-wot 0.15.2 builds its network with, rather than to a
/// restatement of it that would drift. That checks it against the certifier's
/// primary key alone; discounts it if the certifier's key has been revoked as
/// compromised, or had been revoked for any reason or had expired when it was
/// made; and discounts it if the certifier withdrew it, a withdrawal counting
/// once it is dated after the certification and no later than `now` — besides
/// its expiry, the policy ([`Standing::WeakHash`] where it is the hash the
/// policy refuses), and the certified key's own validity at the time
/// ([`Standing::TargetNotValid`]). One dated after `now` is judged as it will
/// be once that date comes, and is [`Standing::NotYet`] if it will count then.
/// [`certify`] refuses to make a certification that this would discount from
/// the moment it was made.
///
/// Supersession is the part that function leaves to its caller, and sequoia-wot
/// settles it in its store before asking (`Backend::redges`): of one
/// certifier's certifications of one user ID, only those from the newest second
/// among the ones that pass count. So a newer certification that fails, an
/// expired one say, does not displace an older one that passes. The rest are
/// [`Standing::Superseded`].
///
/// Whether the binding as a whole can be authenticated is a separate question,
/// which the pill answers: sequoia-wot also finds no path to a key that is
/// revoked or expired at `now`, or to a user ID its owner has retracted,
/// however many certifications of it stand.
///
/// The certifications judged are the ones that name `certifier`, which is how
/// sequoia-wot finds a certifier's; one that names it without being its fails
/// verification here as it does there.
pub(crate) fn standing<'a>(
    certifier: &Cert,
    target: &'a Cert,
    ua: &UserIDAmalgamation<'a>,
    now: SystemTime,
) -> Vec<(&'a Signature, Standing)> {
    let policy = policy();
    let named = ua
        .certifications()
        .filter(|sig| crate::cert::issued_by(sig, certifier));

    // sequoia-wot considers neither end without a valid certificate as of the
    // reference time, and passes over a user ID that is not UTF-8 before
    // looking at any certification of it. A target that is not valid now is
    // [`Standing::TargetNotValid`] for every certification of it.
    let Ok(subject) = target.with_policy(&policy, now) else {
        return named.map(|sig| (sig, Standing::TargetNotValid)).collect();
    };
    let Ok(issuer) = certifier.with_policy(&policy, now) else {
        return named.map(|sig| (sig, Standing::Rejected)).collect();
    };
    if std::str::from_utf8(ua.userid().value()).is_err() {
        return named.map(|sig| (sig, Standing::Rejected)).collect();
    }

    // sequoia-wot sets a certification dated ahead of the reference time
    // aside before it looks at anything else in it, the signature included,
    // and counts it from that date. So such a certification is judged as it
    // will be then, and is NotYet only if it will count; otherwise it gets the
    // reason it will not, a forgery's NotByPrimaryKey among them. It was NotYet
    // whenever it verified, and so offered for withdrawal, and withdrawn, when
    // it could never count: one made with SHA-1, say, or after its certifier
    // was retired, or of a key that will have expired by its date.
    //
    // "Then" is the later of its own date and that of the certifier's newest
    // withdrawal of the user ID, which can be ahead of the clock as well, so
    // that one a later withdrawal already takes back reads as withdrawn rather
    // than as waiting to be withdrawn again. Only withdrawals that verify
    // count towards it, for the reason [`own_withdrawals`] gives.
    let ahead = |signature: &Signature| {
        let then = own_withdrawals(ua, target, certifier)
            .filter_map(|withdrawal| withdrawal.signature_creation_time())
            .chain(signature.signature_creation_time())
            .max()
            .unwrap_or(now);
        // Neither end counts without a valid certificate then, as above for now.
        match (
            certifier.with_policy(&policy, then),
            target.with_policy(&policy, then),
        ) {
            (_, Err(_)) => Standing::TargetNotValid,
            (Err(_), _) => Standing::Rejected,
            (Ok(issuer), Ok(subject)) => match verdict(&issuer, ua, &subject, signature) {
                Standing::Stands => Standing::NotYet,
                standing => standing,
            },
        }
    };

    let mut verdicts: Vec<(&'a Signature, Standing)> = named
        .map(|signature| {
            let standing = match verdict(&issuer, ua, &subject, signature) {
                Standing::NotYet => ahead(signature),
                standing => standing,
            };
            (signature, standing)
        })
        .collect();

    let newest = verdicts
        .iter()
        .filter(|(_, standing)| *standing == Standing::Stands)
        .filter_map(|(signature, _)| signature.signature_creation_time())
        .max();
    for (signature, standing) in &mut verdicts {
        if *standing == Standing::Stands && signature.signature_creation_time() < newest {
            *standing = Standing::Superseded;
        }
    }
    verdicts
}

/// sequoia-wot's verdict on one certification of `ua` by `issuer`, as of
/// `subject`'s reference time, as a [`Standing`]; [`standing`] says what it
/// rests on. A certification dated after that time is [`Standing::NotYet`]
/// here, whatever else holds, since sequoia-wot looks at nothing else in it.
fn verdict(
    issuer: &ValidCert<'_>,
    ua: &UserIDAmalgamation<'_>,
    subject: &ValidCert<'_>,
    signature: &Signature,
) -> Standing {
    let policy = policy();
    let at = subject.time();

    // Whether the policy refuses the certification's hash, by the two cutoff
    // lists it checks a certification's hash against, so that a refusal for
    // the hash is told apart from one for a critical subpacket.
    let weak_hash = || {
        [
            HashAlgoSecurity::CollisionResistance,
            HashAlgoSecurity::SecondPreImageResistance,
        ]
        .into_iter()
        .any(|security| {
            policy
                .hash_cutoff(signature.hash_algo(), security)
                .is_some_and(|cutoff| cutoff <= at)
        })
    };

    match sequoia_wot::Certification::try_from_signature(issuer, Some(ua), subject, signature) {
        Ok(_) => Standing::Stands,
        Err(e) => match e.downcast_ref::<CertificationError>() {
            Some(CertificationError::IssuerRevoked(_)) => Standing::Withdrawn,
            Some(CertificationError::BornLater(..)) => Standing::NotYet,
            Some(CertificationError::InvalidCertification(..)) if weak_hash() => Standing::WeakHash,
            Some(CertificationError::CertificationExpired(..)) => Standing::Expired,
            Some(
                CertificationError::IssuerHardRevoked(..)
                | CertificationError::IssuerSoftRevoked(..),
            ) => Standing::CertifierRevoked,
            Some(
                CertificationError::TargetNotValid(..)
                | CertificationError::TargetNotLive(..)
                | CertificationError::TargetHardRevoked(..)
                | CertificationError::TargetSoftRevoked(..),
            ) => Standing::TargetNotValid,
            Some(_) => Standing::Rejected,
            // The failed verification against the primary key is a plain
            // signature error, not one of sequoia-wot's own.
            None if signature
                .clone()
                .verify_signature(issuer.primary_key().key())
                .is_err() =>
            {
                Standing::NotByPrimaryKey
            }
            None => Standing::Rejected,
        },
    }
}

/// What withdrawing would take back: the user's own certifications that
/// stand, or will once their date comes ([`Standing::is_withdrawable`]), as the
/// user IDs each of the user's keys has certified, keyed by that key's
/// fingerprint.
///
/// The one answer to "is there anything to withdraw", for the button that
/// offers a withdrawal and for the run that makes it, so that the two cannot
/// disagree. They used to, each wrong in its own direction. The button took any
/// withdrawal by a key as retracting everything that key had certified on the
/// user ID, including a certification made after it, so withdrawing and then
/// certifying again took the button away for good. The run signed for every
/// certification a key had ever made, withdrawn or not, so a key with nothing
/// left standing was asked to sign first, and a passphrase that opened only
/// the key that did have something standing failed on the other and never
/// reached it.
pub fn withdrawable(certifications: &[Certification]) -> BTreeMap<String, Vec<String>> {
    let mut by_certifier: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for certification in certifications
        .iter()
        .filter(|c| c.by_me && c.standing.is_some_and(Standing::is_withdrawable))
    {
        let Some(fingerprint) = &certification.certifier_fingerprint else {
            continue;
        };
        let user_ids = by_certifier.entry(fingerprint.clone()).or_default();
        // One entry per user ID: a certifier with a superseded certification
        // beside a standing one would otherwise name the user ID twice, and
        // each repeat would sign an identical revocation.
        if !user_ids.contains(&certification.user_id) {
            user_ids.push(certification.user_id.clone());
        }
    }
    by_certifier
}

/// One resolved certifier, kept for the length of a `certifications()` call.
///
/// Derived values only, never the `Cert`: a certificate endorsed by hundreds
/// of people in the store would otherwise pin hundreds of parsed certificates
/// for the duration. [`standing`] does need the whole certificate, and
/// `certifications()` looks each certifier up again for it, one at a time.
struct Certifier {
    /// The primary key, the only one a certification counts from, and the
    /// only one that says for certain whose a certification is: no other
    /// certificate in the store can have it as its primary.
    primary: Key<PublicParts, UnspecifiedRole>,
    /// Every subkey the certificate binds for certification. Not the primary
    /// alone: a certification a subkey made is still its maker's word, and
    /// naming them beside it, with [`Standing::NotByPrimaryKey`] to say it
    /// does not count, is truer than "signature does not check out". Nor are
    /// revoked or expired subkeys left out, for the same reason: a signature
    /// a subkey made before it was retired is the same signature afterwards,
    /// and leaving the subkey out turned it into a bad one. Whether it counts
    /// is [`standing`]'s question.
    subkeys: Vec<Key<PublicParts, UnspecifiedRole>>,
    name: String,
    fingerprint: String,
    by_me: bool,
}

impl Certifier {
    /// Credit `entry` to this certifier, whose key it verified against.
    fn credit(&self, entry: &mut Certification) {
        entry.verified = Some(true);
        entry.certifier = self.name.clone();
        entry.by_me = self.by_me;
        entry.certifier_fingerprint = Some(self.fingerprint.clone());
    }
}

/// Every third-party certification on `cert`, and every withdrawal of one,
/// verified where possible and, where verified, judged by [`standing`].
pub fn certifications(store: &Store, cert: &Cert) -> Result<Vec<Certification>> {
    let mut out = Vec::new();
    // Which user ID, as an index into `userids`, and which signature each
    // entry of `out` was read from, index for index, for the standing pass
    // after the loop.
    let mut sources: Vec<(usize, &Signature)> = Vec::new();
    let primary = cert.primary_key().key();

    // Both hoisted out of the per-signature loop below. The secrets directory
    // was stat'd once per signature to answer by_me, and the certifier was
    // re-read from the store, re-parsed and re-validated against the policy
    // once per signature — so a certificate carrying twenty endorsements from
    // one person did all of that twenty times over. `unwrap_or_default`, not
    // `?`: an unreadable secrets directory reads as "no secrets" here exactly
    // as `has_secret` treated it, rather than failing the whole listing.
    let secrets = store.secret_fingerprints().unwrap_or_default();
    let mut certifiers: HashMap<String, Option<Certifier>> = HashMap::new();

    let userids: Vec<UserIDAmalgamation> = cert.userids().collect();
    for (index, ua) in userids.iter().enumerate() {
        let user_id = String::from_utf8_lossy(ua.userid().value()).into_owned();

        // `certifications()` holds third-party endorsements;
        // `other_revocations()` holds the signatures that withdraw them. Both
        // belong in the list — a withdrawal the user cannot see is a withdrawal
        // they will make twice.
        let entries = ua
            .certifications()
            .map(|signature| (signature, false))
            .chain(ua.other_revocations().map(|signature| (signature, true)));

        for (signature, is_revocation) in entries {
            let (depth, amount) = signature.trust_signature().unwrap_or((0, FULL));
            let mut entry = Certification {
                is_revocation,
                user_id: user_id.clone(),
                certifier: String::new(),
                certifier_fingerprint: None,
                created: signature.signature_creation_time(),
                exportable: signature.exportable_certification().unwrap_or(true),
                depth,
                amount,
                verified: None,
                by_me: false,
                standing: None,
            };

            // Check the signature against every issuer we can resolve, until
            // one's primary key verifies it. It used to stop at the first
            // issuer that resolved, verified or not, and get_issuers() puts
            // every fingerprint ahead of every key ID, the unhashed area's
            // included. So one unhashed IssuerFingerprint naming any
            // certificate in the store, added to a copy of a key and merged in
            // on import, was tried ahead of the key ID that is all a GnuPG 1.x
            // certification names its maker by, and hid the real certifier
            // behind "signature does not check out" — along with the user's
            // own "(you)" and the way to withdraw it.
            //
            // The primary key, because stopping at the first issuer that
            // verifies at all left the same hole open. A certificate needs no
            // back-signature to bind a key for certification alone (one is
            // asked for only where the flags allow signing), so any
            // certificate can bind the user's public primary key as a
            // certification subkey of its own, and the planted fingerprint
            // naming it again came first: the user's certification was
            // credited to that stranger as made by a subkey, and so as not
            // counting, where sequoia-wot, which tries every issuer and takes
            // the one whose primary key verifies, counts it for the user. A
            // signature that verifies against no issuer's primary key but
            // does against a subkey is put down to the first issuer with such
            // a subkey, which is at least whose word it is.
            //
            // What is reported when nothing verifies is decided once, after
            // the loop: the first issuer that resolved and failed, as before,
            // and failing that the last one that did not resolve.
            let mut by_subkey: Option<String> = None;
            let mut failed: Option<String> = None;
            let mut unresolved: Option<String> = None;
            // A certificate is often named twice, by fingerprint and by key
            // ID, and one that failed once fails again.
            let mut tried: Vec<String> = Vec::new();
            for handle in signature.get_issuers() {
                let handle = handle.to_string();

                // Verify before attributing, not after. get_issuers() reports
                // the issuer subpackets from both the hashed and the unhashed
                // area, and the unhashed half is not covered by the signature
                // — [`own_certifications`] says exactly that. Naming the
                // certifier, and worse setting by_me, from that hint meant a
                // packet anyone could write earned a real identity in the list
                // and a "(you)" badge with a withdraw affordance beside it.
                let resolved = certifiers.entry(handle.clone()).or_insert_with(|| {
                    let certifier = store.lookup(&handle).ok()?;
                    let policy = policy();
                    let subkeys = certifier
                        .with_policy(&policy, None)
                        .ok()
                        .into_iter()
                        .flat_map(|valid| {
                            valid
                                .keys()
                                .subkeys()
                                .supported()
                                .for_certification()
                                .map(|ka| ka.key().clone().role_into_unspecified())
                                .collect::<Vec<_>>()
                        })
                        .collect();
                    let fingerprint = certifier.fingerprint().to_hex();
                    Some(Certifier {
                        primary: certifier
                            .primary_key()
                            .key()
                            .clone()
                            .role_into_unspecified(),
                        subkeys,
                        name: primary_user_id(&certifier),
                        by_me: secrets.contains(&fingerprint),
                        fingerprint,
                    })
                });

                // An unresolvable issuer is normal — it just means we have not
                // met that person — so it is reported rather than dropped.
                let Some(resolved) = resolved else {
                    unresolved = Some(handle);
                    continue;
                };
                if tried.contains(&resolved.fingerprint) {
                    continue;
                }
                tried.push(resolved.fingerprint.clone());

                let verifies = |key: &Key<PublicParts, UnspecifiedRole>| {
                    if is_revocation {
                        signature
                            .clone()
                            .verify_userid_revocation(key, primary, ua.userid())
                            .is_ok()
                    } else {
                        signature
                            .clone()
                            .verify_userid_binding(key, primary, ua.userid())
                            .is_ok()
                    }
                };
                if verifies(&resolved.primary) {
                    resolved.credit(&mut entry);
                    break;
                }
                if resolved.subkeys.iter().any(verifies) {
                    by_subkey.get_or_insert(handle);
                    continue;
                }
                failed.get_or_insert(handle);
            }

            if entry.verified.is_none()
                && let Some(handle) = by_subkey
                && let Some(Some(certifier)) = certifiers.get(&handle)
            {
                certifier.credit(&mut entry);
            }
            if entry.verified.is_none() {
                if let Some(handle) = failed {
                    // Names a certifier but does not verify against it.
                    // Report the handle rather than the identity: by_me stays
                    // false, so no withdraw affordance appears beside a
                    // signature we cannot show the user made.
                    entry.verified = Some(false);
                    entry.certifier = handle;
                } else if let Some(handle) = unresolved {
                    entry.certifier = handle;
                }
            }
            if entry.certifier.is_empty() {
                entry.certifier = "unknown certifier".to_string();
            }
            out.push(entry);
            sources.push((index, signature));
        }
    }

    // Standing, certifier by certifier, for every certification that verified.
    // Grouped so that each certifier is looked up once, and so that
    // [`standing`] sees all of a certifier's certifications of a user ID at
    // once, which supersession needs.
    let now = SystemTime::now();
    let mut judged: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, entry) in out.iter().enumerate() {
        if entry.verified == Some(true)
            && !entry.is_revocation
            && let Some(fingerprint) = &entry.certifier_fingerprint
        {
            judged.entry(fingerprint.clone()).or_default().push(i);
        }
    }
    for (fingerprint, indices) in judged {
        let mut verdicts: Vec<(&Signature, Standing)> = Vec::new();
        if let Ok(certifier) = store.lookup(&fingerprint) {
            let mut uas: Vec<usize> = indices.iter().map(|&i| sources[i].0).collect();
            uas.sort_unstable();
            uas.dedup();
            for ua in uas {
                verdicts.extend(standing(&certifier, cert, &userids[ua], now));
            }
        }
        for i in indices {
            let signature = sources[i].1;
            // A certificate that has gone from the store since it was resolved
            // above can vouch for nothing, which is what sequoia-wot, reading
            // the store afresh, will make of it too.
            out[i].standing = Some(
                verdicts
                    .iter()
                    .find(|(judged, _)| std::ptr::eq(*judged, signature))
                    .map_or(Standing::Rejected, |(_, standing)| *standing),
            );
        }
    }

    out.sort_by(|a, b| {
        b.by_me
            .cmp(&a.by_me)
            .then_with(|| a.user_id.cmp(&b.user_id))
            .then_with(|| a.certifier.cmp(&b.certifier))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyGenRequest, generate};
    use crate::revoke::{Reason, RevokeRequest, revoke_cert, revoke_certification};
    use sequoia_openpgp::Packet;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::crypto::{KeyPair, Signer};
    use sequoia_openpgp::packet::signature::subpacket::{Subpacket, SubpacketValue};
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::serialize::MarshalInto;
    use sequoia_openpgp::types::KeyFlags;

    fn scratch() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    fn key(user_id: &str) -> Cert {
        generate(&KeyGenRequest::new(user_id)).unwrap().cert
    }

    /// How `user_id` on `target` authenticates with `root` as the only trust
    /// root, so that one certifier's word can be read on its own.
    fn under(store: &Store, root: &Cert, target: &Cert, user_id: &str) -> crate::Authentication {
        let certs = store.certs().unwrap();
        crate::wot::for_user_id(
            &crate::wot::authenticate_all(&certs, &[root.fingerprint().to_hex()]),
            &target.fingerprint().to_hex(),
            user_id,
        )
    }

    /// A signer for `cert`'s primary key, whose secret is here and has no
    /// passphrase.
    fn primary_signer(cert: &Cert) -> KeyPair {
        cert.primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap()
    }

    /// `builder` signed by `signer` over `user_id` on `target`: for the shapes
    /// of certification that certify() does not make.
    fn signed(
        signer: &mut dyn Signer,
        builder: SignatureBuilder,
        target: &Cert,
        user_id: &str,
    ) -> Signature {
        let userid = target
            .userids()
            .find(|ua| ua.userid().value() == user_id.as_bytes())
            .unwrap()
            .userid()
            .clone();
        builder
            .sign_userid_binding(signer, target.primary_key().key(), &userid)
            .unwrap()
    }

    /// `signature` with its last byte flipped. That byte is signature
    /// material, so the hashed data, and the digest prefix sequoia files the
    /// signature by, are untouched, and the signature verifies against no key
    /// at all.
    fn damaged(signature: Signature) -> Signature {
        let mut bytes = Packet::from(signature).to_vec().unwrap();
        *bytes.last_mut().unwrap() ^= 0x01;
        match Packet::from_bytes(&bytes).unwrap() {
            Packet::Signature(signature) => signature,
            other => panic!("the damaged signature parsed as {other:?}"),
        }
    }

    /// `target` as the store holds it, with `signatures` merged in and stored.
    fn plant(store: &Store, target: &Cert, signatures: Vec<Signature>) -> Cert {
        let fingerprint = target.fingerprint().to_hex();
        let planted = store
            .lookup(&fingerprint)
            .unwrap()
            .insert_packets(signatures)
            .unwrap()
            .0;
        store.insert(&planted).unwrap();
        store.lookup(&fingerprint).unwrap()
    }

    /// A key made two hours ago whose one user ID is bound only by a SHA-1
    /// self-signature, which the standard policy has rejected since 2023.
    fn bound_with_sha1(user_id: &str) -> Cert {
        use sequoia_openpgp::packet::UserID;
        use sequoia_openpgp::packet::key::{Key4, PrimaryRole, SecretParts};
        use sequoia_openpgp::types::{Curve, HashAlgorithm};

        let then = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
        let mut key: Key4<SecretParts, PrimaryRole> =
            Key4::generate_ecc(true, Curve::Ed25519).unwrap();
        key.set_creation_time(then).unwrap();
        let key: Key<SecretParts, PrimaryRole> = key.into();
        let userid = UserID::from(user_id);
        let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
            .set_hash_algo(HashAlgorithm::SHA1)
            .set_signature_creation_time(then + Duration::from_secs(60))
            .unwrap()
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())
            .unwrap()
            .sign_userid_binding(
                &mut key.clone().into_keypair().unwrap(),
                key.parts_as_public(),
                &userid,
            )
            .unwrap();
        let cert = Cert::from_packets(
            vec![
                Packet::from(key.parts_into_public()),
                Packet::from(userid),
                Packet::from(binding),
            ]
            .into_iter(),
        )
        .unwrap();
        assert!(
            cert.with_policy(&policy(), None).is_err(),
            "the policy must reject the SHA-1 binding, or this proves nothing"
        );
        cert
    }

    #[test]
    fn certifies_a_user_id_and_reads_it_back() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();

        assert!(certifications(&store, &bob).unwrap().is_empty());

        let mut request =
            CertifyRequest::new(alice.fingerprint().to_hex(), bob.fingerprint().to_hex());
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        certify(&store, &request).unwrap();

        let bob = store.lookup(&bob.fingerprint().to_hex()).unwrap();
        let found = certifications(&store, &bob).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].user_id, "Bob <bob@example.org>");
        assert_eq!(found[0].certifier, "Alice <alice@example.org>");
        assert_eq!(found[0].verified, Some(true));
        assert!(found[0].by_me);
        assert!(found[0].exportable);
        assert_eq!(found[0].amount, FULL);
        assert_eq!(found[0].depth, 0);
    }

    /// Certifying is a public claim that a name belongs to someone. Once the
    /// holder revokes a user ID they are saying it no longer does — an old
    /// address, typically, which the provider may since have handed to a
    /// stranger. Vouching for it then puts our signature behind a claim its
    /// own subject has withdrawn.
    #[test]
    fn refuses_to_vouch_for_a_user_id_its_owner_has_revoked() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert_secret(&bob).unwrap();
        let bob_fp = bob.fingerprint().to_hex();
        crate::lifecycle::add_user_id(&store, &bob_fp, "Bob <bob@oldjob.example>", None).unwrap();

        // Bob leaves the job and disowns the address.
        crate::lifecycle::revoke_user_id(
            &store,
            &bob_fp,
            "Bob <bob@oldjob.example>",
            "left that job",
            None,
        )
        .unwrap();

        let mut request = CertifyRequest::new(alice.fingerprint().to_hex(), &bob_fp);
        request.user_ids = vec!["Bob <bob@oldjob.example>".to_string()];
        let refused = certify(&store, &request);
        assert!(
            refused.is_err(),
            "certified an address its owner had revoked"
        );

        // And the live one is still certifiable, or the guard is just a wall.
        let mut request = CertifyRequest::new(alice.fingerprint().to_hex(), &bob_fp);
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        certify(&store, &request).unwrap();
        let bob = store.lookup(&bob_fp).unwrap();
        let found = certifications(&store, &bob).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].user_id, "Bob <bob@example.org>");
    }

    /// The same reasoning one level up. A certification of a revoked
    /// certificate is born dead: sequoia-wot resolves the target as it stood
    /// when the signature was made and discards the certification if it was
    /// revoked then, and drops every certification of a revoked target at the
    /// reference time besides. So the status bar reported "Certified 1 user
    /// ID(s)" and the list drew a tick while the trust column never moved —
    /// and for a hard revocation an exportable attestation over a key its owner
    /// had declared stolen went into the store, and into exports.
    ///
    /// Looking outwards the answer is the same: a certificate its owner has
    /// withdrawn has no standing left to vouch for anyone.
    #[test]
    fn refuses_to_certify_when_either_end_has_been_revoked() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        let dave = generate(&KeyGenRequest::new("Dave <dave@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert_secret(&bob).unwrap();
        store.insert(&dave).unwrap();
        let (alice_fp, bob_fp, dave_fp) = (
            alice.fingerprint().to_hex(),
            bob.fingerprint().to_hex(),
            dave.fingerprint().to_hex(),
        );

        // Bob's laptop is stolen and he publishes the revocation.
        let mut request = crate::revoke::RevokeRequest::new(&bob_fp);
        request.reason = crate::revoke::Reason::Compromised;
        crate::revoke::revoke_cert(&store, &request).unwrap();

        let mut request = CertifyRequest::new(&alice_fp, &bob_fp);
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        // Mapped to `()` before `expect_err` so that a broken guard reports the
        // assertion rather than `Debug`-printing the whole certificate over it.
        let refused = certify(&store, &request)
            .map(|_| ())
            .expect_err("certified a key its owner had revoked");
        let message = refused.to_string();
        assert!(
            message.contains("Bob <bob@example.org> (the key being certified)")
                && message.contains("revoked"),
            "the refusal must say which key, in which role, and why: {message}"
        );
        assert!(
            certifications(&store, &store.lookup(&bob_fp).unwrap())
                .unwrap()
                .is_empty(),
            "a refused certification must not be written to the store"
        );

        // A live target is still certifiable, or the guard is just a wall.
        let mut request = CertifyRequest::new(&alice_fp, &dave_fp);
        request.user_ids = vec!["Dave <dave@example.org>".to_string()];
        certify(&store, &request).unwrap();

        // Now the certifier's end. certify() signs with the primary key and asks
        // it only whether it is alive, so the refusal is all that stands between
        // a revoked certificate and a new certification. Carol carries a
        // certification subkey as well, the shape that once got past the key
        // filter certify() then relied on, since for a subkey `revoked(false)`
        // does not consult the certificate.
        let (carol, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Carol <carol@example.org>")
            .add_subkey(
                sequoia_openpgp::types::KeyFlags::empty().set_certification(),
                None,
                None,
            )
            .generate()
            .unwrap();
        let carol_fp = carol.fingerprint().to_hex();
        store.insert_secret(&carol).unwrap();
        crate::revoke::revoke_cert(&store, &crate::revoke::RevokeRequest::new(&carol_fp)).unwrap();

        let mut request = CertifyRequest::new(&carol_fp, &dave_fp);
        request.user_ids = vec!["Dave <dave@example.org>".to_string()];
        let refused = certify(&store, &request)
            .map(|_| ())
            .expect_err("vouched for someone with a revoked key");
        let message = refused.to_string();
        assert!(
            message.contains("Carol <carol@example.org> (the certifier)"),
            "the refusal must name the certifier as the certifier: {message}"
        );
        assert!(
            !message.contains("Dave <dave@example.org>"),
            "and must not point at the target, which is fine: {message}"
        );
        assert_eq!(
            certifications(&store, &store.lookup(&dave_fp).unwrap())
                .unwrap()
                .len(),
            1,
            "only Alice's certification should be on Dave"
        );
    }

    /// The certifier is resolved from both of the store's halves, so a
    /// revocation that reached cert-d alone still refuses.
    ///
    /// `Store::insert` writes cert-d and never the secret key file, so this is
    /// the shape a revocation takes when it arrives by import or by a keyserver
    /// refresh: the secret half, which is where the certification key lives,
    /// looks live. Retired rather than the default, because a soft revocation
    /// is the one that still reads as usable to anyone who has not seen it.
    #[test]
    fn refuses_to_certify_when_the_certifiers_revocation_reached_only_cert_d() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let dave = generate(&KeyGenRequest::new("Dave <dave@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&dave).unwrap();
        let (alice_fp, dave_fp) = (alice.fingerprint().to_hex(), dave.fingerprint().to_hex());

        // Retired where the key also lives — the owner's other machine — and
        // met here as the public certificate, which is all `insert` ever
        // writes.
        let elsewhere_dir = tempfile::tempdir().unwrap();
        let elsewhere = Store::open(
            elsewhere_dir.path().join("certs.d"),
            elsewhere_dir.path().join("secrets"),
        )
        .unwrap();
        elsewhere.insert_secret(&alice).unwrap();
        let mut request = crate::revoke::RevokeRequest::new(&alice_fp);
        request.reason = crate::revoke::Reason::Retired;
        crate::revoke::revoke_cert(&elsewhere, &request).unwrap();
        store.insert(&elsewhere.lookup(&alice_fp).unwrap()).unwrap();

        assert!(
            !matches!(
                store
                    .secret_cert(&alice_fp)
                    .unwrap()
                    .revocation_status(&policy(), None),
                RevocationStatus::Revoked(_)
            ),
            "the secret half not knowing is the premise of this test"
        );

        let mut request = CertifyRequest::new(&alice_fp, &dave_fp);
        request.user_ids = vec!["Dave <dave@example.org>".to_string()];
        let refused = certify(&store, &request)
            .map(|_| ())
            .expect_err("vouched for someone with a key whose revocation was in cert-d");
        let message = refused.to_string();
        assert!(
            message.contains("Alice <alice@example.org> (the certifier)"),
            "the refusal must name the certifier as the certifier: {message}"
        );
        assert!(
            certifications(&store, &store.lookup(&dave_fp).unwrap())
                .unwrap()
                .is_empty(),
            "a refused certification must not be written to the store"
        );
    }

    /// A user ID is bytes, and everything above the storage layer handles it
    /// as `from_utf8_lossy` text — which maps every invalid byte to the same
    /// replacement character. Two user IDs differing only in those bytes are
    /// one string by the time they reach the dialog, so the user picks a row
    /// that names both and `find` would sign whichever came first while the
    /// list reported the other. There is no answer to give here, only a
    /// choice between guessing and saying so.
    #[test]
    fn two_user_ids_that_display_alike_are_refused_rather_than_guessed() {
        use sequoia_openpgp::packet::UserID;

        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert_secret(&bob).unwrap();
        let bob_fp = bob.fingerprint().to_hex();

        // Two user IDs, different bytes, identical rendering: 0xFE and 0xFF
        // are both invalid UTF-8 and both display as U+FFFD.
        let mut signer = bob
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let mut packets: Vec<sequoia_openpgp::Packet> = Vec::new();
        for byte in [0xFEu8, 0xFF] {
            let raw = [b"Bob <bob@", &[byte][..], b".example>"].concat();
            let userid = UserID::from(raw);
            let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
                .sign_userid_binding(&mut signer, bob.primary_key().key(), &userid)
                .unwrap();
            packets.push(sequoia_openpgp::Packet::from(userid));
            packets.push(sequoia_openpgp::Packet::from(binding));
        }
        let bob = bob.insert_packets(packets).unwrap().0;
        store.insert_secret(&bob).unwrap();

        let displayed = String::from_utf8_lossy(
            &[b"Bob <bob@".to_vec(), vec![0xFE], b".example>".to_vec()].concat(),
        )
        .into_owned();

        let mut request = CertifyRequest::new(alice.fingerprint().to_hex(), &bob_fp);
        request.user_ids = vec![displayed.clone()];
        let refused = certify(&store, &request);
        let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            message.contains("more than one user ID"),
            "an ambiguous identity must be refused, not guessed at; got {message:?}"
        );

        // An unambiguous one still signs, or this is just a wall.
        let mut request = CertifyRequest::new(alice.fingerprint().to_hex(), &bob_fp);
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        certify(&store, &request).unwrap();
    }

    #[test]
    fn records_a_partial_trust_signature() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();

        let mut request =
            CertifyRequest::new(alice.fingerprint().to_hex(), bob.fingerprint().to_hex());
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        request.amount = PARTIAL;
        request.depth = 1;
        request.exportable = false;
        certify(&store, &request).unwrap();

        let bob = store.lookup(&bob.fingerprint().to_hex()).unwrap();
        let found = certifications(&store, &bob).unwrap();

        assert_eq!(found[0].amount, PARTIAL);
        assert_eq!(found[0].depth, 1);
        assert!(!found[0].exportable);
        assert!(found[0].is_good());
    }

    /// Changing a certification means making a new one, and sequoia-wot counts
    /// a certifier's newest certification of a user ID — but it keeps every
    /// one that shares the newest second, and walks the strongest of them. So a
    /// change of mind made within the second of the certification it corrects,
    /// as a script or a quick second click makes it, changed nothing: Full
    /// stayed Full, and a trusted introducer demoted to a plain certification
    /// went on vouching for everyone it had certified. The new certification is
    /// dated after the old one instead, and so replaces it.
    #[test]
    fn a_certification_changed_within_the_second_replaces_the_one_before_it() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();
        let (alice_fp, bob_fp) = (alice.fingerprint().to_hex(), bob.fingerprint().to_hex());

        let mut request = CertifyRequest::new(&alice_fp, &bob_fp);
        request.user_ids = vec!["Bob <bob@example.org>".to_string()];
        request.depth = 1;
        certify(&store, &request).unwrap();

        // Straight away, with no wait: Partial, and no longer an introducer.
        request.depth = 0;
        request.amount = PARTIAL;
        certify(&store, &request).unwrap();

        let mut made: Vec<(SystemTime, u8, u8, Option<Standing>)> =
            certifications(&store, &store.lookup(&bob_fp).unwrap())
                .unwrap()
                .into_iter()
                .filter(|c| c.by_me && !c.is_revocation)
                .map(|c| (c.created.unwrap(), c.depth, c.amount, c.standing))
                .collect();
        made.sort_by_key(|m| m.0);
        assert_eq!(made.len(), 2, "{made:?}");
        assert!(
            made[0].0 < made[1].0,
            "the change shares a second with the certification it corrects: {made:?}"
        );
        assert_eq!(
            (made[1].1, made[1].2, made[1].3),
            (0, PARTIAL, Some(Standing::Stands)),
            "the newer certification must be the change, and the one that counts: {made:?}"
        );
        assert_eq!(
            made[0].3,
            Some(Standing::Superseded),
            "the one it corrects must be listed as replaced: {made:?}"
        );

        let certs = store.certs().unwrap();
        assert_eq!(
            crate::wot::for_user_id(
                &crate::wot::authenticate_all(&certs, std::slice::from_ref(&alice_fp)),
                &bob_fp,
                "Bob <bob@example.org>",
            ),
            crate::Authentication::Marginal,
            "the Full certification the user changed to Partial still counts"
        );
    }

    #[test]
    fn refuses_to_certify_yourself_or_nothing() {
        let (_dir, store) = scratch();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let fingerprint = alice.fingerprint().to_hex();

        let mut same = CertifyRequest::new(&fingerprint, &fingerprint);
        same.user_ids = vec!["Alice <alice@example.org>".to_string()];
        assert!(certify(&store, &same).is_err());

        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert(&bob).unwrap();
        let empty = CertifyRequest::new(&fingerprint, bob.fingerprint().to_hex());
        assert!(certify(&store, &empty).is_err());
    }

    /// Withdrawing is offered for what still stands, per key: not for a
    /// certification its key has already withdrawn, and again for one the key
    /// made after withdrawing.
    ///
    /// The button used to be hidden by any withdrawal a key had made on the
    /// user ID, whatever its date, so withdrawing and certifying again left a
    /// certification in force that the app offered no way to withdraw. And the
    /// run took every certification a key had ever made, withdrawn or not, so
    /// a key with nothing left standing was asked to sign again. The list drew
    /// the withdrawn certification with a tick besides, beside a pill saying
    /// the identity was unverified.
    #[test]
    fn only_certifications_that_stand_are_offered_for_withdrawal() {
        let (_dir, store) = scratch();
        let (one, two, them) = (
            key("One <one@example.org>"),
            key("Two <two@example.org>"),
            key("Them <them@example.org>"),
        );
        store.insert_secret(&one).unwrap();
        store.insert_secret(&two).unwrap();
        store.insert(&them).unwrap();
        let (one_fp, them_fp) = (one.fingerprint().to_hex(), them.fingerprint().to_hex());
        let user_id = "Them <them@example.org>".to_string();

        let request = |certifier: &Cert| {
            let mut request = CertifyRequest::new(certifier.fingerprint().to_hex(), &them_fp);
            request.user_ids = vec![user_id.clone()];
            request
        };
        certify(&store, &request(&one)).unwrap();
        certify(&store, &request(&two)).unwrap();

        let listed = || certifications(&store, &store.lookup(&them_fp).unwrap()).unwrap();
        let offered = |keys: &[&Cert]| -> BTreeMap<String, Vec<String>> {
            keys.iter()
                .map(|key| (key.fingerprint().to_hex(), vec![user_id.clone()]))
                .collect()
        };
        let by_one = |listed: &[Certification]| -> Vec<Option<Standing>> {
            let mut made: Vec<_> = listed
                .iter()
                .filter(|c| c.certifier_fingerprint.as_deref() == Some(&one_fp))
                .filter(|c| !c.is_revocation)
                .map(|c| (c.created, c.standing))
                .collect();
            made.sort_by_key(|(created, _)| *created);
            made.into_iter().map(|(_, standing)| standing).collect()
        };
        assert_eq!(withdrawable(&listed()), offered(&[&one, &two]));

        revoke_certification(
            &store,
            &one_fp,
            &them_fp,
            std::slice::from_ref(&user_id),
            Reason::Retired,
            "",
            None,
        )
        .unwrap();
        let after = listed();
        assert_eq!(
            withdrawable(&after),
            offered(&[&two]),
            "a certification already withdrawn must not be offered for withdrawal again"
        );
        assert_eq!(
            by_one(&after),
            [Some(Standing::Withdrawn)],
            "the withdrawn certification must no longer read as counting"
        );
        assert_eq!(
            under(&store, &one, &them, &user_id),
            crate::Authentication::Unknown
        );

        certify(&store, &request(&one)).unwrap();
        let again = listed();
        assert_eq!(
            withdrawable(&again),
            offered(&[&one, &two]),
            "a certification made after a withdrawal stands, and must be offered for withdrawal"
        );
        assert_eq!(
            by_one(&again),
            [Some(Standing::Withdrawn), Some(Standing::Stands)]
        );
        assert_eq!(
            under(&store, &one, &them, &user_id),
            crate::Authentication::Full
        );
    }

    /// A certification past the expiry it was made with counts for nobody,
    /// and used to keep its tick for ever. Nothing in the app sets an expiry on
    /// a certification, so this is one made elsewhere and imported.
    #[test]
    fn an_expired_certification_does_not_count() {
        let (_dir, store) = scratch();
        let (me, them) = (key("Me <me@example.org>"), key("Them <them@example.org>"));
        store.insert_secret(&me).unwrap();
        let user_id = "Them <them@example.org>";

        // Made half a minute ago, for ten seconds, and so expired twenty
        // seconds ago; both keys were made a minute back, so both were valid
        // then.
        let made = SystemTime::now() - Duration::from_secs(30);
        let certification = signed(
            &mut primary_signer(&me),
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(made)
                .unwrap()
                .set_signature_validity_period(Duration::from_secs(10))
                .unwrap(),
            &them,
            user_id,
        );
        store
            .insert(&them.clone().insert_packets(vec![certification]).unwrap().0)
            .unwrap();

        let found =
            certifications(&store, &store.lookup(&them.fingerprint().to_hex()).unwrap()).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].verified, Some(true));
        assert!(found[0].by_me);
        assert_eq!(found[0].standing, Some(Standing::Expired));
        assert!(
            !found[0].is_good(),
            "an expired certification still reads as good"
        );
        assert!(
            withdrawable(&found).is_empty(),
            "there is nothing to withdraw in a certification that no longer counts"
        );
        assert_eq!(
            under(&store, &me, &them, user_id),
            crate::Authentication::Unknown
        );
    }

    /// A key its owner has declared compromised takes back everything it
    /// ever signed, and sequoia-wot stops counting its certifications; the
    /// list went on drawing them with a tick. A soft revocation made after a
    /// certification leaves that certification standing, in both.
    #[test]
    fn a_hard_revoked_certifiers_certifications_stop_counting_and_a_soft_revoked_ones_do_not() {
        let (_dir, store) = scratch();
        let (carol, dave, them) = (
            key("Carol <carol@example.org>"),
            key("Dave <dave@example.org>"),
            key("Them <them@example.org>"),
        );
        store.insert_secret(&carol).unwrap();
        store.insert_secret(&dave).unwrap();
        store.insert(&them).unwrap();
        let them_fp = them.fingerprint().to_hex();
        let user_id = "Them <them@example.org>";
        let row = |certifier: &Cert| -> Certification {
            certifications(&store, &store.lookup(&them_fp).unwrap())
                .unwrap()
                .into_iter()
                .find(|c| {
                    c.certifier_fingerprint.as_deref() == Some(&certifier.fingerprint().to_hex())
                })
                .unwrap()
        };

        let mut request = CertifyRequest::new(carol.fingerprint().to_hex(), &them_fp);
        request.user_ids = vec![user_id.to_string()];
        certify(&store, &request).unwrap();
        assert_eq!(row(&carol).standing, Some(Standing::Stands));
        assert_eq!(
            under(&store, &carol, &them, user_id),
            crate::Authentication::Full
        );

        let mut compromised = RevokeRequest::new(carol.fingerprint().to_hex());
        compromised.reason = Reason::Compromised;
        revoke_cert(&store, &compromised).unwrap();
        assert_eq!(
            under(&store, &carol, &them, user_id),
            crate::Authentication::Unknown
        );
        let carols = row(&carol);
        assert_eq!(carols.verified, Some(true), "the signature itself is sound");
        assert_eq!(carols.standing, Some(Standing::CertifierRevoked));
        assert!(
            !carols.is_good(),
            "a certification by a key declared compromised still reads as good"
        );

        // Dave's certification is half a minute old when he retires his key,
        // so that the retirement is certainly the later of the two.
        let certification = signed(
            &mut primary_signer(&dave),
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(SystemTime::now() - Duration::from_secs(30))
                .unwrap(),
            &them,
            user_id,
        );
        plant(&store, &them, vec![certification]);
        revoke_cert(&store, &RevokeRequest::new(dave.fingerprint().to_hex())).unwrap();
        assert_eq!(
            under(&store, &dave, &them, user_id),
            crate::Authentication::Full
        );
        assert_eq!(row(&dave).standing, Some(Standing::Stands));
    }

    /// A certification a subkey made is its maker's word, and is listed as
    /// theirs, but sequoia-wot checks certifications against the primary key
    /// alone and never counts it. It used to read as good regardless. And once
    /// that subkey was retired, the key list the listing verified against left
    /// it out, so the same sound signature read as one that does not check out
    /// and lost its maker's name.
    #[test]
    fn a_certification_made_by_a_subkey_is_attributed_but_does_not_count() {
        let (_dir, store) = scratch();
        let (eve, _) = CertBuilder::new()
            .add_userid("Eve <eve@example.org>")
            .add_certification_subkey()
            .generate()
            .unwrap();
        let them = key("Them <them@example.org>");
        store.insert_secret(&eve).unwrap();
        let (eve_fp, them_fp) = (eve.fingerprint().to_hex(), them.fingerprint().to_hex());
        let user_id = "Them <them@example.org>";

        let subkey = eve.keys().subkeys().next().unwrap().key().clone();
        let mut by_subkey = subkey
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let certification = signed(
            &mut by_subkey,
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(SystemTime::now() - Duration::from_secs(30))
                .unwrap(),
            &them,
            user_id,
        );
        store
            .insert(&them.clone().insert_packets(vec![certification]).unwrap().0)
            .unwrap();

        let listed = || {
            let found = certifications(&store, &store.lookup(&them_fp).unwrap()).unwrap();
            assert_eq!(found.len(), 1, "{found:?}");
            found.into_iter().next().unwrap()
        };
        let found = listed();
        assert_eq!(found.verified, Some(true));
        assert_eq!(found.certifier, "Eve <eve@example.org>");
        assert_eq!(found.standing, Some(Standing::NotByPrimaryKey));
        assert!(
            !found.is_good(),
            "a certification the web of trust ignores reads as good"
        );
        assert_eq!(
            under(&store, &eve, &them, user_id),
            crate::Authentication::Unknown
        );

        crate::lifecycle::revoke_subkey(
            &store,
            &eve_fp,
            &subkey.fingerprint().to_hex(),
            Reason::Retired,
            "",
            None,
        )
        .unwrap();
        let found = listed();
        assert_eq!(
            (found.verified, found.certifier.as_str()),
            (Some(true), "Eve <eve@example.org>"),
            "retiring the subkey does not make its signature a bad one"
        );
        assert_eq!(found.standing, Some(Standing::NotByPrimaryKey));
    }

    /// certify() signs with the primary key even where the certificate puts
    /// its certify flag on a subkey instead, because sequoia-wot counts a
    /// certification made by the primary key and no other. It used to sign
    /// with the first key flagged to certify, report success, and leave the
    /// identity exactly as unverified as before.
    #[test]
    fn certify_signs_with_the_primary_key_even_where_a_subkey_is_flagged_to_certify() {
        let (_dir, store) = scratch();
        let (frank, _) = CertBuilder::new()
            .add_userid("Frank <frank@example.org>")
            .set_primary_key_flags(KeyFlags::empty().set_signing())
            .add_certification_subkey()
            .generate()
            .unwrap();
        let them = key("Them <them@example.org>");
        store.insert_secret(&frank).unwrap();
        store.insert(&them).unwrap();
        let user_id = "Them <them@example.org>";
        assert!(
            !frank
                .with_policy(&policy(), None)
                .unwrap()
                .primary_key()
                .key_flags()
                .unwrap()
                .for_certification(),
            "the primary must not be flagged to certify, or this proves nothing"
        );

        let mut request =
            CertifyRequest::new(frank.fingerprint().to_hex(), them.fingerprint().to_hex());
        request.user_ids = vec![user_id.to_string()];
        let certified = certify(&store, &request).unwrap();

        let made = certified
            .userids()
            .flat_map(|ua| ua.certifications())
            .next()
            .unwrap();
        assert!(
            made.clone()
                .verify_signature(frank.primary_key().key())
                .is_ok(),
            "the certification was not made by the primary key"
        );
        let found = certifications(&store, &certified).unwrap();
        assert_eq!(found[0].standing, Some(Standing::Stands));
        assert_eq!(
            under(&store, &frank, &them, user_id),
            crate::Authentication::Full
        );
    }

    /// A certification that names its maker only by key ID, as GnuPG 1.x wrote
    /// them, is still credited to its maker when a copy of the key has had an
    /// issuer fingerprint naming someone else in the store added to it. That
    /// fingerprint is tried first, since fingerprints go ahead of key IDs
    /// whichever area they are in, and the listing used to stop at the first
    /// issuer it could find a certificate for, verified or not: the user's own
    /// certification read as a bad signature by a stranger, with no "(you)"
    /// and no way to withdraw it.
    #[test]
    fn a_certification_named_by_key_id_is_credited_even_behind_a_planted_issuer() {
        let (_dir, store) = scratch();
        let legacy = |user_id: &str| {
            let mut request = KeyGenRequest::new(user_id);
            request.standard = crate::keygen::Standard::Rfc4880;
            generate(&request).unwrap().cert
        };
        let (alice, bob, carol) = (
            legacy("Alice <alice@example.org>"),
            legacy("Bob <bob@example.org>"),
            legacy("Carol <carol@example.org>"),
        );
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();
        store.insert(&carol).unwrap();

        let mut certification = signed(
            &mut primary_signer(&alice),
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_issuer(alice.keyid())
                .unwrap(),
            &bob,
            "Bob <bob@example.org>",
        );
        certification
            .unhashed_area_mut()
            .add(
                Subpacket::new(
                    SubpacketValue::IssuerFingerprint(carol.fingerprint()),
                    false,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            certification.get_issuers(),
            vec![
                sequoia_openpgp::KeyHandle::from(carol.fingerprint()),
                sequoia_openpgp::KeyHandle::from(alice.keyid()),
            ],
            "the planted issuer has to be tried first and Alice's key ID after it, or this proves nothing"
        );
        store
            .insert(&bob.clone().insert_packets(vec![certification]).unwrap().0)
            .unwrap();

        let found =
            certifications(&store, &store.lookup(&bob.fingerprint().to_hex()).unwrap()).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].verified, Some(true), "{found:?}");
        assert_eq!(found[0].certifier, "Alice <alice@example.org>");
        assert!(found[0].by_me);
        assert_eq!(
            found[0].certifier_fingerprint.as_deref(),
            Some(alice.fingerprint().to_hex().as_str())
        );
        assert_eq!(found[0].standing, Some(Standing::Stands));
    }

    /// The same planting, where the planted fingerprint names a certificate
    /// that binds the user's own public primary key as a certification subkey:
    /// a binding that takes no back-signature, and so nothing from the user.
    /// The listing took the first issuer the signature verified against at
    /// all, so the stranger won, and the user's certification read as made by
    /// the stranger's subkey and not counting, with no "(you)" and nothing to
    /// withdraw, while sequoia-wot, which takes a primary key and nothing
    /// else, counted it for the user. A withdrawal planted the same way is the
    /// user's too, and takes the certification back.
    #[test]
    fn a_certification_is_credited_to_its_maker_where_a_stranger_binds_the_same_key_as_a_subkey() {
        use sequoia_openpgp::packet::key::SubordinateRole;

        let (_dir, store) = scratch();
        let legacy = |user_id: &str| {
            let mut request = KeyGenRequest::new(user_id);
            request.standard = crate::keygen::Standard::Rfc4880;
            generate(&request).unwrap().cert
        };
        let (alice, bob, mallory) = (
            legacy("Alice <alice@example.org>"),
            legacy("Bob <bob@example.org>"),
            legacy("Mallory <mallory@example.org>"),
        );
        let alice_fp = alice.fingerprint().to_hex();
        let user_id = "Bob <bob@example.org>";

        let alice_as_subkey: Key<PublicParts, SubordinateRole> =
            alice.primary_key().key().clone().role_into_subordinate();
        let binding = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_key_flags(KeyFlags::empty().set_certification())
            .unwrap()
            .sign_subkey_binding(
                &mut primary_signer(&mallory),
                mallory.primary_key().key(),
                &alice_as_subkey,
            )
            .unwrap();
        let mallory = mallory
            .insert_packets(vec![Packet::from(alice_as_subkey), Packet::from(binding)])
            .unwrap()
            .0;
        assert!(
            mallory
                .with_policy(&policy(), None)
                .unwrap()
                .keys()
                .subkeys()
                .for_certification()
                .any(|ka| ka.key().fingerprint() == alice.fingerprint()),
            "Mallory must bind Alice's key to certify, or this proves nothing"
        );
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();
        store.insert(&mallory).unwrap();

        // Named by Alice's key ID alone, as GnuPG 1.x wrote it, with Mallory's
        // fingerprint planted where get_issuers() puts it first.
        let now = SystemTime::now();
        let by_alice = |kind, at| {
            let mut signature = signed(
                &mut primary_signer(&alice),
                SignatureBuilder::new(kind)
                    .set_signature_creation_time(at)
                    .unwrap()
                    .set_issuer(alice.keyid())
                    .unwrap(),
                &bob,
                user_id,
            );
            signature
                .unhashed_area_mut()
                .add(
                    Subpacket::new(
                        SubpacketValue::IssuerFingerprint(mallory.fingerprint()),
                        false,
                    )
                    .unwrap(),
                )
                .unwrap();
            assert_eq!(
                signature.get_issuers(),
                vec![
                    sequoia_openpgp::KeyHandle::from(mallory.fingerprint()),
                    sequoia_openpgp::KeyHandle::from(alice.keyid()),
                ],
                "Mallory has to be tried first, or this proves nothing"
            );
            signature
        };

        let stored = plant(
            &store,
            &bob,
            vec![by_alice(
                SignatureType::GenericCertification,
                now - Duration::from_secs(60),
            )],
        );
        let found = certifications(&store, &stored).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].certifier, "Alice <alice@example.org>", "{found:?}");
        assert!(found[0].by_me, "{found:?}");
        assert_eq!(
            found[0].certifier_fingerprint.as_deref(),
            Some(alice_fp.as_str())
        );
        assert_eq!(found[0].standing, Some(Standing::Stands), "{found:?}");
        assert_eq!(
            withdrawable(&found),
            BTreeMap::from([(alice_fp.clone(), vec![user_id.to_string()])])
        );
        assert_eq!(
            under(&store, &alice, &bob, user_id),
            crate::Authentication::Full,
            "sequoia-wot has to count it for Alice, or there is nothing to agree with"
        );

        let stored = plant(
            &store,
            &bob,
            vec![by_alice(
                SignatureType::CertificationRevocation,
                now - Duration::from_secs(30),
            )],
        );
        let found = certifications(&store, &stored).unwrap();
        assert_eq!(found.len(), 2, "{found:?}");
        let withdrawal = found.iter().find(|c| c.is_revocation).unwrap();
        assert_eq!(
            (withdrawal.certifier.as_str(), withdrawal.by_me),
            ("Alice <alice@example.org>", true),
            "{withdrawal:?}"
        );
        let certification = found.iter().find(|c| !c.is_revocation).unwrap();
        assert_eq!(certification.standing, Some(Standing::Withdrawn));
        assert!(withdrawable(&found).is_empty(), "{found:?}");
        assert_eq!(
            under(&store, &alice, &bob, user_id),
            crate::Authentication::Unknown
        );
    }

    /// A signature that merely claims to be the certifier's cannot date its
    /// certification. certify() dates a new certification after the
    /// certifier's own certifications and withdrawals of the user ID, and one
    /// planted in the far future would otherwise put it there, where it never
    /// takes effect, or, with a date that far ahead refused, stop the
    /// certification being made at all.
    ///
    /// Two plantings, each of a certification and a withdrawal: signatures A
    /// made and that were then damaged, so that A's name on them is genuine and
    /// the signature is not, and signatures B made and relabelled to name A.
    /// Each is tried alone, so that each is shown to be ignored.
    #[test]
    fn certify_is_not_dated_by_signatures_that_only_claim_to_be_the_certifiers() {
        let (_dir, store) = scratch();
        let (a, b, them) = (
            key("A <a@example.org>"),
            key("B <b@example.org>"),
            key("Them <them@example.org>"),
        );
        store.insert_secret(&a).unwrap();
        store.insert(&them).unwrap();
        let user_id = "Them <them@example.org>";
        let future = SystemTime::now() + Duration::from_secs(5 * 365 * 24 * 60 * 60);
        let kinds = [
            SignatureType::GenericCertification,
            SignatureType::CertificationRevocation,
        ];
        let dated = |kind| {
            SignatureBuilder::new(kind)
                .set_signature_creation_time(future)
                .unwrap()
        };

        let by_a_then_damaged: Vec<Signature> = kinds
            .iter()
            .map(|&kind| damaged(signed(&mut primary_signer(&a), dated(kind), &them, user_id)))
            .collect();
        let by_b_relabelled: Vec<Signature> = kinds
            .iter()
            .map(|&kind| {
                let mut signature = signed(&mut primary_signer(&b), dated(kind), &them, user_id);
                signature
                    .unhashed_area_mut()
                    .add(Subpacket::new(SubpacketValue::Issuer(a.keyid()), false).unwrap())
                    .unwrap();
                signature
            })
            .collect();

        let mut request =
            CertifyRequest::new(a.fingerprint().to_hex(), them.fingerprint().to_hex());
        request.user_ids = vec![user_id.to_string()];
        for (round, (planting, planted)) in [
            ("damaged", by_a_then_damaged),
            ("relabelled", by_b_relabelled),
        ]
        .into_iter()
        .enumerate()
        {
            for signature in &planted {
                assert!(
                    crate::cert::issued_by(signature, &a),
                    "a {planting} packet must name A, or this proves nothing"
                );
            }
            let stored = plant(&store, &them, planted);
            let ua = stored.userids().next().unwrap();
            let far_ahead = |s: &Signature| {
                s.signature_creation_time().is_some_and(|t| {
                    t > SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60)
                })
            };
            // One of each kind per round so far, the earlier round's included.
            assert!(
                ua.certifications().filter(|s| far_ahead(s)).count() == round + 1
                    && ua.other_revocations().filter(|s| far_ahead(s)).count() == round + 1,
                "the {planting} packets must be on the certificate, or this proves nothing"
            );

            let certified = certify(&store, &request)
                .map(|_| ())
                .map_err(|e| e.to_string());
            assert_eq!(
                certified,
                Ok(()),
                "a {planting} packet A did not sign held A's certification back"
            );
            assert_eq!(
                under(&store, &a, &them, user_id),
                crate::Authentication::Full,
                "the certification must count at once, with the {planting} packets present"
            );
        }
    }

    /// A signature is credited to a certifier only if it verifies against
    /// that certifier's key. Otherwise it is listed under the handle it names,
    /// as not checking out, and earns no "(you)", no withdrawal and no tick.
    /// The same two plantings as above: a signature A made, damaged, and one B
    /// made that names A as its only issuer, in the hashed area where a
    /// relabeller can write it as easily as in the unhashed one. B is not in
    /// the store, so that A is the only certificate either one leads to.
    ///
    /// Nor does a forgery displace what A did say. The forgeries are dated
    /// after A's own certification, so that one which took part in deciding
    /// which of A's certifications is the newest would leave A's reading as
    /// replaced.
    #[test]
    fn a_certification_is_credited_only_to_a_key_it_verifies_against() {
        let (_dir, store) = scratch();
        let (a, b, them) = (
            key("A <a@example.org>"),
            key("B <b@example.org>"),
            key("Them <them@example.org>"),
        );
        store.insert_secret(&a).unwrap();
        store.insert(&them).unwrap();
        let a_fp = a.fingerprint().to_hex();
        let user_id = "Them <them@example.org>";

        // A genuinely certifies, so the list has the real "(you)" row beside
        // the forgeries: half a minute ago, and the forgeries ten seconds ago.
        let now = SystemTime::now();
        let certification = |at: SystemTime| {
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(at)
                .unwrap()
        };
        let genuine = signed(
            &mut primary_signer(&a),
            certification(now - Duration::from_secs(30)),
            &them,
            user_id,
        );
        plant(&store, &them, vec![genuine]);

        let later = now - Duration::from_secs(10);
        let damaged = damaged(signed(
            &mut primary_signer(&a),
            certification(later),
            &them,
            user_id,
        ));
        let relabelled = signed(
            &mut primary_signer(&b),
            certification(later)
                .set_issuer_fingerprint(a.fingerprint())
                .unwrap(),
            &them,
            user_id,
        );
        assert_eq!(
            relabelled.get_issuers(),
            vec![sequoia_openpgp::KeyHandle::from(a.fingerprint())],
            "B's signature must name A alone, or this proves nothing"
        );
        let stored = plant(&store, &them, vec![damaged, relabelled]);

        let found = certifications(&store, &stored).unwrap();
        assert_eq!(found.len(), 3, "{found:?}");
        let (genuine, forged): (Vec<_>, Vec<_>) =
            found.iter().partition(|c| c.verified == Some(true));
        assert_eq!(genuine.len(), 1, "{found:?}");
        assert!(genuine[0].by_me);
        assert_eq!(
            genuine[0].standing,
            Some(Standing::Stands),
            "a forgery naming A must not displace A's own certification"
        );
        for c in &forged {
            assert_eq!(c.verified, Some(false), "{c:?}");
            assert!(!c.by_me, "a forgery earned a (you): {c:?}");
            assert_eq!(c.certifier_fingerprint, None, "{c:?}");
            assert_eq!(c.certifier, a_fp, "listed under the handle it names: {c:?}");
            assert_eq!(c.standing, None, "{c:?}");
            assert!(!c.is_good(), "{c:?}");
        }
        assert_eq!(
            withdrawable(&found),
            BTreeMap::from([(a_fp.clone(), vec![user_id.to_string()])]),
            "only A's own certification is A's to withdraw"
        );
    }

    /// certify() refuses a certification that sequoia-wot would discount from
    /// the moment it was made: of a key that has expired, of a key bound only
    /// by signatures the policy rejects, and of a user ID that is not UTF-8.
    /// Each used to be signed and reported as made though it never counted,
    /// and under standing's rules the app would now refuse to withdraw it,
    /// although a published one can be counted by software that does not
    /// share those rules.
    ///
    /// The refusal comes before the certifier's key is unlocked. That key has
    /// a passphrase here and none is given, so a refusal made after unlocking
    /// would read as the missing passphrase instead, as it does for the sound
    /// user ID beside the one that is not UTF-8. The older refusals, of a user
    /// ID its owner has retracted and of a name two user IDs display alike,
    /// used to come after the unlock, and now come before it with these.
    #[test]
    fn refuses_to_certify_what_could_never_count_before_asking_for_a_passphrase() {
        use sequoia_openpgp::cert::UserIDRevocationBuilder;
        use sequoia_openpgp::packet::UserID;
        use sequoia_openpgp::types::ReasonForRevocation;

        let (_dir, store) = scratch();
        let mut request = KeyGenRequest::new("Me <me@example.org>");
        // RFC 4880, whose passphrase protection is quick to open.
        request.standard = crate::keygen::Standard::Rfc4880;
        request.password = Some("correct horse".to_string().into());
        let me = generate(&request).unwrap().cert;
        store.insert_secret(&me).unwrap();
        let me_fp = me.fingerprint().to_hex();

        // Made two hours ago to last one.
        let (expired, _) = CertBuilder::new()
            .add_userid("Expired <expired@example.org>")
            .set_creation_time(SystemTime::now() - Duration::from_secs(2 * 60 * 60))
            .set_validity_period(Duration::from_secs(60 * 60))
            .generate()
            .unwrap();
        let sha1 = bound_with_sha1("Old <old@example.org>");
        let them = key("Them <them@example.org>");
        // Beside the sound user ID: one that is not UTF-8, two whose invalid
        // bytes differ and display alike, and one its owner has retracted.
        let raw = [b"Them <them@".as_slice(), &[0xFE], b".example>"].concat();
        let twins =
            [0xFEu8, 0xFF].map(|byte| [b"Twin <twin@".as_slice(), &[byte], b".example>"].concat());
        let retired = UserID::from("Them <them@oldjob.example>");
        let mut packets = Vec::new();
        for userid in std::iter::once(raw.clone())
            .chain(twins.clone())
            .map(UserID::from)
            .chain(std::iter::once(retired.clone()))
        {
            let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
                .sign_userid_binding(
                    &mut primary_signer(&them),
                    them.primary_key().key(),
                    &userid,
                )
                .unwrap();
            packets.push(Packet::from(userid));
            packets.push(Packet::from(binding));
        }
        packets.push(Packet::from(
            UserIDRevocationBuilder::new()
                .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"left that job")
                .unwrap()
                .build(&mut primary_signer(&them), &them, &retired, None)
                .unwrap(),
        ));
        let them = them.insert_packets(packets).unwrap().0;
        let not_utf8 = String::from_utf8_lossy(&raw).into_owned();
        let twin = String::from_utf8_lossy(&twins[0]).into_owned();
        for cert in [&expired, &sha1, &them] {
            store.insert(cert).unwrap();
        }

        let attempt = |target: &Cert, user_id: &str, password: Option<&str>| {
            let mut request = CertifyRequest::new(&me_fp, target.fingerprint().to_hex());
            request.user_ids = vec![user_id.to_string()];
            request.password = password.map(|p| p.to_string().into());
            certify(&store, &request)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        for (target, user_id, why) in [
            (
                &expired,
                "Expired <expired@example.org>",
                "Expired <expired@example.org> (the key being certified) has expired",
            ),
            (
                &sha1,
                "Old <old@example.org>",
                "Old <old@example.org> (the key being certified) is not valid under the standard policy",
            ),
            (&them, not_utf8.as_str(), "is not valid UTF-8"),
            (&them, twin.as_str(), "more than one user ID"),
            (
                &them,
                "Them <them@oldjob.example>",
                "has been revoked by its owner",
            ),
        ] {
            let refused = attempt(target, user_id, None);
            assert!(
                refused.as_ref().is_err_and(|e| e.contains(why)),
                "certifying {user_id} must be refused, before the key is unlocked, saying why: {refused:?}"
            );
            assert!(
                certifications(
                    &store,
                    &store.lookup(&target.fingerprint().to_hex()).unwrap()
                )
                .unwrap()
                .is_empty(),
                "a refused certification must not be written to the store"
            );
        }

        // The sound user ID on the same key gets as far as the passphrase,
        // which is the point the refusals above have to come before, and with
        // the passphrase it is certified.
        let sound = "Them <them@example.org>";
        let unlocked_first = attempt(&them, sound, None);
        assert!(
            unlocked_first
                .as_ref()
                .is_err_and(|e| e.contains("passphrase")),
            "without a passphrase a sound certification must stop at the key: {unlocked_first:?}"
        );
        assert_eq!(attempt(&them, sound, Some("correct horse")), Ok(()));
    }

    /// A certification of a key that had already expired when it was made,
    /// or that is bound only by signatures the policy rejects, never counted,
    /// and is listed with that reason rather than a bare "does not count".
    /// certify() no longer makes one, so these are as other software, or an
    /// older version of this app, made them.
    ///
    /// A certification made while the key was valid keeps its tick after the
    /// key expires, since the tick is about the certification. The pill, which
    /// is about the name, says unverified all the same.
    #[test]
    fn a_certification_of_a_key_that_was_not_valid_when_certified_does_not_count() {
        let (_dir, store) = scratch();
        let three_hours_ago = SystemTime::now() - Duration::from_secs(3 * 60 * 60);
        let two_hours_ago = three_hours_ago + Duration::from_secs(60 * 60);
        let (carol, _) = CertBuilder::new()
            .add_userid("Carol <carol@example.org>")
            .set_creation_time(three_hours_ago)
            .generate()
            .unwrap();
        let me = key("Me <me@example.org>");
        // Made two hours ago to last one.
        let (then, _) = CertBuilder::new()
            .add_userid("Then <then@example.org>")
            .set_creation_time(two_hours_ago)
            .set_validity_period(Duration::from_secs(60 * 60))
            .generate()
            .unwrap();
        let sha1 = bound_with_sha1("Old <old@example.org>");
        store.insert_secret(&carol).unwrap();
        store.insert_secret(&me).unwrap();
        store.insert(&then).unwrap();
        store.insert(&sha1).unwrap();
        let me_fp = me.fingerprint().to_hex();

        let dated = |at: SystemTime| {
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(at)
                .unwrap()
        };
        let half_a_minute_ago = SystemTime::now() - Duration::from_secs(30);
        // Carol while Then was valid, and Me an hour after it expired.
        plant(
            &store,
            &then,
            vec![
                signed(
                    &mut primary_signer(&carol),
                    dated(two_hours_ago + Duration::from_secs(30 * 60)),
                    &then,
                    "Then <then@example.org>",
                ),
                signed(
                    &mut primary_signer(&me),
                    dated(half_a_minute_ago),
                    &then,
                    "Then <then@example.org>",
                ),
            ],
        );
        plant(
            &store,
            &sha1,
            vec![signed(
                &mut primary_signer(&me),
                dated(half_a_minute_ago),
                &sha1,
                "Old <old@example.org>",
            )],
        );

        let listed = |target: &Cert| {
            certifications(
                &store,
                &store.lookup(&target.fingerprint().to_hex()).unwrap(),
            )
            .unwrap()
        };
        let by = |listed: &[Certification], certifier: &Cert| -> Certification {
            listed
                .iter()
                .find(|c| {
                    c.certifier_fingerprint.as_deref() == Some(&certifier.fingerprint().to_hex())
                })
                .unwrap()
                .clone()
        };

        let carols = by(&listed(&then), &carol);
        assert_eq!(
            carols.standing,
            Some(Standing::Stands),
            "made while the key was valid, it counts: {carols:?}"
        );
        assert_eq!(
            under(&store, &carol, &then, "Then <then@example.org>"),
            crate::Authentication::Unknown,
            "and the name does not authenticate, the key having expired since"
        );

        for (target, user_id) in [
            (&then, "Then <then@example.org>"),
            (&sha1, "Old <old@example.org>"),
        ] {
            let listed = listed(target);
            let mine = by(&listed, &me);
            assert_eq!((mine.verified, mine.by_me), (Some(true), true), "{mine:?}");
            assert_eq!(
                mine.standing,
                Some(Standing::TargetNotValid),
                "{user_id}: {mine:?}"
            );
            assert!(!mine.is_good(), "{user_id}: {mine:?}");
            assert!(
                !withdrawable(&listed).contains_key(&me_fp),
                "{user_id}: a certification that never counted is not offered for withdrawal"
            );
            let refused = revoke_certification(
                &store,
                &me_fp,
                &target.fingerprint().to_hex(),
                &[user_id.to_string()],
                Reason::Retired,
                "",
                None,
            )
            .map(|_| ())
            .map_err(|e| e.to_string());
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|e| e.contains("nothing to withdraw")),
                "{user_id}: {refused:?}"
            );
        }
    }

    /// A certification of the user's own dated ahead of the clock, by a clock
    /// that ran fast where it was made, counts from that date, so it can still
    /// be withdrawn, and is offered for withdrawal. The withdrawal waits the
    /// few seconds it takes to be dated after it or, where the date is further
    /// ahead than that, is refused with the date, as everything that has to
    /// follow such a signature is. Judged by the rule for what counts now, it
    /// read as not counting, with nothing to withdraw, however soon it would
    /// start to.
    ///
    /// A forgery dated ahead of the clock is not the user's to withdraw, and
    /// must neither be offered nor have a withdrawal signed for it.
    #[test]
    fn a_certification_dated_ahead_of_the_clock_can_still_be_withdrawn() {
        let (_dir, store) = scratch();
        let (me, them) = (key("Me <me@example.org>"), key("Them <them@example.org>"));
        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();
        let (me_fp, them_fp) = (me.fingerprint().to_hex(), them.fingerprint().to_hex());
        let user_id = "Them <them@example.org>";

        let ahead = |by: Duration| {
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(SystemTime::now() + by)
                .unwrap()
        };
        let listed = || certifications(&store, &store.lookup(&them_fp).unwrap()).unwrap();
        let mine = || -> Vec<Option<Standing>> {
            let mut mine: Vec<_> = listed()
                .into_iter()
                .filter(|c| c.by_me && !c.is_revocation)
                .map(|c| (c.created, c.standing))
                .collect();
            mine.sort_by_key(|(created, _)| *created);
            mine.into_iter().map(|(_, standing)| standing).collect()
        };
        let withdraw = || {
            revoke_certification(
                &store,
                &me_fp,
                &them_fp,
                &[user_id.to_string()],
                Reason::Retired,
                "",
                None,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        };
        let withdrawals = |cert: &Cert| -> usize {
            cert.userids()
                .map(|ua| ua.other_revocations().count())
                .sum()
        };
        let offered = BTreeMap::from([(me_fp.clone(), vec![user_id.to_string()])]);

        // A forgery five years ahead.
        plant(
            &store,
            &them,
            vec![damaged(signed(
                &mut primary_signer(&me),
                ahead(Duration::from_secs(5 * 365 * 24 * 60 * 60)),
                &them,
                user_id,
            ))],
        );
        assert!(
            withdrawable(&listed()).is_empty(),
            "a forgery was offered for withdrawal"
        );
        let refused = withdraw();
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("nothing to withdraw")),
            "a forgery was taken for something to withdraw: {refused:?}"
        );
        assert_eq!(
            withdrawals(&store.lookup(&them_fp).unwrap()),
            0,
            "a withdrawal was signed for a forgery"
        );

        // Three seconds ahead: offered, and withdrawn once a withdrawal can be
        // dated after it.
        plant(
            &store,
            &them,
            vec![signed(
                &mut primary_signer(&me),
                ahead(Duration::from_secs(3)),
                &them,
                user_id,
            )],
        );
        assert_eq!(
            mine(),
            [Some(Standing::NotYet)],
            "a certification dated ahead of the clock does not count yet"
        );
        assert!(listed().iter().all(|c| !c.is_good()));
        assert_eq!(
            withdrawable(&listed()),
            offered,
            "a certification that will count must be offered for withdrawal"
        );
        assert_eq!(withdraw(), Ok(()));
        assert_eq!(
            mine(),
            [Some(Standing::Withdrawn)],
            "the withdrawal must take it back once its date has passed"
        );
        // Publishable, as the certification it took back was.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exported.asc");
        store
            .export_file(std::slice::from_ref(&them_fp), &path)
            .unwrap();
        assert_eq!(
            withdrawals(&Cert::from_file(&path).unwrap()),
            1,
            "the withdrawal of a publishable certification must be publishable"
        );

        // Three days ahead: offered, and refused with its date.
        plant(
            &store,
            &them,
            vec![signed(
                &mut primary_signer(&me),
                ahead(Duration::from_secs(3 * 24 * 60 * 60)),
                &them,
                user_id,
            )],
        );
        assert_eq!(mine(), [Some(Standing::Withdrawn), Some(Standing::NotYet)]);
        assert_eq!(withdrawable(&listed()), offered);
        let refused = withdraw();
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("ahead of this computer's clock")),
            "a withdrawal that cannot follow the certification must be refused with its date: {refused:?}"
        );
        assert_eq!(
            withdrawals(&store.lookup(&them_fp).unwrap()),
            1,
            "a refused withdrawal must sign nothing"
        );
    }

    /// A certification dated ahead of the clock is judged as sequoia-wot will
    /// judge it when its date comes, and offered for withdrawal only if it
    /// will count then. Any that verified used to be taken for one that would,
    /// so a withdrawal was offered, and signed where the date was near enough,
    /// for a certification that never could count: one of a key that will
    /// have expired by its date, one by a key retired before it, and one that
    /// a withdrawal dated later still already takes back. A forgery dated
    /// ahead is no more the certifier's to withdraw than any other. And a
    /// withdrawal that only names the certifier, dated years ahead, does not
    /// move the date a certification is judged at, or one that will count for
    /// a day would read as expired by the forgery's date.
    #[test]
    fn a_certification_dated_ahead_of_the_clock_is_judged_as_it_will_stand_on_its_date() {
        let (_dir, store) = scratch();
        let (me, retired, them) = (
            key("Me <me@example.org>"),
            key("Retired <retired@example.org>"),
            key("Them <them@example.org>"),
        );
        // Half an hour of validity from now.
        let (brief, _) = CertBuilder::new()
            .add_userid("Brief <brief@example.org>")
            .set_validity_period(Duration::from_secs(30 * 60))
            .generate()
            .unwrap();
        store.insert_secret(&me).unwrap();
        store.insert_secret(&retired).unwrap();
        store.insert(&them).unwrap();
        store.insert(&brief).unwrap();
        revoke_cert(&store, &RevokeRequest::new(retired.fingerprint().to_hex())).unwrap();

        let now = SystemTime::now();
        let (in_an_hour, in_two_hours) = (
            now + Duration::from_secs(60 * 60),
            now + Duration::from_secs(2 * 60 * 60),
        );
        let by = |certifier: &Cert, kind, at, target: &Cert, user_id| {
            signed(
                &mut primary_signer(certifier),
                SignatureBuilder::new(kind)
                    .set_signature_creation_time(at)
                    .unwrap(),
                target,
                user_id,
            )
        };
        let brief_id = "Brief <brief@example.org>";
        let them_id = "Them <them@example.org>";
        plant(
            &store,
            &brief,
            vec![by(
                &me,
                SignatureType::GenericCertification,
                in_an_hour,
                &brief,
                brief_id,
            )],
        );
        plant(
            &store,
            &them,
            vec![
                by(
                    &me,
                    SignatureType::GenericCertification,
                    in_an_hour,
                    &them,
                    them_id,
                ),
                by(
                    &me,
                    SignatureType::CertificationRevocation,
                    in_two_hours,
                    &them,
                    them_id,
                ),
                by(
                    &retired,
                    SignatureType::GenericCertification,
                    in_an_hour,
                    &them,
                    them_id,
                ),
            ],
        );

        for (certifier, target, user_id, expected) in [
            (&me, &brief, brief_id, Standing::TargetNotValid),
            (&me, &them, them_id, Standing::Withdrawn),
            (&retired, &them, them_id, Standing::CertifierRevoked),
        ] {
            let certifier_fp = certifier.fingerprint().to_hex();
            let target_fp = target.fingerprint().to_hex();
            let listed = certifications(&store, &store.lookup(&target_fp).unwrap()).unwrap();
            let row = listed
                .iter()
                .find(|c| {
                    !c.is_revocation && c.certifier_fingerprint.as_deref() == Some(&certifier_fp)
                })
                .unwrap();
            assert_eq!(row.standing, Some(expected), "{user_id}: {row:?}");
            assert!(
                !withdrawable(&listed).contains_key(&certifier_fp),
                "{user_id}: a certification that will never count was offered for withdrawal"
            );
            let refused = revoke_certification(
                &store,
                &certifier_fp,
                &target_fp,
                &[user_id.to_string()],
                Reason::Retired,
                "",
                None,
            )
            .map(|_| ())
            .map_err(|e| e.to_string());
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|e| e.contains("nothing to withdraw")),
                "{user_id}: {refused:?}"
            );
        }

        // A forgery dated an hour ahead, near enough that the key it names is
        // still valid then, is judged as the forgery it will still be.
        let other = key("Other <other@example.org>");
        let other_fp = other.fingerprint().to_hex();
        let other_id = "Other <other@example.org>";
        store.insert(&other).unwrap();
        plant(
            &store,
            &other,
            vec![damaged(by(
                &me,
                SignatureType::GenericCertification,
                in_an_hour,
                &other,
                other_id,
            ))],
        );
        let refused = revoke_certification(
            &store,
            &me.fingerprint().to_hex(),
            &other_fp,
            &[other_id.to_string()],
            Reason::Retired,
            "",
            None,
        )
        .map(|_| ())
        .map_err(|e| e.to_string());
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("nothing to withdraw")),
            "a forgery was taken for something to withdraw: {refused:?}"
        );

        let kept = key("Kept <kept@example.org>");
        store.insert_secret(&kept).unwrap();
        let kept_fp = kept.fingerprint().to_hex();
        let for_a_day = signed(
            &mut primary_signer(&kept),
            SignatureBuilder::new(SignatureType::GenericCertification)
                .set_signature_creation_time(in_an_hour)
                .unwrap()
                .set_signature_validity_period(Duration::from_secs(24 * 60 * 60))
                .unwrap(),
            &them,
            them_id,
        );
        let forged = damaged(by(
            &kept,
            SignatureType::CertificationRevocation,
            now + Duration::from_secs(5 * 365 * 24 * 60 * 60),
            &them,
            them_id,
        ));
        let stored = plant(&store, &them, vec![for_a_day, forged]);
        assert_eq!(
            stored
                .userids()
                .flat_map(|ua| ua.other_revocations())
                .filter(|s| crate::cert::issued_by(s, &kept))
                .count(),
            1,
            "the forged withdrawal must be on the certificate, or this proves nothing"
        );
        let listed = certifications(&store, &stored).unwrap();
        let row = listed
            .iter()
            .find(|c| !c.is_revocation && c.certifier_fingerprint.as_deref() == Some(&kept_fp))
            .unwrap();
        assert_eq!(
            row.standing,
            Some(Standing::NotYet),
            "a forged withdrawal moved the date it is judged at: {row:?}"
        );
        assert!(withdrawable(&listed).contains_key(&kept_fp));
    }

    /// GnuPG 1.x and 2.0 certified with SHA-1 unless told otherwise, and the
    /// standard policy has refused SHA-1 for a certification since 2013, so
    /// sequoia-wot counts none of them. The row gives that reason rather than a
    /// bare "does not count", and nothing is offered for withdrawal, as for
    /// anything else sequoia-wot does not count. A certification the policy
    /// refuses for something else, a critical notation it does not know, is
    /// not put down to its hash.
    #[test]
    fn a_certification_made_with_sha1_does_not_count_and_says_why() {
        use sequoia_openpgp::packet::signature::subpacket::NotationDataFlags;
        use sequoia_openpgp::types::HashAlgorithm;

        let (_dir, store) = scratch();
        // RFC 4880, since a version 6 signature cannot be made with SHA-1.
        let mut request = KeyGenRequest::new("Me <me@example.org>");
        request.standard = crate::keygen::Standard::Rfc4880;
        let me = generate(&request).unwrap().cert;
        let (carol, them) = (
            key("Carol <carol@example.org>"),
            key("Them <them@example.org>"),
        );
        store.insert_secret(&me).unwrap();
        store.insert_secret(&carol).unwrap();
        store.insert(&them).unwrap();
        let (me_fp, them_fp) = (me.fingerprint().to_hex(), them.fingerprint().to_hex());
        let user_id = "Them <them@example.org>";

        plant(
            &store,
            &them,
            vec![
                signed(
                    &mut primary_signer(&me),
                    SignatureBuilder::new(SignatureType::GenericCertification)
                        .set_hash_algo(HashAlgorithm::SHA1),
                    &them,
                    user_id,
                ),
                signed(
                    &mut primary_signer(&carol),
                    SignatureBuilder::new(SignatureType::GenericCertification)
                        .add_notation(
                            "unknown@example.org",
                            b"x",
                            NotationDataFlags::empty(),
                            true,
                        )
                        .unwrap(),
                    &them,
                    user_id,
                ),
            ],
        );

        let listed = certifications(&store, &store.lookup(&them_fp).unwrap()).unwrap();
        let by = |certifier: &Cert| -> Certification {
            listed
                .iter()
                .find(|c| {
                    c.certifier_fingerprint.as_deref() == Some(&certifier.fingerprint().to_hex())
                })
                .unwrap()
                .clone()
        };
        let mine = by(&me);
        assert_eq!(
            (mine.verified, mine.by_me),
            (Some(true), true),
            "the signature itself is sound: {mine:?}"
        );
        assert_eq!(mine.standing, Some(Standing::WeakHash), "{mine:?}");
        assert!(!mine.is_good());
        assert_eq!(
            under(&store, &me, &them, user_id),
            crate::Authentication::Unknown,
            "and sequoia-wot does not count it either"
        );
        let carols = by(&carol);
        assert_eq!(
            carols.standing,
            Some(Standing::Rejected),
            "a certification refused for a critical notation was put down to its hash: {carols:?}"
        );

        assert!(
            withdrawable(&listed).is_empty(),
            "a certification that does not count is not offered for withdrawal"
        );
        let refused = revoke_certification(
            &store,
            &me_fp,
            &them_fp,
            &[user_id.to_string()],
            Reason::Retired,
            "",
            None,
        )
        .map(|_| ())
        .map_err(|e| e.to_string());
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("nothing to withdraw")),
            "{refused:?}"
        );
    }

    /// A certification or a withdrawal that would have to be dated after one
    /// of the user's own signatures, itself dated too far ahead of the clock,
    /// is refused, naming that date, before the key is unlocked, like every
    /// other refusal of either. The date used to be settled once the key was
    /// unlocked, so the refusal cost a passphrase, or a PIN, first.
    #[test]
    fn a_date_too_far_ahead_is_refused_before_asking_for_a_passphrase() {
        let (_dir, store) = scratch();
        let mut request = KeyGenRequest::new("Me <me@example.org>");
        // RFC 4880, whose passphrase protection is quick to open.
        request.standard = crate::keygen::Standard::Rfc4880;
        request.password = Some("correct horse".to_string().into());
        let me = generate(&request).unwrap().cert;
        let them = key("Them <them@example.org>");
        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();
        let (me_fp, them_fp) = (me.fingerprint().to_hex(), them.fingerprint().to_hex());
        let user_id = "Them <them@example.org>";

        // The user's own certification, three days ahead.
        let mut signer = me
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .decrypt_secret(&"correct horse".into())
            .unwrap()
            .into_keypair()
            .unwrap();
        plant(
            &store,
            &them,
            vec![signed(
                &mut signer,
                SignatureBuilder::new(SignatureType::GenericCertification)
                    .set_signature_creation_time(
                        SystemTime::now() + Duration::from_secs(3 * 24 * 60 * 60),
                    )
                    .unwrap(),
                &them,
                user_id,
            )],
        );
        let signatures = || -> usize {
            store
                .lookup(&them_fp)
                .unwrap()
                .userids()
                .map(|ua| ua.certifications().count() + ua.other_revocations().count())
                .sum()
        };

        let mut request = CertifyRequest::new(&me_fp, &them_fp);
        request.user_ids = vec![user_id.to_string()];
        let certified = certify(&store, &request)
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert!(
            certified
                .as_ref()
                .is_err_and(|e| e.contains("ahead of this computer's clock")),
            "certifying must be refused with the date, before the key is unlocked: {certified:?}"
        );

        let withdrawn = revoke_certification(
            &store,
            &me_fp,
            &them_fp,
            &[user_id.to_string()],
            Reason::Retired,
            "",
            None,
        )
        .map(|_| ())
        .map_err(|e| e.to_string());
        assert!(
            withdrawn
                .as_ref()
                .is_err_and(|e| e.contains("ahead of this computer's clock")),
            "withdrawing must be refused with the date, before the key is unlocked: {withdrawn:?}"
        );
        assert_eq!(signatures(), 1, "a refusal must sign nothing");
    }
}
