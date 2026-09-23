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
use sequoia_openpgp::parse::{PacketParser, PacketParserResult, Parse};
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::types::{
    ReasonForRevocation, RevocationStatus, RevocationType, SignatureType,
};
use sequoia_openpgp::{Cert, Fingerprint, KeyHandle, Packet};

use crate::certify::Standing;
use crate::error::{Error, Result};
use crate::policy;
use crate::store::{CertRef, Store};
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

    /// The reason a key revocation's code reads as, hard exactly when sequoia
    /// holds the code hard.
    ///
    /// A code with no reason of its own here takes one that sequoia treats
    /// alike, since whether the reason read back is hard decides whether the
    /// details pane still offers a compromise to declare. The code meant for a
    /// user ID that is no longer valid is soft to sequoia on a key as well,
    /// and is read as a retirement. Read as Unspecified, it would be called
    /// hard, "treated as compromised", while every signature the key made
    /// before it went on verifying, and the details pane would offer nothing
    /// to take them back. Private and unknown codes are hard to sequoia, as
    /// Unspecified is.
    fn from_openpgp(reason: ReasonForRevocation) -> Self {
        match reason {
            ReasonForRevocation::KeySuperseded => Reason::Superseded,
            ReasonForRevocation::KeyCompromised => Reason::Compromised,
            ReasonForRevocation::KeyRetired | ReasonForRevocation::UIDRetired => Reason::Retired,
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
///
/// An already revoked certificate can be revoked again, which is how a key
/// retired with a soft reason is later marked compromised: the hard
/// revocation invalidates the signatures the soft one left standing, and
/// [`revocation_reason`] reports it ahead of the soft one.
///
/// [`Error::SecretKeyNotUpdated`] means the certificate is revoked, in the
/// public half every export reads, and the secret key file could not be
/// brought in step.
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

    apply(store, cert, vec![signature])
}

/// Retract certifications we previously made over `target`'s user IDs.
///
/// This does not touch the target's own self-signatures; it only withdraws our
/// opinion of them. Each user ID named must carry a certification by
/// `certifier` that still stands, or will once its date comes
/// ([`crate::certify::Standing::is_withdrawable`]), and the call is refused
/// otherwise; [`crate::certify::withdrawable`] says which do.
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
    // withdrawn from the app. Both halves of the store, as certify() reads them:
    // whether a certification still stands turns on the certifier's own
    // revocations, and one that reached cert-d alone, by import or refresh, is
    // one the web of trust already acts on.
    let certifier = store.full_cert(certifier)?;
    let target = store.lookup(target)?;

    // What there is to withdraw, settled before any key is unlocked, so that a
    // refusal never costs a passphrase or a PIN.
    let now = SystemTime::now();
    let mut withdrawing = Vec::new();
    for wanted in user_ids {
        // The mirror of certify()'s rule, which this path used to lack: the
        // first user ID whose lossy rendering matched was the one revoked, so a
        // withdrawal could be signed over a user ID this certifier never
        // certified while the real certification stood and the status bar said
        // it had been withdrawn. `cert::resolve_user_id` carries the reasoning.
        let amalgamation = crate::cert::resolve_user_id(&target, wanted)?;
        let verdicts = crate::certify::standing(&certifier, &target, &amalgamation, now);

        // Only a certification that stands, or will, is withdrawn. A user ID
        // on which nothing of this key's counts any more used to be signed over
        // all the same, so a certification already withdrawn was withdrawn
        // again, and a key with nothing left to withdraw was asked for its
        // passphrase ahead of the one that had.
        if !verdicts
            .iter()
            .any(|(_, standing)| standing.is_withdrawable())
        {
            return Err(Error::invalid(format!(
                "no certification {} made of {wanted} is in force, so there is nothing to withdraw",
                crate::certify::primary_user_id(&certifier),
            )));
        }

        // Publishable only if something it takes back was. A withdrawal of a
        // local certification used to be published regardless: export and
        // upload leave out only signatures marked non-exportable, and this one
        // was not marked, so it went out signed by the user over the very user
        // ID a local certification exists to keep quiet about, with its date and
        // its message. It retracts locally all the same, since sequoia-wot does
        // not ask whether a withdrawal is exportable.
        //
        // "Takes back" means what still counted on its own: the certification
        // that stands, or will once its date comes, and any it superseded,
        // since someone holding an older publishable certification but not the
        // local one that replaced it still counts the older one and needs the
        // withdrawal to see it retracted. A certification already withdrawn is
        // not among them, or an old published one would publish the withdrawal
        // of every local one made since; nor is one that counts nowhere,
        // expired or made by a subkey.
        let exportable = verdicts
            .iter()
            .filter(|(_, standing)| {
                matches!(
                    standing,
                    Standing::Stands | Standing::Superseded | Standing::NotYet
                )
            })
            .any(|(signature, _)| signature.exportable_certification().unwrap_or(true));

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
        // that merely names it: a planted packet dated in the far future would
        // otherwise date the withdrawal there, where it never takes effect, or
        // now have it refused. [`crate::certify::own_certifications`] carries
        // the reasoning, and certify() asks it on the mirror path.
        //
        // Dated here, with the rest of what is settled before any key is
        // unlocked: withdrawing a certification dated too far ahead, which is
        // offered like any that will count, is refused with its date, and that
        // refusal should cost no passphrase or PIN either.
        let when = crate::signature_time(crate::certify::own_certifications(
            &amalgamation,
            &target,
            &certifier,
        ))?;

        withdrawing.push((amalgamation, exportable, when));
    }

    let mut signer = certification_signer(&certifier, password)?;
    let mut signatures = Vec::new();
    for (amalgamation, exportable, when) in withdrawing {
        let userid = amalgamation.userid().clone();
        let mut builder = SignatureBuilder::new(SignatureType::CertificationRevocation)
            .set_signature_creation_time(when)?
            .set_reason_for_revocation(reason.to_openpgp(), message.as_bytes())?;
        // Marked only when local, so that a publishable withdrawal is the same
        // packet it always was.
        if !exportable {
            builder = builder.set_exportable_certification(false)?;
        }
        signatures.push(builder.sign_userid_binding(
            &mut *signer,
            target.primary_key().key(),
            &userid,
        )?);
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

/// A revocation of a whole certificate, read from a file and checked against
/// the certificate it revokes, and not yet stored.
///
/// Reading a revocation certificate and storing what it revokes are two
/// steps, [`read_revocation_file`] and [`apply_revocations`], so that what a
/// file would do can be put to the user before anything is written. The app
/// saves a revocation certificate for every key it generates, as a plain
/// public key block that the Import button takes, and storing it used to
/// follow straight from choosing it: one wrong file picked while restoring a
/// backup hard-revoked the user's own key, with no question asked. See
/// [`PendingRevocation::yours`].
#[derive(Debug, Clone)]
pub struct PendingRevocation {
    /// The certificate it revokes.
    pub fingerprint: String,
    /// The certificate's name: its primary user ID, or its fingerprint where
    /// it carries none.
    pub name: String,
    /// The reason the file gives, chosen from its revocations of this
    /// certificate by the rule [`revocation_reason`] reads a certificate by:
    /// the newest hard one, else the newest.
    pub reason: Reason,
    /// The note stored with that revocation, which may be empty.
    pub message: String,
    /// Whether the certificate is one of the user's own keys, which makes
    /// the file one to ask about first. [`read_revocation_file`] sets it where
    /// this store holds the secret key. Only the caller can know of one held
    /// elsewhere, by gpg-agent in its own store or on a card, and sets it for
    /// that too.
    pub yours: bool,
    /// Every revocation of it in the file, each already checked against it.
    signatures: Vec<Signature>,
}

impl PendingRevocation {
    /// This revocation's own reason and note, worded as the details pane words
    /// a revocation. Once it is stored the pane may still name another, where
    /// the key already carries one.
    pub fn describe(&self) -> String {
        crate::cert::describe_revocation(&(self.reason, self.message.clone()))
    }
}

/// What a revocation certificate holds, read and checked but not stored.
#[derive(Debug, Clone)]
pub struct RevocationFile {
    /// One entry per certificate in this store that the file revokes, in the
    /// order the file first revokes them.
    pub revocations: Vec<PendingRevocation>,
    /// Why each revocation in the file that revokes nothing here was set
    /// aside, one sentence each.
    pub refused: Vec<String>,
}

/// Read a revocation certificate and work out what it would revoke in this
/// store, without storing anything.
///
/// This is the emergency path: storing what it finds, with
/// [`apply_revocations`], needs no secret key and no passphrase, because each
/// signature was made when the revocation certificate was.
///
/// Every revocation of a whole key in the file is read, and each one that
/// verifies against a certificate here is kept. This used to stop at the
/// first that applied, so a file revoking two of a contact's keys revoked one
/// of them, and one holding a retirement and then a compromise of the same key
/// stored the retirement alone, which leaves standing every signature the key
/// made before it. A revocation authenticates itself, so taking every one lets
/// nobody revoke anything a file holding that one alone would not.
///
/// An error means the file is no revocation certificate at all. One holding
/// revocations of nothing here comes back with each of them in
/// [`RevocationFile::refused`], so that the caller can say why.
pub fn read_revocation_file(store: &Store, path: &Path) -> Result<RevocationFile> {
    let signatures = revocation_signatures(path)?;

    let mut targets: Vec<(Cert, Vec<Signature>)> = Vec::new();
    let mut refused = Vec::new();
    let mut designations = None;
    for signature in signatures {
        match target_of(store, &signature) {
            Ok(cert) => match targets
                .iter_mut()
                .find(|(target, _)| target.fingerprint() == cert.fingerprint())
            {
                Some((_, theirs)) if theirs.contains(&signature) => {}
                Some((_, theirs)) => theirs.push(signature),
                None => targets.push((cert, vec![signature])),
            },
            Err(e) => refused.push(
                designated_revoker(store, &signature, &mut designations)
                    .unwrap_or_else(|| e.to_string()),
            ),
        }
    }

    let revocations = targets
        .into_iter()
        .map(|(cert, signatures)| {
            let fingerprint = cert.fingerprint().to_hex();
            let (reason, message) =
                described(&cert, &signatures).unwrap_or((Reason::Unspecified, String::new()));
            PendingRevocation {
                name: name_of(&cert),
                yours: store.has_secret(&fingerprint),
                fingerprint,
                reason,
                message,
                signatures,
            }
        })
        .collect();
    Ok(RevocationFile {
        revocations,
        refused,
    })
}

/// Store the revocations [`read_revocation_file`] found, returning one result
/// for each, in the order given.
///
/// Each certificate is read again and each revocation checked again against
/// it, so what is stored is the certificate as it is now, with the
/// revocations that still count on it, rather than the copy the file was read
/// against. An [`Error::SecretKeyNotUpdated`] means that certificate is
/// revoked all the same; any other error means nothing was stored for it.
pub fn apply_revocations(store: &Store, revocations: &[PendingRevocation]) -> Vec<Result<Cert>> {
    revocations
        .iter()
        .map(|pending| {
            let cert = store.lookup(&pending.fingerprint)?;
            apply(store, cert, pending.signatures.clone())
        })
        .collect()
}

/// Every revocation of a whole key in the file at `path`.
fn revocation_signatures(path: &Path) -> Result<Vec<Signature>> {
    // Settled before reading rather than after: every signature in the file is
    // held at once, and this path takes a file somebody else made. The network
    // fetch has had a cap for the same reason since it was written; a file
    // simply arrives by a different road.
    //
    // The number is generous by three orders of magnitude, which is what makes
    // it safe to apply here. A revocation certificate is one signature — GnuPG
    // writes about seven hundred bytes. Nor is this the door a large keyring
    // comes through: `import_file` streams and handles those, and this is only
    // reached when that has already failed to find a single certificate in the
    // file.
    const MAX_REVOCATION: u64 = 1024 * 1024;
    if let Ok(metadata) = std::fs::metadata(path)
        && metadata.len() > MAX_REVOCATION
    {
        return Err(Error::invalid(format!(
            "{} is too large to be a revocation certificate",
            path.display()
        )));
    }

    // Armor block after armor block, as `CertParser` reads a keyring.
    // `PacketPile`, which this used, stops at the end of the first block, so
    // `cat a.rev b.rev`, the obvious way to hand someone two revocation
    // certificates, lost the second before anything looked at it. A packet
    // the first block cannot yield makes the file no OpenPGP file, as it did;
    // past that block, whatever will not parse is taken for the end, the way
    // the armor reader passes over text after a block's footer.
    let not_openpgp = || Error::invalid(format!("{} is not an OpenPGP file", path.display()));
    let mut signatures = Vec::new();
    let mut first_block = true;
    let mut parsed = PacketParser::from_file(path).map_err(|_| not_openpgp())?;
    loop {
        match parsed {
            PacketParserResult::Some(parser) => match parser.next() {
                Ok((packet, next)) => {
                    // Only a revocation of a whole key can revoke a
                    // certificate; a file of other signatures, a detached
                    // signature say, is not a revocation certificate at all.
                    if let Packet::Signature(signature) = packet
                        && signature.typ() == SignatureType::KeyRevocation
                    {
                        signatures.push(signature);
                    }
                    parsed = next;
                }
                Err(_) if first_block => return Err(not_openpgp()),
                Err(_) => break,
            },
            PacketParserResult::EOF(eof) => {
                first_block = false;
                match PacketParser::from_buffered_reader(eof.into_reader()) {
                    Ok(next @ PacketParserResult::Some(_)) => parsed = next,
                    _ => break,
                }
            }
        }
    }

    if signatures.is_empty() {
        return Err(Error::invalid(format!(
            "{} contains no revocation signature",
            path.display()
        )));
    }
    Ok(signatures)
}

/// The certificate in this store that `signature` revokes.
///
/// A key revokes only itself, and a revocation names the key that made it in
/// its issuer subpackets. Every name is tried, not only the first that
/// resolves, since a key ID can resolve to another certificate that shares it
/// or carries the key as a subkey; whether the revocation takes is what
/// decides.
fn target_of(store: &Store, signature: &Signature) -> Result<Cert> {
    let mut last = None;
    for handle in signature.get_issuers() {
        let Ok(cert) = store.lookup(&handle.to_string()) else {
            continue;
        };
        if revokes(&cert, signature) {
            return Ok(cert);
        }
        last = Some(Error::invalid(format!(
            "that signature does not revoke {}",
            cert.fingerprint().to_hex()
        )));
    }
    Err(last.unwrap_or_else(|| {
        Error::invalid("the revocation is for a certificate that is not in this store")
    }))
}

/// Whether `signature`, merged into `cert`, is among the revocations sequoia
/// counts on it; see [`apply`] for why the question is about this signature.
fn revokes(cert: &Cert, signature: &Signature) -> bool {
    cert.clone()
        .insert_packets(signature.clone())
        .is_ok_and(|(merged, _)| counted(&merged, signature))
}

/// Whether `cert`, which carries `signature`, counts it as revoking it.
fn counted(cert: &Cert, signature: &Signature) -> bool {
    match cert.revocation_status(&policy(), None) {
        RevocationStatus::Revoked(verified) => verified.contains(&signature),
        _ => false,
    }
}

/// The reason `signatures`, revocations of `cert`, give it, by the rule
/// [`revocation_reason`] reads a certificate by.
///
/// Read off `cert` with them merged in, in the order sequoia keeps them
/// there, which is the order the banner reads once they are stored. Sorted by
/// time alone, two made in the same second would keep the file's order, where
/// sequoia breaks the tie by the signatures' values, and the dialog could name
/// one reason and the banner, a moment later, another.
fn described(cert: &Cert, signatures: &[Signature]) -> Option<(Reason, String)> {
    let merged = cert.clone().insert_packets(signatures.to_vec()).ok()?.0;
    let RevocationStatus::Revoked(verified) = merged.revocation_status(&policy(), None) else {
        return None;
    };
    reported(
        verified
            .into_iter()
            .filter(|signature| signatures.contains(signature)),
    )
}

/// Why `signature` revokes nothing here, where it is a revocation of a
/// certificate in this store, made by a key that certificate designates to
/// revoke it.
///
/// A designated revoker's revocation of another key names only the revoker,
/// so it resolves to the revoker's own certificate, which it does not revoke,
/// and the refusal used to say only that, as if the file were for some other
/// key. Nor could it ever be applied where it belongs. Sequoia files a
/// revocation of a key made by any other key among the ones it does not
/// verify, and reports a certificate carrying one as one that could be
/// revoked, never as revoked; [`refuse_if_revoked`] says why that is not taken
/// as a revocation. Honouring one would take the revoker's certificate, the
/// designation on the target's own self-signature, a check of the revoker's
/// key as it stood when it signed, and then the same answer from every place
/// that asks whether a key is revoked, the list, the pickers and sequoia's
/// own key filters among them. RFC 9580 deprecates the designation, so this
/// says instead that such a revocation is not applied.
///
/// The certificate it names is one the signature is over, by [`over`], and
/// not merely one that designates its maker. One revoker designated on many
/// keys, an organisation's, is how the mechanism is meant to be used, so a
/// certificate found to designate the maker need not be the one the
/// revocation is for, and the revoker's revocation of its own key, which
/// names the same maker, is for none of them. Where more than one passes,
/// which only a coincidence in the two bytes compared when the revoker's key
/// is not here allows, each is named; where none does, the caller's plain
/// refusal stands.
///
/// The store is read for designations once per file, and only once one of its
/// revocations has been refused.
fn designated_revoker(
    store: &Store,
    signature: &Signature,
    designations: &mut Option<Vec<(Fingerprint, CertRef)>>,
) -> Option<String> {
    let designations = designations.get_or_insert_with(|| {
        let policy = policy();
        let Ok(certs) = store.certs() else {
            return Vec::new();
        };
        certs
            .iter()
            .flat_map(|cert| {
                cert.revocation_keys(&policy)
                    .map(|key| (key.revoker().1.clone(), cert.clone()))
                    .collect::<Vec<_>>()
            })
            .collect()
    });

    let issuers = signature.get_issuers();
    let mut targets: Vec<(&Fingerprint, &CertRef)> = Vec::new();
    for (revoker, target) in designations.iter() {
        let named = issuers
            .iter()
            .any(|issuer| KeyHandle::from(revoker).aliases(issuer));
        if named
            && !targets
                .iter()
                .any(|(_, seen)| seen.fingerprint() == target.fingerprint())
            && over(store, signature, revoker, target)
        {
            targets.push((revoker, target));
        }
    }

    let (revoker, _) = targets.first()?;
    let revoker = store
        .lookup(&revoker.to_hex())
        .map_or_else(|_| revoker.to_hex(), |cert| name_of(&cert));
    let names: Vec<String> = targets.iter().map(|(_, target)| name_of(target)).collect();
    let (named, verb, whose) = match names.as_slice() {
        [target] => (target.clone(), "was", target.clone()),
        several => (several.join(" and "), "were", "each of them".to_string()),
    };
    Some(format!(
        "{named} {verb} not revoked: the revocation names {revoker} as its maker, a key \
         {whose} designates to revoke it, and rPGP does not apply revocations by \
         designated revokers"
    ))
}

/// Whether `signature` is a revocation of `target`'s primary key made by
/// `revoker`, as far as this store can tell.
///
/// Where the store holds the revoker's key, the signature is verified. Where
/// it does not, the two bytes of its hash a signature carries in the clear are
/// compared with the hash over `target`'s key, which is the test sequoia makes
/// before it keeps a revocation by another key with a certificate: a
/// signature over some other key passes it once in 65,536 times.
fn over(store: &Store, signature: &Signature, revoker: &Fingerprint, target: &Cert) -> bool {
    let primary = target.primary_key().key();
    let mut held = false;
    for cert in store.lookup_all(&revoker.to_hex()).unwrap_or_default() {
        for key in cert.keys().key_handle(revoker.clone()) {
            held = true;
            if signature
                .verify_primary_key_revocation(key.key(), primary)
                .is_ok()
            {
                return true;
            }
        }
    }
    !held
        && signature
            .hash_algo()
            .context()
            .and_then(|hash| {
                let mut hash = hash.for_signature(signature.version());
                signature.hash_direct_key(&mut hash, primary)?;
                hash.into_digest()
            })
            .is_ok_and(|digest| digest.starts_with(signature.digest_prefix()))
}

/// What Import should add to its status line about `imported`, when any of
/// them carries a revocation naming as its maker a key it designates to revoke
/// it.
///
/// A revocation GnuPG's `--desig-revoke` writes arrives with the certificate
/// it revokes, so Import takes the file as a certificate like any other and
/// stores the revocation with it, where it is not applied. It went unmentioned
/// while the key went on showing as valid under a status line that said only
/// that it had been imported. The signature is not verified here: sequoia
/// keeps a revocation by another key with a certificate once the two bytes of
/// its hash carried in the clear match, the test [`over`] falls back on, and
/// this goes by that and by the maker the packet names.
pub fn designated_revocations_note(imported: &[Cert]) -> Option<String> {
    let carrying: Vec<String> = imported
        .iter()
        .filter(|cert| carries_designated_revocation(cert))
        .map(name_of)
        .collect();
    if carrying.is_empty() {
        return None;
    }
    Some(format!(
        "{} {} a revocation naming a key it designates to revoke it, which rPGP does not \
         apply.",
        carrying.join(", "),
        if carrying.len() == 1 {
            "carries"
        } else {
            "carry"
        },
    ))
}

/// Whether a revocation `cert` carries names as its maker a key `cert`
/// designates to revoke it.
fn carries_designated_revocation(cert: &Cert) -> bool {
    let revokers: Vec<KeyHandle> = cert
        .revocation_keys(&policy())
        .map(|key| KeyHandle::from(key.revoker().1))
        .collect();
    cert.primary_key()
        .other_revocations()
        .filter(|signature| signature.typ() == SignatureType::KeyRevocation)
        .flat_map(|signature| signature.get_issuers())
        .any(|issuer| revokers.iter().any(|revoker| revoker.aliases(&issuer)))
}

/// Merge into `cert` those of `signatures` that really do revoke it, and
/// store.
///
/// An error means none of them does, or nothing was stored, except for an
/// [`Error::SecretKeyNotUpdated`], which comes back once the revocation is in
/// cert-d.
fn apply(store: &Store, cert: Cert, signatures: Vec<Signature>) -> Result<Cert> {
    let fingerprint = cert.fingerprint().to_hex();

    // Guard against silently storing a signature that changed nothing — a
    // revocation from the wrong key, or one the policy rejects.
    //
    // The test is whether *these* signatures were accepted, not whether the
    // certificate ends up revoked. Sequoia computes revocation_status from the
    // revocations it has already verified, so on a certificate that was
    // revoked before this call the status is Revoked whatever we just inserted
    // — the guard passed on its own history and wrote an arbitrary signature
    // packet into the secret key file. Asking whether the returned set
    // contains each signature keeps the verification sequoia already did.
    //
    // Each is judged on its own, as sequoia judges them, and one that does not
    // count is left out rather than failing the rest. Import reads a file
    // before the user confirms it, and a revocation can stop counting in
    // between: a newer self-signature, from a lookup say, overrides a soft
    // revocation older than it. Refusing the whole file's worth would refuse
    // the hard revocation beside it too, which is the one that matters and
    // which nothing overrides. What is left out goes unreported, since
    // storing it would have changed nothing.
    let merged = cert.clone().insert_packets(signatures.clone())?.0;
    let signatures: Vec<Signature> = signatures
        .into_iter()
        .filter(|signature| counted(&merged, signature))
        .collect();
    if signatures.is_empty() {
        return Err(Error::invalid(format!(
            "that signature does not revoke {fingerprint}"
        )));
    }
    let revoked = cert.insert_packets(signatures.clone())?.0;

    store.insert(&revoked)?;

    // Keep the secret copy in step, since it is the key's whole copy: what the
    // lifecycle operations start from, and what a backup of the key holds. The
    // signatures have to be merged into the *secret* certificate: `revoked`
    // may have come from cert-d, which only ever holds the public half.
    //
    // The revocation is stored by now, so nothing past this point can make it
    // a revocation that was not made. A secret key file that will not read
    // used to fail the whole call here, after the write above, and it is the
    // very case the emergency path serves: every attempt was reported as
    // failed, with a reason about something else, while cert-d showed the key
    // revoked. The file is left as it is for the damaged-file survey to go on
    // reporting, since nothing can be merged into it.
    if store.has_secret(&fingerprint) {
        let updated = store
            .secret_cert(&fingerprint)
            .map_err(|e| match e {
                Error::NoSecretKey(_) => e,
                e => Error::invalid(format!("the secret key file will not read ({e})")),
            })
            .and_then(|secret| store.insert_secret(&secret.insert_packets(signatures)?.0));
        match updated {
            Ok(()) => {}
            // Deleted since `has_secret` looked, so there is no copy left to
            // keep in step.
            Err(Error::NoSecretKey(_)) => {}
            // The secret key file took the revocation, and cert-d then
            // refused the public half insert_secret merges into it, which
            // already carries the revocation from the write above.
            Err(Error::PublicCertNotUpdated(_)) => {}
            Err(e) => return Err(Error::SecretKeyNotUpdated(Box::new(e))),
        }
    }
    Ok(revoked)
}

/// Why a certificate was revoked, if it was.
pub fn revocation_reason(cert: &Cert) -> Option<(Reason, String)> {
    let RevocationStatus::Revoked(signatures) = cert.revocation_status(&policy(), None) else {
        return None;
    };
    reported(signatures)
}

/// The reason a banner gives for `newest_first`, a certificate's revocations
/// in that order, and the note that goes with it.
///
/// A hard revocation stays in force whatever follows it, because nothing
/// undoes one. Reporting the newest would let a KeyRetired — which anyone
/// holding the stolen secret can issue — hide a KeyCompromised behind "No
/// longer used", so prefer the newest hard revocation and fall back to the
/// newest of any kind. A revocation carrying no reason subpacket is hard (RFC
/// 9580 §5.2.3.31), which is also why the reason-less case reports
/// Unspecified rather than blanking the banner: returning None here left the
/// certificate looking unrevoked.
fn reported<'a>(newest_first: impl IntoIterator<Item = &'a Signature>) -> Option<(Reason, String)> {
    let signatures: Vec<&Signature> = newest_first.into_iter().collect();
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

/// The name to give `cert` in a sentence: its primary user ID, or its
/// fingerprint where it carries none.
///
/// A certificate need carry no user ID at all — nothing on the import path
/// asks for one — and for such a certificate `primary_user_id` answers "(no
/// user ID)", which names nothing in a status bar or a dialog that has room
/// for one identifier. The fingerprint is what the rest of the crate falls
/// back to when there is no name, as `Error::NoSecretKey` does.
fn name_of(cert: &Cert) -> String {
    match cert.userids().next() {
        Some(_) => {
            crate::cert::primary_user_id(cert, cert.with_policy(&policy(), None).ok().as_ref())
        }
        None => cert.fingerprint().to_hex(),
    }
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
    let name = name_of(cert);
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

/// A signer for [`revoke_certification`]: the certificate's primary key,
/// whatever has happened to the certificate since.
///
/// Deliberately does not ask [`refuse_if_revoked`], and takes the agent's
/// withdrawal entry point rather than `certifier_for` so that the agent does
/// not ask on its behalf either. Retracting a certification is taking back
/// something already said, not making new use of the key, and someone who has
/// just revoked their own certificate is exactly the person who may now want to
/// withdraw what it vouched for.
///
/// Nor is the key filtered as a key to make something new with would be. It
/// used to be picked by `alive().revoked(false)`, and for a primary key both of
/// those ask about the whole certificate, so once a key had expired or been
/// retired its secret was passed over as if it were not there, the agent was
/// asked instead, and the withdrawal failed saying there was no usable secret
/// key — while every certification the key had made before then went on
/// counting, since sequoia-wot judges an issuer as it stood when it certified.
/// A withdrawal is checked against the certifier's primary key and nothing
/// about the certifier's state now, so the primary signs it and it takes
/// effect. The primary, and not the first key that can certify: sequoia-wot
/// looks for a withdrawal from the primary key alone, so one a subkey signed
/// withdraws nothing.
///
/// A local secret that is only a GnuPG stub goes to the agent, as a card key
/// does, and so does one whose algorithm this build cannot use, as certify()
/// already sends it there: the agent does the arithmetic, not this build.
fn certification_signer(
    cert: &Cert,
    password: Option<&str>,
) -> Result<Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync>> {
    let local = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .ok()
        .filter(|key| key.pk_algo().is_supported() && crate::secret::is_usable(key.secret()));

    // No usable local secret means a card key: hand the agent the certificate
    // and let it find the primary by keygrip, as certify() does — but through
    // the withdrawal entry point, which alone among the agent's signing paths
    // neither refuses a revoked certificate nor passes over an expired key.
    match local {
        // Keeps its primary role: an RFC 9580 secret cannot be decrypted
        // without it. See crate::secret::unlock.
        Some(key) => crate::secret::signer(key, password),
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

        let outcome = apply(&store, revoked, vec![foreign]);
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

    /// Every reason code a key revocation can carry reads back as a reason
    /// exactly as hard as sequoia holds the code, since the details pane goes
    /// by that to decide whether a compromise is still to be declared.
    #[test]
    fn every_revocation_code_reads_back_as_hard_as_sequoia_holds_it() {
        for code in (0..=u8::MAX).map(ReasonForRevocation::from) {
            assert_eq!(
                Reason::from_openpgp(code).is_hard(),
                code.revocation_type() == RevocationType::Hard,
                "{code:?} reads back as {:?}",
                Reason::from_openpgp(code)
            );
        }
    }

    /// A key revoked with the code meant for a user ID, which sequoia holds
    /// soft on a key as well, is described as soft both by the summary the
    /// details pane goes by and by what Import puts to the user, so that the
    /// pane goes on offering a compromise to declare.
    #[test]
    fn a_key_revoked_with_a_code_sequoia_holds_soft_is_not_called_hard() {
        let (dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert(&mine).unwrap();
        let mut signer = primary_signer(&mine, None).unwrap();
        let revocation = CertRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"left that job")
            .unwrap()
            .build(&mut signer, &mine, None)
            .unwrap();

        let path = dir.path().join("mine.rev");
        write_revocations(&path, &[&revocation]);
        let file = read_revocation_file(&store, &path).unwrap();
        let [pending] = file.revocations.as_slice() else {
            panic!("expected one certificate revoked: {:?}", file.refused);
        };
        assert!(
            !pending.reason.is_hard(),
            "Import would call it hard: {}",
            pending.describe()
        );

        let revoked = mine.insert_packets(revocation).unwrap().0;
        let summary = CertSummary::from_cert(&revoked);
        assert_eq!(summary.validity, Validity::Revoked);
        assert!(
            !summary.revocation_hard,
            "the details pane would call it hard: {:?}",
            summary.revocation
        );
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

    /// Every certificate `path` revokes here, read and stored in one go, as
    /// Import does for a file that revokes none of the user's own keys.
    fn apply_file(store: &Store, path: &Path) -> Result<Vec<Cert>> {
        let file = read_revocation_file(store, path)?;
        apply_revocations(store, &file.revocations)
            .into_iter()
            .collect()
    }

    /// Whether the certificate cert-d holds for `fingerprint` is revoked.
    fn revoked_in_cert_d(store: &Store, fingerprint: &str) -> bool {
        CertSummary::from_cert(&store.lookup(fingerprint).unwrap()).validity == Validity::Revoked
    }

    /// The emergency path needs no passphrase, and is two steps. Reading the
    /// file stores nothing, and says what storing it would do: revoke a key
    /// whose secret this store holds, hard, since the certificate made at
    /// generation gives no reason. Reading and storing used to be one call,
    /// made as soon as Import was handed the file, so there was no moment at
    /// which to ask whether the user meant to revoke their own key.
    ///
    /// Make reading store what it reads and this fails.
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

        let path = store.revocation_path(&fingerprint);
        let file = read_revocation_file(&store, &path).unwrap();
        assert!(file.refused.is_empty(), "{:?}", file.refused);
        let [pending] = file.revocations.as_slice() else {
            panic!("expected one certificate revoked: {:?}", file.revocations);
        };
        assert_eq!(pending.fingerprint, fingerprint);
        assert_eq!(pending.name, "Me <me@example.org>");
        assert!(pending.yours, "it is the user's own key");
        assert!(pending.reason.is_hard(), "{:?}", pending.reason);
        for (half, cert) in [
            ("cert-d", store.lookup(&fingerprint).unwrap()),
            (
                "the secret key file",
                store.secret_cert(&fingerprint).unwrap(),
            ),
        ] {
            assert_eq!(
                CertSummary::from_cert(&cert).validity,
                Validity::Valid,
                "reading the file stored its revocation in {half}"
            );
        }

        // Revoking normally would need the passphrase; the stored certificate
        // was signed at generation time and needs nothing.
        let revoked = apply_revocations(&store, &file.revocations)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(CertSummary::from_cert(&revoked).validity, Validity::Revoked);
        assert_eq!(
            CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap()).validity,
            Validity::Revoked
        );
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

        let err = read_revocation_file(&store, &path)
            .map(|_| ())
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
    /// the mirror path, and has a test of its own for it.
    ///
    /// Delete the `verify_userid_binding` filter in
    /// `certify::own_certifications` and this fails: the planted packet would
    /// date the withdrawal five years out, which is now refused, so the
    /// withdrawal the user asked for is not made at all.
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

    /// How `user_id` on `target` authenticates with `root` as the only trust
    /// root.
    fn under(store: &Store, root: &Cert, target: &Cert, user_id: &str) -> crate::Authentication {
        let certs = store.certs().unwrap();
        wot::for_user_id(
            &wot::authenticate_all(&certs, &[root.fingerprint().to_hex()]),
            &target.fingerprint().to_hex(),
            user_id,
        )
    }

    /// `certifier`'s certification of `user_id` on `target`, dated `when`, as
    /// something other than certify() made it: certify() dates by the clock,
    /// and these tests need a certification older than what follows it.
    ///
    /// Signed with the primary key's secret directly, not through
    /// [`certification_signer`], which is what these tests are about: a
    /// regression there has to fail on the withdrawal it breaks, not while the
    /// certification to withdraw is being set up.
    fn certified_at(
        store: &Store,
        certifier: &Cert,
        target: &Cert,
        user_id: &str,
        when: SystemTime,
    ) {
        let userid = target
            .userids()
            .find(|ua| ua.userid().value() == user_id.as_bytes())
            .unwrap()
            .userid()
            .clone();
        let mut signer = certifier
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let certification = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_signature_creation_time(when)
            .unwrap()
            .sign_userid_binding(&mut signer, target.primary_key().key(), &userid)
            .unwrap();
        store
            .insert(
                &target
                    .clone()
                    .insert_packets(vec![certification])
                    .unwrap()
                    .0,
            )
            .unwrap();
    }

    fn withdraw(store: &Store, certifier: &Cert, target: &Cert, user_id: &str) -> Result<Cert> {
        revoke_certification(
            store,
            &certifier.fingerprint().to_hex(),
            &target.fingerprint().to_hex(),
            &[user_id.to_string()],
            Reason::Retired,
            "",
            None,
        )
    }

    /// A certification already withdrawn is not withdrawn again. It used to
    /// be: every certification a key had ever made on the user ID was signed
    /// over again, so the key was unlocked, or its card asked for its PIN, to
    /// write a revocation that changed nothing — and the GUI, handing over
    /// every key that had ever certified, stopped at such a key before it
    /// reached the one whose certification still stood.
    #[test]
    fn withdrawing_what_is_already_withdrawn_is_refused_rather_than_signed_again() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();
        let user_id = "Them <them@example.org>";

        let mut request =
            CertifyRequest::new(me.fingerprint().to_hex(), them.fingerprint().to_hex());
        request.user_ids = vec![user_id.to_string()];
        certify(&store, &request).unwrap();
        withdraw(&store, &me, &them, user_id).unwrap();

        let refused = withdraw(&store, &me, &them, user_id)
            .map(|_| ())
            .expect_err("withdrew a certification that was already withdrawn");
        assert!(
            refused.to_string().contains("nothing to withdraw"),
            "the refusal must say why: {refused}"
        );
        let revocations = store
            .lookup(&them.fingerprint().to_hex())
            .unwrap()
            .userids()
            .map(|ua| ua.other_revocations().count())
            .sum::<usize>();
        assert_eq!(revocations, 1, "a refused withdrawal must sign nothing");
    }

    /// A certification made before its certifier's key was retired, or before
    /// it expired, goes on counting, because sequoia-wot judges a certifier as
    /// it stood when it certified. So it has to stay withdrawable. The
    /// withdrawal used to pick its key with the filter for making new
    /// signatures, which for a primary key asks about the whole certificate:
    /// the retired or expired key's secret was passed over as absent, and the
    /// withdrawal failed saying there was no usable secret key, while the
    /// certification it was asked to take back went on counting.
    #[test]
    fn a_certification_can_be_withdrawn_after_the_certifiers_key_is_retired_or_expired() {
        let (_dir, store) = scratch();

        // Retired: certified half a minute ago, so the retirement is
        // certainly later and the certification counts on past it.
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        let user_id = "Them <them@example.org>";
        certified_at(
            &store,
            &me,
            &them,
            user_id,
            SystemTime::now() - Duration::from_secs(30),
        );
        let mut request = RevokeRequest::new(me.fingerprint().to_hex());
        request.reason = Reason::Superseded;
        revoke_cert(&store, &request).unwrap();
        assert_eq!(
            under(&store, &me, &them, user_id),
            crate::Authentication::Full,
            "a certification made before a soft revocation still counts"
        );
        withdraw(&store, &me, &them, user_id)
            .expect("a retired key must still be able to withdraw what it said");
        assert_eq!(
            under(&store, &me, &them, user_id),
            crate::Authentication::Unknown
        );

        // Expired: a key made two hours ago to last one, which certified while
        // it was alive.
        let two_hours_ago = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
        let (old, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Old <old@example.org>")
            .set_creation_time(two_hours_ago)
            .set_validity_period(Duration::from_secs(60 * 60))
            .generate()
            .unwrap();
        let (then, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Then <then@example.org>")
            .set_creation_time(two_hours_ago)
            .generate()
            .unwrap();
        store.insert_secret(&old).unwrap();
        let user_id = "Then <then@example.org>";
        certified_at(
            &store,
            &old,
            &then,
            user_id,
            two_hours_ago + Duration::from_secs(30 * 60),
        );
        assert_eq!(
            CertSummary::from_cert(&store.lookup(&old.fingerprint().to_hex()).unwrap()).validity,
            Validity::Expired
        );
        assert_eq!(
            under(&store, &old, &then, user_id),
            crate::Authentication::Full,
            "a certification made while its key was alive still counts"
        );
        withdraw(&store, &old, &then, user_id)
            .expect("an expired key must still be able to withdraw what it said");
        assert_eq!(
            under(&store, &old, &then, user_id),
            crate::Authentication::Unknown
        );
    }

    /// What a withdrawal can be refused for is settled before the certifier's
    /// key is unlocked: a user ID with nothing of the key's in force, and a
    /// name two user IDs display alike. The key has a passphrase here and none
    /// is given, so a refusal made after unlocking would read as the missing
    /// passphrase instead. Both used to come after the unlock.
    #[test]
    fn withdrawing_refuses_before_asking_for_a_passphrase() {
        use sequoia_openpgp::packet::UserID;

        let (_dir, store) = scratch();
        let mut request = KeyGenRequest::new("Me <me@example.org>");
        // RFC 4880, whose passphrase protection is quick to open.
        request.standard = crate::keygen::Standard::Rfc4880;
        request.password = Some("correct horse".to_string().into());
        let me = generate(&request).unwrap().cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;

        // Two user IDs whose invalid bytes differ and display alike.
        let twin = |byte: u8| [b"Twin <twin@".as_slice(), &[byte], b".example>"].concat();
        let mut signer = them
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let mut packets = Vec::new();
        for byte in [0xFEu8, 0xFF] {
            let userid = UserID::from(twin(byte));
            let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
                .sign_userid_binding(&mut signer, them.primary_key().key(), &userid)
                .unwrap();
            packets.push(Packet::from(userid));
            packets.push(Packet::from(binding));
        }
        let them = them.insert_packets(packets).unwrap().0;
        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();
        let displayed = String::from_utf8_lossy(&twin(0xFE)).into_owned();

        for (user_id, why) in [
            ("Them <them@example.org>", "nothing to withdraw"),
            (displayed.as_str(), "more than one user ID"),
        ] {
            let refused = withdraw(&store, &me, &them, user_id)
                .map(|_| ())
                .map_err(|e| e.to_string());
            assert!(
                refused.as_ref().is_err_and(|e| e.contains(why)),
                "withdrawing {user_id} must be refused, before the key is unlocked, saying why: {refused:?}"
            );
        }
    }

    /// Whether a certification still stands turns on its certifier's own
    /// revocations, and a revocation met here by import or by a keyserver
    /// refresh reaches cert-d alone: the secret half, which the withdrawal
    /// signs with, still looks live. The listing, like sequoia-wot, reads
    /// cert-d and counts nothing a key declared compromised has said, so it
    /// offers nothing to withdraw; the withdrawal has to judge by the same
    /// certificate, or it signs a revocation of a certification that no longer
    /// counts anywhere.
    #[test]
    fn withdrawing_sees_a_compromise_of_the_certifiers_key_that_reached_only_cert_d() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        let (me_fp, them_fp) = (me.fingerprint().to_hex(), them.fingerprint().to_hex());
        let user_id = "Them <them@example.org>";
        certified_at(
            &store,
            &me,
            &them,
            user_id,
            SystemTime::now() - Duration::from_secs(30),
        );

        // Declared compromised where the key also lives, and met here as the
        // public certificate, which is all `insert` ever writes.
        let elsewhere_dir = tempfile::tempdir().unwrap();
        let elsewhere = Store::open(
            elsewhere_dir.path().join("certs.d"),
            elsewhere_dir.path().join("secrets"),
        )
        .unwrap();
        elsewhere.insert_secret(&me).unwrap();
        let mut request = RevokeRequest::new(&me_fp);
        request.reason = Reason::Compromised;
        revoke_cert(&elsewhere, &request).unwrap();
        store.insert(&elsewhere.lookup(&me_fp).unwrap()).unwrap();
        assert!(
            !matches!(
                store
                    .secret_cert(&me_fp)
                    .unwrap()
                    .revocation_status(&policy(), None),
                RevocationStatus::Revoked(_)
            ),
            "the secret half not knowing is the premise of this test"
        );

        let listed =
            crate::certify::certifications(&store, &store.lookup(&them_fp).unwrap()).unwrap();
        assert!(
            crate::certify::withdrawable(&listed).is_empty(),
            "the listing reads cert-d, and offers nothing to withdraw"
        );
        let refused = withdraw(&store, &me, &them, user_id)
            .map(|_| ())
            .expect_err("withdrew a certification its key's compromise had already taken back");
        assert!(
            refused.to_string().contains("nothing to withdraw"),
            "the refusal must say why: {refused}"
        );
        assert_eq!(
            withdrawals_on(&store.lookup(&them_fp).unwrap()),
            0,
            "a refused withdrawal must sign nothing"
        );
    }

    /// `fingerprint` as `export_file` writes it, read back.
    fn exported(store: &Store, fingerprint: &str) -> Cert {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exported.asc");
        store
            .export_file(std::slice::from_ref(&fingerprint.to_string()), &path)
            .unwrap();
        Cert::from_file(&path).unwrap()
    }

    fn withdrawals_on(cert: &Cert) -> usize {
        cert.userids()
            .map(|ua| ua.other_revocations().count())
            .sum()
    }

    /// The withdrawal of a local certification is as local as the
    /// certification. It used to be publishable whatever it withdrew: export
    /// and upload leave out only signatures marked non-exportable, so the
    /// certification stayed home while its withdrawal went out, signed by the
    /// user over the very user ID a local certification exists to keep quiet
    /// about, with its date and its message. A publishable certification's
    /// withdrawal still goes out, since whoever has the certification needs it.
    #[test]
    fn withdrawing_a_local_certification_publishes_nothing() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let quiet = generate(&KeyGenRequest::new("Quiet <quiet@example.org>"))
            .unwrap()
            .cert;
        let open = generate(&KeyGenRequest::new("Open <open@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&quiet).unwrap();
        store.insert(&open).unwrap();

        for (target, user_id, exportable) in [
            (&quiet, "Quiet <quiet@example.org>", false),
            (&open, "Open <open@example.org>", true),
        ] {
            let mut request =
                CertifyRequest::new(me.fingerprint().to_hex(), target.fingerprint().to_hex());
            request.user_ids = vec![user_id.to_string()];
            request.exportable = exportable;
            certify(&store, &request).unwrap();
            withdraw(&store, &me, target, user_id).unwrap();
            assert_eq!(
                under(&store, &me, target, user_id),
                crate::Authentication::Unknown,
                "the withdrawal must take effect here, local or not"
            );
        }

        let (quiet_fp, open_fp) = (quiet.fingerprint().to_hex(), open.fingerprint().to_hex());
        assert_eq!(withdrawals_on(&store.lookup(&quiet_fp).unwrap()), 1);
        assert_eq!(
            withdrawals_on(&exported(&store, &quiet_fp)),
            0,
            "the withdrawal of a local certification was exported"
        );
        assert_eq!(
            withdrawals_on(&exported(&store, &open_fp)),
            1,
            "the withdrawal of a publishable certification must go with it"
        );
    }

    /// Publishable when anything it takes back was. A publishable
    /// certification the user then changed to a local one is still out there,
    /// and whoever holds it but not the local one counts it, so the
    /// withdrawal that follows must reach them. But a publishable
    /// certification already withdrawn, publicly, makes no later withdrawal of
    /// a local one publishable: that would announce the local one.
    #[test]
    fn a_withdrawal_is_publishable_while_anything_it_takes_back_was() {
        let (_dir, store) = scratch();
        let me = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        let them = generate(&KeyGenRequest::new("Them <them@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();
        let them_fp = them.fingerprint().to_hex();
        let user_id = "Them <them@example.org>";
        let mut request = CertifyRequest::new(me.fingerprint().to_hex(), &them_fp);
        request.user_ids = vec![user_id.to_string()];

        certify(&store, &request).unwrap();
        request.exportable = false;
        certify(&store, &request).unwrap();
        withdraw(&store, &me, &them, user_id).unwrap();
        assert_eq!(
            withdrawals_on(&exported(&store, &them_fp)),
            1,
            "the publishable certification the local one replaced needs its withdrawal published"
        );

        certify(&store, &request).unwrap();
        withdraw(&store, &me, &them, user_id).unwrap();
        assert_eq!(withdrawals_on(&store.lookup(&them_fp).unwrap()), 2);
        assert_eq!(
            withdrawals_on(&exported(&store, &them_fp)),
            1,
            "a withdrawal that takes back only a local certification was exported"
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

        let file = read_revocation_file(&store, &path).unwrap();
        assert!(file.revocations.is_empty(), "{:?}", file.revocations);
        assert_eq!(
            file.refused,
            ["the revocation is for a certificate that is not in this store"]
        );
        assert_eq!(
            CertSummary::from_cert(&store.lookup(&mine.fingerprint().to_hex()).unwrap()).validity,
            Validity::Valid
        );
    }

    /// `signatures`, armored as one block, as a file at `path`.
    fn write_revocations(path: &Path, signatures: &[&Signature]) {
        let mut writer = sequoia_openpgp::armor::Writer::new(
            Vec::new(),
            sequoia_openpgp::armor::Kind::PublicKey,
        )
        .unwrap();
        for signature in signatures {
            Packet::from((*signature).clone())
                .serialize(&mut writer)
                .unwrap();
        }
        std::fs::write(path, writer.finalize().unwrap()).unwrap();
    }

    /// A contact's revocations of both their old keys, in one file, revoke
    /// both. Only the first that applied used to be stored: the second key
    /// stayed valid, and in use, while the status line named the first.
    #[test]
    fn every_revocation_in_a_file_is_applied() {
        let (dir, store) = scratch();
        let old = generate(&KeyGenRequest::new("Old <old@example.org>")).unwrap();
        let older = generate(&KeyGenRequest::new("Older <older@example.org>")).unwrap();
        store.insert(&old.cert).unwrap();
        store.insert(&older.cert).unwrap();
        let path = dir.path().join("both.asc");
        write_revocations(&path, &[&old.revocation, &older.revocation]);

        let revoked = apply_file(&store, &path).unwrap();
        assert_eq!(revoked.len(), 2);
        for cert in [&old.cert, &older.cert] {
            assert!(
                revoked_in_cert_d(&store, &cert.fingerprint().to_hex()),
                "a revocation in the file was not applied"
            );
        }
    }

    /// Two revocation certificates, one after the other in a file, are both
    /// read, which is what `cat a.rev b.rev` makes. The first armor block used
    /// to be the whole of what was read, so the second was lost before any
    /// signature in it was looked at. Text after the last block is passed
    /// over, as the armor reader passes over it after the first.
    #[test]
    fn revocations_in_armor_blocks_one_after_another_are_all_read() {
        let (dir, store) = scratch();
        let first = generate(&KeyGenRequest::new("First <first@example.org>")).unwrap();
        let second = generate(&KeyGenRequest::new("Second <second@example.org>")).unwrap();
        store.insert(&first.cert).unwrap();
        store.insert(&second.cert).unwrap();

        let mut concatenated = armor(&first.revocation).unwrap();
        concatenated.extend(armor(&second.revocation).unwrap());
        concatenated.extend(b"\nSent from a phone\n");
        let path = dir.path().join("concatenated.asc");
        std::fs::write(&path, &concatenated).unwrap();

        let file = read_revocation_file(&store, &path).unwrap();
        let names: Vec<&str> = file
            .revocations
            .iter()
            .map(|pending| pending.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["First <first@example.org>", "Second <second@example.org>"],
            "every armor block in the file should be read"
        );
    }

    /// A retirement and a compromise of one key, in one file, are both
    /// stored, and the key reads as compromised. Only the retirement used to
    /// be, as the first signature in the file: the banner said "No longer
    /// used", and every signature the key made before it stood, whoever made
    /// it. Checking that the key is revoked would not show that; checking what
    /// it is revoked for does.
    #[test]
    fn a_retirement_and_a_compromise_in_one_file_leave_the_key_compromised() {
        let (dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert(&mine).unwrap();
        let fingerprint = mine.fingerprint().to_hex();

        let mut signer = primary_signer(&mine, None).unwrap();
        let mut revocation = |reason: ReasonForRevocation, note: &[u8]| {
            CertRevocationBuilder::new()
                .set_reason_for_revocation(reason, note)
                .unwrap()
                .build(&mut signer, &mine, None)
                .unwrap()
        };
        let retired = revocation(ReasonForRevocation::KeyRetired, b"moving on");
        let compromised = revocation(ReasonForRevocation::KeyCompromised, b"laptop stolen");
        let path = dir.path().join("both.asc");
        write_revocations(&path, &[&retired, &compromised]);

        let file = read_revocation_file(&store, &path).unwrap();
        let [pending] = file.revocations.as_slice() else {
            panic!("expected one certificate revoked: {:?}", file.revocations);
        };
        assert_eq!(
            (pending.reason, pending.message.as_str()),
            (Reason::Compromised, "laptop stolen"),
            "the file should be described by its hard revocation"
        );

        apply_file(&store, &path).unwrap();
        assert_eq!(
            revocation_reason(&store.lookup(&fingerprint).unwrap()),
            Some((Reason::Compromised, "laptop stolen".to_string())),
            "the compromise in the file was not stored"
        );
    }

    /// Two hard revocations of a key made in the same second are described by
    /// the one the banner reports once they are stored, whichever the file
    /// puts first. Sorted by time alone, a tie would stay in the file's order,
    /// while sequoia breaks it by the signatures' values: in one of the two
    /// orders the dialog would name one reason, and the banner, a moment
    /// later, the other.
    #[test]
    fn revocations_made_in_the_same_second_are_described_as_the_banner_will_describe_them() {
        let (dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert(&mine).unwrap();
        let fingerprint = mine.fingerprint().to_hex();

        let when = SystemTime::now();
        let mut signer = primary_signer(&mine, None).unwrap();
        let mut revocation = |reason: ReasonForRevocation, note: &[u8]| {
            CertRevocationBuilder::new()
                .set_signature_creation_time(when)
                .unwrap()
                .set_reason_for_revocation(reason, note)
                .unwrap()
                .build(&mut signer, &mine, None)
                .unwrap()
        };
        let compromised = revocation(ReasonForRevocation::KeyCompromised, b"laptop stolen");
        let unspecified = revocation(ReasonForRevocation::Unspecified, b"just in case");
        let described = |name: &str, signatures: &[&Signature]| {
            let path = dir.path().join(name);
            write_revocations(&path, signatures);
            let file = read_revocation_file(&store, &path).unwrap();
            let [pending] = file.revocations.as_slice() else {
                panic!("expected one certificate revoked: {:?}", file.revocations);
            };
            (pending.reason, pending.message.clone())
        };

        let one_way = described("one.rev", &[&compromised, &unspecified]);
        let other_way = described("other.rev", &[&unspecified, &compromised]);
        assert_eq!(
            one_way, other_way,
            "the order of the file decided what it was described as"
        );
        apply_file(&store, &dir.path().join("one.rev")).unwrap();
        assert_eq!(
            revocation_reason(&store.lookup(&fingerprint).unwrap()),
            Some(one_way),
            "the banner reports a reason other than the one described"
        );
    }

    /// A compromise read from a file is stored even when the retirement beside
    /// it has stopped counting by the time the user confirms the file, as it
    /// does once a newer self-signature arrives, from a lookup say. Were a
    /// key's revocations stored all or none, the compromise would be refused
    /// along with the retirement.
    #[test]
    fn a_compromise_is_stored_when_a_retirement_beside_it_no_longer_counts() {
        let (dir, store) = scratch();
        let now = SystemTime::now();
        let hour = Duration::from_secs(60 * 60);
        let (mine, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Me <me@example.org>")
            .set_creation_time(now - 2 * hour)
            .generate()
            .unwrap();
        store.insert(&mine).unwrap();
        let fingerprint = mine.fingerprint().to_hex();

        let mut signer = primary_signer(&mine, None).unwrap();
        let mut revocation = |reason: ReasonForRevocation, note: &[u8]| {
            CertRevocationBuilder::new()
                .set_signature_creation_time(now - hour)
                .unwrap()
                .set_reason_for_revocation(reason, note)
                .unwrap()
                .build(&mut signer, &mine, None)
                .unwrap()
        };
        let retired = revocation(ReasonForRevocation::KeyRetired, b"moving on");
        let compromised = revocation(ReasonForRevocation::KeyCompromised, b"laptop stolen");
        let path = dir.path().join("both.asc");
        write_revocations(&path, &[&retired, &compromised]);
        let file = read_revocation_file(&store, &path).unwrap();
        let [pending] = file.revocations.as_slice() else {
            panic!("expected one certificate revoked: {:?}", file.revocations);
        };
        assert_eq!(pending.signatures.len(), 2, "both should have been read");

        // A binding newer than the retirement, which overrides it.
        let newer = binding_dated(&mine, now - hour / 2);
        let refreshed = mine
            .clone()
            .insert_packets(vec![Packet::from(newer)])
            .unwrap()
            .0;
        store.insert(&refreshed).unwrap();
        assert!(!revokes(&store.lookup(&fingerprint).unwrap(), &retired));

        for outcome in apply_revocations(&store, &file.revocations) {
            if let Err(e) = outcome {
                panic!("the compromise was refused with the retirement: {e}");
            }
        }
        assert_eq!(
            revocation_reason(&store.lookup(&fingerprint).unwrap()),
            Some((Reason::Compromised, "laptop stolen".to_string()))
        );
    }

    /// A certificate for `user_id` that names `revoker` as a key that may
    /// revoke it, and a revocation of it signed by `revoker`.
    fn designated_revocation(user_id: &str, revoker: &Cert) -> (Cert, Signature) {
        let (cert, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid(user_id)
            .set_revocation_keys(vec![revoker.into()])
            .generate()
            .unwrap();
        let mut signer = primary_signer(revoker, None).unwrap();
        let revocation = SignatureBuilder::new(SignatureType::KeyRevocation)
            .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"per policy")
            .unwrap()
            .sign_direct_key(&mut signer, cert.primary_key().key())
            .unwrap();
        (cert, revocation)
    }

    /// A designated revoker's revocation is refused saying that that is what
    /// it is, naming the key it is for, and that rPGP does not apply one. The
    /// refusal used to say only that it did not revoke the revoker's own key,
    /// or, without that key here, that it was for a certificate not in this
    /// store, as if the file were for another certificate, while two comments
    /// claimed the case was handled; it could never be applied.
    ///
    /// One revoker designated on two keys, as an organisation's is on many,
    /// revokes each with a signature of its own, and each refusal names the
    /// key its signature is over, whether or not the revoker's certificate is
    /// here to verify it by. Naming the first key found to designate the
    /// revoker would name it for both, and for the revoker's own revocation
    /// of itself, which does not count yet. Where the revoker's certificate
    /// is here, a revocation that names it as its maker and was made by
    /// another key is no designated revocation either.
    #[test]
    fn a_designated_revokers_revocation_is_refused_naming_the_key_it_is_for() {
        let (dir, store) = scratch();
        let (revoker, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Org Revoker <revoker@example.org>")
            .generate()
            .unwrap();
        let (alice, of_alice) = designated_revocation("Alice <alice@example.org>", &revoker);
        let (bob, of_bob) = designated_revocation("Bob <bob@example.org>", &revoker);
        let mut signer = primary_signer(&revoker, None).unwrap();
        let of_itself = CertRevocationBuilder::new()
            .set_signature_creation_time(SystemTime::now() + Duration::from_secs(24 * 60 * 60))
            .unwrap()
            .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"")
            .unwrap()
            .build(&mut signer, &revoker, None)
            .unwrap();
        let (stranger, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Stranger <stranger@example.org>")
            .generate()
            .unwrap();
        let forged = SignatureBuilder::new(SignatureType::KeyRevocation)
            .set_issuer(revoker.keyid())
            .unwrap()
            .set_issuer_fingerprint(revoker.fingerprint())
            .unwrap()
            .sign_direct_key(
                &mut primary_signer(&stranger, None).unwrap(),
                alice.primary_key().key(),
            )
            .unwrap();
        store.insert(&alice).unwrap();
        store.insert(&bob).unwrap();
        let path = dir.path().join("desig.rev");
        write_revocations(&path, &[&of_alice, &of_bob, &of_itself, &forged]);

        // Without the revoker's certificate, by the two bytes of each hash
        // that a signature carries in the clear. Asserted loosely, since a
        // signature over the other key matches them once in 65,536 times, and
        // both are then named.
        let file = read_revocation_file(&store, &path).unwrap();
        assert!(file.revocations.is_empty(), "{:?}", file.revocations);
        let [for_alice, for_bob, _, _] = file.refused.as_slice() else {
            panic!("expected four refusals: {:?}", file.refused);
        };
        assert!(
            for_alice.contains("Alice <alice@example.org>")
                && for_bob.contains("Bob <bob@example.org>"),
            "each refusal should name the key its revocation is for: {:?}",
            file.refused
        );

        // With it, by the signatures themselves.
        store.insert(&revoker).unwrap();
        let file = read_revocation_file(&store, &path).unwrap();
        assert!(file.revocations.is_empty(), "{:?}", file.revocations);
        let refusal = |name: &str| {
            format!(
                "{name} was not revoked: the revocation names Org Revoker \
                 <revoker@example.org> as its maker, a key {name} designates to revoke it, \
                 and rPGP does not apply revocations by designated revokers"
            )
        };
        let plain = format!(
            "that signature does not revoke {}",
            revoker.fingerprint().to_hex()
        );
        assert_eq!(
            file.refused,
            [
                refusal("Alice <alice@example.org>"),
                refusal("Bob <bob@example.org>"),
                plain.clone(),
                plain,
            ],
            "neither the revoker's own revocation nor one made by another key is a \
             revocation by the revoker of a key it may revoke"
        );
        for cert in [&alice, &bob, &revoker] {
            assert!(!revoked_in_cert_d(&store, &cert.fingerprint().to_hex()));
        }
    }

    /// A revocation by a designated revoker that arrives attached to the
    /// certificate it revokes, as GnuPG's `--desig-revoke` writes it, is
    /// named in what Import says, and one planted by a key the certificate
    /// does not designate is not. Import used to say only that the
    /// certificate had arrived, while the list showed it valid.
    #[test]
    fn a_designated_revokers_revocation_carried_by_its_certificate_is_named() {
        let (revoker, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Org Revoker <revoker@example.org>")
            .generate()
            .unwrap();
        let (stranger, _) = sequoia_openpgp::cert::CertBuilder::new()
            .add_userid("Stranger <stranger@example.org>")
            .generate()
            .unwrap();
        let (alice, revocation) = designated_revocation("Alice <alice@example.org>", &revoker);
        assert_eq!(
            designated_revocations_note(&[alice.clone(), revoker.clone()]),
            None
        );

        let carried = alice.clone().insert_packets(revocation).unwrap().0;
        assert_eq!(
            designated_revocations_note(std::slice::from_ref(&carried)).as_deref(),
            Some(
                "Alice <alice@example.org> carries a revocation naming a key it designates \
                 to revoke it, which rPGP does not apply."
            )
        );

        // A stranger's revocation, planted on Alice, who designates another
        // key, and on the revoker's certificate, which designates none.
        let mut theirs = primary_signer(&stranger, None).unwrap();
        for target in [alice, revoker] {
            let planted = SignatureBuilder::new(SignatureType::KeyRevocation)
                .sign_direct_key(&mut theirs, target.primary_key().key())
                .unwrap();
            let name = name_of(&target);
            assert_eq!(
                designated_revocations_note(&[target.insert_packets(planted).unwrap().0]),
                None,
                "a revocation by a key {name} does not designate was taken for one"
            );
        }
    }

    /// A revocation stored in cert-d is reported as made when the secret key
    /// file then will not read, which is the case the emergency path is kept
    /// for. It used to fail after the revocation was stored, every time it was
    /// tried, and the file was left where it was.
    #[test]
    fn a_revocation_is_stored_and_said_to_be_when_the_secret_key_file_will_not_read() {
        let (dir, store) = scratch();
        let generated = generate(&KeyGenRequest::new("Me <me@example.org>")).unwrap();
        store.insert_secret(&generated.cert).unwrap();
        let fingerprint = generated.cert.fingerprint().to_hex();
        let path = dir.path().join("me.rev");
        std::fs::write(&path, armor(&generated.revocation).unwrap()).unwrap();

        let secret = dir
            .path()
            .join("secrets")
            .join(format!("{fingerprint}.pgp"));
        let whole = std::fs::read(&secret).unwrap();
        std::fs::write(&secret, &whole[..40]).unwrap();
        assert_eq!(store.damaged_secret_files(), std::slice::from_ref(&secret));

        let file = read_revocation_file(&store, &path).unwrap();
        assert!(file.revocations[0].yours);
        match apply_revocations(&store, &file.revocations).remove(0) {
            Err(Error::SecretKeyNotUpdated(_)) => {}
            other => panic!("expected the revocation reported as stored: {other:?}"),
        }
        assert!(revoked_in_cert_d(&store, &fingerprint));
        assert_eq!(
            store.damaged_secret_files(),
            [secret],
            "the damaged file should be left for the survey to report"
        );
    }

    /// A revocation made from the Revoke dialog is reported as made when the
    /// secret key file cannot be written after cert-d has taken it. The store's
    /// lock stands in for the disk: every write to the secrets directory takes
    /// it, and a directory where its file goes fails the open.
    #[test]
    fn a_revocation_is_said_to_be_stored_when_the_secret_key_file_cannot_be_written() {
        let (dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        let fingerprint = mine.fingerprint().to_hex();
        let lock = dir.path().join("write.lock");
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();

        let mut request = RevokeRequest::new(&fingerprint);
        request.reason = Reason::Compromised;
        match revoke_cert(&store, &request) {
            Err(Error::SecretKeyNotUpdated(_)) => {}
            other => panic!(
                "expected the revocation reported as stored: {:?}",
                other.map(|_| ())
            ),
        }
        assert!(revoked_in_cert_d(&store, &fingerprint));
        assert_eq!(
            CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap()).validity,
            Validity::Valid,
            "the secret key file was written after all, so this proves nothing"
        );
    }

    /// A key retired with a soft reason can be marked compromised afterwards,
    /// and that is a hard revocation: a signature dated before the retirement,
    /// which the retirement leaves standing, stops verifying. The summary says
    /// the first revocation is soft and the second hard, which is what keeps
    /// the details pane offering the second.
    #[test]
    fn a_retired_key_marked_compromised_is_hard_revoked() {
        use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};

        let (_dir, store) = scratch();
        let mine = generate(&KeyGenRequest::new("Me <me@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&mine).unwrap();
        let fingerprint = mine.fingerprint().to_hex();

        // Signed at the key's creation, before any revocation can be dated.
        let created = mine.primary_key().key().creation_time();
        let signing = mine
            .keys()
            .with_policy(&policy(), None)
            .for_signing()
            .secret()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();
        let mut detached = Vec::new();
        {
            let message = Armorer::new(Message::new(&mut detached))
                .kind(sequoia_openpgp::armor::Kind::Signature)
                .build()
                .unwrap();
            let mut signer = Signer::new(message, signing)
                .unwrap()
                .detached()
                .creation_time(created)
                .build()
                .unwrap();
            std::io::Write::write_all(&mut signer, b"backdated").unwrap();
            signer.finalize().unwrap();
        }
        let verifies = || {
            crate::ops::verify_detached(&store, &detached, b"backdated")
                .unwrap()
                .signatures
                .iter()
                .all(|report| report.good)
        };
        assert!(
            verifies(),
            "the signature should verify before any revocation"
        );

        let retired = revoke_cert(&store, &RevokeRequest::new(&fingerprint)).unwrap();
        let summary = CertSummary::from_cert(&retired);
        assert_eq!(summary.revocation.as_deref(), Some("No longer used"));
        assert!(
            !summary.revocation_hard,
            "a retirement is soft, and a key retired has a compromise still to declare"
        );
        assert!(
            verifies(),
            "a soft revocation leaves earlier signatures standing"
        );

        let mut request = RevokeRequest::new(&fingerprint);
        request.reason = Reason::Compromised;
        let compromised = revoke_cert(&store, &request).unwrap();
        assert_eq!(
            revocation_reason(&compromised).map(|(reason, _)| reason),
            Some(Reason::Compromised)
        );
        assert!(CertSummary::from_cert(&compromised).revocation_hard);
        assert!(
            !verifies(),
            "a signature dated before the retirement still verifies after the compromise"
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
