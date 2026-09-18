//! Owning a key over time: changing when it expires, and managing the
//! identities bound to it.
//!
//! All three operations here are new self-signatures by the certificate's own
//! primary key. None of them removes anything: OpenPGP has no delete, only
//! newer signatures that supersede older ones and revocations that retract
//! them. A user ID "removed" from a key is a user ID everyone else still has.

use std::time::{Duration, SystemTime};

use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::cert::{SubkeyRevocationBuilder, UserIDRevocationBuilder};
use sequoia_openpgp::packet::key::{PrimaryRole, PublicParts, SubordinateRole};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{Key, Signature, UserID};
use sequoia_openpgp::types::{ReasonForRevocation, RevocationStatus, SignatureType};
use sequoia_openpgp::{Cert, Packet};

use crate::error::{Error, Result};
use crate::policy;
use crate::store::Store;

/// Set — or clear — when a certificate expires.
///
/// `None` makes it never expire. The change is a fresh self-signature over the
/// primary key and every valid subkey, so an expiry can be extended after the
/// fact: a key that lapsed last week can be brought back by setting a date in
/// the future.
///
/// A revoked certificate is refused outright; see the guard below for why.
///
/// One wrinkle: signature timestamps have one-second resolution and a new
/// self-signature only supersedes one made strictly earlier, so two expiry
/// changes within the same second leave the first standing. It matters only to
/// a caller changing expiry twice in a row, which a person clicking a button
/// will not do, but a test will.
pub fn set_expiry(
    store: &Store,
    fingerprint: &str,
    expires_in: Option<Duration>,
    password: Option<&str>,
) -> Result<Cert> {
    let cert = store.secret_cert(fingerprint)?;

    // The refusal is not merely tidy. Sequoia decides revocation status from
    // the newest of the primary key's self-signatures, and the direct-key
    // signature written below is dated now, so on a soft revocation —
    // KeyRetired, which is this app's default, or KeySuperseded — it overrides
    // the revocation and the certificate reads as live again, here and for
    // everyone who refreshes it afterwards. `revoke` opens by saying there is
    // no un-revoke; this is where that stopped being true.
    //
    // Asked of `full_cert` and not of `cert`, because one's own revocation can
    // reach the public half alone — by import, or by a keyserver refresh — and
    // `secret_cert`, which is the copy changed here, would still look live. The
    // change is still made to `cert`: `store_both` writes back whatever it is
    // handed, and folding cert-d's third-party signatures into the secret key
    // file is not this refusal's business.
    //
    // Ahead of `unlock_primary`, which is not about prompts — it unlocks with
    // the passphrase it is given and never reaches the agent — but so that a
    // refused change unlocks no secret, and so that the owner of a revoked key
    // is told it is revoked rather than that the passphrase is wrong.
    crate::revoke::refuse_if_revoked(&store.full_cert(fingerprint)?)?;

    let policy = policy();
    let mut signer = unlock_primary(&cert, password)?;

    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| Error::invalid("this certificate is not valid under the standard policy"))?;

    // `SystemTime + Duration` panics on overflow, and this is a public entry
    // point whose signature offers to take any lifetime at all. The GUI only
    // ever passes one, two or five years, so nothing in the app can reach it;
    // a panic is still not an answer to an argument, and the check costs a
    // line. A lifetime that fits here but overruns the four-byte field a key
    // expiry is written into is left to sequoia, which measures it from each
    // key's own creation time and says so.
    let expiration = expires_in
        .map(|d| {
            SystemTime::now()
                .checked_add(d)
                .ok_or_else(|| Error::invalid("that expiry is too far in the future"))
        })
        .transpose()?;

    // The primary key first: a direct-key signature plus one self-signature
    // per user ID, which is where a primary key's expiry actually lives.
    let mut signatures = valid
        .primary_key()
        .set_expiration_time(&mut signer, expiration)
        .map_err(Error::OpenPgp)?;

    // Then every subkey, separately. This is not optional and it is not done
    // for us: sequoia's primary-key call touches only the primary key's own
    // signatures, and each subkey carries its own expiry in its own binding
    // signature. Keys generated here give primary and subkeys the same
    // lifetime, so without this an extended certificate has a primary key
    // that lives on and signing and encryption subkeys that die on the
    // original date — the user believes they extended it and a month later
    // nobody can encrypt to them.
    //
    // Sequoia's call rebuilds a subkey's binding out of the old one, and for a
    // subkey that can certify, sign or authenticate it puts a fresh
    // countersignature in it — the primary key binding signature, or
    // "back-sig" — which only that subkey's own secret can make. So it demands
    // a signer for exactly those and refuses one for anything else. Testing
    // for_signing() alone missed authentication subkeys, so every GnuPG
    // [S][E][A] key — which is what `gpg --export-secret-keys` produces —
    // failed the whole change with "requires subkey signer", naming a
    // capability the subkey does not have. Keys generated here have only
    // [S] and [E], so nothing in the tree exercised it.
    //
    // A *fresh* back-sig is what needs the secret, and the secret is often not
    // here. `gpg --export-secret-keys` writes a stub in place of every subkey
    // held on a smartcard, and a key split across machines arrives with plain
    // public subkey packets. Such a subkey used to be skipped, which brought
    // back, for [S], [C] and [A], the very failure encryption subkeys were
    // fixed for — the pane showing the new date over a subkey that lapses on
    // the old one — or, for a stub, aborted the whole change by asking for a
    // passphrase that no passphrase answers, leaving a laptop-held primary
    // unable to re-date anything.
    //
    // Neither is necessary, because the back-sig already there can be carried
    // into the new binding: it covers the (primary, subkey) pair and nothing
    // of the binding it travels in, so moving it does not invalidate it, and
    // `SignatureBuilder::from` keeps it — hashed area, where sequoia puts it,
    // or unhashed, where GnuPG does. Two things have to hold for that to be
    // enough, and both are guaranteed by this subkey having come out of
    // `valid`: sequoia requires a back-sig only of a binding whose flags
    // include signing, and it refuses such a binding whose back-sig the policy
    // rejects, so a binding the policy accepted today carries one if it needs
    // one and the copy will be accepted again. GnuPG writes no back-sig for an
    // [A] subkey at all, which is why the requirement must not be read off
    // `needs_backsig`.
    //
    // Revoked subkeys are left alone: a new expiry on a revoked key is noise.
    for ka in valid.keys().subkeys().revoked(false) {
        let needs_backsig = ka.for_signing() || ka.for_certification() || ka.for_authentication();

        // Not `parts_into_secret` alone: that succeeds on a GnuPG stub as
        // readily as on real key material, which is the whole trouble with
        // stubs. See [`crate::secret::is_usable`].
        let secret = ka
            .key()
            .clone()
            .parts_into_secret()
            .ok()
            .filter(|key| crate::secret::is_usable(key.secret()));

        match (needs_backsig, secret) {
            (true, None) => signatures.push(rebind_subkey(
                &mut signer,
                cert.primary_key().key(),
                ka.key(),
                ka.binding_signature(),
                expiration,
            )?),
            // A secret that is real but will not open — no passphrase, or the
            // wrong one — is still an error rather than a reason to fall back.
            // The user has the key on this machine and typed something wrong,
            // and reusing the old back-sig would hide that.
            (true, Some(secret)) => {
                let mut subkey_signer = crate::secret::keypair(secret, password)?;
                signatures.extend(
                    ka.set_expiration_time(&mut signer, Some(&mut subkey_signer), expiration)
                        .map_err(Error::OpenPgp)?,
                );
            }
            (false, _) => signatures.extend(
                ka.set_expiration_time(&mut signer, None, expiration)
                    .map_err(Error::OpenPgp)?,
            ),
        }
    }

    store_both(store, cert, signatures)
}

/// Bind a new identity to a certificate.
///
/// The new binding is copied from the primary user ID's, so the new name
/// carries the key's flags, its expiry and its algorithm preferences rather
/// than nothing at all, and the primary identity does not move — unless it has
/// been retired, in which case the new name takes it over rather than the
/// retirement being quietly undone.
///
/// A revoked certificate is refused, as in [`set_expiry`] and for the same
/// reason, and so is one the standard policy cannot evaluate: the key's own
/// account of itself is what this copies, and a certificate that cannot be
/// read has none to copy.
pub fn add_user_id(
    store: &Store,
    fingerprint: &str,
    user_id: &str,
    password: Option<&str>,
) -> Result<Cert> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err(Error::invalid("a user ID cannot be empty"));
    }

    let cert = store.secret_cert(fingerprint)?;

    // Where the binding over the primary user ID is re-issued below — which is
    // every certificate whose bindings claim no primary identity, the shape
    // most imported keys have — that signature is dated now, and the primary
    // user ID's binding overrides a soft revocation exactly as a direct-key
    // signature does. So naming a retired key would bring it back to life, and
    // the status bar would then invite its owner to publish it. A certificate
    // that already claims its primary identity takes no re-issue, so nothing
    // this writes lands on the primary user ID and the revocation stands; keys
    // generated here are that shape and so happen to be safe, which is
    // precisely the kind of accident not to leave a guarantee resting on. Both
    // shapes are refused.
    //
    // Both halves of the store are asked, and the guard sits ahead of
    // `unlock_primary`, for the reasons set out in [`set_expiry`].
    crate::revoke::refuse_if_revoked(&store.full_cert(fingerprint)?)?;

    if cert
        .userids()
        .any(|ua| String::from_utf8_lossy(ua.userid().value()) == user_id)
    {
        return Err(Error::invalid(format!("{user_id} is already on this key")));
    }

    let policy = policy();

    // What a certificate says about its own primary key — the key flags, the
    // expiry, the preferred algorithms, the features — lives in the primary
    // user ID's binding signature, with a direct-key signature as the fallback.
    // A bare `SignatureBuilder::new` carries none of it, and on a key whose
    // bindings claim no primary user ID, which is every key GnuPG makes, the
    // new binding is then the newest and becomes the primary one: the key loses
    // its certify and sign flags, loses the expiry its owner set, and is
    // published with neither. Sequoia-based tools, this one included, then
    // refuse to sign or certify with it. Keys generated here escape only
    // because `CertBuilder` flags their first user ID, which is why every test
    // passed.
    //
    // So copy the primary user ID's binding and re-sign it over the new name.
    // That is sequoia's own move when it re-issues a binding — `set_expiry`
    // goes through the same template — and what it copies is exactly what the
    // key claims about itself.
    let (template, pin) = {
        let valid = cert.with_policy(&policy, None).map_err(|_| {
            Error::invalid("this certificate is not valid under the standard policy")
        })?;
        let primary = valid.primary_userid().ok();
        let template = match &primary {
            Some(primary) => primary.binding_signature().clone(),
            // No user ID the policy accepts, so there is nothing to copy but the
            // direct-key signature. A certificate with neither has nothing to
            // say about its own key and cannot be templated from at all.
            None => valid
                .direct_key_signature()
                .map_err(|_| {
                    Error::invalid(
                        "this certificate carries no self-signature to copy the key's \
                         flags and preferences from",
                    )
                })?
                .clone(),
        };

        // Copying the subpackets is not enough on its own: with identical
        // subpackets the new binding is still the newest, and sequoia ranks a
        // claimed primary user ID above a newer one but has nothing else to go
        // on. So where no binding claims it, re-issue the current primary's own
        // binding with the claim made explicit, and the primary stays where it
        // was. A certificate that already names a primary is left alone.
        //
        // A retired identity is left alone too, and that one is not a nicety.
        // Sequoia settles a user ID's revocation status from the newest binding
        // over it, so a binding dated now overrides a soft revocation —
        // UIDRetired, which is this app's own default — exactly as the
        // direct-key signature in `set_expiry` overrides a soft revocation of
        // the whole certificate. On a key whose identities have all been
        // withdrawn, pinning would put the retired name back in service, claim
        // it as the primary one, and write that to both halves of the store and
        // into whatever is published next. Nothing is lost by skipping it:
        // sequoia ranks a live identity above a revoked one whatever the dates
        // say, so the name just added becomes the primary one, which is the only
        // honest answer when every other name on the key has been withdrawn.
        let pin = primary
            .filter(|primary| !matches!(primary.revocation_status(), RevocationStatus::Revoked(_)))
            .filter(|primary| primary.binding_signature().primary_userid() != Some(true))
            .map(|primary| {
                (
                    primary.userid().clone(),
                    primary.binding_signature().clone(),
                )
            });
        (template, pin)
    };

    // Both signatures are dated together, and one second on where the binding
    // being replaced was made in this same second. Signature timestamps are
    // whole seconds and a self-signature supersedes only one made strictly
    // earlier, so a re-issued binding that ties with its predecessor is settled
    // by comparing the two signatures' MPIs — a coin toss that, lost, leaves
    // the primary user ID unclaimed and moves it to the new name after all.
    // Dating both alike keeps the claim, not the clock, deciding which identity
    // is primary, so the one second the pair can spend in the future costs
    // nothing: until it arrives the certificate reads as it did before the call,
    // rather than briefly reading with the wrong primary.
    //
    // This is not the general fix for same-second self-signatures, which is a
    // change of its own; it is this operation not adding another instance.
    let now = SystemTime::now();
    let second = Duration::from_secs(1);
    let when = match pin
        .as_ref()
        .and_then(|(_, sig)| sig.signature_creation_time())
    {
        Some(created) if created + second > now => now + second,
        _ => now,
    };

    let mut signer = unlock_primary(&cert, password)?;
    let userid = UserID::from(user_id);

    let mut builder = SignatureBuilder::from(template)
        .set_type(SignatureType::PositiveCertification)
        .set_signature_creation_time(when)?;
    {
        // Nothing in the template's unhashed area is this signature's to carry.
        // That area is covered by no signature, so anyone who handles a
        // certificate can append to it in flight, and `SignatureBuilder` copies
        // the whole of it across — it drops only the creation time and the
        // issuers. Sequoia reads it for the issuers and for an embedded
        // signature, and signing writes the issuers this signature needs into
        // the hashed area, so emptying it loses nothing the new binding is
        // entitled to and keeps a stranger's packets out of a signature this
        // key makes.
        builder.unhashed_area_mut().clear();

        // What the template says about the key is the point of copying it; what
        // it says about the identity it was made over is not the new identity's
        // to inherit — above all the primary-user-ID claim, which would make
        // the certificate name two. This is the list sequoia strips when it
        // templates a direct-key signature out of a user ID binding: the same
        // question, asked of a subject that is not the identity signed over.
        use sequoia_openpgp::packet::signature::subpacket::SubpacketTag::*;
        for tag in [
            PrimaryUserID,
            SignersUserID,
            ExportableCertification,
            Revocable,
            TrustSignature,
            RegularExpression,
            ReasonForRevocation,
            SignatureTarget,
            EmbeddedSignature,
        ] {
            builder.hashed_area_mut().remove_all(tag);
        }
    }
    let binding = builder.sign_userid_binding(&mut signer, cert.primary_key().key(), &userid)?;

    let mut packets = vec![Packet::from(userid), Packet::from(binding)];
    if let Some((primary, binding)) = pin {
        // Re-issued from its own binding, so it keeps the type it had and every
        // subpacket it carried; only the claim and the date are new. Including
        // the unhashed area, unlike the binding above, because the subject here
        // is the very identity that binding was already made over and this is
        // what sequoia's own re-issue does. It does leave this the one place
        // where a packet appended in flight is carried into a signature this key
        // makes, which is a question for whoever revisits the re-issue.
        packets.push(Packet::from(
            SignatureBuilder::from(binding)
                .set_signature_creation_time(when)?
                .set_primary_userid(true)?
                .sign_userid_binding(&mut signer, cert.primary_key().key(), &primary)?,
        ));
    }

    // secret_cert is where `cert` came from, so the certificate always has a
    // secret half here — the has_secret test that used to guard the write
    // could not be false. What followed it rebuilt the new user ID and its
    // binding out of `updated` and inserted them into `cert` a second time,
    // reconstructing a certificate that had already been built one line
    // above. insert_secret writes the public half itself, so one call does
    // what three did.
    let updated = cert.insert_packets(packets)?.0;
    store.insert_secret(&updated)?;
    Ok(updated)
}

/// Retract one of a certificate's own identities.
///
/// The user ID stays on the key — it has to, so anyone holding an old copy can
/// see it was withdrawn rather than simply not knowing about it.
///
/// The last live identity cannot be retired this way. Where the standard policy
/// cannot evaluate the certificate at all — a legacy key whose self-signatures
/// are all SHA-1, say — which identities are still standing cannot be answered,
/// and the guard falls back to the cruder count it used to keep, so such a key
/// is left exactly the operation it always had.
pub fn revoke_user_id(
    store: &Store,
    fingerprint: &str,
    user_id: &str,
    message: &str,
    password: Option<&str>,
) -> Result<Cert> {
    let cert = store.secret_cert(fingerprint)?;

    // Exactly one user ID, or none. Taking the first row whose lossy rendering
    // matched retired whichever sorted first — which, since the GUI hides the
    // button on the primary and on already-revoked rows, could be the primary
    // identity the user was not offered the choice of retiring, or a second
    // revocation of one already retired while the row they clicked stayed live
    // and the status bar said it had been revoked. `cert::resolve_user_id`
    // carries the reasoning.
    let userid = crate::cert::resolve_user_id(&cert, user_id)?
        .userid()
        .clone();

    // Which identities are actually standing. The count used to be
    // `cert.userids()`, which is every user ID the certificate carries,
    // including ones revoked years ago and ones with no binding signature at
    // all — sequoia keeps a name anyone appended in flight. A key whose second
    // identity was retired last year therefore passed a guard whose own message
    // promises it will not, and the last live name on the key went with it.
    //
    // The refusal comes only where this would take the last live identity
    // away, so retiring a name already retired now goes through where the old
    // count would sometimes have refused it. That writes a second UIDRetired
    // over a name already withdrawn, which leaves the certificate saying
    // exactly what it said before, and the GUI hides the button on those rows
    // in any case.
    let policy = policy();
    let refuse = match cert.with_policy(&policy, None) {
        Ok(valid) => {
            let mut target_is_live = false;
            let mut others_live = 0usize;
            for ua in valid.userids().revoked(false) {
                if ua.userid() == &userid {
                    target_is_live = true;
                } else {
                    others_live += 1;
                }
            }
            target_is_live && others_live == 0
        }
        // Nothing here can read the certificate, so which identities are still
        // standing has no answer and the count above cannot be taken. Falling
        // back to the one this replaces rather than refusing outright: the old
        // count is crude, but a retirement it lets through is one it has always
        // let through, and a legacy key keeps the only way this app offers of
        // retiring an address on it. `set_expiry` refuses such a certificate,
        // but that is a different case — it has to read the key's own account
        // of itself in order to rewrite it, while nothing here does.
        Err(_) => cert.userids().count() < 2,
    };
    if refuse {
        return Err(Error::invalid(
            "this is the only user ID; revoking the whole certificate is the honest \
             way to retire it",
        ));
    }

    let mut signer = unlock_primary(&cert, password)?;
    let signature = UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, message.as_bytes())?
        .build(&mut signer, &cert, &userid, None)?;

    store_both(store, cert, vec![signature])
}

/// Retract a single subkey, leaving the rest of the certificate intact.
///
/// Useful when one subkey's secret is exposed but the primary key is not: the
/// identity survives and only the compromised part is withdrawn. Which is why
/// the reason is a parameter and not hardcoded: "exposed" is a hard
/// revocation, and a soft one would leave whoever holds the subkey able to keep
/// making signatures that verify.
pub fn revoke_subkey(
    store: &Store,
    fingerprint: &str,
    subkey_fingerprint: &str,
    reason: crate::revoke::Reason,
    message: &str,
    password: Option<&str>,
) -> Result<Cert> {
    let cert = store.secret_cert(fingerprint)?;
    let wanted = subkey_fingerprint.to_uppercase();

    let subkey = cert
        .keys()
        .subkeys()
        .map(|ka| ka.key().clone())
        .find(|key| key.fingerprint().to_hex().eq_ignore_ascii_case(&wanted))
        .ok_or_else(|| {
            Error::invalid(format!("{subkey_fingerprint} is not a subkey of this key"))
        })?;

    let mut signer = unlock_primary(&cert, password)?;
    let signature = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(reason.to_openpgp(), message.as_bytes())?
        .build(&mut signer, &cert, &subkey, None)?;

    store_both(store, cert, vec![signature])
}

/// Merge new self-signatures into both halves of the store.
fn store_both(store: &Store, cert: Cert, signatures: Vec<Signature>) -> Result<Cert> {
    let fingerprint = cert.fingerprint().to_hex();
    let updated = cert.insert_packets(signatures)?.0;

    // The secret certificate is the one that carries key material, so it is
    // the copy that must not fall behind; cert-d gets the public half — which
    // insert_secret writes for us, so calling insert as well only serialised
    // the same certificate into the same place twice.
    if store.has_secret(&fingerprint) {
        store.insert_secret(&updated)?;
    } else {
        store.insert(&updated)?;
    }
    Ok(updated)
}

/// Re-issue a subkey's binding with a new expiry, using the primary key alone.
///
/// What sequoia's own call does, minus the fresh back-signature it would make
/// with the subkey's secret: the template is the binding the policy currently
/// accepts, so whatever that carries — including a back-signature, which stays
/// valid wherever it is moved to — comes across into the replacement.
///
/// The unhashed area comes across with it, which [`add_user_id`] deliberately
/// refuses to do for the binding it copies. It is the opposite question here.
/// There the template was made over another identity and anything appended to
/// it in flight is a stranger's; here the template is this subkey's own
/// binding, and the one packet most likely to be sitting in that area is the
/// back-signature GnuPG puts there.
fn rebind_subkey(
    signer: &mut (dyn sequoia_openpgp::crypto::Signer + Send + Sync),
    primary: &Key<PublicParts, PrimaryRole>,
    subkey: &Key<PublicParts, SubordinateRole>,
    binding: &Signature,
    expiration: Option<SystemTime>,
) -> Result<Signature> {
    // A key expiry is stored as a lifetime counted from that key's own
    // creation, which is why this is per subkey rather than one figure for the
    // certificate. An imported subkey can predate the primary, or carry a
    // creation time in the future, so the subtraction is fallible.
    let validity = expiration
        .map(|expires| expires.duration_since(subkey.creation_time()))
        .transpose()
        .map_err(|_| {
            Error::invalid(format!(
                "that expiry is earlier than subkey {} was created",
                subkey.fingerprint().to_hex()
            ))
        })?;

    Ok(SignatureBuilder::from(binding.clone())
        .set_signature_creation_time(SystemTime::now())?
        .set_key_validity_period(validity)?
        .sign_subkey_binding(signer, primary, subkey)?)
}

fn unlock_primary(
    cert: &Cert,
    password: Option<&str>,
) -> Result<Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync>> {
    let key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| Error::NoSecretKey(cert.fingerprint().to_hex()))?;

    // `gpg --export-secret-subkeys` — how a keyring whose primary is kept
    // offline is moved — puts a stub where the primary's secret belongs, and a
    // stub passes every test for secret key material sequoia applies: the call
    // above succeeds, the store files the certificate with the secret keys,
    // and the GUI offers its owner all of these operations. Saying so here is
    // the whole of the fix, because none of them can be done without the
    // primary. Left to `secret::unlock` the answer was a passphrase prompt the
    // key has no passphrase for, and then, for anyone who typed one anyway, a
    // malformed-packet error from the S2K that reads like a corrupt file.
    if !crate::secret::is_usable(key.secret()) {
        return Err(Error::invalid(
            "this key's primary secret is a GnuPG stub: the primary key itself is \
             offline or on a smartcard",
        ));
    }

    crate::secret::signer(key, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Validity;
    use crate::keygen::{KeyGenRequest, generate};
    use crate::revoke::Reason;
    use crate::{CertSummary, cert};

    fn scratch() -> (tempfile::TempDir, Store, Cert) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let cert = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&cert).unwrap();
        (dir, store, cert)
    }

    /// `revoke` opens by saying there is no un-revoke, and this is where that
    /// stopped being true. Sequoia settles a certificate's revocation status
    /// from the newest of the primary key's self-signatures, so the direct-key
    /// signature this writes, dated now, supersedes a soft revocation. The
    /// status bar then said "Expiry updated. Publish the key again so others see
    /// it." over a certificate that had just come back to life — and publishing
    /// it is what brings correspondents back to a key its owner retired.
    #[test]
    fn refuses_to_change_the_expiry_of_a_revoked_certificate() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        let before = CertSummary::from_cert(&cert).expires;

        // Retired is the default and is soft, which is the case that undid the
        // revocation; a hard one survived a new self-signature by itself.
        let mut request = crate::revoke::RevokeRequest::new(&fingerprint);
        request.reason = Reason::Retired;
        crate::revoke::revoke_cert(&store, &request).unwrap();

        // A self-signature only supersedes one made strictly earlier and the
        // timestamps are whole seconds, so without this wait the revocation
        // would survive on a tie rather than on the guard, and the assertions
        // below would hold whether or not the guard exists.
        std::thread::sleep(Duration::from_millis(1100));

        let ten_years = Duration::from_secs(10 * 365 * 24 * 60 * 60);
        // Mapped to `()` before `expect_err` so that a broken guard reports the
        // assertion rather than `Debug`-printing the whole certificate over it.
        let refused = set_expiry(&store, &fingerprint, Some(ten_years), None)
            .map(|_| ())
            .expect_err("changed the expiry of a revoked certificate");
        let message = refused.to_string();
        assert!(
            message.contains("Alice <alice@example.org>") && message.contains("revoked"),
            "the refusal must say whose key and why: {message}"
        );

        // Both halves of the store still say revoked, and the expiry is where
        // it was.
        for reloaded in [
            store.lookup(&fingerprint).unwrap(),
            store.secret_cert(&fingerprint).unwrap(),
        ] {
            let summary = CertSummary::from_cert(&reloaded);
            assert_eq!(summary.validity, Validity::Revoked);
            assert_eq!(summary.expires, before);
        }
    }

    /// The same guard for the same reason, over the two certificate shapes that
    /// answer the question differently.
    ///
    /// Sequoia settles a certificate's revocation status from the newest
    /// self-signature on the *primary user ID*, so whether adding a name
    /// supersedes a soft revocation turns on whether this puts a signature
    /// there. A key generated here flags its first user ID, so that binding
    /// already claims the primary identity, no re-issue is taken, and nothing
    /// at all reaches the primary user ID: that shape is safe by accident. A
    /// certificate whose bindings carry no such subpacket, which is how a fair
    /// number of imported keys look, has its primary user ID re-signed so that
    /// the primary does not move, and that re-signature is dated now. With the
    /// guard removed the second half of this test reads `Valid` again after the
    /// call, which is the harm — a key retired with the default reason back in
    /// service, and the app suggesting it be published. Both halves are
    /// refused, because the difference between them is an accident of how the
    /// certificate was made and not something a guarantee should rest on.
    #[test]
    fn refuses_to_add_a_user_id_to_a_revoked_certificate() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        crate::revoke::revoke_cert(&store, &crate::revoke::RevokeRequest::new(&fingerprint))
            .unwrap();

        let refused = add_user_id(&store, &fingerprint, "Alice <alice@newjob.example>", None)
            .map(|_| ())
            .expect_err("bound a new name to a revoked certificate");
        let message = refused.to_string();
        assert!(
            message.contains("Alice <alice@example.org>") && message.contains("revoked"),
            "the refusal must say whose key and why: {message}"
        );

        let reloaded = store.secret_cert(&fingerprint).unwrap();
        assert_eq!(
            CertSummary::from_cert(&reloaded).validity,
            Validity::Revoked
        );
        assert!(
            !reloaded
                .userids()
                .any(|ua| String::from_utf8_lossy(ua.userid().value())
                    == "Alice <alice@newjob.example>"),
            "a refused change must not reach the store"
        );

        // Now the shape that un-revokes. Re-bind the existing user ID with a
        // signature carrying no primary-user-ID subpacket, so the certificate
        // looks like one that came in through Import rather than one this app
        // generated.
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        let secret = store.secret_cert(&fingerprint).unwrap();
        let userid = secret.userids().next().unwrap().userid().clone();
        let mut signer = unlock_primary(&secret, None).unwrap();

        // A self-signature supersedes one made strictly earlier and the
        // timestamps are whole seconds, so each of these waits is what makes
        // the next signature count rather than tie. Without them the shape
        // under test is never actually built and the revocation would survive
        // on a tie rather than on the guard.
        std::thread::sleep(Duration::from_millis(1100));
        let unflagged = SignatureBuilder::new(SignatureType::PositiveCertification)
            .sign_userid_binding(&mut signer, secret.primary_key().key(), &userid)
            .unwrap();
        let reshaped = secret
            .insert_packets(vec![Packet::from(unflagged)])
            .unwrap()
            .0;
        store.insert_secret(&reshaped).unwrap();

        let policy = policy();
        let reshaped = store.lookup(&fingerprint).unwrap();
        assert!(
            reshaped
                .with_policy(&policy, None)
                .unwrap()
                .primary_userid()
                .unwrap()
                .binding_signature()
                .primary_userid()
                .is_none(),
            "the point of this half is a binding with no primary-user-ID subpacket"
        );

        crate::revoke::revoke_cert(&store, &crate::revoke::RevokeRequest::new(&fingerprint))
            .unwrap();
        std::thread::sleep(Duration::from_millis(1100));

        add_user_id(&store, &fingerprint, "Alice <alice@newjob.example>", None)
            .map(|_| ())
            .expect_err("brought a revoked certificate back by naming it again");
        assert_eq!(
            CertSummary::from_cert(&store.lookup(&fingerprint).unwrap()).validity,
            Validity::Revoked,
            "the certificate must not come back to life"
        );
    }

    /// Both refusals again, over a revocation that is only half in the store.
    ///
    /// `Store::insert` writes cert-d and never the secret key file, so one's
    /// own revocation can arrive on the public half alone — Import of a copy
    /// that was published before it was retracted, or a keyserver refresh —
    /// and `secret_cert`, which is the copy these two operations read and
    /// write, still looks live. Asking that copy alone leaves the un-revoke
    /// open in the one configuration where the user can watch it happen: the
    /// list and the details pane read cert-d and say `revoked`, the dialogs
    /// gate on ownership rather than on validity, and the status bar then
    /// invites the owner to publish what it just brought back.
    ///
    /// Retired, because it is the default and it is soft: a hard revocation
    /// survives a later self-signature by itself, so it would prove nothing
    /// here.
    #[test]
    fn refuses_a_lifecycle_change_when_the_revocation_reached_only_cert_d() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        let before = CertSummary::from_cert(&cert).expires;

        // Revoked where the key also lives — the owner's other machine — and
        // met here as a public certificate, which is all `insert` ever writes.
        let elsewhere_dir = tempfile::tempdir().unwrap();
        let elsewhere = Store::open(
            elsewhere_dir.path().join("certs.d"),
            elsewhere_dir.path().join("secrets"),
        )
        .unwrap();
        elsewhere.insert_secret(&cert).unwrap();
        let mut request = crate::revoke::RevokeRequest::new(&fingerprint);
        request.reason = Reason::Retired;
        crate::revoke::revoke_cert(&elsewhere, &request).unwrap();
        store
            .insert(&elsewhere.lookup(&fingerprint).unwrap())
            .unwrap();

        assert_eq!(
            CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap()).validity,
            Validity::Valid,
            "the secret half not knowing is the premise of this test"
        );

        // As in the expiry test above: a self-signature supersedes one made
        // strictly earlier and the timestamps are whole seconds, so without
        // this wait the revocation would survive a missing guard on a tie.
        std::thread::sleep(Duration::from_millis(1100));

        let ten_years = Duration::from_secs(10 * 365 * 24 * 60 * 60);
        let refused = set_expiry(&store, &fingerprint, Some(ten_years), None)
            .map(|_| ())
            .expect_err("changed the expiry of a key whose revocation was in cert-d");
        assert!(
            refused.to_string().contains("revoked"),
            "the refusal must say why: {refused}"
        );

        let refused = add_user_id(&store, &fingerprint, "Alice <alice@newjob.example>", None)
            .map(|_| ())
            .expect_err("named a key whose revocation was in cert-d");
        assert!(
            refused.to_string().contains("revoked"),
            "the refusal must say why: {refused}"
        );

        let public = store.lookup(&fingerprint).unwrap();
        assert_eq!(
            CertSummary::from_cert(&public).validity,
            Validity::Revoked,
            "the certificate must not come back to life"
        );
        assert_eq!(
            CertSummary::from_cert(&public).expires,
            before,
            "and a refused change must not reach the store"
        );
    }

    #[test]
    fn extends_and_clears_expiry() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        let original = CertSummary::from_cert(&cert).expires.unwrap();

        let ten_years = Duration::from_secs(10 * 365 * 24 * 60 * 60);
        let updated = set_expiry(&store, &fingerprint, Some(ten_years), None).unwrap();
        let extended = CertSummary::from_cert(&updated).expires.unwrap();
        assert!(extended > original, "expiry should have moved outwards");

        // Signature timestamps have one-second granularity, and a new
        // self-signature only supersedes one made strictly earlier. Two expiry
        // changes inside the same second tie, and the older wins — see the note
        // on `set_expiry`.
        std::thread::sleep(Duration::from_millis(1100));

        let updated = set_expiry(&store, &fingerprint, None, None).unwrap();
        assert!(CertSummary::from_cert(&updated).expires.is_none());

        // Both halves of the store must agree, or a reload undoes it.
        assert!(
            CertSummary::from_cert(&store.lookup(&fingerprint).unwrap())
                .expires
                .is_none()
        );
        assert!(
            CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap())
                .expires
                .is_none()
        );
    }

    /// A GnuPG key is [S][E][A], and the authentication subkey is the one this
    /// loop used to get wrong. It cannot sign messages, so `for_signing()` is
    /// false and it was handed no signer — but it *can* authenticate, and
    /// sequoia demands a back-signature from anything that can, so it refused
    /// the whole operation. The user saw "requires subkey signer" naming a
    /// capability their subkey does not have, and could never change that
    /// key's expiry at all. Nothing in the tree caught it because keygen here
    /// only ever makes [S][E].
    #[test]
    fn an_imported_gnupg_key_with_an_auth_subkey_can_still_be_extended() {
        use sequoia_openpgp::cert::CertBuilder;
        use sequoia_openpgp::policy::StandardPolicy;
        let policy = StandardPolicy::new();

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let (cert, _) = CertBuilder::new()
            .add_userid("Alice <alice@example.org>")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_authentication_subkey()
            .set_validity_period(Duration::from_secs(1))
            .generate()
            .unwrap();
        store.insert_secret(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        std::thread::sleep(Duration::from_millis(1500));

        assert_eq!(
            cert.with_policy(&policy, None)
                .unwrap()
                .keys()
                .subkeys()
                .count(),
            3,
            "the shape under test is [S][E][A]"
        );

        let extended = set_expiry(
            &store,
            &fingerprint,
            Some(Duration::from_secs(31_536_000)),
            None,
        )
        .expect("an authentication subkey must not abort the whole change");

        let valid = extended.with_policy(&policy, None).unwrap();
        assert!(
            valid.keys().subkeys().all(|ka| ka.alive().is_ok()),
            "every subkey must be re-dated, including the one that needed a back-signature"
        );
    }

    /// An encryption subkey does not countersign its own binding — only the
    /// primary signs it — so one whose secret is not held locally can still be
    /// re-dated. Filtering the loop by `.secret()` skipped it silently: the
    /// pane showed the new date, read off the primary, while the subkey lapsed
    /// on the old one and nobody could encrypt to the user a month later.
    #[test]
    fn an_encryption_subkey_without_a_local_secret_is_still_re_dated() {
        use sequoia_openpgp::policy::StandardPolicy;
        use sequoia_openpgp::{Packet, cert::CertBuilder};
        let policy = StandardPolicy::new();

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let (cert, _) = CertBuilder::new()
            .add_userid("Alice <alice@example.org>")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .set_validity_period(Duration::from_secs(1))
            .generate()
            .unwrap();

        // Strip the encryption subkey's secret, the way a key that has been
        // split across devices arrives.
        let encryption = cert
            .with_policy(&policy, None)
            .unwrap()
            .keys()
            .subkeys()
            .for_transport_encryption()
            .next()
            .unwrap()
            .key()
            .fingerprint();
        let stripped: Vec<Packet> = cert
            .as_tsk()
            .into_packets()
            .map(|p| match p {
                Packet::SecretSubkey(k) if k.fingerprint() == encryption => {
                    Packet::PublicSubkey(k.take_secret().0)
                }
                other => other,
            })
            .collect();
        let cert = Cert::try_from(stripped).unwrap();
        store.insert_secret(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        std::thread::sleep(Duration::from_millis(1500));

        let extended = set_expiry(
            &store,
            &fingerprint,
            Some(Duration::from_secs(31_536_000)),
            None,
        )
        .unwrap();

        let valid = extended.with_policy(&policy, None).unwrap();
        assert_eq!(
            valid
                .keys()
                .subkeys()
                .alive()
                .for_transport_encryption()
                .count(),
            1,
            "the encryption subkey lapsed while the pane showed the new date"
        );
    }

    /// The same failure, for the subkey it costs the most. A signing subkey
    /// does countersign its own binding, so with no secret to countersign
    /// with, the loop used to skip it and report success: the pane showed the
    /// new date, and the user's signatures stopped verifying as live on the
    /// original one.
    ///
    /// The countersignature already on the binding is what makes this
    /// unnecessary. It covers the pair of keys and says nothing about the
    /// binding carrying it, so the replacement can keep it.
    #[test]
    fn a_signing_subkey_without_a_local_secret_is_still_re_dated() {
        use sequoia_openpgp::policy::StandardPolicy;
        use sequoia_openpgp::{Packet, cert::CertBuilder};
        let policy = StandardPolicy::new();

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let (cert, _) = CertBuilder::new()
            .add_userid("Alice <alice@example.org>")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .set_validity_period(Duration::from_secs(1))
            .generate()
            .unwrap();

        // The signing subkey this time, the way a key whose signing half was
        // moved to another machine arrives.
        let signing = cert
            .with_policy(&policy, None)
            .unwrap()
            .keys()
            .subkeys()
            .for_signing()
            .next()
            .unwrap()
            .key()
            .fingerprint();
        let stripped: Vec<Packet> = cert
            .as_tsk()
            .into_packets()
            .map(|p| match p {
                Packet::SecretSubkey(k) if k.fingerprint() == signing => {
                    Packet::PublicSubkey(k.take_secret().0)
                }
                other => other,
            })
            .collect();
        let cert = Cert::try_from(stripped).unwrap();
        store.insert_secret(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        std::thread::sleep(Duration::from_millis(1500));

        let extended = set_expiry(
            &store,
            &fingerprint,
            Some(Duration::from_secs(31_536_000)),
            None,
        )
        .unwrap();

        let valid = extended.with_policy(&policy, None).unwrap();
        assert_eq!(
            valid.keys().subkeys().alive().for_signing().count(),
            1,
            "the signing subkey lapsed while the pane showed the new date"
        );
        assert_eq!(
            valid
                .keys()
                .subkeys()
                .for_signing()
                .next()
                .unwrap()
                .binding_signature()
                .embedded_signatures()
                .count(),
            1,
            "which works only because the countersignature was carried over"
        );
        // A reload reads the store, not the value returned here.
        let stored = store.secret_cert(&fingerprint).unwrap();
        assert_eq!(
            stored
                .with_policy(&policy, None)
                .unwrap()
                .keys()
                .subkeys()
                .alive()
                .for_signing()
                .count(),
            1
        );
    }

    /// `SystemTime + Duration` panics on overflow, and `expires_in` is an
    /// argument a caller chooses. The GUI offers one, two and five years, so
    /// nothing in the app can reach this; the argument is still part of what
    /// this function offers to take, and a panic is not an answer to it.
    #[test]
    fn an_expiry_too_far_in_the_future_is_refused_rather_than_panicking() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        let before = CertSummary::from_cert(&cert).expires;

        assert!(set_expiry(&store, &fingerprint, Some(Duration::MAX), None).is_err());
        assert_eq!(
            CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap()).expires,
            before,
            "a refused change must not reach the store"
        );
    }

    /// The subkeys, not just the primary. Sequoia's primary-key call leaves
    /// subkey bindings untouched, and the older tests only ever looked at
    /// `CertSummary::expires`, which reads the primary — so a certificate
    /// whose subkeys had all lapsed passed them.
    #[test]
    fn extending_expiry_extends_every_subkey() {
        use sequoia_openpgp::policy::StandardPolicy;
        let policy = StandardPolicy::new();

        // Generated with a one-second lifetime, so primary AND subkeys lapse
        // together — the way a real key does years in. Shortening via
        // set_expiry would not do: it only ever moved the primary, which is
        // the very bug, so the subkeys would never have expired.
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let mut request = KeyGenRequest::new("Alice <alice@example.org>");
        request.validity = Some(Duration::from_secs(1));
        let cert = generate(&request).unwrap().cert;
        store.insert_secret(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        std::thread::sleep(Duration::from_millis(1500));

        // Precondition: everything really has lapsed.
        let lapsed = cert.with_policy(&policy, None).unwrap();
        assert!(lapsed.keys().subkeys().all(|ka| ka.alive().is_err()));

        let year = Duration::from_secs(365 * 24 * 60 * 60);
        let revived = set_expiry(&store, &fingerprint, Some(year), None).unwrap();
        let valid = revived.with_policy(&policy, None).unwrap();

        let subkeys: Vec<_> = valid.keys().subkeys().collect();
        assert!(!subkeys.is_empty(), "the generated key has subkeys");
        for ka in &subkeys {
            assert!(
                ka.alive().is_ok(),
                "subkey {} is still expired after the certificate was extended",
                ka.key().fingerprint()
            );
        }
        // What the user actually needs to still work.
        assert!(
            valid
                .keys()
                .subkeys()
                .alive()
                .for_signing()
                .next()
                .is_some(),
            "no live signing subkey"
        );
        assert!(
            valid
                .keys()
                .subkeys()
                .alive()
                .for_transport_encryption()
                .next()
                .is_some(),
            "no live encryption subkey"
        );
    }

    #[test]
    fn revives_a_lapsed_certificate() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        // Expire it a second from now, then push the expiry back out.
        set_expiry(&store, &fingerprint, Some(Duration::from_secs(1)), None).unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        let lapsed = store.secret_cert(&fingerprint).unwrap();
        assert_eq!(CertSummary::from_cert(&lapsed).validity, Validity::Expired);

        let year = Duration::from_secs(365 * 24 * 60 * 60);
        let revived = set_expiry(&store, &fingerprint, Some(year), None).unwrap();
        assert_eq!(CertSummary::from_cert(&revived).validity, Validity::Valid);
    }

    #[test]
    fn adds_a_user_id() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        let updated =
            add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).unwrap();
        let ids: Vec<String> = cert::user_ids(&updated)
            .iter()
            .map(|u| u.text.clone())
            .collect();
        assert!(ids.iter().any(|u| u == "Alice <alice@work.example>"));
        assert!(ids.iter().any(|u| u == "Alice <alice@example.org>"));

        // Adding the same identity twice is refused rather than duplicated.
        assert!(add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).is_err());
        assert!(add_user_id(&store, &fingerprint, "   ", None).is_err());
    }

    /// Pinning the primary identity means re-issuing its binding, and a
    /// re-issued self-signature has to supersede the one it replaces. Signature
    /// timestamps are whole seconds and a self-signature supersedes only one
    /// made strictly earlier, so a binding written in the same second as the
    /// one it replaces ties, and sequoia settles the tie by comparing the two
    /// signatures' MPIs. Losing that toss leaves the primary user ID unclaimed
    /// and hands the title to the name just added, which is what pinning it
    /// exists to prevent.
    ///
    /// The binding is replaced in the same second on purpose: the call follows
    /// it immediately, the way a second click does.
    #[test]
    fn the_re_issued_primary_binding_supersedes_the_one_it_replaces() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        let policy = policy();

        // Reshape the key to look like one that came in through Import: re-bind
        // its user ID with a signature claiming no primary user ID, so that
        // adding a name has to pin it. The wait is what makes this binding the
        // active one rather than a tie with the one keygen made.
        std::thread::sleep(Duration::from_millis(1100));
        let secret = store.secret_cert(&fingerprint).unwrap();
        let userid = secret.userids().next().unwrap().userid().clone();
        let mut signer = unlock_primary(&secret, None).unwrap();
        let unflagged = SignatureBuilder::new(SignatureType::PositiveCertification)
            .sign_userid_binding(&mut signer, secret.primary_key().key(), &userid)
            .unwrap();
        let replaced = unflagged.signature_creation_time().unwrap();
        let reshaped = secret
            .insert_packets(vec![Packet::from(unflagged)])
            .unwrap()
            .0;
        store.insert_secret(&reshaped).unwrap();
        assert!(
            reshaped
                .with_policy(&policy, None)
                .unwrap()
                .primary_userid()
                .unwrap()
                .binding_signature()
                .primary_userid()
                .is_none(),
            "the point of the shape is a binding that claims nothing"
        );

        let updated =
            add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).unwrap();

        let pinned = updated
            .userids()
            .find(|ua| ua.userid() == &userid)
            .expect("the identity is still there")
            .self_signatures()
            .filter(|sig| sig.primary_userid() == Some(true))
            .filter_map(|sig| sig.signature_creation_time())
            .max()
            .expect("the primary identity must be pinned");
        assert!(
            pinned > replaced,
            "the pinned binding ties with the one it replaces and may lose the tie"
        );
        assert_eq!(
            updated
                .with_policy(&policy, None)
                .unwrap()
                .primary_userid()
                .unwrap()
                .userid(),
            &userid,
            "the primary identity must not move, during that second or after it"
        );
    }

    /// `SignatureBuilder::from` carries the template's unhashed area across
    /// wholesale, dropping only the creation time and the issuers. Nothing
    /// covers that area, so anyone who handled the certificate on its way here
    /// could have appended to it, and stripping the hashed area alone left a
    /// stranger's packet sitting inside a signature this key had just made and
    /// published it under the owner's name.
    ///
    /// Two are planted, because emptying that area is a wider claim than the
    /// strip list. An embedded signature is the one that bites: sequoia reads it
    /// out of the unhashed area as readily as out of the hashed one. A preferred
    /// key server stands for everything else that can be appended there and
    /// would have survived a strip by tag.
    #[test]
    fn a_new_binding_carries_nothing_that_was_appended_to_the_template() {
        use sequoia_openpgp::packet::signature::subpacket::{
            Subpacket, SubpacketTag, SubpacketValue,
        };

        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        let policy = policy();

        // Re-issue the primary user ID's binding from itself, so that it keeps
        // the flags and the primary-user-ID claim and is what `add_user_id`
        // templates from, and append the two packets to the unhashed area of
        // the re-issue. The wait is what makes the re-issue the active binding
        // rather than a tie with the one keygen made.
        std::thread::sleep(Duration::from_millis(1100));
        let secret = store.secret_cert(&fingerprint).unwrap();
        let mut signer = unlock_primary(&secret, None).unwrap();
        let planted = {
            let primary = secret
                .with_policy(&policy, None)
                .unwrap()
                .primary_userid()
                .unwrap();
            let userid = primary.userid().clone();
            let original = primary.binding_signature().clone();
            let mut planted = SignatureBuilder::from(original.clone())
                .sign_userid_binding(&mut signer, secret.primary_key().key(), &userid)
                .unwrap();
            planted
                .unhashed_area_mut()
                .add(Subpacket::new(SubpacketValue::EmbeddedSignature(original), false).unwrap())
                .unwrap();
            planted
                .unhashed_area_mut()
                .add(
                    Subpacket::new(
                        SubpacketValue::PreferredKeyServer(b"hkps://elsewhere.invalid".to_vec()),
                        false,
                    )
                    .unwrap(),
                )
                .unwrap();
            planted
        };
        let reshaped = secret
            .insert_packets(vec![Packet::from(planted)])
            .unwrap()
            .0;
        store.insert_secret(&reshaped).unwrap();
        let appended = [
            SubpacketTag::EmbeddedSignature,
            SubpacketTag::PreferredKeyServer,
        ];
        for tag in appended {
            assert!(
                reshaped
                    .with_policy(&policy, None)
                    .unwrap()
                    .primary_userid()
                    .unwrap()
                    .binding_signature()
                    .unhashed_area()
                    .subpacket(tag)
                    .is_some(),
                "the template must carry {tag:?}, or this proves nothing"
            );
        }

        let updated =
            add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).unwrap();
        let binding = updated
            .userids()
            .find(|ua| String::from_utf8_lossy(ua.userid().value()) == "Alice <alice@work.example>")
            .expect("the new identity is on the key")
            .self_signatures()
            .next()
            .expect("with a binding signature")
            .clone();
        for tag in appended {
            assert!(
                binding.hashed_area().subpacket(tag).is_none()
                    && binding.unhashed_area().subpacket(tag).is_none(),
                "a new binding must carry no {tag:?} that was appended to the one it was \
                 copied from"
            );
        }
    }

    /// Pinning an identity is a binding signature dated now, and sequoia
    /// settles a user ID's revocation status from the newest binding over it:
    /// a soft revocation loses to a binding made later. UIDRetired, which is
    /// what retiring a name writes here, is soft. So on a certificate whose
    /// identities have all been withdrawn — the primary one included, since
    /// sequoia still names one of them primary when no other is left — pinning
    /// put the retired address back into service, claimed it as the primary
    /// identity, and wrote that to both halves of the store and into whatever
    /// was published next. Adding an address is exactly when a key is in that
    /// state: retire the old name, then add the new one.
    ///
    /// This is the harm the guard at the top of `add_user_id` exists to
    /// prevent, one level down. That guard asks whether the certificate is
    /// revoked, and here it is not — only its identities are.
    #[test]
    fn adding_a_user_id_does_not_bring_a_retired_identity_back() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        // The shape that pins: a binding claiming no primary user ID, as an
        // imported key has. The wait is what makes this binding the active one
        // rather than a tie with the one keygen made.
        std::thread::sleep(Duration::from_millis(1100));
        let secret = store.secret_cert(&fingerprint).unwrap();
        let userid = secret.userids().next().unwrap().userid().clone();
        let mut signer = unlock_primary(&secret, None).unwrap();
        let unflagged = SignatureBuilder::new(SignatureType::PositiveCertification)
            .sign_userid_binding(&mut signer, secret.primary_key().key(), &userid)
            .unwrap();

        // Retired with the reason this app writes by default, and built here
        // rather than through `revoke_user_id`, which refuses to take the last
        // live name away.
        let retirement = UserIDRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"left the job")
            .unwrap()
            .build(&mut signer, &secret, &userid, None)
            .unwrap();
        let retired_at = retirement.signature_creation_time().unwrap();
        let reshaped = secret
            .insert_packets(vec![Packet::from(unflagged), Packet::from(retirement)])
            .unwrap()
            .0;
        store.insert_secret(&reshaped).unwrap();
        assert!(
            cert::user_ids(&reshaped).iter().all(|u| u.revoked),
            "the shape under test is a key with no identity left standing"
        );

        // A binding written in the same second as the revocation ties with it
        // and the revocation stands, so without this wait whether the harm
        // happens at all would depend on which second the call landed in.
        std::thread::sleep(Duration::from_millis(1100));
        let updated =
            add_user_id(&store, &fingerprint, "Alice <alice@newjob.example>", None).unwrap();

        for reloaded in [
            updated,
            store.secret_cert(&fingerprint).unwrap(),
            store.lookup(&fingerprint).unwrap(),
        ] {
            let ids = cert::user_ids(&reloaded);
            let retired = ids
                .iter()
                .find(|u| u.text == "Alice <alice@example.org>")
                .expect("a retired identity stays on the key");
            assert!(retired.revoked, "a retired identity must stay retired");
            assert!(
                !retired.is_primary,
                "a retired identity must not be named the primary one"
            );
            assert!(
                ids.iter().any(|u| u.text == "Alice <alice@newjob.example>"
                    && u.is_primary
                    && !u.revoked),
                "the name just added is the only one standing, so it is the primary one"
            );

            // Nothing new was signed over the retired name at all: skipping the
            // pin is the fix, not out-dating it.
            assert!(
                reloaded
                    .userids()
                    .find(|ua| ua.userid() == &userid)
                    .expect("a retired identity stays on the key")
                    .self_signatures()
                    .all(|sig| sig.signature_creation_time() <= Some(retired_at)),
                "no binding may be written over an identity its owner has retired"
            );
        }
    }

    #[test]
    fn revokes_one_subkey_and_leaves_the_others() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        let before = cert::subkeys(&cert);
        assert!(before.len() > 1, "the test key should have several subkeys");
        let victim = before[0].fingerprint.clone();

        let updated = revoke_subkey(
            &store,
            &fingerprint,
            &victim,
            Reason::Compromised,
            "secret exposed",
            None,
        )
        .unwrap();

        let after = cert::subkeys(&updated);
        assert!(
            after
                .iter()
                .find(|k| k.fingerprint == victim)
                .is_some_and(|k| k.revoked),
            "the named subkey should be revoked"
        );
        assert!(
            after
                .iter()
                .filter(|k| k.fingerprint != victim)
                .all(|k| !k.revoked),
            "no other subkey should be touched"
        );
        // The certificate itself is still usable.
        assert_eq!(CertSummary::from_cert(&updated).validity, Validity::Valid);

        assert!(
            revoke_subkey(
                &store,
                &fingerprint,
                &fingerprint,
                Reason::Retired,
                "",
                None
            )
            .is_err()
        );
    }

    #[test]
    fn revokes_a_user_id_but_keeps_it_visible() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        // The last remaining identity cannot be revoked on its own.
        assert!(
            revoke_user_id(&store, &fingerprint, "Alice <alice@example.org>", "", None).is_err()
        );

        add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).unwrap();
        let updated = revoke_user_id(
            &store,
            &fingerprint,
            "Alice <alice@work.example>",
            "left the job",
            None,
        )
        .unwrap();

        let ids = cert::user_ids(&updated);
        let revoked = ids
            .iter()
            .find(|u| u.text == "Alice <alice@work.example>")
            .expect("a revoked user ID stays on the key");
        assert!(revoked.revoked);
        assert!(
            ids.iter()
                .any(|u| u.text == "Alice <alice@example.org>" && !u.revoked)
        );
    }

    /// The same guard, over the shape that used to walk straight through it.
    ///
    /// It counted `cert.userids()`, which is every user ID the certificate
    /// carries — including ones retired years ago, and ones with no binding
    /// signature at all, which sequoia keeps and anyone can append in flight.
    /// A key whose second identity was already revoked therefore had two by
    /// that count and one in fact, and retiring the survivor left a certificate
    /// with no live name on it: precisely what the message this returns
    /// promises will not happen.
    #[test]
    fn refuses_to_revoke_the_last_live_user_id_when_another_is_already_revoked() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).unwrap();
        revoke_user_id(
            &store,
            &fingerprint,
            "Alice <alice@work.example>",
            "left the job",
            None,
        )
        .unwrap();

        let refused = revoke_user_id(&store, &fingerprint, "Alice <alice@example.org>", "", None)
            .map(|_| ())
            .expect_err("retired the only identity the key had left");
        assert!(
            refused.to_string().contains("only user ID"),
            "the refusal must say why: {refused}"
        );

        let ids = cert::user_ids(&store.secret_cert(&fingerprint).unwrap());
        assert!(
            ids.iter()
                .any(|u| u.text == "Alice <alice@example.org>" && !u.revoked),
            "a refused revocation must not reach the store"
        );
    }

    /// A store holding nothing but `secret` with its signatures taken away,
    /// which leaves a certificate the standard policy cannot evaluate:
    /// `with_policy` wants a binding signature for the primary key and there is
    /// none. Sequoia keeps the names, as it keeps any user ID with no binding.
    ///
    /// That is the same state, as far as this guard can tell, as the key the
    /// guard is really about: one whose self-signatures are all SHA-1, which
    /// the standard policy has rejected on a user ID binding since February
    /// 2023. The SHA-1 key is what a test would rather use and cannot — the
    /// crypto backend refuses to make a SHA-1 signature to order — and what the
    /// guard sees of either is the one thing that matters, a `with_policy` that
    /// fails.
    ///
    /// A store of its own because `insert_secret` merges with whatever the
    /// secret file already holds, as it must: a store that had already seen the
    /// signed certificate would hand the signatures straight back, and the
    /// premise this rests on is asserted against what the store returns rather
    /// than what was handed to it.
    fn stored_unreadable(secret: &Cert) -> (tempfile::TempDir, Store) {
        // Through the TSK, because `Cert::into_packets` hands back the public
        // half alone and the store will not take a certificate with no secret
        // in it.
        let stripped = Cert::from_packets(
            secret
                .as_tsk()
                .into_packets()
                .filter(|packet| !matches!(packet, Packet::Signature(_))),
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        store.insert_secret(&stripped).unwrap();
        assert!(
            store
                .secret_cert(&secret.fingerprint().to_hex())
                .unwrap()
                .with_policy(&policy(), None)
                .is_err(),
            "the stored certificate must be one the policy cannot read, or this proves nothing"
        );
        (dir, store)
    }

    /// The guard has to know which identities are still standing, and on a
    /// certificate the standard policy cannot evaluate there is no answer to
    /// that. Refusing outright there would take away the only way this app
    /// offers of retiring an address on a legacy key: the details dialog still
    /// lists such a key's identities and still offers Revoke on every row of
    /// it, since none of them reads as primary or as revoked, so every click
    /// would come back talking about the standard policy. The count this
    /// replaces is taken instead, which leaves that key exactly the operation
    /// it has always had — crude, but a retirement it lets through is one it
    /// has always let through.
    #[test]
    fn retiring_an_identity_still_works_on_a_key_the_policy_cannot_read() {
        let (_scratch_dir, scratch_store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();
        add_user_id(
            &scratch_store,
            &fingerprint,
            "Alice <alice@work.example>",
            None,
        )
        .unwrap();

        let (_dir, store) = stored_unreadable(&scratch_store.secret_cert(&fingerprint).unwrap());
        revoke_user_id(
            &store,
            &fingerprint,
            "Alice <alice@work.example>",
            "left the job",
            None,
        )
        .expect("a legacy key keeps the retirement it has always had");
        assert!(
            store
                .secret_cert(&fingerprint)
                .unwrap()
                .userids()
                .find(|ua| String::from_utf8_lossy(ua.userid().value())
                    == "Alice <alice@work.example>")
                .expect("the retired name stays on the key")
                .self_revocations()
                .next()
                .is_some(),
            "the retirement must reach the store"
        );

        // And the count is still a guard where it can answer at all: one
        // identity on a key nothing can read is still the only one it has.
        let last = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let last_fingerprint = last.fingerprint().to_hex();
        let (_last_dir, last_store) = stored_unreadable(&last);
        let refused = revoke_user_id(
            &last_store,
            &last_fingerprint,
            "Alice <alice@example.org>",
            "",
            None,
        )
        .map(|_| ())
        .expect_err("retired the only identity a legacy key had");
        assert!(
            refused.to_string().contains("only user ID"),
            "the refusal must say why: {refused}"
        );
    }

    /// `certify`'s rule, on the path that retires an identity of your own.
    ///
    /// The details dialog renders every user ID lossily and hands that text
    /// back when Revoke is clicked, and sequoia orders user IDs by their raw
    /// bytes — so of two that display alike the lower-sorting one was retired,
    /// whichever row the user clicked. The dialog hides Revoke on the primary
    /// identity and on rows already revoked, so the click could retire an
    /// identity the user was never offered the choice of retiring, or add a
    /// second revocation to one already gone and report success while the row
    /// they clicked stayed live. Neither is undoable from here: `add_user_id`
    /// takes a `&str` and cannot put the invalid bytes back.
    #[test]
    fn revoking_a_user_id_refuses_a_name_that_matches_two_of_them() {
        let (_dir, store, cert) = scratch();
        let fingerprint = cert.fingerprint().to_hex();

        // Two more user IDs, different bytes, identical rendering: 0xFE and
        // 0xFF are both invalid UTF-8 and both display as U+FFFD. A key like
        // this is imported, not made here — a legacy Latin-1 GnuPG key is the
        // usual way to come by one.
        let secret = store.secret_cert(&fingerprint).unwrap();
        let mut signer = unlock_primary(&secret, None).unwrap();
        let mut packets: Vec<Packet> = Vec::new();
        for byte in [0xFEu8, 0xFF] {
            let userid = UserID::from([b"Alice <alice@", &[byte][..], b".example>"].concat());
            let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
                .sign_userid_binding(&mut signer, secret.primary_key().key(), &userid)
                .unwrap();
            packets.push(Packet::from(userid));
            packets.push(Packet::from(binding));
        }
        store
            .insert_secret(&secret.insert_packets(packets).unwrap().0)
            .unwrap();

        let displayed = String::from_utf8_lossy(
            &[b"Alice <alice@".to_vec(), vec![0xFE], b".example>".to_vec()].concat(),
        )
        .into_owned();

        let refused = revoke_user_id(&store, &fingerprint, &displayed, "", None)
            .map(|_| ())
            .expect_err("retired one of two identities that display alike");
        assert!(
            refused.to_string().contains("more than one user ID"),
            "an ambiguous identity must be refused, not guessed at: {refused}"
        );
        assert!(
            cert::user_ids(&store.secret_cert(&fingerprint).unwrap())
                .iter()
                .all(|u| !u.revoked),
            "a refused revocation must not reach the store"
        );

        // An unambiguous one is still retired, or this is only a wall.
        add_user_id(&store, &fingerprint, "Alice <alice@work.example>", None).unwrap();
        let updated = revoke_user_id(
            &store,
            &fingerprint,
            "Alice <alice@work.example>",
            "left the job",
            None,
        )
        .unwrap();
        assert!(
            cert::user_ids(&updated)
                .iter()
                .any(|u| u.text == "Alice <alice@work.example>" && u.revoked)
        );
    }
}
