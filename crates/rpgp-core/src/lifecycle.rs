//! Owning a key over time: changing when it expires, and managing the
//! identities bound to it.
//!
//! All three operations here are new self-signatures by the certificate's own
//! primary key. None of them removes anything: OpenPGP has no delete, only
//! newer signatures that supersede older ones and revocations that retract
//! them. A user ID "removed" from a key is a user ID everyone else still has.

use std::time::{Duration, SystemTime};

use sequoia_openpgp::cert::{SubkeyRevocationBuilder, UserIDRevocationBuilder};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::types::{ReasonForRevocation, SignatureType};
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
    let policy = policy();
    let mut signer = unlock_primary(&cert, password)?;

    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| Error::invalid("this certificate is not valid under the standard policy"))?;

    let expiration = expires_in.map(|d| SystemTime::now() + d);

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
    // A subkey that can certify, sign or authenticate has to countersign its
    // own new binding (the primary key binding signature, or "back-sig"), so
    // it needs its own signer; anything else must be passed none. That is
    // sequoia's condition verbatim, and it refuses either mismatch. Testing
    // for_signing() alone missed authentication subkeys, so every GnuPG
    // [S][E][A] key — which is what `gpg --export-secret-keys` produces —
    // failed the whole change with "requires subkey signer", naming a
    // capability the subkey does not have. Keys generated here have only
    // [S] and [E], so nothing in the tree exercised it.
    //
    // Revoked subkeys are left alone: a new expiry on a revoked key is noise.
    // Subkeys with no local secret are not filtered out up front, because an
    // encryption subkey does not need one — only the primary signs its
    // binding — and skipping it left it to lapse on the original date while
    // the pane showed the new one. Only the back-sig branch needs it.
    for ka in valid.keys().subkeys().revoked(false) {
        let needs_backsig = ka.for_signing() || ka.for_certification() || ka.for_authentication();
        let mut subkey_signer = if needs_backsig {
            let Ok(secret) = ka.key().clone().parts_into_secret() else {
                continue;
            };
            Some(crate::secret::keypair(secret, password)?)
        } else {
            None
        };
        let subkey_signer = subkey_signer
            .as_mut()
            .map(|s| s as &mut dyn sequoia_openpgp::crypto::Signer);
        signatures.extend(
            ka.set_expiration_time(&mut signer, subkey_signer, expiration)
                .map_err(Error::OpenPgp)?,
        );
    }

    store_both(store, cert, signatures)
}

/// Bind a new identity to a certificate.
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
    if cert
        .userids()
        .any(|ua| String::from_utf8_lossy(ua.userid().value()) == user_id)
    {
        return Err(Error::invalid(format!("{user_id} is already on this key")));
    }

    let mut signer = unlock_primary(&cert, password)?;
    let userid = UserID::from(user_id);
    let binding = SignatureBuilder::new(SignatureType::PositiveCertification).sign_userid_binding(
        &mut signer,
        cert.primary_key().key(),
        &userid,
    )?;

    // secret_cert is where `cert` came from, so the certificate always has a
    // secret half here — the has_secret test that used to guard the write
    // could not be false. What followed it rebuilt the new user ID and its
    // binding out of `updated` and inserted them into `cert` a second time,
    // reconstructing a certificate that had already been built one line
    // above. insert_secret writes the public half itself, so one call does
    // what three did.
    let updated = cert
        .insert_packets(vec![Packet::from(userid), Packet::from(binding)])?
        .0;
    store.insert_secret(&updated)?;
    Ok(updated)
}

/// Retract one of a certificate's own identities.
///
/// The user ID stays on the key — it has to, so anyone holding an old copy can
/// see it was withdrawn rather than simply not knowing about it.
pub fn revoke_user_id(
    store: &Store,
    fingerprint: &str,
    user_id: &str,
    message: &str,
    password: Option<&str>,
) -> Result<Cert> {
    let cert = store.secret_cert(fingerprint)?;
    let userid = cert
        .userids()
        .map(|ua| ua.userid().clone())
        .find(|uid| String::from_utf8_lossy(uid.value()) == user_id)
        .ok_or_else(|| Error::invalid(format!("{user_id} is not a user ID on this key")))?;

    if cert.userids().count() < 2 {
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
}
