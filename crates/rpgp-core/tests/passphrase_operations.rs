//! Every operation that unlocks a passphrase-protected key, run against both
//! OpenPGP profiles.
//!
//! These exist because of a bug only one profile could show. An RFC 9580
//! secret is AEAD-protected and the packet tag feeding the AEAD schedule
//! depends on the key's role, so a key whose role had been erased with
//! `role_into_unspecified` could not be decrypted at all — sequoia answers
//! *cannot decrypt key with unspecified role*. RFC 4880 keys use CFB, never
//! consult the role, and passed regardless. RFC 9580 being rpgp's default,
//! changing the expiry of, adding a user ID to, or revoking a
//! passphrase-protected key failed for anyone who had not opted out of it.
//!
//! So every test here loops over [`Standard::ALL`] rather than taking the
//! default. Testing one profile is what let that through, and a new profile
//! added to the enum is picked up here automatically.

use std::time::Duration;

use rpgp_core::keygen::{KeyGenRequest, Standard, generate};
use rpgp_core::{CertSummary, Store, Validity, certify, lifecycle, ops, revoke};
use sequoia_openpgp::Cert;

const PASSPHRASE: &str = "correct horse";

fn scratch() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
    (dir, store)
}

/// A passphrase-protected key of `standard`, in the store.
fn protected_key(store: &Store, standard: Standard, user_id: &str) -> Cert {
    let mut request = KeyGenRequest::new(user_id);
    request.standard = standard;
    request.password = Some(PASSPHRASE.to_string().into());
    let cert = generate(&request).unwrap().cert;
    store.insert_secret(&cert).unwrap();
    cert
}

/// Runs `case` against every profile, naming the profile if it fails.
fn for_each_profile(case: impl Fn(Standard, &Store) -> Result<(), String>) {
    for standard in Standard::ALL {
        let (_dir, store) = scratch();
        if let Err(e) = case(standard, &store) {
            panic!("{standard:?}: {e}");
        }
    }
}

#[test]
fn set_expiry() {
    for_each_profile(|standard, store| {
        let cert = protected_key(store, standard, "Alice <alice@example.org>");
        let updated = lifecycle::set_expiry(
            store,
            &cert.fingerprint().to_hex(),
            Some(Duration::from_secs(60 * 60 * 24 * 30)),
            Some(PASSPHRASE),
        )
        .map_err(|e| format!("set_expiry: {e}"))?;
        // The expiry has to have *moved*, not merely be present: KeyGenRequest
        // defaults to two years, so `is_some()` held before the call and would
        // hold with set_expiry replaced by a function that returns the
        // certificate untouched.
        let before = CertSummary::from_cert(&cert).expires;
        let after = CertSummary::from_cert(&updated).expires;
        assert!(after.is_some(), "the key should still expire");
        assert_ne!(
            before, after,
            "set_expiry must change the expiry, not just return a certificate"
        );
        Ok(())
    });
}

#[test]
fn add_and_revoke_a_user_id() {
    for_each_profile(|standard, store| {
        let cert = protected_key(store, standard, "Alice <alice@example.org>");
        let fingerprint = cert.fingerprint().to_hex();
        const SECOND: &str = "Alice <alice@example.net>";

        lifecycle::add_user_id(store, &fingerprint, SECOND, Some(PASSPHRASE))
            .map_err(|e| format!("add_user_id: {e}"))?;
        lifecycle::revoke_user_id(
            store,
            &fingerprint,
            SECOND,
            "no longer mine",
            Some(PASSPHRASE),
        )
        .map_err(|e| format!("revoke_user_id: {e}"))?;
        Ok(())
    });
}

#[test]
fn revoke_a_subkey() {
    for_each_profile(|standard, store| {
        let cert = protected_key(store, standard, "Alice <alice@example.org>");
        let subkey = cert
            .keys()
            .subkeys()
            .next()
            .expect("generated key has subkeys")
            .key()
            .fingerprint()
            .to_hex();

        lifecycle::revoke_subkey(
            store,
            &cert.fingerprint().to_hex(),
            &subkey,
            revoke::Reason::Retired,
            "rotating",
            Some(PASSPHRASE),
        )
        .map_err(|e| format!("revoke_subkey: {e}"))?;
        Ok(())
    });
}

#[test]
fn revoke_the_certificate() {
    for_each_profile(|standard, store| {
        let cert = protected_key(store, standard, "Alice <alice@example.org>");
        let request = revoke::RevokeRequest {
            fingerprint: cert.fingerprint().to_hex(),
            reason: revoke::Reason::Retired,
            message: "no longer used".into(),
            password: Some(PASSPHRASE.to_string().into()),
        };
        let revoked =
            revoke::revoke_cert(store, &request).map_err(|e| format!("revoke_cert: {e}"))?;
        assert_eq!(CertSummary::from_cert(&revoked).validity, Validity::Revoked);
        Ok(())
    });
}

#[test]
fn certify_and_retract() {
    for_each_profile(|standard, store| {
        let alice = protected_key(store, standard, "Alice <alice@example.org>");
        let bob = protected_key(store, standard, "Bob <bob@example.org>");
        let (certifier, target) = (alice.fingerprint().to_hex(), bob.fingerprint().to_hex());
        let user_ids = vec!["Bob <bob@example.org>".to_string()];

        certify::certify(
            store,
            &certify::CertifyRequest {
                certifier: certifier.clone(),
                target: target.clone(),
                user_ids: user_ids.clone(),
                exportable: true,
                depth: 0,
                amount: certify::FULL,
                expires: None,
                password: Some(PASSPHRASE.to_string().into()),
            },
        )
        .map_err(|e| format!("certify: {e}"))?;

        revoke::revoke_certification(
            store,
            &certifier,
            &target,
            &user_ids,
            revoke::Reason::Retired,
            "withdrawn",
            Some(PASSPHRASE),
        )
        .map_err(|e| format!("revoke_certification: {e}"))?;
        Ok(())
    });
}

#[test]
fn sign_detached_and_cleartext() {
    for_each_profile(|standard, store| {
        let cert = protected_key(store, standard, "Alice <alice@example.org>");
        const DATA: &[u8] = b"the treaty text";

        let mut detached = Vec::new();
        ops::sign_detached(&cert, Some(PASSPHRASE), DATA, &mut detached)
            .map_err(|e| format!("sign_detached: {e}"))?;
        let result = ops::verify_detached(store, &detached, DATA)
            .map_err(|e| format!("verify_detached: {e}"))?;
        assert!(
            result.all_good(),
            "detached signature did not verify: {:?}",
            result.signatures
        );

        let mut cleartext = Vec::new();
        ops::sign_cleartext(&cert, Some(PASSPHRASE), DATA, &mut cleartext)
            .map_err(|e| format!("sign_cleartext: {e}"))?;
        let (body, result) =
            ops::verify_inline(store, &cleartext).map_err(|e| format!("verify_inline: {e}"))?;
        assert_eq!(body, DATA);
        assert!(
            result.all_good(),
            "cleartext signature did not verify: {:?}",
            result.signatures
        );
        Ok(())
    });
}

/// The round trip that exercises both halves at once: a v6 recipient gets
/// SEIPDv2 with AEAD, and unlocking the key to read it back is the AEAD path
/// that the role bug broke.
#[test]
fn encrypt_signed_then_decrypt() {
    for_each_profile(|standard, store| {
        let cert = protected_key(store, standard, "Alice <alice@example.org>");
        const PLAINTEXT: &[u8] = b"meet at the usual place";

        let mut ciphertext = Vec::new();
        ops::encrypt(
            std::slice::from_ref(&cert),
            &[],
            Some((&cert, Some(PASSPHRASE))),
            PLAINTEXT,
            &mut ciphertext,
        )
        .map_err(|e| format!("encrypt: {e}"))?;
        assert_ne!(ciphertext, PLAINTEXT);

        let mut recovered = Vec::new();
        let result = ops::decrypt(store, &ciphertext, &[PASSPHRASE], &mut recovered)
            .map_err(|e| format!("decrypt: {e}"))?;
        assert_eq!(recovered, PLAINTEXT);
        assert!(
            result.all_good(),
            "the signature did not verify: {:?}",
            result.signatures
        );
        Ok(())
    });
}

/// The fix preserves a key's role; it must not have weakened the check.
#[test]
fn a_wrong_or_missing_passphrase_is_refused() {
    for_each_profile(|standard, store| {
        let cert = protected_key(store, standard, "Alice <alice@example.org>");
        let fingerprint = cert.fingerprint().to_hex();

        for wrong in [None, Some(""), Some("hunter2")] {
            assert!(
                lifecycle::set_expiry(store, &fingerprint, None, wrong).is_err(),
                "set_expiry accepted {wrong:?}",
            );
            assert!(
                ops::sign_detached(&cert, wrong, b"x", Vec::new()).is_err(),
                "sign_detached accepted {wrong:?}",
            );
            assert!(
                revoke::revoke_cert(
                    store,
                    &revoke::RevokeRequest {
                        fingerprint: fingerprint.clone(),
                        reason: revoke::Reason::Retired,
                        message: String::new(),
                        password: wrong.map(|p| p.to_string().into()),
                    },
                )
                .is_err(),
                "revoke_cert accepted {wrong:?}",
            );
        }
        Ok(())
    });
}
