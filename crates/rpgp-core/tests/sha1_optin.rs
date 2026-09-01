//! The SHA-1 opt-in: what it unlocks, and — more importantly — what it does not.
//!
//! The fixture is the real thing rather than something synthesised, because
//! synthesising it is the hard part: sequoia will not readily *make* a
//! SHA-1-self-signed certificate, and a hand-rolled approximation would test
//! the approximation. `fixtures/sha1-cert.asc` is the Decred project's public
//! release key, published at <https://decred.org>, certified in 2016 and still
//! in use. Public key material only, and included for exactly the property that
//! makes it awkward: every self-signature on it is hashed with SHA-1, so
//! sequoia's standard policy finds no valid binding signature anywhere and the
//! certificate has no usable user ID or subkey at all.

use rpgp_core::{CertSummary, Store, Validity, cert, sha1, wot};
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;

const SHA1_CERT: &[u8] = include_bytes!("fixtures/sha1-cert.asc");

fn scratch() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
    (dir, store)
}

fn sha1_cert() -> Cert {
    Cert::from_bytes(SHA1_CERT).unwrap()
}

/// A modern certificate, to stand next to the old one.
fn modern_cert(store: &Store, user_id: &str) -> Cert {
    let cert = rpgp_core::keygen::generate(&rpgp_core::keygen::KeyGenRequest::new(user_id))
        .unwrap()
        .cert;
    store.insert_secret(&cert).unwrap();
    cert
}

/// The premise. If this ever fails the fixture has been replaced with a
/// certificate that is fine, and every other test here is vacuous.
#[test]
fn the_fixture_is_unusable_under_the_standard_policy() {
    let cert = sha1_cert();
    let summary = CertSummary::from_cert(&cert);

    assert_eq!(summary.validity, Validity::Unusable);
    // `is_primary` is the policy-derived half of a UserIdDetail — `self_signed`
    // deliberately reports the raw self-signature whether the policy accepts it
    // or not, so it is present here and is not the signal to assert on.
    assert!(
        cert::user_ids(&cert).iter().all(|u| !u.is_primary),
        "no user ID should bind under the standard policy"
    );
    // The name itself still shows: from_cert falls back to the unpoliced user
    // IDs so an unusable certificate is still identifiable in the list. What is
    // missing is any *policy* endorsement of it, which is what `is_primary`
    // reports above.
    assert!(
        cert::subkeys(&cert).is_empty(),
        "no subkey should bind under the standard policy"
    );
}

/// Unusable certificates are not all alike, and the UI needs to tell them
/// apart: offering a SHA-1 opt-in for a certificate that is broken some other
/// way would be an invitation to weaken the policy for nothing.
#[test]
fn a_sha1_certificate_reports_sha1_as_the_reason_and_a_broken_one_does_not() {
    assert!(
        CertSummary::from_cert(&sha1_cert()).sha1_blocked,
        "the fixture's problem is SHA-1, and it should say so"
    );
    assert!(sha1::blocked(&sha1_cert()));

    // A certificate with its self-signatures stripped is unusable too, but
    // accepting SHA-1 would not bring it back.
    let (_dir, store) = scratch();
    let stripped = Cert::from_packets(
        sha1_cert()
            .into_packets()
            .filter(|p| !matches!(p, sequoia_openpgp::Packet::Signature(_))),
    )
    .unwrap();
    let summary = CertSummary::from_cert(&stripped);
    assert_eq!(summary.validity, Validity::Unusable);
    assert!(
        !summary.sha1_blocked,
        "a certificate with no signatures at all is not a SHA-1 problem"
    );
    drop(store);
}

#[test]
fn opting_in_makes_the_certificate_usable_for_verification() {
    let (_dir, store) = scratch();
    let cert = sha1_cert();
    let fingerprint = cert.fingerprint().to_hex();
    store.insert(&cert).unwrap();

    // Before.
    assert!(store.sha1_policy().unwrap().is_strict());
    assert_eq!(
        CertSummary::from_cert_with(&cert, &store.sha1_policy().unwrap()).validity,
        Validity::Unusable
    );

    store.set_sha1_accepted(&fingerprint, true).unwrap();

    // After.
    let policy = store.sha1_policy().unwrap();
    assert!(!policy.is_strict());
    let summary = CertSummary::from_cert_with(&cert, &policy);
    assert_eq!(summary.validity, Validity::Valid);
    assert!(summary.can_sign, "the signing subkey should bind now");
    assert!(
        !cert::subkeys_with(&cert, &policy).is_empty(),
        "subkeys should bind now"
    );
    assert!(
        cert::user_ids_with(&cert, &policy)
            .iter()
            .any(|u| u.is_primary),
        "the user ID should bind now"
    );

    // And it is undoable.
    store.set_sha1_accepted(&fingerprint, false).unwrap();
    assert!(store.sha1_policy().unwrap().is_strict());
    assert_eq!(
        CertSummary::from_cert_with(&cert, &store.sha1_policy().unwrap()).validity,
        Validity::Unusable
    );
}

/// The property that makes this an opt-in for one certificate rather than a
/// policy downgrade: relaxing the rules for one certificate must leave every
/// other certificate judged exactly as strictly as before, in the very same
/// operation.
#[test]
fn the_opt_in_does_not_leak_to_other_certificates() {
    let (_dir, store) = scratch();
    let sha1 = sha1_cert();
    store.insert(&sha1).unwrap();
    let other = modern_cert(&store, "Someone Else <else@example.com>");

    // Opt in the *modern* key, which needs nothing, and check that the
    // SHA-1 one is not carried along with it.
    store
        .set_sha1_accepted(&other.fingerprint().to_hex(), true)
        .unwrap();

    let policy = store.sha1_policy().unwrap();
    assert!(!policy.is_strict(), "something is opted in");
    assert_eq!(
        CertSummary::from_cert_with(&sha1, &policy).validity,
        Validity::Unusable,
        "a certificate nobody opted in must stay strictly judged"
    );

    // And with both opted in, only then does the old one come back — proving
    // the previous assertion failed for want of *its own* entry rather than
    // because the mechanism was inert.
    store
        .set_sha1_accepted(&sha1.fingerprint().to_hex(), true)
        .unwrap();
    assert_eq!(
        CertSummary::from_cert_with(&sha1, &store.sha1_policy().unwrap()).validity,
        Validity::Valid
    );
}

/// The line the whole design is drawn around: an opted-in certificate may be
/// verified against, and may never be *authenticated*, no matter what else the
/// user does to it. Here it is opted in AND made an explicit trust root — the
/// most trusting configuration the UI can express — and the web of trust still
/// refuses to say the name is vouched for.
#[test]
fn the_opt_in_never_reaches_the_web_of_trust() {
    let (_dir, store) = scratch();
    let cert = sha1_cert();
    let fingerprint = cert.fingerprint().to_hex();
    store.insert(&cert).unwrap();

    store.set_sha1_accepted(&fingerprint, true).unwrap();
    store.set_trust_root(&fingerprint, true).unwrap();

    let certs: Vec<&Cert> = vec![&cert];
    let roots: Vec<String> = store.effective_roots().unwrap().into_iter().collect();
    assert!(
        roots.iter().any(|r| r.eq_ignore_ascii_case(&fingerprint)),
        "the certificate really is a trust root, so the test is not vacuous"
    );

    let authenticated = wot::authenticate_all(&certs, &roots);
    let vouched = authenticated
        .iter()
        .filter(|((fp, _), a)| {
            fp.eq_ignore_ascii_case(&fingerprint)
                && !matches!(a, rpgp_core::Authentication::Unknown)
        })
        .count();
    assert_eq!(
        vouched, 0,
        "a SHA-1 certificate must never authenticate a name, even as a trust root: {authenticated:?}"
    );
}

/// The opt-in list is a list of fingerprints and nothing more; a stale entry
/// for a key that has since been deleted must not break verification for
/// everything else.
#[test]
fn a_stale_opt_in_entry_is_ignored() {
    let (_dir, store) = scratch();
    store
        .set_sha1_accepted("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", true)
        .unwrap();

    let policy = store.sha1_policy().unwrap();
    assert!(
        policy.is_strict(),
        "an entry that resolves to no certificate contributes no keys"
    );
}

/// The other half of the problem, which the Decred fixture cannot show.
///
/// That certificate's *bindings* are SHA-1; its signatures, were it to make new
/// ones, need not be. The reverse case is a modern certificate that hashes the
/// message itself with SHA-1, and it is the more dangerous of the two: a
/// collision there forges the document rather than the key structure.
///
/// Both fixtures are made rather than found, because this build cannot make
/// them: sequoia's RustCrypto backend refuses to *create* a SHA-1 signature at
/// all — `new_hasher` returns `UnsupportedHashAlgorithm` — while still
/// verifying one, which is the asymmetry this whole feature lives in. So they
/// come from gpg:
///
/// ```text
/// gpg --quick-gen-key 'SHA1 Test <sha1@example.invalid>' rsa2048 sign never
/// printf 'the quick brown fox' > data
/// gpg --digest-algo SHA1 --detach-sign --armor -o sha1-detached.asc data
/// gpg --export --armor sha1@example.invalid > sha1-signer.asc
/// ```
///
/// The key's own self-signature is SHA-512, so the only weak thing in play is
/// the message hash. Public key material only; the secret half was thrown away
/// with the scratch keyring.
mod sha1_message_hash {
    use super::*;

    const SIGNER: &[u8] = include_bytes!("fixtures/sha1-signer.asc");
    const SIGNATURE: &[u8] = include_bytes!("fixtures/sha1-detached.asc");
    const DATA: &[u8] = b"the quick brown fox";

    #[test]
    fn the_signer_itself_is_sound_so_only_the_message_hash_is_in_question() {
        let cert = Cert::from_bytes(SIGNER).unwrap();
        let summary = CertSummary::from_cert(&cert);
        assert_eq!(
            summary.validity,
            Validity::Valid,
            "the fixture signer must be valid under the standard policy, or this \
             tests the same thing the Decred fixture already does"
        );
        assert!(!summary.sha1_blocked);
    }

    #[test]
    fn a_sha1_hashed_signature_is_refused_until_opted_in_and_then_disclosed() {
        let (_dir, store) = scratch();
        let cert = Cert::from_bytes(SIGNER).unwrap();
        let fingerprint = cert.fingerprint().to_hex();
        store.insert(&cert).unwrap();

        // Refused by default, even though the certificate is modern and
        // perfectly valid: the policy is about this signature, not the key.
        let refused = rpgp_core::ops::verify_detached(&store, SIGNATURE, DATA);
        assert!(
            refused.as_ref().is_err() || !refused.as_ref().unwrap().all_good(),
            "a SHA-1 message hash must not verify under the standard policy: {refused:?}"
        );

        store.set_sha1_accepted(&fingerprint, true).unwrap();

        let result = rpgp_core::ops::verify_detached(&store, SIGNATURE, DATA).unwrap();
        assert!(result.all_good(), "opted in, it should verify: {result:?}");
        assert!(
            result.signatures.iter().all(|s| s.sha1),
            "and it must say SHA-1 was what made that possible: {:?}",
            result.signatures
        );

        // Tampering is still caught. The opt-in widens which hashes are
        // allowed; it never stops the hash from having to match.
        let tampered = rpgp_core::ops::verify_detached(&store, SIGNATURE, b"the quick brown cat");
        assert!(
            tampered.as_ref().is_err() || !tampered.as_ref().unwrap().all_good(),
            "an opted-in certificate must not make bad signatures good: {tampered:?}"
        );
    }

    /// And the isolation holds on this path too, not just on the display one.
    #[test]
    fn another_certificates_opt_in_does_not_verify_this_signature() {
        let (_dir, store) = scratch();
        store.insert(&Cert::from_bytes(SIGNER).unwrap()).unwrap();
        let other = modern_cert(&store, "Someone Else <else@example.com>");
        store
            .set_sha1_accepted(&other.fingerprint().to_hex(), true)
            .unwrap();

        let result = rpgp_core::ops::verify_detached(&store, SIGNATURE, DATA);
        assert!(
            result.as_ref().is_err() || !result.as_ref().unwrap().all_good(),
            "opting in an unrelated certificate must not verify this: {result:?}"
        );
    }
}

/// An unreadable opt-in list must not break operations that have nothing to do
/// with it.
///
/// The opt-in made the verification policy fallible where it had been infallible,
/// and propagating that error would have meant a single unreadable bookkeeping
/// file turning every verify and decrypt into a failure — including the ones that
/// never touch SHA-1. Strict is what an empty list yields anyway, so degrading to
/// it costs an opted-in certificate its opt-in and nothing else.
#[test]
fn an_unreadable_opt_in_list_degrades_to_strict_rather_than_failing() {
    let dir = tempfile::tempdir().unwrap();
    let secrets = dir.path().join("secrets");
    let store = Store::open(dir.path().join("certs.d"), &secrets).unwrap();

    let signer = Cert::from_bytes(include_bytes!("fixtures/sha1-signer.asc")).unwrap();
    store.insert(&signer).unwrap();

    // Bytes that are not UTF-8, so the read errors rather than returning empty.
    let path = secrets.with_file_name("sha1-accepted");
    std::fs::write(&path, b"\xff\xfe not utf-8 \xff").unwrap();
    assert!(
        store.sha1_accepted().is_err(),
        "the fixture must actually make the read fail, or this proves nothing"
    );

    // A perfectly ordinary signature, unrelated to SHA-1, still verifies.
    let mut signed = Vec::new();
    let mine = rpgp_core::keygen::generate(&rpgp_core::keygen::KeyGenRequest::new(
        "Me <me@example.com>",
    ))
    .unwrap()
    .cert;
    store.insert_secret(&mine).unwrap();
    rpgp_core::ops::sign_detached(&mine, None, b"hello", &mut signed).unwrap();
    let ok = rpgp_core::ops::verify_detached(&store, &signed, b"hello")
        .expect("an unreadable opt-in list must not fail an unrelated verification");
    assert!(ok.all_good(), "{ok:?}");

    // And the SHA-1 signature is refused, because strict is the fallback.
    let refused = rpgp_core::ops::verify_detached(
        &store,
        include_bytes!("fixtures/sha1-detached.asc"),
        b"the quick brown fox",
    );
    assert!(
        refused.as_ref().is_ok_and(|r| !r.all_good()),
        "the fallback must fail closed and must still return a verdict: {refused:?}"
    );
}

/// The opt-in list is repaired to 0600 on open, like the two bookkeeping files
/// beside it. It records which certificates the user has weakened a rule for, so
/// anyone able to write it can widen what verifies.
#[cfg(unix)]
#[test]
fn the_opt_in_list_is_repaired_to_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let secrets = dir.path().join("secrets");
    {
        let store = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
        store.set_sha1_accepted(&"AB".repeat(20), true).unwrap();
    }

    // Whatever a careless earlier build might have left behind.
    let path = secrets.with_file_name("sha1-accepted");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let _store = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "reopening the store should have repaired it");
}
