//! The SHA-1 opt-in: what it unlocks, and — more importantly — what it does not.
//!
//! The fixture is the real thing rather than something synthesised, and
//! deliberately so: a hand-rolled stand-in for a certificate certified in 2016
//! would test the stand-in. `fixtures/sha1-cert.asc` is the Decred project's public
//! release key, published at <https://decred.org>, certified in 2016 and still
//! in use. Public key material only, and included for exactly the property that
//! makes it awkward: every self-signature on it is hashed with SHA-1, so
//! sequoia's standard policy finds no valid binding signature anywhere and the
//! certificate has no usable user ID or subkey at all.

use rpgp_core::{CertSummary, Store, Validity, cert, sha1, wot};
use sequoia_openpgp::packet::signature::subpacket::{Subpacket, SubpacketValue};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::{Cert, KeyID, Packet, PacketPile};

const SHA1_CERT: &[u8] = include_bytes!("fixtures/sha1-cert.asc");

fn scratch() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
    (dir, store)
}

fn sha1_cert() -> Cert {
    Cert::from_bytes(SHA1_CERT).unwrap()
}

/// Every signature in `packets`, with one more Issuer subpacket naming
/// `issuer` written into its *unhashed* area.
///
/// The whole of the attack these fixtures exist for, and it takes no key
/// material and no secret: the unhashed area is not covered by the signature,
/// so anyone holding a copy can write a line into it and the result still
/// verifies, byte for byte, against the key that really made it. Sequoia reads
/// Issuer and IssuerFingerprint from there as well as from the signed area, and
/// a certificate merge keeps what it finds, so a doctored copy survives an
/// import or a keyserver refresh.
fn naming(packets: impl Iterator<Item = Packet>, issuer: KeyID) -> Vec<Packet> {
    packets
        .map(|packet| match packet {
            Packet::Signature(mut sig) => {
                sig.unhashed_area_mut()
                    .add(Subpacket::new(SubpacketValue::Issuer(issuer.clone()), false).unwrap())
                    .unwrap();
                Packet::Signature(sig)
            }
            other => other,
        })
        .collect()
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
    assert!(
        cert::subkeys_with(&cert, policy.for_cert(&cert))
            .iter()
            .any(|k| k.can_sign),
        "the signing subkey should bind now"
    );
    assert!(
        cert::user_ids_with(&cert, policy.for_cert(&cert))
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

/// "For verification" is the whole of it, and the key list has to say so.
///
/// The row reads `valid` once the user opts in, because under their policy it
/// is. Its capabilities are a different question — what this app will *do* with
/// the certificate — and the answer is nothing: every operation builds
/// [`rpgp_core::policy`] itself and never consults the opt-in list, so
/// encrypting to this certificate fails with "no usable encryption key" and
/// signing with it, were the secret half here, would fail for the same reason.
/// The capabilities were read off the opted-in policy, so the row showed `CSE`
/// and the Sign / Encrypt dialog listed a recipient it would then refuse.
#[test]
fn an_opted_in_certificate_is_offered_for_nothing_new() {
    let (_dir, store) = scratch();
    let cert = sha1_cert();
    let fingerprint = cert.fingerprint().to_hex();
    store.insert(&cert).unwrap();
    store.set_sha1_accepted(&fingerprint, true).unwrap();

    let policy = store.sha1_policy().unwrap();
    let summary = CertSummary::from_cert_with(&cert, &policy);
    assert_eq!(
        summary.validity,
        Validity::Valid,
        "the premise: opted in, the certificate itself reads as sound"
    );
    assert_eq!(
        summary.capabilities(),
        "-",
        "and there is still nothing the app will use it for"
    );
    assert!(
        !summary.can_encrypt,
        "the recipient list is built from this"
    );
    assert!(!summary.can_sign, "and the signer list from this");
    assert!(!summary.can_certify, "and the certifier list from this");

    // Which is the answer encrypting gives, and the reason the flags have to
    // agree with it rather than with the pill beside them.
    let refused = rpgp_core::ops::encrypt(
        std::slice::from_ref(&cert),
        &[],
        None,
        b"for the release team",
        Vec::new(),
    )
    .map(|_| ())
    .expect_err("an opted-in SHA-1 certificate cannot be encrypted to");
    assert!(
        refused.to_string().contains("no usable encryption key"),
        "for the reason the banner gives: {refused}"
    );

    // The other certificate in the store is judged strictly and is unaffected,
    // as everywhere else in this file.
    let modern = modern_cert(&store, "Someone Else <else@example.com>");
    assert_eq!(
        CertSummary::from_cert_with(&modern, &store.sha1_policy().unwrap()).capabilities(),
        "CSE"
    );
}

/// A certificate the opt-in does not name is judged under the standard policy,
/// so both ways in have to describe the same row.
///
/// That is what keeps an ordinary reload at one policy pass per row: where the
/// list does not name the certificate, `from_cert_with` takes the strict branch
/// and never resolves it a second time. It rests on an equivalence between two
/// types rather than on one expression — the policy a `Sha1Policy` hands out
/// for a certificate it was not told about *is* the standard policy — and
/// nothing in the code says so, so a field added later could make the two
/// disagree. Opting a *different* certificate in is what keeps the comparison
/// honest: the list is not empty, so nothing here is passing because there was
/// nothing to apply.
#[test]
fn a_certificate_nobody_opted_in_reads_the_same_whichever_branch_answers_it() {
    let (_dir, store) = scratch();
    let decoy = modern_cert(&store, "Decoy <decoy@example.com>");
    store
        .set_sha1_accepted(&decoy.fingerprint().to_hex(), true)
        .unwrap();
    let policy = store.sha1_policy().unwrap();
    assert!(
        !policy.is_strict(),
        "the premise: this policy has something opted in to leak"
    );

    // One certificate of each kind the shortcut has to get right: one the
    // standard policy accepts, and one it refuses for the very reason the
    // opt-in exists to excuse — had it been asked about this certificate.
    let modern = modern_cert(&store, "Someone Else <else@example.com>");
    let old = sha1_cert();
    for (cert, expected) in [(&modern, "CSE"), (&old, "-")] {
        let shortcut = CertSummary::from_cert(cert);
        let resolved_again = CertSummary::from_cert_with(cert, &policy);
        assert_eq!(
            shortcut.capabilities(),
            resolved_again.capabilities(),
            "a certificate nobody opted in reads the same either way"
        );
        assert_eq!(
            shortcut.capabilities(),
            expected,
            "and the comparison above is not between two empty answers"
        );
        assert_eq!(shortcut.validity, resolved_again.validity);
        assert_eq!(shortcut.user_ids, resolved_again.user_ids);
    }
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

/// And the isolation cannot be talked out of, because nothing a certificate
/// says about itself is consulted.
///
/// The old certificate's self-signatures are the ones that have to bind for its
/// row to read anything but `unusable`, and each of them names its issuer only
/// in the unhashed area — so an attacker rewriting that area can make them
/// claim whatever certificate the user has opted in. A key list that decided
/// from those claims showed a certificate nobody opted in as `valid` and
/// sign-capable, and dropped the very banner that would have offered the
/// choice. The row is decided from the certificate's own fingerprint instead,
/// which no signature can alter.
#[test]
fn a_certificate_cannot_borrow_another_ones_opt_in_by_naming_it() {
    let (_dir, store) = scratch();
    let other = modern_cert(&store, "Someone Else <else@example.com>");
    store
        .set_sha1_accepted(&other.fingerprint().to_hex(), true)
        .unwrap();

    let packets = naming(sha1_cert().into_packets(), other.keyid());
    let injected = packets
        .iter()
        .filter(|p| {
            matches!(p, Packet::Signature(sig)
                if sig.issuers().any(|id| *id == other.keyid()))
        })
        .count();
    assert!(
        injected > 0,
        "the doctored fixture must actually name the opted-in certificate, \
         or this test proves nothing"
    );

    let doctored = Cert::from_packets(packets.into_iter()).unwrap();
    assert_eq!(
        doctored.fingerprint(),
        sha1_cert().fingerprint(),
        "the edit is to the unhashed area, so it is still the same certificate"
    );
    store.insert(&doctored).unwrap();

    // Judged as the store holds it rather than as it was built, because the
    // way this reaches a user is an import or a keyserver refresh: a merge
    // keeps the unhashed subpackets it is given, so the row the key list draws
    // is drawn from a certificate carrying the claim.
    let merged = store.lookup(&doctored.fingerprint().to_hex()).unwrap();
    assert!(
        merged
            .clone()
            .into_packets()
            .any(|p| matches!(p, Packet::Signature(sig)
            if sig.issuers().any(|id| *id == other.keyid()))),
        "the merge kept the injected issuer, or the question is no longer \
         being asked"
    );

    let policy = store.sha1_policy().unwrap();
    let summary = CertSummary::from_cert_with(&merged, &policy);
    assert_eq!(
        summary.validity,
        Validity::Unusable,
        "a certificate nobody opted in stays strictly judged, whoever its \
         signatures name"
    );
    assert!(
        summary.sha1_blocked,
        "and the offer to opt it in is still the honest thing to show"
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
/// Both fixtures come from gpg rather than from this build, and it is fidelity
/// rather than capability that keeps them there. Sequoia will make a SHA-1
/// signature if asked — `new_hasher` refuses the algorithm outright, but
/// signing and verification both go through `HashAlgorithm::context`, which
/// routes SHA-1 to SHA1CD, and `sha1_subkey_binding` below relies on that. What
/// gpg gives that this build cannot is the bytes another implementation really
/// produced, which is worth having at least once for the case the whole module
/// is about:
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

    /// Even when the signature says otherwise — which the previous test only
    /// passes because this fixture happens not to.
    ///
    /// The signature is left cryptographically untouched and one Issuer
    /// subpacket naming the opted-in certificate is added to its unhashed
    /// area, which needs no key material and nothing but a copy of the file.
    /// Decide the SHA-1 question from that and the opt-in covers every
    /// certificate in the store rather than the one the user named: this
    /// signature was made by the fixture signer, verifies against the fixture
    /// signer's key, and is reported against the fixture signer — while the
    /// permission it leans on belongs to somebody else entirely.
    #[test]
    fn a_signature_that_merely_names_an_opted_in_issuer_is_refused() {
        let (_dir, store) = scratch();
        let signer = Cert::from_bytes(SIGNER).unwrap();
        store.insert(&signer).unwrap();
        let other = modern_cert(&store, "Someone Else <else@example.com>");
        store
            .set_sha1_accepted(&other.fingerprint().to_hex(), true)
            .unwrap();

        let doctored = PacketPile::from(naming(
            PacketPile::from_bytes(SIGNATURE).unwrap().into_children(),
            other.keyid(),
        ))
        .to_vec()
        .unwrap();

        let refused = rpgp_core::ops::verify_detached(&store, &doctored, DATA)
            .expect("the doctored signature still parses and still verifies against its own key");
        assert!(
            !refused.all_good(),
            "a certificate nobody opted in must not be relaxed by what a \
             signature claims: {:?}",
            refused.signatures
        );
        let row = &refused.signatures[0];
        assert_eq!(
            row.fingerprint.as_deref(),
            Some(signer.fingerprint().to_hex().as_str()),
            "and it is refused as the certificate it really came from"
        );
        assert!(
            row.sha1,
            "for the reason the reader needs, not as an unexplained failure: {row:?}"
        );

        // Not vacuous: the very same doctored bytes verify once the
        // certificate that actually made the signature is opted in, so the
        // refusal above is the opt-in's doing and not the edit's.
        store
            .set_sha1_accepted(&signer.fingerprint().to_hex(), true)
            .unwrap();
        let result = rpgp_core::ops::verify_detached(&store, &doctored, DATA).unwrap();
        assert!(result.all_good(), "{result:?}");
        assert!(result.signatures.iter().all(|s| s.sha1));
    }
}

/// The other shape the same mistake takes: a certificate that looks modern
/// until you ask which key signed.
///
/// [`sequoia_openpgp::Cert::with_policy`] judges the primary key and nothing
/// else, so a certificate whose user IDs were re-signed with SHA-256 — which is
/// all a modern GnuPG does when it extends an expiry — reads as perfectly sound
/// while its signing subkey is still bound by a SHA-1 signature nobody
/// refreshed. Every signature that subkey makes stands on SHA-1 and has to say
/// so, and the certificate has to be opted in before it stands at all.
///
/// Built here rather than found, and it can be: `new_hasher` in sequoia's
/// RustCrypto backend refuses SHA-1, but signing and verification both go
/// through `HashAlgorithm::context`, which routes it to SHA1CD. The fixtures
/// above come from gpg because they are old certificates as they really exist;
/// this one is a shape, and stating the shape in code says more than a blob
/// would.
mod sha1_subkey_binding {
    use std::time::{Duration, SystemTime};

    use super::*;
    use sequoia_openpgp::cert::CertBuilder;
    use sequoia_openpgp::packet::signature::SignatureBuilder;
    use sequoia_openpgp::types::{HashAlgorithm, KeyFlags, SignatureType};

    const DATA: &[u8] = b"rpgp 2.1.6 has been released";

    /// A modern certificate with one SHA-1 signing-subkey binding, and a
    /// SHA-256 detached signature from that subkey.
    fn mixed() -> (Cert, Vec<u8>) {
        let (cert, _) = CertBuilder::new()
            .add_userid("Old Project <release@example.invalid>")
            .add_signing_subkey()
            .generate()
            .unwrap();

        let mut primary = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let subkey = cert.keys().subkeys().next().unwrap().key().clone();
        let mut signer = subkey
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();

        let backsig = SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
            .sign_primary_key_binding(&mut signer, cert.primary_key().key(), &subkey)
            .unwrap();
        let binding = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_hash_algo(HashAlgorithm::SHA1)
            .set_key_flags(KeyFlags::empty().set_signing())
            .unwrap()
            .set_embedded_signature(backsig)
            .unwrap()
            .sign_subkey_binding(&mut primary, cert.primary_key().key(), &subkey)
            .unwrap();

        // The modern binding is dropped rather than superseded. Sequoia falls
        // back to an older binding when the newest one fails the policy, so
        // leaving it in place would let the standard policy bind the subkey
        // after all and the tests below would pass without proving anything.
        //
        // Through the TSK, because `Cert::into_packets` strips secret key
        // material and one test below has to sign with this certificate's
        // primary key. What goes into a store is stripped there anyway.
        let cert = Cert::from_packets(
            cert.into_tsk()
                .into_packets()
                .filter(|p| !matches!(p, Packet::Signature(s) if s.typ() == SignatureType::SubkeyBinding))
                .chain(std::iter::once(Packet::from(binding))),
        )
        .unwrap();

        let signature = Packet::from(
            SignatureBuilder::new(SignatureType::Binary)
                .set_hash_algo(HashAlgorithm::SHA256)
                .sign_message(&mut signer, DATA)
                .unwrap(),
        )
        .to_vec()
        .unwrap();

        (cert, signature)
    }

    #[test]
    fn a_sha1_bound_signing_subkey_is_refused_until_opted_in_and_then_disclosed() {
        let (_dir, store) = scratch();
        let (cert, signature) = mixed();
        let fingerprint = cert.fingerprint().to_hex();
        store.insert(&cert).unwrap();

        // The premise: nothing about the certificate says SHA-1. Its primary
        // key and user ID are modern, so it is sound to everyone who asks the
        // question of the certificate rather than of the key — which is what
        // made the disclosure below go missing.
        let summary = CertSummary::from_cert(&cert);
        assert_eq!(
            summary.validity,
            Validity::Valid,
            "or this tests what the Decred fixture already does"
        );
        assert!(!summary.sha1_blocked);
        assert!(!sha1::blocked(&cert));

        let refused = rpgp_core::ops::verify_detached(&store, &signature, DATA);
        assert!(
            refused.as_ref().is_err() || !refused.as_ref().unwrap().all_good(),
            "the only signing key reaches this certificate through SHA-1: {refused:?}"
        );

        store.set_sha1_accepted(&fingerprint, true).unwrap();

        let result = rpgp_core::ops::verify_detached(&store, &signature, DATA).unwrap();
        assert!(result.all_good(), "opted in, it should verify: {result:?}");
        assert!(
            result.signatures.iter().all(|s| s.sha1),
            "the message hash is SHA-256, so the binding is the only thing that \
             can say this — and it must, because the reader is being told a \
             signature is good that a strict verifier would refuse: {:?}",
            result.signatures
        );
    }

    /// And naming somebody else's opt-in in the binding does not help, which is
    /// the worst form of the whole family: the message hash is modern, so
    /// nothing else in the report would have hinted that SHA-1 was involved at
    /// all.
    #[test]
    fn a_binding_that_names_an_opted_in_certificate_still_does_not_bind() {
        let (_dir, store) = scratch();
        let (cert, signature) = mixed();
        let other = modern_cert(&store, "Someone Else <else@example.com>");
        store
            .set_sha1_accepted(&other.fingerprint().to_hex(), true)
            .unwrap();

        let doctored =
            Cert::from_packets(naming(cert.into_packets(), other.keyid()).into_iter()).unwrap();
        store.insert(&doctored).unwrap();

        let refused = rpgp_core::ops::verify_detached(&store, &signature, DATA);
        assert!(
            refused.as_ref().is_err() || !refused.as_ref().unwrap().all_good(),
            "a binding nobody opted in must not be accepted because it names \
             somebody who was: {refused:?}"
        );
    }

    /// A signing subkey bound twice: an older SHA-256 binding carrying a
    /// validity period that has since run out, and a newer SHA-1 one carrying
    /// none. Plus a SHA-256 detached signature made by that subkey now.
    ///
    /// The point of the shape is that the subkey binds under *either* policy —
    /// the strict one refuses the SHA-1 binding and falls back to the older
    /// one, which is exactly what sequoia does with a superseded binding — and
    /// is alive under only the relaxed one. It is the ordinary way a
    /// certificate is kept going: the binding was refreshed, and the tool that
    /// refreshed it still hashed with SHA-1.
    fn outlived_its_modern_binding() -> (Cert, Vec<u8>) {
        let day = Duration::from_secs(24 * 60 * 60);
        let created = SystemTime::now() - day * 100;
        let refreshed = SystemTime::now() - day * 10;

        let (cert, _) = CertBuilder::new()
            .set_creation_time(created)
            .add_userid("Old Project <release@example.invalid>")
            .add_signing_subkey()
            .generate()
            .unwrap();

        let mut primary = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let subkey = cert.keys().subkeys().next().unwrap().key().clone();
        let mut signer = subkey
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();

        let modern = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_signature_creation_time(created)
            .unwrap()
            .set_key_flags(KeyFlags::empty().set_signing())
            .unwrap()
            .set_key_validity_period(day * 50)
            .unwrap()
            .set_embedded_signature(
                SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(created)
                    .unwrap()
                    .sign_primary_key_binding(&mut signer, cert.primary_key().key(), &subkey)
                    .unwrap(),
            )
            .unwrap()
            .sign_subkey_binding(&mut primary, cert.primary_key().key(), &subkey)
            .unwrap();

        let sha1 = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_signature_creation_time(refreshed)
            .unwrap()
            .set_hash_algo(HashAlgorithm::SHA1)
            .set_key_flags(KeyFlags::empty().set_signing())
            .unwrap()
            .set_embedded_signature(
                SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(refreshed)
                    .unwrap()
                    .sign_primary_key_binding(&mut signer, cert.primary_key().key(), &subkey)
                    .unwrap(),
            )
            .unwrap()
            .sign_subkey_binding(&mut primary, cert.primary_key().key(), &subkey)
            .unwrap();

        // Both bindings, unlike `mixed` above: here the older one has to stay,
        // because it is what the strict policy falls back to and the fallback
        // is the whole subject.
        let cert = Cert::from_packets(
            cert.into_packets()
                .filter(|p| !matches!(p, Packet::Signature(s) if s.typ() == SignatureType::SubkeyBinding))
                .chain([Packet::from(modern), Packet::from(sha1)]),
        )
        .unwrap();

        let signature = Packet::from(
            SignatureBuilder::new(SignatureType::Binary)
                .set_hash_algo(HashAlgorithm::SHA256)
                .sign_message(&mut signer, DATA)
                .unwrap(),
        )
        .to_vec()
        .unwrap();

        (cert, signature)
    }

    /// An opt-in line names one certificate, and it has to reach that
    /// certificate and no other — including when the store can no longer
    /// produce the certificate it names.
    ///
    /// [`rpgp_core::Store::lookup`] is deliberately tolerant of subkeys,
    /// because verification resolves the issuer of a signature and that names
    /// the subkey that signed; where nothing's own fingerprint matches, it
    /// answers with a certificate that merely carries the key. Resolving an
    /// opt-in line that way hands the relaxation to whoever carries the key,
    /// and carrying somebody's key takes nothing from them: a subkey binding
    /// is made by the containing certificate's own primary key, and one
    /// claiming no signing capability needs no back signature either. The line
    /// outliving its certificate is not exotic — deleting a certificate leaves
    /// the opt-in file alone — so the certificate it names is exactly the one
    /// a store may be unable to produce.
    ///
    /// Here rather than beside the other store tests because the consequence
    /// is what makes it worth asserting, and the mixed certificate above is
    /// the one whose verdict the opt-in changes.
    #[test]
    fn an_opt_in_does_not_transfer_to_a_certificate_that_merely_carries_the_key() {
        let (_dir, store) = scratch();

        // Never inserted: this stands for the certificate the user opted in
        // and has since deleted.
        let (absent, _) = CertBuilder::new()
            .add_userid("Deleted Project <gone@example.invalid>")
            .generate()
            .unwrap();

        let (carrier, signature) = mixed();
        let mut primary = carrier
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let borrowed = absent.primary_key().key().clone().role_into_subordinate();
        let binding = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_key_flags(KeyFlags::empty().set_storage_encryption())
            .unwrap()
            .sign_subkey_binding(&mut primary, carrier.primary_key().key(), &borrowed)
            .unwrap();
        let carrier = Cert::from_packets(
            carrier
                .into_packets()
                .chain([Packet::from(borrowed), Packet::from(binding)]),
        )
        .unwrap();
        store.insert(&carrier).unwrap();

        store
            .set_sha1_accepted(&absent.fingerprint().to_hex(), true)
            .unwrap();

        // The premise: asked for the absent certificate, the store has only
        // the carrier to offer, and offers it.
        assert_eq!(
            store
                .lookup(&absent.fingerprint().to_hex())
                .unwrap()
                .fingerprint(),
            carrier.fingerprint(),
            "or the store no longer resolves a key to the certificate that \
             carries it, and this tests nothing"
        );

        // The consequence first: this certificate's only signing key is bound
        // by SHA-1, so an opt-in it borrowed is the whole difference between
        // a refusal and a good signature.
        let refused = rpgp_core::ops::verify_detached(&store, &signature, DATA);
        assert!(
            refused.as_ref().is_err() || !refused.as_ref().unwrap().all_good(),
            "an opt-in belonging to a certificate this one merely carries must \
             not verify its signatures: {refused:?}"
        );
        assert!(
            !store.sha1_policy().unwrap().accepts(&carrier),
            "and the list itself must not name it, whatever any caller does \
             with the answer"
        );
    }

    /// Asking only whether the signing key still *binds* under the strict
    /// policy is not enough, because binding is not the only thing a policy
    /// decides.
    ///
    /// The policy sequoia's verifier runs under is relaxed for the whole
    /// message as soon as anybody is opted in, so everything that policy
    /// decided has to be put to the strict one again afterwards — not just the
    /// binding, but the liveness and revocation questions the verifier asked
    /// alongside it. Here the subkey binds under both policies and is alive
    /// under only the relaxed one, so a check that stopped at binding reported
    /// this signature good, from a certificate nobody opted in, with no
    /// mention of SHA-1 at all.
    #[test]
    fn a_subkey_kept_alive_only_by_its_sha1_binding_is_refused_until_opted_in() {
        let (_dir, store) = scratch();
        let (cert, signature) = outlived_its_modern_binding();
        let fingerprint = cert.fingerprint().to_hex();
        store.insert(&cert).unwrap();

        // The premise, in the words the user would have seen: with nothing
        // opted in, a strict verifier refuses this signature outright, and the
        // subkey's liveness is the reason it gives.
        let strict = rpgp_core::ops::verify_detached(&store, &signature, DATA);
        assert!(
            strict.as_ref().is_err() || !strict.as_ref().unwrap().all_good(),
            "the older binding has expired, so strictly this key is not live: \
             {strict:?}"
        );

        // Somebody else's opt-in relaxes the policy the parser reads the
        // message under. It must not decide anything about this certificate.
        let other = modern_cert(&store, "Someone Else <else@example.com>");
        store
            .set_sha1_accepted(&other.fingerprint().to_hex(), true)
            .unwrap();
        let refused = rpgp_core::ops::verify_detached(&store, &signature, DATA);
        assert!(
            refused.as_ref().is_err() || !refused.as_ref().unwrap().all_good(),
            "a relaxation granted to another certificate must not reach this \
             one: {refused:?}"
        );

        // And opting this certificate in is what makes the difference, with
        // the disclosure that nothing else in the report could carry: the
        // message hash is SHA-256 and the key binds strictly, so the SHA-1
        // binding shows up in neither.
        store.set_sha1_accepted(&fingerprint, true).unwrap();
        let result = rpgp_core::ops::verify_detached(&store, &signature, DATA).unwrap();
        assert!(result.all_good(), "opted in, it should verify: {result:?}");
        assert!(
            result.signatures.iter().all(|s| s.sha1),
            "the SHA-1 binding is the only reason this key is usable, and the \
             reader is being told a signature is good that a strict verifier \
             refuses: {:?}",
            result.signatures
        );
    }

    /// The mirror image of [`outlived_its_modern_binding`]: an older SHA-256
    /// binding that is alive and never expires, superseded by a newer SHA-1
    /// one whose validity period has already run out. Plus a SHA-256 detached
    /// signature made by that subkey now.
    ///
    /// The shape matters because it is the one where the relaxed rules are
    /// *worse* for the certificate than the strict ones: strictly the SHA-1
    /// binding is not there at all and the older one governs, so the key is
    /// live; relax the hash rules and the newer binding comes into force,
    /// bringing an expiry with it.
    fn superseded_by_a_worse_sha1_binding() -> (Cert, Vec<u8>) {
        let day = Duration::from_secs(24 * 60 * 60);
        let created = SystemTime::now() - day * 100;
        let refreshed = SystemTime::now() - day * 10;

        let (cert, _) = CertBuilder::new()
            .set_creation_time(created)
            .add_userid("Old Project <release@example.invalid>")
            .add_signing_subkey()
            .generate()
            .unwrap();

        let mut primary = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let subkey = cert.keys().subkeys().next().unwrap().key().clone();
        let mut signer = subkey
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();

        let modern = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_signature_creation_time(created)
            .unwrap()
            .set_key_flags(KeyFlags::empty().set_signing())
            .unwrap()
            .set_embedded_signature(
                SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(created)
                    .unwrap()
                    .sign_primary_key_binding(&mut signer, cert.primary_key().key(), &subkey)
                    .unwrap(),
            )
            .unwrap()
            .sign_subkey_binding(&mut primary, cert.primary_key().key(), &subkey)
            .unwrap();

        // A key validity period runs from the key's creation time rather than
        // from the signature's, so 95 days on a key created 100 days ago is an
        // expiry that ran out five days ago.
        let sha1 = SignatureBuilder::new(SignatureType::SubkeyBinding)
            .set_signature_creation_time(refreshed)
            .unwrap()
            .set_hash_algo(HashAlgorithm::SHA1)
            .set_key_flags(KeyFlags::empty().set_signing())
            .unwrap()
            .set_key_validity_period(day * 95)
            .unwrap()
            .set_embedded_signature(
                SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(refreshed)
                    .unwrap()
                    .sign_primary_key_binding(&mut signer, cert.primary_key().key(), &subkey)
                    .unwrap(),
            )
            .unwrap()
            .sign_subkey_binding(&mut primary, cert.primary_key().key(), &subkey)
            .unwrap();

        let cert = Cert::from_packets(
            cert.into_packets()
                .filter(|p| !matches!(p, Packet::Signature(s) if s.typ() == SignatureType::SubkeyBinding))
                .chain([Packet::from(modern), Packet::from(sha1)]),
        )
        .unwrap();

        let signature = Packet::from(
            SignatureBuilder::new(SignatureType::Binary)
                .set_hash_algo(HashAlgorithm::SHA256)
                .sign_message(&mut signer, DATA)
                .unwrap(),
        )
        .to_vec()
        .unwrap();

        (cert, signature)
    }

    /// The price of the opt-in, paid by a certificate that has nothing to do
    /// with it — asserted here because [`rpgp_core::sha1`] documents it, and a
    /// documented cost no test holds in place is a cost that drifts.
    ///
    /// Sequoia reads a whole message under one policy and cannot be told which
    /// certificate a signature came from until it has verified, so while
    /// anything is opted in every certificate in the message is read under the
    /// relaxed rules. A policy chooses *which* self-signature is in force, not
    /// merely whether one is, so a certificate whose newest binding is SHA-1
    /// and worse than the one it supersedes reads worse than it strictly is,
    /// and its signature can be refused where a strict verifier calls it good.
    ///
    /// It fails closed, which is why it is recorded rather than fixed here:
    /// closing it means verifying strictly first and re-reading the message
    /// under the relaxed rules only when the strict pass left something
    /// unverified, which the streaming decrypt path cannot do — its plaintext
    /// has already gone to the caller. A change that closes it should turn the
    /// second half of this test around.
    #[test]
    fn a_worse_sha1_binding_costs_its_certificate_a_verdict_while_anything_is_opted_in() {
        let (_dir, store) = scratch();
        let (cert, signature) = superseded_by_a_worse_sha1_binding();
        store.insert(&cert).unwrap();

        // Strictly the SHA-1 binding does not exist, the older one governs,
        // and the key is live: a good signature with no SHA-1 in it anywhere.
        let strict = rpgp_core::ops::verify_detached(&store, &signature, DATA).unwrap();
        assert!(
            strict.all_good(),
            "the strict policy falls back to the older binding, which is \
             alive: {strict:?}"
        );
        assert!(
            strict.signatures.iter().all(|s| !s.sha1),
            "and nothing about it leans on SHA-1: {:?}",
            strict.signatures
        );

        // Somebody else's opt-in, and the same bytes now read under the
        // relaxed rules, where the newer binding is in force and has expired.
        let other = modern_cert(&store, "Someone Else <else@example.com>");
        store
            .set_sha1_accepted(&other.fingerprint().to_hex(), true)
            .unwrap();

        let refused = rpgp_core::ops::verify_detached(&store, &signature, DATA);
        assert!(
            refused.as_ref().is_err() || !refused.as_ref().unwrap().all_good(),
            "the relaxed parse is documented to cost this certificate its \
             verdict; if that has been closed, this is where it is recorded: \
             {refused:?}"
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
