//! What rPGP does with the stubs GnuPG writes where it holds no key.
//!
//! `gpg --export-secret-subkeys` keeps the subkey secrets and puts a
//! `gnu-dummy` placeholder where the primary's belongs: a secret-key packet
//! with the private S2K type 101 and no key material in it at all. Sequoia
//! reads that as an encrypted secret, so the file is a transferable secret key
//! by every test rPGP applies to it, and a merge that prefers the incoming
//! secret takes the placeholder over the real primary it already holds.
//!
//! The first two fixtures are two exports of one throwaway key, made with gpg
//! 2.4.9 in a scratch GNUPGHOME — real gpg output rather than something shaped
//! by hand, because the shape is the thing in question and a guess at it is
//! easy to get backwards:
//!
//! ```text
//! gpg --quick-gen-key 'Stub Fixture <stub@example.invalid>' ed25519 cert never
//! gpg --quick-add-key "$FPR" ed25519 sign never
//! gpg --quick-add-key "$FPR" cv25519 encr never
//! gpg --armor --export-secret-keys    "$FPR" > gnupg-secret-keys.asc
//! gpg --armor --export-secret-subkeys "$FPR" > gnupg-secret-subkeys.asc
//! ```
//!
//! The key is B44CCCCF9992862E40561636268C734A550768D8, generated for this
//! test alone and protected with the passphrase `fixture`. Protected on
//! purpose: a stub and a passphrase-protected secret are both encrypted, so
//! anything that decides on encryption alone gets one of the two wrong.
//!
//! The third fixture is the mirror image, for the other way a key gets split:
//! the primary stays on this machine and the subkeys move to a smartcard, so
//! an export stubs every subkey and leaves the primary whole. It is a second
//! throwaway key, 1283F6FE0695D4BB0F03F7517994862D63BD4D58, with no passphrase
//! anywhere on it — so that a test passing none proves the stubs never ask for
//! one either:
//!
//! ```text
//! gpg --quick-gen-key 'Card Fixture <card@example.invalid>' ed25519 cert never
//! gpg --quick-add-key "$FPR" ed25519 sign never
//! gpg --quick-add-key "$FPR" cv25519 encr never
//! gpg --quick-add-key "$FPR" ed25519 auth never
//! gpg --quick-set-expire "$FPR" seconds=1 '*'
//! gpg --quick-set-expire "$FPR" seconds=1
//! rm private-keys-v1.d/<the keygrip of each subkey>.key
//! gpg --armor --export-secret-keys "$FPR" > gnupg-subkey-stubs.asc
//! ```
//!
//! Deleting the private key files is what moving the subkeys to a card leaves
//! behind, minus the card: gpg then writes `gnu-dummy` rather than
//! `divert-to-card`, which is the same private S2K type 101 and the same
//! absence of key material. Having no card in the loop is the point — the
//! fixture has to be something a test can read without one.
//!
//! The one-second lifetime, set on the subkeys and then on the primary, is
//! what makes a test of re-dating them mean anything. It puts a key expiry in
//! every binding, and it has long since run out however late this is read. A
//! key that simply never expired would prove much less: sequoia falls back to
//! the certificate's direct key signature for a binding that names no expiry
//! of its own, so a subkey the re-dating quietly skipped would report the
//! primary's new date and look re-dated.
//!
//! The fourth and fifth fixtures are for signing. They are two exports of a
//! third throwaway key, 86B79198484A81B11E53B792D8B630CEBC779A18, whose
//! primary signs as well as certifies, as a primary made with GnuPG's defaults
//! does, with a signing subkey and an encryption subkey beside it, and no
//! passphrase anywhere. A primary that signs is the first key a search for one
//! that can sign comes to, so its stub is in the way of everything after it.
//! The fourth is what `gpg --export-secret-subkeys` writes for the key, the
//! primary a stub and the subkeys whole. The fifth is the same export once the
//! subkeys have gone where the third fixture's went, so that every secret in
//! it is a stub, as GnuPG exports a key from a machine where the primary is
//! kept offline and the subkeys are on a card. `tests/gpg_agent.rs` signs with
//! the fifth through an agent given the fourth's subkeys. The recipe makes a
//! GNUPGHOME of its own, as the Keybox fixture's in `store.rs` does, since gpg
//! takes an unset or empty one to mean ~/.gnupg, and stops at the first
//! command that fails:
//!
//! ```text
//! (
//! set -e -o pipefail
//! GNUPGHOME="$(mktemp -d)"
//! export GNUPGHOME
//! echo disable-scdaemon > "$GNUPGHOME/gpg-agent.conf"
//! gpg --batch --passphrase '' --pinentry-mode loopback \
//!     --quick-gen-key 'Signing Fixture <signing@example.invalid>' ed25519 sign never
//! FPR="$(gpg --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10 }')"
//! gpg --batch --passphrase '' --pinentry-mode loopback --quick-add-key "$FPR" ed25519 sign never
//! gpg --batch --passphrase '' --pinentry-mode loopback --quick-add-key "$FPR" cv25519 encr never
//! gpg --batch --armor --export-secret-subkeys "$FPR" > gnupg-signing-subkeys.asc
//! gpg --with-colons --with-keygrip --list-secret-keys "$FPR" |
//!     awk -F: '$1 == "sec" || $1 == "ssb" { kind = $1 }
//!              $1 == "grp" && kind == "ssb" { print $10 }' |
//!     while read -r grip; do rm "$GNUPGHOME/private-keys-v1.d/$grip.key"; done
//! gpg --batch --armor --export-secret-subkeys "$FPR" > gnupg-signing-stubs.asc
//! gpgconf --kill all
//! gpgconf --remove-socketdir
//! rm -r "$GNUPGHOME"
//! )
//! ```
//!
//! Nothing here runs gpg. The fixtures are bytes and the store is a tempdir.

use std::io::Write;
use std::time::{Duration, SystemTime};

use rpgp_core::certify::{CertifyRequest, certify};
use rpgp_core::keygen::{KeyGenRequest, generate};
use rpgp_core::{CertSummary, Error, Store, lifecycle, ops, revoke};
use sequoia_openpgp::crypto::S2K;
use sequoia_openpgp::packet::key::SecretKeyMaterial;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Recipient};
use sequoia_openpgp::{Cert, Fingerprint, Packet, PacketPile};

const FULL: &[u8] = include_bytes!("fixtures/gnupg-secret-keys.asc");
const SUBKEYS_ONLY: &[u8] = include_bytes!("fixtures/gnupg-secret-subkeys.asc");
const SUBKEY_STUBS: &[u8] = include_bytes!("fixtures/gnupg-subkey-stubs.asc");
const SIGNING_SUBKEYS: &[u8] = include_bytes!("fixtures/gnupg-signing-subkeys.asc");

fn scratch() -> (tempfile::TempDir, Store) {
    // Decrypting a message for a stubbed key, and signing with one, go on to
    // ask gpg-agent, and that must not be the developer's own: pointed nowhere,
    // the question fails at once, as on a machine without GnuPG. See
    // `agent::AgentHome`.
    rpgp_core::agent::set_home(rpgp_core::agent::AgentHome::Nowhere);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
    (dir, store)
}

/// Import a fixture the way the GUI does, through a file on disk.
fn import(dir: &tempfile::TempDir, store: &Store, name: &str, bytes: &[u8]) {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    store.import_file(&path).unwrap();
}

fn primary_secret(cert: &Cert) -> Option<&SecretKeyMaterial> {
    cert.primary_key().key().optional_secret()
}

fn is_gnu_stub(secret: &SecretKeyMaterial) -> bool {
    match secret {
        SecretKeyMaterial::Encrypted(encrypted) => {
            matches!(encrypted.s2k(), S2K::Private { tag: 101, .. })
        }
        SecretKeyMaterial::Unencrypted(_) => false,
    }
}

/// The premise. If this fails the fixtures have been replaced and the test
/// below proves nothing about GnuPG.
///
/// Asserted on the S2K itself rather than through `secret::is_usable`, so that
/// a broken check reads as a wrong import below rather than as a bad fixture
/// here.
#[test]
fn the_fixtures_are_a_full_export_and_a_stubbed_one() {
    let full = Cert::from_bytes(FULL).unwrap();
    let stubbed = Cert::from_bytes(SUBKEYS_ONLY).unwrap();
    assert_eq!(full.fingerprint(), stubbed.fingerprint());

    assert!(
        !is_gnu_stub(primary_secret(&full).expect("the full export carries the primary secret")),
        "the full export's primary should be real key material"
    );
    assert!(
        is_gnu_stub(primary_secret(&stubbed).expect("a stub still counts as a secret")),
        "gpg --export-secret-subkeys should leave a gnu-dummy primary"
    );
    assert!(
        stubbed.is_tsk(),
        "the stubbed export is a TSK, which is why import routes it at the secret key"
    );

    // The other half of the shape, and the half the old comment had backwards:
    // it is the subkeys that keep their secrets.
    assert!(
        stubbed.keys().subkeys().count() > 0
            && stubbed
                .keys()
                .subkeys()
                .all(|k| k.key().optional_secret().is_some_and(|s| !is_gnu_stub(s))),
        "the subkeys of a --export-secret-subkeys file are real"
    );
}

/// Importing a `--export-secret-subkeys` file must neither take the primary
/// secret the store holds nor refuse to supply one it lacks.
///
/// Both orders are here because each merge order gets exactly one of them
/// right. Preferring the incoming secret loses the primary in the first;
/// preferring the stored one leaves the stub in place forever in the second.
#[test]
fn a_gnupg_stub_neither_takes_nor_withholds_the_primary_secret() {
    let full = Cert::from_bytes(FULL).unwrap();
    let fingerprint = full.fingerprint().to_hex();

    // Full first, then the stubbed export over it.
    {
        let (dir, store) = scratch();
        import(&dir, &store, "full.asc", FULL);
        import(&dir, &store, "subkeys.asc", SUBKEYS_ONLY);

        let stored = store.secret_cert(&fingerprint).unwrap();
        assert_eq!(
            primary_secret(&stored),
            primary_secret(&full),
            "the stub replaced the primary secret the store held"
        );
        // Compared by kind, not by bytes: gpg re-encrypts every secret it
        // exports under a fresh salt, so the subkeys in the two fixtures are
        // the same keys with different ciphertext.
        assert!(
            stored
                .keys()
                .subkeys()
                .all(|k| k.key().optional_secret().is_some_and(|s| !is_gnu_stub(s))),
            "the subkey secrets should still be real"
        );
    }

    // The stubbed export first, then the full backup that restores the key.
    {
        let (dir, store) = scratch();
        import(&dir, &store, "subkeys.asc", SUBKEYS_ONLY);
        let stubbed = store.secret_cert(&fingerprint).unwrap();
        assert!(
            is_gnu_stub(primary_secret(&stubbed).expect("the stub is kept, having nothing better")),
            "with nothing else held, the stub should have been stored as it arrived"
        );

        import(&dir, &store, "full.asc", FULL);
        let stored = store.secret_cert(&fingerprint).unwrap();
        assert_eq!(
            primary_secret(&stored),
            primary_secret(&full),
            "the full export did not replace the stub"
        );
    }
}

/// The premise for the third fixture, and the detail everything below rests
/// on: which of these bindings GnuPG countersigned.
#[test]
fn the_third_fixture_has_a_local_primary_and_three_stubbed_subkeys() {
    let cert = Cert::from_bytes(SUBKEY_STUBS).unwrap();
    assert!(
        !is_gnu_stub(primary_secret(&cert).expect("the primary secret is real")),
        "the primary of this one is the half that stayed behind"
    );
    assert_eq!(cert.keys().subkeys().count(), 3, "[S], [E] and [A]");
    assert!(
        cert.keys()
            .subkeys()
            .all(|k| k.key().optional_secret().is_some_and(is_gnu_stub)),
        "every subkey secret should be a gnu-dummy placeholder"
    );

    // GnuPG countersigns a signing subkey's binding and nothing else, so the
    // authentication subkey has none to carry over — which is why re-dating a
    // binding must not be made to require one, and why this fixture and not a
    // synthesised [S][E] pair is what proves it.
    let policy = rpgp_core::policy();
    let valid = cert.with_policy(&policy, None).unwrap();
    for ka in valid.keys().subkeys() {
        let countersignatures = ka.binding_signature().embedded_signatures().count();
        let expected = usize::from(ka.for_signing());
        assert_eq!(
            countersignatures,
            expected,
            "subkey {} (signing: {})",
            ka.key().fingerprint(),
            ka.for_signing()
        );
        // Read off the binding itself, not through the amalgamation, which
        // would answer from the direct key signature for a binding that named
        // no expiry. Everything below asks the same way and for the same
        // reason.
        assert_eq!(
            ka.binding_signature().key_validity_period(),
            Some(Duration::from_secs(1)),
            "subkey {} should carry the one-second lifetime of its own",
            ka.key().fingerprint()
        );
        assert!(
            ka.alive().is_err(),
            "the fixture has long since lapsed, which is what makes re-dating it visible"
        );
    }
}

/// A primary on the laptop and the subkeys on a card, which is what moving
/// them there with `keytocard` leaves behind — and the one shape whose expiry
/// rPGP could not change at all. The stub asked for a passphrase, no
/// passphrase answered it, and the whole change was refused, although every
/// signature it needed was one the primary key sitting right there could
/// make.
#[test]
fn subkeys_gnupg_holds_elsewhere_are_re_dated_by_the_primary_alone() {
    let (dir, store) = scratch();
    import(&dir, &store, "subkey-stubs.asc", SUBKEY_STUBS);
    let fingerprint = Cert::from_bytes(SUBKEY_STUBS)
        .unwrap()
        .fingerprint()
        .to_hex();

    let year = Duration::from_secs(365 * 24 * 60 * 60);
    // No passphrase, because there is none anywhere on this key.
    let extended = lifecycle::set_expiry(&store, &fingerprint, Some(year), None)
        .expect("a stubbed subkey must not refuse a change the primary can make");

    let policy = rpgp_core::policy();
    let deadline = SystemTime::now() + year;
    for cert in [&extended, &store.secret_cert(&fingerprint).unwrap()] {
        let valid = cert.with_policy(&policy, None).unwrap();
        let subkeys: Vec<_> = valid.keys().subkeys().collect();
        assert_eq!(subkeys.len(), 3);
        for ka in &subkeys {
            let period = ka
                .binding_signature()
                .key_validity_period()
                .unwrap_or_else(|| panic!("subkey {} was left undated", ka.key().fingerprint()));
            let expires = ka.key().creation_time() + period;
            assert!(
                expires <= deadline && expires + Duration::from_secs(300) > deadline,
                "subkey {} expires at {expires:?}, not around {deadline:?}",
                ka.key().fingerprint()
            );
        }
        // The countersignature on the signing subkey's binding survived the
        // move into the new one, which is the only reason that binding is
        // still valid at all.
        assert_eq!(
            valid.keys().subkeys().alive().for_signing().count(),
            1,
            "no live signing subkey"
        );
        assert_eq!(
            valid.keys().subkeys().alive().for_authentication().count(),
            1
        );
        assert_eq!(
            valid
                .keys()
                .subkeys()
                .alive()
                .for_transport_encryption()
                .count(),
            1
        );
    }
}

/// The other half of the split, where there is nothing to be done and the only
/// thing to get right is what the user is told.
///
/// Every operation in `lifecycle` signs with the primary key, and so does
/// revoking the certificate, so a stub in its place refuses all of them. They
/// used to be refused as a passphrase problem: with the field empty, "this key
/// is passphrase-protected", and with anything typed into it, an error off the
/// S2K that reads like a corrupt file. Neither mentions the one fact that
/// explains both. Revoking kept that answer longest, and it is the one a
/// card's imported stubs bring into view: they put the key under My keys, and
/// its details pane offers Revoke.
#[test]
fn a_stubbed_primary_is_reported_as_a_stub_and_not_as_a_passphrase() {
    let (dir, store) = scratch();
    import(&dir, &store, "subkeys.asc", SUBKEYS_ONLY);
    let cert = Cert::from_bytes(SUBKEYS_ONLY).unwrap();
    let fingerprint = cert.fingerprint().to_hex();

    // Both the empty field and the passphrase that really does open this key's
    // subkeys: it is the primary that is missing, so neither can help.
    for password in [None, Some("fixture")] {
        for message in [
            lifecycle::set_expiry(
                &store,
                &fingerprint,
                Some(Duration::from_secs(3600)),
                password,
            )
            .expect_err("the primary is a stub")
            .to_string(),
            lifecycle::add_user_id(
                &store,
                &fingerprint,
                "Stub <other@example.invalid>",
                password,
            )
            .expect_err("the primary is a stub")
            .to_string(),
            revoke::revoke_cert(
                &store,
                &revoke::RevokeRequest {
                    password: password.map(|p| p.to_string().into()),
                    ..revoke::RevokeRequest::new(&fingerprint)
                },
            )
            .expect_err("the primary is a stub")
            .to_string(),
        ] {
            assert!(message.contains("stub"), "{password:?}: {message}");
            assert!(!message.contains("passphrase"), "{password:?}: {message}");
        }
    }

    // And nothing was written on the way to saying so.
    assert_eq!(
        store.secret_cert(&fingerprint).unwrap().userids().count(),
        cert.userids().count()
    );
    assert_eq!(
        revoke::revocation_reason(&store.full_cert(&fingerprint).unwrap()),
        None
    );
}

/// A message for a subkey whose secret GnuPG keeps on a card is not reported
/// as one for a locked key. Sequoia reads the stub as an encrypted secret, but
/// there is no passphrase to enter: the key opens through gpg-agent or not at
/// all, and asking for its passphrase would send the user after one that does
/// not exist. No agent holds it here, so this is a message no secret key
/// opens, whatever was entered.
#[test]
fn a_message_for_a_stubbed_subkey_does_not_ask_for_its_passphrase() {
    let (dir, store) = scratch();
    import(&dir, &store, "subkey-stubs.asc", SUBKEY_STUBS);
    let cert = Cert::from_bytes(SUBKEY_STUBS).unwrap();

    // Encrypted by hand, to the subkey by name: it has long since expired,
    // and rPGP encrypts only to live keys. Decryption does not ask whether a
    // key is alive, so old mail stays readable.
    let policy = rpgp_core::policy();
    let valid = cert.with_policy(&policy, None).unwrap();
    let recipients: Vec<Recipient> = valid
        .keys()
        .for_transport_encryption()
        .map(|ka| {
            use sequoia_openpgp::cert::Preferences;
            Recipient::new(valid.features(), ka.key().key_handle(), ka.key())
        })
        .collect();
    assert_eq!(recipients.len(), 1, "premise: one encryption subkey");
    let mut ciphertext = Vec::new();
    {
        let message = Message::new(&mut ciphertext);
        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .unwrap();
        let mut message = LiteralWriter::new(message).build().unwrap();
        message.write_all(b"for the card").unwrap();
        message.finalize().unwrap();
    }

    for passwords in [&[][..], &["fixture"][..]] {
        let refused = ops::decrypt(&store, &ciphertext, passwords, &mut Vec::new())
            .expect_err("nothing here holds the subkey's secret");
        assert!(
            !matches!(refused, Error::KeyLocked { .. }),
            "{passwords:?}: asked for the passphrase of a stub: {refused}"
        );
        assert!(
            refused.to_string().contains("no secret key"),
            "{passwords:?}: {refused}"
        );
    }
}

/// A secret key file whose primary is a stub is not one the store can certify
/// with, and the store says so before anything is asked of it: the key is
/// among those it holds a secret key file for, and not among those whose
/// primary is here, and a summary of the file says the same. That is what
/// the Certify button goes by, and certify() agrees: with no gpg-agent to
/// hand the primary to, it refuses, whichever passphrase is given. The full
/// export of the same key, imported over it, is counted, and certifies.
#[test]
fn a_stubbed_primary_is_not_counted_among_the_keys_that_certify_here() {
    let (dir, store) = scratch();
    import(&dir, &store, "subkeys.asc", SUBKEYS_ONLY);
    let fingerprint = Cert::from_bytes(SUBKEYS_ONLY)
        .unwrap()
        .fingerprint()
        .to_hex();
    let target = generate(&KeyGenRequest::new("Target <target@example.org>"))
        .unwrap()
        .cert;
    store.insert(&target).unwrap();
    let mut request = CertifyRequest::new(&fingerprint, target.fingerprint().to_hex());
    request.user_ids = vec!["Target <target@example.org>".to_string()];
    request.password = Some("fixture".to_string().into());

    assert!(
        store.secret_fingerprints().unwrap().contains(&fingerprint),
        "premise: the store holds a secret key file for it"
    );
    assert!(
        !store
            .primary_secret_fingerprints()
            .unwrap()
            .contains(&fingerprint),
        "a stubbed primary was counted as one that certifies here"
    );
    assert!(!CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap()).primary_secret);
    assert!(
        certify(&store, &request).is_err(),
        "certified with a primary the store does not hold"
    );

    import(&dir, &store, "full.asc", FULL);
    assert!(
        store
            .primary_secret_fingerprints()
            .unwrap()
            .contains(&fingerprint),
        "the full export's primary was not counted"
    );
    assert!(CertSummary::from_cert(&store.secret_cert(&fingerprint).unwrap()).primary_secret);
    certify(&store, &request).expect("the full export certifies");
}

/// The key that made the one signature in `armored`, by the fingerprint the
/// signature names.
fn signed_by(armored: &[u8]) -> Fingerprint {
    match PacketPile::from_bytes(armored).unwrap().children().next() {
        Some(Packet::Signature(signature)) => signature
            .issuer_fingerprints()
            .next()
            .expect("the signature names the key that made it")
            .clone(),
        other => panic!("not a signature: {other:?}"),
    }
}

/// A primary that signs as well as certifies, kept offline, arrives from `gpg
/// --export-secret-subkeys` as a stub, with the signing subkey beside it
/// whole, and signing takes the subkey, in the store and not through
/// gpg-agent: none answers in these tests, so a signature can only have been
/// made with the key here.
///
/// The stub is the first of the key's keys that can sign, and signing used to
/// take the first: it asked for the stub's passphrase, which no passphrase
/// answers, and signed nothing, with the key that could sign right there.
#[test]
fn a_stubbed_primary_that_signs_leaves_signing_to_the_subkey_here() {
    let (dir, store) = scratch();
    import(&dir, &store, "signing-subkeys.asc", SIGNING_SUBKEYS);
    let cert = Cert::from_bytes(SIGNING_SUBKEYS).unwrap();
    let fingerprint = cert.fingerprint().to_hex();

    let policy = rpgp_core::policy();
    let valid = cert.with_policy(&policy, None).unwrap();
    assert!(
        valid.primary_key().for_signing() && primary_secret(&cert).is_some_and(is_gnu_stub),
        "premise: the primary can sign, and its secret is a stub"
    );
    let subkey = valid
        .keys()
        .subkeys()
        .for_signing()
        .next()
        .expect("premise: a signing subkey");
    assert!(
        subkey
            .key()
            .optional_secret()
            .is_some_and(|s| !is_gnu_stub(s)),
        "premise: the signing subkey's secret is real"
    );

    let signer = store.full_cert(&fingerprint).unwrap();
    let mut signature = Vec::new();
    // No passphrase, because there is none anywhere on this key.
    ops::sign_detached(&signer, None, b"signed by the subkey", &mut signature)
        .expect("the signing subkey is in the store, and should have signed");
    let verified = ops::verify_detached(&store, &signature, b"signed by the subkey").unwrap();
    assert!(verified.all_good(), "{:?}", verified.signatures);
    assert_eq!(signed_by(&signature), subkey.key().fingerprint());
}

/// The mirror image, in the third fixture once its keys are alive again: the
/// primary is here and only certifies, and the signing subkey's secret is a
/// stub, as on a card. No key here can sign, so signing asks gpg-agent, as
/// decrypting a message for the card does above. None answers in these tests,
/// and the refusal says so, whatever was typed. Signing used to take the stub
/// as the key to sign with and ask for a passphrase that does not exist, so
/// the agent, which can sign with the card, was never asked.
#[test]
fn a_signing_subkey_gnupg_holds_elsewhere_is_asked_of_the_agent() {
    let (dir, store) = scratch();
    import(&dir, &store, "subkey-stubs.asc", SUBKEY_STUBS);
    let fingerprint = Cert::from_bytes(SUBKEY_STUBS)
        .unwrap()
        .fingerprint()
        .to_hex();

    // A key that has lapsed is not one to sign with, here or through the
    // agent, so the stub stands in the way only once it is alive.
    let year = Duration::from_secs(365 * 24 * 60 * 60);
    lifecycle::set_expiry(&store, &fingerprint, Some(year), None).unwrap();
    let signer = store.full_cert(&fingerprint).unwrap();

    let policy = rpgp_core::policy();
    let valid = signer.with_policy(&policy, None).unwrap();
    assert!(
        !valid.primary_key().for_signing(),
        "premise: the primary only certifies"
    );
    let signing: Vec<_> = valid.keys().alive().for_signing().collect();
    assert!(
        signing.len() == 1 && signing[0].key().optional_secret().is_some_and(is_gnu_stub),
        "premise: one live signing key, and its secret a stub"
    );

    for password in [None, Some("anything")] {
        let refused = ops::sign_detached(&signer, password, b"for the card", Vec::new())
            .expect_err("no key here can sign, and no agent answers");
        let message = refused.to_string();
        assert!(message.contains("gpg-agent"), "{password:?}: {message}");
        assert!(!message.contains("passphrase"), "{password:?}: {message}");
    }
}
