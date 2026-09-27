//! What rPGP does with the elliptic-curve secret keys GnuPG exports with a
//! passphrase.
//!
//! From 2.3 on, gpg-agent protects such a secret for export with a length that
//! counts 8 bits for every byte it stores it in, leading zero bits included,
//! where OpenPGP counts from the first bit set. sequoia-openpgp 2.4.1 refuses
//! a secret written that way with "Malformed MPI", which rPGP passed on as a
//! passphrase that does not unlock the key. A cv25519 scalar always has a
//! clear top bit, so every encryption subkey GnuPG's defaults make came out
//! that way: nothing encrypted to one could be read here, and its owner was
//! told the passphrase was wrong. `secret::unlock` says what rPGP does about
//! it now.
//!
//! The fixtures are four throwaway keys, each generated for this test alone
//! in a GNUPGHOME of its own with gpg 2.4.9 and libgcrypt 1.12.4, and exported
//! with the passphrase `fixture` — real gpg output, since the encoding GnuPG
//! writes is the thing in question. Each was kept only once sequoia 2.4.1
//! refused every one of its secrets with the right passphrase, and the P-521
//! one only once both its secrets took the longest form GnuPG writes on that
//! curve. The first test below checks the refusal before anything else,
//! for every key but the Brainpool one, which the Brainpool test checks for
//! itself. Every gpg call ran with
//! `--batch --pinentry-mode loopback --passphrase fixture`:
//!
//! ```text
//! gpg --quick-gen-key 'Protected Fixture <protected@example.invalid>' default default never
//! gpg --armor --export-secret-keys "$FPR" > gnupg-protected-25519.asc
//! echo 'A message for the cv25519 subkey of the protected fixture.' |
//!     gpg --armor --encrypt --recipient "$FPR" > gnupg-protected-25519-message.asc
//!
//! gpg --quick-gen-key 'NIST Fixture <nist@example.invalid>' nistp256 default never
//! gpg --quick-add-key "$FPR" nistp256 encr never
//! gpg --quick-add-key "$FPR" nistp384 sign never
//! gpg --quick-add-key "$FPR" nistp384 encr never
//! gpg --quick-add-key "$FPR" nistp521 sign never
//! gpg --quick-add-key "$FPR" nistp521 encr never
//! gpg --armor --export-secret-keys "$FPR" > gnupg-protected-nist.asc
//!
//! gpg --quick-gen-key 'Brainpool Fixture <brainpool@example.invalid>' brainpoolP256r1 default never
//! gpg --quick-add-key "$FPR" brainpoolP256r1 encr never
//! gpg --armor --export-secret-keys "$FPR" > gnupg-protected-brainpool.asc
//!
//! gpg --quick-gen-key 'P-521 Fixture <p521@example.invalid>' nistp521 default never
//! gpg --quick-add-key "$FPR" nistp521 encr never
//! gpg --armor --export-secret-keys "$FPR" > gnupg-protected-p521.asc
//! ```
//!
//! - 625F9E502399DEA61A20274E05646E1EFCDF6AC9 is GnuPG's default shape, an
//!   Ed25519 primary that signs and certifies and a cv25519 subkey that
//!   encrypts. Both secrets declare 256 bits and hold 255: a cv25519 scalar
//!   always does, and about half of all Ed25519 seeds do, which is why this
//!   key was chosen, so that signing and certifying are tested along with
//!   decryption. The message was encrypted to the subkey by gpg.
//! - 19CEFFAF96EC6A24C615D8DBE1BE7AF082BB227D has an ECDSA and an ECDH key on
//!   each of the three NIST curves, the P-256 ECDSA key primary. Each secret
//!   declares a multiple of 8 bits, one to five more than it holds.
//! - 3A5FEF522C2CC735885F8E97817A8A8A6872D50E is an ECDSA primary and an ECDH
//!   subkey on brainpoolP256r1, which GnuPG writes the same way and which this
//!   build has no implementation of.
//! - D1EC3FABA50D860137A7CB81650BEACDCFAC63A4 is an ECDSA primary and an ECDH
//!   subkey on P-521 whose secrets each fill all 66 bytes of the curve's
//!   field, as about half of P-521 secrets do. Each begins with the byte 0x01,
//!   so GnuPG declares 528 bits where it holds 521. No secret on the curve is
//!   longer, and rPGP has to take one this long where it refuses one a byte
//!   longer; the NIST fixture's P-521 secrets are a byte shorter.
//!
//! Nothing here runs gpg. The fixtures are bytes and the store is a tempdir.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use rpgp_core::certify::{CertifyRequest, certify};
use rpgp_core::error::Unusable;
use rpgp_core::keygen::{KeyGenRequest, Standard, generate};
use rpgp_core::revoke::{Reason, RevokeRequest, revoke_cert};
use rpgp_core::secret::{try_unlock, unlock};
use rpgp_core::{Error, Store, lifecycle, ops};
use sequoia_openpgp::cert::Preferences;
use sequoia_openpgp::crypto::mem::Protected;
use sequoia_openpgp::crypto::{Decryptor, S2K, SessionKey, Signer, mpi};
use sequoia_openpgp::packet::key::{
    Key4, KeyRole, PublicParts, SecretKeyMaterial, SecretParts, SubordinateRole, Unencrypted,
    UnspecifiedRole,
};
use sequoia_openpgp::packet::{Key, PKESK, Packet};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Recipient};
use sequoia_openpgp::serialize::{MarshalInto, Serialize, SerializeInto};
use sequoia_openpgp::types::{Curve, HashAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp::{Cert, Fingerprint, PacketPile};

const PASSPHRASE: &str = "fixture";
const CURVE25519: &[u8] = include_bytes!("fixtures/gnupg-protected-25519.asc");
const MESSAGE: &[u8] = include_bytes!("fixtures/gnupg-protected-25519-message.asc");
const PLAINTEXT: &[u8] = b"A message for the cv25519 subkey of the protected fixture.\n";
const NIST: &[u8] = include_bytes!("fixtures/gnupg-protected-nist.asc");
const BRAINPOOL: &[u8] = include_bytes!("fixtures/gnupg-protected-brainpool.asc");
const P521: &[u8] = include_bytes!("fixtures/gnupg-protected-p521.asc");
const NAME: &str = "Protected Fixture <protected@example.invalid>";

fn scratch() -> (tempfile::TempDir, Store) {
    // Nothing here asks gpg-agent, and should a later change make something
    // do so, it must not be the developer's own; see `agent::AgentHome`.
    rpgp_core::agent::set_home(rpgp_core::agent::AgentHome::Nowhere);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
    (dir, store)
}

/// Import a fixture the way the GUI does, through a file on disk.
fn import(dir: &tempfile::TempDir, store: &Store, bytes: &[u8]) -> Cert {
    let path = dir.path().join("import.asc");
    std::fs::write(&path, bytes).unwrap();
    store.import_file(&path).unwrap();
    Cert::from_bytes(bytes).unwrap()
}

/// Every file in the store's secrets directory, and what it holds.
fn secret_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir.join("secrets"))
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.display().to_string(), std::fs::read(&path).unwrap())
        })
        .collect()
}

/// Every key of `fixture` with its secret, as it was exported.
fn keys(fixture: &[u8]) -> Vec<Key<SecretParts, UnspecifiedRole>> {
    Cert::from_bytes(fixture)
        .unwrap()
        .keys()
        .secret()
        .map(|ka| ka.key().clone())
        .collect()
}

/// What sequoia alone says to `password` for `key`, as rPGP used to pass it on.
fn sequoia_says<R: KeyRole>(key: &Key<SecretParts, R>, password: &str) -> String {
    match key.clone().decrypt_secret(&password.into()) {
        Ok(_) => "unlocked".to_string(),
        Err(refused) => Error::from(refused).to_string(),
    }
}

/// Whether `key`'s secret does what its public half expects: signs what the
/// public key verifies, or opens what the public key encrypts.
fn works<R: KeyRole>(key: Key<SecretParts, R>) -> bool {
    let public = key.parts_as_public().clone();
    let mut pair = key.into_keypair().unwrap();
    if public.pk_algo().for_signing() {
        let digest = [7; 32];
        let signature = pair.sign(HashAlgorithm::SHA256, &digest).unwrap();
        public
            .verify(&signature, HashAlgorithm::SHA256, &digest)
            .is_ok()
    } else {
        let sent = SessionKey::new(32).unwrap();
        let ciphertext = public.encrypt(&sent).unwrap();
        pair.decrypt(&ciphertext, Some(sent.len()))
            .is_ok_and(|opened| opened == sent)
    }
}

/// A message to each key of `recipients` and to no other, whichever other
/// keys their certificates have.
fn to_keys(
    recipients: &[(&Cert, &Key<PublicParts, UnspecifiedRole>)],
    plaintext: &[u8],
) -> Vec<u8> {
    let policy = rpgp_core::policy();
    let recipients = recipients.iter().map(|(cert, key)| {
        let valid = cert.with_policy(&policy, None).unwrap();
        Recipient::new(valid.features(), key.key_handle(), *key)
    });
    let mut ciphertext = Vec::new();
    let message = Message::new(&mut ciphertext);
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .unwrap();
    let mut message = LiteralWriter::new(message).build().unwrap();
    message.write_all(plaintext).unwrap();
    message.finalize().unwrap();
    ciphertext
}

/// `message` with the key its session-key packet names taken out, as
/// `gpg --throw-keyids` writes it: a packet that could be for anybody.
fn hidden_recipient(message: &[u8]) -> Vec<u8> {
    let mut hidden = Vec::new();
    for mut packet in PacketPile::from_bytes(message).unwrap().into_children() {
        if let Packet::PKESK(PKESK::V3(pkesk)) = &mut packet {
            assert!(pkesk.set_recipient(None).is_some(), "premise: it names one");
        }
        packet.serialize(&mut hidden).unwrap();
    }
    hidden
}

/// `key`'s secret as GnuPG writes a 32-byte one: 256 bits declared, whatever
/// the value holds.
fn written_as_gnupg<R: KeyRole>(key: &Key<SecretParts, R>) -> Protected {
    let SecretKeyMaterial::Unencrypted(secret) = key.secret() else {
        panic!("the key is protected");
    };
    secret.map(|secret| {
        let (mpi::SecretKeyMaterial::EdDSA { scalar } | mpi::SecretKeyMaterial::ECDH { scalar }) =
            secret
        else {
            panic!("not a Curve25519 secret");
        };
        let mut mpis = Protected::new(34);
        mpis[..2].copy_from_slice(&256u16.to_be_bytes());
        mpis[2..].copy_from_slice(&scalar.value_padded(32));
        mpis
    })
}

/// `key` with `mpis` for its secret, encrypted again under [`PASSPHRASE`] as
/// GnuPG protects an export, with a SHA-1 checksum over `mpis` exactly as they
/// are.
///
/// An unknown algorithm's secret is written out byte for byte, which is the
/// one way to have sequoia encrypt bytes that it would not write itself.
fn reprotected<R: KeyRole>(key: Key<SecretParts, R>, mpis: Protected) -> Key<SecretParts, R> {
    let secret = Unencrypted::from(mpi::SecretKeyMaterial::Unknown {
        mpis: Vec::new().into_boxed_slice(),
        rest: mpis,
    });
    let encrypted = secret
        .encrypt_with(
            &key,
            S2K::new_iterated(HashAlgorithm::SHA256, 1024).unwrap(),
            SymmetricAlgorithm::AES128,
            None,
            &PASSPHRASE.into(),
        )
        .unwrap();
    key.add_secret(encrypted.into()).0
}

/// The 25519 fixture, damaged: each of its secrets encrypted again under its
/// passphrase over the secret of a stranger's key, written as GnuPG writes
/// it, so that the checksum holds and the secret is not the key's own.
fn damaged() -> Cert {
    let cert = Cert::from_bytes(CURVE25519).unwrap();
    let primary = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap();
    let subkey = cert
        .keys()
        .subkeys()
        .next()
        .unwrap()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap();
    // Strangers whose secrets GnuPG would write with a clear leading bit, as
    // it wrote the fixture's own. A cv25519 scalar always has one; an Ed25519
    // seed about half the time. One with the bit set would be canonical, and
    // sequoia opens a canonical secret whose checksum holds without asking
    // whether it is the key's, as it always has.
    let stranger = |for_signing, curve: Curve| {
        std::iter::repeat_with(|| -> Key<SecretParts, SubordinateRole> {
            Key4::generate_ecc(for_signing, curve.clone())
                .unwrap()
                .into()
        })
        .map(|key| written_as_gnupg(&key))
        .find(|mpis| mpis[2] & 0x80 == 0)
        .unwrap()
    };
    let primary = reprotected(primary, stranger(true, Curve::Ed25519));
    let subkey = reprotected(subkey, stranger(false, Curve::Cv25519));
    cert.insert_packets([Packet::from(primary), Packet::from(subkey)])
        .unwrap()
        .0
}

/// The premise, and the fix. Every secret in the three fixtures this build
/// can use is one that sequoia alone refuses with the right passphrase, as it
/// refused them when they were chosen; if sequoia starts reading them, this
/// says so, and the tests below stop proving anything about the second look.
/// And every one of them opens, to a secret that does what its public key
/// expects of it.
#[test]
fn sequoia_alone_refuses_every_key_here_and_rpgp_opens_each() {
    for key in [CURVE25519, NIST, P521].into_iter().flat_map(keys) {
        let fingerprint = key.fingerprint();
        let refused = key
            .clone()
            .decrypt_secret(&PASSPHRASE.into())
            .expect_err("premise: sequoia alone opens this key");
        assert!(
            matches!(
                refused.downcast_ref::<sequoia_openpgp::Error>(),
                Some(sequoia_openpgp::Error::MalformedMPI(_))
            ),
            "{fingerprint}: premise: {refused}"
        );

        let opened = unlock(key, Some(PASSPHRASE))
            .unwrap_or_else(|e| panic!("{fingerprint}: the right passphrase was refused: {e}"));
        assert!(
            works(opened),
            "{fingerprint}: opened to a secret that does not work"
        );
    }
}

/// What comes out is canonical: sequoia's own strict parser reads it, it can
/// be encrypted again under a passphrase, and what that writes is a key
/// sequoia alone opens, back to the same secret.
#[test]
fn the_opened_secret_is_canonical_and_survives_being_encrypted_again() {
    for fixture in [CURVE25519, NIST, P521] {
        let cert = Cert::from_bytes(fixture).unwrap();
        let mut resealed: Vec<Packet> = Vec::new();
        let mut opened: BTreeMap<Fingerprint, SecretKeyMaterial> = BTreeMap::new();
        for ka in cert.keys().secret() {
            let fingerprint = ka.key().fingerprint();
            let key = unlock(ka.key().clone(), Some(PASSPHRASE)).unwrap();

            let SecretKeyMaterial::Unencrypted(secret) = key.secret() else {
                panic!("{fingerprint}: unlock returned a key still protected");
            };
            let written = secret.map(|mpis| MarshalInto::to_vec(mpis).unwrap());
            assert!(
                mpi::SecretKeyMaterial::from_bytes(key.pk_algo(), &written).is_ok(),
                "{fingerprint}: the secret is not canonical"
            );
            opened.insert(fingerprint.clone(), key.secret().clone());

            let key = key.encrypt_secret(&"resealed".into()).unwrap();
            resealed.push(if fingerprint == cert.fingerprint() {
                key.role_into_primary().into()
            } else {
                key.role_into_subordinate().into()
            });
        }

        let resealed = cert.clone().insert_packets(resealed).unwrap().0;
        let tsk = SerializeInto::to_vec(&resealed.as_tsk()).unwrap();
        let reread = Cert::from_bytes(&tsk).unwrap();
        assert_eq!(reread.keys().secret().count(), opened.len());
        for ka in reread.keys().secret() {
            let fingerprint = ka.key().fingerprint();
            let key = ka
                .key()
                .clone()
                .decrypt_secret(&"resealed".into())
                .unwrap_or_else(|e| {
                    panic!("{fingerprint}: sequoia refused the rewritten key: {e}")
                });
            assert!(
                opened.get(&fingerprint) == Some(key.secret()),
                "{fingerprint}: came back as another secret"
            );
        }
    }
}

/// A message GnuPG encrypted to the cv25519 subkey opens with the key's
/// passphrase, and the Ed25519 primary signs with it; and neither touches
/// the secret key file, which stays as GnuPG wrote it.
#[test]
fn a_message_gnupg_encrypted_to_the_cv25519_subkey_opens_and_the_key_file_is_left_as_it_was() {
    let (dir, store) = scratch();
    let cert = import(&dir, &store, CURVE25519);
    let before = secret_files(dir.path());
    assert_eq!(before.len(), 1, "premise: the key is in the store");

    let mut plaintext = Vec::new();
    let result = ops::decrypt(&store, MESSAGE, &[PASSPHRASE], &mut plaintext)
        .unwrap_or_else(|e| panic!("the message did not open: {e}"));
    assert_eq!(plaintext, PLAINTEXT);
    assert_eq!(result.decrypted_with, Some(cert.fingerprint().to_hex()));

    let mut signature = Vec::new();
    ops::sign_detached(&cert, Some(PASSPHRASE), PLAINTEXT, &mut signature)
        .unwrap_or_else(|e| panic!("the primary did not sign: {e}"));
    let verified = ops::verify_detached(&store, &signature, PLAINTEXT).unwrap();
    assert!(verified.all_good(), "{:?}", verified.signatures);

    assert!(
        secret_files(dir.path()) == before,
        "unlocking rewrote the secret key file"
    );
}

/// Every NIST encryption key opens a message sent to it alone, and each
/// fixture's primary, on P-256 in one and P-521 in the other, signs.
#[test]
fn every_nist_key_opens_a_message_and_the_primary_signs() {
    for (fixture, curves) in [(NIST, 3), (P521, 1)] {
        let (dir, store) = scratch();
        let cert = import(&dir, &store, fixture);
        let policy = rpgp_core::policy();
        let valid = cert.with_policy(&policy, None).unwrap();

        let encryption: Vec<_> = valid.keys().for_transport_encryption().collect();
        assert_eq!(encryption.len(), curves, "premise: one on each curve");
        for ka in encryption {
            let key = ka.key();
            let ciphertext = to_keys(&[(&cert, key)], b"for one key");
            let mut plaintext = Vec::new();
            ops::decrypt(&store, &ciphertext, &[PASSPHRASE], &mut plaintext)
                .unwrap_or_else(|e| panic!("{}: {e}", key.fingerprint()));
            assert_eq!(plaintext, b"for one key");
        }

        let mut signature = Vec::new();
        ops::sign_detached(&cert, Some(PASSPHRASE), b"signed", &mut signature)
            .unwrap_or_else(|e| panic!("{}: the primary did not sign: {e}", cert.fingerprint()));
        let verified = ops::verify_detached(&store, &signature, b"signed").unwrap();
        assert!(verified.all_good(), "{:?}", verified.signatures);
    }
}

/// A wrong passphrase is still reported as one, through a decryption and
/// through `unlock`, exactly as before; the right one no longer is.
#[test]
fn a_wrong_passphrase_is_still_one_and_the_right_one_no_longer_reads_as_one() {
    let (dir, store) = scratch();
    let cert = import(&dir, &store, CURVE25519);

    for (candidates, tried) in [(vec![], false), (vec!["hunter2"], true)] {
        let refused = ops::decrypt(&store, MESSAGE, &candidates, &mut Vec::new())
            .expect_err("opened without the passphrase");
        assert!(
            matches!(&refused, Error::KeyLocked { name, tried: t, or_password: false } if name == NAME && *t == tried),
            "{candidates:?}: {refused:?}"
        );
    }
    let refused = ops::decrypt(&store, MESSAGE, &["hunter2"], &mut Vec::new()).unwrap_err();
    assert!(
        refused.to_string().contains("does not unlock it"),
        "{refused}"
    );
    ops::decrypt(&store, MESSAGE, &[PASSPHRASE], &mut Vec::new())
        .unwrap_or_else(|e| panic!("the right passphrase read as a wrong one: {e}"));

    for key in keys(CURVE25519) {
        let fingerprint = key.fingerprint();
        let refused =
            unlock(key.clone(), Some("hunter2")).expect_err("a wrong passphrase opened it");
        assert_eq!(
            refused.to_string(),
            sequoia_says(&key, "hunter2"),
            "{fingerprint}: a wrong passphrase reads differently"
        );
        assert!(
            matches!(try_unlock(key.clone(), Some("hunter2")), Ok(None)),
            "{fingerprint}: a wrong passphrase should be skipped"
        );
        assert!(
            matches!(try_unlock(key, Some(PASSPHRASE)), Ok(Some(_))),
            "{fingerprint}: the right passphrase was skipped"
        );
    }

    let refused = ops::sign_detached(&cert, Some("hunter2"), PLAINTEXT, Vec::new())
        .expect_err("signed with a wrong passphrase");
    assert!(
        !matches!(refused, Error::KeyUnusable { .. }),
        "a wrong passphrase read as a damaged key: {refused}"
    );
}

/// A secret whose checksum holds and which is not the key's own is a damaged
/// key, and is reported as one, not as a wrong passphrase: here each of the
/// fixture's secrets, re-encrypted under its passphrase over the secret of a
/// stranger's key, written as GnuPG writes it. A wrong passphrase for the
/// same damaged key is still a wrong passphrase.
#[test]
fn a_secret_that_is_not_the_keys_own_is_damage_and_not_a_wrong_passphrase() {
    let damaged = damaged();
    for ka in damaged.keys().secret() {
        let fingerprint = ka.key().fingerprint();
        let refused = unlock(ka.key().clone(), Some(PASSPHRASE)).map(|_| ());
        assert!(
            matches!(
                &refused,
                Err(Error::KeyUnusable { name, why: Unusable::Damaged })
                    if *name == fingerprint.to_hex()
            ),
            "{fingerprint}: {refused:?}"
        );
    }

    let (_dir, store) = scratch();
    store.insert_secret(&damaged).unwrap();

    let refused = ops::decrypt(&store, MESSAGE, &[PASSPHRASE], &mut Vec::new())
        .expect_err("opened with a secret that is not the key's");
    assert!(
        matches!(&refused, Error::KeyUnusable { name, why: Unusable::Damaged } if name == NAME),
        "{refused:?}"
    );
    let message = refused.to_string();
    assert!(
        message.starts_with("the passphrase is right") && message.contains("damaged"),
        "{message}"
    );
    assert!(!message.contains("does not unlock"), "{message}");

    let refused = ops::decrypt(&store, MESSAGE, &["hunter2"], &mut Vec::new()).unwrap_err();
    assert!(
        matches!(refused, Error::KeyLocked { tried: true, .. }),
        "a wrong passphrase for a damaged key read as something else: {refused:?}"
    );

    let refused = ops::sign_detached(&damaged, Some(PASSPHRASE), PLAINTEXT, Vec::new())
        .expect_err("signed with a secret that is not the key's");
    assert!(
        matches!(
            refused,
            Error::KeyUnusable {
                why: Unusable::Damaged,
                ..
            }
        ),
        "{refused:?}"
    );
}

/// A damaged key the message names is reported ahead of a locked key it
/// names as well. What was entered is the damaged key's passphrase, so that is
/// the key the user meant, and being told that what was entered does not
/// unlock the other would send them back to a passphrase that is right.
#[test]
fn a_damaged_key_is_reported_ahead_of_a_locked_one_the_message_also_names() {
    const LOCKED: &str = "Locked <locked@example.org>";
    let mut request = KeyGenRequest::new(LOCKED);
    request.standard = Standard::Rfc4880;
    request.password = Some("another passphrase".to_string().into());
    let locked = generate(&request).unwrap().cert;
    let intact = Cert::from_bytes(CURVE25519).unwrap();
    let policy = rpgp_core::policy();
    let encryption_key = |cert: &Cert| {
        cert.with_policy(&policy, None)
            .unwrap()
            .keys()
            .for_transport_encryption()
            .next()
            .unwrap()
            .key()
            .clone()
    };
    let (for_intact, for_locked) = (encryption_key(&intact), encryption_key(&locked));
    let message = to_keys(
        &[(&intact, &for_intact), (&locked, &for_locked)],
        b"for both",
    );

    // Premise: each key reads as it should on its own. The fixture as GnuPG
    // wrote it opens the message, and the other key, alone, is reported as
    // locked, which only a key the message names is.
    let (_dir, store) = scratch();
    store.insert_secret(&intact).unwrap();
    let mut plaintext = Vec::new();
    ops::decrypt(&store, &message, &[PASSPHRASE], &mut plaintext)
        .unwrap_or_else(|e| panic!("premise: the fixture did not open it: {e}"));
    assert_eq!(plaintext, b"for both");
    let (_dir, store) = scratch();
    store.insert_secret(&locked).unwrap();
    let refused = ops::decrypt(&store, &message, &[PASSPHRASE], &mut Vec::new()).unwrap_err();
    assert!(
        matches!(&refused, Error::KeyLocked { name, tried: true, .. } if name == LOCKED),
        "premise: {refused:?}"
    );

    let (_dir, store) = scratch();
    store.insert_secret(&locked).unwrap();
    store.insert_secret(&damaged()).unwrap();
    let refused = ops::decrypt(&store, &message, &[PASSPHRASE], &mut Vec::new())
        .expect_err("opened with a secret that is not the key's");
    assert!(
        matches!(&refused, Error::KeyUnusable { name, why: Unusable::Damaged } if name == NAME),
        "{refused:?}"
    );
}

/// A damaged key is reported only where the message names it, as a locked
/// key is. A packet that names no key could be for anybody, and sending the
/// user to restore a key from a backup would do nothing for a message that
/// was never for it; here the only packet is GnuPG's own with the key it
/// names taken out.
#[test]
fn a_damaged_key_that_only_a_packet_naming_no_key_could_be_for_is_not_reported() {
    let hidden = hidden_recipient(MESSAGE);

    // Premise: the packet that names no key reaches the fixture's subkey,
    // which opens it.
    let (dir, store) = scratch();
    import(&dir, &store, CURVE25519);
    let mut plaintext = Vec::new();
    ops::decrypt(&store, &hidden, &[PASSPHRASE], &mut plaintext)
        .unwrap_or_else(|e| panic!("premise: the fixture did not open it: {e}"));
    assert_eq!(plaintext, PLAINTEXT);

    let (_dir, store) = scratch();
    store.insert_secret(&damaged()).unwrap();
    let refused = ops::decrypt(&store, &hidden, &[PASSPHRASE], &mut Vec::new())
        .expect_err("opened with a secret that is not the key's");
    assert!(
        !matches!(refused, Error::KeyUnusable { .. } | Error::KeyLocked { .. }),
        "{refused:?}"
    );
    assert!(refused.to_string().contains("no secret key"), "{refused}");
}

/// A Brainpool key that GnuPG wrote the same way opens to the news that this
/// build cannot use it, which is what is true, rather than to a passphrase
/// that does not unlock it. A wrong passphrase is still one.
///
/// Revocation is the operation that shows it, because it signs with the
/// primary without first asking the policy about the certificate, and the
/// policy cannot vouch for this one: its own binding signatures are made on a
/// curve this build cannot verify either.
#[test]
fn a_brainpool_key_is_reported_as_one_this_build_cannot_use_and_not_as_locked() {
    let (_dir, store) = scratch();
    let cert = Cert::from_bytes(BRAINPOOL).unwrap();
    store.insert_secret(&cert).unwrap();
    for key in keys(BRAINPOOL) {
        let fingerprint = key.fingerprint();
        assert_ne!(
            sequoia_says(&key, PASSPHRASE),
            "unlocked",
            "{fingerprint}: premise"
        );
        let refused = unlock(key.clone(), Some(PASSPHRASE));
        assert!(
            matches!(
                &refused,
                Err(Error::KeyUnusable { why: Unusable::Unsupported(curve), .. })
                    if curve == "brainpoolP256r1"
            ),
            "{fingerprint}: {refused:?}"
        );
        assert_eq!(
            unlock(key.clone(), Some("hunter2"))
                .unwrap_err()
                .to_string(),
            sequoia_says(&key, "hunter2"),
            "{fingerprint}"
        );
    }

    let mut request = RevokeRequest::new(cert.fingerprint().to_hex());
    request.reason = Reason::Compromised;
    request.password = Some(PASSPHRASE.to_string().into());
    let refused = revoke_cert(&store, &request).expect_err("signed on a curve this build lacks");
    assert!(
        matches!(
            &refused,
            Error::KeyUnusable {
                why: Unusable::Unsupported(_),
                ..
            }
        ),
        "{refused:?}"
    );
    let message = refused.to_string();
    assert!(
        message.starts_with("the passphrase is right") && message.contains("brainpoolP256r1"),
        "{message}"
    );
}

/// Everything else that unlocks the primary goes through the same place: a
/// new user ID, a new expiry, a certification of someone else's key and a
/// revocation of this one each sign with the Ed25519 primary GnuPG wrote.
#[test]
fn the_primary_changes_certifies_and_revokes_through_the_second_look() {
    let (dir, store) = scratch();
    let cert = import(&dir, &store, CURVE25519);
    let fingerprint = cert.fingerprint().to_hex();

    lifecycle::add_user_id(
        &store,
        &fingerprint,
        "Protected Fixture <second@example.invalid>",
        Some(PASSPHRASE),
    )
    .unwrap_or_else(|e| panic!("add_user_id: {e}"));
    lifecycle::set_expiry(
        &store,
        &fingerprint,
        Some(Duration::from_secs(365 * 24 * 60 * 60)),
        Some(PASSPHRASE),
    )
    .unwrap_or_else(|e| panic!("set_expiry: {e}"));

    let target = generate(&KeyGenRequest::new("Target <target@example.org>"))
        .unwrap()
        .cert;
    store.insert(&target).unwrap();
    let mut request = CertifyRequest::new(&fingerprint, target.fingerprint().to_hex());
    request.user_ids = vec!["Target <target@example.org>".to_string()];
    request.password = Some(PASSPHRASE.to_string().into());
    certify(&store, &request).unwrap_or_else(|e| panic!("certify: {e}"));

    let mut request = RevokeRequest::new(&fingerprint);
    request.reason = Reason::Retired;
    request.password = Some(PASSPHRASE.to_string().into());
    revoke_cert(&store, &request).unwrap_or_else(|e| panic!("revoke_cert: {e}"));
}

/// A damaged key that a message names does not keep anything else from
/// opening it: here the message's own password, which is tried only after
/// every key. Reporting the damaged key as soon as it was found would leave
/// the password, any other key and gpg-agent untried.
#[test]
fn a_damaged_key_does_not_keep_the_messages_password_from_opening_it() {
    let intact = Cert::from_bytes(CURVE25519).unwrap();
    let policy = rpgp_core::policy();
    let key = intact
        .with_policy(&policy, None)
        .unwrap()
        .keys()
        .for_transport_encryption()
        .next()
        .unwrap()
        .key()
        .clone();
    let recipient = Recipient::new(
        intact.with_policy(&policy, None).unwrap().features(),
        key.key_handle(),
        &key,
    );
    let mut ciphertext = Vec::new();
    let message = Message::new(&mut ciphertext);
    let message = Encryptor::for_recipients(message, [recipient])
        .add_passwords(["message password"])
        .build()
        .unwrap();
    let mut message = LiteralWriter::new(message).build().unwrap();
    message.write_all(b"for the key or the password").unwrap();
    message.finalize().unwrap();

    let (_dir, store) = scratch();
    store.insert_secret(&damaged()).unwrap();
    // The premise: with only the key's passphrase, the damaged key is what
    // gets reported.
    let refused = ops::decrypt(&store, &ciphertext, &[PASSPHRASE], &mut Vec::new()).unwrap_err();
    assert!(
        matches!(refused, Error::KeyUnusable { .. }),
        "premise: {refused:?}"
    );
    let mut plaintext = Vec::new();
    ops::decrypt(
        &store,
        &ciphertext,
        &[PASSPHRASE, "message password"],
        &mut plaintext,
    )
    .unwrap_or_else(|e| panic!("the password did not get its turn: {e:?}"));
    assert_eq!(plaintext, b"for the key or the password");
}

/// A Brainpool secret longer than its curve's field is a damaged key, not one
/// on a curve this build cannot use: a curve's size is known whether or not
/// its arithmetic is, and `repaired` asks about the size first.
#[test]
fn an_overlong_brainpool_secret_is_damage_and_not_an_unsupported_curve() {
    for key in keys(BRAINPOOL) {
        let mut mpis = Protected::new(2 + 33);
        mpis[..2].copy_from_slice(&264u16.to_be_bytes());
        for byte in mpis[2..].iter_mut() {
            *byte = 0x11;
        }
        let long = reprotected(key.clone(), mpis);
        let refused = unlock(long, Some(PASSPHRASE));
        assert!(
            matches!(
                refused,
                Err(Error::KeyUnusable {
                    why: Unusable::Damaged,
                    ..
                })
            ),
            "{}: {refused:?}",
            key.fingerprint()
        );
    }
}
