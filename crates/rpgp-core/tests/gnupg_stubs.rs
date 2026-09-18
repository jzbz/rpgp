//! What an import does with the stubs GnuPG writes where it holds no key.
//!
//! `gpg --export-secret-subkeys` keeps the subkey secrets and puts a
//! `gnu-dummy` placeholder where the primary's belongs: a secret-key packet
//! with the private S2K type 101 and no key material in it at all. Sequoia
//! reads that as an encrypted secret, so the file is a transferable secret key
//! by every test rPGP applies to it, and a merge that prefers the incoming
//! secret takes the placeholder over the real primary it already holds.
//!
//! The fixtures are two exports of one throwaway key, made with gpg 2.4.9 in a
//! scratch GNUPGHOME — real gpg output rather than something shaped by hand,
//! because the shape is the thing in question and a guess at it is easy to get
//! backwards:
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
//! Nothing here runs gpg. The fixtures are bytes and the store is a tempdir.

use rpgp_core::Store;
use sequoia_openpgp::Cert;
use sequoia_openpgp::crypto::S2K;
use sequoia_openpgp::packet::key::SecretKeyMaterial;
use sequoia_openpgp::parse::Parse;

const FULL: &[u8] = include_bytes!("fixtures/gnupg-secret-keys.asc");
const SUBKEYS_ONLY: &[u8] = include_bytes!("fixtures/gnupg-secret-subkeys.asc");

fn scratch() -> (tempfile::TempDir, Store) {
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
