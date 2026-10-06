//! Key generation.

use std::time::Duration;

use sequoia_openpgp::Cert;
use sequoia_openpgp::Profile;
use sequoia_openpgp::cert::{CertBuilder, CipherSuite};
use sequoia_openpgp::packet::{Signature, UserID};

use crate::error::{Error, Result};
use crate::store::Store;
use zeroize::Zeroizing;

/// Key types offered in the new-key dialog.
///
/// Deliberately short: Kleopatra's full algorithm matrix is a footgun, and the
/// only two answers that matter are "the modern default" and "RSA, because the
/// other end is old".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyType {
    /// Ed25519 signing, X25519 encryption.
    #[default]
    Curve25519,
    Rsa3072,
    Rsa4096,
}

impl KeyType {
    fn cipher_suite(self) -> CipherSuite {
        match self {
            KeyType::Curve25519 => CipherSuite::Cv25519,
            KeyType::Rsa3072 => CipherSuite::RSA3k,
            KeyType::Rsa4096 => CipherSuite::RSA4k,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            KeyType::Curve25519 => "Curve 25519 (recommended)",
            KeyType::Rsa3072 => "RSA 3072",
            KeyType::Rsa4096 => "RSA 4096",
        }
    }

    pub const ALL: [KeyType; 3] = [KeyType::Curve25519, KeyType::Rsa3072, KeyType::Rsa4096];
}

/// Which OpenPGP standard the key is built to.
///
/// The difference is not cosmetic. RFC 9580 keys get SEIPDv2 with AEAD and
/// Argon2 for password hashing; RFC 4880 keys get CFB with an MDC and iterated
/// SHA-256. The newer one is better cryptography.
///
/// The cost falls on other people: a correspondent whose software does not
/// implement RFC 9580 cannot encrypt to a v6 key or verify its signatures.
/// That is every version of GnuPG, 2.5 included, which follows LibrePGP and its
/// v5 keys instead, as well as anything older. GnuPG 2.4 says "unknown version
/// 6" rather than anything helpful.
///
/// v6 is the default anyway, because that failure is loud and fixable while
/// weaker cryptography is silent and permanent, and because keys outlive the
/// software that cannot read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Standard {
    /// RFC 9580, the OpenPGP crypto refresh. Version 6 keys.
    #[default]
    Rfc9580,
    /// RFC 4880. Version 4 keys, readable by everything deployed.
    Rfc4880,
}

impl Standard {
    pub const ALL: [Standard; 2] = [Standard::Rfc9580, Standard::Rfc4880];

    pub fn label(self) -> &'static str {
        match self {
            Standard::Rfc9580 => "Modern (RFC 9580)",
            Standard::Rfc4880 => "Compatible (RFC 4880)",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Standard::Rfc9580 => "Stronger. Sequoia and other RFC 9580 software, not GnuPG.",
            Standard::Rfc4880 => "Works with every version of GnuPG and everything older.",
        }
    }

    pub fn from_index(index: i32) -> Self {
        Standard::ALL
            .get(index.max(0) as usize)
            .copied()
            .unwrap_or_default()
    }

    fn to_profile(self) -> Profile {
        match self {
            Standard::Rfc9580 => Profile::RFC9580,
            Standard::Rfc4880 => Profile::RFC4880,
        }
    }
}

#[derive(Clone)]
pub struct KeyGenRequest {
    /// Full user IDs, e.g. `Alice <alice@example.org>`.
    pub user_ids: Vec<String>,
    pub key_type: KeyType,
    pub standard: Standard,
    /// Lifetime from now. `None` means the key never expires; an expiry that
    /// can be extended later is the better default, so the GUI pre-fills two
    /// years rather than "never".
    pub validity: Option<Duration>,
    pub password: Option<Zeroizing<String>>,
}

/// Written out rather than derived, so the passphrase cannot be printed; see
/// `secret::redacted`.
impl std::fmt::Debug for KeyGenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyGenRequest")
            .field("user_ids", &self.user_ids)
            .field("key_type", &self.key_type)
            .field("standard", &self.standard)
            .field("validity", &self.validity)
            .field("password", &crate::secret::redacted(&self.password))
            .finish()
    }
}

impl KeyGenRequest {
    pub fn new(user_id: impl Into<String>) -> Self {
        KeyGenRequest {
            user_ids: vec![user_id.into()],
            key_type: KeyType::default(),
            standard: Standard::default(),
            validity: Some(TWO_YEARS),
            password: None,
        }
    }
}

pub const TWO_YEARS: Duration = Duration::from_secs(2 * 365 * 24 * 60 * 60);

pub struct GeneratedKey {
    pub cert: Cert,
    /// A pre-made revocation certificate. It is produced once, at generation
    /// time, and cannot be recreated later without the secret key — losing it
    /// is how people end up with an un-retractable key.
    pub revocation: Signature,
}

/// Refuse a user ID that no key should be given.
///
/// OpenPGP itself puts no rule on what a user ID says: RFC 9580 (section
/// 5.11) calls a name and an address in the form of a mail header a
/// convention only, and GnuPG's `--quick-gen-key` makes a key for `<>` as
/// readily as for anything else. So this refuses only what cannot have been
/// meant, all of which used to go through:
///
/// - Nothing at all, once spaces are trimmed.
/// - A control character. Nobody types one, and Slint drops them from the
///   keyboard, but a paste brings them in: a single-line field turns a pasted
///   line feed into a space and leaves a carriage return or a tab as it is.
///   Looked for on its own, because the parse below runs only where there are
///   angle brackets, and even there it reads every character from U+0080 up
///   as text, the C1 controls among them.
/// - Angle brackets that do not hold an address: `<>`, `Alice <>`, `Alice
///   <alice>`, a second pair after the first, or anything after the `>`. The
///   address is what WKD, a keyserver's search and `gpg --locate-keys` find a
///   key by, and a key whose only user ID has none there cannot be found by
///   any of them. The new-key dialog made `<>` out of two fields of spaces.
///   Sequoia's reading of the convention decides what an address is, and it
///   takes a URI there as well as an e-mail address.
///
/// A name alone, an address alone, with or without its brackets, and a comment
/// in parentheses before the address are all accepted: keys made with GnuPG
/// commonly carry each of them. Text with no angle bracket in it is a name as
/// the convention reads it, whatever else it says.
pub fn check_user_id(user_id: &str) -> Result<()> {
    let user_id = user_id.trim();
    if user_id.is_empty() {
        return Err(Error::invalid("a user ID cannot be empty"));
    }
    refuse_control_characters(user_id)?;
    if user_id.contains(['<', '>']) {
        let parsed = UserID::from(user_id);
        if !matches!(parsed.email(), Ok(Some(_))) && !matches!(parsed.uri(), Ok(Some(_))) {
            // The reason first and the user ID, as long as anyone typed it,
            // last: the status line that also shows this cuts off whatever
            // goes past its last line.
            return Err(Error::invalid(format!(
                "an e-mail address goes between < and >, alone and at the end: {user_id}"
            )));
        }
    }
    Ok(())
}

/// The user ID the new-key dialog's two fields make: `Name <address>`, or
/// either part alone when the other field is left empty. An address alone
/// keeps its brackets, `<address>`, which is the form Sequoia's
/// `UserID::from_address` gives it; GnuPG writes it bare, and both read as an
/// address.
///
/// Refused when both are empty once trimmed, when the address is not an
/// e-mail address, and wherever [`check_user_id`] refuses the result. Slint
/// has no trim, so a field of spaces looks filled in to the dialog, and this
/// is where that is found out. The address is checked on its own before the
/// two are put together, so that the refusal names the field at fault: put
/// together, `Alice <alice>` is refused as a user ID in the wrong form, which
/// is not what the user typed.
pub fn user_id(name: &str, address: &str) -> Result<String> {
    let (name, address) = (name.trim(), address.trim());
    if name.is_empty() && address.is_empty() {
        return Err(Error::invalid("a key needs a name or an e-mail address"));
    }
    refuse_control_characters(name)?;
    refuse_control_characters(address)?;
    // from_address reads what it is given as the address alone, and refuses
    // a URI, which the dialog's field does not ask for.
    if !address.is_empty() && UserID::from_address(None, None, address).is_err() {
        return Err(Error::invalid(format!(
            "{address} is not an e-mail address"
        )));
    }
    let user_id = match (name.is_empty(), address.is_empty()) {
        (false, false) => format!("{name} <{address}>"),
        (true, false) => format!("<{address}>"),
        _ => name.to_string(),
    };
    check_user_id(&user_id)?;
    Ok(user_id)
}

fn refuse_control_characters(text: &str) -> Result<()> {
    if text.contains(char::is_control) {
        return Err(Error::invalid(
            "a user ID cannot hold a control character, such as a tab or a carriage return \
             pasted in with it",
        ));
    }
    Ok(())
}

/// Make a key. Every user ID in the request that is not blank goes through
/// [`check_user_id`], and one it refuses refuses the request; blank ones are
/// passed over, as long as one is left.
pub fn generate(request: &KeyGenRequest) -> Result<GeneratedKey> {
    let user_ids: Vec<&str> = request
        .user_ids
        .iter()
        .map(|u| u.trim())
        .filter(|u| !u.is_empty())
        .collect();
    if user_ids.is_empty() {
        return Err(crate::Error::invalid("a key needs at least one user ID"));
    }
    for user_id in &user_ids {
        check_user_id(user_id)?;
    }

    let mut builder = CertBuilder::new()
        // Set explicitly rather than left to the library default: which
        // standard a key is built to decides who can talk to its owner, and
        // that should be a visible decision in this file.
        .set_profile(request.standard.to_profile())?
        .set_cipher_suite(request.key_type.cipher_suite())
        .set_validity_period(request.validity)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey();

    for user_id in user_ids {
        builder = builder.add_userid(user_id);
    }

    if let Some(password) = request.password.as_deref().filter(|p| !p.is_empty()) {
        builder = builder.set_password(Some(password.as_str().into()));
    }

    let (cert, revocation) = builder.generate()?;
    Ok(GeneratedKey { cert, revocation })
}

/// What [`save`] kept of a key.
#[derive(Debug)]
pub enum Saved {
    /// The key, both halves of it, and the revocation certificate made with
    /// it.
    Whole,
    /// The key, both halves of it, and not its revocation certificate, which
    /// could not be written for the reason given.
    WithoutRevocation(Error),
}

/// Put a key [`generate`] made into the store, then the revocation
/// certificate made with it.
///
/// The key comes first. An error means that nothing of it was kept, so that
/// trying again makes one key rather than two, unless the error says that the
/// new key's secret key could not be removed again; see below. The certificate
/// follows the key because it is worth nothing without one, and because
/// written first it would be left behind whenever the key failed to follow.
/// Once the key is stored, a certificate that cannot be written is
/// [`Saved::WithoutRevocation`] rather than an error. The GUI used to do both
/// in one chain, which reported a certificate that failed after the key was
/// stored as a key generation that had failed: the dialog stayed open with
/// every field filled in, its button made a second key with the same user ID,
/// and the first, held and unlisted until something else reloaded the list,
/// never had a revocation certificate at all.
///
/// Where the secret key is written and cert-d then refuses its public half,
/// the key is removed again. It would otherwise be held where nothing lists
/// it, since the list is read from cert-d, and a key no one has seen yet is
/// better gone than kept out of reach while the user tries again. Should the
/// removal fail as well, the error says that the secret key could not be
/// removed again, and that key stays in the secrets directory, unlisted.
pub fn save(store: &Store, key: &GeneratedKey) -> Result<Saved> {
    let fingerprint = key.cert.fingerprint().to_hex();
    match store.insert_secret(&key.cert) {
        Ok(()) => {}
        Err(Error::PublicCertNotUpdated(refused)) => {
            // Judged by whether the secret key is still there rather than by
            // what the delete returns. Its last step unlinks the certificate
            // in cert-d, which is not there to unlink, and on Unix that step
            // fails outright when whatever refused the key was a file standing
            // where cert-d wanted the certificate's directory.
            let undo = store.delete(&fingerprint, true);
            return Err(if !store.has_secret(&fingerprint) {
                Error::invalid(format!(
                    "the new key could not be added to the certificate store, \
                     and was removed again: {refused}"
                ))
            } else {
                Error::invalid(format!(
                    "the new key could not be added to the certificate store \
                     ({refused}), and its secret key could not be removed \
                     again{}",
                    undo.err().map(|e| format!(": {e}")).unwrap_or_default()
                ))
            });
        }
        Err(e) => return Err(e),
    }

    // Written once, now: a revocation certificate cannot be recreated later
    // without the secret key, and this is the only moment it is certain to be
    // unlocked.
    match crate::revoke::armor(&key.revocation)
        .and_then(|armored| store.save_revocation(&fingerprint, &armored))
    {
        Ok(()) => Ok(Saved::Whole),
        Err(e) => Ok(Saved::WithoutRevocation(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_usable_key() {
        let key = generate(&KeyGenRequest::new("Alice <alice@example.org>")).unwrap();
        let summary = crate::CertSummary::from_cert(&key.cert);

        assert_eq!(summary.primary_user_id, "Alice <alice@example.org>");
        assert_eq!(summary.validity, crate::Validity::Valid);
        assert!(summary.has_secret);
        assert_eq!(summary.capabilities(), "CSE");
        assert!(summary.expires.is_some());
    }

    #[test]
    fn builds_to_the_requested_standard() {
        use sequoia_openpgp::serialize::SerializeInto;

        // The packet version is what other software keys off, so assert on the
        // bytes rather than on our own enum round-tripping.
        for (standard, want) in [(Standard::Rfc9580, 6u8), (Standard::Rfc4880, 4u8)] {
            let mut request = KeyGenRequest::new("Alice <alice@example.org>");
            request.standard = standard;
            let cert = generate(&request).unwrap().cert;

            let bytes = cert.to_vec().unwrap();
            // A public key packet: tag 6, and the version is its first body byte.
            let version = bytes[2];
            assert_eq!(version, want, "{standard:?} should produce v{want} packets");
        }
    }

    #[test]
    fn rejects_an_empty_user_id() {
        let mut request = KeyGenRequest::new("");
        request.user_ids = vec!["   ".into()];
        assert!(generate(&request).is_err());
    }

    /// User IDs in the shapes keys made with GnuPG commonly carry are
    /// accepted, and what cannot have been meant is refused, by the check and
    /// by key generation alike.
    ///
    /// Generation used to refuse only a user ID that was blank, so `<>`, a
    /// name with nothing in its brackets, and text pasted with a carriage
    /// return in it were all made into keys.
    #[test]
    fn a_key_takes_the_usual_user_ids_and_refuses_what_cannot_have_been_meant() {
        for usual in [
            "Alice <alice@example.org>",
            "Alice",
            "alice@example.org",
            "<alice@example.org>",
            "Alice (work) <alice@work.example>",
            "Alice (release signing 2026)",
            "Smith, John <john.smith+pgp@example.org>",
            "Jörg Müller <jörg@bücher.example>",
            "NAS <ssh://nas.example.org>",
        ] {
            check_user_id(usual).unwrap_or_else(|e| panic!("{usual:?} was refused: {e}"));
        }
        generate(&KeyGenRequest::new("Alice (work)")).expect("a name and a comment make a key");

        for meaningless in [
            "<>",
            "Alice <>",
            "Alice <alice>",
            "Alice <ceo@corp.example> <alice@example.org>",
            "Alice <alice@example.org> (work)",
            "Al\rice <alice@example.org>",
            // Without brackets the parse finds a name in anything, so only the
            // control-character check sees these two.
            "Al\rice",
            "Alice\tSmith",
            // A C1 control, which the parse reads as text even beside an
            // address.
            "Alice\u{85} <alice@example.org>",
        ] {
            assert!(
                check_user_id(meaningless).is_err(),
                "{meaningless:?} was accepted"
            );
            assert!(
                generate(&KeyGenRequest::new(meaningless)).is_err(),
                "a key was made for {meaningless:?}"
            );
        }
    }

    /// The new-key dialog's two fields make `Name <address>`, or either part
    /// alone, and a field of spaces counts as empty.
    ///
    /// The dialog used to format both fields into `{} <{}>` whatever they
    /// held, so spaces in both made the user ID `<>`, and spaces in the e-mail
    /// field made `Alice <>`.
    #[test]
    fn the_new_key_dialog_makes_a_user_id_from_either_field_or_both() {
        for (name, address, made) in [
            (
                " Alice ",
                " alice@example.org ",
                "Alice <alice@example.org>",
            ),
            ("Alice", "  ", "Alice"),
            ("", "alice@example.org", "<alice@example.org>"),
            (
                "Alice (work)",
                "alice@work.example",
                "Alice (work) <alice@work.example>",
            ),
        ] {
            assert_eq!(
                user_id(name, address).map_err(|e| e.to_string()).as_deref(),
                Ok(made),
                "from {name:?} and {address:?}"
            );
        }

        for (name, address, why) in [
            (" ", " ", "a name or an e-mail address"),
            ("", "", "a name or an e-mail address"),
            ("Alice", "alice", "alice is not an e-mail address"),
            ("Alice", "https://example.org", "is not an e-mail address"),
            ("Alice", "ali\u{85}ce@example.org", "control character"),
            ("Al\rice", "alice@example.org", "control character"),
            (
                "Alice <ceo@corp.example>",
                "alice@example.org",
                "between < and >",
            ),
        ] {
            let refusal = user_id(name, address)
                .expect_err(&format!("{name:?} and {address:?} made a user ID"))
                .to_string();
            assert!(refusal.contains(why), "{name:?} and {address:?}: {refusal}");
        }
    }

    /// A key whose revocation certificate cannot be written is still stored,
    /// and saving it says what is missing rather than failing.
    ///
    /// A failure here used to be a failed key generation, though the key was
    /// already in the store, and the retry it invited made a second key with
    /// the same user ID. A file sits where the revocations directory goes:
    /// opening the store passes over it, and writing the certificate fails.
    #[test]
    fn a_key_whose_revocation_certificate_cannot_be_written_is_kept_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        let store = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
        std::fs::write(secrets.with_file_name("revocations"), b"").unwrap();
        let key = generate(&KeyGenRequest::new("Alice <alice@example.org>")).unwrap();
        let fingerprint = key.cert.fingerprint().to_hex();

        match save(&store, &key) {
            Ok(Saved::WithoutRevocation(_)) => {}
            other => panic!("expected the key kept without its certificate: {other:?}"),
        }
        assert!(store.has_secret(&fingerprint));
        assert!(
            store.lookup(&fingerprint).is_ok(),
            "the key should be listed, so that it is not made again"
        );
        assert!(!store.has_revocation(&fingerprint));

        // And with nothing in the way, both are kept.
        std::fs::remove_file(secrets.with_file_name("revocations")).unwrap();
        let key = generate(&KeyGenRequest::new("Bob <bob@example.org>")).unwrap();
        assert!(matches!(save(&store, &key), Ok(Saved::Whole)));
        assert!(store.has_revocation(&key.cert.fingerprint().to_hex()));
    }

    /// A key cert-d will not take is removed again, so that nothing of a
    /// generation reported as failed is left in the store.
    ///
    /// The secret half is written before cert-d is asked for the public one,
    /// and a secret key with no certificate in cert-d is held where nothing
    /// lists it: out of reach, while the retry the failure invites makes
    /// another. Here cert-d fails because a file sits where it wants a
    /// directory for the fingerprint.
    #[test]
    fn a_key_cert_d_refuses_is_removed_again() {
        let dir = tempfile::tempdir().unwrap();
        let (certs, secrets) = (dir.path().join("certs.d"), dir.path().join("secrets"));
        let store = Store::open(&certs, &secrets).unwrap();
        let key = generate(&KeyGenRequest::new("Alice <alice@example.org>")).unwrap();
        let fingerprint = key.cert.fingerprint().to_hex();
        std::fs::write(certs.join(&fingerprint.to_lowercase()[..2]), b"").unwrap();

        let refused = save(&store, &key).expect_err("cert-d took the key after all");
        assert!(refused.to_string().contains("removed again"), "{refused}");
        assert!(!store.has_secret(&fingerprint));
        assert_eq!(
            std::fs::read_dir(&secrets).unwrap().count(),
            0,
            "a failed generation left something of the key behind"
        );
        assert!(!store.has_revocation(&fingerprint));
    }
}
