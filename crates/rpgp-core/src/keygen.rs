//! Key generation.

use std::time::Duration;

use sequoia_openpgp::Cert;
use sequoia_openpgp::Profile;
use sequoia_openpgp::cert::{CertBuilder, CipherSuite};
use sequoia_openpgp::packet::Signature;

use crate::error::Result;
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
/// The cost falls on other people: a correspondent whose software predates
/// RFC 9580 — GnuPG 2.4, which is still what Debian stable and Ubuntu LTS
/// ship — cannot encrypt to a v6 key or verify its signatures. They see
/// "unknown version 6" rather than anything helpful.
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
            Standard::Rfc9580 => "Stronger. GnuPG 2.5 and later, and Sequoia.",
            Standard::Rfc4880 => "Works with GnuPG 2.4 and everything older.",
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

/// Written out rather than derived, so the passphrase cannot be printed.
///
/// `Zeroizing` is `#[repr(transparent)]` and its `Debug` delegates straight to
/// the inner `String`, so a derived one rendered the passphrase verbatim into
/// whatever formatted it. Nothing does today; the point is that a `dbg!` or an
/// error that captured the request would, and the type carrying a secret should
/// not depend on nobody ever doing that.
impl std::fmt::Debug for KeyGenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyGenRequest")
            .field("user_ids", &self.user_ids)
            .field("key_type", &self.key_type)
            .field("standard", &self.standard)
            .field("validity", &self.validity)
            .field(
                "password",
                match self.password {
                    Some(_) => &"<redacted>",
                    None => &"None",
                },
            )
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

pub fn generate(request: &KeyGenRequest) -> Result<GeneratedKey> {
    if request.user_ids.iter().all(|u| u.trim().is_empty()) {
        return Err(crate::Error::invalid("a key needs at least one user ID"));
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

    for uid in request.user_ids.iter().filter(|u| !u.trim().is_empty()) {
        builder = builder.add_userid(uid.trim());
    }

    if let Some(password) = request.password.as_deref().filter(|p| !p.is_empty()) {
        builder = builder.set_password(Some(password.as_str().into()));
    }

    let (cert, revocation) = builder.generate()?;
    Ok(GeneratedKey { cert, revocation })
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
}
