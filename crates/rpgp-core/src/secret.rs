//! The one place a secret key is unlocked, and the one place that says whether
//! a secret is real key material at all.
//!
//! Choosing *which* key to use is deliberately not here. Signing, certification
//! and decryption each want a different key, and they disagree about what
//! counts as usable — decryption accepts expired and revoked keys on purpose,
//! because revoking a key withdraws it for future use and does not burn the
//! archive. Folding those filters together would silently change which subkey
//! an operation reaches for, so each caller still selects its own.
//!
//! What every caller does share is the last step: if the key is
//! passphrase-protected, decrypt it, then turn it into something that can sign
//! or decrypt. That is what lives here — so that if key material ever moves out
//! of this process, this is the file that changes. It is also where a secret
//! sequoia will not decrypt is given a second look, since GnuPG writes most of
//! the elliptic-curve secrets it exports with a passphrase in a form sequoia
//! refuses; see [`unlock`].
//!
//! Nothing here caches. A key is unlocked for one operation and dropped, and
//! sequoia zeroes it on the way out, but for the one copy that second look
//! leaves behind, which `cfb_plaintext` describes. See [`crate::store`] for
//! what that does and does not protect against.

use std::io::Read;

use sequoia_openpgp::crypto::mem::Protected;
use sequoia_openpgp::crypto::mpi::{self, ProtectedMPI, SecretKeyChecksum};
use sequoia_openpgp::crypto::symmetric::{self, BlockCipherMode, UnpaddingMode};
use sequoia_openpgp::crypto::{Decryptor, KeyPair, Password, S2K, SessionKey, Signer};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::key::{
    Encrypted, KeyParts, KeyRole, SecretKeyMaterial, SecretParts, Unencrypted,
};
use sequoia_openpgp::parse::{Cookie, buffered_reader};
use sequoia_openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};
use zeroize::Zeroizing;

use crate::error::{Error, Result, Unusable};

/// What a request's `Debug` shows in place of the passphrase it carries.
///
/// `Zeroizing` is `#[repr(transparent)]` and its `Debug` delegates straight to
/// the inner `String`, so a derived `Debug` renders the passphrase verbatim
/// into whatever formats the request. Nothing does today; the point is that a
/// `dbg!` or an error that captured a request would, and a type carrying a
/// secret should not depend on nobody ever doing that. So every request that
/// carries one, [`crate::keygen::KeyGenRequest`],
/// [`crate::certify::CertifyRequest`] and [`crate::revoke::RevokeRequest`],
/// writes its `Debug` out and puts this where the passphrase would be.
pub(crate) fn redacted(password: &Option<Zeroizing<String>>) -> &'static str {
    match password {
        Some(_) => "<redacted>",
        None => "None",
    }
}

/// Whether `secret` is key material this process could ever use, as opposed to
/// a placeholder standing where key material is not.
///
/// GnuPG writes a stub wherever an export carries no key material: `gnu-dummy`
/// for the primary that `gpg --export-secret-subkeys` deliberately leaves out,
/// and `divert-to-card` for a key that lives on a smartcard, whose secret half
/// gpg could not export even if asked to. Both are secret-key packets with the
/// private S2K type 101, so sequoia parses them as an encrypted secret and
/// `has_secret` — and therefore `Cert::is_tsk` — is true of them. No passphrase
/// opens either. Ask this instead of `has_secret` wherever the answer decides
/// whether an operation can proceed, or which of two copies of a key to keep.
///
/// Encryption alone is not the question, which is why this is not
/// `!is_encrypted`: an ordinary passphrase-protected key is real material that
/// the user can open. The test is [`S2K::is_supported`], not a match on the
/// variants, because `S2K` is `#[non_exhaustive]` and `is_supported` is false
/// for exactly the two kinds that carry no derivation sequoia can run,
/// `Private` and `Unknown`.
///
/// [`S2K::is_supported`]: sequoia_openpgp::crypto::S2K::is_supported
pub fn is_usable(secret: &SecretKeyMaterial) -> bool {
    match secret {
        SecretKeyMaterial::Unencrypted(_) => true,
        SecretKeyMaterial::Encrypted(encrypted) => encrypted.s2k().is_supported(),
    }
}

/// Whether this process can sign with `key` itself, without gpg-agent: its
/// secret half is here as key material rather than a stub ([`is_usable`]), and
/// its algorithm is one this build has.
///
/// Asked of the primary key by [`crate::certify::certify`], which goes to the
/// agent for the primary when the answer is no, and by what tells the Certify
/// button which keys the store can certify with, `primary_secret` on
/// [`crate::CertSummary`], so that the two cannot come apart.
pub fn can_sign_here<P: KeyParts, R: KeyRole>(key: &Key<P, R>) -> bool {
    key.pk_algo().is_supported() && key.optional_secret().is_some_and(is_usable)
}

/// Decrypt `key` if it is passphrase-protected, otherwise hand it back as-is.
///
/// A missing passphrase is an error rather than an attempt with an empty one:
/// the caller has a key it cannot use, and saying so beats a decrypt failure
/// that reads like a wrong passphrase.
///
/// Generic over the key's role, and that is load-bearing rather than tidiness.
/// An RFC 9580 key's secret is AEAD-protected, and the packet tag that goes
/// into the AEAD schedule depends on whether the key is a primary or a subkey.
/// A key whose role has been erased with `role_into_unspecified` cannot supply
/// that tag, and sequoia refuses it: *cannot decrypt key with unspecified
/// role*. RFC 4880 keys use CFB, never consult the role, and so hide the
/// problem. Take the caller's role and give it back rather than flattening it.
///
/// A secret sequoia refuses to decrypt is not taken to have been given the
/// wrong passphrase on that alone. From 2.3 on, GnuPG protects an
/// elliptic-curve secret for export with a length that counts every bit of
/// the bytes it stores it in, leading zero bits included, where OpenPGP
/// counts from the first bit set. Sequoia 2.4.1 refuses such a secret with
/// the same "malformed MPI" a wrong passphrase sometimes gets. Every cv25519
/// subkey GnuPG 2.4 exports with a passphrase is written that way, as are
/// about half of its Ed25519 and NIST P-256 and P-384 keys and more of its
/// P-521 and Brainpool ones, so a key made with GnuPG's defaults decrypted
/// nothing here, and the user was told the passphrase was wrong.
///
/// So a refusal of a version 4 key protected the way GnuPG protects one, with
/// CFB under an iterated S2K, is looked into: the secret is decrypted a second
/// time, through sequoia's public API, and the checksum written under the
/// encryption is checked over the bytes as they were written, before anything
/// reads the lengths they declare. Then:
///
/// - A checksum that does not match is a wrong passphrase, and sequoia's
///   refusal is what comes back, as it always has.
/// - A checksum that matches, over one elliptic-curve secret whose declared
///   length only overstates it and which is no longer than its curve allows,
///   is read as that secret. It is handed back in canonical form, and only
///   once it has signed what the public key verifies, or opened what the
///   public key encrypted, so that nothing that merely passes a checksum
///   stands in for the key.
/// - A SHA-1 checksum that matches over anything else, or over a secret that
///   is not the public key's, is [`Error::KeyUnusable`]: the passphrase is
///   right, and the key is damaged, or on a curve this build cannot use.
/// - A 16-bit checksum that matches over anything short of a secret proven to
///   be the key's is still a wrong passphrase. One wrong passphrase in 65,536
///   passes a 16-bit sum, which is too often to tell someone their key is
///   damaged on the strength of one. Such a key is refused as it was before;
///   GnuPG writes SHA-1.
///
/// An AEAD-protected secret needs none of this, since sequoia authenticates
/// it before reading any of it: a secret that authenticates and then does not
/// parse is [`Error::KeyUnusable`], and every other refusal is sequoia's. No
/// program is known to write one that way, so none is read the long way.
///
/// None of this writes anything. The secret key file stays as GnuPG wrote it,
/// and is read the long way each time it is unlocked.
pub fn unlock<R: KeyRole>(
    key: Key<SecretParts, R>,
    password: Option<&str>,
) -> Result<Key<SecretParts, R>> {
    let SecretKeyMaterial::Encrypted(encrypted) = key.secret() else {
        // Saying nothing here would be worse than pedantic. The operation
        // succeeds either way, so a passphrase typed against a key that has
        // none looks accepted — and the next time it is typed wrongly against
        // a key that *is* protected, the failure is a surprise. It usually
        // means the wrong key is selected.
        if password.is_some_and(|p| !p.is_empty()) {
            return Err(Error::invalid(
                "this key has no passphrase; leave the passphrase field empty",
            ));
        }
        return Ok(key);
    };
    let password: Password = password
        .filter(|p| !p.is_empty())
        .ok_or_else(|| Error::invalid("this key is passphrase-protected"))?
        .into();
    // What `Key::decrypt_secret` does, taken apart only so that its refusal
    // can be looked into before it is passed on.
    let secret = match encrypted.decrypt(&key, &password) {
        Ok(secret) => secret,
        Err(refused) => recover(&key, encrypted, &password, refused)?,
    };
    Ok(key.add_secret(secret.into()).0)
}

/// [`unlock`], for a caller working through a list of candidate keys.
///
/// `Ok(None)` where [`unlock`] would return an error, because a key that cannot
/// be opened is a reason to try the next one rather than to give up. The
/// decryption path needs this: a message may name several recipients, and only
/// one of them has to work.
///
/// That includes [`unlock`]'s objection to a passphrase supplied for a key that
/// has none. There the caller named one key and one passphrase, so a mismatch
/// is worth reporting; here the same secret is tried against every candidate
/// key and against the message's own passwords, so it carries no such claim.
///
/// It does not include [`Error::KeyUnusable`], whose reason comes back as the
/// error. That key did open, so there is no point offering it the other
/// candidates, and passing over it in silence is what left the user to be told
/// that the passphrase entered does not unlock it.
pub fn try_unlock<R: KeyRole>(
    key: Key<SecretParts, R>,
    password: Option<&str>,
) -> std::result::Result<Option<Key<SecretParts, R>>, Unusable> {
    match unlock(key, password) {
        Ok(key) => Ok(Some(key)),
        Err(Error::KeyUnusable { why, .. }) => Err(why),
        Err(_) => Ok(None),
    }
}

/// What [`unlock`]'s passphrase really met when sequoia refused `encrypted`,
/// and the secret it withheld where that can be had. [`unlock`] says what
/// comes back for what.
fn recover<R: KeyRole>(
    key: &Key<SecretParts, R>,
    encrypted: &Encrypted,
    password: &Password,
    refused: anyhow::Error,
) -> Result<Unencrypted> {
    let unusable = |why| Error::KeyUnusable {
        name: key.fingerprint().to_hex(),
        why,
    };

    if encrypted.aead_algo().is_some() {
        return Err(if parsed_after_authenticating(&refused) {
            unusable(Unusable::Damaged)
        } else {
            refused.into()
        });
    }

    // GnuPG's shape, and nothing else: a version 6 key may not carry the
    // encoding at all (RFC 9580, section 3.2), and a version 4 key under any
    // other S2K is not one GnuPG exported. This also keeps the second look
    // inside what sequoia allows, since the one CFB protection it refuses on
    // a version 4 key is an Argon2 S2K.
    let (4, Some(checksum), S2K::Iterated { .. }) =
        (key.version(), encrypted.checksum(), encrypted.s2k())
    else {
        return Err(refused.into());
    };
    let Some(plaintext) = cfb_plaintext(encrypted, password) else {
        return Err(refused.into());
    };
    let Some(mpis) = checksummed(&plaintext, checksum) else {
        return Err(refused.into());
    };
    match repaired(key, mpis) {
        Ok(secret) => Ok(secret),
        Err(why) if checksum == SecretKeyChecksum::SHA1 => Err(unusable(why)),
        Err(_) => Err(refused.into()),
    }
}

/// Whether an AEAD-protected secret was refused only after it had been
/// authenticated, which a wrong passphrase cannot get past.
///
/// In sequoia 2.4.1 `Encrypted::decrypt` decrypts and authenticates the whole
/// secret before it parses any of it. A failed authentication is
/// `ManipulatedMessage` from EAX, and the AEAD crate's own error from OCB and
/// GCM; what the parse refuses is a malformed MPI, or the end of the secret
/// reached before a length it declares, and nothing ahead of the parse
/// returns either.
fn parsed_after_authenticating(refused: &anyhow::Error) -> bool {
    matches!(
        refused.downcast_ref::<sequoia_openpgp::Error>(),
        Some(sequoia_openpgp::Error::MalformedMPI(_))
    ) || refused
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::UnexpectedEof)
}

/// `encrypted`, decrypted with the key `password` derives, as sequoia's own
/// `Encrypted::decrypt` decrypts CFB: with a zero IV, and the first block,
/// which is the real IV encrypted, dropped.
///
/// Sequoia offers CFB only through `symmetric::Decryptor`, which feeds the
/// decryption through an ordinary buffered reader, so a copy of the secret is
/// left in memory that is freed without being cleared, where sequoia's own
/// path leaves at most a partial block of it. What this function keeps is all
/// in `Protected`. The copy it cannot reach is the price of reading a key
/// sequoia will not, and a key that sequoia does read never comes here with
/// the right passphrase.
fn cfb_plaintext(encrypted: &Encrypted, password: &Password) -> Option<Protected> {
    let algo = encrypted.algo();
    let block = algo.block_size().ok()?;
    let ciphertext = encrypted.ciphertext().ok()?;
    let mut plaintext = Protected::new(ciphertext.len().checked_sub(block)?);
    let derived = encrypted
        .s2k()
        .derive_key(password, algo.key_size().ok()?)
        .ok()?;
    let mut decryptor = symmetric::Decryptor::new(
        algo,
        BlockCipherMode::CFB,
        UnpaddingMode::None,
        &derived,
        None,
        buffered_reader::Memory::with_cookie(ciphertext, Cookie::default()),
    )
    .ok()?;
    decryptor.read_exact(&mut Protected::new(block)).ok()?;
    decryptor.read_exact(&mut plaintext).ok()?;
    Some(plaintext)
}

/// The secret's MPIs, the front of `plaintext`, if the checksum that ends it
/// is right over them as they were written, whatever lengths they declare.
fn checksummed(plaintext: &[u8], checksum: SecretKeyChecksum) -> Option<&[u8]> {
    let length = match checksum {
        SecretKeyChecksum::SHA1 => 20,
        SecretKeyChecksum::Sum16 => 2,
    };
    let (mpis, sum) = plaintext.split_at(plaintext.len().checked_sub(length)?);
    let right = match checksum {
        SecretKeyChecksum::SHA1 => {
            let mut hash = HashAlgorithm::SHA1.context().ok()?.for_digest();
            hash.update(mpis);
            let mut digest = [0; 20];
            hash.digest(&mut digest).ok()?;
            digest[..] == *sum
        }
        SecretKeyChecksum::Sum16 => {
            let total = mpis.iter().fold(0u16, |t, &b| t.wrapping_add(b.into()));
            total.to_be_bytes()[..] == *sum
        }
    };
    right.then_some(mpis)
}

/// `mpis` read as `key`'s secret the way GnuPG writes it, in canonical form,
/// once it has proved to be the secret half of `key`.
///
/// Only the one shape GnuPG gets wrong: an elliptic-curve key, whose secret is
/// a single MPI. The RSA, DSA and ElGamal secrets it exports declare their
/// lengths exactly, and anything else that sequoia would not read and whose
/// checksum matched is taken to be damaged rather than read some other way.
///
/// A scalar longer than its curve's field is damaged too, although it may
/// well pass [`belongs_to`]. Sequoia's backends read a secret scalar through
/// `ProtectedMPI::value_padded`, which keeps the leading bytes of one that is
/// too long and drops the rest, so the key's own scalar with bytes after it
/// signs and decrypts as the key does. Handing that back would pass off as
/// canonical a secret that is not the key's own.
fn repaired<R: KeyRole>(
    key: &Key<SecretParts, R>,
    mpis: &[u8],
) -> std::result::Result<Unencrypted, Unusable> {
    let scalar = gnupg_scalar(mpis).ok_or(Unusable::Damaged)?;
    let length = scalar.value().len();
    let (secret, curve) = match key.mpis() {
        mpi::PublicKey::EdDSA { curve, .. } => (mpi::SecretKeyMaterial::EdDSA { scalar }, curve),
        mpi::PublicKey::ECDSA { curve, .. } => (mpi::SecretKeyMaterial::ECDSA { scalar }, curve),
        mpi::PublicKey::ECDH { curve, .. } => (mpi::SecretKeyMaterial::ECDH { scalar }, curve),
        _ => return Err(Unusable::Damaged),
    };
    // Asked before whether the curve is one this build has, since a curve's
    // size is known whether or not its arithmetic is, and a key that is
    // certainly damaged is better told as damaged than as unsupported.
    if curve.field_size().is_ok_and(|size| length > size) {
        return Err(Unusable::Damaged);
    }
    if !curve.is_supported() {
        return Err(Unusable::Unsupported(curve.to_string()));
    }
    let secret = Unencrypted::from(secret);
    if belongs_to(key, &secret) {
        Ok(secret)
    } else {
        Err(Unusable::Damaged)
    }
}

/// The one MPI that is the whole of `mpis`, read as GnuPG writes an
/// elliptic-curve secret it protects for export: declaring 8 bits for every
/// byte it stores, so that the value's leading bit may come after the
/// declared one, even whole bytes after it.
///
/// Only that far from canonical, and no further. The bytes have to be exactly
/// those the declared length calls for, and the bits it leaves out of the
/// first byte have to be clear, since a length that understates the value is
/// not GnuPG's mistake. The value that comes back has lost its leading zeros,
/// which is what makes it canonical: sequoia works out an MPI's length from
/// its value when it writes one.
fn gnupg_scalar(mpis: &[u8]) -> Option<ProtectedMPI> {
    let (declared, value) = mpis.split_first_chunk::<2>()?;
    let bits = usize::from(u16::from_be_bytes(*declared));
    if bits == 0 || value.len() != bits.div_ceil(8) {
        return None;
    }
    let left_out = value.len() * 8 - bits;
    if left_out > 0 && value[0] >> (8 - left_out) != 0 {
        return None;
    }
    Some(ProtectedMPI::from(value))
}

/// Whether `secret` is the secret half of `key`: whether what it signs, the
/// public key verifies, or what the public key encrypts, it opens.
///
/// Asked by using the secret, because using it is what this build can do on
/// every curve it supports. That is also the question that matters, since a
/// secret that answers it is one the operation after this can use. On
/// Curve25519 it answers up to the bits X25519 sets and clears in a scalar
/// before using it, as sequoia's own path does for a canonical secret.
fn belongs_to<R: KeyRole>(key: &Key<SecretParts, R>, secret: &Unencrypted) -> bool {
    let public = key.parts_as_public();
    let Ok(mut pair) = KeyPair::new(public.clone().role_into_unspecified(), secret.clone()) else {
        return false;
    };
    match key.pk_algo() {
        PublicKeyAlgorithm::EdDSA | PublicKeyAlgorithm::ECDSA => {
            let digest = [0x5a; 32];
            pair.sign(HashAlgorithm::SHA256, &digest)
                .and_then(|signature| public.verify(&signature, HashAlgorithm::SHA256, &digest))
                .is_ok()
        }
        PublicKeyAlgorithm::ECDH => SessionKey::new(32)
            .and_then(|sent| {
                let opened = pair.decrypt(&public.encrypt(&sent)?, Some(sent.len()))?;
                Ok(opened == sent)
            })
            .unwrap_or(false),
        _ => false,
    }
}

/// Unlock a key and turn it into a keypair.
pub fn keypair<R: KeyRole>(key: Key<SecretParts, R>, password: Option<&str>) -> Result<KeyPair> {
    Ok(unlock(key, password)?.into_keypair()?)
}

/// Unlock a key and box it as a signer.
///
/// The boxed form is what the callers that may instead fall back to gpg-agent
/// need, since an agent-backed signer is a different concrete type.
pub fn signer<R: KeyRole>(
    key: Key<SecretParts, R>,
    password: Option<&str>,
) -> Result<Box<dyn Signer + Send + Sync>> {
    Ok(Box::new(keypair(key, password)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyGenRequest, generate};
    use sequoia_openpgp::crypto::symmetric::{Encryptor, PaddingMode};
    use sequoia_openpgp::packet::key::{Key4, Key6, SubordinateRole};
    use sequoia_openpgp::types::{AEADAlgorithm, Curve, SymmetricAlgorithm};
    use std::io::Write;

    fn primary(
        request: &KeyGenRequest,
    ) -> Key<SecretParts, sequoia_openpgp::packet::key::PrimaryRole> {
        generate(request)
            .unwrap()
            .cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
    }

    /// Encryption is not what makes a secret unusable; being a placeholder is.
    ///
    /// Stated directly as well as through the store, because [`is_usable`]
    /// decides what a caller may attempt, and the three answers belong in one
    /// place: unprotected material is usable, passphrase-protected material is
    /// usable once the passphrase is supplied, and a stub never is.
    #[test]
    fn a_protected_secret_is_usable_material_and_a_stub_is_not() {
        let unprotected = primary(&KeyGenRequest::new("Alice <alice@example.org>"));
        assert!(is_usable(unprotected.secret()));

        let mut request = KeyGenRequest::new("Alice <alice@example.org>");
        request.password = Some("correct horse".to_string().into());
        let protected = primary(&request);
        assert!(protected.secret().is_encrypted());
        assert!(
            is_usable(protected.secret()),
            "a passphrase-protected secret is material the user can open"
        );

        // A `gnu-dummy` stub: the private S2K type 101, whose parameters are a
        // hash-algorithm byte, `GNU`, and the mode, with no key material
        // behind it. `tests/gnupg_stubs.rs` pins this shape against a real gpg
        // export; what matters here is only that the S2K is the private kind.
        let stub = SecretKeyMaterial::Encrypted(Encrypted::new(
            S2K::Private {
                tag: 101,
                parameters: Some(vec![0, b'G', b'N', b'U', 1].into()),
            },
            0.into(),
            Some(mpi::SecretKeyChecksum::Sum16),
            Vec::new().into(),
        ));
        assert!(
            stub.is_encrypted(),
            "which is why `is_encrypted` cannot answer this question"
        );
        assert!(!is_usable(&stub));
    }

    #[test]
    fn an_unprotected_key_needs_no_passphrase() {
        let key = primary(&KeyGenRequest::new("Alice <alice@example.org>"));
        assert!(!key.secret().is_encrypted());
        assert!(unlock(key.clone(), None).is_ok());
        assert!(unlock(key.clone(), Some("")).is_ok());

        // A passphrase for a key that has none is refused rather than ignored:
        // silently accepting it makes the field look checked when it is not.
        assert!(unlock(key.clone(), Some("hunter2")).is_err());
        // But not when walking candidates, where the same secret is offered to
        // every key and to the message's own passwords.
        assert!(matches!(try_unlock(key, Some("hunter2")), Ok(None)));
    }

    #[test]
    fn a_protected_key_round_trips() {
        let mut request = KeyGenRequest::new("Alice <alice@example.org>");
        request.password = Some("correct horse".to_string().into());
        let key = primary(&request);
        assert!(key.secret().is_encrypted());

        assert!(keypair(key.clone(), Some("correct horse")).is_ok());

        // The three ways it can go wrong all have to fail, and `try_unlock`
        // has to report them as "skip this key" rather than propagating.
        for wrong in [None, Some(""), Some("hunter2")] {
            assert!(
                unlock(key.clone(), wrong).is_err(),
                "{wrong:?} should not unlock"
            );
            assert!(
                matches!(try_unlock(key.clone(), wrong), Ok(None)),
                "{wrong:?} should be skipped"
            );
        }
    }

    /// No request that carries a passphrase prints it when formatted.
    ///
    /// Certify's and Revoke's used to derive `Debug`, which went through
    /// `Zeroizing`'s own and printed the passphrase in full, while the key
    /// generation request beside them had already been written out not to.
    /// Everything else in each still prints, so the output is not simply blank.
    #[test]
    fn no_request_prints_the_passphrase_it_carries() {
        use crate::certify::CertifyRequest;
        use crate::revoke::RevokeRequest;

        const PASSPHRASE: &str = "correct horse battery staple";
        let passphrase = || Some(Zeroizing::new(PASSPHRASE.to_string()));

        let mut keygen = KeyGenRequest::new("Alice <alice@example.org>");
        keygen.password = passphrase();
        let mut certify = CertifyRequest::new("CERTIFIER", "TARGET");
        certify.password = passphrase();
        let mut revoke = RevokeRequest::new("FINGERPRINT");
        revoke.message = "moved to a new key".to_string();
        revoke.password = passphrase();

        for (printed, shown) in [
            (format!("{keygen:?}"), "Alice <alice@example.org>"),
            (format!("{certify:?}"), "TARGET"),
            (format!("{revoke:?}"), "moved to a new key"),
        ] {
            assert!(
                !printed.contains(PASSPHRASE),
                "a request printed its passphrase: {printed}"
            );
            assert!(printed.contains("<redacted>"), "{printed}");
            assert!(printed.contains(shown), "{printed}");
        }

        certify.password = None;
        assert!(
            !format!("{certify:?}").contains("<redacted>"),
            "a request with no passphrase should not claim to hide one"
        );
    }

    /// What the keys below are protected with.
    const PASSWORD: &str = "correct horse";

    /// A fresh key of every elliptic-curve shape this build can use.
    ///
    /// The P-521 ones are drawn again until their scalar fills all 66 bytes
    /// of the curve's field, as about half do. That is a secret as long as
    /// its curve allows, which `repaired` has to take, where one byte more is
    /// one it has to refuse; left to chance, half the runs would not ask.
    fn every_curve() -> Vec<Key<SecretParts, SubordinateRole>> {
        [
            (true, Curve::Ed25519),
            (false, Curve::Cv25519),
            (true, Curve::NistP256),
            (false, Curve::NistP256),
            (true, Curve::NistP384),
            (false, Curve::NistP384),
            (true, Curve::NistP521),
            (false, Curve::NistP521),
        ]
        .into_iter()
        .map(|(for_signing, curve)| {
            std::iter::repeat_with(|| -> Key<SecretParts, SubordinateRole> {
                Key4::generate_ecc(for_signing, curve.clone())
                    .unwrap()
                    .into()
            })
            .find(|key| curve != Curve::NistP521 || scalar(key).len() == 66)
            .unwrap()
        })
        .collect()
    }

    /// Which of [`every_curve`] `key` is, for a failure to name.
    fn shape<R: KeyRole>(key: &Key<SecretParts, R>) -> String {
        match key.mpis() {
            mpi::PublicKey::EdDSA { curve, .. }
            | mpi::PublicKey::ECDSA { curve, .. }
            | mpi::PublicKey::ECDH { curve, .. } => format!("{} on {curve}", key.pk_algo()),
            _ => key.pk_algo().to_string(),
        }
    }

    /// The scalar that is the whole of `key`'s unprotected secret.
    fn scalar<R: KeyRole>(key: &Key<SecretParts, R>) -> Protected {
        let SecretKeyMaterial::Unencrypted(secret) = key.secret() else {
            panic!("the key is protected");
        };
        secret.map(|secret| match secret {
            mpi::SecretKeyMaterial::EdDSA { scalar }
            | mpi::SecretKeyMaterial::ECDSA { scalar }
            | mpi::SecretKeyMaterial::ECDH { scalar } => scalar.value().into(),
            other => panic!("not an elliptic-curve secret: {:?}", other.algo()),
        })
    }

    /// `value` as a secret MPI that declares `bits`, whatever `value` holds.
    fn declaring(bits: u16, value: &[u8]) -> Protected {
        let mut mpis = Protected::new(2 + value.len());
        mpis[..2].copy_from_slice(&bits.to_be_bytes());
        mpis[2..].copy_from_slice(value);
        mpis
    }

    /// `key`'s secret in GnuPG's form taken one zero byte further: a zero byte
    /// ahead of the scalar, and eight bits declared for every byte. That is
    /// what GnuPG writes for an Ed25519 seed that begins with a zero byte, and
    /// one byte more than it writes for a scalar that fills its field. The
    /// extra byte is what makes sequoia refuse every one of these, where it
    /// refuses about half of what GnuPG writes on most curves;
    /// `tests/gnupg_protected.rs` has those, as GnuPG wrote them.
    fn as_gnupg_writes<R: KeyRole>(key: &Key<SecretParts, R>) -> Protected {
        let scalar = scalar(key);
        let mut value = Protected::new(1 + scalar.len());
        value[1..].copy_from_slice(&scalar);
        declaring(u16::try_from(8 * value.len()).unwrap(), &value)
    }

    /// `key` with `mpis` for its secret, protected under [`PASSWORD`] as GnuPG
    /// protects an export: CFB after an iterated S2K, and `checksum` over
    /// `mpis` exactly as they are written. By hand, because sequoia writes a
    /// secret only as it is in canonical form, and only with a SHA-1 checksum.
    fn protected<R: KeyRole>(
        key: Key<SecretParts, R>,
        mpis: &[u8],
        checksum: SecretKeyChecksum,
    ) -> Key<SecretParts, R> {
        let s2k = S2K::new_iterated(HashAlgorithm::SHA256, 1024).unwrap();
        protected_under(key, s2k, mpis, checksum)
    }

    /// [`protected`], with the key derived by `s2k` instead.
    fn protected_under<R: KeyRole>(
        key: Key<SecretParts, R>,
        s2k: S2K,
        mpis: &[u8],
        checksum: SecretKeyChecksum,
    ) -> Key<SecretParts, R> {
        let algo = SymmetricAlgorithm::AES128;
        let derived = s2k
            .derive_key(&PASSWORD.into(), algo.key_size().unwrap())
            .unwrap();
        let sum = match checksum {
            SecretKeyChecksum::SHA1 => {
                let mut hash = HashAlgorithm::SHA1.context().unwrap().for_digest();
                hash.update(mpis);
                hash.into_digest().unwrap()
            }
            SecretKeyChecksum::Sum16 => mpis
                .iter()
                .fold(0u16, |t, &b| t.wrapping_add(b.into()))
                .to_be_bytes()
                .to_vec(),
        };
        let mut ciphertext = Vec::new();
        let mut encryptor = Encryptor::new(
            algo,
            BlockCipherMode::CFB,
            PaddingMode::None,
            &derived,
            None,
            &mut ciphertext,
        )
        .unwrap();
        // The block ahead of the secret, whose ciphertext is the IV the rest
        // is encrypted under.
        encryptor.write_all(&[0; 16]).unwrap();
        encryptor.write_all(mpis).unwrap();
        encryptor.write_all(&sum).unwrap();
        encryptor.finalize().unwrap();
        let encrypted = Encrypted::new(s2k, algo, Some(checksum), ciphertext.into());
        key.add_secret(encrypted.into()).0
    }

    /// What `key` gets from sequoia alone, as [`unlock`] used to pass it on.
    fn sequoia_says<R: KeyRole>(key: &Key<SecretParts, R>, password: &str) -> String {
        match key.clone().decrypt_secret(&password.into()) {
            Ok(_) => "unlocked".to_string(),
            Err(refused) => Error::from(refused).to_string(),
        }
    }

    /// A secret written as GnuPG writes it opens, on every curve this build
    /// has, to the very secret it is, where sequoia alone refuses it; a wrong
    /// passphrase is still refused exactly as sequoia refuses it; and the same
    /// secret written as sequoia writes it opens exactly as sequoia opens it.
    #[test]
    fn a_secret_gnupg_wrote_opens_on_every_curve_this_build_has() {
        for key in every_curve() {
            let shape = shape(&key);
            let SecretKeyMaterial::Unencrypted(secret) = key.secret() else {
                unreachable!("generated unprotected");
            };

            let canonical = secret
                .encrypt_with(
                    &key,
                    S2K::new_iterated(HashAlgorithm::SHA256, 1024).unwrap(),
                    SymmetricAlgorithm::AES128,
                    None,
                    &PASSWORD.into(),
                )
                .unwrap();
            let canonical = key.clone().add_secret(canonical.into()).0;
            let opened = unlock(canonical.clone(), Some(PASSWORD)).unwrap();
            let by_sequoia = canonical.decrypt_secret(&PASSWORD.into()).unwrap();
            assert!(
                opened.secret() == key.secret() && opened.secret() == by_sequoia.secret(),
                "{shape}: a canonical secret opened differently"
            );

            let gnupg = protected(key.clone(), &as_gnupg_writes(&key), SecretKeyChecksum::SHA1);
            assert_ne!(
                sequoia_says(&gnupg, PASSWORD),
                "unlocked",
                "{shape}: premise, sequoia alone refuses GnuPG's lengths"
            );
            let opened = unlock(gnupg.clone(), Some(PASSWORD))
                .unwrap_or_else(|e| panic!("{shape}: the right passphrase was refused: {e}"));
            assert!(
                opened.secret() == key.secret(),
                "{shape}: opened to a secret that is not the key's"
            );

            let refused = unlock(gnupg.clone(), Some("hunter2")).expect_err(&shape);
            assert_eq!(
                refused.to_string(),
                sequoia_says(&gnupg, "hunter2"),
                "{shape}"
            );
            assert!(
                matches!(try_unlock(gnupg, Some("hunter2")), Ok(None)),
                "{shape}: a wrong passphrase should be skipped"
            );
        }
    }

    /// A SHA-1 checksum that holds over another key's secret is a damaged key,
    /// not a wrong passphrase: no wrong passphrase gets one past it, and it is
    /// only the check against the public key that finds the secret is not this
    /// key's.
    #[test]
    fn a_checksum_that_holds_over_another_keys_secret_is_damage_and_not_a_wrong_passphrase() {
        for (key, other) in every_curve().into_iter().zip(every_curve()) {
            let shape = shape(&key);
            let swapped = protected(
                key.clone(),
                &as_gnupg_writes(&other),
                SecretKeyChecksum::SHA1,
            );
            let refused = unlock(swapped.clone(), Some(PASSWORD))
                .expect_err("opened to another key's secret");
            assert!(
                matches!(
                    &refused,
                    Error::KeyUnusable { name, why: Unusable::Damaged }
                        if *name == key.fingerprint().to_hex()
                ),
                "{shape}: {refused:?}"
            );
            assert!(
                refused.to_string().starts_with("the passphrase is right"),
                "{refused}"
            );
            assert_eq!(
                try_unlock(swapped, Some(PASSWORD)).map(|_| ()),
                Err(Unusable::Damaged),
                "{shape}"
            );
        }
    }

    /// A SHA-1 checksum that holds over something that is not one MPI in
    /// GnuPG's shape is a damaged key too, however far from that shape it is.
    #[test]
    fn a_checksummed_secret_that_will_not_parse_even_loosely_is_damage() {
        let key: Key<SecretParts, SubordinateRole> =
            Key4::generate_ecc(false, Curve::Cv25519).unwrap().into();
        let value = scalar(&key);
        let mut understated = Protected::new(value.len());
        understated.copy_from_slice(&value);
        understated[0] |= 0x80;
        let mut trailing = Protected::new(value.len() + 1);
        trailing[..value.len()].copy_from_slice(&value);

        for (what, mpis) in [
            ("a length short of the value", declaring(255, &understated)),
            ("a byte after the value", declaring(256, &trailing)),
            ("a length that runs past the end", declaring(512, &value)),
            ("a length far short of the value", declaring(8, &value)),
            ("no length at all", Protected::new(1)),
        ] {
            let broken = protected(key.clone(), &mpis, SecretKeyChecksum::SHA1);
            assert_ne!(
                sequoia_says(&broken, PASSWORD),
                "unlocked",
                "{what}: premise, sequoia alone refuses it"
            );
            let refused = unlock(broken, Some(PASSWORD)).expect_err(what);
            assert!(
                matches!(
                    refused,
                    Error::KeyUnusable {
                        why: Unusable::Damaged,
                        ..
                    }
                ),
                "{what}: {refused:?}"
            );
        }
    }

    /// A scalar with a byte after the key's own is longer than its curve
    /// allows, and is a damaged key, although it signs and decrypts as the key
    /// does: sequoia's backends keep the leading bytes of a scalar too long for
    /// them and drop the rest, so the check against the public key alone would
    /// take it. What would come back is not the key's secret in canonical form.
    #[test]
    fn a_secret_longer_than_its_curve_allows_is_damage_even_where_it_would_work() {
        for key in every_curve() {
            let shape = shape(&key);
            let scalar = scalar(&key);
            let mut value = Protected::new(1 + scalar.len() + 1);
            value[1..=scalar.len()].copy_from_slice(&scalar);
            let mpis = declaring(u16::try_from(8 * value.len()).unwrap(), &value);
            let long = protected(key.clone(), &mpis, SecretKeyChecksum::SHA1);
            assert_ne!(
                sequoia_says(&long, PASSWORD),
                "unlocked",
                "{shape}: premise"
            );

            let refused = unlock(long.clone(), Some(PASSWORD)).expect_err(&shape);
            assert!(
                matches!(
                    refused,
                    Error::KeyUnusable {
                        why: Unusable::Damaged,
                        ..
                    }
                ),
                "{shape}: {refused:?}"
            );
            assert_eq!(
                try_unlock(long, Some(PASSWORD)).map(|_| ()),
                Err(Unusable::Damaged),
                "{shape}"
            );
        }
    }

    /// A 16-bit checksum passes for one wrong passphrase in 65,536, so where it
    /// holds and the secret does not prove to be the key's, the passphrase is
    /// refused as sequoia refuses it, and not reported as damage. Where the
    /// secret does prove to be the key's, it opens: only the claim of damage
    /// needs more than the checksum.
    #[test]
    fn a_sixteen_bit_checksum_is_too_weak_to_call_a_key_damaged() {
        for (key, other) in every_curve().into_iter().zip(every_curve()) {
            let shape = shape(&key);
            let own = protected(
                key.clone(),
                &as_gnupg_writes(&key),
                SecretKeyChecksum::Sum16,
            );
            assert_ne!(sequoia_says(&own, PASSWORD), "unlocked", "{shape}: premise");
            assert!(
                unlock(own, Some(PASSWORD)).is_ok_and(|opened| opened.secret() == key.secret()),
                "{shape}: the key's own secret did not open"
            );

            let swapped = protected(
                key.clone(),
                &as_gnupg_writes(&other),
                SecretKeyChecksum::Sum16,
            );
            let refused = unlock(swapped.clone(), Some(PASSWORD)).expect_err(&shape);
            assert_eq!(
                refused.to_string(),
                sequoia_says(&swapped, PASSWORD),
                "{shape}"
            );
            assert!(
                matches!(try_unlock(swapped, Some(PASSWORD)), Ok(None)),
                "{shape}: reported as more than a wrong passphrase"
            );
        }
    }

    /// The second look reads GnuPG's lengths under the protection GnuPG exports
    /// with, and nowhere else. The same secret, written the same way under the
    /// right passphrase and a SHA-1 checksum that holds, opens on a version 4
    /// key under an iterated S2K, and is refused exactly as sequoia refuses it
    /// under a salted or a simple S2K, which GnuPG does not export with, and on
    /// a version 6 key, whose MPIs RFC 9580 has rejected when they declare more
    /// bits than they hold.
    #[test]
    fn gnupgs_lengths_are_read_under_gnupgs_protection_and_nowhere_else() {
        #[allow(deprecated)]
        let older = [
            (
                S2K::Salted {
                    hash: HashAlgorithm::SHA256,
                    salt: [7; 8],
                },
                "a salted S2K",
            ),
            (
                S2K::Simple {
                    hash: HashAlgorithm::SHA256,
                },
                "a simple S2K",
            ),
        ];
        for key in every_curve() {
            let shape = shape(&key);
            let mpis = as_gnupg_writes(&key);
            let gnupg = protected(key.clone(), &mpis, SecretKeyChecksum::SHA1);
            assert!(
                unlock(gnupg, Some(PASSWORD)).is_ok_and(|opened| opened.secret() == key.secret()),
                "{shape}: did not open under GnuPG's own protection"
            );

            let mut elsewhere: Vec<_> = older
                .clone()
                .into_iter()
                .map(|(s2k, under)| {
                    let sealed = protected_under(key.clone(), s2k, &mpis, SecretKeyChecksum::SHA1);
                    (sealed, under)
                })
                .collect();
            // Version 6 keys have Ed25519 and X25519 algorithms of their own,
            // and RFC 9580 keeps the legacy Curve25519 ones to version 4 keys,
            // so only the NIST keys are made again as version 6 ones.
            if let mpi::PublicKey::ECDSA { .. }
            | mpi::PublicKey::ECDH {
                curve: Curve::NistP256 | Curve::NistP384 | Curve::NistP521,
                ..
            } = key.mpis()
            {
                let SecretKeyMaterial::Unencrypted(secret) = key.secret() else {
                    unreachable!("generated unprotected");
                };
                let version_6: Key<SecretParts, SubordinateRole> = Key6::with_secret(
                    key.creation_time(),
                    key.pk_algo(),
                    key.mpis().clone(),
                    secret.clone().into(),
                )
                .unwrap()
                .into();
                let sealed = protected(version_6, &mpis, SecretKeyChecksum::SHA1);
                elsewhere.push((sealed, "version 6"));
            }

            for (sealed, what) in elsewhere {
                let refused = sequoia_says(&sealed, PASSWORD);
                assert_ne!(refused, "unlocked", "{shape}, {what}: premise");
                assert_eq!(
                    unlock(sealed.clone(), Some(PASSWORD))
                        .map_err(|e| e.to_string())
                        .map(|_| ()),
                    Err(refused),
                    "{shape}, {what}"
                );
                assert!(
                    matches!(try_unlock(sealed, Some(PASSWORD)), Ok(None)),
                    "{shape}, {what}: reported as more than a wrong passphrase"
                );
            }
        }
    }

    /// Sequoia authenticates an AEAD-protected secret before it reads any of
    /// it, so one that authenticates and then does not parse was opened by the
    /// right passphrase, and is a damaged key. A wrong passphrase fails the
    /// authentication, and is refused as sequoia refuses it.
    #[test]
    fn an_aead_secret_that_authenticates_and_does_not_parse_is_damage() {
        let key: Key<SecretParts, SubordinateRole> =
            Key4::generate_ecc(false, Curve::Cv25519).unwrap().into();
        let value = scalar(&key);
        for (what, mpis) in [
            ("GnuPG's lengths", as_gnupg_writes(&key)),
            ("a length that runs past the end", declaring(512, &value)),
        ] {
            // An unknown algorithm's secret is written out byte for byte,
            // which is the one way to have sequoia seal bytes it would not
            // write itself.
            let raw = Unencrypted::from(mpi::SecretKeyMaterial::Unknown {
                mpis: Vec::new().into_boxed_slice(),
                rest: mpis,
            });
            let sealed = raw
                .encrypt_with(
                    &key,
                    S2K::new_iterated(HashAlgorithm::SHA256, 1024).unwrap(),
                    SymmetricAlgorithm::AES128,
                    Some(AEADAlgorithm::OCB),
                    &PASSWORD.into(),
                )
                .unwrap();
            let sealed = key.clone().add_secret(sealed.into()).0;

            let refused = unlock(sealed.clone(), Some(PASSWORD)).expect_err(what);
            assert!(
                matches!(
                    refused,
                    Error::KeyUnusable {
                        why: Unusable::Damaged,
                        ..
                    }
                ),
                "{what}: {refused:?}"
            );
            let refused = unlock(sealed.clone(), Some("hunter2")).expect_err(what);
            assert_eq!(
                refused.to_string(),
                sequoia_says(&sealed, "hunter2"),
                "{what}"
            );
        }
    }
}
