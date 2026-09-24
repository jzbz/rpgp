//! Message operations: encrypt, decrypt, sign, verify.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs;
use std::io::{BufWriter, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use sequoia_openpgp::Fingerprint;
use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::cert::amalgamation::key::{
    ValidErasedKeyAmalgamation, ValidKeyAmalgamationIter,
};
use sequoia_openpgp::crypto::mpi::Ciphertext;
use sequoia_openpgp::crypto::{Decryptor, Password, S2K, SessionKey};
use sequoia_openpgp::packet::{Key, PKESK, SKESK, key};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper, VerifierBuilder,
};
use sequoia_openpgp::serialize::stream::{
    Armorer, Encryptor, LiteralWriter, Message, Recipient, Signer,
};
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{Cert, KeyHandle};

use crate::error::{Error, Result};
use crate::policy;
use crate::store::Store;
use zeroize::Zeroizing;

/// What a single signature in a message turned out to be.
#[derive(Debug, Clone)]
pub struct SignatureReport {
    pub good: bool,
    /// Signer's primary user ID when the certificate is known, otherwise the
    /// key handle from the signature packet.
    pub signer: String,
    pub fingerprint: Option<String>,
    /// Human-readable reason, filled in for bad and unverifiable signatures.
    pub detail: String,
    /// SHA-1 was load-bearing in accepting this signature: either the message
    /// was hashed with it, or the key that made it reaches its certificate
    /// only through a SHA-1 binding, which the user opted that certificate
    /// into under [`crate::sha1`].
    ///
    /// A good signature carrying this is weaker than a good signature without
    /// it, and by a margin worth telling the reader about: SHA-1 collisions are
    /// practical, so what it establishes is that the signer's key was involved,
    /// not that the signer approved this particular document.
    ///
    /// It is also set on the signature this refuses: one that leaned on SHA-1
    /// from a certificate nobody opted in is reported bad, and saying why is
    /// the whole of `detail` there.
    pub sha1: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub signatures: Vec<SignatureReport>,
    /// Fingerprint of the certificate whose subkey decrypted the message.
    pub decrypted_with: Option<String>,
    /// Whether the message actually carried an encryption layer. Sequoia's
    /// Decryptor walks a signed-only or bare-literal message straight to its
    /// Literal packet without ever calling DecryptionHelper::decrypt, so
    /// nothing else here separates "we opened it" from "it was never shut" —
    /// and reporting the second as the first tells the reader a message that
    /// crossed the network in clear arrived confidentially.
    pub encrypted: bool,
}

impl VerifyResult {
    pub fn all_good(&self) -> bool {
        !self.signatures.is_empty() && self.signatures.iter().all(|s| s.good)
    }
}

/// Encrypt to `recipients` and/or to `passwords`, optionally signing.
///
/// Both may be given at once: the message then carries a session key wrapped
/// for every recipient *and* wrapped by each password, so either opens it.
/// That is what lets a file go to a colleague who has a key and to one who
/// only has a shared secret.
///
/// A password-only message is what `gpg -c` produces.
///
/// `Zeroizing`, to match the decrypt side: [`Helper`] has held its candidate
/// passwords that way since it was written, and [`crate::keygen::KeyGenRequest`]
/// its passphrase. This half took a plain `String` and so left the caller's
/// copy — the only copy, since nothing here duplicates it — in freed memory
/// after the message was written. Defence in depth rather than a fix for a
/// reachable bug: reading it needs the address space, which `harden` already
/// closes to `ptrace` and core dumps.
pub fn encrypt(
    recipients: &[Cert],
    passwords: &[Zeroizing<String>],
    signer: Option<(&Cert, Option<&str>)>,
    plaintext: &[u8],
    sink: impl Write + Send + Sync,
) -> Result<()> {
    encrypt_stream(recipients, passwords, signer, &mut &plaintext[..], sink)
}

/// [`encrypt`], reading the plaintext as it goes instead of taking it whole.
///
/// Same packet sequence either way — sequoia's writers serialize identically
/// regardless of how the bytes arrive — so the output is byte-for-byte what the
/// buffered form produced.
fn encrypt_stream(
    recipients: &[Cert],
    passwords: &[Zeroizing<String>],
    signer: Option<(&Cert, Option<&str>)>,
    source: &mut dyn Read,
    sink: impl Write + Send + Sync,
) -> Result<()> {
    let passwords: Vec<&Zeroizing<String>> = passwords.iter().filter(|p| !p.is_empty()).collect();
    if recipients.is_empty() && passwords.is_empty() {
        return Err(Error::invalid(
            "choose at least one recipient, or set a password",
        ));
    }
    let policy = policy();

    // Collect the encryption-capable subkeys of every recipient up front, so a
    // recipient without one fails the whole operation instead of silently
    // producing a message they cannot read.
    let mut recipient_keys: Vec<Recipient> = Vec::new();
    for cert in recipients {
        // Asked before the subkey walk below, because that walk cannot see it:
        // a certificate revoked as a whole still carries unrevoked encryption
        // subkeys, and encrypting to one hands the message to whoever holds a
        // key its owner has declared stolen, or has simply stopped reading.
        crate::revoke::refuse_if_revoked(cert)?;
        let valid = cert
            .with_policy(&policy, None)
            .map_err(|_| Error::NoEncryptionKey(cert.fingerprint().to_hex()))?;
        let before = recipient_keys.len();
        recipient_keys.extend(encryption_keys(&valid).into_iter().map(Recipient::from));
        if recipient_keys.len() == before {
            return Err(Error::NoEncryptionKey(cert.fingerprint().to_hex()));
        }
    }

    let message = Message::new(sink);
    let message = Armorer::new(message).build()?;

    let message = Encryptor::for_recipients(message, recipient_keys)
        .add_passwords(passwords.into_iter().map(|p| Password::from(p.as_str())))
        .build()?;

    let message = match signer {
        Some((cert, password)) => {
            let keypair = signing_keypair(cert, password)?;
            Signer::new(message, keypair)?.build()?
        }
        None => message,
    };

    let mut message = LiteralWriter::new(message).build()?;
    std::io::copy(source, &mut message)?;
    message.finalize()?;
    Ok(())
}

/// The encryption keys `valid` offers under one of the two encryption flags.
///
/// OpenPGP has two — one for messages in flight, one for data at rest — and
/// nearly every implementation sets both on a single subkey, so the distinction
/// is invisible on almost every certificate one meets. It is not always: `sq key
/// generate --can-encrypt=storage` makes a certificate with the storage flag
/// alone, and this app's own [`crate::keygen`] gives each key a separate
/// storage subkey beside its transport one.
///
/// Split out so that the two filters, and everything in front of them, are
/// written once. [`has_encryption_key`] answers the recipient picker from the
/// same two calls, which is what stops the picker offering a certificate that
/// [`encrypt`] then refuses.
fn encryption_candidates<'a>(
    valid: &ValidCert<'a>,
    storage: bool,
) -> ValidKeyAmalgamationIter<'a, key::PublicParts, key::UnspecifiedRole> {
    let keys = valid.keys().alive().revoked(false).supported();
    if storage {
        keys.for_storage_encryption()
    } else {
        keys.for_transport_encryption()
    }
}

/// Every key a message to this certificate is encrypted to.
///
/// Storage keys are a fallback rather than a second helping: they are taken
/// only when the certificate offers no transport key at all. Both at once is
/// the shorter spelling — sequoia unions repeated flag filters on one iterator
/// — but every certificate this app generates carries a separate storage
/// subkey, so it would add a second PKESK to every message sent to one of its
/// own keys. That changes the output for the ordinary certificate in order to
/// serve the unusual one. As a fallback it changes nothing for any certificate
/// that can already be encrypted to, and the certificates that could not now
/// can.
///
/// A storage subkey is a proper encryption key either way. Both decrypt paths
/// below chain the two flags together and [`crate::cert::subkeys_with`] marks
/// either one `E`, so refusing them here was rPGP disagreeing with itself
/// rather than enforcing anything. Sequoia's own documentation puts the
/// distinction in perspective: most implementations set both flags on a single
/// subkey, and offer no way to ask for one kind of protection when encrypting.
fn encryption_keys<'a>(
    valid: &ValidCert<'a>,
) -> Vec<ValidErasedKeyAmalgamation<'a, key::PublicParts>> {
    let transport: Vec<_> = encryption_candidates(valid, false).collect();
    if transport.is_empty() {
        encryption_candidates(valid, true).collect()
    } else {
        transport
    }
}

/// Whether [`encrypt`] has anything to encrypt to here.
///
/// What [`crate::CertSummary::can_encrypt`] reports, and through it which
/// certificates the Sign / Encrypt dialog and the notepad offer as recipients.
/// It asks the same two filters rather than describing them a second time,
/// because a second description is what drifted: the picker offered every
/// certificate with either encryption flag while `encrypt` took only transport
/// keys, so a storage-only certificate was listed, ticked, and then refused
/// with "no usable encryption key".
pub(crate) fn has_encryption_key(valid: &ValidCert<'_>) -> bool {
    encryption_candidates(valid, false).next().is_some()
        || encryption_candidates(valid, true).next().is_some()
}

/// The most plaintext [`decrypt_to_memory`] or [`verify_inline`] will hand
/// back.
///
/// Generous for anything a person pastes into a text box, and far below what a
/// compressed layer can expand to.
pub const MAX_IN_MEMORY_PLAINTEXT: usize = 64 * 1024 * 1024;

/// A sink that refuses to grow past `limit`.
///
/// Decompression is the reason this exists: the size of the output is chosen
/// by whoever wrote the message, not by whoever reads it.
struct Bounded<W> {
    inner: W,
    written: usize,
    limit: usize,
}

impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written = self.written.saturating_add(buf.len());
        if self.written > self.limit {
            return Err(std::io::Error::other(
                "the message expands to more than this window can hold; \
                 decrypt it to a file instead",
            ));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// [`decrypt`] into memory, refusing a plaintext larger than
/// [`MAX_IN_MEMORY_PLAINTEXT`].
///
/// For callers that genuinely need the plaintext in RAM — the notepad, whose
/// output is a text box. A file destination should use [`decrypt_file`], which
/// streams and has no such ceiling.
pub fn decrypt_to_memory(
    store: &Store,
    ciphertext: &[u8],
    passwords: &[&str],
    plaintext: &mut Vec<u8>,
) -> Result<VerifyResult> {
    let mut sink = Bounded {
        inner: plaintext,
        written: 0,
        limit: MAX_IN_MEMORY_PLAINTEXT,
    };
    decrypt(store, ciphertext, passwords, &mut sink)
}

/// Decrypt a message, verifying any signatures against the store.
///
/// `passwords` are candidates, not a single answer: any of them may be a
/// passphrase unlocking one of our secret keys or a password the message was
/// encrypted to, and the caller usually cannot tell which the user meant.
pub fn decrypt(
    store: &Store,
    ciphertext: &[u8],
    passwords: &[&str],
    sink: impl Write,
) -> Result<VerifyResult> {
    decrypt_stream(store, ciphertext, passwords, sink)
}

/// [`decrypt`], reading the ciphertext as it goes instead of taking it whole.
///
/// Same packet stream either way — sequoia's parser consumes a reader
/// regardless of where the bytes come from — so the plaintext and the
/// verification result are what the buffered form produced.
pub fn decrypt_stream<R: std::io::Read + Send + Sync>(
    store: &Store,
    source: R,
    passwords: &[&str],
    mut sink: impl Write,
) -> Result<VerifyResult> {
    // The signature half of a decryption is still verification, so an opted-in
    // sender is honoured here too. Our own decryption key is unaffected:
    // `Helper::decrypt` builds `crate::policy` for itself and never sees this
    // one, and the relaxation this one carries decides nothing on its own —
    // `Helper::check` settles every signature against the certificate that
    // made it.
    let policy = sha1_policy_or_strict(store);
    let helper = Helper::new(store, passwords, &policy);

    let mut decryptor = DecryptorBuilder::from_reader(source)?
        .with_policy(policy.verification(), None, helper)
        .map_err(as_made)?;
    std::io::copy(&mut decryptor, &mut sink).map_err(|e| Error::io("decrypting message", e))?;

    let helper = decryptor.into_helper();
    Ok(VerifyResult {
        signatures: helper.signatures,
        encrypted: helper.encrypted,
        decrypted_with: helper.decrypted_with,
    })
}

/// An error from [`Helper::decrypt`] as the helper made it.
///
/// The helper answers Sequoia in `anyhow::Error`, and Sequoia hands its error
/// back unchanged, so one of this crate's own comes back wrapped. Left in
/// [`Error::OpenPgp`], a refusal from gpg-agent or a key left locked read
/// "OpenPGP operation failed:" before saying what happened, which the GUI puts
/// after its own "Decryption failed:". Only those two are taken out, so that
/// every other failure reads as it did.
fn as_made(error: anyhow::Error) -> Error {
    match error.downcast::<Error>() {
        Ok(error @ (Error::AgentRefused { .. } | Error::KeyLocked { .. })) => error,
        Ok(other) => Error::OpenPgp(other.into()),
        Err(error) => Error::OpenPgp(error),
    }
}

/// Produce a detached, armored signature over `data`.
pub fn sign_detached(
    signer: &Cert,
    password: Option<&str>,
    data: &[u8],
    sink: impl Write + Send + Sync,
) -> Result<()> {
    sign_detached_stream(signer, password, &mut &data[..], sink)
}

/// [`sign_detached`], reading the signed data as it goes.
fn sign_detached_stream(
    signer: &Cert,
    password: Option<&str>,
    source: &mut dyn Read,
    sink: impl Write + Send + Sync,
) -> Result<()> {
    let keypair = signing_keypair(signer, password)?;

    let message = Message::new(sink);
    let message = Armorer::new(message)
        .kind(sequoia_openpgp::armor::Kind::Signature)
        .build()?;
    let mut message = Signer::new(message, keypair)?.detached().build()?;
    std::io::copy(source, &mut message)?;
    message.finalize()?;
    Ok(())
}

/// Sign `data` so the text stays readable, with the signature appended.
///
/// This is the cleartext signature framework — what belongs in an e-mail or a
/// forum post, where a detached signature would be useless because there is
/// nowhere to put the second file.
pub fn sign_cleartext(
    signer: &Cert,
    password: Option<&str>,
    data: &[u8],
    sink: impl Write + Send + Sync,
) -> Result<()> {
    let keypair = signing_keypair(signer, password)?;
    let message = Message::new(sink);
    let mut message = Signer::new(message, keypair)?.cleartext().build()?;

    // A trailing bare CR is completed to CRLF before it reaches the cleartext
    // writer, which otherwise emits a block it cannot verify itself: the final
    // line runs straight into the signature marker with no line ending between
    // them, and reading it back gives "Bad signature: Message has been
    // manipulated" over text nobody touched.
    //
    // Deliberately only the trailing byte. A bare CR in the middle round-trips
    // today, and rewriting those would change where the reader sees line breaks
    // in someone else's message. The last line ending is not part of the signed
    // text (RFC 9580 §7.1), so completing it changes nothing that is signed.
    //
    // The input is easy to produce and hard to see: everything copied out of a
    // Windows application is CRLF, and deleting the trailing blank line leaves
    // exactly this.
    if data.last() == Some(&b'\r') {
        message.write_all(data)?;
        message.write_all(b"\n")?;
    } else {
        message.write_all(data)?;
    }
    message.finalize()?;
    Ok(())
}

/// The verification policy, degrading to strict rather than failing.
///
/// Reading the opt-in list can fail for reasons that have nothing to do with the
/// message in hand — the file is there but unreadable, or holds bytes that are
/// not UTF-8. Propagating that would make an unreadable `sha1-accepted` break
/// every verify and decrypt in the app, including the overwhelming majority that
/// never involve SHA-1 at all; before the opt-in existed those calls could not
/// fail this way. Strict is the same answer an empty list gives, so the cost of
/// the fallback is that an opted-in certificate stops being opted in, which
/// fails closed. The GUI names the unreadable file in its status line when it
/// reloads, so the condition is reported once where it can be explained rather
/// than at every operation.
fn sha1_policy_or_strict(store: &Store) -> crate::Sha1Policy {
    store
        .sha1_policy()
        .unwrap_or_else(|_| crate::Sha1Policy::strict())
}

/// Verify a message that carries its own text: cleartext-signed, or signed and
/// wrapped. Returns the text alongside the verdict.
pub fn verify_inline(store: &Store, signed: &[u8]) -> Result<(Vec<u8>, VerifyResult)> {
    let policy = sha1_policy_or_strict(store);
    let helper = Helper::new(store, &[], &policy);

    let mut verifier =
        VerifierBuilder::from_bytes(signed)?.with_policy(policy.verification(), None, helper)?;
    let mut text = Vec::new();
    // Bounded like decrypt_to_memory. The notepad routes some armored input
    // here rather than through the decrypt path, and an inline-signed message
    // carries a compressed layer that expands to whatever the sender chose —
    // so without this the ceiling the notepad's own comment claimed applied to
    // only one of the two branches it can take.
    let mut sink = Bounded {
        inner: &mut text,
        written: 0,
        limit: MAX_IN_MEMORY_PLAINTEXT,
    };
    std::io::copy(&mut verifier, &mut sink).map_err(|e| Error::io("verifying message", e))?;

    let helper = verifier.into_helper();
    Ok((
        text,
        VerifyResult {
            signatures: helper.signatures,
            decrypted_with: None,
            // A detached or inline verification is not a decryption, and its
            // callers do not claim otherwise.
            encrypted: false,
        },
    ))
}

/// Verify a detached signature over `data`.
pub fn verify_detached(store: &Store, signature: &[u8], data: &[u8]) -> Result<VerifyResult> {
    let policy = sha1_policy_or_strict(store);
    let helper = Helper::new(store, &[], &policy);

    let mut verifier = DetachedVerifierBuilder::from_bytes(signature)?.with_policy(
        policy.verification(),
        None,
        helper,
    )?;
    verifier.verify_bytes(data)?;

    let helper = verifier.into_helper();
    Ok(VerifyResult {
        signatures: helper.signatures,
        decrypted_with: None,
        encrypted: false,
    })
}

/// Unlock a signing-capable secret key.
///
/// Local key material is used when the certificate carries it. Otherwise the
/// user's gpg-agent is asked, which is how a smartcard signs: the secret never
/// leaves the card, and the PIN prompt is the agent's own pinentry rather than
/// anything rpgp draws.
///
/// Every signing path in this module comes through here — detached, cleartext
/// and the signer inside [`encrypt_stream`] — so the revocation guard sits here
/// once rather than at each of the three.
fn signing_keypair(
    cert: &Cert,
    password: Option<&str>,
) -> Result<Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync>> {
    // Ahead of everything else, and in particular ahead of the agent fallback
    // below: keys generated here sign with a subkey, which survives a
    // certificate-level revocation untouched, so without this the app happily
    // produced signatures that every verifier holding the revocation — rpgp's
    // own included — reports as bad. Refusing here also means a card never
    // raises its PIN prompt for a signature that cannot be trusted anyway.
    crate::revoke::refuse_if_revoked(cert)?;

    let policy = policy();
    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| Error::NoSecretKey(cert.fingerprint().to_hex()))?;

    let Some(ka) = valid
        .keys()
        .secret()
        .alive()
        .revoked(false)
        .supported()
        .for_signing()
        .next()
    else {
        return Ok(Box::new(crate::agent::signer_for(cert)?));
    };

    crate::secret::signer(ka.key().clone(), password)
}

/// Shared decryption/verification callbacks.
///
/// Sequoia drives verification through this trait pair rather than returning a
/// result: `get_certs` supplies the certificates it needs mid-stream, and
/// `check` is handed the message structure once the body has been read.
struct Helper<'a> {
    store: &'a Store,
    /// The user's SHA-1 opt-in, to settle each good signature against the
    /// certificate that made it. The policy the verifier itself runs under
    /// cannot do this: see [`crate::sha1::Sha1Policy::verification`].
    sha1: &'a crate::Sha1Policy,
    /// Every secret the caller could offer: a passphrase that unlocks one of
    /// our keys, a password the message was encrypted to, or both. A single
    /// slot forced the UI to guess which role the user meant, and it guessed
    /// wrong — text encrypted to a password could not be decrypted with it.
    passwords: Vec<Zeroizing<String>>,
    signatures: Vec<SignatureReport>,
    decrypted_with: Option<String>,
    /// Set from the message structure, not from whether decrypt() ran: a
    /// message encrypted only to a password we do not hold still had a layer.
    encrypted: bool,
    /// What the sender's Argon2 parameters may still cost, for this whole
    /// message rather than for one of its encryption containers. See
    /// [`Argon2Budget`].
    argon2: Argon2Budget,
}

impl<'a> Helper<'a> {
    fn new(store: &'a Store, passwords: &[&str], sha1: &'a crate::Sha1Policy) -> Self {
        Helper {
            store,
            sha1,
            passwords: passwords
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| Zeroizing::new((*p).to_owned()))
                .collect(),
            signatures: Vec::new(),
            decrypted_with: None,
            encrypted: false,
            argon2: Argon2Budget::new(),
        }
    }
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> anyhow::Result<Vec<Cert>> {
        // Every certificate that carries the issuer key, not the one
        // [`Store::lookup`] would single out. An issuer names the key that
        // signed, usually a subkey, and a key can hang off more than one
        // certificate — including one a stranger built by attaching the
        // signer's public subkey to a certificate of their own, which takes
        // no secret of the signer's and no back-signature as long as the
        // binding claims encryption. One certificate per issuer means such a
        // certificate can be the only one the verifier ever sees, and the
        // genuine signature then comes back "key is not signing capable".
        // Sequoia walks the candidates and stops at the first signature that
        // checks out, so the rejected ones cost only the attempt.
        //
        // A signer we do not have is still not an error here: it surfaces as
        // a MissingKey verification error in `check`, which is a better
        // message than aborting the whole read.
        let mut certs: Vec<Cert> = Vec::new();
        for id in ids {
            for cert in self.store.lookup_all(&id.to_string()).unwrap_or_default() {
                // Deduplicated across the whole list rather than per issuer:
                // two issuers in one message can pull in the same certificate.
                if !certs.iter().any(|c| c.fingerprint() == cert.fingerprint()) {
                    certs.push(cert);
                }
            }
        }
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> anyhow::Result<()> {
        for layer in structure {
            let results = match layer {
                // Recorded rather than skipped: this is the only place the
                // presence of an encryption layer is observable.
                MessageLayer::Encryption { .. } => {
                    self.encrypted = true;
                    continue;
                }
                MessageLayer::Compression { .. } => continue,
                MessageLayer::SignatureGroup { results } => results,
            };
            for result in results {
                self.signatures.push(match result {
                    Ok(good) => {
                        let cert = good.ka.cert();
                        // Deliberately the standard policy, not the one this
                        // verification ran under: the question is what the
                        // certificate looks like to everyone else, and
                        // summarising it under its own opt-in would report the
                        // certificate as ordinary in the one place the reader
                        // most needs to hear that it is not.
                        let summary = crate::CertSummary::from_cert(cert);

                        // Where the SHA-1 opt-in is actually applied, and the
                        // only place it can be. The policy the verifier ran
                        // under was told nothing about certificates — a
                        // sequoia policy is handed a signature alone, and the
                        // issuer it could read from one is a claim anyone may
                        // write into the unhashed area of somebody else's
                        // signature. Here the certificate is no longer a
                        // claim: `good.ka` is the key the bytes actually
                        // verified against. So a signature that needed SHA-1
                        // stands only if the user opted *that* certificate in,
                        // and is otherwise reported exactly as it would have
                        // been had nobody opted anything in.
                        let sha1 =
                            crate::sha1::load_bearing(good.sig, cert, good.ka.key().key_handle());
                        let refused = sha1 && !self.sha1.accepts(cert);
                        SignatureReport {
                            good: !refused,
                            signer: summary.primary_user_id,
                            fingerprint: Some(summary.fingerprint.clone()),
                            detail: if refused {
                                format!(
                                    "SHA-1 was needed to accept this signature, and {} is not a \
                                     certificate you have accepted SHA-1 from",
                                    summary.fingerprint
                                )
                            } else {
                                String::new()
                            },
                            sha1,
                        }
                    }
                    Err(err) => SignatureReport {
                        good: false,
                        signer: "unknown".to_string(),
                        fingerprint: None,
                        detail: format!("{err}"),
                        sha1: false,
                    },
                });
            }
        }
        Ok(())
    }
}

/// The largest exponent of the Argon2 memory size, in KiB, that a message may
/// ask a recipient for.
///
/// 21 is 2 GiB, which is what RFC 9580's own sample locked key uses (`t = 1,
/// p = 4, m = 21`, RFC 9106's first recommendation); its alternative for
/// memory-constrained machines is `t = 3, p = 4, m = 16`, 64 MiB. Anything
/// above 21 is a request nobody following the specification makes.
///
/// The work budget below would refuse nearly all of it on its own, since
/// `t * 2^m` passes the ceiling for every `t` of 1 or more once `m` reaches 22.
/// What this check is load-bearing for is the arithmetic underneath it: `m`
/// arrives as a raw octet, and `1 << m` is not a number at all above 63. It
/// also answers a packet naming `t = 0`, which has no work to weigh however
/// much memory it asks for, and it lets the refusal name memory rather than
/// work — the half of this that ends in an OOM kill rather than a wait.
const MAX_ARGON2_M: u8 = 21;

/// What one Argon2 derivation may cost, in KiB-passes — `t` passes over 2^`m`
/// KiB of memory.
///
/// 2^21 is 2 GiB hashed once. Both of RFC 9106's recommended parameter sets
/// fit: `t = 1, m = 21` exactly, and `t = 3, m = 16` with room to spare. It
/// was measured at about 2.7 s in a release build on a 2020s x86-64 desktop,
/// which is what admitting the stronger of the two costs.
const MAX_ARGON2_WORK: u64 = 1 << 21;

/// What every Argon2 derivation in one decryption may cost together — across
/// every session-key packet, every candidate password, and every encryption
/// container the message nests.
///
/// Four derivations at the per-attempt ceiling. The largest honest shape is a
/// message sealed to two passwords tried against the two candidates the
/// notepad offers, and that is four; a message that wants more than this is
/// spending the recipient's machine, not protecting its own password.
const MAX_ARGON2_TOTAL_WORK: u64 = 4 * MAX_ARGON2_WORK;

/// Charges every Argon2 derivation a decryption asks for against a budget for
/// the whole message.
///
/// Each charge is settled before the derivation that would pay it, so a packet
/// priced past the limits never reaches the allocator, and a message cannot
/// spend more of the recipient's machine than [`MAX_ARGON2_TOTAL_WORK`]
/// however many packets and candidate passwords it multiplies together.
///
/// This is a field of [`Helper`] rather than a local in its `decrypt`, because
/// `decrypt` is not called once per message. Sequoia calls it for every
/// encryption container it descends into, against every session-key packet
/// accumulated so far, and it descends as far as its default recursion limit
/// of sixteen. A budget scoped to the method is handed back full at each
/// layer, so sixteen nested containers would buy sixteen times what the limit
/// says, out of a message a couple of kilobytes long.
struct Argon2Budget {
    /// KiB-passes still unspent.
    remaining: u64,
}

impl Argon2Budget {
    fn new() -> Self {
        Argon2Budget {
            remaining: MAX_ARGON2_TOTAL_WORK,
        }
    }

    /// Settle what deriving `skesk`'s key will cost, before doing it.
    ///
    /// Everything that is not Argon2 is free, which is everything rpgp or its
    /// correspondents normally produce: sequoia's own encryptor writes every
    /// SKESK, v4 and v6, with `S2K::default()`, and GnuPG 2.4.9 does the same
    /// and offers no way to ask for anything else — `--s2k-mode` accepts 0, 1
    /// and 3, and there is no 4. Both of those are `Iterated`, whose cost its
    /// own encoding already caps at 0x3e00000 bytes of hashing. Argon2 is the
    /// one S2K whose price the sender sets, and sequoia bounds neither `t` nor
    /// `m`: it reads both as raw octets and hands them to `argon2`, whose own
    /// maxima are `u32::MAX`, so without this the only thing between a message
    /// and several gigabytes held for minutes is that the allocation might
    /// fail.
    ///
    /// `p`, the degree of parallelism, is deliberately not part of the price.
    /// It divides the same 2^`m` KiB into lanes rather than adding any, and
    /// the `argon2` crate is built here without `rayon`, so the lanes run one
    /// after another and the total work is unchanged.
    fn charge(&mut self, skesk: &SKESK) -> anyhow::Result<()> {
        let s2k = match skesk {
            SKESK::V4(s) => s.s2k(),
            SKESK::V6(s) => s.s2k(),
            // `SKESK` is `#[non_exhaustive]`. A version sequoia adds later is
            // one whose S2K cannot be read here, so it is left to `decrypt` as
            // it was before rather than charged a price that cannot be known.
            _ => return Ok(()),
        };
        // `S2K` is `#[non_exhaustive]` too, so this matches the one variant
        // that needs a budget rather than listing the ones that do not.
        let &S2K::Argon2 { t, m, .. } = s2k else {
            return Ok(());
        };

        if m > MAX_ARGON2_M {
            return Err(anyhow::anyhow!(
                "this message's password hashing asks for 2^{m} KiB of memory for every \
                 attempt to open it, above the 2 GiB rpgp will allocate — the password \
                 was not tried against it"
            ));
        }
        // `m` is 21 or less from here on, so the shift cannot overflow and
        // the memory size is a number of megabytes a reader can picture.
        let work = u64::from(t) * (1u64 << m);
        if work > MAX_ARGON2_WORK {
            let mib = (1u64 << m) / 1024;
            return Err(anyhow::anyhow!(
                "this message's password hashing asks for {mib} MiB of memory hashed {t} \
                 times over for every attempt to open it, more work than rpgp will spend — \
                 the password was not tried against it"
            ));
        }
        let Some(left) = self.remaining.checked_sub(work) else {
            return Err(anyhow::anyhow!(
                "this message's password hashing asks for more work in total than rpgp will \
                 spend on one message — the password was not tried against the packets that \
                 asked for it"
            ));
        };
        self.remaining = left;
        Ok(())
    }
}

impl DecryptionHelper for Helper<'_> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> anyhow::Result<Option<Cert>> {
        let policy = policy();

        // A real message carries one session-key packet per recipient plus one
        // per password — single digits. Every loop below is O(packets × keys)
        // with a key derivation inside: the local path runs our S2K once per
        // protected key, and the symmetric path runs the *sender's* S2K once
        // per (packet × password). Nothing in sequoia bounds the count, so a
        // padded message is a decrypt-side amplifier: 128 wildcard packets in a
        // 14 KB file pinned a core for ~9s, and the message still decrypted, so
        // nothing looked wrong. 256 is a chosen ceiling, not a constant of
        // nature: it is far above any real recipient list.
        //
        // What it bounds is how many derivations run, not what each one costs.
        // On the symmetric path those are two different questions, because the
        // S2K there is the sender's and an Argon2 one prices it freely; that is
        // [`Argon2Budget`]'s job, not this cap's.
        //
        // Nor does it bound them once per message. Sequoia calls this method
        // for every encryption container it descends into, against every
        // session-key packet accumulated so far, and descends up to sixteen
        // levels, so 256 packets placed ahead of sixteen nested containers are
        // tried sixteen times over. What the two caps together leave is
        // therefore 4096 iterated-SHA-256 derivations per candidate password —
        // each one capped by its own encoding at 0x3e00000 bytes of hashing,
        // about 350 ms on the machine sequoia benchmarks against, so something
        // like twenty-five minutes per candidate. That is arithmetic from the
        // two ceilings rather than a measurement, and it is a residual this cap
        // does not close, not the "seconds" this comment used to claim.
        //
        // The gpg-agent path at the end is bounded by the same cap and no
        // better. Each of its attempts is a private-key operation in the
        // agent, over a connection of its own (sequoia-gpg-agent 0.6.2 opens
        // one for every decryption), and for a card key an operation on the
        // card, which for RSA can take the better part of a second. A packet
        // that names a key is put to that key alone, but one that names none
        // is put to every key the agent holds whose shape it fits, so the 256
        // packets come to at most 256 operations for each key the agent holds
        // that they could be for, and the same again at each of sixteen
        // containers. For a single card key that is thousands of card
        // operations, and minutes, again by arithmetic and not measured. What
        // the path no longer does is multiply them by the store. It used to
        // try every packet against every certificate with a key the packet
        // could name, connecting to the agent to build a keypair for each; it
        // now builds one keypair per key, which connects once, and asks it
        // about the packets that key could open. See
        // [`crate::agent::decryption_attempts`].
        const MAX_ESK: usize = 256;
        let esks = pkesks.len() + skesks.len();
        if esks > MAX_ESK {
            return Err(anyhow::anyhow!(
                "this message carries {esks} session-key packets, more than rpgp will try"
            ));
        }

        // A PKESK names the *subkey* it was encrypted to, and a wildcard
        // recipient names nothing at all, so there is no lookup by primary
        // fingerprint to be done here: walk the secret keys we hold and match
        // on key handles.
        // Not unwrap_or_default: an unreadable secrets directory is a
        // different failure from an empty one, and reporting it as "no key
        // opens this message" sent the user looking at the wrong thing.
        let secrets = self.store.secret_certs()?;

        // The first key here that a packet names, that is protected by a
        // passphrase, and that nothing offered opened. Kept for the error at
        // the end: "no secret key" sent the user looking for a key they had,
        // when what was missing was its passphrase.
        let mut locked: Option<String> = None;

        // Keys outside, packets inside. The other way round re-derived every
        // protected key's passphrase once per packet, so the cost was
        // (packets × keys) key derivations rather than (keys) — which is what
        // made padding worth doing. The same set of keys is unlocked either
        // way, just once each.
        for cert in &secrets {
            let Ok(valid) = cert.with_policy(&policy, None) else {
                continue;
            };

            // Encryption keys only: a wildcard PKESK names no recipient,
            // so without this filter every signing and certification key
            // gets unlocked and tried as well.
            //
            // Deliberately *not* filtered by alive/revoked. Old mail must
            // stay readable after a subkey expires or is retired —
            // revoking a key withdraws it for future use, it does not
            // burn the archive.
            let usable = valid
                .keys()
                .secret()
                .for_transport_encryption()
                .chain(valid.keys().secret().for_storage_encryption());

            for ka in usable {
                // The per-packet recipient test, hoisted: skip a key that no
                // packet in this message could be addressed to *before*
                // paying for its passphrase.
                if !pkesks.iter().any(|pkesk| {
                    pkesk
                        .recipient()
                        .is_none_or(|handle| handle.aliases(ka.key().key_handle()))
                }) {
                    continue;
                }

                // try_unlock, not unlock: this walks every key the message
                // might be addressed to, so one that will not open is a
                // reason to try the next rather than to fail the decrypt.
                // `None` first, which is what opens a key with no
                // passphrase, then each secret the caller offered.
                let Some(key) = std::iter::once(None)
                    .chain(self.passwords.iter().map(|p| Some(p.as_str())))
                    .find_map(|p| crate::secret::try_unlock(ka.key().clone(), p))
                else {
                    // Only a key a packet names. One that names no key could
                    // be for anybody, and asking for the passphrase of every
                    // protected key here on account of a message meant for
                    // someone else would ask for one that can never work. Nor
                    // a GnuPG stub, which is encrypted as far as Sequoia can
                    // tell but has no passphrase, being where a card key's
                    // secret is not; the agent below is how that one opens.
                    let secret = ka.key().secret();
                    if locked.is_none()
                        && secret.is_encrypted()
                        && crate::secret::is_usable(secret)
                        && pkesks.iter().any(|pkesk| {
                            pkesk
                                .recipient()
                                .is_some_and(|handle| handle.aliases(ka.key().key_handle()))
                        })
                    {
                        locked = Some(crate::revoke::name_of(cert));
                    }
                    continue;
                };
                let Ok(mut pair) = key.into_keypair() else {
                    continue;
                };

                for pkesk in pkesks {
                    if let Some(handle) = pkesk.recipient()
                        && !handle.aliases(ka.key().key_handle())
                    {
                        continue;
                    }
                    if pkesk
                        .decrypt(&mut pair, sym_algo)
                        .is_some_and(|(algo, session_key)| decrypt(algo, &session_key))
                    {
                        self.decrypted_with = Some(cert.fingerprint().to_hex());
                        return Ok(Some(cert.clone()));
                    }
                }
            }
        }

        // A password-encrypted message carries no recipient at all, so try the
        // supplied passphrase against the symmetric envelopes before deciding
        // this message was not meant for us.
        //
        // Each attempt is charged against [`Helper::argon2`], which is a budget
        // for the whole message and not for this call, and every charge is
        // settled before the derivation it pays for, so an Argon2 packet over
        // the limit never reaches the allocator. The budget is four
        // derivations at the per-attempt ceiling, which covers the largest
        // honest shape — a message sealed to two passwords, tried against the
        // two candidates the notepad offers — while holding the symmetric path
        // of an entire message to about ten seconds of hashing rather than the
        // hours 256 packets at t=255 would otherwise buy.
        //
        // A packet nobody can afford is passed over rather than ending the
        // decrypt here: one over-priced envelope is no reason to refuse a
        // message that a cheaper envelope, or the card key the agent loop
        // below asks about, would still open. The price is remembered and
        // reported at the end if nothing does.
        let mut too_expensive = None;
        for candidate in &self.passwords {
            let password = Password::from(candidate.as_str());
            for skesk in skesks {
                if let Err(price) = self.argon2.charge(skesk) {
                    too_expensive.get_or_insert(price);
                    continue;
                }
                if let Ok((algo, session_key)) = skesk.decrypt(&password)
                    && decrypt(algo, &session_key)
                {
                    return Ok(None);
                }
            }
        }

        // Nothing local fits. The message may be for a key only gpg-agent
        // holds, a card key among them, whose secret half exists only on the
        // card: ask the agent, which raises its own prompt if the key needs
        // one.
        //
        // Not when the message has no packet for a key, which is every message
        // encrypted to a password alone. There is nothing to ask the agent
        // about, and asking cost a mistyped password a parse of every
        // certificate in the store and, where GnuPG is installed, an agent
        // started for nothing, with a certificate that would not parse
        // reported in place of the password.
        if !pkesks.is_empty() {
            // Read once, not once per packet: certs() parses every certificate
            // it returns.
            let certs = self.store.certs()?;

            // The agent's listing, fetched once and only when some key in the
            // store could open some packet here. An unreachable agent is not
            // an error at this point: it means there is nothing on a card to
            // try, and the decryption goes on to the same "nothing opens this"
            // it would have reached anyway.
            let attempts =
                crate::agent::decryption_attempts(pkesks, certs.iter().map(|c| &**c), || {
                    crate::agent::keys().unwrap_or_default()
                });
            if let Some(cert) = through_agent(&attempts, sym_algo, decrypt, crate::agent::signer)? {
                self.decrypted_with = Some(cert.fingerprint().to_hex());
                // The one place a caller genuinely needs an owned Cert:
                // DecryptionHelper returns it by value. Exactly one clone, of
                // the certificate that opened the message.
                return Ok(Some(cert.clone()));
            }
        }

        // A key the message names, here and locked, comes first: its
        // passphrase is what opens the message, where the price below only
        // says why one way in was not tried.
        if let Some(name) = locked {
            return Err(Error::KeyLocked {
                name,
                tried: !self.passwords.is_empty(),
                // The message's password would have done as well, and what
                // was entered, which Decrypt / Verify offers as both, did not
                // open it either. Not where an envelope was passed over as too
                // dear: what was entered was never tried as its password.
                or_password: !skesks.is_empty() && too_expensive.is_none(),
            }
            .into());
        }

        // What an envelope cost beats "no password opens this message", which
        // sends the reader off to check a password that was never the problem
        // — the same reasoning this file gives for not collapsing an unreadable
        // secrets directory into "no key".
        if let Some(price) = too_expensive {
            return Err(price);
        }

        Err(anyhow::anyhow!(
            "no secret key, and no password, opens this message"
        ))
    }
}

/// Ask gpg-agent each of `attempts` in turn, as
/// [`crate::agent::decryption_attempts`] ordered them, until one opens the
/// message, and give back the certificate that did.
///
/// One keypair per key, built when the key is first asked about and used for
/// every packet after, where one used to be built, and the agent connected to,
/// for each pair of packet and certificate.
///
/// The first refusal from the agent ends it, and is the answer. Sequoia's
/// `PKESK::decrypt` turns every error into `None`, so a cancelled PIN prompt,
/// a card that was not there or an agent with no pinentry to ask with read as
/// a key that did not fit: the next attempt put up the prompt again, for the
/// same key when a message named two of its subkeys, and when nothing was left
/// the user was told no secret key opened the message and went looking at
/// their keys instead of their card. So the keypair is wrapped to keep what
/// the agent said, and trying stops there. That the agent refused rather than
/// that the key did not fit is all there is to go on: sequoia-gpg-agent keeps
/// the words of the agent's answer and drops its code, so a cancelled prompt
/// cannot be told apart from a card that would not use one packet (see
/// [`crate::agent::refusal`]). A second key that would have opened the message
/// is therefore not asked after the first is refused, which is the price of
/// not prompting again. An agent that cannot be reached to build a keypair
/// ends it the same way, as the agent's answer for every key.
///
/// The one refusal that does not end it is an RSA card turning down a packet
/// that names no key, which may be the card saying the packet is someone
/// else's; [`crate::agent::Attempt::refusal_is_final`] gives the reasons. The
/// next attempt is made, and if nothing opens the message the first such
/// refusal is the answer, since it may have been a cancelled prompt.
///
/// A key that simply did not fit says nothing, and the next attempt is made.
///
/// `keypair` is [`crate::agent::signer`] outside the tests, which hand in a
/// stand-in for the agent.
fn through_agent<'a, D: Decryptor>(
    attempts: &[crate::agent::Attempt<'a>],
    sym_algo: Option<SymmetricAlgorithm>,
    decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    mut keypair: impl FnMut(&Key<key::PublicParts, key::UnspecifiedRole>) -> Result<D>,
) -> Result<Option<&'a Cert>> {
    let refused = |attempt: &crate::agent::Attempt<'_>, reason: String| Error::AgentRefused {
        name: crate::revoke::name_of(attempt.cert),
        reason,
    };
    let mut pairs: HashMap<Fingerprint, Answering<D>> = HashMap::new();
    let mut passed_over: Option<Error> = None;
    for attempt in attempts {
        let pair = match pairs.entry(attempt.key.fingerprint()) {
            Entry::Occupied(pair) => pair.into_mut(),
            Entry::Vacant(slot) => slot.insert(Answering {
                agent: keypair(&attempt.key).map_err(|e| refused(attempt, e.to_string()))?,
                refusal: None,
            }),
        };
        if attempt
            .pkesk
            .decrypt(pair, sym_algo)
            .is_some_and(|(algo, session_key)| decrypt(algo, &session_key))
        {
            return Ok(Some(attempt.cert));
        }
        if let Some(reason) = pair.refusal.take() {
            if attempt.refusal_is_final() {
                return Err(refused(attempt, reason));
            }
            passed_over.get_or_insert_with(|| refused(attempt, reason));
        }
    }
    match passed_over {
        Some(refusal) => Err(refusal),
        None => Ok(None),
    }
}

/// An agent-backed decryptor that keeps what `PKESK::decrypt` would drop: the
/// agent's answer when it refused. See [`through_agent`].
struct Answering<D> {
    agent: D,
    refusal: Option<String>,
}

impl<D: Decryptor> Decryptor for Answering<D> {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        self.agent.public()
    }

    fn decrypt(
        &mut self,
        ciphertext: &Ciphertext,
        plaintext_len: Option<usize>,
    ) -> sequoia_openpgp::Result<SessionKey> {
        self.agent
            .decrypt(ciphertext, plaintext_len)
            .inspect_err(|error| {
                if let Some(reason) = crate::agent::refusal(error) {
                    self.refusal = Some(reason);
                }
            })
    }
}

/// What a file handed to "Decrypt / Verify" turns out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// An OpenPGP message: encrypted, signed inline, or both.
    Message,
    /// A bare signature — the other half of a detached pair, useless without
    /// the file it signs.
    DetachedSignature,
    NotOpenPgp,
}

/// [`classify`] for a file, reading only as much of it as the answer needs.
///
/// The armor check looks at the first kilobyte and the binary check at the
/// first packet's header, so a prefix decides it. The caller used to read the
/// whole file to ask this question — on the UI thread, from a file dialog,
/// where picking a multi-gigabyte archive meant reading a multi-gigabyte
/// archive before the window could repaint.
pub fn classify_file(path: &Path) -> InputKind {
    /// Comfortably past the kilobyte of armor header and any first-packet
    /// header, while still being a read that cannot hurt.
    const ENOUGH: u64 = 64 * 1024;

    let Ok(file) = fs::File::open(path) else {
        return InputKind::NotOpenPgp;
    };
    let mut head = Vec::new();
    if std::io::Read::read_to_end(&mut std::io::Read::take(file, ENOUGH), &mut head).is_err() {
        return InputKind::NotOpenPgp;
    }
    classify(&head)
}

/// Decide what `data` is, so the UI knows whether to ask for a second file.
pub fn classify(data: &[u8]) -> InputKind {
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    // Armored input says what it is in the header line. Check bytes rather
    // than decoding: the file may be binary, and a UTF-8 error here would
    // wrongly rule out an armored file whose tail is not valid UTF-8.
    let head = &data[..data.len().min(1024)];
    // Cleartext first: a cleartext-signed message contains *both* markers —
    // its own header and the signature block that follows the text — so
    // testing for the signature first misreads it as a detached signature and
    // sends the reader off looking for a file that does not exist.
    if contains(head, b"-----BEGIN PGP SIGNED MESSAGE-----") {
        return InputKind::Message;
    }
    if contains(head, b"-----BEGIN PGP SIGNATURE-----") {
        return InputKind::DetachedSignature;
    }
    if contains(head, b"-----BEGIN PGP MESSAGE-----") {
        return InputKind::Message;
    }

    // Binary: the first packet is enough to tell the two apart.
    use sequoia_openpgp::Packet;
    use sequoia_openpgp::parse::{PacketParser, PacketParserResult};
    match PacketParser::from_bytes(data) {
        Ok(PacketParserResult::Some(pp)) => match pp.packet {
            Packet::Signature(_) => InputKind::DetachedSignature,
            Packet::PKESK(_)
            | Packet::SKESK(_)
            | Packet::SEIP(_)
            | Packet::OnePassSig(_)
            | Packet::CompressedData(_)
            | Packet::Literal(_) => InputKind::Message,
            _ => InputKind::NotOpenPgp,
        },
        _ => InputKind::NotOpenPgp,
    }
}

/// `notes.txt` -> `notes.txt.asc`.
pub fn encrypted_name(input: &Path) -> PathBuf {
    free_name(append_extension(input, "asc"))
}

/// The first name in the `name`, `name (1)`, `name (2)` … series that is not
/// already taken.
///
/// Outside a Flatpak the GUI derives every output path from the input rather
/// than asking the user for one, so without this an operation silently
/// destroys an unrelated file that happens to sit at the derived name:
/// decrypting `notes.txt.asc` next to a `notes.txt` you wrote yourself
/// overwrites your notes. Deriving a free name is quieter than a prompt and
/// loses nothing, since the result is reported.
///
/// Best-effort, and deliberately so: it picks a pleasant name, it does not
/// enforce the rule. The name can be taken between the check and the write,
/// and after 999 collisions the series is exhausted and the original path
/// comes back — which is why the places that actually destroy data refuse
/// rather than trust the name they were handed. `create_new` makes each
/// staging file and a detached signature written straight to its name, and
/// refuses any entry already there, a dangling symlink included, in the same
/// call that creates the file. Before a rename, the `output.exists()` check
/// only narrows the window, since the rename replaces whatever is at the name
/// by then; see [`write_staged`].
///
/// Only a derived name comes through here. Inside a Flatpak the user chooses
/// each output in a save dialog instead, and that path is written as chosen,
/// with [`Existing::Replace`]: the dialog has already asked about a file at
/// that name, and stepping around it would write somewhere the user did not
/// choose. The staging name beside either kind still comes through here.
fn free_name(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    // Insert before the extension when there is one: `notes (1).txt`, not
    // `notes.txt (1)`, so the file still opens in the right application.
    let (base, ext) = match stem.rsplit_once('.') {
        Some((base, ext)) if !base.is_empty() => (base.to_string(), format!(".{ext}")),
        _ => (stem.clone(), String::new()),
    };
    for n in 1..1000 {
        let candidate = parent.join(format!("{base} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    path
}

/// `notes.txt` -> `notes.txt.sig`.
pub fn signature_name(input: &Path) -> PathBuf {
    free_name(append_extension(input, "sig"))
}

/// `notes.txt.asc` -> `notes.txt`. A name with no OpenPGP extension to strip
/// gets `.out` appended rather than being overwritten in place.
pub fn decrypted_name(input: &Path) -> PathBuf {
    let strippable = input
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e, "asc" | "pgp" | "gpg"));
    free_name(if strippable {
        input.with_extension("")
    } else {
        append_extension(input, "out")
    })
}

fn append_extension(path: &Path, extension: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(extension);
    PathBuf::from(name)
}

/// What a file operation does about a file already at its output path.
///
/// Either way, an operation that fails leaves that file as it was. A refused
/// file is never written to, and a replaced one is replaced only by renaming
/// a finished output onto it, never by writing into it, so nothing reaches it
/// until the operation has succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Refuse, for an output name derived from the input by
    /// [`encrypted_name`], [`signature_name`] or [`decrypted_name`]. Nobody
    /// was asked about whatever is there; see `free_name`.
    Refuse,
    /// Replace it, for a path the user chose in a save dialog. The dialog has
    /// already asked whether to, and refusing would overrule the answer.
    Replace,
}

/// Who may read a file an operation writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Readers {
    /// Its owner alone: 0600 on Unix, whatever the umask.
    ///
    /// For plaintext. A decrypted file was protected until the moment it was
    /// written, and under the usual umask it came out 0644, readable by every
    /// local account that can reach the directory it lands in, such as /tmp
    /// or a group-shared folder. The mode is set by the call that creates the
    /// staging file rather than by a chmod after it, which would leave a
    /// window in which another user could open the file while it was still
    /// empty and read everything written to it afterwards through that
    /// descriptor. A file replacing a chosen one takes this mode too, whatever
    /// that one had.
    ///
    /// Windows has no mode, and the file takes the ACL its directory passes
    /// down, as it always has; under the user's profile that already keeps
    /// other users out. The store's owner-only ACL is not borrowed for it,
    /// because that would cut the file off from whatever a shared or synced
    /// folder the user chose passes down.
    Owner,
    /// Whoever the umask and the directory allow, as for any other new file
    /// the user makes. For ciphertext and signatures, which exist to be handed
    /// on.
    Usual,
}

impl Readers {
    /// Options that create a new file for these readers, and refuse any entry
    /// already at the name, a symlink included, rather than open it.
    fn options(self) -> fs::OpenOptions {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if self == Readers::Owner {
                options.mode(0o600);
            }
        }
        options
    }
}

/// A file an operation created and has not finished with, removed when this
/// is dropped unless [`Unfinished::keep`] or [`Unfinished::rename_onto`] says
/// otherwise.
///
/// Every way out of an operation passes through the drop: an error from any
/// step, one added later included, and a panic unwinding out of Sequoia on the
/// GUI's worker thread. Removing the file by hand in each error arm missed
/// some of them. A decrypt whose last buffered write failed on a full disk
/// returned its error and left all of the plaintext but that last buffer at
/// `<output>.part`, where a retry stepped around it to `<output> (1).part`,
/// and a rename that failed left the whole of it. A process that ends without
/// unwinding, in a crash or with the window closed while a worker is still
/// writing, still leaves the file behind.
///
/// Only [`create_new`] makes one, and only once the file exists, so a name
/// that was already taken is refused and left alone rather than removed.
/// Whoever holds the file closes it first, so that nothing is renamed or
/// removed while a handle to it is still open.
struct Unfinished {
    path: PathBuf,
    kept: bool,
}

impl Unfinished {
    /// Leave the file where it is.
    fn keep(mut self) {
        self.kept = true;
    }

    /// Rename the file onto `output`, and leave it there once it is.
    fn rename_onto(self, output: &Path) -> Result<()> {
        fs::rename(&self.path, output)
            .map_err(|e| Error::io(format!("writing {}", output.display()), e))?;
        self.keep();
        Ok(())
    }
}

impl Drop for Unfinished {
    fn drop(&mut self) {
        if !self.kept {
            // Best effort: the error on its way back is the one that matters.
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Create a new file at `path` for `readers`, with the [`Unfinished`] that
/// removes it again unless the operation succeeds.
fn create_new(path: PathBuf, readers: Readers) -> Result<(Unfinished, fs::File)> {
    let file = readers
        .options()
        .open(&path)
        .map_err(|e| Error::io(format!("writing {}", path.display()), e))?;
    Ok((Unfinished { path, kept: false }, file))
}

fn already_exists(output: &Path) -> Error {
    Error::invalid(format!("{} already exists", output.display()))
}

/// How much of a streamed output is gathered before it is written.
///
/// Sequoia's armor writer hands its sink one 64-column line at a time, and a
/// decrypt copies 8 KiB at a time, so behind `BufWriter`'s default of 8 KiB a
/// gigabyte of output took between 130,000 and 180,000 writes. Each of them
/// appends to a new file, which is dear on a copy-on-write filesystem:
/// measured on btrfs, an encrypt ran a sixth to a quarter faster with this
/// buffer, and a decrypt a few percent. A mebibyte is small beside what
/// Sequoia buffers for itself, 4 MiB per packet it writes and 25 MiB held
/// back while it decrypts.
const OUTPUT_BUFFER: usize = 1 << 20;

/// Write an output to a new file beside it, and rename that onto `output`
/// once `fill` and the last buffered write have both succeeded.
///
/// So an operation that fails at any step leaves `output` as it was and
/// nothing beside it: a wrong passphrase, a message that does not decrypt, a
/// full disk at the last write and a refused rename all end the same way. A
/// file already at `output` is refused or replaced by the rename, never
/// written into; see [`Existing`].
///
/// The staging name is the output's with `.part` appended rather than
/// substituted: `output.with_extension("part")` turned `notes.txt.asc` into
/// `notes.part`, a name the user may well own. It goes through `free_name`,
/// so it steps around a `.part` file already there, and [`create_new`] refuses
/// it if it is taken all the same, so the file written and renamed is always
/// one this call made.
///
/// With [`Existing::Refuse`], a file that has appeared at `output` by the time
/// the output is finished is refused. That narrows the window between
/// `free_name` and the rename to a check just before it, and does not close
/// it: `fs::rename` replaces whatever is at the name, and a rename that
/// refuses to is not portable.
///
/// Nothing is synced before the rename, unlike the store's writes, whose
/// files stay in the store's own directory. On macOS `sync_all` is
/// `fcntl(F_FULLFSYNC)` with no fallback to `fsync`, and that fails on some
/// volumes an output may well be written to, such as SMB shares and FAT or
/// exFAT drives, so it would turn a good output there into a reported
/// failure. The last buffered write still catches a full disk or an
/// exhausted quota on a local filesystem; an error that a network filesystem
/// reports only at close is lost.
fn write_staged<T>(
    output: &Path,
    existing: Existing,
    readers: Readers,
    fill: impl FnOnce(&mut BufWriter<fs::File>) -> Result<T>,
) -> Result<T> {
    let (staging, file) = create_new(free_name(append_extension(output, "part")), readers)?;
    // Declared after `staging`, so that on every way out, a panic included,
    // the file is closed before its name is removed.
    let mut sink = BufWriter::with_capacity(OUTPUT_BUFFER, file);
    let value = fill(&mut sink)?;
    // Flushed by into_inner rather than by the drop, which discards a failed
    // write: up to a whole buffer, and so all of a small output, is written
    // only here.
    let file = sink.into_inner().map_err(|e| {
        Error::io(
            format!("writing {}", staging.path.display()),
            e.into_error(),
        )
    })?;
    // Closed before it is renamed, so that no handle to it outlives the
    // operation.
    drop(file);
    if existing == Existing::Refuse && output.exists() {
        return Err(already_exists(output));
    }
    staging.rename_onto(output)?;
    Ok(value)
}

pub fn encrypt_file(
    recipients: &[Cert],
    passwords: &[Zeroizing<String>],
    signer: Option<(&Cert, Option<&str>)>,
    input: &Path,
    output: &Path,
    existing: Existing,
) -> Result<()> {
    // Streamed in both directions rather than buffered. The property being
    // preserved is the one the buffering used to provide: nothing is left at
    // the output path when encryption fails, because a wrong passphrase or a
    // recipient with no encryption key otherwise truncated whatever was
    // already there. The reason for changing how is that the plaintext is
    // caller-supplied and unbounded and the armored ciphertext is about a
    // third larger again, so holding both made peak memory a multiple of a
    // file the user picked — a multi-gigabyte archive was an out-of-memory
    // kill rather than a slow encrypt.
    //
    // Staged through write_staged, as decrypt_file is.
    let mut source =
        fs::File::open(input).map_err(|e| Error::io(format!("reading {}", input.display()), e))?;
    write_staged(output, existing, Readers::Usual, |sink| {
        encrypt_stream(recipients, passwords, signer, &mut source, sink)
    })
}

pub fn sign_detached_file(
    signer: &Cert,
    password: Option<&str>,
    input: &Path,
    output: &Path,
    existing: Existing,
) -> Result<()> {
    // Only the signature is held — a few hundred bytes — so peak memory does
    // not follow the size of the file being signed.
    let mut source =
        fs::File::open(input).map_err(|e| Error::io(format!("reading {}", input.display()), e))?;
    let mut signature = Vec::new();
    sign_detached_stream(signer, password, &mut source, &mut signature)?;
    match existing {
        // Written straight to its name, since nothing there is being
        // replaced, into a file create_new makes. The name used to be checked
        // with exists() and then written with fs::write, which truncated a
        // file that appeared in between, and followed a dangling symlink
        // planted at the name, which exists() reports as absent, to create the
        // signature wherever the link pointed. A signature cut short by a
        // failed write is removed, since the file is known to be this call's.
        Existing::Refuse => {
            let (unfinished, mut file) = match create_new(output.to_path_buf(), Readers::Usual) {
                Err(Error::Io { source, .. }) if source.kind() == ErrorKind::AlreadyExists => {
                    return Err(already_exists(output));
                }
                created => created?,
            };
            let written = file.write_all(&signature);
            drop(file);
            written.map_err(|e| Error::io(format!("writing {}", output.display()), e))?;
            unfinished.keep();
            Ok(())
        }
        // Staged and renamed onto the chosen file, as encrypt_file and
        // decrypt_file stage, rather than written straight into it. A write
        // truncates its file first, so one that failed part-way, on a full
        // disk or over quota, would leave the file the user agreed to replace
        // neither what it was nor a signature.
        Existing::Replace => write_staged(output, existing, Readers::Usual, |sink| {
            sink.write_all(&signature)
                .map_err(|e| Error::io(format!("writing {}", output.display()), e))
        }),
    }
}

pub fn decrypt_file(
    store: &Store,
    input: &Path,
    passwords: &[&str],
    output: &Path,
    existing: Existing,
) -> Result<VerifyResult> {
    // The ciphertext is streamed too, not read whole. The output half of this
    // function has always been streamed; the input half was still a read() of
    // a file the user picked, so peak memory tracked its size on the one
    // operation whose binding resource is memory.
    let source =
        fs::File::open(input).map_err(|e| Error::io(format!("reading {}", input.display()), e))?;
    let source = std::io::BufReader::new(source);

    // Streamed to a sibling file and renamed on success, rather than buffered
    // in memory. The property being preserved is that a failed decryption
    // leaves nothing at the output path; the reason for changing how is that
    // OpenPGP messages carry compressed layers, sequoia inflates them
    // transparently, and it bounds the *nesting* of those layers rather than
    // the bytes they expand to. Anyone can encrypt a highly compressible
    // message to a published key, so buffering the plaintext made the size of
    // an allocation the sender's choice. On disk it is the filesystem's
    // problem, and write_staged removes the partial file however the
    // decryption ends. It is readable by its owner alone from the moment it
    // exists; see Readers::Owner.
    write_staged(output, existing, Readers::Owner, |sink| {
        decrypt_stream(store, source, passwords, sink)
    })
}

/// Verify an armored or binary detached signature against the file it signs.
pub fn verify_detached_files(
    store: &Store,
    signature_path: &Path,
    data_path: &Path,
) -> Result<VerifyResult> {
    let signature = read(signature_path)?;
    // The signed file is streamed rather than read whole: it is unbounded and
    // caller-supplied, while the signature beside it is a few hundred bytes.
    //
    // It is read through a file handle rather than handed to verify_file,
    // which on Unix maps a file of 64 KiB or more into memory. A mapped file
    // that shrinks while it is being hashed, or whose disk or network share
    // goes away meanwhile, raises SIGBUS, and that kills the whole window,
    // where a read ends early at a bad signature or returns an error. On a
    // file that does not change, the verdict is the one verify_bytes reaches.
    // This writes nothing, so there is no output to keep intact.
    let data = fs::File::open(data_path)
        .map_err(|e| Error::io(format!("reading {}", data_path.display()), e))?;
    let policy = sha1_policy_or_strict(store);
    let helper = Helper::new(store, &[], &policy);
    let mut verifier = DetachedVerifierBuilder::from_bytes(&signature)?.with_policy(
        policy.verification(),
        None,
        helper,
    )?;
    verifier.verify_reader(data)?;

    let helper = verifier.into_helper();
    Ok(VerifyResult {
        signatures: helper.signatures,
        decrypted_with: None,
        encrypted: false,
    })
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| Error::io(format!("reading {}", path.display()), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyGenRequest, generate};
    use sequoia_openpgp::crypto::mpi;
    use sequoia_openpgp::packet::skesk::{SKESK4, SKESK6};
    use sequoia_openpgp::serialize::Serialize;
    use sequoia_openpgp::types::AEADAlgorithm;
    use sequoia_openpgp::{Packet, PacketPile};

    fn scratch_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
    }

    /// OpenPGP's two encryption flags mean "in flight" and "at rest", and this
    /// app used to answer the same question differently depending on who asked.
    ///
    /// [`crate::CertSummary::can_encrypt`], the details pane and both decrypt
    /// paths all count either flag; encrypting took transport keys alone. A
    /// certificate whose only encryption subkey carries the storage flag — `sq
    /// key generate --can-encrypt=storage` makes one — was therefore listed in
    /// the recipient picker, shown with an `E`, and refused with "no usable
    /// encryption key" the moment it was used.
    #[test]
    fn encrypts_to_a_certificate_whose_only_encryption_key_is_for_storage() {
        use sequoia_openpgp::cert::CertBuilder;
        use sequoia_openpgp::types::KeyFlags;

        let (_dir, store) = scratch_store();
        let (cert, _) = CertBuilder::new()
            .add_userid("Dana <dana@example.org>")
            .add_subkey(KeyFlags::empty().set_storage_encryption(), None, None)
            .generate()
            .unwrap();
        store.insert_secret(&cert).unwrap();
        assert!(
            crate::CertSummary::from_cert(&cert).can_encrypt,
            "the recipient picker is built from this, and it offers the key"
        );

        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&cert),
            &[],
            None,
            b"the quarterly figures",
            &mut ciphertext,
        )
        .expect("a storage-encryption key is an encryption key");

        // And what came out is really readable, rather than merely produced.
        let mut plaintext = Vec::new();
        decrypt(&store, &ciphertext, &[], &mut plaintext).unwrap();
        assert_eq!(plaintext, b"the quarterly figures");

        // Storage keys are a fallback, not an addition: a key generated here
        // carries a storage subkey beside its transport one, and taking both
        // would put a second PKESK on every message it is ever sent.
        let ordinary = generate(&KeyGenRequest::new("Erin <erin@example.org>"))
            .unwrap()
            .cert;
        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&ordinary),
            &[],
            None,
            b"the quarterly figures",
            &mut ciphertext,
        )
        .unwrap();
        let pkesks = sequoia_openpgp::PacketPile::from_bytes(&ciphertext)
            .unwrap()
            .descendants()
            .filter(|p| matches!(p, sequoia_openpgp::Packet::PKESK(_)))
            .count();
        assert_eq!(pkesks, 1, "one recipient, one PKESK");
    }

    /// The notepad routes cleartext-signed input to verify_inline rather than
    /// to the decrypt path, and only the decrypt path had a ceiling — so the
    /// comment claiming the notepad's output was bounded covered one of the
    /// two branches it can take. An inline-signed message carries a compressed
    /// layer, which expands to whatever the sender chose.
    #[test]
    fn an_inline_signed_bomb_is_refused_rather_than_held_in_memory() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        // Signed inline, with a body larger than the window. Zeroes compress
        // to almost nothing, which is the whole point of the shape.
        let huge = vec![0u8; MAX_IN_MEMORY_PLAINTEXT + 1];
        let mut signed = Vec::new();
        {
            use sequoia_openpgp::serialize::stream::{Compressor, LiteralWriter, Message, Signer};
            let keypair = alice
                .keys()
                .secret()
                .with_policy(&policy(), None)
                .for_signing()
                .next()
                .unwrap()
                .key()
                .clone()
                .into_keypair()
                .unwrap();
            let message = Message::new(&mut signed);
            let signer = Signer::new(message, keypair).unwrap().build().unwrap();
            let compressor = Compressor::new(signer).build().unwrap();
            let mut literal = LiteralWriter::new(compressor).build().unwrap();
            literal.write_all(&huge).unwrap();
            literal.finalize().unwrap();
        }
        assert!(
            signed.len() < 1024 * 1024,
            "the point is a small message with a large expansion, got {} bytes",
            signed.len()
        );

        let refused = verify_inline(&store, &signed);
        let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            message.contains("more than this window can hold"),
            "an oversized inline-signed message must be refused, got: {message:?}"
        );
    }

    /// Session-key packets are cheap to add and expensive to try. Each one is
    /// tested against every key we hold, and each protected key costs a key
    /// derivation, so a sender who pads a message with wildcard packets makes
    /// the recipient burn CPU proportional to (packets × keys) — behind a
    /// modal that says "Working..." and cannot be cancelled. A real message
    /// carries one per recipient.
    #[test]
    fn a_message_padded_with_session_key_packets_is_refused() {
        use sequoia_openpgp::{Packet, PacketPile, serialize::Serialize};

        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(&[alice], &[], None, b"hello", &mut ciphertext).unwrap();

        // The honest message opens.
        let mut out = Vec::new();
        assert!(decrypt_to_memory(&store, &ciphertext, &[], &mut out).is_ok());

        // Now pad it. Duplicating the one real PKESK is enough: every copy
        // has to be tried, and the count is all the guard looks at.
        let pile = PacketPile::from_bytes(&ciphertext).unwrap();
        let mut packets: Vec<Packet> = pile.into_children().collect();
        let pkesk = packets
            .iter()
            .find(|p| matches!(p, Packet::PKESK(_)))
            .unwrap()
            .clone();
        for _ in 0..300 {
            packets.insert(0, pkesk.clone());
        }
        let mut padded = Vec::new();
        for packet in &packets {
            packet.serialize(&mut padded).unwrap();
        }

        let mut out = Vec::new();
        let refused = decrypt_to_memory(&store, &padded, &[], &mut out);
        let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            message.contains("session-key packets"),
            "a padded message must be refused up front, got: {message:?}"
        );
    }

    /// Rebuild the session-key envelope of a password-encrypted message around
    /// `s2k`, leaving the rest of the message exactly as sequoia wrote it.
    ///
    /// Sequoia cannot be asked for an Argon2 envelope — its encryptor writes
    /// `S2K::default()`, iterated SHA-256 — so a test that needs one has to
    /// recover the session key from the packet sequoia did write and seal it
    /// again. Building the packet derives the key once, so `s2k` wants to be a
    /// cheap one even in a test about expensive ones; `set_s2k` re-prices the
    /// packet afterwards without deriving anything.
    fn resealed(message: &[u8], password: &Password, s2k: S2K) -> Vec<Packet> {
        let pile = PacketPile::from_bytes(message).unwrap();
        let mut packets: Vec<Packet> = pile.into_children().collect();
        let sealed = packets
            .iter()
            .find_map(|p| match p {
                Packet::SKESK(SKESK::V4(skesk)) => Some(skesk.clone()),
                _ => None,
            })
            .expect("a password-only message is sealed with a v4 SKESK");
        let (payload_algo, session_key) = sealed.decrypt(password).unwrap();
        let replacement = SKESK4::with_password(
            payload_algo,
            sealed.symmetric_algo(),
            s2k,
            &session_key,
            password,
        )
        .unwrap();
        for packet in &mut packets {
            if matches!(packet, Packet::SKESK(_)) {
                *packet = Packet::from(replacement.clone());
            }
        }
        packets
    }

    /// The wire form of a packet sequence a test has assembled by hand.
    fn packet_bytes(packets: &[Packet]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for packet in packets {
            packet.serialize(&mut bytes).unwrap();
        }
        bytes
    }

    /// An Argon2 envelope that charges its full stated price and derives
    /// nothing.
    ///
    /// `p = 0` is what makes that possible: `p` is a raw octet on the wire, and
    /// `argon2` rejects a parallelism below one while building its parameters,
    /// before it asks the allocator for anything. So a test can put several of
    /// these in a message, spend the budget exactly as a real message would,
    /// and still finish in milliseconds.
    fn free_but_dear() -> Packet {
        Packet::from(
            SKESK4::new(
                SymmetricAlgorithm::AES256,
                S2K::Argon2 {
                    salt: [0u8; 16],
                    t: 1,
                    p: 0,
                    m: MAX_ARGON2_M,
                },
                None,
            )
            .unwrap(),
        )
    }

    /// A session-key packet's S2K is the *sender's* choice, and Argon2 lets it
    /// name a memory size and a pass count that the recipient pays — once for
    /// every (packet × candidate password), and before the password is checked
    /// at all, so a wrong guess costs exactly as much as a right one. Sequoia
    /// reads `t` and `m` as raw octets and bounds neither, and `argon2`'s own
    /// maxima are `u32::MAX`, so the limits have to be rpgp's own.
    ///
    /// They are drawn where nobody following the specification lands: what a
    /// correctly built message asks for has to go through, or the guard costs
    /// more than the attack.
    #[test]
    fn the_argon2_budget_admits_what_the_specification_recommends_and_refuses_more() {
        // `new` rather than `with_password`, which would run the S2K it is
        // handed. Nothing here derives anything, which is the point: the
        // budget answers before any derivation, so the test can name
        // parameters no machine would survive.
        let asking = |t: u8, p: u8, m: u8| -> SKESK {
            SKESK4::new(
                SymmetricAlgorithm::AES256,
                S2K::Argon2 {
                    salt: [0u8; 16],
                    t,
                    p,
                    m,
                },
                None,
            )
            .unwrap()
            .into()
        };

        // RFC 9580 specifies Argon2 for v6, so a v6 envelope is the one an
        // over-priced packet actually arrives in. It carries its S2K in the
        // same place and is priced from the same match arm; the fields around
        // it are never read here, so they can be anything.
        let asking_v6 = |t: u8, p: u8, m: u8| -> SKESK {
            SKESK6::new(
                SymmetricAlgorithm::AES256,
                AEADAlgorithm::OCB,
                S2K::Argon2 {
                    salt: [0u8; 16],
                    t,
                    p,
                    m,
                },
                vec![0u8; 15].into_boxed_slice(),
                vec![0u8; 48].into_boxed_slice(),
            )
            .unwrap()
            .into()
        };

        // RFC 9580's own sample locked key asks for t=1, p=4, m=21, and its
        // alternative for memory-constrained machines for t=3, p=4, m=16 —
        // RFC 9106's two recommendations. Refusing either would mean refusing
        // a message somebody had produced correctly.
        let mut budget = Argon2Budget::new();
        budget
            .charge(&asking(1, 4, 21))
            .expect("RFC 9106's first recommendation is what the ceiling is set to");
        budget
            .charge(&asking(3, 4, 16))
            .expect("RFC 9106's recommendation for constrained machines is far inside it");
        Argon2Budget::new()
            .charge(&asking_v6(1, 4, 21))
            .expect("a v6 envelope is admitted on the same terms as a v4 one");

        // An iterated S2K costs nothing against the budget: its own encoding
        // caps it at 0x3e00000 bytes of hashing, and it is what every SKESK
        // sequoia and GnuPG write carries. A message padded to the packet
        // ceiling must not be refused for asking for Argon2 it never asked
        // for.
        let iterated: SKESK = SKESK4::new(SymmetricAlgorithm::AES256, S2K::default(), None)
            .unwrap()
            .into();
        let mut budget = Argon2Budget::new();
        for _ in 0..256 {
            budget
                .charge(&iterated)
                .expect("an iterated S2K is bounded by its own encoding");
        }

        // Memory past the recommendation is refused before anything is asked
        // of the allocator, which is the half of this that ends in an
        // OOM kill rather than a wait.
        let refused = Argon2Budget::new()
            .charge(&asking(1, 4, 22))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            refused.contains("2^22 KiB of memory") && refused.contains("rpgp will allocate"),
            "4 GiB for one attempt must be refused as memory, got: {refused:?}"
        );

        // A packet naming no passes at all is the one the work check cannot
        // answer, because its work is zero whatever memory it asks for. The
        // memory check is what stops `1 << m` being evaluated for an `m` that
        // is not a shift distance.
        let refused = Argon2Budget::new()
            .charge(&asking(0, 4, 200))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            refused.contains("2^200 KiB of memory"),
            "a zero-pass packet must still be refused on its memory, got: {refused:?}"
        );

        // And so is a pass count that stays inside the memory limit and
        // multiplies the work instead. This is the shape a memory cap alone
        // misses: 16 MiB is nothing, 16 MiB hashed 255 times over is twice
        // the ceiling.
        for over in [asking(255, 4, 14), asking_v6(255, 4, 14)] {
            let refused = Argon2Budget::new()
                .charge(&over)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(
                refused.contains("16 MiB of memory hashed 255 times over")
                    && refused.contains("more work than rpgp will spend"),
                "a high pass count must be refused as work, got: {refused:?}"
            );
        }

        // Four derivations at the per-attempt ceiling is the whole allowance
        // for one decryption, so a fifth is refused however legal it is on its
        // own. Without this, 256 packets tried against two candidates are 512
        // individually legal derivations.
        let mut budget = Argon2Budget::new();
        for _ in 0..4 {
            budget
                .charge(&asking(1, 4, 21))
                .expect("four at the ceiling is what the allowance is");
        }
        let refused = budget
            .charge(&asking(1, 4, 21))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            refused.contains("more work in total"),
            "the fifth derivation must exhaust the budget, got: {refused:?}"
        );
    }

    /// The other half of the same guard: that it is wired into the decrypt
    /// path ahead of the derivation, rather than sitting in a type nothing
    /// asks. A message of a few hundred bytes could otherwise hold the app for
    /// minutes behind a modal whose Cancel button is disabled while it works.
    #[test]
    fn a_message_that_prices_its_password_hashing_beyond_the_budget_is_refused() {
        let (_dir, store) = scratch_store();
        let password = Zeroizing::new("correct horse battery staple".to_string());
        let secret = Password::from(password.as_str());

        let mut ciphertext = Vec::new();
        encrypt(
            &[],
            std::slice::from_ref(&password),
            None,
            b"the quarterly figures",
            &mut ciphertext,
        )
        .unwrap();

        // Deliberately tiny, because building the packet derives the key: the
        // test pays once for whatever it asks for here, and the parameters it
        // is re-priced to below are never derived at all.
        let mut packets = resealed(
            &ciphertext,
            &secret,
            S2K::Argon2 {
                salt: [7u8; 16],
                t: 1,
                p: 4,
                m: 10,
            },
        );

        // An Argon2 message inside the budget is untouched by any of this.
        let mut plaintext = Vec::new();
        decrypt_to_memory(
            &store,
            &packet_bytes(&packets),
            &[password.as_str()],
            &mut plaintext,
        )
        .expect("Argon2 within the budget is ordinary password-encrypted mail");
        assert_eq!(plaintext, b"the quarterly figures");

        // The same message, with the sender asking for 16 MiB hashed 255 times
        // over for every attempt to open it. The password is the right one, so
        // a refusal that mentioned the password would be a lie as well as a
        // dead end.
        for packet in &mut packets {
            if let Packet::SKESK(SKESK::V4(skesk)) = packet {
                skesk.set_s2k(S2K::Argon2 {
                    salt: [7u8; 16],
                    t: 255,
                    p: 4,
                    m: 14,
                });
            }
        }
        let priced = packet_bytes(&packets);
        let started = std::time::Instant::now();
        let mut plaintext = Vec::new();
        let refused = decrypt_to_memory(&store, &priced, &[password.as_str()], &mut plaintext);
        let elapsed = started.elapsed();
        let detail = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            detail.contains("more work than rpgp will spend"),
            "an over-priced message must be refused as over-priced, got: {detail:?}"
        );
        assert!(
            !detail.contains("no secret key, and no password"),
            "the refusal must not read as a wrong password, got: {detail:?}"
        );
        // Refusing after the derivation rather than before it would produce
        // this same sentence, having already spent everything it refuses to
        // spend, so the wording alone does not establish the guard. The
        // measured separation is not subtle: the derivation this skips takes
        // about 30 s in an unoptimised build, against 16 ms measured here for
        // the guarded path, and most of that was asking gpg-agent about card
        // keys, which a message with no packet for a key no longer does.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "the refusal has to come before the derivation, not after it: took {elapsed:?}"
        );
    }

    /// An envelope rpgp will not pay for is passed over, not fatal.
    ///
    /// A message can carry several, and the over-priced one need not be the one
    /// that would have opened it — nor is the symmetric path the last thing
    /// tried, since the card keys the agent holds are asked about after it.
    /// Ending the decrypt at the first packet with a price on it would refuse
    /// messages that were always readable, so the price is remembered and
    /// reported only if nothing else works.
    #[test]
    fn an_over_priced_envelope_does_not_condemn_the_rest_of_the_message() {
        let (_dir, store) = scratch_store();
        let password = Zeroizing::new("correct horse battery staple".to_string());

        let mut ciphertext = Vec::new();
        encrypt(
            &[],
            std::slice::from_ref(&password),
            None,
            b"the quarterly figures",
            &mut ciphertext,
        )
        .unwrap();

        // The envelope sequoia wrote, left exactly as it was — iterated
        // SHA-256, which costs the budget nothing — behind one asking for
        // 16 MiB hashed 255 times over. Built with `new`, so the parameters it
        // names are derived neither here nor in the decrypt that declines
        // them.
        let sealed: Vec<Packet> = PacketPile::from_bytes(&ciphertext)
            .unwrap()
            .into_children()
            .collect();
        let mixed: Vec<Packet> = std::iter::once(Packet::from(
            SKESK4::new(
                SymmetricAlgorithm::AES256,
                S2K::Argon2 {
                    salt: [0u8; 16],
                    t: 255,
                    p: 4,
                    m: 14,
                },
                None,
            )
            .unwrap(),
        ))
        .chain(sealed)
        .collect();

        let mut plaintext = Vec::new();
        decrypt_to_memory(
            &store,
            &packet_bytes(&mixed),
            &[password.as_str()],
            &mut plaintext,
        )
        .expect("an envelope rpgp declined to price is not the only envelope");
        assert_eq!(plaintext, b"the quarterly figures");
    }

    /// The budget has to span the message rather than the call it is charged
    /// in, and those are not the same thing.
    ///
    /// Sequoia calls the decryption helper once for every encryption container
    /// it descends into, handing it every session-key packet accumulated so
    /// far, and it descends as far as its default recursion limit of sixteen.
    /// A budget held in that method is therefore handed back full at each
    /// layer, and a message that nests its containers buys one budget per
    /// layer out of a couple of kilobytes — a smaller copy of exactly the
    /// thing the budget exists to stop.
    #[test]
    fn a_nested_encryption_container_does_not_buy_a_second_hashing_budget() {
        let (_dir, store) = scratch_store();
        let password = Zeroizing::new("correct horse battery staple".to_string());
        let secret = Password::from(password.as_str());

        // The inner message, sealed under an Argon2 envelope cheap enough to
        // derive for real. It is the only thing that opens the inner
        // container, so whether the budget still has room for it when the
        // second container is reached is the whole question here.
        let mut inner_plain = Vec::new();
        encrypt(
            &[],
            std::slice::from_ref(&password),
            None,
            b"the quarterly figures",
            &mut inner_plain,
        )
        .unwrap();
        let inner = packet_bytes(&resealed(
            &inner_plain,
            &secret,
            S2K::Argon2 {
                salt: [7u8; 16],
                t: 1,
                p: 4,
                m: 10,
            },
        ));

        // A second container around it, written by sequoia, whose contents are
        // that message rather than a literal packet. Nesting is what makes the
        // helper's `decrypt` run twice.
        let mut nested = Vec::new();
        {
            let message = Message::new(&mut nested);
            let mut message = Encryptor::with_passwords(message, vec![secret.clone()])
                .build()
                .unwrap();
            message.write_all(&inner).unwrap();
            message.finalize().unwrap();
        }
        let outer: Vec<Packet> = PacketPile::from_bytes(&nested)
            .unwrap()
            .into_children()
            .collect();

        // Nesting on its own changes nothing: both layers ask for parameters
        // well inside the budget, so the message reads exactly as it would
        // unwrapped. Without this the rest of the test would pass on a message
        // that was simply malformed.
        let mut plaintext = Vec::new();
        decrypt_to_memory(&store, &nested, &[password.as_str()], &mut plaintext)
            .expect("two layers of ordinary parameters are two layers of ordinary mail");
        assert_eq!(plaintext, b"the quarterly figures");

        // Three envelopes at the per-attempt ceiling, ahead of the outer
        // container, leave one of the four the budget holds. The outer
        // container spends the three and opens on its own iterated envelope;
        // the inner one is then handed all three again, and a budget scoped to
        // the call would hand it the same four back and let its Argon2
        // envelope through.
        let priced: Vec<Packet> = std::iter::repeat_with(free_but_dear)
            .take(3)
            .chain(outer)
            .collect();
        let mut plaintext = Vec::new();
        let refused = decrypt_to_memory(
            &store,
            &packet_bytes(&priced),
            &[password.as_str()],
            &mut plaintext,
        );
        let detail = refused.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            detail.contains("more work in total"),
            "the second container must be charged against what the first one spent, \
             got: {detail:?}"
        );
    }

    /// Text that ends without a trailing newline — a bare CR, or nothing at all
    /// — must still round-trip. Pasting from a Windows application yields CRLF,
    /// and deleting the trailing blank line then leaves a bare CR at the end;
    /// the app signed that without complaint and then called its own output
    /// "Message has been manipulated" when asked to verify it back.
    #[test]
    fn cleartext_signing_round_trips_whatever_the_text_ends_with() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut failures = Vec::new();
        for (name, body) in [
            ("trailing CRLF", "Line one.\r\nLine two.\r\n"),
            ("trailing bare CR", "Line one.\r\nLine two.\r"),
            ("no trailing newline", "Line one.\r\nLine two."),
            ("trailing LF", "Line one.\nLine two.\n"),
            ("bare CR in the middle", "Line one.\rLine two.\n"),
        ] {
            let mut signed = Vec::new();
            sign_cleartext(&alice, None, body.as_bytes(), &mut signed).unwrap();
            let (_text, result) = verify_inline(&store, &signed).unwrap();
            if !result.all_good() {
                failures.push(name);
            }
        }
        assert!(
            failures.is_empty(),
            "signed our own text and then rejected it: {failures:?}"
        );
    }

    /// A signed-but-unencrypted message opens through exactly the same code
    /// path as an encrypted one — sequoia's Decryptor walks straight to the
    /// Literal packet and never calls DecryptionHelper::decrypt — so without
    /// an explicit flag the app told the reader that a message which crossed
    /// the network in clear had been "Decrypted to <path>", in the same tone
    /// a properly encrypted one gets. The signature verdict was honest; the
    /// confidentiality claim was not.
    #[test]
    fn a_signed_but_unencrypted_message_is_not_reported_as_encrypted() {
        use sequoia_openpgp::serialize::stream::{LiteralWriter, Message, Signer};

        let (_dir, store) = scratch_store();
        let mallory = generate(&KeyGenRequest::new("Mallory <mallory@example.org>"))
            .unwrap()
            .cert;
        store.insert(&mallory).unwrap();

        // Signed, encrypted to nobody: OnePassSig / Literal / Signature.
        let keypair = mallory
            .keys()
            .secret()
            .with_policy(&policy(), None)
            .for_signing()
            .next()
            .unwrap()
            .key()
            .clone()
            .into_keypair()
            .unwrap();
        let mut cleartext = Vec::new();
        {
            let message = Message::new(&mut cleartext);
            let signer = Signer::new(message, keypair).unwrap().build().unwrap();
            let mut literal = LiteralWriter::new(signer).build().unwrap();
            literal
                .write_all(b"this crossed the network in clear")
                .unwrap();
            literal.finalize().unwrap();
        }

        let mut plaintext = Vec::new();
        let result = decrypt_to_memory(&store, &cleartext, &[], &mut plaintext).unwrap();

        assert_eq!(plaintext, b"this crossed the network in clear");
        assert!(
            result.all_good(),
            "the signature itself is genuine: {:?}",
            result.signatures
        );
        assert!(
            !result.encrypted,
            "a message with no encryption layer must not be reported as decrypted"
        );

        // And a real one still reads as encrypted, or the flag is a constant.
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let mut ciphertext = Vec::new();
        encrypt(&[alice], &[], None, b"secret", &mut ciphertext).unwrap();
        let mut out = Vec::new();
        let opened = decrypt_to_memory(&store, &ciphertext, &[], &mut out).unwrap();
        assert!(opened.encrypted, "a real encryption layer must be seen");
    }

    #[test]
    fn encrypt_sign_decrypt_round_trip() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert_secret(&bob).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&bob),
            &[],
            Some((&alice, None)),
            b"attack at dawn",
            &mut ciphertext,
        )
        .unwrap();
        assert!(ciphertext.starts_with(b"-----BEGIN PGP MESSAGE-----"));

        let mut plaintext = Vec::new();
        let result = decrypt(&store, &ciphertext, &[], &mut plaintext).unwrap();

        assert_eq!(plaintext, b"attack at dawn");
        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        assert_eq!(result.signatures[0].signer, "Alice <alice@example.org>");
        assert_eq!(result.decrypted_with, Some(bob.fingerprint().to_hex()));
    }

    #[test]
    fn classifies_what_the_verify_dialog_will_be_handed() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut message = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"hello",
            &mut message,
        )
        .unwrap();
        assert_eq!(classify(&message), InputKind::Message);

        let mut signature = Vec::new();
        sign_detached(&alice, None, b"hello", &mut signature).unwrap();
        assert_eq!(classify(&signature), InputKind::DetachedSignature);

        // A cleartext signature carries both markers; it is a message, not a
        // detached signature, whatever order they appear in.
        let mut cleartext = Vec::new();
        sign_cleartext(&alice, None, b"hello", &mut cleartext).unwrap();
        assert_eq!(classify(&cleartext), InputKind::Message);

        assert_eq!(classify(b"just a text file\n"), InputKind::NotOpenPgp);
        assert_eq!(classify(b""), InputKind::NotOpenPgp);
    }

    /// The size ceiling itself, at a limit small enough to test quickly.
    #[test]
    fn the_in_memory_sink_refuses_to_grow_past_its_limit() {
        let mut out = Vec::new();
        let mut sink = Bounded {
            inner: &mut out,
            written: 0,
            limit: 1024,
        };
        assert!(sink.write_all(&[0u8; 1000]).is_ok());
        let err = sink
            .write_all(&[0u8; 100])
            .expect_err("past the limit must fail");
        assert!(err.to_string().contains("decrypt it to a file"), "{err}");
        // And it stopped writing rather than truncating silently.
        assert!(out.len() <= 1024);
    }

    /// A compressed layer expands to whatever the sender chose. Sequoia bounds
    /// how deeply layers may nest, not how far they expand, so the in-memory
    /// path needs its own ceiling and the file path streams instead of
    /// buffering. rpgp does not compress on write, so the bomb is built here
    /// the way a hostile sender would.
    #[test]
    fn a_compressed_bomb_streams_to_disk_and_leaves_no_debris() {
        use sequoia_openpgp::serialize::stream::{Compressor, Encryptor, LiteralWriter, Message};
        use sequoia_openpgp::types::CompressionAlgorithm;

        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        // 8 MiB of zeroes behind a deflate layer: a few kilobytes on the wire.
        let bulk = vec![0u8; 8 * 1024 * 1024];
        let policy = policy();
        let valid = alice.with_policy(&policy, None).unwrap();
        let recipients: Vec<_> = valid
            .keys()
            .alive()
            .revoked(false)
            .supported()
            .for_transport_encryption()
            .map(Recipient::from)
            .collect();

        let mut ciphertext = Vec::new();
        {
            let message = Message::new(&mut ciphertext);
            let message = Encryptor::for_recipients(message, recipients)
                .build()
                .unwrap();
            let message = Compressor::new(message)
                .algo(CompressionAlgorithm::Zip)
                .build()
                .unwrap();
            let mut message = LiteralWriter::new(message).build().unwrap();
            message.write_all(&bulk).unwrap();
            message.finalize().unwrap();
        }
        assert!(
            ciphertext.len() < bulk.len() / 100,
            "the fixture must actually compress: {} bytes",
            ciphertext.len()
        );

        // Streamed to a file: the expansion lands on disk, not in a Vec.
        let input = dir.path().join("bomb.pgp");
        std::fs::write(&input, &ciphertext).unwrap();
        let output = dir.path().join("bomb.out");
        decrypt_file(&store, &input, &[], &output, Existing::Refuse).unwrap();
        assert_eq!(std::fs::metadata(&output).unwrap().len(), bulk.len() as u64);

        // A failure leaves neither the output nor the staging file.
        let bad = dir.path().join("bad.pgp");
        std::fs::write(&bad, b"-----BEGIN PGP MESSAGE-----\nnonsense\n").unwrap();
        let out = dir.path().join("bad.out");
        assert!(decrypt_file(&store, &bad, &[], &out, Existing::Refuse).is_err());
        assert!(!out.exists(), "no output on failure");
        assert!(
            !append_extension(&out, "part").exists(),
            "no staging file left behind"
        );
    }

    /// The staging file must not land on a name the user already owns.
    ///
    /// encrypt_file stages like decrypt_file now, so it inherits the same
    /// hazard: a staging name derived from the output must not land on a file
    /// the user owns, and must not survive a failure.
    #[test]
    fn encrypting_stages_without_destroying_an_unrelated_file() {
        let (dir, _store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;

        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"hello").unwrap();
        let output = dir.path().join("notes.txt.asc");

        // What the substituting name would have collided with.
        let bystander = dir.path().join("notes.part");
        std::fs::write(&bystander, b"someone else's file").unwrap();

        encrypt_file(
            std::slice::from_ref(&alice),
            &[],
            None,
            &input,
            &output,
            Existing::Refuse,
        )
        .unwrap();

        assert!(output.exists(), "the encrypted output should exist");
        assert_eq!(
            std::fs::read(&bystander).unwrap(),
            b"someone else's file",
            "encrypting destroyed an unrelated file"
        );
        assert!(
            !append_extension(&output, "part").exists(),
            "the staging file outlived a successful encrypt"
        );

        // And a failure leaves neither a staging file nor a damaged output.
        // Alice's key has no passphrase, so offering one fails the signing
        // step, as "this key has no passphrase", once the staging file has
        // been made. That is not the refusal of the taken output name, which
        // is never reached here;
        // a_chosen_output_replaces_the_file_there_and_a_derived_one_does_not
        // tests that.
        std::fs::write(&output, b"PRECIOUS").unwrap();
        assert!(
            encrypt_file(
                std::slice::from_ref(&alice),
                &[],
                Some((&alice, Some("wrong"))),
                &input,
                &output,
                Existing::Refuse,
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"PRECIOUS");
        assert!(
            !append_extension(&output, "part").exists(),
            "a failed encrypt left its staging file behind"
        );
        assert_eq!(std::fs::read(&bystander).unwrap(), b"someone else's file");
    }

    /// `output.with_extension("part")` substituted rather than appended, so
    /// decrypting `notes.txt.asc` next to an unrelated `notes.part` truncated
    /// that file on create and then renamed it away — the exact destruction
    /// `free_name` exists to prevent, on the one path that skipped it.
    #[test]
    fn the_staging_file_does_not_destroy_an_unrelated_file() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"hello",
            &mut ciphertext,
        )
        .unwrap();
        let input = dir.path().join("notes.txt.asc");
        std::fs::write(&input, &ciphertext).unwrap();

        // The bystander: what the old substituting name would have collided
        // with, and what a real user might have had sitting there.
        let bystander = dir.path().join("notes.part");
        std::fs::write(&bystander, b"someone else's file").unwrap();

        let output = decrypted_name(&input);
        decrypt_file(&store, &input, &[], &output, Existing::Refuse).unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), b"hello");
        assert_eq!(
            std::fs::read(&bystander).unwrap(),
            b"someone else's file",
            "decrypting destroyed an unrelated file"
        );
    }

    /// The derived name steps aside rather than destroying an unrelated file
    /// that happens to be sitting there.
    #[test]
    fn derived_names_do_not_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let notes = dir.path().join("notes.txt");
        std::fs::write(&notes, b"mine").unwrap();

        // Decrypting notes.txt.asc would land on notes.txt, which exists.
        let encrypted = dir.path().join("notes.txt.asc");
        std::fs::write(&encrypted, b"x").unwrap();
        let out = decrypted_name(&encrypted);
        assert_eq!(
            out,
            dir.path().join("notes (1).txt"),
            "must not target notes.txt"
        );
        assert_eq!(
            std::fs::read(&notes).unwrap(),
            b"mine",
            "the original is untouched"
        );

        // And it keeps stepping while names are taken.
        std::fs::write(&out, b"first").unwrap();
        assert_eq!(decrypted_name(&encrypted), dir.path().join("notes (2).txt"));

        // The suffix goes before the extension, so the result is still an
        // .asc and still opens as one.
        assert_eq!(encrypted_name(&notes), dir.path().join("notes.txt (1).asc"));

        // A free name is returned unchanged.
        assert_eq!(
            decrypted_name(&dir.path().join("fresh.txt.asc")),
            dir.path().join("fresh.txt")
        );
    }

    /// The bounded read must reach the same verdict as reading everything,
    /// including on a file far larger than the prefix.
    #[test]
    fn classify_file_agrees_with_classify_on_a_large_file() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        // Several megabytes, so the whole thing is far past the 64KiB prefix.
        let bulk = vec![b'x'; 4 * 1024 * 1024];

        let armored = dir.path().join("m.asc");
        let mut out = Vec::new();
        encrypt(std::slice::from_ref(&alice), &[], None, &bulk, &mut out).unwrap();
        std::fs::write(&armored, &out).unwrap();
        assert_eq!(classify(&out), InputKind::Message);
        assert_eq!(classify_file(&armored), InputKind::Message);

        let sig = dir.path().join("m.sig");
        let mut out = Vec::new();
        sign_detached(&alice, None, &bulk, &mut out).unwrap();
        std::fs::write(&sig, &out).unwrap();
        assert_eq!(classify_file(&sig), InputKind::DetachedSignature);

        let plain = dir.path().join("plain.bin");
        std::fs::write(&plain, &bulk).unwrap();
        assert_eq!(classify_file(&plain), InputKind::NotOpenPgp);

        assert_eq!(
            classify_file(&dir.path().join("nope")),
            InputKind::NotOpenPgp
        );
    }

    #[test]
    fn derives_output_names() {
        assert_eq!(
            encrypted_name(Path::new("notes.txt")),
            Path::new("notes.txt.asc")
        );
        assert_eq!(
            signature_name(Path::new("notes.txt")),
            Path::new("notes.txt.sig")
        );
        assert_eq!(
            decrypted_name(Path::new("notes.txt.asc")),
            Path::new("notes.txt")
        );
        assert_eq!(
            decrypted_name(Path::new("notes.txt.gpg")),
            Path::new("notes.txt")
        );
        // Nothing to strip: do not overwrite the input.
        assert_eq!(
            decrypted_name(Path::new("notes.txt")),
            Path::new("notes.txt.out")
        );
    }

    #[test]
    fn file_round_trip() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"the coordinates are in the second envelope").unwrap();

        let encrypted = encrypted_name(&input);
        encrypt_file(
            std::slice::from_ref(&alice),
            &[],
            Some((&alice, None)),
            &input,
            &encrypted,
            Existing::Refuse,
        )
        .unwrap();

        let decrypted = dir.path().join("out.txt");
        let result = decrypt_file(&store, &encrypted, &[], &decrypted, Existing::Refuse).unwrap();

        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        assert_eq!(
            std::fs::read(&decrypted).unwrap(),
            b"the coordinates are in the second envelope"
        );

        let signature = signature_name(&input);
        sign_detached_file(&alice, None, &input, &signature, Existing::Refuse).unwrap();
        assert!(
            verify_detached_files(&store, &signature, &input)
                .unwrap()
                .all_good()
        );
    }

    /// The mirror image for the write side. Creating the output before
    /// validating meant a wrong passphrase truncated whatever was already at
    /// that path.
    #[test]
    fn failed_encryption_and_signing_leave_the_output_untouched() {
        let (dir, _store) = scratch_store();
        let mut request = KeyGenRequest::new("Alice <alice@example.org>");
        request.password = Some("correct horse".to_string().into());
        let alice = generate(&request).unwrap().cert;

        let input = dir.path().join("in.txt");
        std::fs::write(&input, b"plaintext").unwrap();
        let output = dir.path().join("out.asc");
        std::fs::write(&output, b"PRECIOUS EARLIER OUTPUT").unwrap();

        // Signing with the wrong passphrase must fail — and fail *before*
        // touching the file.
        assert!(
            sign_detached_file(&alice, Some("wrong"), &input, &output, Existing::Refuse).is_err()
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"PRECIOUS EARLIER OUTPUT");

        // Likewise sign-and-encrypt with a wrong signing passphrase.
        assert!(
            encrypt_file(
                std::slice::from_ref(&alice),
                &[],
                Some((&alice, Some("wrong"))),
                &input,
                &output,
                Existing::Refuse,
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"PRECIOUS EARLIER OUTPUT");

        // And a nonexistent input, the other easy way to fail.
        assert!(
            encrypt_file(
                &[alice],
                &[],
                None,
                &dir.path().join("nope"),
                &output,
                Existing::Refuse
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"PRECIOUS EARLIER OUTPUT");
    }

    /// A path chosen in a save dialog is written over the file already there,
    /// and a derived one is not.
    ///
    /// Inside the Flatpak each output is chosen in a save dialog, which asks
    /// before it hands back the name of a file that exists. Refusing that name
    /// again here would turn the user's "Replace" into "already exists", and
    /// stepping around it would write somewhere they did not choose. A derived
    /// name was never asked about, so it keeps its refusal. Either way a
    /// failed operation leaves the file as it was: a chosen file is replaced
    /// by renaming a finished output onto its name, never by writing into it.
    #[test]
    fn a_chosen_output_replaces_the_file_there_and_a_derived_one_does_not() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"the plaintext").unwrap();
        let earlier: &[u8] = b"AN EARLIER FILE";
        let refused = |result: Result<()>, output: &Path| {
            let error = result.expect_err("a derived name must not replace a file");
            assert!(
                error.to_string().contains("already exists"),
                "the refusal should say why: {error}"
            );
            assert_eq!(std::fs::read(output).unwrap(), earlier);
        };
        // A second name for a file about to be replaced. It still reads the
        // earlier contents afterwards only if the output was renamed onto the
        // chosen name. Written into the file instead, the output would show
        // through it, and a write that failed part-way, which nothing here can
        // provoke, would have been cut short inside the file the user agreed
        // to replace.
        let links = dir.path().join("links");
        std::fs::create_dir(&links).unwrap();
        let second_name = |path: &Path| {
            let link = links.join(path.file_name().unwrap());
            std::fs::hard_link(path, &link).unwrap();
            link
        };
        let untouched = |link: &Path| {
            assert_eq!(
                std::fs::read(link).unwrap(),
                earlier,
                "the chosen file was written into rather than replaced"
            );
        };

        let encrypted = dir.path().join("chosen.asc");
        std::fs::write(&encrypted, earlier).unwrap();
        let encrypt = |existing| {
            let recipients = std::slice::from_ref(&alice);
            encrypt_file(recipients, &[], None, &input, &encrypted, existing)
        };
        refused(encrypt(Existing::Refuse), &encrypted);
        let kept = second_name(&encrypted);
        encrypt(Existing::Replace).expect("a chosen name is replaced");
        assert_eq!(classify_file(&encrypted), InputKind::Message);
        untouched(&kept);

        let signature = dir.path().join("chosen.sig");
        std::fs::write(&signature, earlier).unwrap();
        let sign = |existing| sign_detached_file(&alice, None, &input, &signature, existing);
        refused(sign(Existing::Refuse), &signature);
        let kept = second_name(&signature);
        sign(Existing::Replace).expect("a chosen name is replaced");
        assert!(
            verify_detached_files(&store, &signature, &input)
                .unwrap()
                .all_good()
        );
        untouched(&kept);

        let decrypted = dir.path().join("chosen.txt");
        std::fs::write(&decrypted, earlier).unwrap();
        let decrypt =
            |existing| decrypt_file(&store, &encrypted, &[], &decrypted, existing).map(|_| ());
        refused(decrypt(Existing::Refuse), &decrypted);

        // The user agreed to replace the file, not to lose it to a message
        // that does not decrypt.
        let bad = dir.path().join("bad.asc");
        std::fs::write(&bad, b"-----BEGIN PGP MESSAGE-----\nnonsense\n").unwrap();
        assert!(decrypt_file(&store, &bad, &[], &decrypted, Existing::Replace).is_err());
        assert_eq!(std::fs::read(&decrypted).unwrap(), earlier);

        let kept = second_name(&decrypted);
        decrypt(Existing::Replace).expect("a chosen name is replaced");
        assert_eq!(std::fs::read(&decrypted).unwrap(), b"the plaintext");
        untouched(&kept);

        // Every output went exactly where it was sent, and no staging file
        // outlived its operation.
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| !name.contains(" (1)") && !name.ends_with(".part")),
            "{names:?}"
        );
    }

    #[test]
    fn failed_decryption_leaves_no_output_file() {
        let (dir, store) = scratch_store();
        let stranger = generate(&KeyGenRequest::new("Stranger <nobody@example.org>"))
            .unwrap()
            .cert;
        // The store never sees the secret key, so nothing can decrypt this.
        store.insert(&stranger).unwrap();

        let encrypted = dir.path().join("secret.asc");
        encrypt_file(
            &[stranger],
            &[],
            None,
            &{
                let p = dir.path().join("in.txt");
                std::fs::write(&p, b"x").unwrap();
                p
            },
            &encrypted,
            Existing::Refuse,
        )
        .unwrap();

        let output = dir.path().join("out.txt");
        assert!(decrypt_file(&store, &encrypted, &[], &output, Existing::Refuse).is_err());
        assert!(
            !output.exists(),
            "a failed decryption must not create the output file"
        );
    }

    /// A staged output leaves nothing behind however it fails.
    ///
    /// Each error arm used to remove the staging file by hand, and the last
    /// write was not one of them: a decrypt whose final flush failed, on a
    /// full disk or over quota, returned its error and left all of the
    /// plaintext but that last buffer at `<output>.part`. Here the file under
    /// the buffer is swapped for a handle that cannot write, which fails that
    /// flush the same way. A panic, which no error arm sees, goes through the
    /// same drop.
    #[test]
    fn a_staged_output_leaves_nothing_behind_however_it_fails() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("out.txt");
        let staging = append_extension(&output, "part");
        let nothing_left = |how: &str| {
            assert!(!output.exists(), "{how} left an output");
            assert!(!staging.exists(), "{how} left its staging file behind");
        };

        let failed = write_staged::<()>(&output, Existing::Refuse, Readers::Owner, |sink| {
            sink.write_all(b"half a plaintext").unwrap();
            Err(Error::invalid("the rest did not decrypt"))
        });
        assert!(failed.is_err());
        nothing_left("a failed operation");

        let error = write_staged(&output, Existing::Refuse, Readers::Owner, |sink| {
            sink.write_all(b"a plaintext the last write never lands")
                .unwrap();
            *sink.get_mut() = fs::File::open(&staging).unwrap();
            Ok(())
        })
        .expect_err("an operation whose last write fails has failed");
        assert!(
            error.to_string().contains(".part"),
            "the error should name the file it could not write: {error}"
        );
        nothing_left("a failed last write");

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_staged::<()>(&output, Existing::Refuse, Readers::Owner, |sink| {
                sink.write_all(b"some of a plaintext").unwrap();
                panic!("a bug part-way through an operation");
            })
        }));
        assert!(panicked.is_err());
        nothing_left("a panic");

        // The control: one that succeeds leaves its output and nothing else.
        write_staged(&output, Existing::Refuse, Readers::Owner, |sink| {
            sink.write_all(b"a plaintext").map_err(Error::from)
        })
        .unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"a plaintext");
        assert!(!staging.exists(), "a finished output left its staging file");
    }

    /// A rename that fails leaves no staging file behind either.
    ///
    /// It used to leave the whole output under its `.part` name: for a
    /// decrypt, all of the plaintext, in a file the user was told had not been
    /// written. A directory at each chosen path is what fails the rename here.
    #[test]
    fn a_failed_rename_leaves_no_staging_file_behind() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"the plaintext").unwrap();
        let encrypted = dir.path().join("notes.txt.asc");
        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"the plaintext",
            &mut ciphertext,
        )
        .unwrap();
        std::fs::write(&encrypted, &ciphertext).unwrap();

        let outputs = dir.path().join("outputs");
        std::fs::create_dir(&outputs).unwrap();
        let in_the_way = |name: &str| {
            let path = outputs.join(name);
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("inside"), b"kept").unwrap();
            path
        };
        let rename_failed = |result: Result<()>, output: &Path| {
            let error = result.expect_err("a rename onto a directory must fail");
            assert!(
                error
                    .to_string()
                    .starts_with(&format!("writing {}:", output.display())),
                "the operation should have got as far as the rename: {error}"
            );
        };

        let output = in_the_way("chosen.asc");
        let recipients = std::slice::from_ref(&alice);
        let encrypted_to = encrypt_file(recipients, &[], None, &input, &output, Existing::Replace);
        rename_failed(encrypted_to, &output);
        let output = in_the_way("chosen.sig");
        let signed = sign_detached_file(&alice, None, &input, &output, Existing::Replace);
        rename_failed(signed, &output);
        let output = in_the_way("chosen.txt");
        let decrypted = decrypt_file(&store, &encrypted, &[], &output, Existing::Replace);
        rename_failed(decrypted.map(|_| ()), &output);

        let mut names: Vec<String> = std::fs::read_dir(&outputs)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["chosen.asc", "chosen.sig", "chosen.txt"]);
        for name in names {
            assert_eq!(
                std::fs::read(outputs.join(name).join("inside")).unwrap(),
                b"kept"
            );
        }
    }

    /// A staging name that is already taken is refused, and the file there is
    /// left as it was.
    ///
    /// free_name hands back a taken name once its series is used up, or when
    /// another file takes the name first, and then only `create_new` stands
    /// between that file and the operation. It is also the one failure that
    /// must not remove the file it failed on, which is somebody else's.
    #[test]
    fn a_taken_staging_name_is_refused_and_left_as_it_was() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"the plaintext").unwrap();
        let encrypted = dir.path().join("notes.txt.asc");
        encrypt_file(
            std::slice::from_ref(&alice),
            &[],
            None,
            &input,
            &encrypted,
            Existing::Refuse,
        )
        .unwrap();

        let output = dir.path().join("out.txt");
        let staging = append_extension(&output, "part");
        let taken: Vec<PathBuf> = std::iter::once(staging.clone())
            .chain((1..1000).map(|n| dir.path().join(format!("out.txt ({n}).part"))))
            .collect();
        for path in &taken {
            std::fs::write(path, b"somebody else's").unwrap();
        }
        assert_eq!(free_name(staging.clone()), staging, "the series is used up");

        // Replace, so that the signature is staged as well.
        let recipients = std::slice::from_ref(&alice);
        let refused = [
            encrypt_file(recipients, &[], None, &input, &output, Existing::Replace),
            sign_detached_file(&alice, None, &input, &output, Existing::Replace),
            decrypt_file(&store, &encrypted, &[], &output, Existing::Replace).map(|_| ()),
        ];
        for result in refused {
            let error = result.expect_err("a taken staging name must be refused");
            assert!(error.to_string().contains("exists"), "{error}");
        }
        assert!(!output.exists());
        for path in &taken {
            assert_eq!(
                std::fs::read(path).unwrap(),
                b"somebody else's",
                "{} was not left as it was",
                path.display()
            );
        }
    }

    /// A derived output name that comes back taken is refused rather than
    /// written over.
    ///
    /// Once `name (1)` to `name (999)` are all taken, free_name hands back the
    /// name itself, and only each operation's own refusal stands between its
    /// output and the file there. This is the way the GUI reaches it: outside
    /// a Flatpak it derives every output name through these three functions.
    #[test]
    fn a_derived_name_that_comes_back_taken_is_refused() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"the plaintext").unwrap();
        let letter = dir.path().join("letter.txt.gpg");
        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"the plaintext",
            &mut ciphertext,
        )
        .unwrap();
        std::fs::write(&letter, &ciphertext).unwrap();

        let earlier: &[u8] = b"AN EARLIER FILE";
        let take_series = |base: &str, extension: &str| -> Vec<PathBuf> {
            let series: Vec<PathBuf> = std::iter::once(format!("{base}{extension}"))
                .chain((1..1000).map(|n| format!("{base} ({n}){extension}")))
                .map(|name| dir.path().join(name))
                .collect();
            for path in &series {
                std::fs::write(path, earlier).unwrap();
            }
            series
        };
        let refused = |result: Result<()>, series: &[PathBuf]| {
            let error = result.expect_err("a taken derived name must be refused");
            assert!(error.to_string().contains("already exists"), "{error}");
            for path in series {
                assert_eq!(std::fs::read(path).unwrap(), earlier, "{}", path.display());
            }
        };

        let series = take_series("notes.txt", ".asc");
        let output = encrypted_name(&input);
        assert_eq!(output, series[0]);
        let recipients = std::slice::from_ref(&alice);
        let encrypted = encrypt_file(recipients, &[], None, &input, &output, Existing::Refuse);
        refused(encrypted, &series);

        let series = take_series("notes.txt", ".sig");
        let output = signature_name(&input);
        assert_eq!(output, series[0]);
        refused(
            sign_detached_file(&alice, None, &input, &output, Existing::Refuse),
            &series,
        );

        let series = take_series("letter", ".txt");
        let output = decrypted_name(&letter);
        assert_eq!(output, series[0]);
        let decrypted = decrypt_file(&store, &letter, &[], &output, Existing::Refuse);
        refused(decrypted.map(|_| ()), &series);

        let staged = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".part"))
            .collect::<Vec<_>>();
        assert!(staged.is_empty(), "{staged:?}");
    }

    /// A detached signature is not written through a dangling symlink at its
    /// name.
    ///
    /// The name was checked with `exists()`, which follows the link and finds
    /// nothing, and then written with `fs::write`, which follows it too and
    /// creates the file it points at: an extracted archive or a cloned
    /// repository carrying `release.tar.gz.sig -> ../elsewhere` had the
    /// signature created outside the directory. `create_new` refuses the link
    /// itself.
    #[cfg(unix)]
    #[test]
    fn a_signature_is_not_written_through_a_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let project = dir.path().join("project");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&elsewhere).unwrap();
        let input = project.join("release.tar.gz");
        std::fs::write(&input, b"a release").unwrap();
        let planted = elsewhere.join("planted");
        let link = project.join("release.tar.gz.sig");
        std::os::unix::fs::symlink(&planted, &link).unwrap();

        // free_name follows the link and finds nothing either, so the name
        // the GUI would use is the link's.
        let output = signature_name(&input);
        assert_eq!(output, link);
        let error = sign_detached_file(&alice, None, &input, &output, Existing::Refuse)
            .expect_err("a symlink at the name must be refused");
        assert!(error.to_string().contains("already exists"), "{error}");
        assert!(
            !planted.exists(),
            "the signature was written through the link"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// A decrypted file is readable by its owner alone, and so is its staging
    /// file from the moment it exists; ciphertext and signatures keep the
    /// mode any new file gets.
    ///
    /// The plaintext used to be created 0666 less the umask, usually 0644:
    /// readable by every local account that can reach the directory, while it
    /// streamed and after. Under a umask of 077 every new file is private
    /// already, and this cannot tell the difference.
    #[cfg(unix)]
    #[test]
    fn a_decrypted_file_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let input = dir.path().join("payroll.csv");
        std::fs::write(&input, b"name,salary").unwrap();
        // What any new file gets here, under whatever umask this runs with.
        let usual = mode(&input);

        let encrypted = encrypted_name(&input);
        let recipients = std::slice::from_ref(&alice);
        encrypt_file(recipients, &[], None, &input, &encrypted, Existing::Refuse).unwrap();
        let signature = signature_name(&input);
        sign_detached_file(&alice, None, &input, &signature, Existing::Refuse).unwrap();
        assert_eq!(mode(&encrypted), usual, "the ciphertext");
        assert_eq!(mode(&signature), usual, "the signature");

        std::fs::remove_file(&input).unwrap();
        let decrypted = decrypted_name(&encrypted);
        decrypt_file(&store, &encrypted, &[], &decrypted, Existing::Refuse).unwrap();
        assert_eq!(std::fs::read(&decrypted).unwrap(), b"name,salary");
        assert_eq!(mode(&decrypted), 0o600, "the plaintext");

        // A chosen file the plaintext replaces is replaced by a private one.
        let chosen = dir.path().join("chosen.csv");
        std::fs::write(&chosen, b"an earlier file").unwrap();
        std::fs::set_permissions(&chosen, std::fs::Permissions::from_mode(0o644)).unwrap();
        decrypt_file(&store, &encrypted, &[], &chosen, Existing::Replace).unwrap();
        assert_eq!(mode(&chosen), 0o600, "the plaintext over a chosen file");

        // Before a byte of plaintext is in it, not after.
        let output = dir.path().join("early.csv");
        write_staged(&output, Existing::Refuse, Readers::Owner, |sink| {
            let staging = sink.get_ref().metadata().unwrap();
            assert_eq!(staging.len(), 0);
            assert_eq!(
                staging.permissions().mode() & 0o777,
                0o600,
                "the staging file"
            );
            Ok(())
        })
        .unwrap();
    }

    /// One of the counters in `/proc/thread-self/io` for the calling thread.
    #[cfg(target_os = "linux")]
    fn thread_io(counter: &str) -> u64 {
        let text = std::fs::read_to_string("/proc/thread-self/io").unwrap();
        text.lines()
            .find_map(|line| line.strip_prefix(counter)?.strip_prefix(": ")?.parse().ok())
            .unwrap_or_else(|| panic!("no {counter} in {text}"))
    }

    /// The file a detached signature covers is read rather than mapped into
    /// memory.
    ///
    /// `verify_file` maps a file of 64 KiB or more on Unix, and a mapped file
    /// that shrinks while it is being hashed, or whose device goes away,
    /// raises SIGBUS and takes the whole window with it. A test that provoked
    /// that would race the hash, so this looks at how the bytes arrive
    /// instead: a read counts them in this thread's `rchar`, and a page fault
    /// on a mapping does not.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_signed_file_is_read_rather_than_mapped_into_memory() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        // Sixteen times the size at which buffered-reader starts to map.
        let size = 1024 * 1024;
        let data = dir.path().join("image.iso");
        std::fs::write(&data, vec![0x5a; size]).unwrap();
        let signature = signature_name(&data);
        sign_detached_file(&alice, None, &data, &signature, Existing::Refuse).unwrap();

        let before = thread_io("rchar");
        let result = verify_detached_files(&store, &signature, &data).unwrap();
        let read = thread_io("rchar") - before;
        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        assert!(
            read >= size as u64,
            "{read} bytes were read to verify a file of {size}, so it was mapped"
        );
    }

    /// A streamed output reaches its file in large writes rather than a write
    /// for every 8 KiB; see [`OUTPUT_BUFFER`].
    #[cfg(target_os = "linux")]
    #[test]
    fn a_streamed_output_is_written_in_large_pieces() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        let input = dir.path().join("archive.tar");
        std::fs::write(&input, vec![0x5a; 2 * 1024 * 1024]).unwrap();
        let average_write = |run: &dyn Fn()| {
            let (calls, bytes) = (thread_io("syscw"), thread_io("wchar"));
            run();
            let (calls, bytes) = (thread_io("syscw") - calls, thread_io("wchar") - bytes);
            assert!(calls > 0);
            bytes / calls
        };

        let encrypted = dir.path().join("archive.tar.asc");
        let encrypt = || {
            let recipients = std::slice::from_ref(&alice);
            encrypt_file(recipients, &[], None, &input, &encrypted, Existing::Refuse).unwrap();
        };
        let average = average_write(&encrypt);
        assert!(
            average >= 256 * 1024,
            "an encrypt wrote {average} bytes a write"
        );

        let decrypted = dir.path().join("out.tar");
        let decrypt = || {
            decrypt_file(&store, &encrypted, &[], &decrypted, Existing::Refuse).unwrap();
        };
        let average = average_write(&decrypt);
        assert!(
            average >= 256 * 1024,
            "a decrypt wrote {average} bytes a write"
        );
    }

    #[test]
    fn a_revoked_key_still_opens_what_it_encrypted() {
        let (dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"written while current",
            &mut ciphertext,
        )
        .unwrap();

        // Retire the whole certificate, as someone rotating keys would.
        let mut request = crate::revoke::RevokeRequest::new(alice.fingerprint().to_hex());
        request.reason = crate::revoke::Reason::Superseded;
        crate::revoke::revoke_cert(&store, &request).unwrap();
        assert_eq!(
            crate::CertSummary::from_cert(&store.lookup(&alice.fingerprint().to_hex()).unwrap())
                .validity,
            crate::Validity::Revoked
        );

        // The archive must stay readable. Revoking withdraws a key from future
        // use; it does not destroy what was already sent.
        let mut plaintext = Vec::new();
        decrypt(&store, &ciphertext, &[], &mut plaintext).unwrap();
        assert_eq!(plaintext, b"written while current");
        let _ = dir;
    }

    /// The other half of the rule the test above states: a message written now
    /// *is* future use. Sequoia's own filters do not catch this. `revoked(false)`
    /// asks each key about its own revocation, and the encryption subkey of a
    /// certificate revoked as a whole carries none — so the recipient stayed in
    /// the picker, the message went out, and whoever holds the key its owner
    /// declared stolen can read it.
    ///
    /// Both kinds of reason are refused. A soft one says the owner has stopped
    /// reading this key, which makes the message no more deliverable than a
    /// hard one makes it private.
    #[test]
    fn refuses_to_encrypt_to_a_certificate_its_owner_revoked() {
        for (reason, name) in [
            (crate::revoke::Reason::Compromised, "Bob <bob@example.org>"),
            (crate::revoke::Reason::Retired, "Carol <carol@example.org>"),
        ] {
            let (_dir, store) = scratch_store();
            let cert = generate(&KeyGenRequest::new(name)).unwrap().cert;
            let fingerprint = cert.fingerprint().to_hex();
            store.insert_secret(&cert).unwrap();

            let mut request = crate::revoke::RevokeRequest::new(&fingerprint);
            request.reason = reason;
            crate::revoke::revoke_cert(&store, &request).unwrap();
            let cert = store.lookup(&fingerprint).unwrap();

            let mut ciphertext = Vec::new();
            let refused = encrypt(
                std::slice::from_ref(&cert),
                &[],
                None,
                b"meet at noon",
                &mut ciphertext,
            )
            .expect_err("encrypted to a certificate its owner had revoked");

            // The GUI prints this after "Encryption failed: ", and someone who
            // ticked several recipients has to be told which one was refused.
            let message = refused.to_string();
            assert!(
                message.contains(name) && message.contains("revoked"),
                "the refusal must say whose key and why: {message}"
            );
            assert!(
                ciphertext.is_empty(),
                "a refused encryption must write nothing"
            );
        }
    }

    /// Signing, which is the same rule seen from the other side. The shape of a
    /// key generated here is what made it bite: the primary key certifies and a
    /// subkey signs, so a certificate-level revocation leaves a perfectly usable
    /// signing subkey in place. The app said "Signed." while every verifier
    /// holding the revocation — rpgp's own included — called the result bad,
    /// and the only readers who accepted it were the ones with a stale copy of
    /// the certificate, which is exactly who revoking was meant to reach.
    #[test]
    fn refuses_to_sign_with_a_certificate_its_owner_revoked() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        let bob = generate(&KeyGenRequest::new("Bob <bob@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();
        store.insert(&bob).unwrap();
        let fingerprint = alice.fingerprint().to_hex();

        // The default reason, which is soft: past signatures stand, which is
        // precisely why a new one must not be made.
        crate::revoke::revoke_cert(&store, &crate::revoke::RevokeRequest::new(&fingerprint))
            .unwrap();

        // From the secret half, so the local signing subkey is the one on offer
        // and no part of this reaches the user's gpg-agent.
        let alice = store.secret_cert(&fingerprint).unwrap();
        assert!(alice.is_tsk(), "the local secret is what is under test");

        let mut detached = Vec::new();
        let refused = sign_detached(&alice, None, b"the treaty text", &mut detached)
            .expect_err("signed with a certificate its owner had retired");
        let message = refused.to_string();
        assert!(
            message.contains("Alice <alice@example.org>") && message.contains("revoked"),
            "the refusal must say whose key and why: {message}"
        );
        assert!(
            detached.is_empty(),
            "a refused signature must write nothing"
        );

        let mut cleartext = Vec::new();
        assert!(
            sign_cleartext(&alice, None, b"the treaty text", &mut cleartext).is_err(),
            "cleartext signing goes through the same guard"
        );
        assert!(cleartext.is_empty());

        // And the signer inside an encryption, the third caller of that guard.
        // Bob is not revoked, so the recipient half of the operation is sound
        // and only the signer can be what refuses it.
        let mut signed_and_encrypted = Vec::new();
        assert!(
            encrypt(
                std::slice::from_ref(&bob),
                &[],
                Some((&alice, None)),
                b"the treaty text",
                &mut signed_and_encrypted,
            )
            .is_err(),
            "sign-and-encrypt goes through the same guard"
        );
    }

    #[test]
    fn encrypts_to_a_password_alone() {
        let (_dir, store) = scratch_store();

        let mut ciphertext = Vec::new();
        encrypt(
            &[],
            &[Zeroizing::new("hunter2".to_string())],
            None,
            b"no keys involved",
            &mut ciphertext,
        )
        .unwrap();

        let mut plaintext = Vec::new();
        decrypt(&store, &ciphertext, &["hunter2"], &mut plaintext).unwrap();
        assert_eq!(plaintext, b"no keys involved");

        // The wrong password must not open it, and neither must none.
        assert!(decrypt(&store, &ciphertext, &["hunter3"], &mut Vec::new()).is_err());
        assert!(decrypt(&store, &ciphertext, &[], &mut Vec::new()).is_err());
    }

    /// The notepad offers a key passphrase and a message password in separate
    /// boxes and cannot know which one opens a given message, so it hands over
    /// both. Passing only one is what made text encrypted to a password
    /// impossible to read back.
    #[test]
    fn any_of_several_candidate_passwords_opens_a_message() {
        let (_dir, store) = scratch_store();
        let mut request = KeyGenRequest::new("Alice <alice@example.org>");
        request.password = Some("key passphrase".to_string().into());
        let alice = generate(&request).unwrap().cert;
        store.insert_secret(&alice).unwrap();

        // Encrypted to Alice's protected key *and* to a message password.
        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[Zeroizing::new("message password".to_string())],
            None,
            b"either secret opens this",
            &mut ciphertext,
        )
        .unwrap();

        // Whichever order the two are offered in, and with an unrelated one
        // alongside, exactly one of them works and the message opens.
        for candidates in [
            vec!["key passphrase", "message password"],
            vec!["message password", "key passphrase"],
            vec!["hunter2", "message password"],
            vec!["hunter2", "key passphrase"],
        ] {
            let mut plaintext = Vec::new();
            decrypt(&store, &ciphertext, &candidates, &mut plaintext)
                .unwrap_or_else(|e| panic!("{candidates:?}: {e}"));
            assert_eq!(plaintext, b"either secret opens this");
        }

        // And none of them still fails, rather than quietly succeeding.
        assert!(decrypt(&store, &ciphertext, &["hunter2"], &mut Vec::new()).is_err());
        assert!(decrypt(&store, &ciphertext, &[], &mut Vec::new()).is_err());
    }

    #[test]
    fn a_message_can_take_either_a_key_or_a_password() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[Zeroizing::new("shared secret".to_string())],
            None,
            b"either way in",
            &mut ciphertext,
        )
        .unwrap();

        // Alice's key opens it with no password at all.
        let mut by_key = Vec::new();
        decrypt(&store, &ciphertext, &[], &mut by_key).unwrap();
        assert_eq!(by_key, b"either way in");

        // And an empty store with only the password opens the same message.
        let (_other_dir, bare) = scratch_store();
        let mut by_password = Vec::new();
        decrypt(&bare, &ciphertext, &["shared secret"], &mut by_password).unwrap();
        assert_eq!(by_password, b"either way in");
    }

    /// A key generated to RFC 4880, the only kind gpg-agent can hold: GnuPG
    /// 2.4 has no version 6 keys, and sequoia-ipc derives no keygrip for one.
    fn agent_shaped(user_id: &str) -> Cert {
        let mut request = KeyGenRequest::new(user_id);
        request.standard = crate::keygen::Standard::Rfc4880;
        generate(&request).unwrap().cert
    }

    /// `cert`'s encryption keys as the agent would be handed them, the
    /// transport key first, each with its secret half.
    fn encryption_pairs(
        cert: &Cert,
    ) -> Vec<(
        Key<key::PublicParts, key::UnspecifiedRole>,
        sequoia_openpgp::crypto::KeyPair,
    )> {
        let policy = policy();
        let valid = cert.with_policy(&policy, None).unwrap();
        valid
            .keys()
            .for_transport_encryption()
            .chain(valid.keys().for_storage_encryption())
            .map(|ka| {
                let public = ka.key().clone();
                let pair = public
                    .clone()
                    .parts_into_secret()
                    .unwrap()
                    .into_keypair()
                    .unwrap();
                (public, pair)
            })
            .collect()
    }

    /// The agent's listing, for keys held in its own store.
    fn held(keys: &[&Key<key::PublicParts, key::UnspecifiedRole>]) -> Vec<crate::agent::AgentKey> {
        keys.iter()
            .map(|key| crate::agent::AgentKey {
                keygrip: sequoia_ipc::Keygrip::of(key.mpis()).unwrap().to_string(),
                card_serial: None,
            })
            .collect()
    }

    /// Stands in for gpg-agent in [`through_agent`].
    enum StandIn {
        /// It holds the secret half and uses it, whichever packet it is given.
        Holds(sequoia_openpgp::crypto::KeyPair),
        /// It refuses, as it does when the user cancels its prompt.
        Refuses(Key<key::PublicParts, key::UnspecifiedRole>),
        /// An RSA key on a card: the card removes the padding itself, and
        /// turns down with an error a packet that is not its key's.
        Card(sequoia_openpgp::crypto::KeyPair),
    }

    /// What sequoia-gpg-agent 0.6.2 makes of an Assuan ERR line saying
    /// `words`.
    fn agent_error(words: &str) -> anyhow::Error {
        sequoia_gpg_agent::Error::from(sequoia_gpg_agent::assuan::Error::OperationFailed(
            words.into(),
        ))
        .into()
    }

    impl Decryptor for StandIn {
        fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
            match self {
                StandIn::Holds(pair) | StandIn::Card(pair) => pair.public(),
                StandIn::Refuses(key) => key,
            }
        }

        fn decrypt(
            &mut self,
            ciphertext: &Ciphertext,
            plaintext_len: Option<usize>,
        ) -> sequoia_openpgp::Result<SessionKey> {
            match self {
                StandIn::Holds(pair) => pair.decrypt(ciphertext, plaintext_len),
                StandIn::Refuses(_) => Err(agent_error("Operation cancelled <Pinentry>")),
                // The words are the stand-in's; a real card's depend on the
                // card and the language.
                StandIn::Card(pair) => pair
                    .decrypt(ciphertext, plaintext_len)
                    .map_err(|_| agent_error("Bad data <SCD>")),
            }
        }
    }

    /// `D`, counting in `asked` how often it is asked to decrypt: each is a
    /// private-key operation in the agent, and a prompt if one is needed.
    struct Counted<'c, D> {
        agent: D,
        asked: &'c std::cell::Cell<usize>,
    }

    impl<D: Decryptor> Decryptor for Counted<'_, D> {
        fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
            self.agent.public()
        }

        fn decrypt(
            &mut self,
            ciphertext: &Ciphertext,
            plaintext_len: Option<usize>,
        ) -> sequoia_openpgp::Result<SessionKey> {
            self.asked.set(self.asked.get() + 1);
            self.agent.decrypt(ciphertext, plaintext_len)
        }
    }

    /// `cert` with an RSA encryption subkey added, of the smallest size the
    /// standard policy accepts: a larger one takes this build many seconds
    /// to generate.
    fn with_rsa_key(cert: Cert) -> Cert {
        use sequoia_openpgp::cert::{CipherSuite, KeyBuilder};
        use sequoia_openpgp::types::KeyFlags;

        let policy = policy();
        KeyBuilder::new(KeyFlags::empty().set_transport_encryption())
            .set_cipher_suite(CipherSuite::RSA2k)
            .subkey(cert.with_policy(&policy, None).unwrap())
            .unwrap()
            .attach_cert()
            .unwrap()
    }

    /// A packet that names no key, carrying what a packet for another RSA
    /// key of `key`'s size could: a number below `key`'s modulus that was not
    /// made with it.
    fn someone_elses_rsa_packet(key: &Key<key::PublicParts, key::UnspecifiedRole>) -> PKESK {
        let mpi::PublicKey::RSA { n, .. } = key.mpis() else {
            panic!("premise: an RSA key");
        };
        let mut c = vec![0; n.value().len()];
        sequoia_openpgp::crypto::random(&mut c).unwrap();
        c[0] = n.value()[0] >> 1;
        sequoia_openpgp::packet::pkesk::PKESK3::new(
            None,
            key.pk_algo(),
            Ciphertext::RSA {
                c: mpi::MPI::new(&c),
            },
        )
        .unwrap()
        .into()
    }

    /// A session key and a packet wrapping it for `key`, named or hidden.
    fn wrapped_for(
        key: &Key<key::PublicParts, key::UnspecifiedRole>,
        named: bool,
    ) -> (SessionKey, PKESK) {
        let session_key = SessionKey::new(32).unwrap();
        let mut pkesk = sequoia_openpgp::packet::pkesk::PKESK3::for_recipient(
            SymmetricAlgorithm::AES256,
            &session_key,
            key,
        )
        .unwrap();
        if !named {
            pkesk.set_recipient(None);
        }
        (session_key, pkesk.into())
    }

    /// The first refusal from the agent is the answer, and nothing is asked
    /// after it.
    ///
    /// Sequoia's `PKESK::decrypt` turns every error into `None`, so a cancelled
    /// prompt read as a key that did not fit: the next packet the agent held a
    /// key for put the prompt up again, and when nothing was left the user was
    /// told no secret key opened the message.
    #[test]
    fn the_agents_refusal_is_the_answer_and_nothing_is_asked_after_it() {
        let alice = agent_shaped("Alice <alice@example.org>");
        let bob = agent_shaped("Bob <bob@example.org>");
        let (for_alice, _) = encryption_pairs(&alice).remove(0);
        let (for_bob, _) = encryption_pairs(&bob).remove(0);
        let (session_key, first) = wrapped_for(&for_alice, true);
        let (_, second) = wrapped_for(&for_bob, true);
        let pkesks = [first, second];

        let listing = held(&[&for_alice, &for_bob]);
        let attempts =
            crate::agent::decryption_attempts(&pkesks, [&alice, &bob], || listing.clone());
        assert_eq!(attempts.len(), 2, "premise: two keys to ask");

        let asked = std::cell::Cell::new(0);
        let refused = through_agent(
            &attempts,
            None,
            &mut |_, got: &SessionKey| *got == session_key,
            |key| {
                asked.set(asked.get() + 1);
                Ok(StandIn::Refuses(key.clone()))
            },
        )
        .expect_err("a refusal read as a key that did not fit");
        assert_eq!(asked.get(), 1, "the agent was asked again after refusing");
        assert!(
            matches!(&refused, Error::AgentRefused { reason, .. } if reason == "Operation cancelled <Pinentry>"),
            "{refused:?}"
        );
        let message = refused.to_string();
        assert!(
            message.starts_with("gpg-agent: Operation cancelled <Pinentry>")
                && message.contains("Alice <alice@example.org>"),
            "the status line must say what the agent said, first: {message}"
        );

        // An agent that listed its keys and then cannot be reached to build a
        // keypair is answered the same way, and the next key is not tried.
        let asked = std::cell::Cell::new(0);
        let unreachable = through_agent(
            &attempts,
            None,
            &mut |_, got: &SessionKey| *got == session_key,
            |_| -> Result<StandIn> {
                asked.set(asked.get() + 1);
                Err(Error::invalid("no gpg-agent to talk to: it went away"))
            },
        )
        .expect_err("opened with no agent to ask");
        assert_eq!(asked.get(), 1);
        assert!(
            matches!(&unreachable, Error::AgentRefused { reason, .. } if reason == "no gpg-agent to talk to: it went away"),
            "{unreachable:?}"
        );
    }

    /// An RSA key on a card that turns down a packet naming no key does not
    /// end the decryption, and the key's own packet after it is still tried.
    ///
    /// The card removes RSA's padding itself, and so answers a packet made for
    /// another RSA key of its size with an error, where a key in the agent's
    /// own store hands it back to fail quietly on this side. Ending at that
    /// error left a message sent to several hidden RSA recipients unreadable
    /// on the card whenever another's packet came first. The price, when the
    /// error was a cancelled prompt instead, is that the prompt goes up again
    /// for each packet left, and the first refusal is the answer. Everywhere
    /// else the first refusal still ends the decryption.
    #[test]
    fn a_card_turning_down_a_hidden_rsa_packet_goes_on_to_the_next() {
        let alice = with_rsa_key(agent_shaped("Alice <alice@example.org>"));
        let (rsa, pair) = encryption_pairs(&alice)
            .into_iter()
            .find(|(key, _)| matches!(key.mpis(), mpi::PublicKey::RSA { .. }))
            .expect("premise: an RSA key");
        let on_card = |keys: &[&Key<key::PublicParts, key::UnspecifiedRole>]| {
            let mut listing = held(keys);
            for key in &mut listing {
                key.card_serial = Some("D2760001240100000006".into());
            }
            listing
        };
        let (session_key, own) = wrapped_for(&rsa, false);
        let pkesks = [
            someone_elses_rsa_packet(&rsa),
            someone_elses_rsa_packet(&rsa),
            own,
        ];
        let listing = on_card(&[&rsa]);
        let attempts = crate::agent::decryption_attempts(&pkesks, [&alice], || listing.clone());
        assert_eq!(attempts.len(), 3, "premise: every packet fits the key");

        let asked = std::cell::Cell::new(0);
        let opened = through_agent(
            &attempts,
            None,
            &mut |_, got: &SessionKey| *got == session_key,
            |_| {
                Ok(Counted {
                    agent: StandIn::Card(pair.clone()),
                    asked: &asked,
                })
            },
        )
        .unwrap_or_else(|e| panic!("the card's own packet was never tried: {e}"));
        assert_eq!(opened.map(Cert::fingerprint), Some(alice.fingerprint()));
        assert_eq!(asked.get(), 3);

        // A cancelled prompt: asked again for each packet, and then the
        // refusal is the answer rather than that no key opens the message.
        let asked = std::cell::Cell::new(0);
        let refused = through_agent(
            &attempts,
            None,
            &mut |_, got: &SessionKey| *got == session_key,
            |key| {
                Ok(Counted {
                    agent: StandIn::Refuses(key.clone()),
                    asked: &asked,
                })
            },
        )
        .expect_err("opened with every prompt cancelled");
        assert_eq!(asked.get(), 3);
        assert!(
            matches!(&refused, Error::AgentRefused { reason, .. } if reason == "Operation cancelled <Pinentry>"),
            "{refused:?}"
        );

        // The first refusal still ends it for the same key in the agent's
        // own store, for a packet that names the card key, and for a card key
        // that is not RSA.
        let curve = encryption_pairs(&alice)
            .into_iter()
            .map(|(key, _)| key)
            .find(|key| key.fingerprint() != rsa.fingerprint())
            .unwrap();
        let (_, named) = wrapped_for(&rsa, true);
        let cases = [
            (
                "RSA in the agent's store",
                held(&[&rsa]),
                vec![someone_elses_rsa_packet(&rsa), wrapped_for(&rsa, false).1],
            ),
            (
                "a named packet",
                on_card(&[&rsa]),
                vec![named, someone_elses_rsa_packet(&rsa)],
            ),
            (
                "Curve25519 on a card",
                on_card(&[&curve]),
                vec![wrapped_for(&curve, false).1, wrapped_for(&curve, false).1],
            ),
        ];
        for (case, listing, pkesks) in cases {
            let attempts = crate::agent::decryption_attempts(&pkesks, [&alice], || listing.clone());
            assert_eq!(attempts.len(), 2, "{case}: premise: two attempts");
            let asked = std::cell::Cell::new(0);
            let refused = through_agent(&attempts, None, &mut |_, _: &SessionKey| false, |key| {
                Ok(Counted {
                    agent: StandIn::Refuses(key.clone()),
                    asked: &asked,
                })
            })
            .expect_err("opened with the prompt cancelled");
            assert_eq!(asked.get(), 1, "{case}: the prompt went up again");
            assert!(
                matches!(refused, Error::AgentRefused { .. }),
                "{case}: {refused:?}"
            );
        }
    }

    /// A key that does not fit a packet is passed over without a word, and the
    /// next attempt is made; what went wrong with it is not reported, as
    /// Sequoia does not report it, because which check a packet failed says
    /// something about the key to whoever made the packet.
    ///
    /// Either of a certificate's encryption keys opens what was sent to it
    /// through the agent, which a key generated here could not when the agent
    /// held both: the agent was handed the certificate's first.
    #[test]
    fn a_key_that_does_not_fit_is_passed_over_quietly() {
        let alice = agent_shaped("Alice <alice@example.org>");
        let pairs = encryption_pairs(&alice);
        assert_eq!(pairs.len(), 2, "premise: a transport and a storage key");
        let listing = held(&[&pairs[0].0, &pairs[1].0]);
        let stand_in = |key: &Key<key::PublicParts, key::UnspecifiedRole>| {
            let (_, pair) = pairs
                .iter()
                .find(|(public, _)| public.fingerprint() == key.fingerprint())
                .unwrap();
            Ok(StandIn::Holds(pair.clone()))
        };

        // For the storage key and naming none, so the transport key, asked
        // first, does not fit it.
        for (public, _) in &pairs {
            for named in [true, false] {
                let (session_key, pkesk) = wrapped_for(public, named);
                let pkesks = [pkesk];
                let attempts =
                    crate::agent::decryption_attempts(&pkesks, [&alice], || listing.clone());
                let opened = through_agent(
                    &attempts,
                    None,
                    &mut |_, got: &SessionKey| *got == session_key,
                    stand_in,
                )
                .unwrap_or_else(|e| panic!("named: {named}: {e}"));
                assert_eq!(
                    opened.map(Cert::fingerprint),
                    Some(alice.fingerprint()),
                    "named: {named}, for {}",
                    public.fingerprint()
                );
            }
        }

        // A packet neither key fits leaves nothing to report.
        let stranger = agent_shaped("Stranger <stranger@example.org>");
        let (for_stranger, _) = encryption_pairs(&stranger).remove(0);
        let (session_key, pkesk) = wrapped_for(&for_stranger, false);
        let pkesks = [pkesk];
        let attempts = crate::agent::decryption_attempts(&pkesks, [&alice], || listing.clone());
        assert_eq!(attempts.len(), 2, "premise: both keys are asked");
        let opened = through_agent(
            &attempts,
            None,
            &mut |_, got: &SessionKey| *got == session_key,
            stand_in,
        )
        .expect("a key that did not fit was reported as the agent refusing");
        assert!(opened.is_none());
    }

    /// A message for a passphrase-protected key held here says so when the key
    /// was left locked, rather than that no secret key opens it.
    ///
    /// Only for a key a packet names. A packet that names none could be for
    /// anybody, and asking for the passphrase of a key on account of a message
    /// meant for someone else would ask for one that can never work.
    #[test]
    fn a_protected_key_left_locked_is_named_rather_than_missing() {
        let (_dir, store) = scratch_store();
        let mut request = KeyGenRequest::new("Alice <alice@example.org>");
        request.password = Some("correct horse".to_string().into());
        let alice = generate(&request).unwrap().cert;
        store.insert_secret(&alice).unwrap();

        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"for Alice",
            &mut ciphertext,
        )
        .unwrap();

        for (candidates, tried) in [(vec![], false), (vec!["hunter2"], true)] {
            let refused = decrypt(&store, &ciphertext, &candidates, &mut Vec::new())
                .expect_err("opened without the passphrase");
            assert!(
                matches!(&refused, Error::KeyLocked { name, tried: t, or_password: false } if name == "Alice <alice@example.org>" && *t == tried),
                "{candidates:?}: {refused:?}"
            );
        }
        let message = decrypt(&store, &ciphertext, &[], &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(
            message.contains("passphrase-protected") && message.contains("enter its passphrase"),
            "{message}"
        );
        let message = decrypt(&store, &ciphertext, &["hunter2"], &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(message.contains("does not unlock it"), "{message}");

        let mut plaintext = Vec::new();
        decrypt(&store, &ciphertext, &["correct horse"], &mut plaintext).unwrap();
        assert_eq!(plaintext, b"for Alice");

        // The same key, behind a packet that names no one.
        let policy = policy();
        let valid = alice.with_policy(&policy, None).unwrap();
        let hidden: Vec<Recipient> = valid
            .keys()
            .for_transport_encryption()
            .map(|ka| {
                use sequoia_openpgp::cert::Preferences;
                Recipient::new(valid.features(), None, ka.key())
            })
            .collect();
        let mut ciphertext = Vec::new();
        {
            let message = Message::new(&mut ciphertext);
            let message = Encryptor::for_recipients(message, hidden).build().unwrap();
            let mut message = LiteralWriter::new(message).build().unwrap();
            message.write_all(b"for someone").unwrap();
            message.finalize().unwrap();
        }
        let refused = decrypt(&store, &ciphertext, &[], &mut Vec::new())
            .expect_err("opened without the passphrase");
        assert!(
            !matches!(refused, Error::KeyLocked { .. }),
            "asked for the passphrase of a key the message does not name: {refused}"
        );
    }

    /// A message for a locked key here and for a password as well says that
    /// either would open it, or that what was entered opened neither, rather
    /// than speaking of the key alone: Decrypt / Verify has one field for
    /// both, and what was entered may have been meant as the password.
    ///
    /// Not where the password's envelope was passed over as too dear to
    /// derive, since what was entered was then never tried as the password.
    #[test]
    fn a_locked_key_beside_a_password_is_named_with_it() {
        let (_dir, store) = scratch_store();
        let mut request = KeyGenRequest::new("Alice <alice@example.org>");
        request.password = Some("correct horse".to_string().into());
        let alice = generate(&request).unwrap().cert;
        store.insert_secret(&alice).unwrap();

        let password = Zeroizing::new("open sesame".to_string());
        let mut ciphertext = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            std::slice::from_ref(&password),
            None,
            b"for Alice, or the password",
            &mut ciphertext,
        )
        .unwrap();

        for (candidates, tried, says) in [
            (
                vec![],
                false,
                "enter the key's passphrase or the message's password",
            ),
            (
                vec!["hunter2"],
                true,
                "neither unlocks the key nor opens the message",
            ),
        ] {
            let refused = decrypt(&store, &ciphertext, &candidates, &mut Vec::new())
                .expect_err("opened with neither");
            assert!(
                matches!(&refused, Error::KeyLocked { name, tried: t, or_password: true } if name == "Alice <alice@example.org>" && *t == tried),
                "{candidates:?}: {refused:?}"
            );
            assert!(refused.to_string().contains(says), "{refused}");
        }
        let mut plaintext = Vec::new();
        decrypt(&store, &ciphertext, &["open sesame"], &mut plaintext).unwrap();
        assert_eq!(plaintext, b"for Alice, or the password");

        // The same key, beside an envelope asking for 16 MiB hashed 255 times
        // over, which is declined before anything is derived.
        let mut for_alice = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"for Alice",
            &mut for_alice,
        )
        .unwrap();
        let priced: Vec<Packet> = std::iter::once(Packet::from(
            SKESK4::new(
                SymmetricAlgorithm::AES256,
                S2K::Argon2 {
                    salt: [0u8; 16],
                    t: 255,
                    p: 4,
                    m: 14,
                },
                None,
            )
            .unwrap(),
        ))
        .chain(PacketPile::from_bytes(&for_alice).unwrap().into_children())
        .collect();
        let refused = decrypt(
            &store,
            &packet_bytes(&priced),
            &["hunter2"],
            &mut Vec::new(),
        )
        .expect_err("opened with neither");
        assert!(
            matches!(
                &refused,
                Error::KeyLocked {
                    tried: true,
                    or_password: false,
                    ..
                }
            ),
            "said the password was tried against an envelope it never was: {refused:?}"
        );
    }

    /// A message nothing here could open is not taken to the agent: one
    /// encrypted to a password alone, tried with the wrong one, and one for a
    /// key the store does not have. Each used to ask the agent for its
    /// listing, which on a machine with GnuPG starts an agent if none is
    /// running. One for a key the store does have asks it once.
    #[test]
    fn a_message_nothing_here_could_open_is_not_taken_to_the_agent() {
        let (_dir, store) = scratch_store();
        let alice = agent_shaped("Alice <alice@example.org>");
        let stranger = agent_shaped("Stranger <stranger@example.org>");
        store.insert(&alice).unwrap();
        let connects = || crate::agent::CONNECTS.with(std::cell::Cell::get);

        let mut for_a_password = Vec::new();
        encrypt(
            &[],
            &[Zeroizing::new("hunter2".to_string())],
            None,
            b"no keys involved",
            &mut for_a_password,
        )
        .unwrap();
        let mut for_a_stranger = Vec::new();
        encrypt(
            std::slice::from_ref(&stranger),
            &[],
            None,
            b"not for us",
            &mut for_a_stranger,
        )
        .unwrap();
        let mut for_alice = Vec::new();
        encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"for a key only the agent could hold",
            &mut for_alice,
        )
        .unwrap();

        let before = connects();
        assert!(decrypt(&store, &for_a_password, &["hunter3"], &mut Vec::new()).is_err());
        assert_eq!(connects(), before, "a wrong password went to the agent");
        assert!(decrypt(&store, &for_a_stranger, &[], &mut Vec::new()).is_err());
        assert_eq!(connects(), before, "a stranger's message went to the agent");

        let refused = decrypt(&store, &for_alice, &[], &mut Vec::new()).unwrap_err();
        assert_eq!(connects(), before + 1, "the agent is asked once");
        assert!(
            refused.to_string().contains("no secret key"),
            "an agent that answers nothing leaves the usual message: {refused}"
        );
    }

    #[test]
    fn refuses_a_message_addressed_to_nobody() {
        assert!(encrypt(&[], &[], None, b"x", Vec::new()).is_err());
        assert!(
            encrypt(
                &[],
                &[Zeroizing::new(String::new())],
                None,
                b"x",
                Vec::new()
            )
            .is_err()
        );
    }

    #[test]
    fn cleartext_signature_keeps_the_text_readable() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut signed = Vec::new();
        sign_cleartext(&alice, None, b"the meeting is at noon", &mut signed).unwrap();

        // The point of cleartext: a reader who has no OpenPGP tools can still
        // read it.
        assert!(signed.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----"));
        assert!(
            String::from_utf8_lossy(&signed).contains("the meeting is at noon"),
            "the text should stay legible"
        );

        let (text, result) = verify_inline(&store, &signed).unwrap();
        assert_eq!(text, b"the meeting is at noon");
        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        assert_eq!(result.signatures[0].signer, "Alice <alice@example.org>");
    }

    #[test]
    fn detached_signature_round_trip() {
        let (_dir, store) = scratch_store();
        let alice = generate(&KeyGenRequest::new("Alice <alice@example.org>"))
            .unwrap()
            .cert;
        store.insert_secret(&alice).unwrap();

        let mut signature = Vec::new();
        sign_detached(&alice, None, b"minutes of the meeting", &mut signature).unwrap();

        let good = verify_detached(&store, &signature, b"minutes of the meeting").unwrap();
        assert!(good.all_good());

        let tampered = verify_detached(&store, &signature, b"minutes of the meating");
        assert!(tampered.is_err() || !tampered.unwrap().all_good());
    }

    /// A genuine signature still verifies when another certificate in the
    /// store carries the subkey that made it.
    ///
    /// A signature's issuer names the key that signed, which for every key
    /// this app generates is a subkey — and a subkey can hang off more than
    /// one certificate. Mallory needs no secret of Alice's to arrange that:
    /// her public subkey plus a binding claiming encryption, which carries no
    /// primary-key back-signature, makes a certificate of his own answer to
    /// her issuer. Candidates come back sorted by certificate fingerprint, so
    /// drawing his from below hers makes his the one a single-certificate
    /// resolution picks, and Alice's the one the verifier never sees. Give
    /// `get_certs` back its old `lookup` and this fails: the signature is
    /// reported bad, "key is not signing capable", for as long as his
    /// certificate is in the store.
    #[test]
    fn a_signature_verifies_though_another_certificate_carries_the_subkey() {
        use sequoia_openpgp::packet::signature::SignatureBuilder;
        use sequoia_openpgp::types::{KeyFlags, SignatureType};

        let (_dir, store) = scratch_store();
        // Alice from the upper half of the fingerprint space and Mallory from
        // the lower, so his sorts first whatever hers turns out to be. Drawing
        // Mallory until he merely sorts below a fixed Alice runs out whenever
        // hers lands near the bottom, which over 64 draws is one run in
        // sixty-five. Each draw here takes two tries on average; the bound
        // only stops a hang if key generation ever stopped being random.
        let alice = (0..64)
            .map(|_| {
                generate(&KeyGenRequest::new("Alice <alice@example.org>"))
                    .unwrap()
                    .cert
            })
            .find(|cert| cert.fingerprint().as_bytes()[0] >= 0x80)
            .expect("64 generated keys all sorted into the lower half");
        store.insert(&alice).unwrap();

        let mut signature = Vec::new();
        sign_detached(&alice, None, b"minutes of the meeting", &mut signature).unwrap();
        assert!(
            verify_detached(&store, &signature, b"minutes of the meeting")
                .unwrap()
                .all_good(),
            "the signature is good before Mallory's certificate arrives"
        );

        // The subkey that signed. It is Alice's public key and nothing more,
        // which is all Mallory needs.
        let signing = alice
            .keys()
            .with_policy(&policy(), None)
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .expect("a generated key signs with a subkey")
            .key()
            .clone()
            .role_into_subordinate();

        // Mallory, from the lower half of the fingerprint space, so his
        // primary fingerprint sorts below Alice's.
        let mallory = (0..64)
            .map(|_| {
                generate(&KeyGenRequest::new("Mallory <mallory@example.org>"))
                    .unwrap()
                    .cert
            })
            .find(|cert| cert.fingerprint().as_bytes()[0] < 0x80)
            .expect("64 generated keys all sorted into the upper half");
        let mut signer = mallory
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let binding = signing
            .bind(
                &mut signer,
                &mallory,
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_key_flags(KeyFlags::empty().set_transport_encryption())
                    .unwrap(),
            )
            .unwrap();
        let mallory = mallory
            .insert_packets(vec![Packet::from(signing.clone()), binding.into()])
            .unwrap()
            .0;
        store.insert(&mallory).unwrap();

        assert_eq!(
            store
                .lookup(&signing.fingerprint().to_hex())
                .unwrap()
                .fingerprint(),
            mallory.fingerprint(),
            "resolving the issuer to one certificate really does answer with Mallory's"
        );

        let result = verify_detached(&store, &signature, b"minutes of the meeting").unwrap();
        assert!(
            result.all_good(),
            "Alice's certificate has to reach the verifier as well: {:?}",
            result.signatures
        );
        assert_eq!(
            result.signatures[0].fingerprint.as_deref(),
            Some(alice.fingerprint().to_hex().as_str()),
            "and the signature is still attributed to Alice"
        );
    }
}
