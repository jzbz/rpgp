//! Message operations: encrypt, decrypt, sign, verify.

use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use sequoia_openpgp::crypto::{Password, SessionKey};
use sequoia_openpgp::packet::{PKESK, SKESK};
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
pub fn encrypt(
    recipients: &[Cert],
    passwords: &[String],
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
    passwords: &[String],
    signer: Option<(&Cert, Option<&str>)>,
    source: &mut dyn Read,
    sink: impl Write + Send + Sync,
) -> Result<()> {
    let passwords: Vec<&String> = passwords.iter().filter(|p| !p.is_empty()).collect();
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
        let valid = cert
            .with_policy(&policy, None)
            .map_err(|_| Error::NoEncryptionKey(cert.fingerprint().to_hex()))?;
        let before = recipient_keys.len();
        for ka in valid
            .keys()
            .alive()
            .revoked(false)
            .supported()
            .for_transport_encryption()
        {
            recipient_keys.push(Recipient::from(ka));
        }
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

/// The most plaintext [`decrypt_to_memory`] will hand back.
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
    let policy = policy();
    let helper = Helper::new(store, passwords);

    let mut decryptor =
        DecryptorBuilder::from_reader(source)?.with_policy(&policy, None, helper)?;
    std::io::copy(&mut decryptor, &mut sink).map_err(|e| Error::io("decrypting message", e))?;

    let helper = decryptor.into_helper();
    Ok(VerifyResult {
        signatures: helper.signatures,
        encrypted: helper.encrypted,
        decrypted_with: helper.decrypted_with,
    })
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
    message.write_all(data)?;
    message.finalize()?;
    Ok(())
}

/// Verify a message that carries its own text: cleartext-signed, or signed and
/// wrapped. Returns the text alongside the verdict.
pub fn verify_inline(store: &Store, signed: &[u8]) -> Result<(Vec<u8>, VerifyResult)> {
    let policy = policy();
    let helper = Helper::new(store, &[]);

    let mut verifier = VerifierBuilder::from_bytes(signed)?.with_policy(&policy, None, helper)?;
    let mut text = Vec::new();
    std::io::copy(&mut verifier, &mut text).map_err(|e| Error::io("verifying message", e))?;

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
    let policy = policy();
    let helper = Helper::new(store, &[]);

    let mut verifier =
        DetachedVerifierBuilder::from_bytes(signature)?.with_policy(&policy, None, helper)?;
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
fn signing_keypair(
    cert: &Cert,
    password: Option<&str>,
) -> Result<Box<dyn sequoia_openpgp::crypto::Signer + Send + Sync>> {
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
}

impl<'a> Helper<'a> {
    fn new(store: &'a Store, passwords: &[&str]) -> Self {
        Helper {
            store,
            passwords: passwords
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| Zeroizing::new((*p).to_owned()))
                .collect(),
            signatures: Vec::new(),
            decrypted_with: None,
            encrypted: false,
        }
    }
}

impl VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> anyhow::Result<Vec<Cert>> {
        // A signer we do not have is not an error here: it surfaces as a
        // MissingKey verification error in `check`, which is a better message
        // than aborting the whole read.
        Ok(ids
            .iter()
            .filter_map(|id| self.store.lookup(&id.to_string()).ok())
            .collect())
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
                        let summary = crate::CertSummary::from_cert(good.ka.cert());
                        SignatureReport {
                            good: true,
                            signer: summary.primary_user_id.clone(),
                            fingerprint: Some(summary.fingerprint),
                            detail: String::new(),
                        }
                    }
                    Err(err) => SignatureReport {
                        good: false,
                        signer: "unknown".to_string(),
                        fingerprint: None,
                        detail: format!("{err}"),
                    },
                });
            }
        }
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
        // per (packet × password), which a v6 Argon2 SKESK can make arbitrarily
        // expensive. Nothing in sequoia bounds the count, so a padded message
        // is a decrypt-side amplifier: 128 wildcard packets in a 14 KB file
        // pinned a core for ~9s, and the message still decrypted, so nothing
        // looked wrong. 256 is a chosen ceiling, not a constant of nature: it
        // is far above any real recipient list and keeps the residual worst
        // case in seconds.
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
        for candidate in &self.passwords {
            let password = Password::from(candidate.as_str());
            for skesk in skesks {
                if let Ok((algo, session_key)) = skesk.decrypt(&password)
                    && decrypt(algo, &session_key)
                {
                    return Ok(None);
                }
            }
        }

        // Nothing local fits. The message may be for a card key, whose secret
        // half exists only on the card — ask the agent, which will raise its
        // own PIN prompt if the card needs one.
        // Read the store once, not once per recipient: certs() parses every
        // certificate it returns, and a message to several people would
        // otherwise re-parse the whole store for each of them.
        let candidates = self.store.certs()?;

        // The agent's key list, fetched once. decryptor_for connects and
        // enumerates on every call, and the loop below runs it for every
        // (packet x certificate) pair — so a message no local key opened paid a
        // round trip per combination to re-fetch a list that cannot change
        // during one decrypt. An unreachable agent is not an error here: it
        // means there is nothing on a card to try, and the loop falls through
        // to the same "nothing opens this" it would have reached anyway.
        let held = crate::agent::keys().unwrap_or_default();

        for pkesk in pkesks {
            for cert in &candidates {
                let Ok(valid) = cert.with_policy(&policy, None) else {
                    continue;
                };
                // Same permissive rule as the local path above: a card key
                // that has since been revoked must still open what it
                // encrypted while it was current.
                let matches = valid
                    .keys()
                    .for_transport_encryption()
                    .chain(valid.keys().for_storage_encryption())
                    .any(|ka| {
                        pkesk
                            .recipient()
                            .is_none_or(|handle| handle.aliases(ka.key().key_handle()))
                    });
                if !matches {
                    continue;
                }

                let Ok(mut pair) = crate::agent::decryptor_for_with(cert, &held) else {
                    continue;
                };
                if pkesk
                    .decrypt(&mut pair, sym_algo)
                    .is_some_and(|(algo, session_key)| decrypt(algo, &session_key))
                {
                    self.decrypted_with = Some(cert.fingerprint().to_hex());
                    // The one place a caller genuinely needs an owned Cert:
                    // DecryptionHelper returns it by value. Exactly one clone,
                    // of the certificate that opened the message.
                    return Ok(Some((**cert).clone()));
                }
            }
        }

        Err(anyhow::anyhow!(
            "no secret key, and no password, opens this message"
        ))
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
/// Every output path here is derived from the input rather than chosen by the
/// user, so without this an operation silently destroys an unrelated file that
/// happens to sit at the derived name: decrypting `notes.txt.asc` next to a
/// `notes.txt` you wrote yourself overwrites your notes. Deriving a free name
/// is quieter than a prompt and loses nothing, since the result is reported.
///
/// Best-effort, and deliberately so: it picks a pleasant name, it does not
/// enforce the rule. The name can be taken between the check and the write,
/// and after 999 collisions the series is exhausted and the original path
/// comes back — which is why the three places that actually destroy data
/// (`File::create_new` for the staging file, and the `output.exists()` guards
/// before the renames and the detached-signature write) refuse rather than
/// trust the name they were handed.
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

pub fn encrypt_file(
    recipients: &[Cert],
    passwords: &[String],
    signer: Option<(&Cert, Option<&str>)>,
    input: &Path,
    output: &Path,
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
    // Staged exactly as decrypt_file stages, free_name included: the naive
    // `output.with_extension("part")` turned notes.txt.asc into notes.part and
    // truncated a file the user may well own, which is what free_name and
    // append_extension exist to prevent.
    let mut source =
        fs::File::open(input).map_err(|e| Error::io(format!("reading {}", input.display()), e))?;
    let staging = free_name(append_extension(output, "part"));
    {
        let file = fs::File::create_new(&staging)
            .map_err(|e| Error::io(format!("writing {}", staging.display()), e))?;
        let mut sink = BufWriter::new(file);
        match encrypt_stream(recipients, passwords, signer, &mut source, &mut sink) {
            Ok(()) => sink
                .flush()
                .map_err(|e| Error::io(format!("writing {}", staging.display()), e))?,
            Err(e) => {
                let _ = fs::remove_file(&staging);
                return Err(e);
            }
        }
    }
    if output.exists() {
        let _ = fs::remove_file(&staging);
        return Err(Error::invalid(format!(
            "{} already exists",
            output.display()
        )));
    }
    fs::rename(&staging, output)
        .map_err(|e| Error::io(format!("writing {}", output.display()), e))?;
    Ok(())
}

pub fn sign_detached_file(
    signer: &Cert,
    password: Option<&str>,
    input: &Path,
    output: &Path,
) -> Result<()> {
    // Only the signature is held — a few hundred bytes — so peak memory does
    // not follow the size of the file being signed.
    let mut source =
        fs::File::open(input).map_err(|e| Error::io(format!("reading {}", input.display()), e))?;
    let mut signature = Vec::new();
    sign_detached_stream(signer, password, &mut source, &mut signature)?;
    if output.exists() {
        return Err(Error::invalid(format!(
            "{} already exists",
            output.display()
        )));
    }
    write(output, &signature)
}

pub fn decrypt_file(
    store: &Store,
    input: &Path,
    passwords: &[&str],
    output: &Path,
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
    // problem, and a partial temp file is removed.
    // Appended rather than substituted, and routed through free_name: the old
    // `output.with_extension("part")` turned notes.txt into notes.part — a name
    // a user may well own — and this path truncates that file on create, then
    // renames it away on success or unlinks it on failure. free_name is the
    // same rule decrypted_name already applies to the output; the staging file
    // had simply been left out of it.
    let staging = free_name(append_extension(output, "part"));
    let result = {
        let file = fs::File::create_new(&staging)
            .map_err(|e| Error::io(format!("writing {}", staging.display()), e))?;
        let mut sink = BufWriter::new(file);
        match decrypt_stream(store, source, passwords, &mut sink) {
            Ok(result) => {
                sink.flush()
                    .map_err(|e| Error::io(format!("writing {}", staging.display()), e))?;
                result
            }
            Err(e) => {
                let _ = fs::remove_file(&staging);
                return Err(e);
            }
        }
    };
    if output.exists() {
        let _ = fs::remove_file(&staging);
        return Err(Error::invalid(format!(
            "{} already exists",
            output.display()
        )));
    }
    fs::rename(&staging, output)
        .map_err(|e| Error::io(format!("writing {}", output.display()), e))?;
    Ok(result)
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
    // verify_file reaches the same verdict as verify_bytes; this writes
    // nothing, so there is no output to keep intact.
    let policy = policy();
    let helper = Helper::new(store, &[]);
    let mut verifier =
        DetachedVerifierBuilder::from_bytes(&signature)?.with_policy(&policy, None, helper)?;
    verifier.verify_file(data_path)?;

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

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).map_err(|e| Error::io(format!("writing {}", path.display()), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::{KeyGenRequest, generate};

    fn scratch_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        (dir, store)
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
        decrypt_file(&store, &input, &[], &output).unwrap();
        assert_eq!(std::fs::metadata(&output).unwrap().len(), bulk.len() as u64);

        // A failure leaves neither the output nor the staging file.
        let bad = dir.path().join("bad.pgp");
        std::fs::write(&bad, b"-----BEGIN PGP MESSAGE-----\nnonsense\n").unwrap();
        let out = dir.path().join("bad.out");
        assert!(decrypt_file(&store, &bad, &[], &out).is_err());
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

        encrypt_file(std::slice::from_ref(&alice), &[], None, &input, &output).unwrap();

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
        std::fs::write(&output, b"PRECIOUS").unwrap();
        assert!(
            encrypt_file(
                std::slice::from_ref(&alice),
                &[],
                Some((&alice, Some("wrong"))),
                &input,
                &output
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
        decrypt_file(&store, &input, &[], &output).unwrap();

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
        )
        .unwrap();

        let decrypted = dir.path().join("out.txt");
        let result = decrypt_file(&store, &encrypted, &[], &decrypted).unwrap();

        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        assert_eq!(
            std::fs::read(&decrypted).unwrap(),
            b"the coordinates are in the second envelope"
        );

        let signature = signature_name(&input);
        sign_detached_file(&alice, None, &input, &signature).unwrap();
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
        assert!(sign_detached_file(&alice, Some("wrong"), &input, &output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"PRECIOUS EARLIER OUTPUT");

        // Likewise sign-and-encrypt with a wrong signing passphrase.
        assert!(
            encrypt_file(
                std::slice::from_ref(&alice),
                &[],
                Some((&alice, Some("wrong"))),
                &input,
                &output
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&output).unwrap(), b"PRECIOUS EARLIER OUTPUT");

        // And a nonexistent input, the other easy way to fail.
        assert!(encrypt_file(&[alice], &[], None, &dir.path().join("nope"), &output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"PRECIOUS EARLIER OUTPUT");
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
        )
        .unwrap();

        let output = dir.path().join("out.txt");
        assert!(decrypt_file(&store, &encrypted, &[], &output).is_err());
        assert!(
            !output.exists(),
            "a failed decryption must not create the output file"
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

    #[test]
    fn encrypts_to_a_password_alone() {
        let (_dir, store) = scratch_store();

        let mut ciphertext = Vec::new();
        encrypt(
            &[],
            &["hunter2".to_string()],
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
            &["message password".to_string()],
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
            &["shared secret".to_string()],
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

    #[test]
    fn refuses_a_message_addressed_to_nobody() {
        assert!(encrypt(&[], &[], None, b"x", Vec::new()).is_err());
        assert!(encrypt(&[], &[String::new()], None, b"x", Vec::new()).is_err());
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
}
