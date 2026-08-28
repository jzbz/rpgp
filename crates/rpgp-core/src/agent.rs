//! Reaching keys held by the user's `gpg-agent`, including smartcard keys.
//!
//! This is the only workable route to a YubiKey on a machine that has GnuPG
//! set up. `scdaemon` claims the card reader with an exclusive PC/SC
//! transaction, so a second process asking the reader directly gets
//! `SCARD_E_SHARING_VIOLATION` — shared *and* exclusive modes both fail. Going
//! through the agent sidesteps the fight entirely.
//!
//! It also keeps rpgp out of the PIN business: the agent runs the user's own
//! `pinentry`, so the passphrase or card PIN never passes through this process.
//!
//! `sequoia-gpg-agent` is async and the rest of this crate is not, so calls are
//! driven on a small dedicated runtime created once per process.

use std::collections::HashMap;
use std::sync::OnceLock;

use sequoia_gpg_agent::Agent;
use sequoia_ipc::Keygrip;
use sequoia_openpgp::Cert;
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use tokio::runtime::Runtime;

use crate::error::{Error, Result};

/// A secret key the agent can use on our behalf.
#[derive(Debug, Clone)]
pub struct AgentKey {
    /// GnuPG's identifier for the key. Not an OpenPGP fingerprint: it is a
    /// hash of the public key parameters, and is how the agent is addressed.
    pub keygrip: String,
    /// Serial number of the smartcard holding the key, when it is on one.
    /// `None` means the key material is a file in the agent's store.
    pub card_serial: Option<String>,
}

impl AgentKey {
    pub fn is_on_card(&self) -> bool {
        self.card_serial.is_some()
    }
}

/// The runtime the agent calls are driven on.
///
/// One per process, built lazily: most runs of rpgp never touch the agent, and
/// spinning up a runtime for them would be waste.
fn runtime() -> Result<&'static Runtime> {
    static RUNTIME: OnceLock<std::result::Result<Runtime, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| Error::invalid(format!("cannot start the agent runtime: {e}")))
}

/// How long the app will wait for the agent to answer a question that needs
/// no human — connecting, listing keys.
///
/// The prompt paths (signing, decrypting, certifying) are deliberately *not*
/// held to this: a PIN entry can legitimately take a minute. But enumeration
/// is called from the reload path, and an agent that has hung, or a socket
/// left behind by one that died, used to hang the whole application with it.
const ENUMERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn connect() -> Result<Agent> {
    runtime()?.block_on(async {
        // No pinentry context is set here, deliberately. This connection only
        // ever lists keys and is dropped before any crypto runs; the prompting
        // paths open their own connection and send their own options, built by
        // sequoia-gpg-agent from GPG_TTY, TERM, DISPLAY and friends
        // (sequoia-gpg-agent 0.6.2 KeyPair::sign_async / decrypt_async).
        // Assuan options are per-connection state, so anything set here could
        // never have reached a prompt — it only cost three round trips on
        // every connect, which annotate and every crypto operation make.
        let agent = tokio::time::timeout(ENUMERATION_TIMEOUT, Agent::connect_to_default())
            .await
            .map_err(|_| Error::invalid("gpg-agent did not answer in time"))?
            .map_err(|e| Error::invalid(format!("no gpg-agent to talk to: {e}")))?;
        Ok(agent)
    })
}

/// Whether a gpg-agent is reachable at all.
///
/// Not currently called by the GUI, which reaches the agent through
/// [`annotate`] and the fallbacks in `ops` instead and lets each of those fail
/// on its own. The earlier note here claimed the UI used this to decide whether
/// to offer card-backed keys; no such gate was ever built, and a reader tracing
/// how card keys reach the interface was sent somewhere nothing calls.
///
/// Kept because it is the cheap reachability probe the tests below use, and the
/// obvious primitive if that gate is ever wanted.
pub fn available() -> bool {
    connect().is_ok()
}

/// Every key the agent holds.
pub fn keys() -> Result<Vec<AgentKey>> {
    let mut agent = connect()?;
    runtime()?.block_on(async {
        let listing = tokio::time::timeout(ENUMERATION_TIMEOUT, agent.list_keys())
            .await
            .map_err(|_| Error::invalid("gpg-agent did not list its keys in time"))?
            .map_err(|e| Error::invalid(format!("the agent would not list its keys: {e}")))?;

        Ok(listing
            .iter()
            .map(|info| AgentKey {
                keygrip: info.keygrip().to_string(),
                card_serial: info.serialno().map(str::to_owned),
            })
            .collect())
    })
}

/// Only the keys that live on a smartcard.
///
/// Like [`available`], not on a GUI path today: the list pane gets its card
/// badges from [`annotate`], which answers for the whole store in one round
/// trip. This is the single-question form, used by the tests.
pub fn card_keys() -> Result<Vec<AgentKey>> {
    Ok(keys()?.into_iter().filter(AgentKey::is_on_card).collect())
}

/// A signer backed by the agent, for a public key the agent has the secret
/// half of.
///
/// The agent finds the secret half by keygrip, so only the public key is
/// needed here. Any PIN or passphrase prompt happens in the user's pinentry
/// while this call blocks.
pub fn signer(key: &Key<PublicParts, UnspecifiedRole>) -> Result<sequoia_gpg_agent::KeyPair> {
    let agent = connect()?;
    // Only connecting is async. The returned KeyPair implements Sequoia's
    // Signer and Decryptor synchronously, so it drops straight into the
    // existing stream builders with no runtime in sight.
    agent
        .keypair(key)
        .map_err(|e| Error::invalid(format!("the agent cannot use this key: {e}")))
}

/// Whether the agent can act for any signing-capable key of `cert`, and if so
/// which smartcard — if any — it is on.
///
/// Matching is by keygrip, which is what the agent indexes by, so a
/// certificate imported from anywhere lines up with the agent's copy of its
/// secret without the two ever having been introduced.
pub fn holds_signing_key(cert: &Cert) -> Result<Option<AgentKey>> {
    let held = keys()?;
    let policy = crate::policy();
    let Ok(valid) = cert.with_policy(&policy, None) else {
        return Ok(None);
    };

    for ka in valid.keys().alive().revoked(false).for_signing() {
        let Ok(grip) = Keygrip::of(ka.key().mpis()) else {
            continue;
        };
        let grip = grip.to_string();
        if let Some(found) = held.iter().find(|k| k.keygrip.eq_ignore_ascii_case(&grip)) {
            return Ok(Some(found.clone()));
        }
    }
    Ok(None)
}

/// Match a whole set of certificates against the agent in one round trip.
///
/// Returns fingerprint -> the agent key backing it. Per-certificate lookups
/// would re-connect and re-list for every row in the list; the store is read
/// wholesale, so this is too.
pub fn annotate<C>(certs: &[C]) -> HashMap<String, AgentKey>
where
    C: std::ops::Deref<Target = Cert>,
{
    let mut found = HashMap::new();
    let Ok(held) = keys() else {
        return found;
    };
    // An agent that answers but holds nothing — a fresh GnuPG install, or a
    // machine whose secrets live only here — makes every match below fail, so
    // the policy walk and the keygrip of every signing key would rebuild the
    // empty map we already have.
    if held.is_empty() {
        return found;
    }
    let policy = crate::policy();

    for cert in certs {
        let Ok(valid) = cert.with_policy(&policy, None) else {
            continue;
        };
        for ka in valid.keys().alive().revoked(false).for_signing() {
            let Ok(grip) = Keygrip::of(ka.key().mpis()) else {
                continue;
            };
            let grip = grip.to_string();
            if let Some(key) = held.iter().find(|k| k.keygrip.eq_ignore_ascii_case(&grip)) {
                // A card-held key wins over a file-held one for the same cert.
                let better = found
                    .get(&cert.fingerprint().to_hex())
                    .is_none_or(|existing: &AgentKey| !existing.is_on_card());
                if better {
                    found.insert(cert.fingerprint().to_hex(), key.clone());
                }
            }
        }
    }
    found
}

/// A certification key for `cert`, backed by the agent.
///
/// Certifying uses a different capability from signing messages, so this
/// cannot share `signer_for`: on most certificates the certification key is
/// the primary key and the signing key is a subkey.
pub fn certifier_for(cert: &Cert) -> Result<sequoia_gpg_agent::KeyPair> {
    keypair_for(cert, Purpose::Certify)
}

/// A decryptor for `cert`, backed by the agent. The returned `KeyPair`
/// implements Sequoia's `Decryptor` as well as `Signer`.
pub fn decryptor_for(cert: &Cert) -> Result<sequoia_gpg_agent::KeyPair> {
    keypair_for(cert, Purpose::Decrypt)
}

/// [`decryptor_for`] against a key listing the caller already fetched with
/// [`keys`], for callers walking many certificates in one operation.
pub fn decryptor_for_with(cert: &Cert, held: &[AgentKey]) -> Result<sequoia_gpg_agent::KeyPair> {
    keypair_for_with(cert, Purpose::Decrypt, held)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Sign,
    Certify,
    Decrypt,
}

/// A signer for `cert`, backed by the agent.
///
/// Prefers a key the agent reports as being on a smartcard, so a certificate
/// whose secret exists both on a card and in a file signs on the card.
pub fn signer_for(cert: &Cert) -> Result<sequoia_gpg_agent::KeyPair> {
    keypair_for(cert, Purpose::Sign)
}

fn keypair_for(cert: &Cert, purpose: Purpose) -> Result<sequoia_gpg_agent::KeyPair> {
    keypair_for_with(cert, purpose, &keys()?)
}

/// [`keypair_for`] against a key listing the caller already has.
///
/// Every one of these calls connects to the agent and enumerates its keys, and
/// the decrypt fallback in `ops` runs it inside a loop over (packet x
/// certificate) — so a message that no local key opens paid a round trip per
/// combination to re-fetch a list that does not change during one operation.
/// Splitting the listing out lets that loop fetch it once.
///
/// This does not move any PIN prompt: the agent asks when the returned keypair
/// is *used*, not when it is built.
fn keypair_for_with(
    cert: &Cert,
    purpose: Purpose,
    held: &[AgentKey],
) -> Result<sequoia_gpg_agent::KeyPair> {
    let policy = crate::policy();
    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| Error::NoSecretKey(cert.fingerprint().to_hex()))?;

    let usable: Vec<_> = match purpose {
        Purpose::Sign => valid.keys().alive().revoked(false).for_signing().collect(),
        Purpose::Certify => valid
            .keys()
            .alive()
            .revoked(false)
            .for_certification()
            .collect(),
        // Deliberately *not* filtered by alive/revoked, matching the local
        // path in ops.rs: revoking or retiring a card key withdraws it for
        // future use, it does not burn the archive. Old mail must stay
        // readable after the subkey it was sent to has expired or been
        // retired — and only for making new signatures does liveness matter.
        Purpose::Decrypt => valid
            .keys()
            .for_transport_encryption()
            .chain(valid.keys().for_storage_encryption())
            .collect(),
    };

    let mut candidates: Vec<_> = usable
        .into_iter()
        .filter_map(|ka| {
            let grip = Keygrip::of(ka.key().mpis()).ok()?.to_string();
            let held = held
                .iter()
                .find(|k| k.keygrip.eq_ignore_ascii_case(&grip))?;
            Some((held.is_on_card(), ka.key().clone()))
        })
        .collect();

    // Card first.
    candidates.sort_by_key(|(on_card, _)| std::cmp::Reverse(*on_card));
    let (_, key) = candidates
        .into_iter()
        .next()
        .ok_or_else(|| Error::NoSecretKey(cert.fingerprint().to_hex()))?;

    signer(&key.role_into_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Enumeration against whatever agent the developer happens to be running.
    ///
    /// Skips rather than fails when there is no agent: CI has none, and a test
    /// that depends on the developer's GnuPG setup must not break the suite.
    #[test]
    fn lists_whatever_the_local_agent_holds() {
        if !available() {
            eprintln!("no gpg-agent reachable; skipping");
            return;
        }

        let keys = keys().unwrap();
        for key in &keys {
            // A keygrip is a 40-character hex SHA-1 of the key parameters.
            assert_eq!(key.keygrip.len(), 40, "odd keygrip: {}", key.keygrip);
            assert!(key.keygrip.chars().all(|c| c.is_ascii_hexdigit()));
        }

        let on_card = card_keys().unwrap();
        assert!(on_card.iter().all(AgentKey::is_on_card));
        eprintln!(
            "agent holds {} key(s), {} on a smartcard",
            keys.len(),
            on_card.len()
        );
    }

    /// Signs with whatever `RPGP_TEST_CERT` points at, through the agent.
    ///
    /// `#[ignore]` because it is interactive: a card key makes the agent's
    /// pinentry ask for the PIN, and an unattended run would hang on it.
    #[test]
    #[ignore = "interactive: the agent will prompt for a PIN or passphrase"]
    fn signs_through_the_agent() {
        let Some(path) = std::env::var_os("RPGP_TEST_CERT") else {
            eprintln!("RPGP_TEST_CERT unset; skipping");
            return;
        };

        use sequoia_openpgp::parse::Parse;
        let cert = Cert::from_file(&path).unwrap();
        let backing = holds_signing_key(&cert).unwrap().expect("agent holds it");
        eprintln!("signing with card={:?}", backing.card_serial);

        let dir = tempfile::tempdir().unwrap();
        let store =
            crate::Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        store.insert(&cert).unwrap();

        let mut signature = Vec::new();
        crate::ops::sign_detached(&cert, None, b"signed on the card", &mut signature).unwrap();
        assert!(signature.starts_with(b"-----BEGIN PGP SIGNATURE-----"));

        let result =
            crate::ops::verify_detached(&store, &signature, b"signed on the card").unwrap();
        assert!(result.all_good(), "signatures: {:?}", result.signatures);
        eprintln!("verified: {}", result.signatures[0].signer);
    }

    /// Decrypting to, and certifying with, a card key. Interactive for the
    /// same reason as `signs_through_the_agent`.
    #[test]
    #[ignore = "interactive: the agent will prompt for a PIN or passphrase"]
    fn decrypts_and_certifies_through_the_agent() {
        let Some(path) = std::env::var_os("RPGP_TEST_CERT") else {
            eprintln!("RPGP_TEST_CERT unset; skipping");
            return;
        };

        use sequoia_openpgp::parse::Parse;
        let card = Cert::from_file(&path).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store =
            crate::Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        store.insert(&card).unwrap();

        {
            let held = keys().unwrap();
            let policy = crate::policy();
            let valid = card.with_policy(&policy, None).unwrap();
            for ka in valid.keys().alive().revoked(false) {
                let grip = Keygrip::of(ka.key().mpis())
                    .map(|g| g.to_string())
                    .unwrap_or_default();
                let m = held.iter().find(|k| k.keygrip.eq_ignore_ascii_case(&grip));
                eprintln!(
                    "  subkey {} sign={} enc={} agent={:?}",
                    ka.key().fingerprint().to_hex(),
                    ka.for_signing(),
                    ka.for_transport_encryption(),
                    m.map(|k| k.card_serial.clone()),
                );
            }
        }

        // Certify first, so a decryption failure does not mask its result.
        let stranger = crate::keygen::generate(&crate::keygen::KeyGenRequest::new(
            "Stranger <s@example.org>",
        ))
        .unwrap()
        .cert;
        store.insert(&stranger).unwrap();
        let mut request = crate::certify::CertifyRequest::new(
            card.fingerprint().to_hex(),
            stranger.fingerprint().to_hex(),
        );
        request.user_ids = vec!["Stranger <s@example.org>".to_string()];
        crate::certify::certify(&store, &request).unwrap();
        let reloaded = store.lookup(&stranger.fingerprint().to_hex()).unwrap();
        let found = crate::certify::certifications(&store, &reloaded).unwrap();
        assert_eq!(found[0].verified, Some(true));
        eprintln!("certified by the card: {}", found[0].certifier);

        // Encrypt to the card, then decrypt with it. No local secret exists
        // for this certificate, so success can only come from the agent.
        let mut ciphertext = Vec::new();
        crate::ops::encrypt(
            std::slice::from_ref(&card),
            &[],
            None,
            b"for the card only",
            &mut ciphertext,
        )
        .unwrap();

        // Surface whichever of the two steps is actually failing.
        {
            use sequoia_openpgp::crypto::Decryptor;
            use sequoia_openpgp::parse::Parse;
            let pile = sequoia_openpgp::PacketPile::from_bytes(&ciphertext).unwrap();
            for packet in pile.into_children() {
                if let sequoia_openpgp::Packet::PKESK(pkesk) = packet {
                    match decryptor_for(&card) {
                        Ok(mut pair) => {
                            eprintln!("  decryptor_for: ok, key {}", pair.public().fingerprint());
                            // PKESK::decrypt swallows the Decryptor error into
                            // None; call the decryptor directly to see it.
                            match pair.decrypt(pkesk.esk(), None) {
                                Ok(_) => eprintln!("  decryptor.decrypt: ok"),
                                Err(e) => eprintln!("  decryptor.decrypt: {e:#}"),
                            }
                        }
                        Err(e) => eprintln!("  decryptor_for failed: {e}"),
                    }
                }
            }
        }

        let mut plaintext = Vec::new();
        let result = crate::ops::decrypt(&store, &ciphertext, &[], &mut plaintext).unwrap();
        assert_eq!(plaintext, b"for the card only");
        assert_eq!(result.decrypted_with, Some(card.fingerprint().to_hex()));
        eprintln!("decrypted on the card");
    }

    /// Matching a certificate to the agent's copy of its secret, against a real
    /// certificate when one is offered via `RPGP_TEST_CERT`.
    ///
    /// Skipped by default: it needs a running agent that actually holds the
    /// key, which is a property of the developer's machine, not of the code.
    #[test]
    fn matches_a_certificate_to_the_agents_key() {
        let Some(path) = std::env::var_os("RPGP_TEST_CERT") else {
            eprintln!("RPGP_TEST_CERT unset; skipping");
            return;
        };
        if !available() {
            eprintln!("no gpg-agent reachable; skipping");
            return;
        }

        use sequoia_openpgp::parse::Parse;
        let cert = Cert::from_file(&path).unwrap();
        let found = holds_signing_key(&cert)
            .unwrap()
            .expect("the agent should hold this certificate's signing key");

        eprintln!(
            "{} -> keygrip {} card={:?}",
            cert.fingerprint().to_hex(),
            found.keygrip,
            found.card_serial
        );
    }
}
