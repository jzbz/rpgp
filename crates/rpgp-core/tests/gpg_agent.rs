//! The gpg-agent paths, against an agent each test starts for itself.
//!
//! Every other test keeps away from gpg-agent: an agent a test reaches can put
//! up a PIN prompt for a real card, and answers with keys the test knows
//! nothing about. These start one with its own home in a temporary directory,
//! which puts its sockets out of the way of the user's too, point rpgp-core at
//! it with `agent::set_home`, give it keys through its import command, and stop
//! it when they finish, however they finish. They run one at a time, because
//! the agent rpgp-core asks is chosen for the whole process.
//!
//! The agent is told never to start scdaemon, so nothing here opens a card
//! reader, and to prompt through a stand-in pinentry that always answers
//! Cancel and counts how often it was asked. Keys go in without a passphrase
//! unless a test wants the prompt.
//!
//! Where GnuPG is not installed they skip rather than fail, unless
//! `RPGP_TEST_REQUIRE_GPG_AGENT` is set. CI's Linux jobs set it, so that a
//! runner without GnuPG fails there instead of passing having tested nothing.
//! Unix only: the stand-in pinentry is a shell script.

#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rpgp_core::agent::{self, AgentHome};
use rpgp_core::keygen::{KeyGenRequest, Standard, generate};
use rpgp_core::{Error, Store, ops};
use sequoia_gpg_agent::{Agent, Context};
use sequoia_openpgp::cert::prelude::SubkeyRevocationBuilder;
use sequoia_openpgp::cert::{CipherSuite, KeyBuilder, Preferences};
use sequoia_openpgp::crypto::mpi::{Ciphertext, MPI, PublicKey};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::pkesk::PKESK3;
use sequoia_openpgp::packet::{Key, PKESK};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Recipient};
use sequoia_openpgp::serialize::{Serialize, SerializeInto};
use sequoia_openpgp::types::{KeyFlags, ReasonForRevocation};
use sequoia_openpgp::{Cert, Packet, PacketPile};

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// A pinentry whose user presses Cancel every time, and which writes a line to
/// `LOG` each time it is asked for a PIN or passphrase, and to `@DESC@` the
/// description the agent gives it for each prompt, as the agent sent it.
const PINENTRY: &str = r#"#!/bin/sh
echo "OK Pleased to meet you"
while IFS= read -r line; do
  case "$line" in
    GETPIN*) echo asked >> 'LOG'; echo "ERR 83886179 Operation cancelled <Pinentry>" ;;
    SETDESC\ *) printf '%s\n' "${line#SETDESC }" >> '@DESC@'; echo "OK" ;;
    BYE*) echo "OK closing connection"; exit 0 ;;
    *) echo "OK" ;;
  esac
done
"#;

/// A gpg-agent of the test's own, which rpgp-core asks until it is dropped.
struct Throwaway {
    /// Ephemeral: dropping it stops the agent, removes its socket directory
    /// and deletes its home.
    ctx: Context,
    pinentry_log: PathBuf,
    descriptions: PathBuf,
    _one_at_a_time: MutexGuard<'static, ()>,
}

impl Throwaway {
    /// Start an agent in a fresh temporary home, or `None` where GnuPG is not
    /// installed.
    fn start() -> Option<Self> {
        let one_at_a_time = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
        let ctx = match Context::ephemeral() {
            Ok(ctx) => ctx,
            Err(e) => return skip(&e),
        };
        let home = ctx
            .homedir()
            .expect("an ephemeral context has a home")
            .to_path_buf();

        let pinentry_log = home.join("pinentry.log");
        let descriptions = home.join("descriptions.log");
        let pinentry = home.join("pinentry");
        std::fs::write(
            &pinentry,
            PINENTRY
                .replace("LOG", &pinentry_log.display().to_string())
                .replace("@DESC@", &descriptions.display().to_string()),
        )
        .unwrap();
        std::fs::set_permissions(&pinentry, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            home.join("gpg-agent.conf"),
            format!(
                "disable-scdaemon\npinentry-program {}\n",
                pinentry.display()
            ),
        )
        .unwrap();

        if let Err(e) = ctx.start("gpg-agent") {
            return skip(&e);
        }
        agent::set_home(AgentHome::At(home));
        Some(Throwaway {
            ctx,
            pinentry_log,
            descriptions,
            _one_at_a_time: one_at_a_time,
        })
    }

    fn home(&self) -> &Path {
        self.ctx.homedir().unwrap()
    }

    /// Give the agent every secret key of `cert`, protected as they are.
    ///
    /// Unattended, which stores a key the way it arrives: one without a
    /// passphrase needs none to use, and one with a passphrase is asked for it
    /// when it is used, not now.
    fn give(&self, cert: &Cert) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut agent = Agent::connect_to(self.home()).await.unwrap();
            let policy = StandardPolicy::new();
            for ka in cert.keys().secret() {
                agent
                    .import(&policy, cert, ka.key().role_as_unspecified(), true, true)
                    .await
                    .unwrap();
            }
        });
    }

    /// How often the agent has put up its prompt.
    fn prompts(&self) -> usize {
        std::fs::read_to_string(&self.pinentry_log)
            .map(|log| log.lines().count())
            .unwrap_or(0)
    }

    /// The description the agent gave with each prompt, as the pinentry
    /// shows it: the agent escapes a line break, and anything else Assuan
    /// cannot carry, as `%` and two hex digits.
    fn descriptions(&self) -> Vec<String> {
        let log = std::fs::read_to_string(&self.descriptions).unwrap_or_default();
        log.lines().map(unescape).collect()
    }
}

/// `line` with the Assuan escapes, `%` and two hex digits, undone.
fn unescape(line: &str) -> String {
    let mut bytes = Vec::new();
    let mut rest = line.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        let decoded = (first == b'%')
            .then(|| tail.get(..2))
            .flatten()
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        match decoded {
            Some(byte) => {
                bytes.push(byte);
                rest = &tail[2..];
            }
            None => {
                bytes.push(first);
                rest = tail;
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

impl Drop for Throwaway {
    fn drop(&mut self) {
        agent::set_home(AgentHome::Nowhere);
    }
}

fn skip(e: &dyn std::fmt::Display) -> Option<Throwaway> {
    // Empty counts as unset, which is how CI's workflow leaves it on the
    // platforms that do not require it.
    if std::env::var_os("RPGP_TEST_REQUIRE_GPG_AGENT").is_some_and(|v| !v.is_empty()) {
        panic!("RPGP_TEST_REQUIRE_GPG_AGENT is set and no gpg-agent could be started: {e}");
    }
    eprintln!("SKIP: no gpg-agent could be started ({e}); is GnuPG installed?");
    None
}

/// A key as generated here, to RFC 4880: GnuPG 2.4 has no version 6 keys, and
/// sequoia-ipc derives no keygrip for one.
fn key(user_id: &str, passphrase: Option<&str>) -> Cert {
    let mut request = KeyGenRequest::new(user_id);
    request.standard = Standard::Rfc4880;
    request.password = passphrase.map(|p| p.to_string().into());
    generate(&request).unwrap().cert
}

/// `cert` with an RSA subkey added for encrypting data at rest, which puts it
/// after the certificate's key for data in transit, and of the smallest size
/// the standard policy accepts: a larger one takes this build many seconds to
/// generate.
fn with_rsa_key(cert: Cert) -> Cert {
    let policy = StandardPolicy::new();
    KeyBuilder::new(KeyFlags::empty().set_storage_encryption())
        .set_cipher_suite(CipherSuite::RSA2k)
        .subkey(cert.with_policy(&policy, None).unwrap())
        .unwrap()
        .attach_cert()
        .unwrap()
}

/// A store holding only the public halves of `certs`, so that whatever opens
/// or signs with them has to be the agent.
fn public_store(dir: &tempfile::TempDir, certs: &[&Cert]) -> Store {
    let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
    for cert in certs {
        store.insert(cert).unwrap();
    }
    store
}

/// `cert`'s encryption keys, the transport key first.
fn encryption_keys(cert: &Cert) -> Vec<Key<PublicParts, UnspecifiedRole>> {
    let policy = StandardPolicy::new();
    let valid = cert.with_policy(&policy, None).unwrap();
    valid
        .keys()
        .for_transport_encryption()
        .chain(valid.keys().for_storage_encryption())
        .map(|ka| ka.key().clone())
        .collect()
}

/// A message encrypted to `key` of `cert` alone, its packet naming the key or,
/// as `gpg --throw-keyids` writes it, naming none.
fn sealed(
    cert: &Cert,
    key: &Key<PublicParts, UnspecifiedRole>,
    named: bool,
    text: &[u8],
) -> Vec<u8> {
    let policy = StandardPolicy::new();
    let features = cert.with_policy(&policy, None).unwrap().features();
    let recipient = Recipient::new(features, named.then(|| key.key_handle()), key);
    let mut ciphertext = Vec::new();
    let message = Message::new(&mut ciphertext);
    let message = Encryptor::for_recipients(message, [recipient])
        .build()
        .unwrap();
    let mut message = LiteralWriter::new(message).build().unwrap();
    message.write_all(text).unwrap();
    message.finalize().unwrap();
    ciphertext
}

/// What the agent holds is listed, matched to a certificate by keygrip, and
/// none of it is on a card: scdaemon is never started here.
#[test]
fn the_agent_lists_what_it_holds_and_matches_it_to_a_certificate() {
    let Some(agent_home) = Throwaway::start() else {
        return;
    };
    let alice = key("Alice <alice@example.org>", None);
    agent_home.give(&alice);

    assert!(agent::available());
    let held = agent::keys().unwrap();
    for ka in alice.keys() {
        let grip = sequoia_ipc::Keygrip::of(ka.key().mpis())
            .unwrap()
            .to_string();
        assert!(
            held.iter().any(|k| k.keygrip.eq_ignore_ascii_case(&grip)),
            "the agent does not list {}",
            ka.key().fingerprint()
        );
    }
    assert!(held.iter().all(|k| k.keygrip.len() == 40));
    assert!(agent::card_keys().unwrap().is_empty());

    let public = alice.clone().strip_secret_key_material();
    let found = agent::holds_signing_key(&public)
        .unwrap()
        .expect("the agent holds Alice's signing key");
    assert!(!found.is_on_card());
    let annotated = agent::annotate(&[&public]);
    assert!(annotated.contains_key(&alice.fingerprint().to_hex()));
}

/// A message to either of a certificate's encryption keys opens through the
/// agent, and so does one to a key its owner has since retired.
///
/// The agent used to be handed the certificate's first encryption key it
/// held, whatever the message named, and a key generated here has two, so one
/// of them never opened this way.
#[test]
fn a_message_to_any_encryption_key_the_agent_holds_opens_through_it() {
    let Some(agent_home) = Throwaway::start() else {
        return;
    };
    let alice = key("Alice <alice@example.org>", None);
    agent_home.give(&alice);
    let dir = tempfile::tempdir().unwrap();
    let store = public_store(&dir, &[&alice]);

    let keys = encryption_keys(&alice);
    assert_eq!(keys.len(), 2, "premise: a transport and a storage key");
    for key in &keys {
        let ciphertext = sealed(&alice, key, true, b"for one key");
        let mut plaintext = Vec::new();
        let result = ops::decrypt(&store, &ciphertext, &[], &mut plaintext)
            .unwrap_or_else(|e| panic!("to {}: {e}", key.fingerprint()));
        assert_eq!(plaintext, b"for one key");
        assert_eq!(result.decrypted_with, Some(alice.fingerprint().to_hex()));
    }

    // Retire the transport key, as someone rotating it would. What was sent to
    // it still has to open.
    let retired = &keys[0];
    let mut signer = alice
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap()
        .into_keypair()
        .unwrap();
    let subkey = alice
        .keys()
        .subkeys()
        .find(|ka| ka.key().fingerprint() == retired.fingerprint())
        .unwrap();
    let revocation = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"rotated")
        .unwrap()
        .build(&mut signer, &alice, subkey.key(), None)
        .unwrap();
    let ciphertext = sealed(&alice, retired, true, b"sent before it was retired");
    store
        .insert(&alice.clone().insert_packets(revocation).unwrap().0)
        .unwrap();
    let mut plaintext = Vec::new();
    ops::decrypt(&store, &ciphertext, &[], &mut plaintext).unwrap();
    assert_eq!(plaintext, b"sent before it was retired");
    assert_eq!(agent_home.prompts(), 0, "no key here has a passphrase");
}

/// An RSA key in the agent's own store opens a message to hidden recipients
/// when its packet comes after those of other RSA keys of its size, and
/// nothing prompts.
///
/// For a key in its store the agent hands back whatever the decryption gives,
/// and a packet that is not the key's fails on this side without a word, so
/// the next is tried. The key is one of three encryption keys the agent holds
/// for the certificate, and not the first: the agent used to be handed the
/// first, a Curve25519 key that no RSA packet fits.
#[test]
fn a_hidden_rsa_packet_after_other_recipients_opens_through_the_agent() {
    let Some(agent_home) = Throwaway::start() else {
        return;
    };
    let alice = with_rsa_key(key("Alice <alice@example.org>", None));
    agent_home.give(&alice);
    let dir = tempfile::tempdir().unwrap();
    let store = public_store(&dir, &[&alice]);
    let rsa = encryption_keys(&alice)
        .into_iter()
        .find(|key| matches!(key.mpis(), PublicKey::RSA { .. }))
        .expect("premise: an RSA key");
    let PublicKey::RSA { n, .. } = rsa.mpis() else {
        unreachable!()
    };

    // Two packets for other RSA keys of Alice's size ahead of hers, naming
    // nobody, and carrying what theirs would: a number below her modulus that
    // was not made with her key.
    let someone_elses = || -> Packet {
        let mut c = vec![0; n.value().len()];
        sequoia_openpgp::crypto::random(&mut c).unwrap();
        c[0] = n.value()[0] >> 1;
        let pkesk = PKESK3::new(None, rsa.pk_algo(), Ciphertext::RSA { c: MPI::new(&c) });
        PKESK::from(pkesk.unwrap()).into()
    };
    let mut packets = vec![someone_elses(), someone_elses()];
    let hers = sealed(&alice, &rsa, false, b"for a hidden recipient");
    packets.extend(PacketPile::from_bytes(&hers).unwrap().into_children());
    let mut message = Vec::new();
    PacketPile::from(packets).serialize(&mut message).unwrap();

    let mut plaintext = Vec::new();
    let result = ops::decrypt(&store, &message, &[], &mut plaintext)
        .unwrap_or_else(|e| panic!("Alice's own packet did not open it: {e}"));
    assert_eq!(plaintext, b"for a hidden recipient");
    assert_eq!(result.decrypted_with, Some(alice.fingerprint().to_hex()));
    assert_eq!(agent_home.prompts(), 0, "no key here has a passphrase");
}

/// A cancelled prompt is what the decryption reports, and it is not put up
/// again for the next key the message is for.
///
/// Both keys here are the agent's and both are protected. The prompt for the
/// first used to be taken for a key that did not fit: the second prompt went
/// up at once, and when it was cancelled too the user read that no secret key
/// opened the message.
#[test]
fn a_cancelled_prompt_is_the_answer_and_is_not_put_up_again() {
    let Some(agent_home) = Throwaway::start() else {
        return;
    };
    let alice = key("Alice <alice@example.org>", Some("alice's passphrase"));
    let bob = key("Bob <bob@example.org>", Some("bob's passphrase"));
    agent_home.give(&alice);
    agent_home.give(&bob);
    let dir = tempfile::tempdir().unwrap();
    let store = public_store(&dir, &[&alice, &bob]);

    let mut ciphertext = Vec::new();
    ops::encrypt(
        &[alice.clone(), bob.clone()],
        &[],
        None,
        b"for either",
        &mut ciphertext,
    )
    .unwrap();

    let refused = ops::decrypt(&store, &ciphertext, &[], &mut Vec::new())
        .expect_err("opened with every prompt cancelled");
    assert_eq!(
        agent_home.prompts(),
        1,
        "the prompt went up again: {refused}"
    );
    // The agent's own words are passed on, and it words them in the user's
    // language, so only their being there is checked.
    match &refused {
        Error::AgentRefused { name, reason } => {
            assert!(!reason.is_empty());
            assert!(
                name == "Alice <alice@example.org>" || name == "Bob <bob@example.org>",
                "{name}"
            );
        }
        other => panic!("reported as something other than the agent refusing: {other}"),
    }
    assert!(refused.to_string().starts_with("gpg-agent: "), "{refused}");
}

/// Signing and certifying through the agent, with a key whose secret is only
/// there.
#[test]
fn signs_and_certifies_through_the_agent() {
    let Some(agent_home) = Throwaway::start() else {
        return;
    };
    let alice = key("Alice <alice@example.org>", None);
    let bob = key("Bob <bob@example.org>", None);
    agent_home.give(&alice);
    let dir = tempfile::tempdir().unwrap();
    let store = public_store(&dir, &[&alice, &bob]);
    let public = store.lookup(&alice.fingerprint().to_hex()).unwrap();
    assert!(!public.is_tsk(), "premise: no secret here but the agent's");

    let mut signature = Vec::new();
    ops::sign_detached(&public, None, b"signed by the agent", &mut signature).unwrap();
    let verified = ops::verify_detached(&store, &signature, b"signed by the agent").unwrap();
    assert!(verified.all_good(), "{:?}", verified.signatures);

    let mut request = rpgp_core::certify::CertifyRequest::new(
        alice.fingerprint().to_hex(),
        bob.fingerprint().to_hex(),
    );
    request.user_ids = vec!["Bob <bob@example.org>".to_string()];
    rpgp_core::certify::certify(&store, &request).unwrap();
    let bob = store.lookup(&bob.fingerprint().to_hex()).unwrap();
    let found = rpgp_core::certify::certifications(&store, &bob).unwrap();
    assert!(
        found
            .iter()
            .any(|c| c.verified == Some(true) && c.certifier.contains("Alice")),
        "{found:?}"
    );
    assert_eq!(agent_home.prompts(), 0);
}

/// `message` as `holder`, one of its recipients, could send it on to `to`:
/// the session key `holder`'s own key opens, wrapped again for `to`'s key, in
/// front of the sender's encrypted container as it was written. Version 6
/// packets only, which is what `ops::encrypt` writes to a key generated here.
fn forwarded(message: &[u8], holder: &Cert, to: &Cert) -> Vec<u8> {
    use sequoia_openpgp::packet::SEIP;
    use sequoia_openpgp::packet::pkesk::PKESK6;

    let policy = StandardPolicy::new();
    let packets: Vec<Packet> = PacketPile::from_bytes(message)
        .unwrap()
        .into_children()
        .collect();
    let cipher = packets.iter().find_map(|p| match p {
        Packet::SEIP(SEIP::V2(seip)) => Some(seip.symmetric_algo()),
        _ => None,
    });
    let mut keypair = holder
        .keys()
        .secret()
        .with_policy(&policy, None)
        .for_transport_encryption()
        .next()
        .unwrap()
        .key()
        .clone()
        .into_keypair()
        .unwrap();
    let (_, session_key) = packets
        .iter()
        .find_map(|p| match p {
            Packet::PKESK(pkesk @ PKESK::V6(_)) => pkesk.decrypt(&mut keypair, cipher),
            _ => None,
        })
        .expect("the holder's key opens a version 6 packet in the message");
    let rewrapped = PKESK6::for_recipient(&session_key, &encryption_keys(to)[0]).unwrap();
    let mut sent_on = Vec::new();
    Packet::from(rewrapped).serialize(&mut sent_on).unwrap();
    for packet in packets
        .iter()
        .filter(|p| !matches!(p, Packet::PKESK(_) | Packet::SKESK(_)))
    {
        packet.serialize(&mut sent_on).unwrap();
    }
    sent_on
}

/// Whether a signature was meant for its reader is settled against the
/// certificate a decryption credits, and through the agent that is the first
/// in the store found carrying the key that opened the message. So Alice's
/// signature, made through the agent on a message she encrypted to Bob,
/// reads as good where the agent opens it for Bob, and as not valid where
/// Bob has sent it on to Carol and the agent opens it for her. Each store
/// here holds one certificate carrying each key, so which comes first does
/// not arise; `ops::Helper`'s `decrypt` says where it does.
#[test]
fn a_signed_message_sent_on_is_found_out_where_the_agent_opens_it() {
    let Some(agent_home) = Throwaway::start() else {
        return;
    };
    let alice = key("Alice <alice@example.org>", None);
    let bob = key("Bob <bob@example.org>", None);
    let carol = key("Carol <carol@example.org>", None);
    for cert in [&alice, &bob, &carol] {
        agent_home.give(cert);
    }

    let dir = tempfile::tempdir().unwrap();
    let alices = public_store(&dir, &[&alice]);
    let signer = alices.lookup(&alice.fingerprint().to_hex()).unwrap();
    let mut sent = Vec::new();
    ops::encrypt(
        std::slice::from_ref(&bob),
        &[],
        Some((&signer, None)),
        b"You are hired",
        &mut sent,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let bobs = public_store(&dir, &[&alice, &bob]);
    let opened = ops::decrypt(&bobs, &sent, &[], &mut Vec::new()).unwrap();
    assert_eq!(opened.decrypted_with, Some(bob.fingerprint().to_hex()));
    assert!(opened.all_good(), "{:?}", opened.signatures);

    let dir = tempfile::tempdir().unwrap();
    let carols = public_store(&dir, &[&alice, &carol]);
    let mut plaintext = Vec::new();
    let opened = ops::decrypt(
        &carols,
        &forwarded(&sent, &bob, &carol),
        &[],
        &mut plaintext,
    )
    .unwrap();
    assert_eq!(plaintext, b"You are hired");
    assert_eq!(
        opened.decrypted_with,
        Some(carol.fingerprint().to_hex()),
        "premise: the agent opened what Bob sent on with Carol's key"
    );
    assert!(
        !opened.all_good(),
        "Bob sent it on to Carol, and Alice's signature still reads as meant for her"
    );
    assert!(
        opened.signatures[0].detail.contains("intended recipient"),
        "{:?}",
        opened.signatures
    );
    assert_eq!(agent_home.prompts(), 0);
}

/// `cert` with the secret halves of its primary key alone, or of its subkeys
/// alone, as a card holds them when the primary is kept offline.
fn with_secrets_of(cert: &Cert, primary: bool) -> Cert {
    let primary_key = cert.fingerprint();
    let bytes = cert
        .as_tsk()
        .set_filter(move |key| (key.fingerprint() == primary_key) == primary)
        .to_vec()
        .unwrap();
    Cert::from_bytes(&bytes).unwrap()
}

/// The survey after a reload asks the agent, for each use, about the key that
/// use takes. Given only the subkeys, as a card holds them when the primary is
/// kept offline, the agent signs and decrypts for the certificate but is not
/// found to certify for it, and certifying through it is refused. Given only
/// the primary, it is found to certify, and a certification made through it
/// counts, though it holds no key that signs.
///
/// The survey used to look at signing keys alone, and the certify dialog took
/// what it found for certifying: it listed the first as a certifier, which
/// then failed, and never listed the second.
#[test]
fn the_agent_is_found_to_certify_only_where_it_holds_the_primary() {
    let Some(agent_home) = Throwaway::start() else {
        return;
    };
    let alice = key("Alice <alice@example.org>", None);
    let bob = key("Bob <bob@example.org>", None);
    let carol = key("Carol <carol@example.org>", None);
    agent_home.give(&with_secrets_of(&alice, false));
    agent_home.give(&with_secrets_of(&bob, true));
    let dir = tempfile::tempdir().unwrap();
    let store = public_store(&dir, &[&alice, &bob, &carol]);
    let public = |cert: &Cert| store.lookup(&cert.fingerprint().to_hex()).unwrap();

    let found = agent::annotate(&[&public(&alice), &public(&bob), &public(&carol)]);
    let of = |cert: &Cert| found.get(&cert.fingerprint().to_hex());
    let subkeys_only = of(&alice).expect("the agent holds Alice's subkeys");
    assert!(
        subkeys_only.sign.is_some() && subkeys_only.decrypt.is_some(),
        "{subkeys_only:?}"
    );
    assert!(
        subkeys_only.certify.is_none(),
        "found to certify without the primary: {subkeys_only:?}"
    );
    let primary_only = of(&bob).expect("the agent holds Bob's primary");
    assert!(
        primary_only.certify.is_some(),
        "the primary was not found to certify: {primary_only:?}"
    );
    assert!(
        primary_only.sign.is_none() && primary_only.decrypt.is_none(),
        "{primary_only:?}"
    );
    assert!(of(&carol).is_none(), "the agent holds nothing of Carol's");

    let certify_carol = |certifier: &Cert| {
        let mut request = rpgp_core::certify::CertifyRequest::new(
            certifier.fingerprint().to_hex(),
            carol.fingerprint().to_hex(),
        );
        request.user_ids = vec!["Carol <carol@example.org>".to_string()];
        rpgp_core::certify::certify(&store, &request)
    };
    let refused = certify_carol(&alice).expect_err("certified without the primary");
    assert!(matches!(refused, Error::NoSecretKey(_)), "{refused}");
    certify_carol(&bob).expect("the agent's primary certifies");
    let listed = rpgp_core::certify::certifications(&store, &public(&carol)).unwrap();
    let bob_fp = bob.fingerprint().to_hex();
    assert!(
        listed
            .iter()
            .any(|c| c.is_good() && c.certifier_fingerprint.as_deref() == Some(bob_fp.as_str())),
        "{listed:?}"
    );
    assert_eq!(agent_home.prompts(), 0);
}

/// The agent's passphrase prompt names the certificate whose key it unlocks:
/// its primary user ID, and the primary key's ID beside the subkey's, as
/// GnuPG's own prompt does, for decrypting and for signing.
///
/// It used to give the subkey's ID and creation time and nothing else. The
/// decryption fallback asks with keys the user never picked, and a user with
/// several keys in the agent could not tell from the prompt whose passphrase
/// to type.
#[test]
fn the_passphrase_prompt_names_the_certificate() {
    let Some(agent_home) = Throwaway::start() else {
        return;
    };
    let alice = key("Alice <alice@example.org>", Some("alice's passphrase"));
    agent_home.give(&alice);
    let dir = tempfile::tempdir().unwrap();
    let store = public_store(&dir, &[&alice]);
    let public = store.lookup(&alice.fingerprint().to_hex()).unwrap();

    let mut ciphertext = Vec::new();
    ops::encrypt(
        std::slice::from_ref(&alice),
        &[],
        None,
        b"for alice",
        &mut ciphertext,
    )
    .unwrap();
    ops::decrypt(&store, &ciphertext, &[], &mut Vec::new())
        .expect_err("opened with the prompt cancelled");
    ops::sign_detached(&public, None, b"to be signed", Vec::new())
        .expect_err("signed with the prompt cancelled");

    let descriptions = agent_home.descriptions();
    assert_eq!(
        descriptions.len(),
        2,
        "premise: one prompt each: {descriptions:?}"
    );
    let main_key_id = format!("(main key ID {})", alice.keyid().to_hex());
    for (operation, description) in ["decrypting", "signing"].iter().zip(&descriptions) {
        eprintln!("{operation}: {description:?}");
        assert!(
            description.contains("Alice <alice@example.org>"),
            "{operation}: the prompt does not name the certificate: {description:?}"
        );
        assert!(
            description.contains(&main_key_id),
            "{operation}: the prompt does not give the primary key's ID: {description:?}"
        );
    }
}
