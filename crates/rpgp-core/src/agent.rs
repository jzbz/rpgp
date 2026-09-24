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
//!
//! Choosing a key and asking the agent are kept apart: `select_key`,
//! `decryption_attempts` and `holds` decide from what the agent listed, without
//! a connection, so that what they choose can be tested where there is no
//! agent.
//!
//! Finding the agent is rPGP's own, in [`gpgconf`], because sequoia-gpg-agent's
//! way cannot find it on macOS or Windows, or from inside the Flatpak; that
//! module says why. Only the connection to the socket it finds is
//! sequoia-gpg-agent's.

mod gpgconf;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError, RwLock};

use sequoia_gpg_agent::{Agent, KeyPair};
use sequoia_ipc::Keygrip;
use sequoia_openpgp::cert::ValidCert;
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::{Key, PKESK};
use sequoia_openpgp::{Cert, Fingerprint};
use tokio::runtime::Runtime;

use crate::error::{Error, Result};

/// Which gpg-agent this process asks. For tests only: the app must never set
/// it, and it is public only because the integration tests and the GUI's
/// tests, which are other crates, have to.
///
/// The app asks the user's own and never changes that. The choice exists for
/// the tests, which must not reach it: an agent a test reaches can put up a PIN
/// prompt for a real card, is started for a GnuPG home that was not running
/// one, and answers with keys the test knows nothing about, so what the test
/// checks depends on the machine it runs on. rpgp-core's own unit tests start
/// pointed [`AgentHome::Nowhere`], and the tests in other crates that could
/// reach one point themselves there. A test that wants an agent starts one of
/// its own in a temporary directory and points the process [`AgentHome::At`]
/// it; only a test that is `#[ignore]`d asks for the developer's by name.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentHome {
    /// The agent GnuPG itself would use: that of `GNUPGHOME`, or of GnuPG's
    /// default home when it is unset.
    User,
    /// The agent serving this GnuPG home directory, started there if none is
    /// running yet and the directory exists.
    At(PathBuf),
    /// No agent at all. Every question fails at once, as it does on a machine
    /// without GnuPG, and nothing is looked up or started.
    Nowhere,
}

#[cfg(not(test))]
const FIRST_HOME: AgentHome = AgentHome::User;
#[cfg(test)]
const FIRST_HOME: AgentHome = AgentHome::Nowhere;

static HOME: RwLock<AgentHome> = RwLock::new(FIRST_HOME);

/// Point every later question to the agent at `home`, from whichever thread it
/// is asked.
///
/// For tests only, and never called by the app; see [`AgentHome`].
/// Process-wide rather than per thread, because the questions are asked from
/// threads a test does not start: the GUI's survey after a reload runs on one
/// of its own.
#[doc(hidden)]
pub fn set_home(home: AgentHome) {
    *HOME.write().unwrap_or_else(PoisonError::into_inner) = home;
}

#[cfg(test)]
thread_local! {
    /// How often this thread has tried to reach an agent, for the tests that
    /// check an operation did not. Per thread, so that tests running beside
    /// each other do not count each other's; the question is asked on the
    /// caller's thread before anything moves to the runtime.
    pub(crate) static CONNECTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

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

/// What the agent holds of one certificate, for each use rPGP puts it to: the
/// key each operation would ask it for, chosen as that operation chooses it.
///
/// Per use, because one answer served them all and was right for signing
/// alone. [`annotate`] marked a certificate when the agent held a live signing
/// key of it, and the certify dialog read the mark as "can certify", which
/// needs the primary key. In the layout most YubiKey guides recommend, the
/// primary kept offline and the subkeys on the card, the certificate was
/// offered as a certifier and every certification failed for want of the
/// primary; and one whose primary the agent held, but none of its signing
/// keys, was never offered at all.
#[derive(Debug, Clone, Default)]
pub struct AgentHolds {
    /// The key signing asks for: a live signing key, one on a card before one
    /// in the agent's own store. See [`signer_for`].
    pub sign: Option<AgentKey>,
    /// The primary key, which certifying asks for, and only while it is
    /// alive. See [`certifier_for`].
    pub certify: Option<AgentKey>,
    /// An encryption key of either kind, one on a card first, whether or not
    /// it is still in use: decrypting asks every one a message could be for,
    /// retired and expired ones too.
    pub decrypt: Option<AgentKey>,
}

impl AgentHolds {
    /// Whether the agent holds nothing of the certificate for any of the
    /// three.
    pub fn is_empty(&self) -> bool {
        self.sign.is_none() && self.certify.is_none() && self.decrypt.is_none()
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
///
/// Connecting is held to it whole, gpgconf included; [`reach`] says how. The
/// bound is on the caller only: a gpgconf that never exits is left running,
/// with the thread that waits on it, and each connection made meanwhile starts
/// another of each.
const ENUMERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Where the agent of one [`AgentHome`] listens, as gpgconf said, kept from
/// the first connection to it that worked.
///
/// Every connection used to learn it afresh, running gpgconf twice through
/// sequoia-gpg-agent 0.6.2 (`Context::new`), and then twice more, to create
/// the socket directory and launch an agent that was almost always running
/// already (`Agent::connect`): four processes before the socket was tried, and
/// on Windows a `cygpath` for every line gpgconf printed. Every keypair paid
/// for another connection besides, only to learn the socket's path. With the
/// socket kept, gpgconf runs for the first connection, once
/// ([`gpgconf::find`]), and again only once the socket does not answer, as
/// when the agent has been stopped.
///
/// Only a socket an agent has answered on is kept. gpgconf failing, or naming
/// a home that does not exist, is how a machine looks before GnuPG is
/// installed or first run, and either can change while the app is open, which
/// should not need the app restarted. A connection to the kept socket that
/// fails asks gpgconf again before it gives up, and one that gives up, or runs
/// out of time, drops the socket; see [`reach`].
///
/// Kept per home, because the tests point the process at agents of their own;
/// the app asks one home for as long as it runs. Nothing the agent holds is
/// kept, only where it listens: a card inserted since is in the next listing.
static KNOWN: Mutex<Option<(AgentHome, PathBuf)>> = Mutex::new(None);

/// The socket kept for `home`, if one is.
fn known(home: &AgentHome) -> Option<PathBuf> {
    KNOWN
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
        .filter(|(kept_for, _)| kept_for == home)
        .map(|(_, socket)| socket.clone())
}

fn remember(home: &AgentHome, socket: &Path) {
    *KNOWN.lock().unwrap_or_else(PoisonError::into_inner) =
        Some((home.clone(), socket.to_path_buf()));
}

fn forget(home: &AgentHome) {
    let mut kept = KNOWN.lock().unwrap_or_else(PoisonError::into_inner);
    if kept.as_ref().is_some_and(|(kept_for, _)| kept_for == home) {
        *kept = None;
    }
}

fn connect() -> Result<Agent> {
    Ok(connected()?.0)
}

/// A connection to the agent, and the socket it was reached on.
fn connected() -> Result<(Agent, PathBuf)> {
    #[cfg(test)]
    CONNECTS.with(|count| count.set(count.get() + 1));

    let home = HOME.read().unwrap_or_else(PoisonError::into_inner).clone();
    let dir = match &home {
        AgentHome::User => None,
        AgentHome::At(dir) => Some(dir.clone()),
        AgentHome::Nowhere => {
            return Err(Error::invalid(
                "no gpg-agent to talk to: this process was told to ask none",
            ));
        }
    };
    runtime()?.block_on(async {
        // No pinentry context is set here, deliberately. This connection only
        // ever lists keys and is dropped before any crypto runs; the prompting
        // paths open their own connection and send their own options, built by
        // sequoia-gpg-agent from GPG_TTY, TERM, DISPLAY and friends
        // (sequoia-gpg-agent 0.6.2 KeyPair::sign_async / decrypt_async).
        // Assuan options are per-connection state, so anything set here could
        // never have reached a prompt — it only cost three round trips on
        // every connect, which annotate and every crypto operation make.
        match tokio::time::timeout(ENUMERATION_TIMEOUT, reach(&home, dir)).await {
            Ok(Ok(reached)) => Ok(reached),
            Ok(Err(e)) => {
                forget(&home);
                Err(Error::invalid(format!("no gpg-agent to talk to: {e}")))
            }
            Err(_) => {
                forget(&home);
                Err(Error::invalid("gpg-agent did not answer in time"))
            }
        }
    })
}

/// Connect to the agent of `home`, whose GnuPG home is `dir`, or GnuPG's
/// default where that is `None`.
///
/// On the socket kept for `home` when there is one. Otherwise, or when that
/// socket does not answer, in the steps sequoia-gpg-agent's `Agent::connect`
/// takes, but in a different order: gpgconf is found and asked where the agent
/// listens ([`gpgconf::find`]), that socket is tried, and only if nothing is
/// listening there is an agent started and the socket tried again. Not even
/// then where the home is not there, as inside the Flatpak; see `Never` in
/// `gpgconf::Route`. `Agent::connect` launches first, every time, and
/// against an agent that accepts a connection and then never answers, which
/// is what a hung agent does, gpgconf's launch never returns: it waits on that
/// agent's greeting through `gpg-connect-agent`. A socket that is there but
/// silent is left to the timeout instead, which lets go of it, and launches
/// nothing that would outlive the attempt.
///
/// gpgconf runs on the runtime's blocking pool. `tokio::time::timeout` checks
/// its deadline only when the future it holds is pending, and gpgconf, run
/// with `std::process::Command`, blocks inside the poll that started it: the
/// timeout could not fire until gpgconf exited, and a gpgconf that hung held
/// the caller with it. From the blocking pool, the wait is a pending task like
/// any other. What is left inside the poll is the socket's own connect, which
/// sequoia-gpg-agent makes blocking before it awaits the greeting. On Unix
/// that blocks only while the socket's queue of connections waiting to be
/// accepted is full, as that of an agent stopped outright can become. On
/// Windows it is a TCP connect to the local port the socket file names, which
/// the system bounds, and against a GnuPG built for Cygwin a handshake after
/// it, which nothing does.
///
/// A new socket is kept once an agent has answered on it. Nothing is forgotten
/// here; the caller forgets the kept socket if this fails.
async fn reach(
    home: &AgentHome,
    dir: Option<PathBuf>,
) -> std::result::Result<(Agent, PathBuf), sequoia_gpg_agent::Error> {
    if let Some(socket) = known(home)
        && let Ok(agent) = Agent::connect_to_agent(&socket).await
    {
        return Ok((agent, socket));
    }

    let found = off_the_poll(move || gpgconf::find(dir)).await?;
    let socket = found.socket.clone();
    let agent = match Agent::connect_to_agent(&socket).await {
        Ok(agent) => agent,
        Err(_) => {
            off_the_poll(move || found.start_agent()).await?;
            Agent::connect_to_agent(&socket).await?
        }
    };
    remember(home, &socket);
    Ok((agent, socket))
}

/// Run `work`, which runs gpgconf, on the runtime's blocking pool, so that the
/// deadline of whatever awaits it can pass while gpgconf runs.
async fn off_the_poll<T: Send + 'static>(
    work: impl FnOnce() -> std::result::Result<T, sequoia_gpg_agent::Error> + Send + 'static,
) -> std::result::Result<T, sequoia_gpg_agent::Error> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| sequoia_gpg_agent::Error::Other(e.into()))?
}

/// Whether a gpg-agent is reachable at all.
///
/// Not currently called by the GUI, which reaches the agent through
/// [`annotate`] and the fallbacks in `ops` instead and lets each of those fail
/// on its own. The earlier note here claimed the UI used this to decide whether
/// to offer card-backed keys; no such gate was ever built, and a reader tracing
/// how card keys reach the interface was sent somewhere nothing calls.
///
/// Kept because it is the cheap reachability probe the tests use, and the
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

/// A signer, and decryptor, backed by the agent, for `key` of `cert`, a key
/// the agent has the secret half of.
///
/// The agent finds the secret half by keygrip, so only the public key is
/// needed to reach it. `cert` is for the prompt. The agent is handed the
/// words GnuPG's own passphrase prompt uses, which give the certificate's
/// primary user ID, then the key's ID and, for a subkey, the primary key's
/// (sequoia-gpg-agent 0.6.2 `KeyPair::with_cert`, sent as `SETKEYDESC`).
/// Without it the prompt gave the key's ID and creation time alone, which for
/// the subkey that decrypts is an ID few users have seen, and the decryption
/// fallback asks with keys the user never picked. Where `cert` has no valid
/// self-signature under the policy, the prompt stays that bare one. Whether a
/// card's PIN prompt shows these words is gpg-agent's choice.
///
/// Building it does not connect. The keypair opens a connection of its own
/// each time it is used, to the socket the last connection that worked went
/// through, which is also when any PIN or passphrase prompt happens in the
/// user's pinentry, while that use blocks. It used to connect here as well,
/// running gpgconf four times, only to learn that socket's path. Only when no
/// connection has worked yet, or the last one failed, does this connect, to
/// find the socket.
pub fn signer(cert: &Cert, key: &Key<PublicParts, UnspecifiedRole>) -> Result<KeyPair> {
    // The returned KeyPair implements Sequoia's Signer and Decryptor
    // synchronously, so it drops straight into the existing stream builders
    // with no runtime in sight.
    let pair = KeyPair::new_for_socket(socket()?, key)
        .map_err(|e| Error::invalid(format!("the agent cannot use this key: {e}")))?;
    let policy = crate::policy();
    Ok(match cert.with_policy(&policy, None) {
        Ok(valid) => pair.with_cert(&valid),
        Err(_) => pair,
    })
}

/// The agent's socket: the one the last connection that worked went through,
/// or, when there is none, a new connection's.
fn socket() -> Result<PathBuf> {
    let home = HOME.read().unwrap_or_else(PoisonError::into_inner).clone();
    match known(&home) {
        Some(socket) => Ok(socket),
        None => Ok(connected()?.1),
    }
}

/// Whether the agent can act for a signing key of `cert`, the one signing
/// would use, and if so which smartcard — if any — it is on.
///
/// Matching is by keygrip, which is what the agent indexes by, so a
/// certificate imported from anywhere lines up with the agent's copy of its
/// secret without the two ever having been introduced.
pub fn holds_signing_key(cert: &Cert) -> Result<Option<AgentKey>> {
    Ok(holds(cert, &keys()?).sign)
}

/// Match a whole set of certificates against the agent in one round trip.
///
/// Returns fingerprint -> what the agent holds of it, for each certificate it
/// holds anything of. Per-certificate lookups would re-connect and re-list for
/// every row in the list; the store is read wholesale, so this is too.
pub fn annotate<C>(certs: &[C]) -> HashMap<String, AgentHolds>
where
    C: std::ops::Deref<Target = Cert>,
{
    let mut found = HashMap::new();
    let Ok(held) = keys() else {
        return found;
    };
    // An agent that answers but holds nothing — a fresh GnuPG install, or a
    // machine whose secrets live only here — makes every match below fail, so
    // the policy walk and the keygrip of every key would rebuild the empty map
    // we already have.
    if held.is_empty() {
        return found;
    }

    for cert in certs {
        let held_of_cert = holds(cert, &held);
        if !held_of_cert.is_empty() {
            found.insert(cert.fingerprint().to_hex(), held_of_cert);
        }
    }
    found
}

/// What of `cert` the agent holds, for each use, judged from `held`, the
/// agent's listing, without asking the agent anything.
///
/// Each use takes the key its operation would take: signing and certifying
/// through [`usable_keys`], as [`select_key`] does, and decrypting through
/// [`decryption_keys`], as [`decryption_attempts`] does, so that what the
/// pickers offer on the strength of this is what the operation behind them
/// will find. Nothing for a certificate that is not valid under the policy,
/// which none of the three will use.
fn holds(cert: &Cert, held: &[AgentKey]) -> AgentHolds {
    let policy = crate::policy();
    let Ok(valid) = cert.with_policy(&policy, None) else {
        return AgentHolds::default();
    };
    let held_of = |keys: Vec<&Key<PublicParts, UnspecifiedRole>>| {
        choose(keys, held).map(|(_, entry)| entry.clone())
    };
    AgentHolds {
        sign: held_of(usable_keys(&valid, Purpose::Sign)),
        certify: held_of(usable_keys(&valid, Purpose::Certify)),
        decrypt: held_of(decryption_keys(&valid).collect()),
    }
}

/// A certification key for `cert`, backed by the agent: its primary key.
///
/// Certifying uses a different capability from signing messages, so this
/// cannot share `signer_for`: the certification key is the primary key and the
/// signing key is usually a subkey. The primary alone, and not whichever
/// certification-capable key the agent holds, card first: sequoia-wot checks a
/// certification against the certifier's primary key and nothing else, so a
/// certification made by a certification subkey on a card counted for nobody.
/// See [`crate::certify::certify`].
pub fn certifier_for(cert: &Cert) -> Result<sequoia_gpg_agent::KeyPair> {
    keypair_for(cert, Purpose::Certify)
}

/// [`certifier_for`] for a signature that *withdraws* a certification.
///
/// The same key, the primary. What differs is that nothing is refused on
/// account of the certificate's state: not a revoked certificate, and not an
/// expired key either. Taking back what a key already said is not new use of
/// it, so revoking your own certificate, or letting it lapse, must not also
/// freeze every endorsement you ever issued with it, and sequoia-wot honours a
/// withdrawal whatever has happened to its maker since. See
/// `revoke::certification_signer`.
///
/// `pub(crate)` where its neighbours are `pub`: it is the one entry point here
/// that does not ask about revocation, and a bypass is not something to offer
/// outside the crate that decides when it applies.
pub(crate) fn certification_withdrawer_for(cert: &Cert) -> Result<sequoia_gpg_agent::KeyPair> {
    keypair_for(cert, Purpose::WithdrawCertification)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Purpose {
    Sign,
    Certify,
    /// Certification again, for a signature that retracts one: the same key as
    /// [`Purpose::Certify`], the primary, which the revocation check lets
    /// through and the selection takes whether or not it is still alive.
    WithdrawCertification,
}

/// A signer for `cert`, backed by the agent.
///
/// Prefers a key the agent reports as being on a smartcard, so a certificate
/// whose secret exists both on a card and in a file signs on the card.
pub fn signer_for(cert: &Cert) -> Result<sequoia_gpg_agent::KeyPair> {
    keypair_for(cert, Purpose::Sign)
}

/// The agent's keypair for `purpose`: the key [`select_key`] chooses from the
/// agent's listing, handed to the agent.
///
/// This does not move any PIN prompt: the agent asks when the returned keypair
/// is *used*, not when it is built.
fn keypair_for(cert: &Cert, purpose: Purpose) -> Result<sequoia_gpg_agent::KeyPair> {
    // Ahead of `keys()`, which is what opens the socket: a request that is going
    // to be refused should not enumerate the agent's keys first, and should fail
    // saying the certificate is revoked rather than saying whatever the agent
    // says when it is not running at all.
    refuse_if_revoked_for(cert, purpose)?;
    signer(cert, &select_key(cert, purpose, &keys()?)?)
}

/// Refuses `cert` when `purpose` is new use of a key its owner has withdrawn.
///
/// The per-key filters in [`select_key`] cannot see a certificate-level
/// revocation on a subkey, so this asks separately. Refusing before the keypair
/// is built is what keeps the card quiet: it is never returned and so never
/// used, and per the note on [`keypair_for`] it is use that raises the prompt.
/// The purpose that is not new use of the key is let through: withdrawing a
/// certification, for the reason given on [`certification_withdrawer_for`].
/// Reading is not new use either, and the decryption path does not come
/// through here at all; see [`decryption_attempts`]. Matched exhaustively so
/// that a purpose added later has to say which it is.
fn refuse_if_revoked_for(cert: &Cert, purpose: Purpose) -> Result<()> {
    match purpose {
        Purpose::Sign | Purpose::Certify => crate::revoke::refuse_if_revoked(cert),
        Purpose::WithdrawCertification => Ok(()),
    }
}

/// The key of `cert` the agent should use for `purpose`, chosen from `held`,
/// the agent's listing, without asking the agent anything.
///
/// Split from [`keypair_for`], which connects, so that the choice can be tested
/// with a listing made up for the purpose: which keys each purpose allows, and
/// that a key on a smartcard is preferred, which no agent without a card can
/// show.
fn select_key(
    cert: &Cert,
    purpose: Purpose,
    held: &[AgentKey],
) -> Result<Key<PublicParts, UnspecifiedRole>> {
    let policy = crate::policy();
    let valid = cert
        .with_policy(&policy, None)
        .map_err(|_| Error::NoSecretKey(cert.fingerprint().to_hex()))?;

    choose(usable_keys(&valid, purpose), held)
        .map(|(key, _)| key.clone())
        .ok_or_else(|| Error::NoSecretKey(cert.fingerprint().to_hex()))
}

/// The keys of `valid` that `purpose` may use, whether or not the agent holds
/// them, in the certificate's order.
///
/// Shared by [`select_key`], which picks one to use, and [`holds`], which says
/// ahead of time whether there will be one to pick.
fn usable_keys<'a>(
    valid: &ValidCert<'a>,
    purpose: Purpose,
) -> Vec<&'a Key<PublicParts, UnspecifiedRole>> {
    let primary = valid.primary_key();
    match purpose {
        Purpose::Sign => valid
            .keys()
            .alive()
            .revoked(false)
            .for_signing()
            .map(|ka| ka.key())
            .collect(),
        // The primary key alone, and without asking for its certify flag,
        // which sequoia-wot does not ask for either; see `certifier_for`. Its
        // revocation is the certificate's, which `refuse_if_revoked_for` has
        // already asked about.
        Purpose::Certify => match primary.alive() {
            Ok(()) => vec![primary.key().role_as_unspecified()],
            Err(_) => Vec::new(),
        },
        Purpose::WithdrawCertification => vec![primary.key().role_as_unspecified()],
    }
}

/// The first of `keys` that `held` lists, a key on a smartcard before one in
/// the agent's own store, with the agent's entry for it.
fn choose<'k, 'h>(
    keys: impl IntoIterator<Item = &'k Key<PublicParts, UnspecifiedRole>>,
    held: &'h [AgentKey],
) -> Option<(&'k Key<PublicParts, UnspecifiedRole>, &'h AgentKey)> {
    let mut candidates: Vec<_> = keys
        .into_iter()
        .filter_map(|key| Some((key, held_as(key, held)?)))
        .collect();

    // Card first.
    candidates.sort_by_key(|(_, entry)| std::cmp::Reverse(entry.is_on_card()));
    candidates.into_iter().next()
}

/// The entry of `held` for `key`, matched by keygrip, which is what the agent
/// indexes by.
fn held_as<'h>(
    key: &Key<PublicParts, UnspecifiedRole>,
    held: &'h [AgentKey],
) -> Option<&'h AgentKey> {
    let grip = Keygrip::of(key.mpis()).ok()?.to_string();
    held.iter().find(|k| k.keygrip.eq_ignore_ascii_case(&grip))
}

/// One question for the agent while decrypting: whether `key` opens `pkesk`.
#[derive(Debug)]
pub(crate) struct Attempt<'a> {
    /// The certificate `key` was found on, which a message it opens is
    /// credited to.
    ///
    /// It is also what Sequoia checks the intended recipients a signature in
    /// that message names against, so which certificate this is decides
    /// whether a signed message reads as meant for its reader, one someone
    /// sent on and one that was meant for them alike.
    /// [`decryption_attempts`] takes each key once, on the first certificate
    /// in the store's order that carries it, and that need not be the
    /// reader's; see `ops::Helper`'s `decrypt`.
    pub(crate) cert: &'a Cert,
    pub(crate) key: Key<PublicParts, UnspecifiedRole>,
    pub(crate) pkesk: &'a PKESK,
    /// Whether the agent reports `key` on a smartcard.
    pub(crate) on_card: bool,
}

impl Attempt<'_> {
    /// Whether the agent turning this attempt down is its answer for the whole
    /// message, so that nothing more is asked; see `ops::through_agent`.
    ///
    /// It is, except where the packet names no key and the key is RSA on a
    /// smartcard. Such a packet may be another recipient's, and [`could_open`]
    /// cannot keep away every one made for another RSA key: what it carries is
    /// in range for this key too whenever it is smaller than this modulus,
    /// which for keys of one size it is more often than not. For a key in its
    /// own store the agent hands back whatever the decryption gives, and
    /// sequoia-ipc checks it on this side, where a packet that is not this
    /// key's fails without a word. An RSA card removes the padding itself and
    /// answers such a packet with an error instead, as it answers a cancelled
    /// PIN prompt, and too little of either answer reaches rPGP to tell the
    /// two apart (see [`refusal`]). Ending there would leave a message sent to
    /// several hidden RSA recipients unreadable on the card whenever another's
    /// packet came before this key's, however often it was tried. So the
    /// attempts go on, and for such a message a cancelled prompt goes up again
    /// for each packet left. So does the prompt after a wrong PIN, which
    /// gpg-agent passes on from the card as an error rather than asking again
    /// itself, and each wrong PIN entered there uses up one of the card's
    /// tries.
    ///
    /// An ECDH key, on a card or not, turns another key's packet into a
    /// shared secret that fails on this side in the same quiet way, and needs
    /// no exception, unless the packet's point is not on its curve at all; see
    /// [`could_open`] for that.
    pub(crate) fn refusal_is_final(&self) -> bool {
        use sequoia_openpgp::crypto::mpi::PublicKey;

        self.pkesk.recipient().is_some()
            || !self.on_card
            || !matches!(self.key.mpis(), PublicKey::RSA { .. })
    }
}

/// What to ask the agent, and in what order, to open a message whose
/// session-key packets are `pkesks`, given the certificates in the store.
///
/// A packet names the key it was encrypted to, or no key at all when the
/// sender hid its recipients. Each packet is tried only with a key it could be
/// for: the one it names, or, for one that names none, each key whose shape
/// it fits (see [`could_open`]). The agent opens a packet with whichever key
/// it is told to use and does not compare the two, so asking it with any other
/// key is a private-key operation, and on a card a PIN prompt, that cannot
/// succeed. That is what the certificate's first held encryption key used to
/// be whenever the agent held two: a subkey kept after a rotation, or an old
/// file key beside a new card key, left every message to the one that sorted
/// second unreadable, and on a card asked for the PIN of the wrong key first.
///
/// The same test on what a hidden packet carries keeps most packets made for
/// someone else's key away from the agent, but not all: one for another RSA
/// key of the same size fits this key's shape more often than not, and one
/// for an ECDH key on a curve whose points are written the same way always
/// does. Put to an RSA key on a card the first is turned down, and
/// [`Attempt::refusal_is_final`] says why that does not end the decryption.
///
/// Encryption keys only, of both kinds, and each key taken once however many
/// flags or certificates carry it, since every attempt can be a card
/// operation. Deliberately *not* filtered by alive or revoked, as on the local
/// path in `ops`: revoking or retiring a key withdraws it from future use, it
/// does not burn the archive, and old mail must stay readable after the subkey
/// it was sent to has expired or been retired.
///
/// A key is asked about every packet it could open, even two that name it.
/// Sequoia hands over the packets of every container it has opened on the way
/// to this one, so a message encrypted twice to one key names that key in two
/// packets, and only the inner one opens the inner container.
///
/// Packets that name a key come first, then those that name none, and within
/// each the keys the agent reports on a smartcard before those in its own
/// store, then in the store's order. A named packet is almost certainly the one
/// that opens the message; trying it first keeps a guess at a hidden recipient
/// from putting up a prompt the named one would not have needed.
///
/// `held` is the agent's listing, asked for only when some key here could open
/// some packet: a message with no packet for a key, which is every message
/// encrypted to a password alone, or one addressed to nobody in the store,
/// never reaches the agent.
pub(crate) fn decryption_attempts<'a>(
    pkesks: &'a [PKESK],
    certs: impl IntoIterator<Item = &'a Cert>,
    held: impl FnOnce() -> Vec<AgentKey>,
) -> Vec<Attempt<'a>> {
    let policy = crate::policy();

    let mut seen: HashSet<Fingerprint> = HashSet::new();
    let mut addressed: Vec<(&'a Cert, Key<PublicParts, UnspecifiedRole>)> = Vec::new();
    for cert in certs {
        let Ok(valid) = cert.with_policy(&policy, None) else {
            continue;
        };
        for key in decryption_keys(&valid) {
            if pkesks.iter().any(|pkesk| could_open(key, pkesk)) && seen.insert(key.fingerprint()) {
                addressed.push((cert, key.clone()));
            }
        }
    }
    if addressed.is_empty() {
        return Vec::new();
    }

    let held = held();
    let mut keys: Vec<(bool, &'a Cert, Key<PublicParts, UnspecifiedRole>)> = addressed
        .into_iter()
        .filter_map(|(cert, key)| {
            let on_card = held_as(&key, &held)?.is_on_card();
            Some((on_card, cert, key))
        })
        .collect();
    keys.sort_by_key(|(on_card, ..)| std::cmp::Reverse(*on_card));

    let mut attempts = Vec::new();
    for named in [true, false] {
        for (on_card, cert, key) in &keys {
            for pkesk in pkesks {
                if pkesk.recipient().is_some() == named && could_open(key, pkesk) {
                    attempts.push(Attempt {
                        cert,
                        key: key.clone(),
                        pkesk,
                        on_card: *on_card,
                    });
                }
            }
        }
    }
    attempts
}

/// The keys of `valid` a message could have been encrypted to: encryption keys
/// of both kinds, with no test of alive or revoked, for the reason
/// [`decryption_attempts`] gives. A key carrying both flags comes twice.
///
/// Shared with [`holds`], so that what the survey says the agent can decrypt
/// with is what a decryption will ask it about.
fn decryption_keys<'a>(
    valid: &ValidCert<'a>,
) -> impl Iterator<Item = &'a Key<PublicParts, UnspecifiedRole>> + use<'a> {
    valid
        .keys()
        .for_transport_encryption()
        .chain(valid.keys().for_storage_encryption())
        .map(|ka| ka.key())
}

/// Whether `pkesk` could have been made for `key`, judged from the packet: it
/// names `key` or names nothing, and what it carries is shaped for `key`.
///
/// The shape is the algorithm; for ECDH, an ephemeral point encoded as the
/// key's curve encodes its points; and for RSA, a ciphertext smaller than the
/// modulus. A hidden recipient's packet says nothing else about whom it is
/// for, and these are what a message to several hidden recipients differs in.
///
/// The encoding tells Curve25519 from the NIST curves, but not a NIST curve
/// from the Brainpool curve of the same size, whose points are written alike;
/// only arithmetic on the curve would, and nothing here does it. gpg-agent
/// turns down a point that is not on the key's curve, and that refusal ends
/// the decryption, so a message to hidden recipients on both kinds of curve
/// of one size does not open through the agent when a packet for the other
/// kind comes first. RSA needs no arithmetic: a ciphertext is always smaller
/// than the modulus it was made with, so one that is not was made for another
/// key, and is not worth an operation on the card.
fn could_open(key: &Key<PublicParts, UnspecifiedRole>, pkesk: &PKESK) -> bool {
    use sequoia_openpgp::crypto::mpi::{Ciphertext, PublicKey};

    if pkesk
        .recipient()
        .is_some_and(|handle| !handle.aliases(key.key_handle()))
    {
        return false;
    }
    if pkesk.pk_algo() != key.pk_algo() {
        return false;
    }
    match (pkesk.esk(), key.mpis()) {
        (Ciphertext::ECDH { e, .. }, PublicKey::ECDH { curve, .. }) => {
            e.decode_point(curve).is_ok()
        }
        (Ciphertext::RSA { c }, PublicKey::RSA { n, .. }) => c < n,
        _ => true,
    }
}

/// What the agent said, when `error` came from it: a cancelled PIN or
/// passphrase prompt, a card that is not there, no pinentry to ask with, a
/// decryption it turned down, or a connection that failed.
///
/// `None` for everything else, which is a key that did not fit: sequoia-ipc
/// finishing the decryption on this side and finding the result is not a
/// session key. That is kept quiet, as Sequoia keeps it, because saying which
/// check a packet failed tells whoever made it something about the key.
///
/// The agent's own words, and not a kind of refusal read out of them:
/// sequoia-gpg-agent 0.6.2 keeps the text of the Assuan `ERR` line and drops
/// its code (`KeyPair::decrypt_async` through `Agent::operation_failed`), and
/// the text is gpg-agent's `gpg_strerror`, which it translates into the user's
/// language. So a cancelled prompt cannot be told apart from a card that could
/// not use one packet, and matching on "Operation cancelled" would work only
/// in English.
///
/// The code is there to be had by asking another way: `Agent` is also a
/// stream of the agent's responses, and an `ERR` read from it keeps its code.
/// Sending PKDECRYPT over that stream, as `decrypt_async` does, would tell a
/// cancelled prompt from the rest and lift the rule that the first refusal
/// ends a decryption. It needs the `Stream` trait, and so futures-core as a
/// dependency of this crate, which it does not have today.
pub(crate) fn refusal(error: &anyhow::Error) -> Option<String> {
    use sequoia_gpg_agent::assuan;

    Some(match error.downcast_ref::<sequoia_gpg_agent::Error>()? {
        sequoia_gpg_agent::Error::Assuan(assuan::Error::OperationFailed(message)) => {
            message.clone()
        }
        other => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use sequoia_openpgp::cert::prelude::SubkeyRevocationBuilder;
    use sequoia_openpgp::cert::{CertBuilder, CipherSuite, KeyBuilder};
    use sequoia_openpgp::crypto::SessionKey;
    use sequoia_openpgp::crypto::mpi::{Ciphertext, MPI, PublicKey};
    use sequoia_openpgp::packet::PKESK;
    use sequoia_openpgp::packet::pkesk::PKESK3;
    use sequoia_openpgp::types::{
        KeyFlags, PublicKeyAlgorithm, ReasonForRevocation, SymmetricAlgorithm,
    };

    use super::*;

    /// A key as generated here, to RFC 4880: GnuPG 2.4 has no version 6 keys,
    /// and sequoia-ipc derives no keygrip for one, so no agent could hold it.
    fn generated(user_id: &str) -> Cert {
        let mut request = crate::keygen::KeyGenRequest::new(user_id);
        request.standard = crate::keygen::Standard::Rfc4880;
        crate::keygen::generate(&request).unwrap().cert
    }

    /// `cert` with an RSA encryption subkey added, of the smallest size the
    /// standard policy accepts: a larger one takes this build many seconds
    /// to generate.
    fn with_rsa_key(cert: Cert) -> Cert {
        let policy = crate::policy();
        KeyBuilder::new(KeyFlags::empty().set_transport_encryption())
            .set_cipher_suite(CipherSuite::RSA2k)
            .subkey(cert.with_policy(&policy, None).unwrap())
            .unwrap()
            .attach_cert()
            .unwrap()
    }

    /// What the agent lists for `keys`: each by its keygrip, on the card
    /// `card` names or in the agent's own store.
    fn listing<'k>(
        keys: impl IntoIterator<Item = &'k Key<PublicParts, UnspecifiedRole>>,
        card: Option<&str>,
    ) -> Vec<AgentKey> {
        keys.into_iter()
            .map(|key| AgentKey {
                keygrip: Keygrip::of(key.mpis()).unwrap().to_string(),
                card_serial: card.map(str::to_owned),
            })
            .collect()
    }

    /// `cert`'s encryption keys, the transport key first. A key generated here
    /// has one of each kind, which is the shape a message to the second one
    /// could not be opened through: the agent was handed the first.
    fn encryption_keys(cert: &Cert) -> Vec<Key<PublicParts, UnspecifiedRole>> {
        let policy = crate::policy();
        let valid = cert.with_policy(&policy, None).unwrap();
        valid
            .keys()
            .for_transport_encryption()
            .chain(valid.keys().for_storage_encryption())
            .map(|ka| ka.key().clone())
            .collect()
    }

    fn packet_for(key: &Key<PublicParts, UnspecifiedRole>) -> PKESK {
        let session_key = SessionKey::new(32).unwrap();
        PKESK3::for_recipient(SymmetricAlgorithm::AES256, &session_key, key)
            .unwrap()
            .into()
    }

    /// A packet for `key` that names no recipient, as `gpg --throw-keyids`
    /// writes it.
    fn hidden_packet_for(key: &Key<PublicParts, UnspecifiedRole>) -> PKESK {
        let session_key = SessionKey::new(32).unwrap();
        let mut pkesk =
            PKESK3::for_recipient(SymmetricAlgorithm::AES256, &session_key, key).unwrap();
        pkesk.set_recipient(None);
        pkesk.into()
    }

    /// Which key each attempt asks with, and whether its packet names one.
    fn asked(attempts: &[Attempt<'_>]) -> Vec<(Fingerprint, bool)> {
        attempts
            .iter()
            .map(|a| (a.key.fingerprint(), a.pkesk.recipient().is_some()))
            .collect()
    }

    /// A packet goes to the key it names and to no other, whichever of a
    /// certificate's encryption keys that is.
    ///
    /// The agent used to be handed the certificate's first encryption key it
    /// held, card first and then in Sequoia's order, which follows the key
    /// material rather than age or anything the packet says. A key generated
    /// here has two, one for each kind, so held by the agent one of the two
    /// could never be opened through it: which one depended on the key.
    #[test]
    fn a_packet_is_put_to_the_key_it_names_and_no_other() {
        let alice = generated("Alice <alice@example.org>");
        let keys = encryption_keys(&alice);
        assert_eq!(keys.len(), 2, "premise: a transport and a storage key");
        let held = listing(&keys, None);

        for key in &keys {
            let pkesks = [packet_for(key)];
            let attempts = decryption_attempts(&pkesks, [&alice], || held.clone());
            assert_eq!(
                asked(&attempts),
                [(key.fingerprint(), true)],
                "the packet names {}",
                key.fingerprint()
            );
            assert_eq!(attempts[0].cert.fingerprint(), alice.fingerprint());
        }
    }

    /// A key two packets name is asked about both, and not about one only.
    ///
    /// Sequoia hands over the packets of every container it has opened on the
    /// way to the one it is opening, so a message encrypted twice to one key
    /// names that key in two packets, and only the inner one opens the inner
    /// container. Asking the key about the first packet that names it, and no
    /// other, would leave such a message unopened.
    #[test]
    fn a_key_two_packets_name_is_asked_about_both() {
        let alice = generated("Alice <alice@example.org>");
        let keys = encryption_keys(&alice);
        let held = listing(&keys, None);

        // The storage key, which comes second, so that asking the first held
        // key about everything would not pass either.
        let pkesks = [packet_for(&keys[1]), packet_for(&keys[1])];
        let attempts = decryption_attempts(&pkesks, [&alice], || held.clone());
        assert_eq!(
            asked(&attempts),
            [(keys[1].fingerprint(), true), (keys[1].fingerprint(), true)]
        );
        assert!(
            std::ptr::eq(attempts[0].pkesk, &pkesks[0])
                && std::ptr::eq(attempts[1].pkesk, &pkesks[1]),
            "one packet was asked about twice and the other not at all"
        );
    }

    /// A packet that names no key is put to every held key it could be for,
    /// and to each only once, however many flags or certificates carry it:
    /// every attempt can be a card operation.
    #[test]
    fn a_hidden_packet_is_put_to_each_held_key_once() {
        let (both, _) = CertBuilder::new()
            .add_userid("Both <both@example.org>")
            .add_subkey(
                KeyFlags::empty()
                    .set_transport_encryption()
                    .set_storage_encryption(),
                None,
                None,
            )
            .generate()
            .unwrap();
        let keys = encryption_keys(&both);
        assert_eq!(
            keys.len(),
            2,
            "premise: one key, listed once for each flag it carries"
        );
        assert_eq!(keys[0].fingerprint(), keys[1].fingerprint());
        let held = listing(&keys[..1], None);

        let pkesks = [hidden_packet_for(&keys[0])];
        // The same certificate twice stands for a key that two certificates
        // carry, which nothing stops a stranger's certificate doing.
        let attempts = decryption_attempts(&pkesks, [&both, &both], || held.clone());
        assert_eq!(asked(&attempts), [(keys[0].fingerprint(), false)]);

        let alice = generated("Alice <alice@example.org>");
        let keys = encryption_keys(&alice);
        let held = listing(&keys, None);
        let pkesks = [hidden_packet_for(&keys[0])];
        let attempts = decryption_attempts(&pkesks, [&alice], || held.clone());
        assert_eq!(
            asked(&attempts),
            [
                (keys[0].fingerprint(), false),
                (keys[1].fingerprint(), false)
            ],
            "a hidden recipient could be either encryption key, and nothing else"
        );
    }

    /// Packets that name a key are tried before those that name none, and a
    /// key on a smartcard before one in the agent's own store.
    #[test]
    fn named_packets_come_first_and_a_card_before_the_agents_store() {
        let alice = generated("Alice <alice@example.org>");
        let bob = generated("Bob <bob@example.org>");
        let on_card = encryption_keys(&alice).remove(0);
        let in_file = encryption_keys(&bob).remove(0);
        let mut held = listing([&on_card], Some("D2760001240100000006"));
        held.extend(listing([&in_file], None));

        // Bob's store comes first and the hidden packet first in the message,
        // so neither order is what puts the card ahead or the named packet
        // first.
        let pkesks = [hidden_packet_for(&on_card), packet_for(&in_file)];
        let attempts = decryption_attempts(&pkesks, [&bob, &alice], || held.clone());
        assert_eq!(
            asked(&attempts),
            [
                (in_file.fingerprint(), true),
                (on_card.fingerprint(), false),
                (in_file.fingerprint(), false),
            ]
        );
    }

    /// A packet that names no key is not put to a key it cannot be for: one of
    /// another algorithm, an ECDH packet whose ephemeral point is encoded for
    /// another curve, or an RSA packet carrying a number no smaller than the
    /// key's modulus. Each would be a private-key operation that cannot
    /// succeed, and on a card a PIN prompt. The agent would refuse the first
    /// two, and that refusal ends the decryption, so a message to several
    /// hidden recipients would stop at the first that was someone else's.
    #[test]
    fn a_hidden_packet_shaped_for_another_key_is_not_put_to_this_one() {
        let alice = generated("Alice <alice@example.org>");
        let keys = encryption_keys(&alice);
        let held = listing(&keys, None);

        // An ECDH packet for a NIST P-256 key: its point is 65 octets and
        // starts 0x04, where a Curve25519 point is 33 and starts 0x40.
        let p256 = PKESK3::new(
            None,
            PublicKeyAlgorithm::ECDH,
            Ciphertext::ECDH {
                e: MPI::new(&[0x04; 65]),
                key: vec![0; 40].into_boxed_slice(),
            },
        )
        .unwrap();
        #[allow(deprecated)]
        let rsa = PKESK3::new(
            None,
            PublicKeyAlgorithm::RSAEncryptSign,
            Ciphertext::RSA {
                c: MPI::new(&[0x42; 384]),
            },
        )
        .unwrap();
        let pkesks = [PKESK::from(p256), PKESK::from(rsa)];
        let attempts = decryption_attempts(&pkesks, [&alice], || held.clone());
        assert!(attempts.is_empty(), "asked: {:?}", asked(&attempts));

        // The same key, asked about a packet shaped for it, is asked.
        let pkesks = [hidden_packet_for(&keys[0])];
        assert!(!decryption_attempts(&pkesks, [&alice], || held.clone()).is_empty());

        // An RSA packet of the key's length, but carrying a number at or
        // above its modulus, as one for another key of that size can: nothing
        // made with this key is that large. Below the modulus, it could be for
        // this key and is put to it.
        let bob = with_rsa_key(generated("Bob <bob@example.org>"));
        let rsa = encryption_keys(&bob)
            .into_iter()
            .find(|key| matches!(key.mpis(), PublicKey::RSA { .. }))
            .expect("premise: an RSA key");
        let PublicKey::RSA { n, .. } = rsa.mpis() else {
            unreachable!()
        };
        let held = listing(encryption_keys(&bob).iter(), None);
        let carrying = |c: Vec<u8>| -> PKESK {
            PKESK3::new(None, rsa.pk_algo(), Ciphertext::RSA { c: MPI::new(&c) })
                .unwrap()
                .into()
        };
        let mut above = n.value().to_vec();
        *above.last_mut().unwrap() = 0xff;
        let pkesks = [carrying(above)];
        let attempts = decryption_attempts(&pkesks, [&bob], || held.clone());
        assert!(attempts.is_empty(), "asked: {:?}", asked(&attempts));
        let mut below = n.value().to_vec();
        below[0] >>= 1;
        let pkesks = [carrying(below)];
        let attempts = decryption_attempts(&pkesks, [&bob], || held.clone());
        assert_eq!(asked(&attempts), [(rsa.fingerprint(), false)]);
    }

    /// An encryption key its owner has retired, or that has expired, is still
    /// asked about the packets made for it, as the local path does: revoking a
    /// key withdraws it from future use, it does not burn the archive. This is
    /// the rule the agent's path lost once already, filtering by alive and not
    /// revoked, so that a retired card key could not read its own mail.
    #[test]
    fn a_retired_or_expired_encryption_key_is_still_asked() {
        let alice = generated("Alice <alice@example.org>");
        let retired = encryption_keys(&alice).remove(0);
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
        let alice = alice.insert_packets(revocation).unwrap().0;
        let policy = crate::policy();
        assert!(
            alice
                .with_policy(&policy, None)
                .unwrap()
                .keys()
                .revoked(false)
                .all(|ka| ka.key().fingerprint() != retired.fingerprint()),
            "premise: the subkey is revoked"
        );

        let pkesks = [packet_for(&retired)];
        let held = listing([&retired], Some("D2760001240100000006"));
        let attempts = decryption_attempts(&pkesks, [&alice], || held.clone());
        assert_eq!(asked(&attempts), [(retired.fingerprint(), true)]);

        // Made two days ago to last one.
        let day = Duration::from_secs(24 * 60 * 60);
        let (lapsed, _) = CertBuilder::new()
            .add_userid("Lapsed <lapsed@example.org>")
            .set_creation_time(SystemTime::now() - 2 * day)
            .set_validity_period(day)
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();
        let key = lapsed
            .keys()
            .subkeys()
            .next()
            .unwrap()
            .key()
            .clone()
            .role_into_unspecified();
        assert!(
            lapsed
                .with_policy(&policy, None)
                .unwrap()
                .keys()
                .alive()
                .all(|ka| ka.key().fingerprint() != key.fingerprint()),
            "premise: the subkey has expired"
        );
        let pkesks = [packet_for(&key)];
        let held = listing([&key], None);
        let attempts = decryption_attempts(&pkesks, [&lapsed], || held.clone());
        assert_eq!(asked(&attempts), [(key.fingerprint(), true)]);
    }

    /// Nothing here could open a message with no packet for a key, which is
    /// every message encrypted to a password alone, or one addressed only to
    /// keys the store does not have, so neither asks the agent what it holds.
    #[test]
    fn a_message_no_key_here_could_open_does_not_ask_the_agent() {
        let alice = generated("Alice <alice@example.org>");
        let stranger = generated("Stranger <stranger@example.org>");
        let not_asked = || -> Vec<AgentKey> { panic!("the agent was asked what it holds") };

        assert!(decryption_attempts(&[], [&alice], not_asked).is_empty());
        let pkesks: Vec<PKESK> = encryption_keys(&stranger).iter().map(packet_for).collect();
        assert!(decryption_attempts(&pkesks, [&alice], not_asked).is_empty());

        // And when some key here could open it, the agent is asked once.
        let asked = std::cell::Cell::new(0);
        let pkesks: Vec<PKESK> = encryption_keys(&alice).iter().map(packet_for).collect();
        decryption_attempts(&pkesks, [&alice, &stranger], || {
            asked.set(asked.get() + 1);
            Vec::new()
        });
        assert_eq!(asked.get(), 1);
    }

    /// Signing takes a live signing key, one on a card before one in the
    /// agent's own store, and passes over a key its owner has retired.
    #[test]
    fn signing_prefers_a_card_and_passes_over_a_retired_key() {
        let (cert, _) = CertBuilder::new()
            .add_userid("Alice <alice@example.org>")
            .add_signing_subkey()
            .add_signing_subkey()
            .generate()
            .unwrap();
        let signing: Vec<Key<PublicParts, UnspecifiedRole>> = cert
            .keys()
            .subkeys()
            .map(|ka| ka.key().clone().role_into_unspecified())
            .collect();
        let (first, second) = (&signing[0], &signing[1]);

        for (card, file) in [(first, second), (second, first)] {
            let mut held = listing([file], None);
            held.extend(listing([card], Some("D2760001240100000006")));
            let chosen = select_key(&cert, Purpose::Sign, &held).unwrap();
            assert_eq!(chosen.fingerprint(), card.fingerprint());
        }

        // Retire the first and put it on the card: a key its owner has
        // retired is passed over however the agent holds it.
        let mut signer = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap()
            .into_keypair()
            .unwrap();
        let subkey = cert
            .keys()
            .subkeys()
            .find(|ka| ka.key().fingerprint() == first.fingerprint())
            .unwrap();
        let revocation = SubkeyRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"rotated")
            .unwrap()
            .build(&mut signer, &cert, subkey.key(), None)
            .unwrap();
        let cert = cert.insert_packets(revocation).unwrap().0;
        let mut held = listing([first], Some("D2760001240100000006"));
        held.extend(listing([second], None));
        let chosen = select_key(&cert, Purpose::Sign, &held).unwrap();
        assert_eq!(
            chosen.fingerprint(),
            second.fingerprint(),
            "signed with a key its owner retired, because it was on the card"
        );
    }

    /// Certifying takes the primary key and nothing else, and only while it is
    /// alive; withdrawing a certification takes it whatever its state.
    #[test]
    fn certifying_takes_the_primary_alone_and_only_while_it_is_alive() {
        let alice = generated("Alice <alice@example.org>");
        let primary = alice.primary_key().key().clone().role_into_unspecified();
        let subkeys: Vec<_> = alice
            .keys()
            .subkeys()
            .map(|ka| ka.key().clone().role_into_unspecified())
            .collect();

        let everything = listing(std::iter::once(&primary).chain(&subkeys), None);
        let chosen = select_key(&alice, Purpose::Certify, &everything).unwrap();
        assert_eq!(chosen.fingerprint(), primary.fingerprint());
        assert!(
            select_key(&alice, Purpose::Certify, &listing(&subkeys, Some("D276"))).is_err(),
            "certified with a subkey, which sequoia-wot credits to nobody"
        );

        let day = Duration::from_secs(24 * 60 * 60);
        let (lapsed, _) = CertBuilder::new()
            .add_userid("Lapsed <lapsed@example.org>")
            .set_creation_time(SystemTime::now() - 2 * day)
            .set_validity_period(day)
            .generate()
            .unwrap();
        let primary = lapsed.primary_key().key().clone().role_into_unspecified();
        let held = listing([&primary], None);
        assert!(select_key(&lapsed, Purpose::Certify, &held).is_err());
        let chosen = select_key(&lapsed, Purpose::WithdrawCertification, &held).unwrap();
        assert_eq!(chosen.fingerprint(), primary.fingerprint());
    }

    /// With the primary key kept offline and the subkeys on a card, the layout
    /// most YubiKey guides recommend, the agent signs and decrypts for the
    /// certificate but does not certify for it, since certifying takes the
    /// primary. The survey used to give one answer for all three, from the
    /// signing keys, and the certify dialog listed such a card as a certifier
    /// that then failed for want of the primary.
    #[test]
    fn a_card_holding_only_the_subkeys_signs_and_decrypts_but_does_not_certify() {
        let alice = generated("Alice <alice@example.org>");
        let subkeys: Vec<_> = alice
            .keys()
            .subkeys()
            .map(|ka| ka.key().clone().role_into_unspecified())
            .collect();
        let held = listing(&subkeys, Some("D2760001240100000006"));

        let found = holds(&alice, &held);
        assert!(
            found.sign.as_ref().is_some_and(AgentKey::is_on_card),
            "the card's signing key was not found: {found:?}"
        );
        assert!(
            found.decrypt.as_ref().is_some_and(AgentKey::is_on_card),
            "the card's encryption key was not found: {found:?}"
        );
        assert!(
            found.certify.is_none(),
            "a card without the primary key was taken to certify: {found:?}"
        );
        // Which is what certifying through the agent finds, and signing too.
        assert!(select_key(&alice, Purpose::Certify, &held).is_err());
        assert!(select_key(&alice, Purpose::Sign, &held).is_ok());
    }

    /// A primary key the agent holds certifies, though the agent holds none of
    /// the certificate's signing keys, and a signing key on a card says
    /// nothing about where the primary is. The survey used to look at the
    /// signing keys alone: it missed the first, and took the card for the
    /// key that certifies in the second.
    #[test]
    fn a_held_primary_certifies_wherever_the_signing_key_is() {
        let alice = generated("Alice <alice@example.org>");
        let primary = alice.primary_key().key().clone().role_into_unspecified();
        let policy = crate::policy();
        let signing: Vec<_> = alice
            .with_policy(&policy, None)
            .unwrap()
            .keys()
            .for_signing()
            .map(|ka| ka.key().clone())
            .collect();
        assert!(
            signing.len() == 1 && signing[0].fingerprint() != primary.fingerprint(),
            "premise: one signing key, and not the primary"
        );

        let held = listing([&primary], None);
        let found = holds(&alice, &held);
        assert!(
            found.certify.as_ref().is_some_and(|key| !key.is_on_card()),
            "the primary in the agent's store was not found to certify: {found:?}"
        );
        assert!(found.sign.is_none() && found.decrypt.is_none(), "{found:?}");
        assert!(select_key(&alice, Purpose::Certify, &held).is_ok());

        let mut held = listing([&primary], None);
        held.extend(listing(&signing, Some("D2760001240100000006")));
        let found = holds(&alice, &held);
        assert!(found.sign.as_ref().is_some_and(AgentKey::is_on_card));
        assert!(
            found.certify.as_ref().is_some_and(|key| !key.is_on_card()),
            "certifying was put on the card that holds the signing key: {found:?}"
        );
    }

    /// Signs with whatever `RPGP_TEST_CERT` points at, through the developer's
    /// own agent.
    ///
    /// `#[ignore]` because it is interactive: a card key makes the agent's
    /// pinentry ask for the PIN, and an unattended run would hang on it. It
    /// points the whole test process at that agent, so run it with
    /// `--ignored`, not `--include-ignored`, or the tests beside it reach the
    /// developer's agent too.
    #[test]
    #[ignore = "interactive: the agent will prompt for a PIN or passphrase"]
    fn signs_through_the_agent() {
        let Some(path) = std::env::var_os("RPGP_TEST_CERT") else {
            eprintln!("RPGP_TEST_CERT unset; skipping");
            return;
        };
        set_home(AgentHome::User);

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

    /// Decrypting to, and certifying with, a card key. Interactive, and run
    /// alone, for the same reasons as `signs_through_the_agent`.
    #[test]
    #[ignore = "interactive: the agent will prompt for a PIN or passphrase"]
    fn decrypts_and_certifies_through_the_agent() {
        let Some(path) = std::env::var_os("RPGP_TEST_CERT") else {
            eprintln!("RPGP_TEST_CERT unset; skipping");
            return;
        };
        set_home(AgentHome::User);

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

        // Surface whichever of the two steps is actually failing: what the
        // decryption would ask the agent, and what the agent answers.
        {
            use sequoia_openpgp::crypto::Decryptor;
            let pkesks: Vec<PKESK> = sequoia_openpgp::PacketPile::from_bytes(&ciphertext)
                .unwrap()
                .into_children()
                .filter_map(|packet| match packet {
                    sequoia_openpgp::Packet::PKESK(pkesk) => Some(pkesk),
                    _ => None,
                })
                .collect();
            let held = keys().unwrap();
            for attempt in decryption_attempts(&pkesks, [&card], || held.clone()) {
                match signer(attempt.cert, &attempt.key) {
                    Ok(mut pair) => {
                        eprintln!(
                            "  asking the agent with key {}",
                            pair.public().fingerprint()
                        );
                        // PKESK::decrypt swallows the Decryptor error into
                        // None; call the decryptor directly to see it.
                        match pair.decrypt(attempt.pkesk.esk(), None) {
                            Ok(_) => eprintln!("  decryptor.decrypt: ok"),
                            Err(e) => eprintln!("  decryptor.decrypt: {e:#}"),
                        }
                    }
                    Err(e) => eprintln!("  signer failed: {e}"),
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
    /// certificate offered via `RPGP_TEST_CERT`.
    ///
    /// `#[ignore]` because it asks the developer's own agent, which only a test
    /// run for the purpose may do; see [`AgentHome`], and run it alone for the
    /// reason `signs_through_the_agent` gives. The same match against an agent
    /// the test starts itself runs with the rest, in `tests/gpg_agent.rs`.
    #[test]
    #[ignore = "asks the developer's own gpg-agent about RPGP_TEST_CERT"]
    fn matches_a_certificate_to_the_agents_key() {
        let Some(path) = std::env::var_os("RPGP_TEST_CERT") else {
            eprintln!("RPGP_TEST_CERT unset; skipping");
            return;
        };
        set_home(AgentHome::User);
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
