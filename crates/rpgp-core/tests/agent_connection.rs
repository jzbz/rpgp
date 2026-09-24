//! Connecting to gpg-agent: how long a connection may take, and how often
//! gpgconf runs to make one.
//!
//! sequoia-gpg-agent finds the agent by running gpgconf, which it looks up on
//! PATH, so each test here puts a stand-in first on this process's PATH for as
//! long as it runs, and puts PATH back when it ends. The stand-in writes down
//! every time it is run and with what, and then runs the real gpgconf, or, when
//! a test asks, never answers. Nothing outside this test process sees it. The
//! tests run one at a time, since PATH, and the agent rpgp-core asks, are the
//! whole process's.
//!
//! The agents they reach are their own, as in `tests/gpg_agent.rs`: started in
//! a temporary GnuPG home, told never to start scdaemon, given no pinentry that
//! could show anything, and stopped when the test ends, however it ends. Where
//! GnuPG is not installed, the tests that need it skip rather than fail, unless
//! `RPGP_TEST_REQUIRE_GPG_AGENT` is set. Unix only: the stand-in is a shell
//! script.

#![cfg(unix)]

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::{Duration, Instant};

use rpgp_core::agent::{self, AgentHome};
use rpgp_core::keygen::{KeyGenRequest, Standard, generate};
use rpgp_core::{Store, ops};
use sequoia_gpg_agent::Agent;
use sequoia_openpgp::Cert;
use sequoia_openpgp::policy::StandardPolicy;

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// How long a test waits for a question to the agent before it gives up on
/// it: well past rpgp-core's five-second bound on connecting, so that only a
/// connection that bound did not hold is still waiting.
const WATCHDOG: Duration = Duration::from_secs(30);

/// How long a connection that the bound held may have taken: five seconds,
/// and room for a machine busy running the other tests.
const BOUND: Duration = Duration::from_secs(15);

/// A stand-in for gpgconf, first on this process's PATH until it is dropped.
struct StandIn {
    dir: tempfile::TempDir,
    /// The gpgconf found on PATH before the stand-in went in front of it.
    real: Option<PathBuf>,
    path_before: Option<OsString>,
    _one_at_a_time: MutexGuard<'static, ()>,
}

impl StandIn {
    fn install() -> Self {
        let one_at_a_time = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
        let path_before = std::env::var_os("PATH");
        let searched: Vec<PathBuf> = path_before
            .as_ref()
            .map(|path| std::env::split_paths(path).collect())
            .unwrap_or_default();
        let real = searched
            .iter()
            .map(|dir| dir.join("gpgconf"))
            .find(|candidate| {
                std::fs::metadata(candidate)
                    .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            });

        let dir = tempfile::tempdir().unwrap();
        let at = dir.path().display().to_string();
        let run_the_real_one = match &real {
            Some(real) => format!("exec '{}' \"$@\"", real.display()),
            None => "exit 127".to_string(),
        };
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$*\" >> '{at}/calls'\n\
             if [ -e '{at}/hang' ]; then\n\
             \x20 echo $$ >> '{at}/hanging'\n\
             \x20 exec sleep 120\n\
             fi\n\
             {run_the_real_one}\n"
        );
        let gpgconf = dir.path().join("gpgconf");
        std::fs::write(&gpgconf, script).unwrap();
        std::fs::set_permissions(&gpgconf, std::fs::Permissions::from_mode(0o755)).unwrap();

        let in_front = std::iter::once(dir.path().to_path_buf()).chain(searched);
        let path = std::env::join_paths(in_front).unwrap();
        // SAFETY: every test in this file holds ONE_AT_A_TIME from before it
        // changes PATH until after it has put it back, so no other test reads
        // PATH while it changes. What else runs in this process meanwhile,
        // rpgp-core's runtime and the threads a test starts, reads the
        // environment only through std, which takes its lock on it, as
        // spawning a process does; what makes `set_var` unsafe is C code that
        // reads the environment without that lock, and none runs here.
        unsafe { std::env::set_var("PATH", path) };

        StandIn {
            dir,
            real,
            path_before,
            _one_at_a_time: one_at_a_time,
        }
    }

    /// Every run of gpgconf since the last [`StandIn::clear`], with what it
    /// was asked, less the `--homedir` it was pointed at.
    fn calls(&self) -> Vec<String> {
        let log = std::fs::read_to_string(self.dir.path().join("calls")).unwrap_or_default();
        log.lines()
            .map(|line| {
                let words: Vec<&str> = line.split(' ').collect();
                match words.as_slice() {
                    ["--homedir", _, rest @ ..] => rest.join(" "),
                    all => all.join(" "),
                }
            })
            .collect()
    }

    fn clear(&self) {
        let _ = std::fs::remove_file(self.dir.path().join("calls"));
    }

    /// From now on, gpgconf never answers.
    fn hang(&self) {
        std::fs::write(self.dir.path().join("hang"), b"").unwrap();
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        agent::set_home(AgentHome::Nowhere);
        // Each gpgconf told to hang is a `sleep` by now, with the stand-in's
        // process ID; stopping it lets go of the thread that waits on it.
        let hanging = std::fs::read_to_string(self.dir.path().join("hanging")).unwrap_or_default();
        for pid in hanging.lines() {
            let _ = Command::new("kill").arg(pid).status();
        }
        // SAFETY: as in `install`; ONE_AT_A_TIME is still held, and is let go
        // only after this returns.
        unsafe {
            match &self.path_before {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }
}

/// Whether `gpgconf` knows of a gpg-agent, installed where it says.
fn has_gpg_agent(gpgconf: &Path) -> bool {
    let Ok(output) = Command::new(gpgconf).arg("--list-components").output() else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        let mut fields = line.split(':');
        fields.next() == Some("gpg-agent") && fields.nth(1).is_some_and(|at| Path::new(at).exists())
    })
}

fn skip(reason: &str) {
    // Empty counts as unset, which is how CI's workflow leaves it on the
    // platforms that do not require it.
    if std::env::var_os("RPGP_TEST_REQUIRE_GPG_AGENT").is_some_and(|v| !v.is_empty()) {
        panic!("RPGP_TEST_REQUIRE_GPG_AGENT is set and {reason}");
    }
    eprintln!("SKIP: {reason}; is GnuPG installed?");
}

/// A GnuPG home of the test's own, whose agents are stopped, and whose socket
/// directory is removed, when this is dropped. gpgconf makes a socket
/// directory for a home as soon as it is asked about it, whether the home
/// exists or not.
struct Home {
    dir: PathBuf,
    gpgconf: PathBuf,
}

impl Home {
    /// The GnuPG home at `dir`, which [`Home::create`] makes.
    fn at(dir: &Path, gpgconf: &Path) -> Self {
        Home {
            dir: dir.to_path_buf(),
            gpgconf: gpgconf.to_path_buf(),
        }
    }

    /// Make the home, where an agent started never starts scdaemon, and has
    /// no pinentry to ask with.
    fn create(&self) {
        std::fs::create_dir(&self.dir).unwrap();
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            self.dir.join("gpg-agent.conf"),
            format!(
                "disable-scdaemon\npinentry-program {}\n",
                self.dir.join("no-pinentry").display()
            ),
        )
        .unwrap();
    }

    /// Run the real gpgconf for this home, and not the stand-in, which would
    /// write it down, and give back what it printed.
    fn gpgconf(&self, args: &[&str]) -> String {
        let output = Command::new(&self.gpgconf)
            .arg("--homedir")
            .arg(&self.dir)
            .args(args)
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn agent_socket(&self) -> PathBuf {
        PathBuf::from(self.gpgconf(&["--list-dirs", "agent-socket"]))
    }

    /// Stop the agent, as `gpgconf --kill gpg-agent` is used to reset a card,
    /// and wait until its socket is gone.
    fn stop_agent(&self) {
        self.gpgconf(&["--kill", "gpg-agent"]);
        let socket = self.agent_socket();
        let started = Instant::now();
        while socket.exists() && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!socket.exists(), "premise: the agent has stopped");
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        self.gpgconf(&["--kill", "all"]);
        self.gpgconf(&["--remove-socketdir"]);
    }
}

/// A socket that accepts every connection and never says a word, as an agent
/// that has hung does: the kernel completes a connection to it whatever the
/// agent is doing.
struct Silent {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    accepted: Arc<Mutex<Vec<UnixStream>>>,
    listening: Option<std::thread::JoinHandle<()>>,
}

impl Silent {
    fn bind(socket: &Path) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let listening = {
            let (stop, accepted) = (Arc::clone(&stop), Arc::clone(&accepted));
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        accepted.lock().unwrap().push(stream);
                    }
                }
            })
        };
        Silent {
            socket: socket.to_path_buf(),
            stop,
            accepted,
            listening: Some(listening),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.lock().unwrap().len()
    }
}

impl Drop for Silent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket);
        if let Some(listening) = self.listening.take() {
            let _ = listening.join();
        }
        // Closing what it accepted also ends whatever is still waiting on it
        // for a greeting.
        self.accepted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Ask the agent what it holds, on a thread of its own, and give back its
/// answer and how long it took, or panic if it has not answered by the time
/// [`WATCHDOG`] is up.
fn keys_within_watchdog() -> (Result<usize, String>, Duration) {
    let started = Instant::now();
    let (answer, answered) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = answer.send(
            agent::keys()
                .map(|keys| keys.len())
                .map_err(|e| e.to_string()),
        );
    });
    match answered.recv_timeout(WATCHDOG) {
        Ok(answer) => (answer, started.elapsed()),
        Err(_) => panic!("still waiting on the agent after {WATCHDOG:?}"),
    }
}

/// A key as generated here, to RFC 4880: GnuPG 2.4 has no version 6 keys.
fn key(user_id: &str) -> Cert {
    let mut request = KeyGenRequest::new(user_id);
    request.standard = Standard::Rfc4880;
    generate(&request).unwrap().cert
}

/// Give the agent at `home` every secret key of `cert`.
fn give(home: &Path, cert: &Cert) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut agent = Agent::connect_to(home).await.unwrap();
        let policy = StandardPolicy::new();
        for ka in cert.keys().secret() {
            agent
                .import(&policy, cert, ka.key().role_as_unspecified(), true, true)
                .await
                .unwrap();
        }
    });
}

/// A gpgconf that never answers holds the question to the agent no longer
/// than the bound on connecting.
///
/// The bound was a timeout around a future whose first poll ran gpgconf, four
/// times over, to completion, and a timeout is only looked at when the future
/// inside it is waiting, so it could not fire until gpgconf had exited. The
/// reload's survey, and a signature or decryption with a card key, waited for
/// as long as gpgconf did.
#[test]
fn a_gpgconf_that_never_answers_holds_the_caller_only_until_the_timeout() {
    let stand_in = StandIn::install();
    stand_in.hang();
    let dir = tempfile::tempdir().unwrap();
    agent::set_home(AgentHome::At(dir.path().to_path_buf()));

    let (answer, took) = keys_within_watchdog();
    let error = answer.expect_err("a gpgconf that never answered found an agent");
    assert!(error.contains("did not answer in time"), "{error}");
    assert!(took < BOUND, "took {took:?}");
    assert_eq!(stand_in.calls(), ["--list-dirs homedir"]);
}

/// An agent that accepts a connection and then never says a word costs the
/// bound on connecting, and nothing is launched against it.
///
/// Connecting used to have gpgconf launch an agent first, every time, and
/// gpgconf's launch waits for the agent's greeting through
/// gpg-connect-agent, so it never returned, and neither did the question: an
/// agent that had hung kept the survey after every reload, or a signature
/// with a card key, waiting for good, with a gpgconf and a gpg-connect-agent
/// left behind for each.
#[test]
fn an_agent_that_never_answers_costs_the_timeout_and_launches_nothing() {
    let stand_in = StandIn::install();
    let Some(real) = stand_in.real.clone() else {
        return skip("there is no gpgconf on PATH");
    };
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(&dir.path().join("gnupg"), &real);
    home.create();
    home.gpgconf(&["--create-socketdir"]);
    let silent = Silent::bind(&home.agent_socket());
    agent::set_home(AgentHome::At(home.dir.clone()));

    let (answer, took) = keys_within_watchdog();
    let error = answer.expect_err("a silent agent answered");
    assert!(error.contains("did not answer in time"), "{error}");
    assert!(took < BOUND, "took {took:?}");
    assert!(silent.accepted() > 0, "premise: the question reached it");
    let calls = stand_in.calls();
    assert!(
        !calls.iter().any(|call| call.starts_with("--launch")),
        "gpgconf launched an agent where one was listening: {calls:?}"
    );
}

/// gpgconf runs until an agent has answered, and after that not again, for
/// listing, matching, signing or decrypting, until the agent is gone.
///
/// Every connection used to run gpgconf four times, and every keypair made
/// one more connection just to learn the socket's path: eight runs before a
/// card was asked to sign, and four more for each key a decryption tried.
/// What gpgconf answers is kept only once an agent has answered through it,
/// so a home that did not exist yet is looked for again once it does, as it
/// is when GnuPG is first run while the app is open, and an agent that has
/// been stopped is looked for, and launched, again.
#[test]
fn gpgconf_runs_until_an_agent_answers_and_again_only_once_it_is_gone() {
    let stand_in = StandIn::install();
    let Some(real) = stand_in.real.clone() else {
        return skip("there is no gpgconf on PATH");
    };
    if !has_gpg_agent(&real) {
        return skip("gpgconf knows of no gpg-agent");
    }
    let dir = tempfile::tempdir().unwrap();
    let home = Home::at(&dir.path().join("gnupg"), &real);
    agent::set_home(AgentHome::At(home.dir.clone()));

    let missing = agent::keys().expect_err("an agent answered for a home that does not exist");
    assert_eq!(
        stand_in.calls(),
        ["--list-dirs homedir", "--list-dirs"],
        "{missing}"
    );

    home.create();
    stand_in.clear();
    agent::keys().unwrap_or_else(|e| panic!("no agent was found or started: {e}"));
    let discovered = [
        "--list-dirs homedir",
        "--list-dirs",
        "--create-socketdir",
        "--launch gpg-agent",
    ];
    assert_eq!(
        stand_in.calls(),
        discovered,
        "what was learnt of a home that did not exist was kept"
    );

    let alice = key("Alice <alice@example.org>");
    give(&home.dir, &alice);
    let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
    store.insert(&alice).unwrap();
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
    stand_in.clear();

    assert!(!agent::keys().unwrap().is_empty());
    assert!(agent::annotate(&[&public]).contains_key(&alice.fingerprint().to_hex()));
    ops::sign_detached(&public, None, b"signed by the agent", Vec::new()).unwrap();
    let mut plaintext = Vec::new();
    ops::decrypt(&store, &ciphertext, &[], &mut plaintext).unwrap();
    assert_eq!(plaintext, b"for alice");
    assert_eq!(
        stand_in.calls(),
        Vec::<String>::new(),
        "gpgconf ran again with an agent answering"
    );

    home.stop_agent();
    stand_in.clear();
    ops::sign_detached(&public, None, b"signed after a restart", Vec::new())
        .unwrap_or_else(|e| panic!("the agent was not started again: {e}"));
    assert_eq!(stand_in.calls(), discovered);
    stand_in.clear();
    agent::keys().unwrap();
    assert_eq!(stand_in.calls(), Vec::<String>::new());
}
