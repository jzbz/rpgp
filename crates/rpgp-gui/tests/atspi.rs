//! A passphrase field publishes nothing on the real accessibility bus.
//!
//! tests/accessibility.rs reads Slint's own properties through the testing
//! backend, which never sees what the winit backend's AccessKit adapter makes
//! of them, and since Slint 1.18 that adapter is where a passphrase's length
//! leaked: one bullet per character, a caret, and an event for every key (see
//! `SecretField` in ui/widgets.slint). This test runs FieldProbe from
//! ui/testing/field-probe.slint as a real window under winit, types into it,
//! and reads what reached AT-SPI, as a screen reader would:
//!
//! - The passphrase field is one node, named, with the password role, focusable
//!   and editable, with no Text interface or an empty one, and no signal of
//!   any kind comes from the probe while the passphrase is typed.
//! - Focus given to that node through AT-SPI reaches the passphrase input
//!   itself, which then takes the keys.
//! - The ordinary field beside it does publish what is typed, text and events
//!   alike, so that the silence above is not typing gone nowhere, text runs no
//!   longer being published at all, or the listening not working.
//!
//! Measured with Slint 1.18.1, against a password TextInput as Field used to
//! hold a passphrase: with its placeholder an accessible Text, as Field's is,
//! there were two nodes named Passphrase before anything was typed; with the
//! placeholder taken out of the tree, the probe sent 14 signals while the
//! passphrase was typed, a text insertion and a caret move for each key.
//! Against SecretField with its decoy 1px square instead of 0x0, the field
//! sent a caret move as it took focus; with the decoy after the real input,
//! the same 14 signals as Field.
//!
//! Linux only, since AT-SPI is; elsewhere `main` does nothing. No test
//! harness (`harness = false` in Cargo.toml), because winit wants the main
//! thread: the binary runs itself a second time as the probe window, told so
//! by RPGP_ATSPI_CHILD, and drives it over its stdin and stdout.
//!
//! It needs Xvfb, dbus-daemon, at-spi-bus-launcher and at-spi2-registryd. It
//! skips without them, or fails when RPGP_TEST_REQUIRE_ATSPI=1, as CI sets on
//! Linux so that the check cannot quietly stop running there.
//!
//! Nothing here touches the desktop it runs on. Everything is started with an
//! emptied environment, so neither the user's session bus nor their AT-SPI
//! bus (AT_SPI_BUS_ADDRESS, which Flatpak sandboxes and some desktops set and
//! AccessKit reads first) is ever reached, and no WAYLAND_DISPLAY sends the
//! window to their compositor. Each process gets a scratch HOME, XDG
//! directories and runtime directory, GSETTINGS_BACKEND=memory, because the
//! bus launcher writes GSettings' toolkit-accessibility key when IsEnabled is
//! set, and ATSPI_DBUS_IMPLEMENTATION=dbus-daemon, because with dbus-broker the
//! launcher activates services through the user's systemd. The session bus's
//! configuration names no service directory, so nothing can be activated on
//! it, and the registry is started here rather than left to the accessibility
//! bus to activate, which had one outlive a run. Every process is started with
//! a parent-death signal, so a test killed by cargo or a timeout takes them
//! with it (SIGKILLed mid-run, it left none behind, the accessibility bus's
//! own dbus-daemon included), and is otherwise stopped by pid.

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

/// AT-SPI is Linux's, and so are this test's dependencies, so elsewhere there
/// is nothing to run.
#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
mod linux {
    include!(concat!(env!("OUT_DIR"), "/field-probe.rs"));

    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{Receiver, channel};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use atspi::events::EventBodyOwned;
    use atspi::proxy::accessible::AccessibleProxy;
    use atspi::proxy::bus::{BusProxy, StatusProxy};
    use atspi::proxy::component::ComponentProxy;
    use atspi::proxy::registry::RegistryProxy;
    use atspi::proxy::text::TextProxy;
    use atspi::{Interface, Role, State};
    use futures_lite::StreamExt;
    use futures_lite::future::block_on;
    use zbus::proxy::CacheProperties;

    const NAME: &str = "a_passphrase_field_publishes_nothing_on_the_accessibility_bus";
    /// Set in the probe window's environment.
    const CHILD: &str = "RPGP_ATSPI_CHILD";
    /// What is typed into each field.
    const TYPED: &str = "hunter2";
    /// How long to let AccessKit's signals arrive after the last key.
    const SETTLE: Duration = Duration::from_secs(1);
    /// How long to let the signals that came with a change of focus arrive
    /// before typing begins.
    const QUIET: Duration = Duration::from_millis(500);
    /// How long to wait for any one thing before failing.
    const PATIENCE: Duration = Duration::from_secs(20);
    /// After this the test stops everything it started and fails, rather than
    /// hang on something that never answers.
    const WATCHDOG: Duration = Duration::from_secs(180);

    pub fn main() {
        if std::env::var_os(CHILD).is_some() {
            probe_window();
            return;
        }
        if !selected() {
            return;
        }
        println!("\nrunning 1 test");
        let tools = match Tools::find() {
            Ok(tools) => tools,
            Err(missing) => {
                if std::env::var("RPGP_TEST_REQUIRE_ATSPI").is_ok_and(|v| v == "1") {
                    println!("test {NAME} ... FAILED");
                    eprintln!(
                        "RPGP_TEST_REQUIRE_ATSPI=1, but this needs {}",
                        missing.join(", ")
                    );
                    std::process::exit(101);
                }
                println!("test {NAME} ... ignored, needs {}", missing.join(", "));
                return;
            }
        };

        let scratch = tempfile::Builder::new()
            .prefix("rpgp-atspi-")
            .tempdir()
            .expect("making a scratch directory");
        let watched = scratch.path().to_path_buf();
        std::thread::spawn(move || {
            std::thread::sleep(WATCHDOG);
            eprintln!("{NAME}: still running after {WATCHDOG:?}; stopping everything it started");
            stop_all();
            print_logs(&watched);
            let _ = std::fs::remove_dir_all(&watched);
            std::process::exit(101);
        });

        let outcome = std::panic::catch_unwind(|| run(&tools, scratch.path()));
        stop_all();
        match outcome {
            Ok(()) => {
                println!("test {NAME} ... ok");
                println!("\ntest result: ok. 1 passed; 0 failed\n");
            }
            Err(_) => {
                println!("test {NAME} ... FAILED");
                print_logs(scratch.path());
                drop(scratch);
                std::process::exit(101);
            }
        }
    }

    /// Whether the arguments cargo passed on select this test, as libtest's
    /// would: a filter it contains, `--exact` for its whole name, `--skip`,
    /// `--ignored` for ignored tests alone (this one is not), and `--list`.
    fn selected() -> bool {
        let mut filters = Vec::new();
        let mut skips = Vec::new();
        let (mut exact, mut ignored_only, mut list) = (false, false, false);
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--exact" => exact = true,
                "--ignored" => ignored_only = true,
                "--list" => list = true,
                "--skip" => skips.extend(args.next()),
                // The options that take their value as the next argument.
                "--test-threads" | "--format" | "--color" | "--logfile" | "-Z" => {
                    args.next();
                }
                _ if arg.starts_with('-') => {}
                _ => filters.push(arg),
            }
        }
        let matches = |filter: &String| {
            if exact {
                filter == NAME
            } else {
                NAME.contains(filter.as_str())
            }
        };
        let chosen = !ignored_only
            && (filters.is_empty() || filters.iter().any(matches))
            && !skips.iter().any(matches);
        if list {
            if chosen {
                println!("{NAME}: test");
            }
            return false;
        }
        chosen
    }

    /// The programs the private display and buses are made of.
    struct Tools {
        xvfb: PathBuf,
        dbus_daemon: PathBuf,
        launcher: PathBuf,
        registryd: PathBuf,
    }

    impl Tools {
        /// Where they are, or the names of those that could not be found.
        fn find() -> Result<Tools, Vec<String>> {
            let on_path = |name: &str| {
                std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                    .map(|dir| dir.join(name))
                    .find(|path| path.is_file())
            };
            // Arch keeps the two at-spi daemons in /usr/lib, Debian and Ubuntu
            // in /usr/libexec, and older Debian in a directory of their own.
            let at_spi = |name: &str| {
                ["/usr/libexec", "/usr/lib", "/usr/lib/at-spi2-core"]
                    .iter()
                    .map(|dir| Path::new(dir).join(name))
                    .find(|path| path.is_file())
            };
            let found = [
                ("Xvfb", on_path("Xvfb")),
                ("dbus-daemon", on_path("dbus-daemon")),
                ("at-spi-bus-launcher", at_spi("at-spi-bus-launcher")),
                ("at-spi2-registryd", at_spi("at-spi2-registryd")),
            ];
            let missing: Vec<String> = found
                .iter()
                .filter(|(_, path)| path.is_none())
                .map(|(name, _)| name.to_string())
                .collect();
            if !missing.is_empty() {
                return Err(missing);
            }
            let [xvfb, dbus_daemon, launcher, registryd] = found.map(|(_, path)| path.unwrap());
            Ok(Tools {
                xvfb,
                dbus_daemon,
                launcher,
                registryd,
            })
        }
    }

    /// Every process this test started, in the order it started them.
    static CHILDREN: Mutex<Vec<(&'static str, Child)>> = Mutex::new(Vec::new());

    /// Stop every process this test started, last first: TERM, so that Xvfb
    /// takes its lock file and socket with it and the bus launcher its bus,
    /// then KILL for anything still there after three seconds.
    fn stop_all() {
        let mut children = CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
        while let Some((_, mut child)) = children.pop() {
            let pid = rustix::process::Pid::from_child(&child);
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if Instant::now() > deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        }
    }

    /// The environment every process here starts from, and nothing else: the
    /// caller's is dropped whole, its bus addresses and display above all.
    fn command(program: &Path, scratch: &Path) -> Command {
        let mut command = Command::new(program);
        command
            // Not even PATH. Run with none, every one of them started, and
            // so did what they start in turn, xkbcomp for Xvfb and the
            // accessibility bus's own dbus-daemon for the launcher.
            .env_clear()
            .env("HOME", scratch.join("home"))
            .env("XDG_CONFIG_HOME", scratch.join("config"))
            .env("XDG_DATA_HOME", scratch.join("data"))
            .env("XDG_CACHE_HOME", scratch.join("cache"))
            .env("XDG_RUNTIME_DIR", scratch.join("run"))
            .env("GSETTINGS_BACKEND", "memory")
            .env("ATSPI_DBUS_IMPLEMENTATION", "dbus-daemon")
            .current_dir(scratch)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        command
    }

    /// Start `command`, its stderr to a log of its own in `scratch`, with a
    /// parent-death signal so that it cannot outlive the test, and keep it to
    /// be stopped. What comes back is the pipes the test talks to it through.
    fn spawn(what: &'static str, mut command: Command, scratch: &Path) -> Taken {
        use std::os::unix::process::CommandExt;
        let log = std::fs::File::create(scratch.join("logs").join(format!("{what}.log")))
            .expect("making a log file");
        command.stderr(log);
        let parent = rustix::process::getpid();
        // SAFETY: only async-signal-safe system calls, and no allocation,
        // between fork and exec.
        unsafe {
            command.pre_exec(move || {
                rustix::process::set_parent_process_death_signal(Some(
                    rustix::process::Signal::TERM,
                ))?;
                // The test may have gone between the fork and the line above,
                // too soon for the signal.
                if rustix::process::getppid() != Some(parent) {
                    return Err(std::io::ErrorKind::Other.into());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .unwrap_or_else(|e| panic!("starting {what}: {e}"));
        let taken = take_pipes(&mut child);
        CHILDREN.lock().unwrap().push((what, child));
        taken
    }

    /// The parts of a child process the test talks to; the process itself is
    /// in [`CHILDREN`].
    struct Taken {
        pid: u32,
        stdin: Option<ChildStdin>,
        lines: Option<Receiver<String>>,
    }

    /// Take `child`'s pipes, turning its stdout into a channel of lines, which
    /// can be waited on with a timeout.
    fn take_pipes(child: &mut Child) -> Taken {
        let lines = child.stdout.take().map(|stdout| {
            let (sender, receiver) = channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            });
            receiver
        });
        Taken {
            pid: child.id(),
            stdin: child.stdin.take(),
            lines,
        }
    }

    /// The next line from `child`, within [`PATIENCE`].
    fn line_from(child: &Taken, what: &str) -> String {
        child
            .lines
            .as_ref()
            .expect("the child's stdout is piped")
            .recv_timeout(PATIENCE)
            .unwrap_or_else(|e| panic!("waiting for {what}: {e}"))
    }

    /// Ask `what` of `poll` every 50ms until it answers, within [`PATIENCE`].
    fn wait_for<T>(what: &str, mut poll: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(answer) = poll() {
                return answer;
            }
            assert!(Instant::now() < deadline, "gave up waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// A private connection to the bus at `address`. Never
    /// `Connection::session()`, which reads the caller's own address.
    fn connect(address: &str) -> zbus::Connection {
        block_on(async {
            zbus::connection::Builder::address(address)?
                .method_timeout(Duration::from_secs(10))
                .build()
                .await
        })
        .unwrap_or_else(|e| panic!("connecting to {address}: {e}"))
    }

    fn has_owner(conn: &zbus::Connection, name: &'static str) -> bool {
        let name = zbus::names::BusName::try_from(name).expect("a bus name");
        block_on(async {
            let dbus = zbus::fdo::DBusProxy::new(conn).await?;
            zbus::Result::Ok(dbus.name_has_owner(name).await?)
        })
        .unwrap_or(false)
    }

    /// One signal the probe sent on the accessibility bus.
    #[derive(Debug, Clone)]
    struct Signal {
        at: Instant,
        path: String,
        member: String,
        /// The event's kind, such as `insert` for a text change or `focused`
        /// for a change of state.
        kind: String,
        detail1: i32,
    }

    /// An accessible node, as AT-SPI names it.
    #[derive(Debug, Clone)]
    struct Node {
        name: String,
        path: String,
        role: Role,
    }

    async fn accessible<'a>(
        conn: &zbus::Connection,
        destination: &str,
        path: &str,
    ) -> zbus::Result<AccessibleProxy<'a>> {
        AccessibleProxy::builder(conn)
            .destination(destination.to_owned())?
            .path(path.to_owned())?
            .cache_properties(CacheProperties::No)
            .build()
            .await
    }

    /// Every node under the application at `app` on `conn`, depth first.
    fn nodes(conn: &zbus::Connection, app: &str) -> Vec<Node> {
        block_on(async {
            let mut found = Vec::new();
            let mut pending = vec!["/org/a11y/atspi/accessible/root".to_string()];
            while let Some(path) = pending.pop() {
                let node = accessible(conn, app, &path).await?;
                found.push(Node {
                    name: node.name().await?,
                    path: path.clone(),
                    role: node.get_role().await?,
                });
                let children = node.get_children().await?;
                pending.extend(
                    children
                        .iter()
                        .rev()
                        .map(|child| child.path_as_str().to_string()),
                );
            }
            zbus::Result::Ok(found)
        })
        .expect("reading the probe's accessibility tree")
    }

    fn states(conn: &zbus::Connection, app: &str, path: &str) -> atspi::StateSet {
        block_on(async { accessible(conn, app, path).await?.get_state().await })
            .expect("reading a node's states")
    }

    fn grab_focus(conn: &zbus::Connection, app: &str, path: &str) {
        let granted = block_on(async {
            ComponentProxy::builder(conn)
                .destination(app.to_owned())?
                .path(path.to_owned())?
                .build()
                .await?
                .grab_focus()
                .await
        })
        .expect("asking for focus through AT-SPI");
        assert!(granted, "GrabFocus on {path} was refused");
    }

    /// What a node's Text interface says: count, text and caret, or `None`
    /// for a node without one.
    fn text_of(conn: &zbus::Connection, app: &str, path: &str) -> Option<(i32, String, i32)> {
        block_on(async {
            let interfaces = accessible(conn, app, path).await?.get_interfaces().await?;
            if !interfaces.contains(Interface::Text) {
                return zbus::Result::Ok(None);
            }
            let text = TextProxy::builder(conn)
                .destination(app.to_owned())?
                .path(path.to_owned())?
                .cache_properties(CacheProperties::No)
                .build()
                .await?;
            Ok(Some((
                text.character_count().await?,
                text.get_text(0, -1).await?,
                text.caret_offset().await?,
            )))
        })
        .expect("reading a node's text")
    }

    /// Keep every signal `app` sends on `conn` from now on.
    fn record_signals(conn: &zbus::Connection, app: &str) -> Arc<Mutex<Vec<Signal>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (ready, listening) = channel();
        let (conn, app, kept) = (conn.clone(), app.to_string(), seen.clone());
        std::thread::spawn(move || {
            block_on(async move {
                let rule = zbus::MatchRule::builder()
                    .msg_type(zbus::message::Type::Signal)
                    .sender(app.as_str())
                    .expect("a bus name")
                    .build();
                let mut stream = zbus::MessageStream::for_match_rule(rule, &conn, None)
                    .await
                    .expect("listening for the probe's signals");
                let _ = ready.send(());
                while let Some(Ok(message)) = stream.next().await {
                    let header = message.header();
                    let body = message.body().deserialize::<EventBodyOwned>().ok();
                    kept.lock().unwrap().push(Signal {
                        at: Instant::now(),
                        path: header.path().map(|p| p.to_string()).unwrap_or_default(),
                        member: format!(
                            "{}.{}",
                            header
                                .interface()
                                .map(|i| i.to_string())
                                .unwrap_or_default(),
                            header.member().map(|m| m.to_string()).unwrap_or_default(),
                        ),
                        kind: body.as_ref().map(|b| b.kind.clone()).unwrap_or_default(),
                        detail1: body.as_ref().map_or(0, |b| b.detail1),
                    });
                }
            });
        });
        listening
            .recv_timeout(PATIENCE)
            .expect("listening for the probe's signals");
        seen
    }

    fn short(member: &str) -> &str {
        member.rsplit('.').next().unwrap_or(member)
    }

    /// Whether the node at `path` has announced that it gained focus.
    fn focus_announced(signals: &Mutex<Vec<Signal>>, path: &str) -> bool {
        signals.lock().unwrap().iter().any(|s| {
            s.path == path
                && short(&s.member) == "StateChanged"
                && s.kind == "focused"
                && s.detail1 == 1
        })
    }

    fn run(tools: &Tools, scratch: &Path) {
        for dir in ["home", "config", "data", "cache", "run", "logs"] {
            std::fs::create_dir(scratch.join(dir)).expect("making a scratch directory");
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(scratch.join("run"), std::fs::Permissions::from_mode(0o700))
            .expect("closing the runtime directory");

        // A display of its own, on whichever number is free.
        let mut xvfb = command(&tools.xvfb, scratch);
        xvfb.args(["-displayfd", "1", "-nolisten", "tcp", "-noreset"])
            .args(["-screen", "0", "640x480x24"])
            .stdout(Stdio::piped());
        let xvfb = spawn("Xvfb", xvfb, scratch);
        let display = format!(":{}", line_from(&xvfb, "Xvfb's display number").trim());

        // A session bus of its own, from which nothing can be activated: no
        // service directory. The policy is the stock session.conf's; without
        // its catch-all `allow`, which receiving needs, not even the reply to
        // Hello arrives.
        let config = scratch.join("session.conf");
        std::fs::write(
            &config,
            format!(
                r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
                scratch.join("session-bus").display()
            ),
        )
        .expect("writing the session bus's configuration");
        let mut dbus = command(&tools.dbus_daemon, scratch);
        dbus.arg(format!("--config-file={}", config.display()))
            .args(["--nofork", "--print-address=1"])
            .stdout(Stdio::piped());
        let dbus = spawn("dbus-daemon", dbus, scratch);
        let session_address = line_from(&dbus, "the session bus's address");
        let session = connect(&session_address);

        // The accessibility bus, and the registry on it.
        let mut launcher = command(&tools.launcher, scratch);
        launcher
            .arg("--launch-immediately")
            .env("DBUS_SESSION_BUS_ADDRESS", &session_address);
        spawn("at-spi-bus-launcher", launcher, scratch);
        wait_for("the accessibility bus launcher", || {
            has_owner(&session, "org.a11y.Bus").then_some(())
        });
        let a11y_address = block_on(async { BusProxy::new(&session).await?.get_address().await })
            .expect("asking for the accessibility bus's address");
        let a11y = connect(&a11y_address);
        let mut registryd = command(&tools.registryd, scratch);
        registryd
            .env("DBUS_SESSION_BUS_ADDRESS", &session_address)
            .env("AT_SPI_BUS_ADDRESS", &a11y_address);
        spawn("at-spi2-registryd", registryd, scratch);
        wait_for("the AT-SPI registry", || {
            has_owner(&a11y, "org.a11y.atspi.Registry").then_some(())
        });

        // Accessibility on, as a screen reader turns it on, and a listener
        // registered as one would be: the launcher turns IsEnabled off again
        // once the last registered listener has gone.
        block_on(async {
            StatusProxy::new(&session)
                .await?
                .set_is_enabled(true)
                .await?;
            let registry = RegistryProxy::new(&a11y).await?;
            for event in ["object:", "window:", "focus:"] {
                registry.register_event(event).await?;
            }
            zbus::Result::Ok(())
        })
        .expect("turning accessibility on");

        // The probe window, this binary run again.
        let mut probe = command(&std::env::current_exe().expect("this test's path"), scratch);
        probe
            .env(CHILD, "1")
            .env("DISPLAY", &display)
            .env("DBUS_SESSION_BUS_ADDRESS", &session_address)
            .env("SLINT_BACKEND", "winit-software")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut probe = spawn("probe", probe, scratch);
        let ready = line_from(&probe, "the probe window");
        assert_eq!(ready, "ready", "the probe window could not start");
        let mut stdin = probe.stdin.take().expect("the probe's stdin is piped");
        let mut tell = |what: &str| {
            writeln!(stdin, "{what}").expect("writing to the probe");
            stdin.flush().expect("writing to the probe");
        };

        // The probe on the bus, by its pid.
        let app = wait_for("the probe on the accessibility bus", || {
            block_on(async {
                let root = accessible(
                    &a11y,
                    "org.a11y.atspi.Registry",
                    "/org/a11y/atspi/accessible/root",
                )
                .await?;
                let dbus = zbus::fdo::DBusProxy::new(&a11y).await?;
                for app in root.get_children().await? {
                    let Some(name) = app.name_as_str() else {
                        continue;
                    };
                    let pid = dbus
                        .get_connection_unix_process_id(name.try_into()?)
                        .await
                        .unwrap_or(0);
                    if pid == probe.pid {
                        return zbus::Result::Ok(Some(name.to_string()));
                    }
                }
                Ok(None)
            })
            .ok()
            .flatten()
        });
        let signals = record_signals(&a11y, &app);

        let tree = wait_for("the probe's two fields on the bus", || {
            let tree = nodes(&a11y, &app);
            let fields = tree
                .iter()
                .filter(|node| node.name == "Passphrase" || node.name == "Search")
                .count();
            (fields >= 2).then_some(tree)
        });
        let named = |tree: &[Node], name: &str| -> Vec<Node> {
            tree.iter()
                .filter(|node| node.name == name)
                .cloned()
                .collect()
        };
        let secret = named(&tree, "Passphrase");
        assert_eq!(
            secret.len(),
            1,
            "the passphrase field should be one node, with no placeholder of the same name: \
             {secret:?}"
        );
        let secret = secret[0].clone();
        let plain = named(&tree, "Search")
            .into_iter()
            .find(|node| node.role == Role::Entry)
            .expect("the ordinary field on the bus");
        let window = tree
            .iter()
            .find(|node| node.role == Role::Frame)
            .expect("the probe's window on the bus")
            .clone();

        // Slint publishes focus only while its window has it, which the probe
        // gave itself on the X server.
        wait_for("the probe's window to be active", || {
            states(&a11y, &app, &window.path)
                .contains(State::Active)
                .then_some(())
        });

        // Focus through AT-SPI, as a screen reader moves it, then the
        // passphrase typed.
        //
        // The focus has to have been announced, and every signal that came
        // with it heard, before typing begins: GetState can answer Focused
        // before the signal is through, and the signal would then seem to
        // come from the typing.
        grab_focus(&a11y, &app, &secret.path);
        wait_for("the passphrase field to announce its focus", || {
            focus_announced(&signals, &secret.path).then_some(())
        });
        assert!(
            states(&a11y, &app, &secret.path).contains(State::Focused),
            "the passphrase field announced its focus, but does not have it"
        );
        std::thread::sleep(QUIET);
        let secret_began = Instant::now();
        tell("type secret");
        let typed = line_from(&probe, "the passphrase to be typed");
        assert_eq!(typed, "typed", "typing the passphrase");
        std::thread::sleep(SETTLE);
        let secret_ended = Instant::now();

        // And the same into the ordinary field.
        grab_focus(&a11y, &app, &plain.path);
        wait_for("the ordinary field to announce its focus", || {
            focus_announced(&signals, &plain.path).then_some(())
        });
        std::thread::sleep(QUIET);
        let plain_began = Instant::now();
        tell("type plain");
        let typed = line_from(&probe, "the ordinary field to be typed into");
        assert_eq!(typed, "typed", "typing into the ordinary field");
        std::thread::sleep(SETTLE);

        let signals = signals.lock().unwrap().clone();
        let during = |from: Instant, to: Instant| -> Vec<&Signal> {
            signals
                .iter()
                .filter(|s| s.at >= from && s.at < to)
                .collect()
        };

        // The ordinary field first: it is what shows that keys arrived, that
        // text is published at all, and that signals were heard.
        let from_plain: Vec<_> = during(plain_began, Instant::now())
            .into_iter()
            .filter(|s| s.path == plain.path)
            .collect();
        let count = |member: &str| {
            from_plain
                .iter()
                .filter(|s| short(&s.member) == member)
                .count()
        };
        assert!(
            count("TextChanged") >= TYPED.len() && count("TextCaretMoved") >= 1,
            "the ordinary field should publish each key and the caret: {from_plain:?}"
        );
        assert_eq!(
            text_of(&a11y, &app, &plain.path),
            Some((TYPED.len() as i32, TYPED.to_string(), TYPED.len() as i32)),
            "the ordinary field should publish its text"
        );

        // Then the passphrase field. Not a signal from anywhere in the probe
        // while it was typed: no text or caret from the field, and no child
        // added or removed anywhere, as Field's placeholder was on the first
        // key.
        let while_secret = during(secret_began, secret_ended);
        assert!(
            while_secret.is_empty(),
            "the probe published {} signal(s) while the passphrase was typed: {while_secret:?}",
            while_secret.len()
        );
        let from_secret: Vec<_> = signals
            .iter()
            .filter(|s| s.path == secret.path && short(&s.member) != "StateChanged")
            .collect();
        assert!(
            from_secret.is_empty(),
            "the passphrase field published more than its focus: {from_secret:?}"
        );

        let tree = nodes(&a11y, &app);
        let after = named(&tree, "Passphrase");
        assert_eq!(
            after.len(),
            1,
            "the passphrase field's nodes changed: {after:?}"
        );
        assert_eq!(after[0].path, secret.path);
        assert_eq!(
            after[0].role,
            Role::PasswordText,
            "the passphrase field should be announced as a password field"
        );
        let held = states(&a11y, &app, &secret.path);
        assert!(
            held.contains(State::Focusable) && held.contains(State::Editable),
            "the passphrase field should be focusable and editable: {held:?}"
        );
        if let Some(text) = text_of(&a11y, &app, &secret.path) {
            assert_eq!(
                text,
                (0, String::new(), 0),
                "the passphrase field's Text interface gives the passphrase away"
            );
        }

        tell("quit");
    }

    /// The last lines of each process's log, for a failure.
    fn print_logs(scratch: &Path) {
        let Ok(logs) = std::fs::read_dir(scratch.join("logs")) else {
            return;
        };
        for log in logs.flatten() {
            let text = std::fs::read_to_string(log.path()).unwrap_or_default();
            let lines: Vec<_> = text.lines().collect();
            let tail = &lines[lines.len().saturating_sub(40)..];
            eprintln!("--- {} ---", log.file_name().to_string_lossy());
            for line in tail {
                eprintln!("{line}");
            }
        }
    }

    /// The probe window: FieldProbe under winit, which gives itself the X
    /// server's focus, says `ready` on stdout, and then types what it is told
    /// to on stdin into whatever has focus, answering `typed` once the right
    /// field holds it.
    fn probe_window() {
        let probe = FieldProbe::new().expect("making the probe window");
        probe.show().expect("showing the probe window");

        // The X server has no window manager to give the window focus, and
        // without it Slint tells AT-SPI nothing about focus, so it takes it
        // itself, once the window exists and is mapped.
        let focus = std::rc::Rc::new(slint::Timer::default());
        let (weak, timer) = (probe.as_weak(), std::rc::Rc::downgrade(&focus));
        focus.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(50),
            move || {
                let Some(probe) = weak.upgrade() else { return };
                if take_x_focus(&probe) {
                    if let Some(timer) = timer.upgrade() {
                        timer.stop();
                    }
                    println!("ready");
                }
            },
        );

        let weak = probe.as_weak();
        std::thread::spawn(move || {
            for line in std::io::stdin().lines() {
                let Ok(line) = line else { break };
                let weak = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(probe) = weak.upgrade() {
                        obey(&probe, line.trim());
                    }
                });
            }
            // The test has gone.
            let _ = slint::quit_event_loop();
        });

        slint::run_event_loop().expect("running the probe window");
    }

    /// What a field holds, read off the probe.
    type Holds = fn(&FieldProbe) -> slint::SharedString;

    fn obey(probe: &FieldProbe, command: &str) {
        let (field, holds): (&'static str, Holds) = match command {
            "type secret" => {
                // Focus came through AT-SPI to the field's node, which is not
                // the input: it has to have reached the input itself.
                if !probe.get_secret_has_focus() {
                    println!("the passphrase input does not have focus");
                    return;
                }
                ("passphrase", FieldProbe::get_secret_text)
            }
            "type plain" => ("ordinary", FieldProbe::get_plain_text),
            "quit" => {
                let _ = slint::quit_event_loop();
                return;
            }
            other => {
                println!("no such command: {other}");
                return;
            }
        };
        type_from(probe.as_weak(), 0, field, holds);
    }

    /// Type the key of [`TYPED`] at `at` into whatever has focus, and the rest
    /// a little later, one each time round the event loop as a person types,
    /// so that AccessKit publishes what each key changed rather than all seven
    /// at once. Then say whether the field holds them.
    fn type_from(probe: slint::Weak<FieldProbe>, at: usize, field: &'static str, holds: Holds) {
        let Some(window_of) = probe.upgrade() else {
            return;
        };
        let Some(key) = TYPED.chars().nth(at) else {
            let held = holds(&window_of);
            if held == TYPED {
                println!("typed");
            } else {
                println!(
                    "the {field} field holds {} chars, not {}",
                    held.chars().count(),
                    TYPED.len()
                );
            }
            return;
        };
        let text = slint::SharedString::from(key.to_string());
        let window = window_of.window();
        window.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
        window.dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
        slint::Timer::single_shot(Duration::from_millis(40), move || {
            type_from(probe, at + 1, field, holds);
        });
    }

    /// Give the probe's window the X server's input focus, once it is mapped.
    /// Whether that was done.
    fn take_x_focus(probe: &FieldProbe) -> bool {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        use x11rb::protocol::xproto::{ConnectionExt as _, InputFocus, MapState};
        let slint_handle = probe.window().window_handle();
        let Ok(handle) = slint_handle.window_handle() else {
            return false;
        };
        let window = match handle.as_raw() {
            RawWindowHandle::Xlib(xlib) => xlib.window as u32,
            RawWindowHandle::Xcb(xcb) => xcb.window.get(),
            other => panic!("the probe window is not an X11 window: {other:?}"),
        };
        let (conn, _) = x11rb::connect(None).expect("connecting to the X server");
        let mapped = conn
            .get_window_attributes(window)
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .is_some_and(|attributes| attributes.map_state == MapState::VIEWABLE);
        mapped
            && conn
                .set_input_focus(InputFocus::PARENT, window, x11rb::CURRENT_TIME)
                .ok()
                .and_then(|cookie| cookie.check().ok())
                .is_some()
    }
}
