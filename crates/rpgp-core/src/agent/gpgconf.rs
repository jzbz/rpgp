//! Finding the agent: where gpgconf is, where it says the agent listens, and
//! having it start one when none does.
//!
//! sequoia-gpg-agent 0.6.2 can do all of this itself (`Context::new`, then
//! `Agent::connect`), but not on two of the three platforms rPGP ships for,
//! nor in the Flatpak:
//!
//! - It runs gpgconf by name, found on PATH. An app opened from the Finder,
//!   the Dock or Spotlight is given launchd's PATH,
//!   `/usr/bin:/bin:/usr/sbin:/sbin`, which has no gpgconf from Homebrew or
//!   GPG Suite in it, so on macOS no agent was found unless rPGP was started
//!   from a shell.
//! - On Windows it hands every path gpgconf prints to `cygpath`, which only a
//!   Cygwin or MSYS2 install has, and fails when that is not found. With
//!   Gpg4win alone, every connection failed before the agent was asked
//!   anything.
//! - It refuses a GnuPG home that does not exist before it looks at the
//!   socket. The Flatpak is given the host agent's socket (`xdg-run/gnupg` in
//!   its manifest) and not `~/.gnupg`, which holds the secret keys, so inside
//!   it the home never exists and the socket was never tried.
//!
//! So rPGP finds gpgconf itself, reads the agent's socket from what gpgconf
//! prints, which on Windows is already a path Windows opens, and connects to
//! that socket with `Agent::connect_to_agent`, which needs nothing else. Where
//! to look, and what to do with what gpgconf says, are decided by [`locate`]
//! and [`route`], from an environment they are handed, so that what each
//! platform does is tested on any of them.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use sequoia_gpg_agent::{Context, Error, gnupg};

/// The kinds of system whose GnuPG differs in where gpgconf is, and in how a
/// path is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    /// Linux, and every other Unix but macOS.
    Unix,
    MacOs,
    Windows,
}

impl Platform {
    /// The one this build is for.
    const OURS: Platform = if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Unix
    };

    /// gpgconf's file name.
    fn gpgconf(self) -> &'static str {
        match self {
            Platform::Windows => "gpgconf.exe",
            Platform::Unix | Platform::MacOs => "gpgconf",
        }
    }

    /// Whether `path` is absolute as this platform reads it: from the root on
    /// Unix, and from a drive or a network share on Windows.
    fn absolute(self, path: &Path) -> bool {
        let bytes = path.as_os_str().as_encoded_bytes();
        match self {
            Platform::Unix | Platform::MacOs => bytes.starts_with(b"/"),
            Platform::Windows => {
                bytes.starts_with(br"\\")
                    || matches!(bytes, [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic())
            }
        }
    }
}

/// Where GnuPG's installers for `platform` put gpgconf, for a process whose
/// PATH does not say. `var` reads an environment variable.
///
/// On macOS that is every app opened other than from a shell: launchd gives it
/// `/usr/bin:/bin:/usr/sbin:/sbin`, and it is a shell's profile that adds
/// Homebrew. Homebrew puts gpgconf in `/opt/homebrew/bin` on Apple silicon and
/// in `/usr/local/bin` on Intel, GPG Suite in `/usr/local/MacGPG2/bin` with a
/// link in `/usr/local/bin`, and MacPorts in `/opt/local/bin`. Homebrew's
/// directories come first, in case both are installed, since theirs is the
/// gpgconf a shell would have found.
///
/// On Windows, Gpg4win's installer adds its directory to PATH, but a process
/// started from something that was already running then, such as the
/// terminal Gpg4win was installed from with winget, still has the PATH from
/// before. The 32-bit GnuPG that Gpg4win 4 installs is under `Program Files
/// (x86)`, and a 64-bit one under `Program Files`.
///
/// On Linux and the other Unix systems, `/usr/bin`, where most distributions
/// and the Flatpak's runtime put GnuPG. It is on PATH almost everywhere, but
/// not where PATH is unset, and running gpgconf by name, as rPGP did before it
/// looked for gpgconf itself, found it there even then: with no PATH, `execvp`
/// searches a default one, which has `/usr/bin` in it.
fn installed(platform: Platform, var: &dyn Fn(&str) -> Option<OsString>) -> Vec<PathBuf> {
    match platform {
        Platform::Unix => vec![PathBuf::from("/usr/bin")],
        Platform::MacOs => [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/local/MacGPG2/bin",
            "/opt/local/bin",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect(),
        Platform::Windows => ["ProgramFiles(x86)", "ProgramFiles"]
            .into_iter()
            .filter_map(var)
            .map(|mut dir| {
                dir.push(r"\GnuPG\bin");
                PathBuf::from(dir)
            })
            .collect(),
    }
}

/// The gpgconf to run on `platform`: the first in a directory of `path`, the
/// entries of PATH, and failing that the first in a directory [`installed`]
/// names. `var` reads an environment variable, and `runnable` says whether a
/// file is there that can be run, which [`runnable`] does outside the tests.
///
/// PATH comes first so that a shell's choice stands when rPGP is started from
/// one. An entry of PATH that is not absolute is passed over: a shell looks
/// for it in the directory it is in, and a GUI app can be in any directory,
/// including one holding a program called gpgconf that is not GnuPG's.
fn locate(
    platform: Platform,
    path: impl IntoIterator<Item = PathBuf>,
    var: &dyn Fn(&str) -> Option<OsString>,
    runnable: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    path.into_iter()
        .filter(|dir| platform.absolute(dir))
        .chain(installed(platform, var))
        .map(|dir| dir.join(platform.gpgconf()))
        .find(|candidate| runnable(candidate))
}

/// Whether `file` is a program that can be run: a file, and on Unix one some
/// user may execute, as a shell and `execvp` look for. Either passes over a
/// gpgconf that is not, such as one left behind by an uninstall, for the next
/// on PATH, where running it would fail.
fn runnable(file: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(file)
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        file.is_file()
    }
}

/// What gpgconf says of a GnuPG home: where the home is, and where its agent
/// listens.
#[derive(Debug, PartialEq, Eq)]
struct Dirs {
    /// The home, which gpgconf names whether it exists or not.
    homedir: Option<PathBuf>,
    agent_socket: PathBuf,
}

/// Read what `gpgconf --list-dirs` printed.
///
/// One `name:value` line for each directory or socket, the value escaped as
/// `%` and two hex digits wherever it holds a colon, which would end the name,
/// a percent sign, a comma or a line break. sequoia-gpg-agent undid the first
/// alone, which is all a Windows drive letter needs. Asked for by name, the
/// two lines wanted here come without escapes, but also without their names,
/// in gpgconf's order rather than the order asked, so from a single run it
/// would not be clear which is which.
///
/// Lines ending `\r\n`, as on Windows, are read as ending `\n`, and lines with
/// no name are skipped.
fn parse(listing: &[u8]) -> Result<Dirs, Error> {
    let mut homedir = None;
    let mut agent_socket = None;
    for line in listing.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let slot = match &line[..colon] {
            b"homedir" => &mut homedir,
            b"agent-socket" => &mut agent_socket,
            _ => continue,
        };
        let value = String::from_utf8(unescape(&line[colon + 1..])).map_err(|e| e.utf8_error())?;
        *slot = Some(PathBuf::from(value));
    }
    let agent_socket = agent_socket
        .ok_or_else(|| gnupg::Error::GPGConf("gpgconf named no socket for gpg-agent".into()))?;
    Ok(Dirs {
        homedir,
        agent_socket,
    })
}

/// `value` with gpgconf's escapes undone: each `%` followed by two hex digits
/// is the byte they spell, and anything else is itself.
fn unescape(value: &[u8]) -> Vec<u8> {
    fn hex(digit: u8) -> Option<u8> {
        (digit as char).to_digit(16).map(|d| d as u8)
    }

    let mut unescaped = Vec::with_capacity(value.len());
    let mut rest = value;
    while let Some((&first, tail)) = rest.split_first() {
        if first == b'%'
            && let [high, low, after @ ..] = tail
            && let (Some(high), Some(low)) = (hex(*high), hex(*low))
        {
            unescaped.push((high << 4) | low);
            rest = after;
        } else {
            unescaped.push(first);
            rest = tail;
        }
    }
    unescaped
}

/// What to make of what gpgconf said: which socket to try, and what to do
/// when nothing answers there.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// Have gpgconf start an agent, and try the socket again: what `gpg`
    /// itself does.
    Launch,
    /// Nothing more: the home an agent started here would serve, which this
    /// holds, is not there.
    ///
    /// Inside the Flatpak it never is. The host agent's socket is shared with
    /// it, and `~/.gnupg` is not, so the host's agent, if it is running, is
    /// the whole of what the sandbox can reach, and one started inside would
    /// be the runtime's own, for a home it cannot see. Natively, a missing
    /// home is a machine where GnuPG has not been run. Nothing is started for
    /// it, as sequoia-gpg-agent started nothing, but its socket is tried
    /// first, which sequoia-gpg-agent did not do. So where systemd listens on
    /// it for gpg-agent, as some distributions set it up to, the connection
    /// has systemd start the agent, which makes the missing home as it
    /// starts, just as a first run of `gpg` would.
    Never(PathBuf),
    /// Leave both to sequoia-gpg-agent's `Context`: the gpgconf found is a
    /// Cygwin or MSYS2 build, which names a drive as `/c/` or `/cygdrive/c/`,
    /// and only `cygpath` turns such a path into one Windows opens. A PATH
    /// that holds that gpgconf holds its `cygpath` too, and this is how every
    /// connection was made before, which for such a build worked.
    Cygpath,
}

/// What to do about the agent gpgconf described in `dirs` on `platform`.
/// `exists` says whether a directory is there.
fn route(platform: Platform, dirs: &Dirs, exists: &dyn Fn(&Path) -> bool) -> Route {
    if platform == Platform::Windows && !platform.absolute(&dirs.agent_socket) {
        return Route::Cygpath;
    }
    match &dirs.homedir {
        Some(home) if !exists(home) => Route::Never(home.clone()),
        _ => Route::Launch,
    }
}

/// A gpgconf, and the home it is asked about: GnuPG's default where `homedir`
/// is `None`.
struct Gpgconf {
    program: PathBuf,
    homedir: Option<PathBuf>,
}

impl Gpgconf {
    /// What gpgconf printed when run with `args`, or why it failed, in the
    /// words sequoia-gpg-agent used.
    fn run(&self, args: &[&str]) -> Result<Vec<u8>, Error> {
        let mut command = Command::new(&self.program);
        if let Some(homedir) = &self.homedir {
            // GNUPGHOME as well, as sequoia-gpg-agent sets it: gpgconf does
            // not pass --homedir on to everything it runs (GnuPG's T4496).
            command
                .arg("--homedir")
                .arg(homedir)
                .env("GNUPGHOME", homedir);
        }
        command.args(args);
        #[cfg(windows)]
        {
            // rPGP has no console, and a console program it starts is given a
            // console window of its own, which flashes up for each run,
            // unless it is told not to be.
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        let output = command.output().map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => gnupg::Error::GPGConfMissing,
            _ => gnupg::Error::GPGConf(e.to_string()),
        })?;
        if !output.status.success() {
            return Err(gnupg::Error::GPGConf(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
            .into());
        }
        Ok(output.stdout)
    }

    /// Start the agent for this home, as sequoia-gpg-agent's `Context::start`
    /// does: make its socket directory first, as far as that works, since an
    /// agent for a home other than the default listens in one only if it is
    /// there when the agent starts.
    fn launch_agent(&self) -> Result<(), Error> {
        let _ = self.run(&["--create-socketdir"]);
        self.run(&["--launch", "gpg-agent"]).map_err(|e| match e {
            Error::GnuPG(gnupg::Error::GPGConf(message))
                if message.contains("probably not installed") =>
            {
                gnupg::Error::ComponentMissing("gpg-agent".into()).into()
            }
            e => e,
        })?;
        Ok(())
    }
}

/// Where the agent of a home listens, and how to start one there should none
/// be listening.
pub(super) struct Found {
    pub(super) socket: PathBuf,
    starter: Starter,
}

enum Starter {
    Gpgconf(Gpgconf),
    /// None is started; see [`Route::Never`].
    Never(PathBuf),
    /// See [`Route::Cygpath`].
    Sequoia(Context),
}

impl Found {
    /// Start an agent where [`Found::socket`] says, or say why none is.
    pub(super) fn start_agent(&self) -> Result<(), Error> {
        match &self.starter {
            Starter::Gpgconf(gpgconf) => gpgconf.launch_agent(),
            Starter::Never(home) => Err(anyhow::anyhow!(
                "none answers at {}, and none is started, since GnuPG's home \
                 directory ({}) does not exist or cannot be seen from here",
                self.socket.display(),
                home.display()
            )
            .into()),
            Starter::Sequoia(ctx) => ctx.start("gpg-agent"),
        }
    }
}

/// Find the agent of the GnuPG home `homedir`, or of GnuPG's default where
/// that is `None`, through the gpgconf [`locate`] chooses. This runs gpgconf
/// once, and for a Cygwin build on Windows twice more, as sequoia-gpg-agent
/// does.
pub(super) fn find(homedir: Option<PathBuf>) -> Result<Found, Error> {
    let path = std::env::var_os("PATH");
    let program = locate(
        Platform::OURS,
        path.iter().flat_map(std::env::split_paths),
        &|name| std::env::var_os(name),
        &runnable,
    )
    .ok_or(gnupg::Error::GPGConfMissing)?;
    let gpgconf = Gpgconf { program, homedir };
    let dirs = parse(&gpgconf.run(&["--list-dirs"])?)?;

    Ok(match route(Platform::OURS, &dirs, &Path::exists) {
        Route::Launch => Found {
            socket: dirs.agent_socket,
            starter: Starter::Gpgconf(gpgconf),
        },
        Route::Never(home) => Found {
            socket: dirs.agent_socket,
            starter: Starter::Never(home),
        },
        Route::Cygpath => {
            let ctx = match gpgconf.homedir {
                None => Context::new()?,
                Some(dir) => Context::with_homedir(dir)?,
            };
            Found {
                socket: ctx.socket("agent")?.to_path_buf(),
                starter: Starter::Sequoia(ctx),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PATH, as `std::env::split_paths` hands it over.
    fn entries(dirs: &[&str]) -> Vec<PathBuf> {
        dirs.iter().map(PathBuf::from).collect()
    }

    fn no_variables(_: &str) -> Option<OsString> {
        None
    }

    /// Where gpgconf is found on `platform` with PATH `path` and environment
    /// `var`, when the files that exist are `files`.
    fn found(
        platform: Platform,
        path: &[&str],
        var: &dyn Fn(&str) -> Option<OsString>,
        files: &[PathBuf],
    ) -> Option<PathBuf> {
        locate(platform, entries(path), var, &|candidate| {
            files.iter().any(|file| file == candidate)
        })
    }

    /// What launchd gives an app opened from the Finder, the Dock or
    /// Spotlight, or with `open`.
    const LAUNCHD_PATH: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

    /// An app opened from the Finder has launchd's PATH, without Homebrew or
    /// GPG Suite on it, and finds gpgconf where each of them installs it.
    /// That app found none, and so no agent: only one started from a shell,
    /// whose profile adds Homebrew to PATH, did.
    #[test]
    fn on_macos_gpgconf_is_found_where_homebrew_and_gpg_suite_put_it() {
        for dir in [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/local/MacGPG2/bin",
            "/opt/local/bin",
        ] {
            let gpgconf = Path::new(dir).join("gpgconf");
            assert_eq!(
                found(
                    Platform::MacOs,
                    LAUNCHD_PATH,
                    &no_variables,
                    std::slice::from_ref(&gpgconf)
                ),
                Some(gpgconf),
                "installed in {dir}"
            );
        }

        // Homebrew's is taken over GPG Suite's when both are there, and one on
        // PATH, as from a shell, over either.
        let homebrew = Path::new("/opt/homebrew/bin").join("gpgconf");
        let gpg_suite = Path::new("/usr/local/MacGPG2/bin").join("gpgconf");
        let on_path = Path::new("/Users/alice/.local/bin").join("gpgconf");
        let everywhere = [gpg_suite.clone(), homebrew.clone(), on_path.clone()];
        assert_eq!(
            found(Platform::MacOs, LAUNCHD_PATH, &no_variables, &everywhere),
            Some(homebrew)
        );
        assert_eq!(
            found(
                Platform::MacOs,
                &["/Users/alice/.local/bin", "/usr/bin"],
                &no_variables,
                &everywhere
            ),
            Some(on_path)
        );
        assert_eq!(
            found(Platform::MacOs, LAUNCHD_PATH, &no_variables, &[]),
            None
        );
    }

    /// On Windows, `gpgconf.exe` is found on PATH as Gpg4win's installer
    /// leaves it, and failing that in GnuPG's directory under either Program
    /// Files, for a process whose PATH is from before the install.
    #[test]
    fn on_windows_gpgconf_is_found_on_path_or_where_gpg4win_puts_it() {
        let gpg4win = Path::new(r"C:\Program Files (x86)\GnuPG\bin").join("gpgconf.exe");
        let path = [
            r"C:\WINDOWS\system32",
            r"C:\WINDOWS",
            r"C:\Program Files (x86)\GnuPG\bin",
        ];
        assert_eq!(
            found(
                Platform::Windows,
                &path,
                &no_variables,
                std::slice::from_ref(&gpg4win)
            ),
            Some(gpg4win.clone())
        );
        // The same name without its extension is not what Windows would run.
        let bare = Path::new(r"C:\Program Files (x86)\GnuPG\bin").join("gpgconf");
        assert_eq!(
            found(Platform::Windows, &path, &no_variables, &[bare]),
            None
        );

        let program_files = |name: &str| match name {
            "ProgramFiles(x86)" => Some(OsString::from(r"C:\Program Files (x86)")),
            "ProgramFiles" => Some(OsString::from(r"C:\Program Files")),
            _ => None,
        };
        let stale = [r"C:\WINDOWS\system32", r"C:\WINDOWS"];
        assert_eq!(
            found(
                Platform::Windows,
                &stale,
                &program_files,
                std::slice::from_ref(&gpg4win)
            ),
            Some(gpg4win)
        );
        let sixty_four = Path::new(r"C:\Program Files\GnuPG\bin").join("gpgconf.exe");
        assert_eq!(
            found(
                Platform::Windows,
                &stale,
                &program_files,
                std::slice::from_ref(&sixty_four)
            ),
            Some(sixty_four)
        );
    }

    /// On Linux gpgconf is looked for in those directories of PATH given from
    /// the root, since one given relative to where the app was started could
    /// be anywhere, and failing that in `/usr/bin`, where running gpgconf by
    /// name found it with no PATH at all. Not where macOS's installers put it.
    #[test]
    fn on_linux_gpgconf_is_found_in_an_absolute_directory_of_path_or_in_usr_bin() {
        let usr_bin = Path::new("/usr/bin").join("gpgconf");
        let local = Path::new("/usr/local/bin").join("gpgconf");
        let here = Path::new("bin").join("gpgconf");
        let homebrew = Path::new("/opt/homebrew/bin").join("gpgconf");
        let files = [
            here.clone(),
            homebrew.clone(),
            local.clone(),
            usr_bin.clone(),
        ];
        assert_eq!(
            found(
                Platform::Unix,
                &["bin", "", "/usr/local/bin", "/usr/bin"],
                &no_variables,
                &files
            ),
            Some(local)
        );
        assert_eq!(
            found(Platform::Unix, &["bin", "/bin"], &no_variables, &files),
            Some(usr_bin.clone())
        );
        assert_eq!(
            found(
                Platform::Unix,
                &[],
                &no_variables,
                std::slice::from_ref(&usr_bin)
            ),
            Some(usr_bin)
        );
        assert_eq!(
            found(Platform::Unix, &["bin"], &no_variables, &[here, homebrew]),
            None
        );
    }

    /// On Windows, as on Linux, only a directory of PATH given from the root
    /// is searched: from a drive or a network share, and not from the
    /// current drive's root, or from a drive's current directory.
    #[test]
    fn on_windows_gpgconf_is_found_only_in_a_directory_of_path_from_a_drive_or_a_share() {
        let at = |dir: &str| Path::new(dir).join("gpgconf.exe");
        let relative = [r"\GnuPG\bin", r"D:GnuPG\bin"];
        let files = [
            at(relative[0]),
            at(relative[1]),
            at(r"\\server\share\GnuPG\bin"),
            at(r"D:\GnuPG\bin"),
        ];
        assert_eq!(
            found(Platform::Windows, &relative, &no_variables, &files),
            None
        );
        for absolute in [r"\\server\share\GnuPG\bin", r"D:\GnuPG\bin"] {
            assert_eq!(
                found(
                    Platform::Windows,
                    &[relative[0], relative[1], absolute],
                    &no_variables,
                    &files
                ),
                Some(at(absolute)),
                "{absolute}"
            );
        }
    }

    /// A gpgconf that cannot be run, a file no one may execute or a directory
    /// of that name, is passed over for the next on PATH, as a shell passes
    /// it over. Taken, it would fail every connection, however runnable the
    /// gpgconf after it.
    #[cfg(unix)]
    #[test]
    fn a_gpgconf_that_cannot_be_run_is_passed_over_as_a_shell_would() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let [unexecutable, directory, executable] =
            ["unexecutable", "directory", "executable"].map(|name| dir.path().join(name));
        for (bin, mode) in [(&unexecutable, 0o644), (&executable, 0o755)] {
            std::fs::create_dir(bin).unwrap();
            let gpgconf = bin.join("gpgconf");
            std::fs::write(&gpgconf, b"#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&gpgconf, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        std::fs::create_dir_all(directory.join("gpgconf")).unwrap();

        assert_eq!(
            locate(
                Platform::Unix,
                [unexecutable, directory, executable.clone()],
                &no_variables,
                &runnable
            ),
            Some(executable.join("gpgconf"))
        );
    }

    /// The socket and home are read from gpgconf's listing with its escapes
    /// undone, all of them, and not only the colon.
    #[test]
    fn the_listing_is_read_with_every_escape_undone() {
        let listing = b"sysconfdir:/etc/gnupg\n\
            socketdir:/run/user/1000/gnupg/d.8r5tmwpdf9815rq9xtmbnjqp\n\
            agent-ssh-socket:/run/user/1000/gnupg/d.8r5tmwpdf9815rq9xtmbnjqp/S.gpg-agent.ssh\n\
            agent-socket:/run/user/1000/gnupg/d.8r5tmwpdf9815rq9xtmbnjqp/S.gpg-agent\n\
            homedir:/home/alice/keys/a%25b%2cc%3ad%0ae \xc3\xa9\n";
        assert_eq!(
            parse(listing).unwrap(),
            Dirs {
                homedir: Some(PathBuf::from("/home/alice/keys/a%b,c:d\ne é")),
                agent_socket: PathBuf::from(
                    "/run/user/1000/gnupg/d.8r5tmwpdf9815rq9xtmbnjqp/S.gpg-agent"
                ),
            }
        );
        // A percent sign that is not an escape is itself.
        assert_eq!(unescape(b"100%%zz%4"), b"100%%zz%4");

        let no_agent = b"homedir:/home/alice/.gnupg\n";
        assert!(parse(no_agent).is_err());
    }

    /// Gpg4win's gpgconf ends its lines `\r\n` and escapes the colon after a
    /// drive letter; read, what it prints is a path Windows opens, with no
    /// `cygpath` to run.
    ///
    /// The listing is written from GnuPG's format, the drive's colon escaped as
    /// on Linux and the sockets under the local application data directory,
    /// where GnuPG has put them on Windows since 2.3. It was not captured on
    /// Windows.
    #[test]
    fn a_listing_from_gpg4win_names_a_socket_windows_opens() {
        let listing = b"sysconfdir:C%3a\\ProgramData\\GNU\\etc\\gnupg\r\n\
            bindir:C%3a\\Program Files (x86)\\GnuPG\\bin\r\n\
            socketdir:C%3a\\Users\\Alice\\AppData\\Local\\gnupg\r\n\
            agent-socket:C%3a\\Users\\Alice\\AppData\\Local\\gnupg\\S.gpg-agent\r\n\
            homedir:C%3a\\Users\\Alice\\AppData\\Roaming\\gnupg\r\n";
        let dirs = parse(listing).unwrap();
        assert_eq!(
            dirs,
            Dirs {
                homedir: Some(PathBuf::from(r"C:\Users\Alice\AppData\Roaming\gnupg")),
                agent_socket: PathBuf::from(r"C:\Users\Alice\AppData\Local\gnupg\S.gpg-agent"),
            }
        );
        assert_eq!(route(Platform::Windows, &dirs, &|_| true), Route::Launch);
    }

    /// A gpgconf built for Cygwin or MSYS2, such as Git for Windows' own,
    /// names its paths as Unix does, and those are left to sequoia-gpg-agent,
    /// whose `cygpath` turns them into Windows paths. The same path on Unix is
    /// an ordinary one.
    #[test]
    fn a_listing_in_cygwin_paths_is_left_to_cygpath_on_windows_alone() {
        let dirs = parse(
            b"agent-socket:/c/Users/Alice/.gnupg/S.gpg-agent\n\
              homedir:/c/Users/Alice/.gnupg\n",
        )
        .unwrap();
        assert_eq!(route(Platform::Windows, &dirs, &|_| true), Route::Cygpath);
        assert_eq!(route(Platform::Unix, &dirs, &|_| true), Route::Launch);
        assert_eq!(route(Platform::MacOs, &dirs, &|_| true), Route::Launch);
    }

    /// Inside the Flatpak, gpgconf names the host's agent socket, which the
    /// manifest shares, and a home the sandbox cannot see. That socket is
    /// tried, and no agent is started, on any platform, for a home that is not
    /// there; one that is gets an agent started when none answers.
    ///
    /// The home not being there is what sequoia-gpg-agent refused, before the
    /// socket was tried, so that the Flatpak never reached the host's agent.
    #[test]
    fn a_home_that_cannot_be_seen_gets_its_socket_tried_and_no_agent_started() {
        // What the runtime's gpgconf prints inside the sandbox.
        let dirs = parse(
            b"socketdir:/run/user/1000/gnupg\n\
              agent-socket:/run/user/1000/gnupg/S.gpg-agent\n\
              homedir:/home/alice/.gnupg\n",
        )
        .unwrap();
        assert_eq!(
            dirs.agent_socket,
            Path::new("/run/user/1000/gnupg/S.gpg-agent")
        );

        let hidden = |_: &Path| false;
        for platform in [Platform::Unix, Platform::MacOs] {
            assert_eq!(
                route(platform, &dirs, &hidden),
                Route::Never(PathBuf::from("/home/alice/.gnupg"))
            );
        }
        let seen = |dir: &Path| dir == Path::new("/home/alice/.gnupg");
        assert_eq!(route(Platform::Unix, &dirs, &seen), Route::Launch);

        let windows = parse(
            b"agent-socket:C%3a\\Users\\Alice\\AppData\\Local\\gnupg\\S.gpg-agent\n\
              homedir:C%3a\\Users\\Alice\\AppData\\Roaming\\gnupg\n",
        )
        .unwrap();
        assert_eq!(
            route(Platform::Windows, &windows, &hidden),
            Route::Never(PathBuf::from(r"C:\Users\Alice\AppData\Roaming\gnupg"))
        );
    }
}
