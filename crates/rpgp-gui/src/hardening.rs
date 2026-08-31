//! Making the process a poor target for memory inspection.
//!
//! Sequoia already does the difficult part: [`Protected`] memzeroes secret
//! buffers on drop, and both `Password` and unlocked secret key MPIs are held
//! AES-sealed in RAM, decrypted only for the span of one operation. That
//! sealing is aimed at *imperfect* readout — Spectre, Rowhammer, coldboot —
//! where a bitflip in the pre-key avalanches and leaves the attacker nothing.
//!
//! It is explicitly not aimed at a *perfect* read of the whole address space,
//! because the pre-key is a static sitting in that same address space. A core
//! file or a debugger attach hands over both halves at once. Those are what
//! this module closes.
//!
//! What it does not close: this is not a privilege boundary. Key material
//! still passes through this process, and root, or anything holding
//! `CAP_SYS_PTRACE`, can still read it. Treat it as defence in depth.
//!
//! [`Protected`]: sequoia_openpgp::crypto::mem::Protected

/// Set to any value to keep the process debuggable.
///
/// Without an escape hatch the first crash report becomes unanswerable: no
/// core, nothing for `coredumpctl`, and `gdb` refusing to attach.
const ALLOW_DEBUG: &str = "RPGP_ALLOW_DEBUG";

/// Refuse to dump core, and on Linux refuse to be attached to.
///
/// Best-effort throughout. Every one of these can fail under a sandbox or a
/// hardened kernel, and none of them failing is a reason not to start — the
/// alternative is an app that will not run rather than one that is slightly
/// easier to inspect.
pub fn harden() {
    if std::env::var_os(ALLOW_DEBUG).is_some() {
        eprintln!("rpgp: {ALLOW_DEBUG} is set: core dumps and debugger attach are permitted");
        return;
    }

    #[cfg(unix)]
    {
        // Belt and braces, and the only one of the two available on macOS.
        // On a systemd machine this is close to useless on its own, because
        // `kernel.core_pattern` pipes to systemd-coredump and a pipe target
        // ignores RLIMIT_CORE; PR_SET_DUMPABLE below is what actually stops
        // it there.
        let no_core = rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        if let Err(e) = rustix::process::setrlimit(rustix::process::Resource::Core, no_core) {
            eprintln!("rpgp: could not disable core dumps: {e}");
        }
    }

    // PR_SET_DUMPABLE also revokes same-user ptrace, so this covers both a
    // core file and someone attaching gdb to a running rpgp. There is no
    // portable equivalent: macOS has PT_DENY_ATTACH, which is bypassable and
    // breaks crash reporting, so the macOS answer is the hardened runtime at
    // signing time instead — applied by `packaging/macos-sign.sh`, which signs
    // with --options runtime and no entitlements file, so the bundle carries no
    // get-task-allow. A locally built macOS binary is unsigned and has neither.
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        if let Err(e) = set_dumpable_behavior(DumpableBehavior::NotDumpable) {
            eprintln!("rpgp: could not make the process non-dumpable: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    /// `harden()` itself, in a child process.
    ///
    /// The previous test never called it: it exercised
    /// `set_dumpable_behavior` directly and asserted the kernel honoured it,
    /// which tests rustix rather than this module — deleting the call inside
    /// `harden` left it green. A child is the way to test the real function
    /// without making the test binary itself undebuggable.
    #[test]
    #[cfg(target_os = "linux")]
    fn harden_makes_the_process_non_dumpable() {
        // Re-exec this test binary and run only the helper below.
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--nocapture",
                "--ignored",
                "hardening::tests::dumpable_probe",
            ])
            .env("RPGP_HARDEN_PROBE", "1")
            .env_remove(super::ALLOW_DEBUG)
            .output()
            .expect("re-exec the test binary");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("PROBE dumpable=NotDumpable"),
            "harden() did not clear the dumpable flag in the child; stdout was: {text}"
        );
    }

    /// The escape hatch: with `RPGP_ALLOW_DEBUG` set, `harden()` must leave the
    /// flag alone, or the documented way to get a backtrace does not work.
    #[test]
    #[cfg(target_os = "linux")]
    fn allow_debug_leaves_the_process_dumpable() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--nocapture",
                "--ignored",
                "hardening::tests::dumpable_probe",
            ])
            .env("RPGP_HARDEN_PROBE", "1")
            .env(super::ALLOW_DEBUG, "1")
            .output()
            .expect("re-exec the test binary");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("PROBE dumpable=Dumpable"),
            "RPGP_ALLOW_DEBUG did not keep the process dumpable; stdout was: {text}"
        );
    }

    /// Not a test: the body the two tests above re-exec. `#[ignore]` keeps it
    /// out of an ordinary run, and it only acts when the parent sets the
    /// marker, so it never hardens the shared test process by accident.
    #[test]
    #[ignore = "helper process for the harden tests"]
    #[cfg(target_os = "linux")]
    fn dumpable_probe() {
        if std::env::var_os("RPGP_HARDEN_PROBE").is_none() {
            return;
        }
        super::harden();
        let state = rustix::process::dumpable_behavior().unwrap();
        println!("PROBE dumpable={state:?}");
    }
}
