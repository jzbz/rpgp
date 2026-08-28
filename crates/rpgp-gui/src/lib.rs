//! The rPGP interface, as a library so its pure parts can be measured.
//!
//! Everything here used to live in `main.rs`. A binary crate has no library
//! target, so nothing inside it can be reached from a benchmark — and the row
//! building and list ordering that a keystroke pays for are exactly what wants
//! measuring. `main.rs` is now a wrapper around [`run_app`]; this module is
//! unchanged otherwise.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rpgp_core::cert::format_time;
use rpgp_core::certify::{self, Certification, CertifyRequest};
use rpgp_core::keygen::{self, KeyGenRequest, KeyType};
use rpgp_core::lifecycle;
use rpgp_core::ops::{self, InputKind, VerifyResult};
use rpgp_core::revoke::{self, Reason, RevokeRequest};
use rpgp_core::{CertSummary, Store, wot};
use slint::{ModelRc, SharedString, VecModel};
use zeroize::Zeroizing;

pub mod hardening;

slint::include_modules!();

/// How the list is ordered.
///
/// The list is drawn as custom rows rather than a table, so this is a control
/// rather than clickable column headers — but it is the same idea, and it puts
/// "expiring soonest" within reach, which a name column never would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    /// Own keys first, then by name. The default: they are the ones a person
    /// reaches for.
    MineFirst,
    Name,
    Newest,
    ExpiringSoonest,
}

impl Sort {
    fn from_index(index: i32) -> Self {
        match index {
            1 => Sort::Name,
            2 => Sort::Newest,
            3 => Sort::ExpiringSoonest,
            _ => Sort::MineFirst,
        }
    }

    /// Order `shown` — positions in `all` — by what those positions point at.
    ///
    /// Takes indices rather than summaries because the list is a view: sorting
    /// the view must not require copying the things it views.
    fn apply_to(self, all: &[CertSummary], shown: &mut [usize]) {
        let get = |i: &usize| &all[*i];
        // sort_by_cached_key, not sort_by/sort_by_key: the name key allocates,
        // and a comparator calls it on every comparison — twice, for the arms
        // that fall back to it — which is O(n log n) allocations for a list
        // that is re-sorted on every keystroke. Cached, it is one per element.
        //
        // The descending components become Reverse rather than a flipped cmp,
        // and "never expires sorts last" becomes `is_none()` ordering false
        // before true; both produce the same sequence the comparators did.
        let by_name = |c: &CertSummary| c.primary_user_id.to_lowercase();
        match self {
            Sort::MineFirst => shown.sort_by_cached_key(|i| {
                let c = get(i);
                (std::cmp::Reverse(c.has_secret), by_name(c))
            }),
            Sort::Name => shown.sort_by_cached_key(|i| by_name(get(i))),
            Sort::Newest => shown.sort_by_cached_key(|i| {
                let c = get(i);
                (std::cmp::Reverse(c.created), by_name(c))
            }),
            // Certificates that never expire sort last rather than first: an
            // absent date is the opposite of urgent.
            Sort::ExpiringSoonest => shown.sort_by_cached_key(|i| {
                let c = get(i);
                (c.expires.is_none(), c.expires, by_name(c))
            }),
        }
    }
}

/// Which slice of the store the list is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    All,
    Mine,
    Others,
}

impl Scope {
    fn from_index(index: i32) -> Self {
        match index {
            1 => Scope::Mine,
            2 => Scope::Others,
            _ => Scope::All,
        }
    }

    fn accepts(self, cert: &CertSummary) -> bool {
        match self {
            Scope::All => true,
            Scope::Mine => cert.has_secret,
            Scope::Others => !cert.has_secret,
        }
    }
}

/// A certificate offered as an encryption recipient, plus whether it is ticked.
struct Recipient {
    fingerprint: String,
    label: String,
    sublabel: String,
    initials: String,
    tint: i32,
    selected: bool,
}

/// Everything the callbacks share.
///
/// `all` is the store's contents; `shown` is what the list is displaying after
/// the scope and search filters. A row index from the UI refers to `shown`, so
/// the two are only ever rebuilt together — see [`reload`] and [`apply_filter`].
struct State {
    /// Behind an `Arc` so a worker can clone it out under a brief lock and
    /// then do its I/O — which may be a card PIN prompt lasting a minute —
    /// without holding the mutex the UI needs. `Store` is `Send + Sync`, and
    /// all its methods take `&self`.
    store: Arc<Store>,
    all: Vec<CertSummary>,
    /// Positions in `all`, not copies of it: the list is a view, and cloning
    /// every matching summary to build it allocated six to eight times per
    /// certificate on every reload and every keystroke. Rebuilt by
    /// `apply_filter` whenever `all` changes, so an index is never stale.
    shown: Vec<usize>,
    filter: String,
    scope: Scope,
    sort: Sort,

    se_input: Option<PathBuf>,
    se_recipients: Vec<Recipient>,
    /// Narrows the recipient list. Held here rather than in the UI because the
    /// index a row reports is an index into what is *shown*, so the filter has
    /// to be applied in the same place the mapping back is done.
    se_filter: String,
    /// (fingerprint, label) of every certificate that can sign and has a
    /// secret key in the store.
    se_signers: Vec<(String, String)>,

    dv_input: Option<PathBuf>,
    dv_data: Option<PathBuf>,
    dv_kind: InputKind,

    /// Fingerprint of the certificate the certify dialog is about.
    certify_target: Option<String>,
    /// (user ID, ticked)
    certify_user_ids: Vec<(String, bool)>,
    /// (fingerprint, label) of our own certification-capable keys.
    certify_certifiers: Vec<(String, String)>,

    /// Certificates found on the network, not yet in the store.
    lookup_results: Vec<rpgp_core::keyserver::Found>,

    /// Fingerprint the revoke dialog is about, and whether it is withdrawing a
    /// certification rather than revoking the key itself.
    revoke_target: Option<String>,
    revoke_certification: bool,
}

type Shared = Arc<Mutex<State>>;

/// Take the state lock, ignoring poisoning.
///
/// A panic while the lock is held would otherwise poison it and turn one
/// failed operation into an app that can do nothing at all — every callback
/// unwrapping the same `PoisonError` in turn. The state behind it is a list of
/// certificate summaries and some dialog scratch: a panic mid-update leaves it
/// stale or half-rebuilt, not dangerous, and the next reload overwrites it
/// wholesale. Carrying on with stale rows beats a window that has stopped
/// responding.
fn lock(state: &Shared) -> std::sync::MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// Callbacks and worker completions reach the window through a weak handle and
// bail out if it has gone. Unwrapping instead would panic when the user closes
// the window mid-operation: a worker's completion runs through
// invoke_from_event_loop after the fact, by which point the window may be
// gone. There is nothing useful to do at that point except stop.

// ------------------------------------------------------------------ renderer

/// Matches the basename of `desktop/app.rpgp.rpgp.desktop`, which is how a
/// Wayland compositor finds the icon for this window.
const APP_ID: &str = "app.rpgp.rpgp";

/// Clears the busy flag if a worker thread panics.
///
/// Every long operation runs on a worker that sets `busy` before starting and
/// clears it from the completion closure it posts back. A panic never reaches
/// that closure, so `busy` stayed set and every control in the window stayed
/// disabled until the app was restarted — a crash in one operation taking the
/// whole application with it.
///
/// Drop runs during unwinding, which is what lets this catch what an early
/// return could not. It deliberately does nothing on the normal path: the
/// completion closure is the one that should clear the flag, and say what
/// happened while doing so.
struct BusyGuard(slint::Weak<AppWindow>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let ui_weak = self.0.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_busy(false);
                ui.set_status("That operation failed unexpectedly. Nothing was changed.".into());
            }
        });
    }
}

/// Set on the restarted process so the software fallback can only happen once.
const FALLBACK_GUARD: &str = "RPGP_SOFTWARE_FALLBACK";

/// Raised by the panic hook when the panic was wgpu failing to find an adapter,
/// so that an unrelated panic is not mistaken for a graphics problem.
static NO_GPU_ADAPTER: AtomicBool = AtomicBool::new(false);

/// Choose the renderer up front, so a machine without a usable GPU gets a
/// window instead of a crash.
///
/// Asking for wgpu explicitly is what makes this possible: `select()` probes
/// for an adapter and reports failure as an error, where leaving Slint to pick
/// the renderer on its own defers the same question to window-creation time,
/// where it is an `expect` and takes the process with it.
///
/// The probe cannot see everything. It asks wgpu for an adapter without a
/// surface, so a driver that exists but cannot present to a window — a plain X
/// server with no DRI3, some VMs — still satisfies it and still fails later.
/// [`restart_with_software_renderer`] is the net under that case.
///
/// The backend set is pinned to `PRIMARY` on purpose. `WGPUSettings::default()`
/// asks for more than Slint does internally — the GL backend among them — and
/// wgpu's GL backend *hangs indefinitely* on a display it cannot use rather
/// than reporting failure. A machine that would only have managed GL now gets
/// the software renderer, which is slower but appears.
fn configure_renderer() {
    // An explicit choice by the user wins.
    if std::env::var_os("SLINT_BACKEND").is_some() {
        return;
    }

    use slint::wgpu_29::{WGPUConfiguration, WGPUSettings, wgpu};

    // WGPUSettings is #[non_exhaustive], so it has to be built by mutation.
    let mut settings = WGPUSettings::default();
    settings.backends = wgpu::Backends::PRIMARY;

    let gpu = slint::BackendSelector::new()
        .require_wgpu_29(WGPUConfiguration::Automatic(settings))
        .select();

    let Err(e) = gpu else {
        return;
    };

    eprintln!("rpgp: no GPU renderer ({e}); using the software renderer.");
    if let Err(e) = slint::BackendSelector::new()
        .renderer_name("software".into())
        .select()
    {
        eprintln!("rpgp: could not select the software renderer either: {e}");
    }
}

fn install_panic_hook() {
    let inner = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or_default();

        if message.contains("Failed to find an appropriate adapter") {
            NO_GPU_ADAPTER.store(true, Ordering::Relaxed);
            // Swallow the backtrace: main turns this into a restart, and the
            // wall of wgpu diagnostics would only look like a crash.
            return;
        }
        inner(info);
    }));
}

/// Re-run this executable on the software renderer.
///
/// A fresh process rather than a retry in-place: Slint's platform can only be
/// set once, and the failed attempt leaves the winit event loop half-built.
fn restart_with_software_renderer() -> ExitCode {
    if std::env::var_os(FALLBACK_GUARD).is_some() {
        eprintln!("rpgp: the software renderer failed as well; giving up.");
        return ExitCode::FAILURE;
    }

    eprintln!("rpgp: no usable GPU adapter, restarting with the software renderer.");

    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("rpgp: cannot locate this executable to restart it: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut command = std::process::Command::new(executable);
    command
        .args(std::env::args_os().skip(1))
        .env("SLINT_BACKEND", "winit-software")
        .env(FALLBACK_GUARD, "1");

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec replaces this process, so on success nothing below runs.
        let e = command.exec();
        eprintln!("rpgp: could not restart: {e}");
        ExitCode::FAILURE
    }

    #[cfg(not(unix))]
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("rpgp: could not restart: {e}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------- app

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let ui = AppWindow::new()?;

    let store = match Store::open_default() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("rpgp: cannot open the certificate store: {e}");
            return Err(e.into());
        }
    };

    let state: Shared = Arc::new(Mutex::new(State {
        store: Arc::new(store),
        all: Vec::new(),
        shown: Vec::new(),
        filter: String::new(),
        scope: Scope::All,
        sort: Sort::MineFirst,
        se_input: None,
        se_recipients: Vec::new(),
        se_filter: String::new(),
        se_signers: Vec::new(),
        dv_input: None,
        dv_data: None,
        dv_kind: InputKind::NotOpenPgp,
        certify_target: None,
        certify_user_ids: Vec::new(),
        certify_certifiers: Vec::new(),
        lookup_results: Vec::new(),
        revoke_target: None,
        revoke_certification: false,
    }));

    ui.set_version(env!("CARGO_PKG_VERSION").into());
    ui.on_about_open_link({
        let ui_weak = ui.as_weak();
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            if let Err(e) = open::that_detached("https://rpgp.app/") {
                ui.set_status(format!("Could not open the browser: {e}").into());
            }
        }
    });

    reload(&ui, &state);
    wire_list(&ui, &state);
    wire_keygen(&ui, &state);
    wire_sign_encrypt(&ui, &state);
    wire_decrypt_verify(&ui, &state);
    wire_certify(&ui, &state);
    wire_revoke(&ui, &state);
    wire_delete(&ui, &state);
    wire_notepad(&ui, &state);
    wire_lifecycle(&ui, &state);
    wire_lookup(&ui, &state);

    ui.run()?;
    Ok(())
}

// ---------------------------------------------------------------- list pane

fn wire_list(ui: &AppWindow, state: &Shared) {
    ui.on_refresh({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            reload(&ui, &state);
        }
    });

    ui.on_filter_changed({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |text| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            // A mutation is in flight and is about to replace `all`, so
            // acting on what is there now would act on state that is already
            // stale — and the reselect that follows would fight this callback
            // for the selection. These read-only callbacks therefore bow out
            // until it lands.
            //
            // Not, as this used to say, because a worker holds the state lock
            // across a card PIN prompt: run_sign_encrypt and run_certify both
            // take the lock in a scoped block and drop it before any crypto,
            // so the prompt happens with the lock free. Import is the one
            // worker that holds it throughout, and import never prompts.
            if ui.get_busy() {
                return;
            }
            lock(&state).filter = text.to_lowercase();
            apply_filter(&ui, &state);
        }
    });

    ui.on_sort_changed({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            // A mutation is in flight and is about to replace `all`, so
            // acting on what is there now would act on state that is already
            // stale — and the reselect that follows would fight this callback
            // for the selection. These read-only callbacks therefore bow out
            // until it lands.
            //
            // Not, as this used to say, because a worker holds the state lock
            // across a card PIN prompt: run_sign_encrypt and run_certify both
            // take the lock in a scoped block and drop it before any crypto,
            // so the prompt happens with the lock free. Import is the one
            // worker that holds it throughout, and import never prompts.
            if ui.get_busy() {
                return;
            }
            lock(&state).sort = Sort::from_index(index);
            apply_filter(&ui, &state);
        }
    });

    ui.on_scope_changed({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            // A mutation is in flight and is about to replace `all`, so
            // acting on what is there now would act on state that is already
            // stale — and the reselect that follows would fight this callback
            // for the selection. These read-only callbacks therefore bow out
            // until it lands.
            //
            // Not, as this used to say, because a worker holds the state lock
            // across a card PIN prompt: run_sign_encrypt and run_certify both
            // take the lock in a scoped block and drop it before any crypto,
            // so the prompt happens with the lock free. Import is the one
            // worker that holds it throughout, and import never prompts.
            if ui.get_busy() {
                return;
            }
            lock(&state).scope = Scope::from_index(index);
            apply_filter(&ui, &state);
        }
    });

    ui.on_row_selected({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |row| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            // A mutation is in flight and is about to replace `all`, so
            // acting on what is there now would act on state that is already
            // stale — and the reselect that follows would fight this callback
            // for the selection. These read-only callbacks therefore bow out
            // until it lands.
            //
            // Not, as this used to say, because a worker holds the state lock
            // across a card PIN prompt: run_sign_encrypt and run_certify both
            // take the lock in a scoped block and drop it before any crypto,
            // so the prompt happens with the lock free. Import is the one
            // worker that holds it throughout, and import never prompts.
            if ui.get_busy() {
                return;
            }
            let guard = lock(&state);

            let Some(summary) = usize::try_from(row)
                .ok()
                .and_then(|r| guard.shown_at(r))
                .cloned()
            else {
                ui.set_has_selection(false);
                return;
            };

            ui.set_detail(to_row(&summary));
            ui.set_has_selection(true);
            push_certifications(&ui, &guard, &summary);
        }
    });

    ui.on_import_file({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            // The portal dialog is driven by the Slint event loop rather than a
            // worker thread: on macOS a file dialog has to live on the main
            // thread, and this way one code path works on both platforms.
            let _ = slint::spawn_local(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Import certificates")
                    .add_filter(
                        "OpenPGP",
                        &["asc", "pgp", "gpg", "key", "pub", "sec", "kbx"],
                    )
                    .add_filter("All files", &["*"])
                    .pick_file()
                    .await
                else {
                    return;
                };
                let Some(ui) = ui_weak.upgrade() else {
                    return;
                };
                // Off the event loop, like key generation above. Parsing a
                // keyring and writing one cert-d file per certificate is
                // unbounded work — a GnuPG pubring can hold thousands — and
                // doing it here held the state lock and froze the window for
                // the whole import. The file dialog itself has to stay on the
                // main thread, which is why only this half moves.
                ui.set_busy(true);
                ui.set_status("Importing…".into());
                let path = file.path().to_path_buf();
                let (ui_weak, state) = (ui_weak.clone(), state.clone());
                std::thread::spawn(move || {
                    let _busy = BusyGuard(ui_weak.clone());
                    let outcome = {
                        let guard = lock(&state);
                        // A revocation certificate is a bare signature, not a
                        // certificate, so CertParser rejects it. Same button,
                        // because a user handed a .rev file expects Import to
                        // take it.
                        match guard.store.import_file(&path) {
                            Ok(certs) => {
                                // Secret keys are called out rather than folded
                                // into the count: one arriving is the difference
                                // between adding someone's certificate and taking
                                // custody of their key, and an imported key is
                                // deliberately not a trust root.
                                let secrets = certs.iter().filter(|c| c.is_tsk()).count();
                                Ok(if secrets == 0 {
                                    format!("Imported {} certificate(s)", certs.len())
                                } else {
                                    format!(
                                        "Imported {} certificate(s), {secrets} with a secret \
                                         key. A secret key that arrives in a file is not made \
                                         a trust root; tick Trust root in its details pane if \
                                         you meant to trust it.",
                                        certs.len()
                                    )
                                })
                            }
                            Err(import_error) => {
                                match revoke::apply_revocation_file(&guard.store, &path) {
                                    Ok(cert) => Ok(format!(
                                        "Revoked {}",
                                        rpgp_core::CertSummary::from_cert(&cert).primary_user_id
                                    )),
                                    Err(_) => Err(import_error),
                                }
                            }
                        }
                    };

                    // One refresh at the end rather than progressive updates:
                    // the list stays as it was until the import is complete,
                    // which is what it did when this ran inline.
                    let _ = slint::invoke_from_event_loop(move || {
                        let Some(ui) = ui_weak.upgrade() else {
                            return;
                        };
                        ui.set_busy(false);
                        match outcome {
                            Ok(message) => {
                                reload(&ui, &state);
                                ui.set_status(message.into());
                            }
                            Err(e) => ui.set_status(format!("Import failed: {e}").into()),
                        }
                    });
                });
            });
        }
    });

    ui.on_export_selected({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let (fingerprint, suggested) = {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    let row = ui.get_current_row();
                    let state = lock(&state);
                    match usize::try_from(row).ok().and_then(|r| state.shown_at(r)) {
                        Some(s) => (s.fingerprint.clone(), format!("{}.asc", s.key_id)),
                        None => return,
                    }
                };

                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Export certificate")
                    .set_file_name(&suggested)
                    .save_file()
                    .await
                else {
                    return;
                };

                let Some(ui) = ui_weak.upgrade() else {
                    return;
                };
                let outcome = lock(&state)
                    .store
                    .export_file(std::slice::from_ref(&fingerprint), file.path());
                ui.set_status(SharedString::from(match outcome {
                    Ok(()) => format!("Exported to {}", file.path().display()),
                    Err(e) => format!("Export failed: {e}"),
                }));
            });
        }
    });
}

// ------------------------------------------------------------- key generation

fn wire_keygen(ui: &AppWindow, state: &Shared) {
    ui.on_generate_key({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |name, email, password, key_type, expiry, standard| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };

            let request = KeyGenRequest {
                user_ids: vec![format!("{} <{}>", name.trim(), email.trim())],
                key_type: KeyType::ALL
                    .get(key_type.max(0) as usize)
                    .copied()
                    .unwrap_or_default(),
                standard: keygen::Standard::from_index(standard),
                validity: expiry_from_index(expiry),
                password: Some(Zeroizing::new(password.to_string())).filter(|p| !p.is_empty()),
            };

            ui.set_busy(true);
            ui.set_status("Generating key…".into());

            // RSA-4096 takes seconds. Run it off the UI thread and hand the
            // finished certificate back through the event loop.
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let generated = keygen::generate(&request);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match generated.and_then(|key| {
                        let guard = lock(&state);
                        guard.store.insert_secret(&key.cert)?;
                        // Written once, now: a revocation certificate cannot be
                        // recreated later without the secret key, and this is
                        // the only moment we are certain to have it unlocked.
                        let fingerprint = key.cert.fingerprint().to_hex();
                        guard
                            .store
                            .save_revocation(&fingerprint, &revoke::armor(&key.revocation)?)?;
                        Ok(fingerprint)
                    }) {
                        Ok(fingerprint) => {
                            ui.set_keygen_open(false);
                            reload(&ui, &state);
                            ui.set_status(format!("Created {fingerprint}").into());
                        }
                        Err(e) => ui.set_status(format!("Key generation failed: {e}").into()),
                    }
                });
            });
        }
    });
}

fn expiry_from_index(index: i32) -> Option<Duration> {
    const YEAR: u64 = 365 * 24 * 60 * 60;
    match index {
        0 => Some(Duration::from_secs(2 * YEAR)),
        1 => Some(Duration::from_secs(YEAR)),
        2 => Some(Duration::from_secs(5 * YEAR)),
        _ => None,
    }
}

// ------------------------------------------------------------- sign / encrypt

fn wire_sign_encrypt(ui: &AppWindow, state: &Shared) {
    ui.on_open_sign_encrypt({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let mut guard = lock(&state);

            // Anyone who can receive encrypted mail is a candidate recipient;
            // whatever is selected in the list starts ticked.
            let preselect = usize::try_from(ui.get_current_row())
                .ok()
                .and_then(|r| guard.shown_at(r))
                .map(|s| s.fingerprint.clone());

            build_signing_targets(&mut guard, preselect.as_deref());

            push_sign_encrypt(&ui, &guard);
            drop(guard);
            ui.set_signenc_open(true);
        }
    });

    ui.on_se_pick_input({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("File to sign or encrypt")
                    .pick_file()
                    .await
                else {
                    return;
                };
                let Some(ui) = ui_weak.upgrade() else {
                    return;
                };
                let mut guard = lock(&state);
                guard.se_input = Some(file.path().to_path_buf());
                push_sign_encrypt(&ui, &guard);
            });
        }
    });

    ui.on_se_toggle_recipient({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let mut guard = lock(&state);
            // Through the filter: `index` counts shown rows, not recipients.
            if let Some(target) = usize::try_from(index)
                .ok()
                .and_then(|i| visible_recipients(&guard).get(i).copied())
                && let Some(entry) = guard.se_recipients.get_mut(target)
            {
                entry.selected = !entry.selected;
            }
            push_sign_encrypt(&ui, &guard);
        }
    });

    ui.on_se_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |encrypt, sign, signer_index, password, secret| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            ui.set_busy(true);
            ui.set_status(
                if encrypt {
                    "Encrypting…"
                } else {
                    "Signing…"
                }
                .into(),
            );

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let (password, secret) = (password.to_string(), secret.to_string());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let outcome =
                    run_sign_encrypt(&state, encrypt, sign, signer_index, &password, &secret);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok(output) => {
                            ui.set_signenc_open(false);
                            ui.set_status(format!("Wrote {}", output.display()).into());
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });
}

/// The blocking half of Sign / Encrypt, run on a worker thread.
fn run_sign_encrypt(
    state: &Shared,
    encrypt: bool,
    sign: bool,
    signer_index: i32,
    password: &str,
    secret: &str,
) -> Result<PathBuf, String> {
    // Snapshot what is needed and release the lock: everything below is I/O,
    // and a card PIN prompt can hold it for a minute while the UI waits.
    let (store, input, signers, recipients) = {
        let guard = lock(state);
        (
            guard.store.clone(),
            guard.se_input.clone(),
            guard.se_signers.clone(),
            guard
                .se_recipients
                .iter()
                .filter(|r| r.selected)
                .map(|r| (r.fingerprint.clone(), r.label.clone()))
                .collect::<Vec<_>>(),
        )
    };
    let input = input.ok_or_else(|| "Choose a file first".to_string())?;
    let password = Some(password).filter(|p| !p.is_empty());

    // The signer is resolved from the *secret* store: cert-d only holds the
    // public half, which cannot produce a signature.
    let signer = if sign {
        let (fingerprint, _) = signers
            .get(signer_index.max(0) as usize)
            .ok_or_else(|| "Choose a key to sign with".to_string())?;
        // Local secret if we have it; otherwise the public certificate, which
        // is all the agent needs — it finds the secret by keygrip.
        Some(
            store
                .secret_cert(fingerprint)
                .or_else(|_| store.lookup(fingerprint))
                .map_err(|e| format!("Signing key unavailable: {e}"))?,
        )
    } else {
        None
    };

    if encrypt {
        let mut certs = Vec::new();
        for (fingerprint, label) in &recipients {
            certs.push(
                store
                    .lookup(fingerprint)
                    .map_err(|e| format!("Recipient {label} unavailable: {e}"))?,
            );
        }
        let passwords: Vec<String> = if secret.is_empty() {
            Vec::new()
        } else {
            vec![secret.to_string()]
        };
        if certs.is_empty() && passwords.is_empty() {
            return Err("Select a recipient, or set a password".to_string());
        }

        let output = ops::encrypted_name(&input);
        ops::encrypt_file(
            &certs,
            &passwords,
            signer.as_ref().map(|cert| (cert, password)),
            &input,
            &output,
        )
        .map_err(|e| format!("Encryption failed: {e}"))?;
        Ok(output)
    } else {
        let signer = signer.ok_or_else(|| "Nothing to do: tick Encrypt or Sign".to_string())?;
        let output = ops::signature_name(&input);
        ops::sign_detached_file(&signer, password, &input, &output)
            .map_err(|e| format!("Signing failed: {e}"))?;
        Ok(output)
    }
}

/// Positions in `se_recipients` the current filter leaves visible.
///
/// The one definition of "shown", used both to build the model and to turn a
/// clicked row back into a recipient. Deriving it twice from the same function
/// is what stops the two drifting apart when the filter changes.
fn visible_recipients(state: &State) -> Vec<usize> {
    let needle = state.se_filter.trim().to_lowercase();
    state
        .se_recipients
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            needle.is_empty()
                || r.label.to_lowercase().contains(&needle)
                || r.sublabel.to_lowercase().contains(&needle)
                || r.fingerprint.to_lowercase().contains(&needle)
        })
        .map(|(i, _)| i)
        .collect()
}

fn push_sign_encrypt(ui: &AppWindow, state: &State) {
    let rows: Vec<RecipientRow> = visible_recipients(state)
        .into_iter()
        .map(|i| &state.se_recipients[i])
        .map(|r| RecipientRow {
            fingerprint: r.fingerprint.clone().into(),
            label: r.label.clone().into(),
            sublabel: r.sublabel.clone().into(),
            initials: r.initials.clone().into(),
            tint_index: r.tint,
            selected: r.selected,
        })
        .collect();

    let signers: Vec<SharedString> = state
        .se_signers
        .iter()
        .map(|(_, label)| SharedString::from(label.as_str()))
        .collect();

    // Counted over every recipient, not the shown ones: a selection hidden by
    // the filter is still encrypted to, and a count that dropped when you
    // typed would say the opposite.
    ui.set_se_selected_count(state.se_recipients.iter().filter(|r| r.selected).count() as i32);
    ui.set_se_recipients(ModelRc::new(VecModel::from(rows)));
    ui.set_se_signers(ModelRc::new(VecModel::from(signers)));

    match &state.se_input {
        Some(path) => {
            ui.set_se_input(path.display().to_string().into());
            ui.set_se_output_encrypt(ops::encrypted_name(path).display().to_string().into());
            ui.set_se_output_sign(ops::signature_name(path).display().to_string().into());
        }
        None => {
            ui.set_se_input(SharedString::new());
            ui.set_se_output_encrypt(SharedString::new());
            ui.set_se_output_sign(SharedString::new());
        }
    }
}

// ----------------------------------------------------------- decrypt / verify

fn wire_decrypt_verify(ui: &AppWindow, state: &Shared) {
    ui.on_open_decrypt_verify({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let mut guard = lock(&state);
            guard.dv_input = None;
            guard.dv_data = None;
            guard.dv_kind = InputKind::NotOpenPgp;
            ui.set_dv_result(SharedString::new());
            ui.set_dv_tone(0);
            ui.set_dv_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
            push_decrypt_verify(&ui, &guard);
            ui.set_verify_open(true);
        }
    });

    ui.on_dv_pick_input({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Encrypted message or signature")
                    .add_filter("OpenPGP", &["asc", "pgp", "gpg", "sig", "signature"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                    .await
                else {
                    return;
                };

                let path = file.path().to_path_buf();
                // Reads only as far as the answer needs, which decides
                // whether the dialog has to ask for the signed file as well.
                // This used to read the whole file, here on the event loop.
                let kind = ops::classify_file(&path);

                let Some(ui) = ui_weak.upgrade() else {
                    return;
                };
                let mut guard = lock(&state);
                guard.dv_input = Some(path);
                guard.dv_kind = kind;
                ui.set_dv_result(SharedString::new());
                ui.set_dv_tone(0);
                push_decrypt_verify(&ui, &guard);
            });
        }
    });

    ui.on_dv_pick_data({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("File the signature covers")
                    .pick_file()
                    .await
                else {
                    return;
                };
                let Some(ui) = ui_weak.upgrade() else {
                    return;
                };
                let mut guard = lock(&state);
                guard.dv_data = Some(file.path().to_path_buf());
                push_decrypt_verify(&ui, &guard);
            });
        }
    });

    ui.on_dv_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |password| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            ui.set_busy(true);
            ui.set_status("Working…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let password = password.to_string();
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let outcome = run_decrypt_verify(&state, &password);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok((summary, tone, result)) => {
                            let rows = signature_rows(&lock(&state).all, &result.signatures);
                            ui.set_dv_signatures(ModelRc::new(VecModel::from(rows)));
                            ui.set_dv_result(summary.clone().into());
                            ui.set_dv_tone(tone);
                            ui.set_status(summary.into());
                        }
                        Err(message) => {
                            ui.set_dv_signatures(ModelRc::new(VecModel::from(
                                Vec::<SignatureRow>::new(),
                            )));
                            ui.set_dv_result(message.clone().into());
                            ui.set_dv_tone(3);
                            ui.set_status(message.into());
                        }
                    }
                });
            });
        }
    });
}

/// The blocking half of Decrypt / Verify. Returns a summary line, a tone for
/// the result banner (1 good, 2 needs attention, 3 bad) and the signatures.
fn run_decrypt_verify(
    state: &Shared,
    password: &str,
) -> Result<(String, i32, VerifyResult), String> {
    // Snapshot what is needed and release the lock: everything below is I/O,
    // and a card PIN prompt can hold it for a minute while the UI waits.
    let (store, input, kind, data) = {
        let guard = lock(state);
        (
            guard.store.clone(),
            guard.dv_input.clone(),
            guard.dv_kind,
            guard.dv_data.clone(),
        )
    };
    let input = input.ok_or_else(|| "Choose a file first".to_string())?;

    if kind == InputKind::DetachedSignature {
        let data = data.ok_or_else(|| "Choose the file the signature covers".to_string())?;

        let result = ops::verify_detached_files(&store, &input, &data)
            .map_err(|e| format!("Verification failed: {e}"))?;

        let summary = if result.signatures.is_empty() {
            ("The file contains no signature".to_string(), 2)
        } else {
            signature_verdict(&lock(state).all, &result)
        };
        return Ok((summary.0, summary.1, result));
    }

    let output = ops::decrypted_name(&input);
    // One field here, but still a candidate list: the Decrypt/Verify dialog
    // asks for "the passphrase or password", so the single value it collects
    // may be either.
    let candidates: Vec<&str> = Some(password)
        .filter(|p| !p.is_empty())
        .into_iter()
        .collect();
    let result = ops::decrypt_file(&store, &input, &candidates, &output)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    let written = format!("Decrypted to {}", output.display());
    let summary = if result.signatures.is_empty() {
        (format!("{written}. The message was not signed."), 2)
    } else {
        // The same verdict the verify path gives, prefixed with where the
        // plaintext went. Composed rather than restated so the two cannot
        // drift apart on what counts as verified.
        let (verdict, tone) = signature_verdict(&lock(state).all, &result);
        (format!("{written}. {verdict}"), tone)
    };
    Ok((summary.0, summary.1, result))
}

fn push_decrypt_verify(ui: &AppWindow, state: &State) {
    ui.set_dv_needs_data(state.dv_kind == InputKind::DetachedSignature);

    ui.set_dv_input(match &state.dv_input {
        Some(path) => path.display().to_string().into(),
        None => SharedString::new(),
    });
    ui.set_dv_data(match &state.dv_data {
        Some(path) => path.display().to_string().into(),
        None => SharedString::new(),
    });
    ui.set_dv_output(match &state.dv_input {
        Some(path) => ops::decrypted_name(path).display().to_string().into(),
        None => SharedString::new(),
    });
}

// ------------------------------------------------------------ certify / trust

fn wire_certify(ui: &AppWindow, state: &Shared) {
    ui.on_open_certify({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let mut guard = lock(&state);

            let Some(target) = usize::try_from(ui.get_current_row())
                .ok()
                .and_then(|r| guard.shown_at(r))
                .cloned()
            else {
                return;
            };

            // Every user ID starts ticked: certifying a person usually means
            // certifying the identity you just checked, and they normally have
            // one. Unticking is cheaper than hunting for the right box. The
            // exception is one the holder has revoked — a name they have
            // disowned, which core refuses to sign anyway, so offering it
            // pre-ticked only sets up an error at the end of the dialog.
            let revoked: std::collections::HashSet<String> = guard
                .store
                .lookup(&target.fingerprint)
                .map(|cert| {
                    rpgp_core::cert::user_ids(&cert)
                        .into_iter()
                        .filter(|uid| uid.revoked)
                        .map(|uid| uid.text)
                        .collect()
                })
                .unwrap_or_default();
            let user_ids: Vec<(String, bool)> = target
                .user_ids
                .iter()
                .map(|uid| (uid.clone(), !revoked.contains(uid)))
                .collect();

            let certifiers: Vec<(String, String)> = guard
                .all
                .iter()
                .filter(|c| c.can_certify && (c.has_secret || c.agent_backed))
                .map(|c| {
                    let label = match &c.card_serial {
                        Some(_) => format!("{} (smartcard)", c.primary_user_id),
                        None => c.primary_user_id.clone(),
                    };
                    (c.fingerprint.clone(), label)
                })
                .collect();

            guard.certify_target = Some(target.fingerprint.clone());
            guard.certify_user_ids = user_ids;
            guard.certify_certifiers = certifiers;

            ui.set_certify_target(target.primary_user_id.clone().into());
            push_certify(&ui, &guard);
            drop(guard);
            ui.set_certify_open(true);
        }
    });

    ui.on_certify_toggle_user_id({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let mut guard = lock(&state);
            if let Some(entry) = usize::try_from(index)
                .ok()
                .and_then(|i| guard.certify_user_ids.get_mut(i))
            {
                entry.1 = !entry.1;
            }
            push_certify(&ui, &guard);
        }
    });

    ui.on_certify_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |certifier_index, publishable, introducer, confidence, password| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            ui.set_busy(true);
            ui.set_status("Certifying…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let password = password.to_string();
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let outcome = run_certify(
                    &state,
                    certifier_index,
                    publishable,
                    introducer,
                    confidence,
                    &password,
                );
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok(count) => {
                            ui.set_certify_open(false);
                            reload(&ui, &state);
                            ui.set_status(format!("Certified {count} user ID(s)").into());
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });

    ui.on_toggle_trust_root({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let fingerprint = ui.get_detail().fingerprint.to_string();
            if fingerprint.is_empty() {
                return;
            }

            let outcome = {
                let guard = lock(&state);
                let was_root = guard
                    .all
                    .iter()
                    .find(|c| c.fingerprint == fingerprint)
                    .is_some_and(|c| c.is_trust_root);
                guard.store.set_trust_root(&fingerprint, !was_root)
            };

            match outcome {
                Ok(()) => {
                    // Trust roots change what the whole graph authenticates,
                    // so this is a full recompute, not a row update.
                    reload(&ui, &state);
                    reselect(&ui, &state, &fingerprint);
                }
                Err(e) => ui.set_status(format!("Could not change trust root: {e}").into()),
            }
        }
    });
}

/// The blocking half of Certify, run on a worker thread.
fn run_certify(
    state: &Shared,
    certifier_index: i32,
    publishable: bool,
    introducer: bool,
    confidence: i32,
    password: &str,
) -> Result<usize, String> {
    // Snapshot what is needed and release the lock: everything below is I/O,
    // and a card PIN prompt can hold it for a minute while the UI waits.
    let (store, target, certifier, user_ids) = {
        let guard = lock(state);
        let target = guard
            .certify_target
            .clone()
            .ok_or_else(|| "No certificate selected".to_string())?;
        let (certifier, _) = guard
            .certify_certifiers
            .get(certifier_index.max(0) as usize)
            .ok_or_else(|| "Choose a key to certify with".to_string())?;
        let user_ids: Vec<String> = guard
            .certify_user_ids
            .iter()
            .filter(|(_, selected)| *selected)
            .map(|(uid, _)| uid.clone())
            .collect();
        (guard.store.clone(), target, certifier.clone(), user_ids)
    };
    if user_ids.is_empty() {
        return Err("Select at least one user ID".to_string());
    }

    let mut request = CertifyRequest::new(certifier, target);
    request.user_ids = user_ids;
    request.exportable = publishable;
    request.depth = if introducer { 1 } else { 0 };
    request.amount = if confidence == 0 {
        certify::FULL
    } else {
        certify::PARTIAL
    };
    request.password = Some(Zeroizing::new(password.to_string())).filter(|p| !p.is_empty());

    let count = request.user_ids.len();
    certify::certify(&store, &request).map_err(|e| format!("Certification failed: {e}"))?;
    Ok(count)
}

fn push_certify(ui: &AppWindow, state: &State) {
    let rows: Vec<UserIdRow> = state
        .certify_user_ids
        .iter()
        .map(|(text, selected)| UserIdRow {
            text: text.clone().into(),
            selected: *selected,
        })
        .collect();

    let certifiers: Vec<SharedString> = state
        .certify_certifiers
        .iter()
        .map(|(_, label)| SharedString::from(label.as_str()))
        .collect();

    ui.set_certify_chosen(state.certify_user_ids.iter().filter(|(_, s)| *s).count() as i32);
    ui.set_certify_user_ids(ModelRc::new(VecModel::from(rows)));
    ui.set_certify_certifiers(ModelRc::new(VecModel::from(certifiers)));
}

/// Load and display the certifications on one certificate.
fn push_certifications(ui: &AppWindow, state: &State, summary: &CertSummary) {
    let certifications = match state.store.lookup(&summary.fingerprint) {
        Ok(cert) => certify::certifications(&state.store, &cert).unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    // Offer to withdraw only what is actually still standing — per key and
    // per user ID, not store-wide. The old test asked "have I certified
    // anything, and have I revoked anything", so one key withdrawing hid the
    // button while another key's endorsement was still in force, leaving no
    // way to withdraw it from the app at all.
    let withdrawn: HashSet<(&str, Option<&str>)> = certifications
        .iter()
        .filter(|c| c.by_me && c.is_revocation)
        .map(|c| (c.user_id.as_str(), c.certifier_fingerprint.as_deref()))
        .collect();
    let withdrawable = certifications.iter().any(|c| {
        c.by_me
            && !c.is_revocation
            && !withdrawn.contains(&(c.user_id.as_str(), c.certifier_fingerprint.as_deref()))
    });

    let rows: Vec<CertificationRow> = certifications
        .iter()
        .map(|c| certification_row(c, summary.user_ids.len() > 1))
        .collect();

    ui.set_detail_certifications(ModelRc::new(VecModel::from(rows)));
    ui.set_can_withdraw(withdrawable);
    ui.set_has_revocation_cert(
        summary.has_secret && state.store.has_revocation(&summary.fingerprint),
    );
}

fn certification_row(certification: &Certification, show_user_id: bool) -> CertificationRow {
    let mut parts: Vec<String> = Vec::new();

    if show_user_id {
        parts.push(certification.user_id.clone());
    }
    if certification.is_revocation {
        parts.push("withdrawn".to_string());
    } else {
        parts.push(
            if certification.amount >= certify::FULL {
                "full"
            } else {
                "partial"
            }
            .to_string(),
        );
    }
    parts.push(
        if certification.exportable {
            "publishable"
        } else {
            "local"
        }
        .to_string(),
    );
    if certification.depth > 0 {
        parts.push(format!("introducer, depth {}", certification.depth));
    }
    if let Some(created) = certification.created {
        parts.push(format_time(Some(created)));
    }
    match certification.verified {
        Some(true) => {}
        Some(false) => parts.push("signature does not check out".to_string()),
        None => parts.push("certifier not in this store".to_string()),
    }

    CertificationRow {
        certifier: certification.certifier.clone().into(),
        user_id: certification.user_id.clone().into(),
        detail: parts.join(" · ").into(),
        good: certification.is_good(),
        by_me: certification.by_me,
        is_revocation: certification.is_revocation,
    }
}

/// Re-select the row for `fingerprint` after the list has been rebuilt.
fn reselect(ui: &AppWindow, state: &Shared, fingerprint: &str) {
    let guard = lock(state);
    let Some(index) = guard.shown.iter().position(|&i| {
        guard
            .all
            .get(i)
            .is_some_and(|c| c.fingerprint == fingerprint)
    }) else {
        return;
    };

    let Some(summary) = guard.shown_at(index).cloned() else {
        return;
    };
    ui.set_current_row(index as i32);
    ui.set_detail(to_row(&summary));
    ui.set_has_selection(true);
    push_certifications(ui, &guard, &summary);
}

// --------------------------------------------------------------------- lookup

fn wire_lookup(ui: &AppWindow, state: &Shared) {
    ui.on_open_lookup({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            lock(&state).lookup_results.clear();
            ui.set_lookup_results(ModelRc::new(VecModel::from(Vec::<LookupRow>::new())));
            ui.set_lookup_status(SharedString::new());
            ui.set_lookup_searched(false);
            ui.set_lookup_open(true);
        }
    });

    ui.on_lookup_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |query| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            ui.set_busy(true);
            ui.set_lookup_status("Searching…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let query = query.to_string();
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                // Off the UI thread: this is a network round trip that can sit
                // on a DNS timeout for seconds.
                let outcome = rpgp_core::keyserver::lookup(&query);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    ui.set_lookup_searched(true);

                    match outcome {
                        Ok(found) => {
                            let mut guard = lock(&state);
                            let rows: Vec<LookupRow> = found
                                .iter()
                                .map(|f| {
                                    let summary = rpgp_core::CertSummary::from_cert(&f.cert);
                                    let (name, email) = split_user_id(&summary.primary_user_id);
                                    LookupRow {
                                        primary_user_id: summary.primary_user_id.clone().into(),
                                        fingerprint_pretty: summary.fingerprint_pretty().into(),
                                        source: f.source.as_str().into(),
                                        initials: initials(&name, &email, &summary.key_id).into(),
                                        tint_index: tint_index(&summary.fingerprint),
                                        already_known: guard
                                            .store
                                            .lookup(&summary.fingerprint)
                                            .is_ok(),
                                    }
                                })
                                .collect();
                            let count = rows.len();
                            guard.lookup_results = found;
                            drop(guard);

                            ui.set_lookup_results(ModelRc::new(VecModel::from(rows)));
                            ui.set_lookup_status(
                                if count == 0 {
                                    "Nothing found for that.".to_string()
                                } else {
                                    format!("{count} certificate(s) found. Check the fingerprint against the owner before trusting it.")
                                }
                                .into(),
                            );
                        }
                        Err(e) => {
                            ui.set_lookup_results(ModelRc::new(VecModel::from(
                                Vec::<LookupRow>::new(),
                            )));
                            ui.set_lookup_status(format!("Lookup failed: {e}").into());
                        }
                    }
                });
            });
        }
    });

    ui.on_lookup_import({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let outcome = {
                let guard = lock(&state);
                match usize::try_from(index)
                    .ok()
                    .and_then(|i| guard.lookup_results.get(i))
                {
                    Some(found) => guard
                        .store
                        .insert(&found.cert)
                        .map(|()| rpgp_core::CertSummary::from_cert(&found.cert).primary_user_id),
                    None => return,
                }
            };

            match outcome {
                Ok(who) => {
                    reload(&ui, &state);
                    // Imported, not trusted: a fetched certificate is
                    // unauthenticated until somebody certifies it.
                    ui.set_lookup_status(
                        format!("Imported {who}. It is unverified until you certify it.").into(),
                    );
                    ui.set_status(format!("Imported {who} from the network").into());
                }
                Err(e) => ui.set_lookup_status(format!("Import failed: {e}").into()),
            }
        }
    });
}

// ------------------------------------------------------------------ lifecycle

fn wire_lifecycle(ui: &AppWindow, state: &Shared) {
    let open = |ui: &AppWindow, mode: i32, target: SharedString| {
        ui.set_lifecycle_mode(mode);
        ui.set_lifecycle_target(target);
        ui.set_lifecycle_open(true);
    };

    ui.on_open_expiry({
        let ui_weak = ui.as_weak();
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, 0, SharedString::new());
        }
    });
    ui.on_open_revoke_subkey({
        let ui_weak = ui.as_weak();
        move |subkey| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, 4, subkey);
        }
    });
    ui.on_open_publish({
        let ui_weak = ui.as_weak();
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, 3, SharedString::new());
        }
    });
    ui.on_open_add_user_id({
        let ui_weak = ui.as_weak();
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, 1, SharedString::new());
        }
    });
    ui.on_open_revoke_user_id({
        let ui_weak = ui.as_weak();
        move |user_id| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, 2, user_id);
        }
    });

    ui.on_lifecycle_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |mode, expiry, value, password, reason| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let fingerprint = ui.get_detail().fingerprint.to_string();
            let target = ui.get_lifecycle_target().to_string();
            ui.set_busy(true);
            ui.set_status("Working…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let input = LifecycleInput {
                mode,
                fingerprint,
                target,
                expiry: expiry.to_string(),
                value: value.to_string(),
                password: password.to_string(),
                reason,
            };
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let outcome = run_lifecycle(&state, &input);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok((message, fingerprint)) => {
                            ui.set_lifecycle_open(false);
                            reload(&ui, &state);
                            reselect(&ui, &state, &fingerprint);
                            ui.set_status(message.into());
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });
}

/// Everything the lifecycle dialog hands over, as one value: it carries a
/// mode selector plus the union of every mode's inputs, and the worker reads
/// the ones its mode needs.
struct LifecycleInput {
    mode: i32,
    fingerprint: String,
    /// The user ID or subkey fingerprint a revoke mode is about.
    target: String,
    /// Index into the expiry choices, as the dialog reports it.
    expiry: String,
    value: String,
    password: String,
    /// Index into Reason::ALL; only mode 4 reads it.
    reason: i32,
}

fn run_lifecycle(state: &Shared, input: &LifecycleInput) -> Result<(String, String), String> {
    let LifecycleInput {
        mode,
        fingerprint,
        target,
        expiry,
        value,
        password,
        reason,
    } = input;
    let (mode, reason) = (*mode, *reason);
    let (fingerprint, target, expiry, value) = (
        fingerprint.as_str(),
        target.as_str(),
        expiry.as_str(),
        value.as_str(),
    );
    // Snapshot what is needed and release the lock: everything below is I/O,
    // and a card PIN prompt can hold it for a minute while the UI waits.
    let store = lock(state).store.clone();
    let password = Some(password.as_str()).filter(|p| !p.is_empty());

    match mode {
        0 => {
            let index: i32 = expiry.parse().unwrap_or(0);
            lifecycle::set_expiry(&store, fingerprint, expiry_from_index(index), password)
                .map_err(|e| format!("Could not change the expiry: {e}"))?;
            Ok((
                match expiry_from_index(index) {
                    Some(_) => "Expiry updated. Publish the key again so others see it.",
                    None => "Expiry removed. Publish the key again so others see it.",
                }
                .to_string(),
                fingerprint.to_string(),
            ))
        }
        1 => {
            lifecycle::add_user_id(&store, fingerprint, value, password)
                .map_err(|e| format!("Could not add the user ID: {e}"))?;
            Ok((
                "User ID added. Publish the key again so others see it.".to_string(),
                fingerprint.to_string(),
            ))
        }
        2 => {
            lifecycle::revoke_user_id(&store, fingerprint, target, value, password)
                .map_err(|e| format!("Could not revoke the user ID: {e}"))?;
            Ok((
                "User ID revoked. Publish the key so others stop using it.".to_string(),
                fingerprint.to_string(),
            ))
        }
        4 => {
            lifecycle::revoke_subkey(
                &store,
                fingerprint,
                target,
                Reason::from_index(reason),
                value,
                password,
            )
            .map_err(|e| format!("Could not revoke the subkey: {e}"))?;
            Ok((
                "Subkey revoked. Publish the key so others stop using it.".to_string(),
                fingerprint.to_string(),
            ))
        }
        // Publish is mode 3 and says so. It used to be the catch-all arm,
        // which meant any mode this function did not recognise performed an
        // irreversible upload to a public keyserver.
        3 => {
            // Only ever the public half — `keyserver::publish` strips
            // secret key material before it serialises anything.
            let cert = store
                .lookup(fingerprint)
                .map_err(|e| format!("Certificate unavailable: {e}"))?;
            let published = rpgp_core::keyserver::publish(&cert)
                .map_err(|e| format!("Publishing failed: {e}"))?;

            let pending: Vec<String> = published
                .addresses
                .iter()
                .filter(|(_, state)| state != "published")
                .map(|(address, _)| address.clone())
                .collect();

            // Ask for the confirmation mails, since an unverified address is
            // stored but never served.
            let mut message = format!("Published {}", published.fingerprint);
            if let Some(token) = published.token.as_deref()
                && !pending.is_empty()
            {
                // Reported either way. The upload cannot be undone and an
                // unverified address is stored but never served, so a silently
                // swallowed failure here left the user believing the key was
                // published and searchable when only the first half was true.
                match rpgp_core::keyserver::request_verification(token, &pending) {
                    Ok(()) => message.push_str(&format!(
                        ". Confirmation mail sent to {}; the address is not served until it is confirmed.",
                        pending.join(", ")
                    )),
                    Err(e) => message.push_str(&format!(
                        ". The key is uploaded, but asking for the confirmation mail to {} failed ({e}); \
                         until that succeeds the address is stored and not served. Publish again to retry.",
                        pending.join(", ")
                    )),
                }
            }
            Ok((message, fingerprint.to_string()))
        }
        // Anything else is a bug in the dialog, not an instruction. Erring is
        // the only safe response: every arm above either writes to the store
        // or uploads to the network.
        other => Err(format!("Unknown lifecycle action {other}")),
    }
}

// -------------------------------------------------------------------- notepad

fn wire_notepad(ui: &AppWindow, state: &Shared) {
    ui.on_open_details({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let guard = lock(&state);
            let fingerprint = ui.get_detail().fingerprint.to_string();
            let Ok(cert) = guard.store.lookup(&fingerprint) else {
                return;
            };

            let user_ids: Vec<UserIdDetailRow> = rpgp_core::cert::user_ids(&cert)
                .iter()
                .map(|u| UserIdDetailRow {
                    text: u.text.clone().into(),
                    is_primary: u.is_primary,
                    revoked: u.revoked,
                    self_signed: format_time(u.self_signed).into(),
                })
                .collect();
            let subkeys: Vec<SubkeyRow> = rpgp_core::cert::subkeys(&cert)
                .iter()
                .map(|k| SubkeyRow {
                    fingerprint: k.fingerprint.clone().into(),
                    algorithm: k.algorithm.clone().into(),
                    created: format_time(Some(k.created)).into(),
                    expires: format_time(k.expires).into(),
                    capabilities: k.capabilities().into(),
                    revoked: k.revoked,
                    has_secret: k.has_secret,
                })
                .collect();

            ui.set_detail_user_ids(ModelRc::new(VecModel::from(user_ids)));
            ui.set_detail_subkeys(ModelRc::new(VecModel::from(subkeys)));
            drop(guard);
            ui.set_details_open(true);
        }
    });

    ui.on_open_notepad({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            // Shares the Sign / Encrypt models, so opening the notepad has to
            // fill them the same way.
            load_signing_targets(&ui, &state);
            ui.set_np_output(SharedString::new());
            ui.set_np_result(SharedString::new());
            ui.set_np_tone(0);
            ui.set_np_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
            ui.set_notepad_open(true);
        }
    });

    ui.on_filter_recipients({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |text| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let mut guard = lock(&state);
            guard.se_filter = text.to_string();
            push_sign_encrypt(&ui, &guard);
        }
    });

    ui.on_copy_value({
        let ui_weak = ui.as_weak();
        move |text| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            // The row confirms itself in Slint; the status line is for the
            // case the clipboard refuses, which is otherwise invisible.
            match copy_to_clipboard(text.to_string()) {
                Ok(()) => ui.set_status("Copied to the clipboard".into()),
                Err(e) => ui.set_status(format!("Could not copy: {e}").into()),
            }
        }
    });

    ui.on_np_copy({
        let ui_weak = ui.as_weak();
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let text = ui.get_np_output().to_string();
            match copy_to_clipboard(text) {
                Ok(()) => {
                    ui.set_np_copied(true);
                    ui.set_status("Copied to the clipboard".into());
                    // Let the button say so, then go back to offering the action.
                    let ui_weak = ui.as_weak();
                    slint::Timer::single_shot(std::time::Duration::from_millis(1500), move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_np_copied(false);
                        }
                    });
                }
                Err(e) => ui.set_status(format!("Could not copy: {e}").into()),
            }
        }
    });

    ui.on_np_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |action, text, signer_index, password, secret| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            ui.set_busy(true);
            ui.set_status("Working…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let (text, password, secret) =
                (text.to_string(), password.to_string(), secret.to_string());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let outcome = run_notepad(&state, action, &text, signer_index, &password, &secret);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok((output, summary, tone, signatures)) => {
                            let rows = signature_rows(&lock(&state).all, &signatures);
                            ui.set_np_signatures(ModelRc::new(VecModel::from(rows)));
                            ui.set_np_output(output.into());
                            ui.set_np_result(summary.clone().into());
                            ui.set_np_tone(tone);
                            ui.set_status(summary.into());
                        }
                        Err(message) => {
                            // Clear the previous run's verdict and output, as
                            // the Decrypt/Verify worker does on this branch.
                            // Both persist for the life of the dialog and were
                            // cleared only at open, so a failed run left the
                            // last message's "good signature — Alice
                            // (verified)" row and her plaintext on screen under
                            // a red banner describing a different message.
                            ui.set_np_signatures(ModelRc::new(VecModel::from(
                                Vec::<SignatureRow>::new(),
                            )));
                            ui.set_np_output(SharedString::new());
                            ui.set_np_result(message.clone().into());
                            ui.set_np_tone(3);
                            ui.set_status(message.into());
                        }
                    }
                });
            });
        }
    });
}

/// The blocking half of the notepad. Returns the output text, a summary line,
/// a tone for the banner, and any signatures found.
fn run_notepad(
    state: &Shared,
    action: i32,
    text: &str,
    signer_index: i32,
    password: &str,
    secret: &str,
) -> Result<(String, String, i32, Vec<rpgp_core::ops::SignatureReport>), String> {
    // Snapshot what is needed and release the lock: everything below is I/O,
    // and a card PIN prompt can hold it for a minute while the UI waits.
    let (store, signers, chosen) = {
        let guard = lock(state);
        (
            guard.store.clone(),
            guard.se_signers.clone(),
            guard
                .se_recipients
                .iter()
                .filter(|r| r.selected)
                .map(|r| (r.fingerprint.clone(), r.label.clone()))
                .collect::<Vec<_>>(),
        )
    };
    let password = Some(password).filter(|p| !p.is_empty());

    // Return types inferred: naming them would mean importing a Sequoia
    // type into the GUI, which this crate deliberately avoids.
    let signer = || {
        let (fingerprint, _) = signers
            .get(signer_index.max(0) as usize)
            .ok_or_else(|| "Choose a key to sign with".to_string())?;
        store
            .secret_cert(fingerprint)
            .or_else(|_| store.lookup(fingerprint))
            .map_err(|e| format!("Signing key unavailable: {e}"))
    };

    let recipients = || {
        let mut out = Vec::new();
        for (fingerprint, label) in &chosen {
            out.push(
                store
                    .lookup(fingerprint)
                    .map_err(|e| format!("Recipient {label} unavailable: {e}"))?,
            );
        }
        // A password on its own is a complete instruction; only object when
        // there is neither.
        if out.is_empty() && secret.is_empty() {
            return Err("Select a recipient, or set a password".to_string());
        }
        Ok::<_, String>(out)
    };

    let mut output = Vec::new();
    match action {
        // Cleartext, not detached: a detached signature is useless in a text
        // box, since there is nowhere to put the file it covers.
        0 => {
            let cert = signer()?;
            ops::sign_cleartext(&cert, password, text.as_bytes(), &mut output)
                .map_err(|e| format!("Signing failed: {e}"))?;
            Ok((
                string_of(output),
                "Signed. The text stays readable to anyone.".to_string(),
                1,
                Vec::new(),
            ))
        }
        1 | 2 => {
            let certs = recipients()?;
            let signing = if action == 2 { Some(signer()?) } else { None };
            let passwords: Vec<String> = if secret.is_empty() {
                Vec::new()
            } else {
                vec![secret.to_string()]
            };
            ops::encrypt(
                &certs,
                &passwords,
                signing.as_ref().map(|cert| (cert, password)),
                text.as_bytes(),
                &mut output,
            )
            .map_err(|e| format!("Encryption failed: {e}"))?;
            let what = if action == 2 {
                "Signed and encrypted"
            } else {
                "Encrypted"
            };
            Ok((string_of(output), what.to_string(), 1, Vec::new()))
        }
        // Decrypt, or verify if what was pasted is a bare signature.
        _ => {
            if ops::classify(text.as_bytes()) == InputKind::DetachedSignature {
                return Err(
                    "That is a detached signature; it needs the file it signs, so use \
                     Decrypt / Verify instead."
                        .to_string(),
                );
            }

            // Cleartext-signed text carries its own content, so it is verified
            // rather than decrypted.
            if text.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
                let (verified, result) = ops::verify_inline(&store, text.as_bytes())
                    .map_err(|e| format!("Verification failed: {e}"))?;
                let (summary, tone) = signature_verdict(&lock(state).all, &result);
                return Ok((string_of(verified), summary, tone, result.signatures));
            }
            // Both fields, as candidates. The notepad shows a key passphrase
            // and a message password, and which one opens a given message is
            // not something the dialog can know — passing only the passphrase
            // is what made text encrypted to a password impossible to read
            // back.
            let mut candidates: Vec<&str> = Vec::new();
            candidates.extend(password);
            if !secret.is_empty() {
                candidates.push(secret);
            }
            // Bounded: the notepad's output is a text box, and a compressed
            // layer expands to whatever the sender chose.
            let result = ops::decrypt_to_memory(&store, text.as_bytes(), &candidates, &mut output)
                .map_err(|e| format!("Decryption failed: {e}"))?;

            let (summary, tone) = if result.signatures.is_empty() {
                ("Decrypted. The message was not signed.".to_string(), 2)
            } else {
                let (verdict, tone) = signature_verdict(&lock(state).all, &result);
                (format!("Decrypted. {verdict}"), tone)
            };
            Ok((string_of(output), summary, tone, result.signatures))
        }
    }
}

/// Armored output is text; anything else is shown as a note rather than as
/// mojibake.
fn string_of(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|e| format!("<{} bytes of binary output>", e.as_bytes().len()))
}

/// Fill the shared recipient and signer models from the store.
/// Fill the shared recipient and signer models from the store.
///
/// `preselect` is the one thing the two callers disagree about: the
/// sign/encrypt dialog ticks whatever the list has highlighted, the notepad
/// starts with nothing ticked. Everything else — who can receive, who can
/// sign, how each is labelled — was duplicated verbatim between them, which is
/// two places to keep in step for every change to how recipients are chosen.
fn build_signing_targets(state: &mut State, preselect: Option<&str>) {
    let recipients: Vec<Recipient> = state
        .all
        .iter()
        .filter(|c| c.can_encrypt)
        .map(|c| {
            let (name, email) = split_user_id(&c.primary_user_id);
            Recipient {
                selected: preselect == Some(c.fingerprint.as_str()),
                initials: initials(&name, &email, &c.key_id),
                tint: tint_index(&c.fingerprint),
                label: if name.is_empty() {
                    c.primary_user_id.clone()
                } else {
                    name
                },
                sublabel: if email.is_empty() {
                    c.key_id.clone()
                } else {
                    email
                },
                fingerprint: c.fingerprint.clone(),
            }
        })
        .collect();

    // A card key has no local secret: the agent holds it. Label those so it is
    // obvious which choice will ask for a PIN.
    let signers: Vec<(String, String)> = state
        .all
        .iter()
        .filter(|c| c.can_sign && (c.has_secret || c.agent_backed))
        .map(|c| {
            let label = match &c.card_serial {
                Some(_) => format!("{} (smartcard)", c.primary_user_id),
                None => c.primary_user_id.clone(),
            };
            (c.fingerprint.clone(), label)
        })
        .collect();

    state.se_recipients = recipients;
    state.se_filter.clear();
    state.se_signers = signers;
}

fn load_signing_targets(ui: &AppWindow, state: &Shared) {
    let mut guard = lock(state);
    build_signing_targets(&mut guard, None);
    push_sign_encrypt(ui, &guard);
}

// ----------------------------------------------------------------- revocation

fn wire_delete(ui: &AppWindow, state: &Shared) {
    ui.on_open_delete({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            let detail = ui.get_detail();
            let fingerprint = detail.fingerprint.to_string();
            if fingerprint.is_empty() {
                return;
            }

            let (has_secret, has_revocation) = {
                let guard = lock(&state);
                (
                    guard.store.has_secret(&fingerprint),
                    guard.store.has_revocation(&fingerprint),
                )
            };

            ui.set_delete_target(detail.primary_user_id.clone());
            ui.set_delete_has_secret(has_secret);
            ui.set_delete_has_revocation(has_revocation);
            ui.set_delete_confirm_word(detail.key_id.clone());
            ui.set_delete_open(true);
        }
    });

    ui.on_delete_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            ui.set_busy(true);
            ui.set_status("Deleting…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let fingerprint = ui.get_detail().fingerprint.to_string();
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let outcome = run_delete(&state, &fingerprint);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok(message) => {
                            ui.set_delete_open(false);
                            reload(&ui, &state);
                            ui.set_status(message.into());
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });
}

/// Delete, then swap in a store that can actually see the deletion.
///
/// A live `Store` keeps reporting a deleted certificate, because the index
/// scan that prunes it is rate-limited. Reopening is the only way to get a
/// current view, and it is I/O, so it happens off the lock like every other
/// worker here.
fn run_delete(state: &Shared, fingerprint: &str) -> Result<String, String> {
    let store = {
        let guard = lock(state);
        guard.store.clone()
    };

    let had_secret = store.has_secret(fingerprint);
    store
        .delete(fingerprint, had_secret)
        .map_err(|e| format!("Could not delete the certificate: {e}"))?;

    let refreshed =
        Arc::new(store.reopen().map_err(|e| {
            format!("Deleted, but the certificate list could not be refreshed: {e}")
        })?);

    lock(state).store = refreshed;

    Ok(if had_secret {
        "Key and secret key deleted. The revocation certificate was kept.".to_string()
    } else {
        "Certificate deleted.".to_string()
    })
}

fn wire_revoke(ui: &AppWindow, state: &Shared) {
    ui.on_open_revoke({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open_revoke_dialog(&ui, &state, false);
        }
    });

    ui.on_open_withdraw({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open_revoke_dialog(&ui, &state, true);
        }
    });

    ui.on_revoke_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |reason, message, password| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            ui.set_busy(true);
            ui.set_status("Revoking…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let (message, password) = (message.to_string(), password.to_string());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let outcome = run_revoke(&state, reason, &message, &password);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok((fingerprint, message)) => {
                            ui.set_revoke_open(false);
                            reload(&ui, &state);
                            reselect(&ui, &state, &fingerprint);
                            ui.set_status(message.into());
                        }
                        Err(message) => ui.set_status(message.into()),
                    }
                });
            });
        }
    });

    ui.on_save_revocation_cert({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let _ = slint::spawn_local(async move {
                let (source, suggested) = {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    let fingerprint = ui.get_detail().fingerprint.to_string();
                    let guard = lock(&state);
                    (
                        guard.store.revocation_path(&fingerprint),
                        format!("{}-revocation.asc", ui.get_detail().key_id),
                    )
                };

                let Some(file) = rfd::AsyncFileDialog::new()
                    .set_title("Save revocation certificate")
                    .set_file_name(&suggested)
                    .save_file()
                    .await
                else {
                    return;
                };

                let Some(ui) = ui_weak.upgrade() else {
                    return;
                };
                ui.set_status(
                    match std::fs::copy(&source, file.path()) {
                        Ok(_) => format!(
                            "Saved to {}. Keep it somewhere you can reach without this key.",
                            file.path().display()
                        ),
                        Err(e) => format!("Could not save the revocation certificate: {e}"),
                    }
                    .into(),
                );
            });
        }
    });
}

fn open_revoke_dialog(ui: &AppWindow, state: &Shared, certification: bool) {
    let mut guard = lock(state);

    let Some(target) = usize::try_from(ui.get_current_row())
        .ok()
        .and_then(|r| guard.shown_at(r))
        .cloned()
    else {
        return;
    };

    guard.revoke_target = Some(target.fingerprint.clone());
    guard.revoke_certification = certification;
    drop(guard);

    ui.set_revoke_target(target.primary_user_id.into());
    ui.set_revoke_is_certification(certification);
    ui.set_revoke_open(true);
}

/// The blocking half of revocation. Returns the affected fingerprint so the
/// list can re-select it, and the line to show in the status bar.
fn run_revoke(
    state: &Shared,
    reason: i32,
    message: &str,
    password: &str,
) -> Result<(String, String), String> {
    // Snapshot what is needed and release the lock: everything below is I/O,
    // and a card PIN prompt can hold it for a minute while the UI waits.
    let (store, target, is_certification) = {
        let guard = lock(state);
        (
            guard.store.clone(),
            guard.revoke_target.clone(),
            guard.revoke_certification,
        )
    };
    let target = target.ok_or_else(|| "No certificate selected".to_string())?;
    let reason = Reason::from_index(reason);
    let password = Some(password).filter(|p| !p.is_empty());

    if is_certification {
        // Withdrawing our own endorsement: the certifier is whichever of our
        // keys actually made a certification on this certificate.
        let cert = store
            .lookup(&target)
            .map_err(|e| format!("Certificate unavailable: {e}"))?;
        let certifications = certify::certifications(&store, &cert).unwrap_or_default();

        // Grouped by which of our keys made each certification, because a
        // revocation only retracts a certification made by the same key. This
        // used to sign every withdrawal with whichever key happened to sort
        // first, so when two of our keys had certified the same person one
        // endorsement quietly survived while the status line said it had been
        // withdrawn. The user IDs are deduplicated too: the flat list repeated
        // them, and each repeat produced an identical revocation packet.
        let mut by_certifier: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for c in certifications
            .iter()
            .filter(|c| c.by_me && !c.is_revocation)
        {
            let Some(fingerprint) = c.certifier_fingerprint.clone() else {
                continue;
            };
            let ids = by_certifier.entry(fingerprint).or_default();
            if !ids.contains(&c.user_id) {
                ids.push(c.user_id.clone());
            }
        }
        if by_certifier.is_empty() {
            return Err("You have not certified this key".to_string());
        }

        // One passphrase is collected for the whole dialog, so a set of keys
        // with different passphrases stops at the first that will not unlock.
        // Reporting how far it got beats reporting a flat failure over work
        // that was partly done.
        let total = by_certifier.len();
        for (done, (certifier, user_ids)) in by_certifier.iter().enumerate() {
            revoke::revoke_certification(
                &store, certifier, &target, user_ids, reason, message, password,
            )
            .map_err(|e| {
                if done == 0 {
                    format!("Could not withdraw the certification: {e}")
                } else {
                    format!("Withdrew {done} of {total}; the rest failed: {e}")
                }
            })?;
        }

        return Ok((
            target,
            if total == 1 {
                "Certification withdrawn. It stops counting a second from now.".to_string()
            } else {
                format!("{total} certifications withdrawn, one per key that made them.")
            },
        ));
    }

    let mut request = RevokeRequest::new(&target);
    request.reason = reason;
    request.message = message.to_string();
    request.password = password.map(|p| Zeroizing::new(p.to_owned()));

    revoke::revoke_cert(&store, &request).map_err(|e| format!("Revocation failed: {e}"))?;
    Ok((
        target,
        "Key revoked. Publish or send the certificate so others stop using it.".to_string(),
    ))
}

// ------------------------------------------------------------------- plumbing

/// Re-read the store from disk and rebuild the list.
///
/// Everything here is local — cert-d, the trust graph, the secret-key
/// directory — and runs on the event loop because the list has to exist before
/// the call returns: several call sites follow it immediately with `reselect`.
///
/// It reads the secrets directory but does not open the keys in it: which
/// certificates have a secret half is answered from the filenames, via
/// [`Store::secret_fingerprints`]. The parts that leave the machine, and the
/// damaged-file survey that does re-parse every secret key, are handed to
/// [`survey_agent_and_secrets`] instead.
fn reload(ui: &AppWindow, state: &Shared) {
    let mut guard = lock(state);

    let certs = match guard.store.certs() {
        Ok(certs) => certs,
        Err(e) => {
            ui.set_status(format!("Cannot read the certificate store: {e}").into());
            return;
        }
    };

    guard.all = certs.iter().map(|c| CertSummary::from_cert(c)).collect();

    // Authentication is a property of the whole graph, so it is computed once
    // for the store rather than per certificate. Trust roots are the explicit
    // list plus every key whose secret half is here.
    let roots: Vec<String> = guard
        .store
        .effective_roots()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let explicit_roots = guard.store.trust_roots().unwrap_or_default();
    let authenticated = wot::authenticate_all(&certs, &roots);

    // The secret half lives outside cert-d, so ask the store which ones it has
    // — once, as a set. Asking per certificate meant a stat syscall and four
    // string allocations each, to re-derive what the directory listing above
    // already produced.
    let secrets = guard.store.secret_fingerprints().unwrap_or_default();
    let State { all, .. } = &mut *guard;
    for summary in all.iter_mut() {
        let key = summary.fingerprint.to_uppercase();
        summary.has_secret = secrets.contains(&key);
        summary.is_trust_root = explicit_roots.contains(&key);
        // The verdict for the identity actually shown on the row, not the
        // best over every identity on the certificate.
        summary.authentication = wot::for_user_id(&authenticated, &key, &summary.primary_user_id);
    }

    // Ordering belongs to apply_filter, so changing the sort does not
    // require re-reading the store.

    let store = guard.store.clone();
    drop(guard);
    apply_filter(ui, state);
    survey_agent_and_secrets(ui, state, store);
}

/// Turn signature reports into rows, resolving each signer's authentication.
///
/// `rpgp-core` deliberately reports only what it can prove about a signature:
/// that the bytes verify against a key, and which key. Whether that key really
/// belongs to the name on it is a property of the whole store — the web of
/// trust computed in `reload` — so it can only be answered here, where the
/// store's own view lives.
///
/// Carrying it this far is the point. The list pane distinguishes a valid
/// certificate from an authenticated one, exactly as the README describes; the
/// verify banner did not, so a lookalike key produced the same reassurance as
/// the real one.
fn signature_rows(known: &[CertSummary], signatures: &[ops::SignatureReport]) -> Vec<SignatureRow> {
    signatures
        .iter()
        .map(|s| {
            let authentication = s
                .fingerprint
                .as_deref()
                .and_then(|fingerprint| {
                    known
                        .iter()
                        .find(|c| c.fingerprint.eq_ignore_ascii_case(fingerprint))
                })
                .map(|c| c.authentication)
                .unwrap_or_default();
            SignatureRow {
                good: s.good,
                signer: s.signer.clone().into(),
                detail: s.detail.clone().into(),
                authentication: authentication.as_str().into(),
                authenticated: authentication == rpgp_core::Authentication::Full,
            }
        })
        .collect()
}

/// The banner for a verify or decrypt result: what to say, and in what tone.
///
/// A signature that verifies cryptographically but comes from a key nobody has
/// authenticated is not "verified" in the sense a reader takes from that word.
/// Tone 1 (the reassuring one) is reserved for signatures whose signer is
/// authenticated; a good signature from an unknown key gets tone 2 and says
/// so.
fn signature_verdict(known: &[CertSummary], result: &ops::VerifyResult) -> (String, i32) {
    if result.signatures.is_empty() {
        return ("The message was not signed".to_string(), 2);
    }
    if !result.all_good() {
        return ("Signature is NOT valid".to_string(), 3);
    }
    let rows = signature_rows(known, &result.signatures);
    if rows.iter().all(|r| r.authenticated) {
        ("Signature verified".to_string(), 1)
    } else {
        (
            "Valid signature, but the signer's identity is not verified".to_string(),
            2,
        )
    }
}

/// Put `text` on the system clipboard.
///
/// One clipboard for the process, not one per click. On X11 arboard serves the
/// selection from a window it owns, and dropping the last handle destroys that
/// window after a single 100ms attempt to hand the contents to a clipboard
/// manager — so a handle created and dropped inside a callback loses the text
/// immediately on any session without one running. Both copy callbacks run on
/// the event loop, so a thread-local is enough, and its destructor still makes
/// the handover at exit, which is where that belongs.
fn copy_to_clipboard(text: String) -> std::result::Result<(), String> {
    thread_local! {
        static CLIPBOARD: RefCell<Option<arboard::Clipboard>> = const { RefCell::new(None) };
    }
    CLIPBOARD.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        // A clipboard that has stopped working — the X server went away, say —
        // is dropped so the next copy builds a fresh one rather than failing
        // forever.
        let result = slot
            .as_mut()
            .expect("just populated")
            .set_text(text)
            .map_err(|e| e.to_string());
        if result.is_err() {
            *slot = None;
        }
        result
    })
}

/// The slow half of a reload: which keys gpg-agent holds, and which secret key
/// files will not parse.
///
/// Off the event loop, because asking the agent leaves the process. An agent
/// that has hung — or a stale socket left by one that died — used to freeze the
/// window until it gave up, holding the state lock the whole time. The list now
/// appears immediately and the smartcard badges arrive when the agent answers,
/// or never, with nothing waiting on it.
///
/// The damaged-file survey rides along because it re-parses every secret key,
/// which is the other thing in a reload that has no business on the UI thread.
///
/// The certificates are re-read here rather than handed over from `reload`,
/// because naming their type would put a `sequoia_openpgp` type in this crate
/// and the GUI is deliberately free of them. The extra read is the cost of
/// that boundary, and it is paid on a worker thread where nothing waits for it.
fn survey_agent_and_secrets(ui: &AppWindow, state: &Shared, store: std::sync::Arc<Store>) {
    let (ui_weak, state) = (ui.as_weak(), state.clone());
    std::thread::spawn(move || {
        let certs = store.certs().unwrap_or_default();
        let agent_keys = rpgp_core::agent::annotate(&certs);
        let damaged: Vec<String> = store
            .damaged_secret_files()
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        if agent_keys.is_empty() && damaged.is_empty() {
            return;
        }

        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };

            if !agent_keys.is_empty() {
                // Of the two fields the survey sets, only card_serial can reach
                // a row: CertRow carries card-serial, while agent_backed is read
                // straight off State when the certify and sign dialogs build
                // their key lists. So the rows only need rebuilding when a card
                // serial actually changed — otherwise reload's own apply_filter
                // already produced exactly the rows this would produce again,
                // and for anyone whose key is merely in gpg-agent rather than on
                // a card, that second pass rebuilt every row to no effect.
                let mut rows_changed = false;
                {
                    let mut guard = lock(&state);
                    for summary in guard.all.iter_mut() {
                        if let Some(key) = agent_keys.get(&summary.fingerprint) {
                            summary.agent_backed = true;
                            if summary.card_serial != key.card_serial {
                                summary.card_serial = key.card_serial.clone();
                                rows_changed = true;
                            }
                        }
                    }
                }
                if rows_changed {
                    // Read the selection now rather than before the agent was
                    // asked: the user may have moved since. apply_filter clears
                    // the selection, so it has to be put back.
                    let selected = ui
                        .get_has_selection()
                        .then(|| ui.get_detail().fingerprint.to_string());

                    // And the status line with it. Every mutation sets its own
                    // confirmation — "Imported 3 certificates" — and reload
                    // then spawns this survey, which ends in apply_filter,
                    // which overwrites the status with its generic count.
                    // from_cert resets card_serial to None on every reload, so
                    // for anyone whose agent reports a card this fired every
                    // time: the confirmation was replaced before it could be
                    // read.
                    let status = ui.get_status();

                    apply_filter(&ui, &state);
                    if let Some(fingerprint) = selected {
                        reselect(&ui, &state, &fingerprint);
                    }
                    ui.set_status(status);
                }
            }

            // Last, so it survives: apply_filter above always overwrites the
            // status with its own count. A secret key file that will not parse
            // is skipped rather than allowed to hide every other key, but
            // skipping silently would turn "my key is gone" into a mystery.
            if !damaged.is_empty() {
                ui.set_status(
                    format!(
                        "{} secret key file{} could not be read and {} skipped: {}",
                        damaged.len(),
                        if damaged.len() == 1 { "" } else { "s" },
                        if damaged.len() == 1 { "was" } else { "were" },
                        damaged.join(", ")
                    )
                    .into(),
                );
            }
        });
    });
}

impl State {
    /// The summary a displayed row refers to, resolving the index in `shown`.
    fn shown_at(&self, row: usize) -> Option<&CertSummary> {
        self.all.get(*self.shown.get(row)?)
    }
}

/// Which certificates the list shows, in the order it shows them.
///
/// The pure half of [`apply_filter`], split out so it can be measured: this is
/// what a keystroke pays for, and it was unreachable from a benchmark while it
/// lived inside a function that takes an `AppWindow`.
pub fn visible(all: &[CertSummary], filter: &str, scope: Scope, sort: Sort) -> Vec<usize> {
    let mut shown: Vec<usize> = all
        .iter()
        .enumerate()
        .filter(|(_, c)| scope.accepts(c) && c.matches(filter))
        .map(|(i, _)| i)
        .collect();
    sort.apply_to(all, &mut shown);
    shown
}

/// The rows the list model is built from, for the same reason.
///
/// Note what this does today: one `CertRow` per *matching* certificate, each
/// about thirty heap strings, however few of them the window can show. That is
/// the cost a lazy model would remove, and the reason this is public.
pub fn visible_rows(all: &[CertSummary], filter: &str, scope: Scope, sort: Sort) -> Vec<CertRow> {
    visible(all, filter, scope, sort)
        .iter()
        .filter_map(|&i| all.get(i))
        .map(to_row)
        .collect()
}

/// Rebuild `shown` and the list model from the current scope and search text.
///
/// The impure half: [`visible`] decides *which* certificates and in what
/// order, this turns that answer into rows and hands them to the window. The
/// summary above used to sit on `visible`, left there when the pure half was
/// split out for the keystroke bench.
fn apply_filter(ui: &AppWindow, state: &Shared) {
    let mut guard = lock(state);

    let (filter, scope, sort) = (guard.filter.clone(), guard.scope, guard.sort);
    guard.shown = visible(&guard.all, &filter, scope, sort);

    let rows: Vec<CertRow> = guard
        .shown
        .iter()
        .filter_map(|&i| guard.all.get(i))
        .map(to_row)
        .collect();
    let total = guard.all.len();
    let mine = guard.all.iter().filter(|c| c.has_secret).count();
    let shown = rows.len();
    let can_certify = guard.all.iter().any(|c| c.has_secret && c.can_certify);
    drop(guard);

    ui.set_certs(ModelRc::new(VecModel::from(rows)));
    ui.set_can_certify(can_certify);
    ui.set_count_all(total as i32);
    ui.set_count_mine(mine as i32);
    ui.set_count_others((total - mine) as i32);

    // The old row index is meaningless against a new row set.
    ui.set_current_row(-1);
    ui.set_has_selection(false);
    ui.set_status(
        if shown == total {
            format!("{total} certificate(s), {mine} with a secret key")
        } else {
            format!("{shown} of {total} certificate(s), {mine} with a secret key")
        }
        .into(),
    );
}

pub fn to_row(summary: &CertSummary) -> CertRow {
    let (name, email) = split_user_id(&summary.primary_user_id);
    CertRow {
        fingerprint: summary.fingerprint.clone().into(),
        fingerprint_pretty: summary.fingerprint_pretty().into(),
        key_id: summary.key_id.clone().into(),
        primary_user_id: summary.primary_user_id.clone().into(),
        initials: initials(&name, &email, &summary.key_id).into(),
        tint_index: tint_index(&summary.fingerprint),
        name: name.into(),
        email: email.into(),
        user_ids: summary.user_ids.join("\n").into(),
        algorithm: summary.algorithm.clone().into(),
        created: format_time(Some(summary.created)).into(),
        expires: format_time(summary.expires).into(),
        validity: summary.validity.as_str().into(),
        capabilities: summary.capabilities().into(),
        has_secret: summary.has_secret,
        authentication: summary.authentication.as_str().into(),
        is_trust_root: summary.is_trust_root,
        revocation: summary.revocation.clone().unwrap_or_default().into(),
        card_serial: summary.card_serial.clone().unwrap_or_default().into(),
    }
}

/// `Alice Smith <alice@example.org>` -> `("Alice Smith", "alice@example.org")`.
fn split_user_id(user_id: &str) -> (String, String) {
    match (user_id.find('<'), user_id.rfind('>')) {
        (Some(open), Some(close)) if close > open => (
            user_id[..open].trim().to_string(),
            user_id[open + 1..close].trim().to_string(),
        ),
        _ if user_id.contains('@') && !user_id.contains(' ') => {
            (String::new(), user_id.trim().to_string())
        }
        _ => (user_id.trim().to_string(), String::new()),
    }
}

/// Up to two letters for the monogram, falling back through name, e-mail and
/// key ID so a certificate with no user ID still gets a legible circle.
fn initials(name: &str, email: &str, key_id: &str) -> String {
    let from_name: String = name
        .split_whitespace()
        .filter_map(|word| word.chars().next())
        .take(2)
        .collect();
    if !from_name.is_empty() {
        return from_name.to_uppercase();
    }
    email
        .chars()
        .chain(key_id.chars())
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string())
}

/// Pick one of Theme.monograms from the fingerprint, so a certificate keeps its
/// colour between sessions. FNV-1a: short, stable, and not a hash that anything
/// depends on for security.
fn tint_index(fingerprint: &str) -> i32 {
    const PALETTE: u64 = 6;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in fingerprint.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash % PALETTE) as i32
}

/// The binary's entry point, here so `main.rs` stays a wrapper.
pub fn run_app() -> ExitCode {
    // First, before the renderer brings up wgpu and long before any key
    // material exists: everything after this point is inside a process that
    // will not dump core.
    hardening::harden();
    configure_renderer();

    // After the backend is selected and before any window is created: it needs
    // a platform to talk to, and the id is read when the window is built.
    //
    // On Wayland an application cannot set its own taskbar icon at all. The
    // compositor matches this id against an installed .desktop file and takes
    // the Icon= from there, so this and desktop/app.rpgp.rpgp.desktop have to
    // agree or the window gets a generic placeholder.
    if let Err(e) = slint::set_xdg_app_id(APP_ID) {
        eprintln!("rpgp: could not set the application id: {e}");
    }
    install_panic_hook();

    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(e)) => {
            eprintln!("rpgp: {e}");
            ExitCode::FAILURE
        }
        Err(payload) => {
            if NO_GPU_ADAPTER.load(Ordering::Relaxed) {
                restart_with_software_renderer()
            } else {
                // Not a graphics failure: let it look like an ordinary crash.
                std::panic::resume_unwind(payload)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpgp_core::Authentication;

    fn report(fingerprint: &str, good: bool) -> ops::SignatureReport {
        ops::SignatureReport {
            good,
            signer: "Alice <alice@example.org>".to_string(),
            fingerprint: Some(fingerprint.to_string()),
            detail: String::new(),
        }
    }

    fn known(fingerprint: &str, authentication: Authentication) -> CertSummary {
        let cert = rpgp_core::keygen::generate(&rpgp_core::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        let mut summary = CertSummary::from_cert(&cert);
        summary.fingerprint = fingerprint.to_string();
        summary.authentication = authentication;
        summary
    }

    /// The list is a view of positions into `all`, so ordering it must still
    /// produce the sequence the old by-value comparators did.
    ///
    /// MineFirst is the default and the one that used to allocate twice per
    /// comparison; the tie inside it is what would expose a stability change.
    #[test]
    fn sorting_the_view_orders_by_what_the_positions_point_at() {
        use std::time::{Duration, UNIX_EPOCH};

        let make = |name: &str, secret: bool, age: u64| {
            let mut c = known(&format!("{age:040X}"), Authentication::Unknown);
            c.primary_user_id = name.to_string();
            c.has_secret = secret;
            c.created = UNIX_EPOCH + Duration::from_secs(age);
            c
        };
        // Deliberately unsorted, with a has_secret tie between "alice"/"Bob".
        let all = vec![
            make("carol", false, 30),
            make("Bob", true, 10),
            make("alice", true, 20),
            make("dave", false, 40),
        ];

        let named = |shown: &[usize]| -> Vec<&str> {
            shown
                .iter()
                .map(|&i| all[i].primary_user_id.as_str())
                .collect()
        };

        let mut shown: Vec<usize> = (0..all.len()).collect();
        Sort::MineFirst.apply_to(&all, &mut shown);
        assert_eq!(
            named(&shown),
            ["alice", "Bob", "carol", "dave"],
            "secret keys first, then case-insensitive by name"
        );

        let mut shown: Vec<usize> = (0..all.len()).collect();
        Sort::Name.apply_to(&all, &mut shown);
        assert_eq!(named(&shown), ["alice", "Bob", "carol", "dave"]);

        let mut shown: Vec<usize> = (0..all.len()).collect();
        Sort::Newest.apply_to(&all, &mut shown);
        assert_eq!(named(&shown), ["dave", "carol", "alice", "Bob"]);

        // A filtered view: the indices are a subset and must stay valid.
        let mut shown = vec![3usize, 1];
        Sort::Name.apply_to(&all, &mut shown);
        assert_eq!(named(&shown), ["Bob", "dave"]);
    }

    /// A signature that verifies says the bytes came from a key. It does not
    /// say the key belongs to the name printed beside it — and the banner used
    /// to claim exactly that, so a lookalike key got the same green
    /// reassurance as the real one.
    #[test]
    fn only_an_authenticated_signer_reads_as_verified() {
        let fingerprint = "AB".repeat(20);
        let result = ops::VerifyResult {
            signatures: vec![report(&fingerprint, true)],
            decrypted_with: None,
        };

        // Authenticated: the reassuring tone is earned.
        let store = [known(&fingerprint, Authentication::Full)];
        let (text, tone) = signature_verdict(&store, &result);
        assert_eq!(tone, 1, "{text}");
        assert_eq!(text, "Signature verified");

        // Valid, but nobody has vouched for the name.
        for weaker in [Authentication::Unknown, Authentication::Marginal] {
            let store = [known(&fingerprint, weaker)];
            let (text, tone) = signature_verdict(&store, &result);
            assert_eq!(tone, 2, "{weaker:?} should not read as verified: {text}");
            assert!(text.contains("not verified"), "{text}");
        }

        // A signer we hold no certificate for at all is likewise not verified.
        let (text, tone) = signature_verdict(&[], &result);
        assert_eq!(tone, 2, "{text}");

        // A bad signature still outranks everything else.
        let bad = ops::VerifyResult {
            signatures: vec![report(&fingerprint, false)],
            decrypted_with: None,
        };
        let store = [known(&fingerprint, Authentication::Full)];
        assert_eq!(signature_verdict(&store, &bad).1, 3);
    }

    /// The rows carry the same distinction the banner does.
    #[test]
    fn rows_report_each_signers_authentication() {
        let fingerprint = "CD".repeat(20);
        let store = [known(&fingerprint, Authentication::Full)];
        let rows = signature_rows(&store, &[report(&fingerprint, true)]);
        assert_eq!(rows[0].authentication, "verified");
        assert!(rows[0].authenticated);

        // Unknown signer: named from the signature, but not vouched for.
        let rows = signature_rows(&[], &[report(&fingerprint, true)]);
        assert_eq!(rows[0].authentication, "unverified");
        assert!(!rows[0].authenticated);
    }
}
