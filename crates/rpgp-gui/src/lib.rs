//! The rPGP interface, as a library so its pure parts can be measured.
//!
//! Everything here used to live in `main.rs`. A binary crate has no library
//! target, so nothing inside it can be reached from a benchmark — and the row
//! building and list ordering that a keystroke pays for are exactly what wants
//! measuring. `main.rs` is now a wrapper around [`run_app`]; this module is
//! unchanged otherwise.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rpgp_core::cert::format_time;
use rpgp_core::certify::{self, Certification, CertifyRequest};
use rpgp_core::keygen::{self, KeyGenRequest, KeyType};
use rpgp_core::lifecycle;
use rpgp_core::ops::{self, Existing, InputKind, VerifyResult};
use rpgp_core::revoke::{self, Reason, RevokeRequest};
use rpgp_core::{CertSummary, Sha1Policy, Store, wot};
use slint::{ModelRc, SharedString, VecModel};
use zeroize::Zeroizing;

mod clipboard;
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
    /// Which reload the contents of `all` came from. Bumped when one is asked
    /// for and checked when its worker comes back, so two mutations in quick
    /// succession cannot have the slower read put an older keyring back.
    reload_generation: u64,
    /// Bumped every time the user picks a row, so a reload can tell whether
    /// they have moved since it was asked for. One that carries a row of its
    /// own to select only gets to select it if they have not.
    selection_generation: u64,
    filter: String,
    scope: Scope,
    sort: Sort,

    /// Whether Sign / Encrypt and Decrypt ask where to save their output
    /// rather than writing it beside their input, which they do inside a
    /// Flatpak sandbox and nowhere else.
    ///
    /// The sandbox has no access to the user's files. The file chooser portal
    /// hands back a document-portal path such as `/run/flatpak/doc/<id>/a.txt`,
    /// whose directory holds the picked file and nothing else. The portal
    /// keeps any other name created there as a hidden `.xdp-<name>-XXXXXX`
    /// file in the real directory, and renaming one such name onto another
    /// only relabels it in memory. So an output derived beside the input
    /// never reached the host under its own name, while the status line said
    /// it had been written, and a decrypt left its plaintext behind in one of
    /// those hidden files. A path from the save dialog is a document of its
    /// own: the output is still staged beside it, but the rename onto it is a
    /// real one.
    choose_outputs: bool,

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
    /// Which choice of files the Decrypt / Verify dialog is showing. Bumped
    /// whenever it opens or a file is chosen, and taken by the worker in the
    /// same snapshot as the paths, so a result that comes back for files the
    /// user has since replaced is not shown beside the new ones.
    dv_generation: u64,

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

    /// (fingerprint, warned): the certificate the delete dialog is about, and
    /// whether it warned that a secret key goes with it.
    delete_target: Option<(String, bool)>,
    /// Fingerprint of the certificate the lifecycle dialog is about.
    lifecycle_fingerprint: Option<String>,
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

/// Whether an operation is already in flight, in which case the caller
/// returns without doing anything.
///
/// `busy` stands for exactly one operation, and more than the look of the
/// window relies on there never being two: the store's read-merge-write paths
/// are not safe to run against each other, and every completion clears `busy`
/// when it lands, so the first of two to finish would re-enable the whole
/// window while the other was still writing. Every control that starts an
/// operation is disabled while `busy` is set, but a rule that lives only on
/// the controls holds only for as long as nothing reaches a handler another
/// way, and several things can. Slint's own `enabled` keeps the pointer out
/// and stops a control gaining focus, but a button or checkbox that already
/// had focus still receives Enter and Space after it is disabled, and on Linux
/// and macOS an assistive-technology activation reaches its callback whatever
/// `enabled` says, as only the Windows adapter refuses a disabled control. The
/// app's own widgets check `enabled` against both themselves, but that covers
/// a control only for as long as it is built from one of them. A file dialog's
/// answer arrives with no control involved at all: the dialogs have no parent
/// window, so on Linux and Windows the window behind one stays live, and an
/// operation can start while it is open.
///
/// So the rule is kept where the work starts. Every handler that sets `busy`
/// asks here first, Import's included, which gets there only once its file
/// dialog has answered. So do the pickers that choose an operation's input,
/// and the recipient toggle, whose rows are drawn by hand rather than built
/// from the app's widgets and choose who a run encrypts to. So do the two
/// details-pane toggles, which write the store without setting `busy`
/// because they finish before they return. Export and Save revocation
/// certificate do not ask once their dialogs answer, and that is deliberate:
/// they start no operation and change nothing in the store, only copying out
/// of it into the file the user chose. Sign / Encrypt and Decrypt, whose save
/// dialog in a Flatpak is part of the operation, ask before it opens and set
/// `busy` as it does, since it asks where to write a run already settled on
/// screen; see [`ask_where_to_save`]. Nothing can come between a handler
/// asking and it setting `busy`, since both happen on the event loop, which
/// runs one callback at a time.
fn refuse_while_busy(ui: &AppWindow) -> bool {
    ui.get_busy()
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

    // Returned rather than reported here: run_app funnels every startup failure
    // through report_fatal, which also puts it in front of a user who launched
    // this from a desktop and has no terminal to read.
    let store = Store::open_default()?;

    let state: Shared = Arc::new(Mutex::new(State {
        store: Arc::new(store),
        all: Vec::new(),
        shown: Vec::new(),
        reload_generation: 0,
        selection_generation: 0,
        filter: String::new(),
        scope: Scope::All,
        sort: Sort::MineFirst,
        choose_outputs: flatpak_sandbox(Path::new("/")),
        se_input: None,
        se_recipients: Vec::new(),
        se_filter: String::new(),
        se_signers: Vec::new(),
        dv_input: None,
        dv_data: None,
        dv_kind: InputKind::NotOpenPgp,
        dv_generation: 0,
        certify_target: None,
        certify_user_ids: Vec::new(),
        certify_certifiers: Vec::new(),
        lookup_results: Vec::new(),
        revoke_target: None,
        revoke_certification: false,
        delete_target: None,
        lifecycle_fingerprint: None,
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

    // Held across the event loop, and declared after `ui` so that it is dropped
    // first on the way out of this function, on an error or an unwind as well:
    // a clipboard on the window's own Wayland connection, where there is one,
    // has to go while the window, whose connection it shares, still exists.
    // See clipboard::attach.
    let _clipboard = clipboard::attach(&ui);
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
            // so the prompt happens with the lock free. Import, which used to
            // hold it throughout, now takes it only to clone the store out.
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
            // so the prompt happens with the lock free. Import, which used to
            // hold it throughout, now takes it only to clone the store out.
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
            // so the prompt happens with the lock free. Import, which used to
            // hold it throughout, now takes it only to clone the store out.
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
            // until its worker comes back. The reload it then asks for is not
            // waited out: busy is already clear while that reads the store,
            // and a row picked in that window stays picked, because the
            // reload checks `selection_generation` before it selects a row of
            // its own.
            //
            // Not, as this used to say, because a worker holds the state lock
            // across a card PIN prompt: run_sign_encrypt and run_certify both
            // take the lock in a scoped block and drop it before any crypto,
            // so the prompt happens with the lock free. Import, which used to
            // hold it throughout, now takes it only to clone the store out.
            if ui.get_busy() {
                return;
            }
            let mut guard = lock(&state);
            // Before anything can fail, because a click on a row that turns
            // out not to be one still moves the user off the row they were
            // on — and a reload still in flight must not put them back.
            guard.selection_generation += 1;

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
                import_chosen_file(&ui, &state, file.path().to_path_buf());
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

/// Import the file the Import picker came back with.
///
/// Split out of the picker, like [`choose_dv_input`], because the dialog
/// cannot be driven without a display and this half is what a test needs to
/// reach.
fn import_chosen_file(ui: &AppWindow, state: &Shared, path: PathBuf) {
    // The file dialog is not modal, so another operation can have started
    // while it was open. Two must not run at once, and the user is told rather
    // than left to wonder why the certificates never arrived.
    if refuse_while_busy(ui) {
        ui.set_status(
            "Nothing was imported, because another operation is still running. \
             Import the file again when it finishes."
                .into(),
        );
        return;
    }
    // Off the event loop, like key generation. Parsing a keyring and writing
    // one cert-d file per certificate is unbounded work — a GnuPG pubring can
    // hold thousands — and doing it here held the state lock and froze the
    // window for the whole import. The file dialog itself has to stay on the
    // main thread, which is why only this half moves.
    ui.set_busy(true);
    ui.set_status("Importing…".into());
    let (ui_weak, state) = (ui.as_weak(), state.clone());
    std::thread::spawn(move || {
        let _busy = BusyGuard(ui_weak.clone());
        // Cloned out under a brief lock, exactly as the comment on State::store
        // describes. Importing a GnuPG pubring parses and writes thousands of
        // certificates, and holding the mutex across all of it blocked every
        // other worker for the duration. Nothing below touches the State the
        // lock protects — `all` is rebuilt by the reload in the completion
        // closure.
        let store = lock(&state).store.clone();
        let outcome = import_into(&store, &path);

        // One refresh at the end rather than progressive updates: the list
        // stays as it was until the import is complete, which is what it did
        // when this ran inline. A failure refreshes it too, since an import
        // that stops partway has stored what came before it.
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            ui.set_busy(false);
            match outcome {
                Ok(message) => reload_after(
                    &ui,
                    &state,
                    AfterReload {
                        status: Some(message),
                        ..Default::default()
                    },
                ),
                Err(e) => report_and_reload(&ui, &state, format!("Import failed: {e}")),
            }
        });
    });
}

/// The blocking half of Import: store what is in the file, and say what
/// arrived.
fn import_into(store: &Store, path: &Path) -> rpgp_core::Result<String> {
    // A revocation certificate is a bare signature, not a certificate, so
    // CertParser rejects it. Same button, because a user handed a .rev file
    // expects Import to take it.
    match store.import_file(path) {
        Ok(certs) => {
            // Secret keys are called out rather than folded into the count:
            // one arriving is the difference between adding someone's
            // certificate and taking custody of their key, and an imported
            // key is deliberately not a trust root.
            let secrets = certs.iter().filter(|c| c.is_tsk()).count();
            Ok(if secrets == 0 {
                format!("Imported {} certificate(s)", certs.len())
            } else {
                format!(
                    "Imported {} certificate(s), {secrets} with a secret key. A \
                     secret key that arrives in a file is not made a trust root; \
                     tick Trust root in its details pane if you meant to trust it.",
                    certs.len()
                )
            })
        }
        // The file held a certificate, so it is no revocation certificate, and
        // what came before that one is stored. Handed to the fallback below as
        // well, a keyring that had stored a revoked certificate before it
        // stopped was reported as that certificate revoked, and the reason the
        // import stopped went unsaid.
        Err(stopped @ rpgp_core::Error::ImportStopped { .. }) => Err(stopped),
        Err(import_error) => match revoke::apply_revocation_file(store, path) {
            Ok(cert) => Ok(format!(
                "Revoked {}",
                rpgp_core::CertSummary::from_cert(&cert).primary_user_id
            )),
            Err(_) => Err(import_error),
        },
    }
}

// ------------------------------------------------------------- key generation

fn wire_keygen(ui: &AppWindow, state: &Shared) {
    ui.on_generate_key({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |name, email, password, key_type, expiry, standard| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            if refuse_while_busy(&ui) {
                return;
            }

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

            // RSA-4096 takes seconds. Run it off the UI thread, store it there
            // too, and hand the outcome back through the event loop. Storing
            // it used to happen in the completion, on the event loop and with
            // the state lock held across the key file's sync and cert-d's
            // write, which waits on cert-d's lock for as long as another
            // program holds it. The store is cloned out under a brief lock, as
            // every other worker here does.
            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let store = lock(&state).store.clone();
                let outcome = keygen::generate(&request).and_then(|key| {
                    let fingerprint = key.cert.fingerprint().to_hex();
                    keygen::save(&store, &key).map(|saved| (fingerprint, saved))
                });
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    finish_keygen(&ui, &state, outcome);
                });
            });
        }
    });
}

/// Show what became of a key generation, on the event loop.
///
/// A key that was stored closes the dialog and is listed, with or without the
/// revocation certificate that should come with it. An error leaves the
/// dialog open for another try, since [`keygen::save`] keeps nothing when it
/// reports one, unless the error says that the new key's secret key could not
/// be removed again: that key stays in the secrets directory, unlisted, and
/// another try makes a second one beside it. A stored key used to be reported
/// as a failure when its certificate could not be written, and the dialog's
/// button, pressed again, made a second one.
///
/// Split out of the worker's completion, like [`show_decrypt_verify`], so a
/// test can hand it an outcome without an event loop to deliver one.
fn finish_keygen(
    ui: &AppWindow,
    state: &Shared,
    outcome: rpgp_core::Result<(String, keygen::Saved)>,
) {
    ui.set_busy(false);
    let status = match outcome {
        Ok((fingerprint, keygen::Saved::Whole)) => format!("Created {fingerprint}"),
        // What went wrong ahead of the fingerprint, since the status line
        // elides its tail.
        Ok((fingerprint, keygen::Saved::WithoutRevocation(e))) => format!(
            "Key created, but its revocation certificate could not be saved ({e}): {fingerprint}"
        ),
        Err(e) => {
            ui.set_status(format!("Key generation failed: {e}").into());
            return;
        }
    };
    ui.set_keygen_open(false);
    reload_after(
        ui,
        state,
        AfterReload {
            status: Some(status),
            ..Default::default()
        },
    );
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

// --------------------------------------------------------------- file outputs

/// Whether this process runs inside a Flatpak sandbox, judged by the
/// `.flatpak-info` file Flatpak puts at the root of every sandbox it builds.
/// That file is the conventional test, the one GLib makes. `root` is `/`
/// except in a test.
fn flatpak_sandbox(root: &Path) -> bool {
    root.join(".flatpak-info").exists()
}

/// Ask where to save an operation's output, offering `suggested`, and hand
/// the answer to `then`, which starts the operation there. `what` names the
/// output in the dialog's title and on the status line.
///
/// Asked only inside a Flatpak; see [`State::choose_outputs`]. `busy` goes up
/// as the dialog opens rather than once it answers, because the dialog has no
/// parent window and the window behind it stays live, while the run it asks
/// about was settled on screen when Run was pressed. With `busy` up, the
/// run's files and recipients stay as they were shown, since the pickers and
/// the recipient toggle refuse while it is, and the rest of the run, what it
/// does, as whom and with which passphrases, was taken from the dialog when
/// Run was pressed. No other operation starts, and Run cannot open a second
/// dialog. Cancelling ends the operation there, with nothing written.
///
/// The folder offered is the input's, which inside the sandbox is a
/// document-portal path. The portal's interface documents that it replaces
/// such a path with the folder on the host before the desktop's dialog sees
/// it, and that the desktop is free to ignore the suggestion.
fn ask_where_to_save(
    ui: &AppWindow,
    suggested: &Path,
    what: &str,
    then: impl FnOnce(&AppWindow, PathBuf) + 'static,
) {
    ui.set_busy(true);
    ui.set_status(format!("Choose where to save the {what}…").into());
    let mut dialog = rfd::AsyncFileDialog::new().set_title(format!("Save {what}"));
    if let Some(name) = suggested.file_name() {
        dialog = dialog.set_file_name(name.to_string_lossy());
    }
    if let Some(folder) = suggested.parent() {
        dialog = dialog.set_directory(folder);
    }

    let ui_weak = ui.as_weak();
    let spawned = slint::spawn_local(async move {
        let chosen = dialog.save_file().await;
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        match chosen {
            Some(file) => then(&ui, file.path().to_path_buf()),
            None => {
                ui.set_busy(false);
                ui.set_status(
                    "Nothing was written, because no file was chosen to write it to.".into(),
                );
            }
        }
    });
    // Only without an event loop, which the app always has. Left up, `busy`
    // would hold every control in the window disabled for good.
    if spawned.is_err() {
        ui.set_busy(false);
        ui.set_status("Nothing was written, because the save dialog could not open.".into());
    }
}

/// How the Sign / Encrypt and Decrypt dialogs name the output a run will
/// write: in full where it is derived beside the input, and by the name alone
/// where a save dialog will ask for the rest. The folder is then the user's to
/// choose, and inside a Flatpak the input's own folder is a document-portal
/// path that names nothing the user could find on the host.
fn output_preview(state: &State, output: &Path) -> SharedString {
    if state.choose_outputs {
        output
            .file_name()
            .unwrap_or(output.as_os_str())
            .to_string_lossy()
            .into_owned()
            .into()
    } else {
        output.display().to_string().into()
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
                choose_se_input(&ui, &state, file.path().to_path_buf());
            });
        }
    });

    ui.on_se_toggle_recipient({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |index| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            // The run reads its recipients once its worker starts, which
            // inside a Flatpak is only once the save dialog has answered, and
            // that dialog leaves the rows behind it live. A tick changed in
            // between would encrypt the file to recipients other than the
            // ones on screen when Run was pressed.
            if refuse_while_busy(&ui) {
                return;
            }
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
            if refuse_while_busy(&ui) {
                return;
            }

            // These two copies live on the worker for the whole operation,
            // which on a card can be a minute of waiting at a PIN prompt. The
            // Slint string they are copied from cannot be wiped — that is the
            // toolkit's memory — but ours can be, and this is where a passphrase
            // and a message password sit longest.
            let (password, secret) = (
                Zeroizing::new(password.to_string()),
                Zeroizing::new(secret.to_string()),
            );
            let start = {
                let state = state.clone();
                move |ui: &AppWindow, chosen: Option<PathBuf>| {
                    ui.set_busy(true);
                    ui.set_status(
                        if encrypt {
                            "Encrypting…"
                        } else {
                            "Signing…"
                        }
                        .into(),
                    );
                    let ui_weak = ui.as_weak();
                    std::thread::spawn(move || {
                        let _busy = BusyGuard(ui_weak.clone());
                        let outcome = run_sign_encrypt(
                            &state,
                            encrypt,
                            sign,
                            signer_index,
                            &password,
                            &secret,
                            chosen,
                        );
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
            };

            // Inside a Flatpak the output's place is asked for first, offered
            // under the name it would have been given beside the input. With
            // no file chosen, or nothing ticked, there is nothing to ask
            // about, and the worker says so as it does outside.
            let suggested = {
                let guard = lock(&state);
                match &guard.se_input {
                    Some(input) if guard.choose_outputs && encrypt => {
                        Some((ops::encrypted_name(input), "encrypted file"))
                    }
                    Some(input) if guard.choose_outputs && sign => {
                        Some((ops::signature_name(input), "signature"))
                    }
                    _ => None,
                }
            };
            match suggested {
                Some((suggested, what)) => {
                    ask_where_to_save(&ui, &suggested, what, move |ui, chosen| {
                        start(ui, Some(chosen))
                    });
                }
                None => start(&ui, None),
            }
        }
    });
}

/// Take a newly chosen file to sign or encrypt, as the picker does once the
/// file dialog answers.
///
/// Split out of the picker, like [`choose_dv_input`], so that a test can reach
/// it.
fn choose_se_input(ui: &AppWindow, state: &Shared, path: PathBuf) {
    // As for Decrypt / Verify's pickers: a file dialog opened before Run is
    // not modal and can answer during the run. The run takes its file from
    // here once its worker starts, so the file shown when Run was pressed is
    // the one it signs or encrypts only if nothing is taken in the meantime.
    if refuse_while_busy(ui) {
        return;
    }
    let mut guard = lock(state);
    guard.se_input = Some(path);
    push_sign_encrypt(ui, &guard);
}

/// The blocking half of Sign / Encrypt, run on a worker thread.
///
/// `chosen` is where the save dialog said the output goes, and it is used as
/// it stands: not stepped around a file already there, which the dialog has
/// asked about, and not refused for one. Without it the output goes beside
/// the input, under a name that steps around whatever is there.
fn run_sign_encrypt(
    state: &Shared,
    encrypt: bool,
    sign: bool,
    signer_index: i32,
    password: &str,
    secret: &str,
    chosen: Option<PathBuf>,
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

    // The signer is everything the store knows about the chosen key: the local
    // secret where there is one, which is what actually signs, and cert-d's
    // signatures over it. A card key has no local secret half at all and the
    // public certificate is enough, since the agent finds the secret by
    // keygrip; and a revocation that arrived by import or by a keyserver
    // refresh reaches cert-d alone, so folding that in is what puts it in front
    // of the refusal in `ops`.
    let signer = if sign {
        let (fingerprint, _) = signers
            .get(signer_index.max(0) as usize)
            .ok_or_else(|| "Choose a key to sign with".to_string())?;
        Some(
            store
                .full_cert(fingerprint)
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
        // Zeroizing, as `ops::encrypt_file` now asks for: this vector holds the
        // only copy of the message password that outlives the call, so it is
        // the one worth wiping.
        let passwords: Vec<Zeroizing<String>> = if secret.is_empty() {
            Vec::new()
        } else {
            vec![Zeroizing::new(secret.to_string())]
        };
        if certs.is_empty() && passwords.is_empty() {
            return Err("Select a recipient, or set a password".to_string());
        }

        let (output, existing) = match chosen {
            Some(output) => (output, Existing::Replace),
            None => (ops::encrypted_name(&input), Existing::Refuse),
        };
        ops::encrypt_file(
            &certs,
            &passwords,
            signer.as_ref().map(|cert| (cert, password)),
            &input,
            &output,
            existing,
        )
        .map_err(|e| format!("Encryption failed: {e}"))?;
        Ok(output)
    } else {
        let signer = signer.ok_or_else(|| "Nothing to do: tick Encrypt or Sign".to_string())?;
        let (output, existing) = match chosen {
            Some(output) => (output, Existing::Replace),
            None => (ops::signature_name(&input), Existing::Refuse),
        };
        ops::sign_detached_file(&signer, password, &input, &output, existing)
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

    ui.set_choose_outputs(state.choose_outputs);
    match &state.se_input {
        Some(path) => {
            ui.set_se_input(path.display().to_string().into());
            ui.set_se_output_encrypt(output_preview(state, &ops::encrypted_name(path)));
            ui.set_se_output_sign(output_preview(state, &ops::signature_name(path)));
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
            // A fresh dialog is a fresh choice of files, so a run still in
            // flight from before it was closed has nothing to show in it.
            guard.dv_generation += 1;
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
                choose_dv_input(&ui, &state, path, kind);
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
                choose_dv_data(&ui, &state, file.path().to_path_buf());
            });
        }
    });

    ui.on_dv_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |password| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            if refuse_while_busy(&ui) {
                return;
            }

            let password = password.to_string();
            let start = {
                let state = state.clone();
                move |ui: &AppWindow, chosen: Option<PathBuf>| {
                    ui.set_busy(true);
                    ui.set_status("Working…".into());
                    let ui_weak = ui.as_weak();
                    std::thread::spawn(move || {
                        let _busy = BusyGuard(ui_weak.clone());
                        let (read, outcome) = run_decrypt_verify(&state, &password, chosen);
                        let _ = slint::invoke_from_event_loop(move || {
                            let Some(ui) = ui_weak.upgrade() else {
                                return;
                            };
                            ui.set_busy(false);
                            show_decrypt_verify(&ui, &state, read, outcome);
                        });
                    });
                }
            };

            // As in Sign / Encrypt: inside a Flatpak a message's plaintext
            // goes where the save dialog says. A detached signature writes
            // nothing, so a verify asks nothing. Everything else is asked
            // about, since the worker tries to decrypt everything else, not
            // only what was classified as a message: classification reads a
            // prefix, and a message it cannot place, such as one that opens
            // with a marker packet, still decrypts. A file that turns out not
            // to be OpenPGP at all then fails after the dialog has answered,
            // with nothing written.
            let suggested = {
                let guard = lock(&state);
                match &guard.dv_input {
                    Some(input)
                        if guard.choose_outputs
                            && guard.dv_kind != InputKind::DetachedSignature =>
                    {
                        Some(ops::decrypted_name(input))
                    }
                    _ => None,
                }
            };
            match suggested {
                Some(suggested) => {
                    ask_where_to_save(&ui, &suggested, "decrypted file", move |ui, chosen| {
                        start(ui, Some(chosen))
                    });
                }
                None => start(&ui, None),
            }
        }
    });
}

/// What a Decrypt / Verify run found: a summary line, a tone for the result
/// banner (1 good, 2 needs attention, 3 bad) and the signatures, or the line
/// saying why it failed.
type DvOutcome = Result<(String, i32, VerifyResult), String>;

/// Which choice of files a Decrypt / Verify run read.
struct DvRead {
    /// The generation they were chosen under, held against the dialog's when
    /// the result comes back.
    generation: u64,
    /// Their names, "a.tar.sig against a.tar", for a result that comes back
    /// after the dialog has moved on to other files. A verify's own summary
    /// names none, so without these it would read as a verdict on whatever
    /// the dialog shows by then.
    names: String,
}

/// Take a newly chosen message or signature, as the input picker does once
/// the file dialog answers.
///
/// Split out of the picker, like [`choose_dv_data`], because the dialog cannot
/// be driven without a display and this half is what a test needs to reach.
fn choose_dv_input(ui: &AppWindow, state: &Shared, path: PathBuf, kind: InputKind) {
    // The Choose buttons are disabled while an operation is in flight, but a
    // file dialog opened before Run is not modal and can answer during the
    // run. The files the dialog shows are the ones that run is reading, so
    // they stay as they are, and its verdict lands beside the files it is
    // about.
    if refuse_while_busy(ui) {
        return;
    }
    let mut guard = lock(state);
    guard.dv_input = Some(path);
    guard.dv_kind = kind;
    // A different choice of files, so a result for the previous one is no
    // longer about what the dialog shows. With the refusal above no run on
    // the previous files should still be going; if one ever is, this is what
    // keeps its result out of the dialog.
    guard.dv_generation += 1;
    ui.set_dv_result(SharedString::new());
    ui.set_dv_tone(0);
    push_decrypt_verify(ui, &guard);
}

/// Take a newly chosen signed file, as the data picker does once the file
/// dialog answers.
fn choose_dv_data(ui: &AppWindow, state: &Shared, path: PathBuf) {
    // Refused while busy, and a new generation otherwise, for the reasons
    // given for the input.
    if refuse_while_busy(ui) {
        return;
    }
    let mut guard = lock(state);
    guard.dv_data = Some(path);
    guard.dv_generation += 1;
    push_decrypt_verify(ui, &guard);
}

/// The event-loop half of Decrypt / Verify: show what a run found.
///
/// In the dialog only if the files it read are still the ones chosen. They
/// should be. A picker opened before Run can come back during it, because on
/// Linux and Windows the file dialog has no parent window and the main window
/// stays live behind it, but [`choose_dv_input`] and [`choose_dv_data`] refuse
/// what it brings while the run is in flight. This check does not depend on
/// those refusals: the dialog can still be closed while a run goes on, and its
/// opener does not ask whether one is. Painted beside the new files, a verdict
/// about the old ones reads as "Signature verified" next to a file nothing
/// checked. It still goes on the status line, because a decrypt has already
/// written its output by the time it gets here and hiding that would hide a
/// plaintext file. There it says first that it is not about the files now
/// chosen, because the status line elides and the tail is what goes, and then
/// names the files it is about.
fn show_decrypt_verify(ui: &AppWindow, state: &Shared, read: DvRead, outcome: DvOutcome) {
    if lock(state).dv_generation != read.generation {
        let message = match outcome {
            Ok((summary, _, _)) => summary,
            Err(message) => message,
        };
        let message = if read.names.is_empty() {
            message
        } else {
            format!("{}: {message}", read.names)
        };
        ui.set_status(format!("Not for the files now chosen. {message}").into());
        return;
    }

    match outcome {
        Ok((summary, tone, result)) => {
            let rows = signature_rows(&lock(state).all, &result.signatures);
            ui.set_dv_signatures(ModelRc::new(VecModel::from(rows)));
            ui.set_dv_result(summary.clone().into());
            ui.set_dv_tone(tone);
            ui.set_status(summary.into());
        }
        Err(message) => {
            ui.set_dv_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
            ui.set_dv_result(message.clone().into());
            ui.set_dv_tone(3);
            ui.set_status(message.into());
        }
    }
}

/// The blocking half of Decrypt / Verify. Returns which choice of files it
/// ran against and what it found.
///
/// A decrypt writes to `chosen` when the save dialog chose it, and beside
/// its input otherwise; see [`decrypt_or_verify`].
fn run_decrypt_verify(
    state: &Shared,
    password: &str,
    chosen: Option<PathBuf>,
) -> (DvRead, DvOutcome) {
    // Snapshot what is needed and release the lock: everything below is I/O,
    // and a card PIN prompt can hold it for a minute while the UI waits. The
    // generation comes out of the same snapshot as the paths, so it names
    // exactly the files read below and nothing chosen since.
    let (store, generation, input, kind, data) = {
        let guard = lock(state);
        (
            guard.store.clone(),
            guard.dv_generation,
            guard.dv_input.clone(),
            guard.dv_kind,
            guard.dv_data.clone(),
        )
    };
    let read = DvRead {
        generation,
        names: dv_names(input.as_deref(), kind, data.as_deref()),
    };
    (
        read,
        decrypt_or_verify(state, &store, input, kind, data, password, chosen),
    )
}

/// How a status line names the files a run read. The file names alone: the
/// dialog shows full paths, and a status line has no room for two of them.
fn dv_names(input: Option<&Path>, kind: InputKind, data: Option<&Path>) -> String {
    let name = |path: &Path| {
        path.file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned()
    };
    match (input, data) {
        (Some(input), Some(data)) if kind == InputKind::DetachedSignature => {
            format!("{} against {}", name(input), name(data))
        }
        (Some(input), _) => name(input),
        (None, _) => String::new(),
    }
}

/// What [`run_decrypt_verify`] does with its snapshot.
///
/// `chosen` is where the save dialog said the plaintext goes, and it is used
/// as it stands: not stepped around a file already there, which the dialog
/// has asked about, and not refused for one. Without it the plaintext goes
/// beside the input, under a name that steps around whatever is there.
fn decrypt_or_verify(
    state: &Shared,
    store: &Store,
    input: Option<PathBuf>,
    kind: InputKind,
    data: Option<PathBuf>,
    password: &str,
    chosen: Option<PathBuf>,
) -> DvOutcome {
    let input = input.ok_or_else(|| "Choose a file first".to_string())?;

    if kind == InputKind::DetachedSignature {
        let data = data.ok_or_else(|| "Choose the file the signature covers".to_string())?;

        let result = ops::verify_detached_files(store, &input, &data)
            .map_err(|e| format!("Verification failed: {e}"))?;

        let summary = if result.signatures.is_empty() {
            ("The file contains no signature".to_string(), 2)
        } else {
            signature_verdict(&lock(state).all, &result)
        };
        return Ok((summary.0, summary.1, result));
    }

    let (output, existing) = match chosen {
        Some(output) => (output, Existing::Replace),
        None => (ops::decrypted_name(&input), Existing::Refuse),
    };
    // One field here, but still a candidate list: the Decrypt/Verify dialog
    // asks for "the passphrase or password", so the single value it collects
    // may be either.
    let candidates: Vec<&str> = Some(password)
        .filter(|p| !p.is_empty())
        .into_iter()
        .collect();
    let result = ops::decrypt_file(store, &input, &candidates, &output, existing)
        .map_err(|e| format!("Decryption failed: {e}"))?;

    // A message with no encryption layer opens just as cleanly, so saying
    // "Decrypted to" would tell the reader that something which crossed the
    // network in clear arrived confidentially. Say what actually happened,
    // and hold the tone below green whatever the signature turned out to be.
    let written = if result.encrypted {
        format!("Decrypted to {}", output.display())
    } else {
        format!(
            "This message was not encrypted. Written to {}",
            output.display()
        )
    };
    let summary = if result.signatures.is_empty() {
        (format!("{written}. The message was not signed."), 2)
    } else {
        // The same verdict the verify path gives, prefixed with where the
        // plaintext went. Composed rather than restated so the two cannot
        // drift apart on what counts as verified.
        let (verdict, tone) = signature_verdict(&lock(state).all, &result);
        (
            format!("{written}. {verdict}"),
            if result.encrypted { tone } else { tone.max(2) },
        )
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
    ui.set_choose_outputs(state.choose_outputs);
    ui.set_dv_output(match &state.dv_input {
        Some(path) => output_preview(state, &ops::decrypted_name(path)),
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
            if refuse_while_busy(&ui) {
                return;
            }
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
                            reload_after(
                                &ui,
                                &state,
                                AfterReload {
                                    status: Some(format!("Certified {count} user ID(s)")),
                                    ..Default::default()
                                },
                            );
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
            // Of the two things that disable the checkbox, only `busy` is
            // kept here. It is also disabled for a key generated here, which
            // is a trust root whatever the list says, so an entry written for
            // one changes nothing the web of trust sees. A secret key that
            // arrived by import is not a root until it is made one, and making
            // it one is this handler's job.
            if refuse_while_busy(&ui) {
                return;
            }
            let fingerprint = ui.get_detail().fingerprint.to_string();
            if fingerprint.is_empty() {
                return;
            }

            // Which way to flip it is asked of the store, not of `all`: the
            // list is only replaced when the reload this toggle starts lands,
            // and nothing stops a second click before then. Read from the
            // list, that click saw the value from before the first and wrote
            // the first click's answer again, so two clicks left a
            // certificate a trust root rather than back where it started.
            // `detail` holds the bare hex fingerprint, so uppercased it is
            // the key the store's own list is written under.
            let outcome = {
                let guard = lock(&state);
                guard.store.trust_roots().and_then(|roots| {
                    let was_root = roots.contains(&fingerprint.to_uppercase());
                    guard.store.set_trust_root(&fingerprint, !was_root)
                })
            };

            match outcome {
                Ok(()) => {
                    // Trust roots change what the whole graph authenticates,
                    // so this is a full recompute, not a row update.
                    reload_after(
                        &ui,
                        &state,
                        AfterReload {
                            select: Some(fingerprint),
                            ..Default::default()
                        },
                    );
                }
                Err(e) => ui.set_status(format!("Could not change trust root: {e}").into()),
            }
        }
    });

    ui.on_toggle_sha1_accepted({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            if refuse_while_busy(&ui) {
                return;
            }
            let detail = ui.get_detail();
            let fingerprint = detail.fingerprint.to_string();
            if fingerprint.is_empty() {
                return;
            }

            // From the store rather than the list, as the trust-root toggle
            // does and for the same reason.
            let outcome = {
                let guard = lock(&state);
                guard.store.sha1_accepted().and_then(|list| {
                    let accepted = !list.contains(&fingerprint.to_uppercase());
                    guard
                        .store
                        .set_sha1_accepted(&fingerprint, accepted)
                        .map(|()| accepted)
                })
            };

            match outcome {
                Ok(accepted) => {
                    // A full reload for the same reason the trust-root toggle
                    // takes one: the certificate is re-summarised under a
                    // different policy, so its user IDs, subkeys and
                    // capabilities all change with it.
                    //
                    // The message comes from what was just written rather than
                    // from reading the row back. It used to read `detail` after
                    // reselect, which only worked while the reload was
                    // synchronous; the store is the authority either way.
                    //
                    // It names the certificate rather than saying "this one",
                    // because it appears when the reload lands, and a user who
                    // has picked another row by then stays on it. "No longer
                    // accepted" beside a certificate that still is would be
                    // read as a withdrawal that never happened.
                    let name = &detail.primary_user_id;
                    reload_after(
                        &ui,
                        &state,
                        AfterReload {
                            select: Some(fingerprint),
                            status: Some(if accepted {
                                format!(
                                    "SHA-1 accepted for {name}. Signatures from it can now be checked; it still cannot be trusted or encrypted to."
                                )
                            } else {
                                format!("SHA-1 no longer accepted for {name}.")
                            }),
                        },
                    );
                }
                Err(e) => ui.set_status(format!("Could not change SHA-1 acceptance: {e}").into()),
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
            if refuse_while_busy(&ui) {
                return;
            }
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
                    // The lookup dialog's own line is not touched by
                    // apply_filter, so it is set here; the main status line is.
                    ui.set_lookup_status(
                        format!("Imported {who}. It is unverified until you certify it.").into(),
                    );
                    reload_after(
                        &ui,
                        &state,
                        AfterReload {
                            status: Some(format!("Imported {who} from the network")),
                            ..Default::default()
                        },
                    );
                }
                Err(e) => ui.set_lookup_status(format!("Import failed: {e}").into()),
            }
        }
    });
}

// ------------------------------------------------------------------ lifecycle

fn wire_lifecycle(ui: &AppWindow, state: &Shared) {
    // The certificate a lifecycle action works on is fixed here, when the
    // dialog opens, from the one the details pane is showing — the same moment
    // the user ID or subkey a revoke mode acts on is handed over, so for as
    // long as this dialog is open the two belong together. They can already
    // disagree when it opens: the Details dialog's lists, which the user ID or
    // subkey was picked from, were filled when that dialog opened, and an
    // assistive-technology activation of a list row can move the pane behind
    // its scrim in between. Keeping focus and activation inside an open
    // dialog is what closes that, and it is not done here.
    //
    // The run used to read the pane again when its button was pressed, and a
    // reload landing behind the scrim put the selection back wherever it had
    // been asked to. An expiry or a new user ID could then go to another of
    // the user's keys, and Publish could upload a certificate the dialog was
    // never opened for, which cannot be taken back. Reloads now defer to a row
    // the user has picked, but what the dialog acts on must not depend on
    // nothing else moving the pane. The scrim stops only the pointer: an
    // assistive-technology activation of a list row still reaches
    // row_selected, and a reload can still be asked to select a row read from
    // a highlight that has drifted away from the pane. The name the dialog
    // shows comes from the same read, rather than being bound to the pane,
    // for the same reason.
    let open = |ui: &AppWindow, state: &Shared, mode: i32, target: SharedString| {
        let detail = ui.get_detail();
        if detail.fingerprint.is_empty() {
            return;
        }
        lock(state).lifecycle_fingerprint = Some(detail.fingerprint.to_string());
        ui.set_lifecycle_key_name(detail.primary_user_id);
        ui.set_lifecycle_key_id(detail.key_id);
        ui.set_lifecycle_mode(mode);
        ui.set_lifecycle_target(target);
        ui.set_lifecycle_open(true);
    };

    ui.on_open_expiry({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, &state, 0, SharedString::new());
        }
    });
    ui.on_open_revoke_subkey({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |subkey| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, &state, 4, subkey);
        }
    });
    ui.on_open_publish({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, &state, 3, SharedString::new());
        }
    });
    ui.on_open_add_user_id({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, &state, 1, SharedString::new());
        }
    });
    ui.on_open_revoke_user_id({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |user_id| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            open(&ui, &state, 2, user_id);
        }
    });

    ui.on_lifecycle_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move |mode, expiry, value, password, reason| {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            if refuse_while_busy(&ui) {
                return;
            }
            // What the dialog was opened for, not what the pane shows now.
            // Written every time the dialog opens, which is the only way to
            // reach this button, and dropped when an action goes through, so
            // it never answers for an earlier dialog.
            let fingerprint = lock(&state).lifecycle_fingerprint.clone();
            let Some(fingerprint) = fingerprint else {
                ui.set_status("No certificate selected".into());
                return;
            };
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
                            // The record goes when a success closes the dialog.
                            // Were the button ever reached again without an
                            // opener writing a fresh one, it would then find
                            // nothing to act on rather than this dialog's key.
                            // A dialog dismissed without acting keeps its
                            // record, since dismissing never reaches Rust; the
                            // opener, which is the way back to the button,
                            // writes over it.
                            lock(&state).lifecycle_fingerprint = None;
                            ui.set_lifecycle_open(false);
                            reload_after(
                                &ui,
                                &state,
                                AfterReload {
                                    select: Some(fingerprint),
                                    status: Some(message),
                                },
                            );
                        }
                        // A change is two writes, the secret key's and then the
                        // public certificate's, and a failure can come after
                        // the first. The dialog stays open for another try.
                        Err(message) => report_and_reload(&ui, &state, message),
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
    /// The certificate the dialog was opened for.
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
            own_key_or_refuse(&store, fingerprint)?;
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

/// Refuse to publish a certificate that is not one of the user's own keys.
///
/// The details pane offers Publish only when the store holds the secret half.
/// The rule is kept here too, where the upload happens, because an upload
/// cannot be taken back: it makes the certificate public for good and asks the
/// keyserver to mail every address on it, which for someone else's key is a
/// publication its holder may have chosen not to make. A rule that lives only
/// on a button holds only for as long as nothing reaches the dialog another
/// way.
///
/// Its own function, not a line in [`run_lifecycle`], so that a test can hold
/// it to the rule without a failing run reaching a real keyserver.
fn own_key_or_refuse(store: &Store, fingerprint: &str) -> Result<(), String> {
    if store.has_secret(fingerprint) {
        Ok(())
    } else {
        Err(
            "Nothing was uploaded: this is not one of your keys, and only your own \
             are published from here."
                .to_string(),
        )
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
            match clipboard::copy(text.to_string()) {
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
            match clipboard::copy(text) {
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
            if refuse_while_busy(&ui) {
                return;
            }
            ui.set_busy(true);
            ui.set_status("Working…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let (text, password, secret) = (
                text.to_string(),
                Zeroizing::new(password.to_string()),
                Zeroizing::new(secret.to_string()),
            );
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
        // Everything the store knows, as in `run_sign_encrypt` and for the same
        // reasons: the local secret signs, and a revocation that reached cert-d
        // alone is still in the certificate `ops` is asked to sign with.
        store
            .full_cert(fingerprint)
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
            let passwords: Vec<Zeroizing<String>> = if secret.is_empty() {
                Vec::new()
            } else {
                vec![Zeroizing::new(secret.to_string())]
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

            // Both arms below are bounded: the notepad's output is a text
            // box, and either a compressed encryption layer or an inline
            // signed one expands to whatever the sender chose.
            //
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
            let result = ops::decrypt_to_memory(&store, text.as_bytes(), &candidates, &mut output)
                .map_err(|e| format!("Decryption failed: {e}"))?;

            // As on the file path: an unencrypted message opens just as
            // cleanly, and calling that "Decrypted" claims a confidentiality
            // it never had.
            let opened = if result.encrypted {
                "Decrypted."
            } else {
                "This message was not encrypted."
            };
            let (summary, tone) = if result.signatures.is_empty() {
                (format!("{opened} The message was not signed."), 2)
            } else {
                let (verdict, tone) = signature_verdict(&lock(state).all, &result);
                (
                    format!("{opened} {verdict}"),
                    if result.encrypted { tone } else { tone.max(2) },
                )
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
                let mut guard = lock(&state);
                let has_secret = guard.store.has_secret(&fingerprint);
                // The record the delete is performed against: the certificate
                // this dialog names, and whether it warned that a secret key
                // goes with it and asked for the key ID to be typed. It comes
                // from the same read of the pane as everything the dialog
                // says. The delete used to read the pane again when its button
                // was pressed, and a reload landing behind the scrim put the
                // selection back wherever it had been asked to, so the dialog
                // went on naming one certificate while the delete removed
                // another. Reloads now defer to a row the user has picked, but
                // the delete must not depend on nothing else moving the pane:
                // the scrim stops only the pointer, so an assistive-technology
                // activation of a list row still reaches row_selected, and a
                // reload can still be asked to select a row read from a
                // highlight that has drifted away from the pane. Written afresh
                // every time the dialog opens, which is the only way to reach
                // its Delete button, and dropped once a delete goes through, so
                // it never answers for an earlier one.
                guard.delete_target = Some((fingerprint.clone(), has_secret));
                (has_secret, guard.store.has_revocation(&fingerprint))
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
            if refuse_while_busy(&ui) {
                return;
            }
            // What the dialog named and what it warned about, as recorded when
            // it opened, not whatever the pane shows now.
            let target = lock(&state).delete_target.clone();
            let Some((fingerprint, confirmed_secret)) = target else {
                ui.set_status("No certificate selected".into());
                return;
            };
            ui.set_busy(true);
            ui.set_status("Deleting…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone());
                let outcome = run_delete(&state, &fingerprint, confirmed_secret);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok(message) => {
                            // As for the lifecycle dialog: the record goes when
                            // a success closes the dialog, so a button reached
                            // again without a fresh one finds nothing rather
                            // than this dialog's certificate. A dismissed
                            // dialog keeps it until the opener writes over it.
                            lock(&state).delete_target = None;
                            ui.set_delete_open(false);
                            reload_after(
                                &ui,
                                &state,
                                AfterReload {
                                    status: Some(message),
                                    ..Default::default()
                                },
                            );
                        }
                        // The certificate's trust-root and SHA-1 entries go
                        // before anything is unlinked, so a delete that fails
                        // can already have changed the badges on its row.
                        Err(message) => report_and_reload(&ui, &state, message),
                    }
                });
            });
        }
    });
}

/// Delete, off the event loop like every other worker here.
///
/// The store in `State` goes on being used afterwards, and its next listing
/// leaves the certificate out; see [`Store::certs`]. This used to swap in a
/// reopened store after every delete, believing a live one could never see
/// the deletion, and a reopen that failed after the files were gone reported
/// the delete as a failure and kept the old store, which then listed the
/// deleted certificate on every reload until something looked that
/// certificate up on its own.
///
/// `fingerprint` is the certificate the dialog named and `confirmed_secret` is
/// what it warned about, both recorded when it opened; the second is not what
/// is on disk now. Asking the store again here would hand [`Store::delete`]
/// the very answer its guard compares against, so the guard could never
/// refuse — and a secret key that appeared after the dialog opened, which is
/// exactly what the guard is for, would be destroyed without the warning or
/// the typed key ID the user would have been asked for. Nothing stops a second
/// rPGP window, or anything else writing to the same directories, from putting
/// one there in the meantime.
fn run_delete(state: &Shared, fingerprint: &str, confirmed_secret: bool) -> Result<String, String> {
    let store = {
        let guard = lock(state);
        guard.store.clone()
    };

    // Claiming at the end that a secret key went takes both halves: one there
    // to take, and a delete that was allowed to take it. The two can disagree
    // now that `secret_too` no longer comes from this read — an unwarned
    // secret key that vanishes before the guard looks lets the delete through,
    // and unlinking an absent file succeeds, but nothing secret was removed
    // and the status must not say one was.
    let had_secret = confirmed_secret && store.has_secret(fingerprint);

    // The guard refuses because a secret key is there that the dialog did not
    // warn about, and its wording — that deleting it needs to be confirmed —
    // describes a confirmation the user was never offered. So say what is true
    // of the store. The target is the one the dialog named when it opened, so
    // this is a secret key written since then by some other writer, and which
    // one is not something this can know. What to do comes first, because the
    // status line elides and the tail is what goes; it names the buttons that
    // are on screen, since a failed delete leaves the dialog open and
    // dismissing it is what makes reopening re-read the store and put the
    // warning back. The state is read here rather than before the call so that
    // a failure past the guard, with the certificate's trust-root and SHA-1
    // entries already removed, is not reported as having deleted nothing.
    store.delete(fingerprint, confirmed_secret).map_err(|e| {
        if !confirmed_secret && store.has_secret(fingerprint) {
            "Cancel, then open Delete again: nothing was deleted, because this \
             certificate has a secret key the dialog did not warn about."
                .to_string()
        } else {
            format!("Could not delete the certificate: {e}")
        }
    })?;

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
            if refuse_while_busy(&ui) {
                return;
            }
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
                            reload_after(
                                &ui,
                                &state,
                                AfterReload {
                                    select: Some(fingerprint),
                                    status: Some(message),
                                },
                            );
                        }
                        // A revocation is written to the public certificate and
                        // then to the secret key, and a withdrawal from several
                        // keys stops at the first that fails, with those before
                        // it made.
                        Err(message) => report_and_reload(&ui, &state, message),
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
                "Certification withdrawn.".to_string()
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

/// What a caller wants done once a reload's worker comes back.
///
/// Both fields exist because [`apply_filter`] runs at the end of a reload and
/// writes over two things a caller used to set for itself. When the reload was
/// synchronous, `reload(); reselect(); set_status()` ran in that order and the
/// caller's writes landed last. Off the event loop it comes back a turn later,
/// so what used to be the caller's next statement has to travel with the
/// request instead.
#[derive(Default)]
struct AfterReload {
    /// The row to put the selection back on. `None` keeps whichever row the
    /// user is on, which is not the same as clearing it: a reload no longer
    /// blocks them, so they are free to move while one is in flight. For the
    /// same reason a row given here is put back only if they have not moved
    /// since the reload was asked for; once they have picked another, theirs
    /// wins.
    select: Option<String>,
    /// The confirmation the mutation wants shown — "Imported 3 certificates".
    /// Set by the caller after `apply_filter` has had its say, exactly as it
    /// was before.
    status: Option<String>,
}

/// Everything a reload reads, with nothing in it that touches the window.
struct Loaded {
    all: Vec<CertSummary>,
    /// Bookkeeping files that would not read. Named rather than counted, so
    /// the status line can say which badge may be missing.
    degraded: Vec<&'static str>,
}

/// Re-read the store from disk and rebuild the list.
///
/// Everything here is local — cert-d, the trust graph, the secret-key
/// directory — and all of it now happens on a worker, because it does not fit
/// in a frame. Measured by `benches/reload.rs`, the read is 18ms at a thousand
/// certificates and 127ms at five thousand, against a 16ms budget; the web of
/// trust alone is 53ms of that second figure. It ran on the event loop because
/// the list had to exist before the call returned, several callers following it
/// straight away with `reselect` — [`AfterReload`] carries that intent across
/// the gap instead.
///
/// It reads the secrets directory but does not open the keys in it: which
/// certificates have a secret half is answered from the filenames, via
/// [`Store::secret_fingerprints`]. The parts that leave the machine, and the
/// damaged-file survey that does re-parse every secret key, are handed to
/// [`survey_agent_and_secrets`] instead.
fn reload(ui: &AppWindow, state: &Shared) {
    reload_after(ui, state, AfterReload::default());
}

/// [`reload`], with something to do when it lands.
fn reload_after(ui: &AppWindow, state: &Shared, after: AfterReload) {
    let (store, generation, selection, first) = {
        let mut guard = lock(state);
        guard.reload_generation += 1;
        (
            guard.store.clone(),
            guard.reload_generation,
            guard.selection_generation,
            guard.all.is_empty(),
        )
    };

    // Only when there is nothing on screen yet, which in practice means
    // startup. A refresh of a list already showing keeps showing them, and
    // replacing the count with this for one frame would just be a flicker.
    if first {
        ui.set_status("Reading the certificate store…".into());
    }

    let (ui_weak, state) = (ui.as_weak(), state.clone());
    std::thread::spawn(move || {
        let loaded = read_store(&store);
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            // A read that a newer one has already overtaken says nothing at
            // all — not even its error, which would otherwise sit on the status
            // line describing a store the newer read is about to succeed at.
            // Without this the list could also go backwards: delete then
            // import, and if the delete's read finishes second it puts the
            // deleted certificate back on screen until something forces
            // another reload.
            if lock(&state).reload_generation != generation {
                return;
            }

            let loaded = match loaded {
                Ok(loaded) => loaded,
                Err(e) => {
                    ui.set_status(format!("Cannot read the certificate store: {e}").into());
                    return;
                }
            };
            lock(&state).all = loaded.all;

            // Read before apply_filter, which clears it. The caller's row is
            // honoured only while the user is where they were when the reload
            // was asked for. Put back regardless, it took the details pane off
            // a row the user had moved to in the meantime — and off the
            // certificate a dialog they had opened since then was naming,
            // behind that dialog's back.
            let moved = lock(&state).selection_generation != selection;
            let select = after.select.filter(|_| !moved).or_else(|| {
                ui.get_has_selection()
                    .then(|| ui.get_detail().fingerprint.to_string())
            });

            apply_filter(&ui, &state);
            if let Some(fingerprint) = &select {
                reselect(&ui, &state, fingerprint);
            }

            // After apply_filter, never before: that sets the status line
            // itself, so a message written earlier would be overwritten by the
            // ordinary count and the reader would never see it. The caller's
            // own confirmation wins over the degraded notice, which is the
            // order these two arrived in when the caller set its status on the
            // line after `reload`.
            if let Some(status) = after.status {
                ui.set_status(status.into());
            } else if !loaded.degraded.is_empty() {
                // Two reads can land under one name: the SHA-1 list is read
                // twice, and the trust roots come from two files. So dedupe
                // rather than name one part of the store twice.
                let mut degraded = loaded.degraded;
                degraded.sort_unstable();
                degraded.dedup();
                ui.set_status(
                    format!(
                        "Loaded, but could not read: {}. Badges for those may be missing.",
                        degraded.join(", ")
                    )
                    .into(),
                );
            }

            survey_agent_and_secrets(&ui, &state, store);
        });
    });
}

/// Report a failure, and read the store again behind the message.
///
/// For the operations that make more than one write, where a failure can
/// come after some of them have landed: an import that stops partway, a key
/// change whose secret half was written, a revocation, a withdrawal from
/// several keys, a delete past its list entries. Their failures used to set
/// the status line and leave the list as it was, so what had been written did
/// not show until something else reloaded, and the user acted on a picture
/// that was no longer the store. The message goes up at once, rather than
/// waiting for the reload to land, and again when it does, since landing
/// writes over the status line. A reload that cannot read the store puts its
/// own "Cannot read the certificate store" in place of the message instead:
/// the list then still shows the old picture, and that is the more pressing
/// thing to know.
fn report_and_reload(ui: &AppWindow, state: &Shared, message: String) {
    ui.set_status(message.clone().into());
    reload_after(
        ui,
        state,
        AfterReload {
            status: Some(message),
            ..Default::default()
        },
    );
}

/// The blocking half of a reload: every read of the store, and no window.
///
/// Split out for the same reason [`visible`] was — it is what the cost is, and
/// it was unreachable from a worker thread while it lived inside a function
/// that takes an `AppWindow`.
fn read_store(store: &Store) -> std::result::Result<Loaded, String> {
    let certs = store.certs().map_err(|e| e.to_string())?;

    // The bookkeeping reads below each fall back to an empty answer, and every
    // one of those fallbacks errs in the safe direction: fewer trust roots means
    // fewer identities authenticate, no SHA-1 entries means the strict policy,
    // no secret fingerprints means no key claims to hold one. So a failure here
    // cannot turn into a badge that overstates what is known — but it can make
    // one quietly disappear, and an unexplained missing badge is exactly how "my
    // key is gone" becomes a mystery. That is the reasoning behind the
    // damaged-file survey elsewhere, and it applies here too: fall back, then
    // say so.
    let mut degraded: Vec<&'static str> = Vec::new();

    // Summarised under the store's policy rather than the standard one, so a
    // certificate the user opted into SHA-1 shows the user IDs and subkeys it
    // actually has. Strict for everything else, and strict for all of it when
    // nothing is opted in — which is the ordinary case and costs nothing.
    let sha1_policy = store.sha1_policy().unwrap_or_else(|_| {
        degraded.push("SHA-1 acceptance");
        Sha1Policy::strict()
    });
    let mut all: Vec<CertSummary> = certs
        .iter()
        .map(|c| CertSummary::from_cert_with(c, &sha1_policy))
        .collect();

    // Authentication is a property of the whole graph, so it is computed once
    // for the store rather than per certificate. Trust roots are the explicit
    // list plus every key generated here, the union Store::effective_roots
    // makes. It is built here from the two halves instead, because the details
    // pane needs them apart: its Trust root box is ticked for a key in either
    // and locked only for a key generated here. Built from the one reading,
    // the box is ticked for exactly the keys the web of trust below starts
    // from. If either half cannot be read, the web of trust starts from the
    // other alone: fewer roots, never more, the safe direction the note above
    // asks for.
    let explicit_roots = store.trust_roots().unwrap_or_else(|_| {
        degraded.push("trust roots");
        Default::default()
    });
    // Asked of the store rather than read off the secret half: a secret key
    // that arrived by import is held but is not a root until it is made one.
    // If this read fails, every secret key's box is left free, a generated
    // key's included. Ticking one then writes an entry that its box cannot
    // remove once the store reads again, which is harmless: that key is a
    // root either way.
    let implicit_roots = store.implicit_roots().unwrap_or_else(|_| {
        degraded.push("trust roots");
        Default::default()
    });
    let roots: Vec<String> = explicit_roots.union(&implicit_roots).cloned().collect();
    let sha1_accepted = store.sha1_accepted().unwrap_or_else(|_| {
        degraded.push("SHA-1 acceptance");
        Default::default()
    });
    let authenticated = wot::authenticate_all(&certs, &roots);

    // The secret half lives outside cert-d, so ask the store which ones it has
    // — once, as a set. Asking per certificate meant a stat syscall and four
    // string allocations each, to re-derive what the directory listing above
    // already produced.
    let secrets = store.secret_fingerprints().unwrap_or_else(|_| {
        degraded.push("secret keys");
        Default::default()
    });
    for summary in all.iter_mut() {
        let key = summary.fingerprint.to_uppercase();
        summary.has_secret = secrets.contains(&key);
        summary.is_trust_root = explicit_roots.contains(&key);
        summary.implicit_root = implicit_roots.contains(&key);
        summary.sha1_accepted = sha1_accepted.contains(&key);
        // The verdict for the identity actually shown on the row, not the
        // best over every identity on the certificate.
        summary.authentication = wot::for_user_id(&authenticated, &key, &summary.primary_user_id);
    }

    // Ordering belongs to apply_filter, so changing the sort does not
    // require re-reading the store.
    Ok(Loaded { all, degraded })
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
                sha1: s.sha1,
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
    // Ahead of the authentication check, and it has to be: a SHA-1 signer can
    // never authenticate anyway, so without this the reader is told only that
    // the identity is unverified — the smaller of the two problems, and the one
    // that hides the larger. Never tone 1, whatever else is true of it.
    if rows.iter().any(|r| r.sha1) {
        return (
            "Valid only because you accepted SHA-1 — this shows the key was involved, not that its holder signed this".to_string(),
            2,
        );
    }
    if rows.iter().all(|r| r.authenticated) {
        ("Signature verified".to_string(), 1)
    } else {
        (
            "Valid signature, but the signer's identity is not verified".to_string(),
            2,
        )
    }
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
        implicit_root: summary.implicit_root,
        sha1_blocked: summary.sha1_blocked,
        sha1_accepted: summary.sha1_accepted,
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
/// Report a failure that happened before there was a window to put it in.
///
/// Every startup error funnels through here, and until now every one of them
/// was invisible in exactly the situation where it matters. A GUI launch has no
/// terminal attached: on Windows a `windows_subsystem = "windows"` process has
/// no console at all, and std maps a write to that invalid handle to `Ok(())`
/// rather than an error, so `eprintln!` succeeds and discards. A macOS .app
/// opened from Finder and a Flatpak launched from a menu both send stderr
/// somewhere the user will not look either. The window does not exist yet —
/// `AppWindow::new` only constructs, nothing is shown until `run()` — so a
/// failure to open the certificate store ended as a process that started and
/// vanished, with no window, no message and nothing in a log the user reads.
///
/// The terminal test is the condition itself rather than a platform check: if
/// stderr is a terminal the message is already in front of whoever ran it, and
/// a modal dialog would be in the way — and would hang a headless run that has
/// no one to dismiss it.
fn report_fatal(message: &str) {
    eprintln!("rpgp: {message}");
    if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
        return;
    }
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title("rPGP could not start")
        .set_description(message)
        .show();
}

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
            report_fatal(&e.to_string());
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
            sha1: false,
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

    /// The reads that moved off the event loop, exercised where they now live.
    ///
    /// `read_store` is the whole of what a reload does before it touches the
    /// window, and the stitching at the end of it is the part that would fail
    /// quietly: `has_secret`, `is_trust_root`, `implicit_root` and
    /// `sha1_accepted` each come from a different read of the store, are
    /// matched to a row by uppercased fingerprint, and a mismatch produces a
    /// row with somebody else's badges rather than an error. Nothing else
    /// asserts on that join.
    #[test]
    fn read_store_puts_every_badge_on_the_right_row() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();

        let generate = |user_id: &str| {
            rpgp_core::keygen::generate(&rpgp_core::keygen::KeyGenRequest::new(user_id))
                .unwrap()
                .cert
        };
        let mine = generate("Me <me@example.org>");
        let imported = generate("Imported <imported@example.org>");
        let other = generate("Other <other@example.org>");
        store.insert_secret(&mine).unwrap();
        // Stored the way Import stores a secret key that arrives in a file.
        store.insert_imported_secret(&imported).unwrap();
        store.insert(&other).unwrap();

        let (mine, imported, other) = (
            mine.fingerprint().to_hex(),
            imported.fingerprint().to_hex(),
            other.fingerprint().to_hex(),
        );
        store.set_trust_root(&mine, true).unwrap();
        store.set_sha1_accepted(&other, true).unwrap();

        let loaded = read_store(&store).expect("a healthy store reads");
        assert!(
            loaded.degraded.is_empty(),
            "nothing was damaged, so nothing should be reported: {:?}",
            loaded.degraded
        );
        assert_eq!(loaded.all.len(), 3);

        let row = |fingerprint: &str| {
            loaded
                .all
                .iter()
                .find(|c| c.fingerprint == fingerprint)
                .unwrap_or_else(|| panic!("{fingerprint} is missing from the list"))
        };
        let (mine, imported, other) = (row(&mine), row(&imported), row(&other));

        assert!(mine.has_secret, "the secret half is in the store");
        assert!(mine.is_trust_root, "it was just made one");
        assert!(
            mine.implicit_root,
            "it was generated here, which makes it a root whatever the list says"
        );
        assert!(!mine.sha1_accepted, "the other certificate was opted in");

        assert!(imported.has_secret, "an imported secret key is still held");
        assert!(!imported.is_trust_root);
        assert!(
            !imported.implicit_root,
            "an imported secret key is not a trust root until it is made one"
        );

        assert!(!other.has_secret);
        assert!(!other.is_trust_root);
        assert!(!other.implicit_root);
        assert!(other.sha1_accepted);
    }

    /// A trust-root file that cannot be read leaves the web of trust fewer
    /// roots, never more, and the reload says so.
    ///
    /// The roots are read in two halves, the explicit list and the keys
    /// generated here, and each falls back to nothing on its own. An unreadable
    /// list costs each listed key its root, and a key generated here keeps its
    /// own. An unreadable imported-secrets file costs every secret key its
    /// implicit root: nothing is left to tell a key generated here from an
    /// imported one, and counting them all would make every imported key a
    /// root nobody chose. The listed keys stay roots. Before the halves were
    /// read apart, a failure of either left the web of trust no roots at all.
    #[test]
    fn an_unreadable_trust_root_file_leaves_fewer_roots_and_says_so() {
        fn row<'a>(loaded: &'a Loaded, fingerprint: &str) -> &'a CertSummary {
            loaded
                .all
                .iter()
                .find(|c| c.fingerprint == fingerprint)
                .unwrap_or_else(|| panic!("{fingerprint} is missing from the list"))
        }

        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        let store = Store::open(dir.path().join("certs.d"), &secrets).unwrap();
        let mine = generated("Me <me@example.org>").cert;
        let restored = generated("Restored <restored@example.org>").cert;
        store.insert_secret(&mine).unwrap();
        // Stored the way Import stores a secret key that arrives in a file,
        // then made a root with the Trust root box.
        store.insert_imported_secret(&restored).unwrap();
        let (mine, restored) = (mine.fingerprint().to_hex(), restored.fingerprint().to_hex());
        store.set_trust_root(&restored, true).unwrap();

        // A reload with one of the store's files damaged, which is repaired
        // again afterwards.
        let read_damaged = |name: &str| {
            let path = secrets.with_file_name(name);
            let intact = std::fs::read(&path).unwrap();
            // Bytes that are not UTF-8, so the read errors rather than
            // returning empty.
            std::fs::write(&path, b"\xff\xfe not utf-8 \xff").unwrap();
            let loaded = read_store(&store).expect("only a bookkeeping file is damaged");
            std::fs::write(&path, intact).unwrap();
            assert!(
                loaded.degraded.contains(&"trust roots"),
                "the damaged {name} went unreported: {:?}",
                loaded.degraded
            );
            loaded
        };

        // A root vouches for its own identity, and nothing else here certifies
        // either key, so a row's own verdict says whether the web of trust
        // started from that key.
        let healthy = read_store(&store).expect("a healthy store reads");
        assert!(healthy.degraded.is_empty(), "{:?}", healthy.degraded);
        for key in [&mine, &restored] {
            assert_eq!(
                row(&healthy, key).authentication,
                Authentication::Full,
                "both keys are roots while nothing is damaged"
            );
        }

        let loaded = read_damaged("imported-secrets");
        let (mine_row, restored_row) = (row(&loaded, &mine), row(&loaded, &restored));
        assert!(
            !mine_row.implicit_root && !restored_row.implicit_root,
            "no key may count as generated here while the imported list cannot be read"
        );
        assert_eq!(mine_row.authentication, Authentication::Unknown);
        assert!(restored_row.is_trust_root);
        assert_eq!(
            restored_row.authentication,
            Authentication::Full,
            "the explicit list could still be read, so the key it names is still a root"
        );

        let loaded = read_damaged("trust-roots");
        let (mine_row, restored_row) = (row(&loaded, &mine), row(&loaded, &restored));
        assert!(mine_row.implicit_root);
        assert_eq!(
            mine_row.authentication,
            Authentication::Full,
            "a key generated here is a root whatever the list says, read or not"
        );
        assert!(!restored_row.is_trust_root);
        assert_eq!(restored_row.authentication, Authentication::Unknown);
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
            encrypted: true,
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
            encrypted: true,
        };
        let store = [known(&fingerprint, Authentication::Full)];
        assert_eq!(signature_verdict(&store, &bad).1, 3);
    }

    /// SHA-1 outranks authentication in the banner, because it is the worse
    /// news. An opted-in certificate cannot authenticate — so a reader who
    /// only saw "identity is not verified" would be told the lesser of the two
    /// problems and left to infer the greater one.
    #[test]
    fn a_sha1_signature_never_reads_as_verified() {
        let fingerprint = "EF".repeat(20);
        let mut sha1_report = report(&fingerprint, true);
        sha1_report.sha1 = true;
        let result = ops::VerifyResult {
            signatures: vec![sha1_report],
            decrypted_with: None,
            encrypted: true,
        };

        // Even with the signer fully authenticated — which cannot happen for a
        // real SHA-1 certificate, and is asserted here so that the banner does
        // not quietly depend on that being enforced elsewhere.
        let store = [known(&fingerprint, Authentication::Full)];
        let (text, tone) = signature_verdict(&store, &result);
        assert_eq!(tone, 2, "{text}");
        assert!(text.contains("SHA-1"), "{text}");

        // And a bad SHA-1 signature is still reported as bad, not as weak.
        let mut bad = report(&fingerprint, false);
        bad.sha1 = true;
        let result = ops::VerifyResult {
            signatures: vec![bad],
            decrypted_with: None,
            encrypted: true,
        };
        assert_eq!(signature_verdict(&store, &result).1, 3);
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

    /// A `State` holding nothing but the store, with everything else as `run`
    /// starts it. A test that needs the list fills `all` itself, or builds a
    /// window over the state with `window_for`, which reads it in.
    fn state_for(store: Store) -> Shared {
        Arc::new(Mutex::new(State {
            store: Arc::new(store),
            all: Vec::new(),
            shown: Vec::new(),
            reload_generation: 0,
            selection_generation: 0,
            filter: String::new(),
            scope: Scope::All,
            sort: Sort::MineFirst,
            choose_outputs: false,
            se_input: None,
            se_recipients: Vec::new(),
            se_filter: String::new(),
            se_signers: Vec::new(),
            dv_input: None,
            dv_data: None,
            dv_kind: InputKind::NotOpenPgp,
            dv_generation: 0,
            certify_target: None,
            certify_user_ids: Vec::new(),
            certify_certifiers: Vec::new(),
            lookup_results: Vec::new(),
            revoke_target: None,
            revoke_certification: false,
            delete_target: None,
            lifecycle_fingerprint: None,
        }))
    }

    /// The dialog decides once, when it opens, whether this is a tidying
    /// operation or the destruction of the only copy of a key — and it asks
    /// for the key ID to be typed only in the second case. The delete has to
    /// act on that same answer, so that a secret key written by something else
    /// in between is refused by the store rather than removed on the strength
    /// of a confirmation the user was never shown.
    #[test]
    fn deleting_follows_the_warning_the_dialog_showed() {
        let dir = tempfile::tempdir().unwrap();
        let (certs, secrets) = (dir.path().join("certs.d"), dir.path().join("secrets"));
        let cert = rpgp_core::keygen::generate(&rpgp_core::keygen::KeyGenRequest::new(
            "Bob <bob@example.org>",
        ))
        .unwrap()
        .cert;
        let fingerprint = cert.fingerprint().to_hex();

        // The public half only, so the dialog opens with no warning and no
        // field to type in.
        let store = Store::open(&certs, &secrets).unwrap();
        store.insert(&cert).unwrap();
        let state = state_for(store);

        // Another writer on the same directories — a second rPGP window, a
        // sync tool — restores the secret half while the dialog is open.
        let elsewhere = Store::open(&certs, &secrets).unwrap();
        elsewhere.insert_secret(&cert).unwrap();
        assert!(elsewhere.has_secret(&fingerprint));

        let refused = run_delete(&state, &fingerprint, false)
            .expect_err("a secret key the dialog never warned about must not be deleted");
        assert!(
            refused.contains("the dialog did not warn about"),
            "the message should say what is wrong, not just that it failed: {refused}"
        );
        assert!(
            elsewhere.has_secret(&fingerprint),
            "the secret key is still on disk"
        );
        assert!(
            elsewhere.reopen().unwrap().lookup(&fingerprint).is_ok(),
            "and so is the certificate, since nothing was deleted"
        );

        // Reopened, the dialog now warns and asks for the key ID; confirmed,
        // both halves go.
        let message = run_delete(&state, &fingerprint, true).expect("a confirmed delete proceeds");
        assert!(
            message.contains("secret key deleted"),
            "the status should report what went: {message}"
        );
        assert!(!elsewhere.has_secret(&fingerprint));
        assert!(elsewhere.reopen().unwrap().lookup(&fingerprint).is_err());
    }

    /// Both Sign paths resolve the signer from the whole certificate, so a
    /// revocation the store holds is one `ops` gets to refuse.
    ///
    /// `Store::insert` writes cert-d and never the secret key file, and it is
    /// what Import and a keyserver refresh both go through — so one's own
    /// revocation, coming back from wherever it was made, reaches the public
    /// half alone. Resolving the signer from the secret half first picked the
    /// one copy that did not know: the list drew `revoked` against the row, the
    /// picker still offered the key, and the app signed with it.
    ///
    /// Retired is the default and is soft, which is the worse case — those
    /// signatures keep verifying for anyone who has not seen the revocation,
    /// so nothing downstream announces that the key was withdrawn.
    #[test]
    fn signing_sees_a_revocation_that_reached_only_cert_d() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let cert = rpgp_core::keygen::generate(&rpgp_core::keygen::KeyGenRequest::new(
            "Alice <alice@example.org>",
        ))
        .unwrap()
        .cert;
        let fingerprint = cert.fingerprint().to_hex();
        store.insert_secret(&cert).unwrap();

        let input = dir.path().join("treaty.txt");
        std::fs::write(&input, b"the treaty text").unwrap();
        let output = ops::signature_name(&input);

        let state = state_for(store);
        {
            let mut guard = lock(&state);
            guard.se_signers = vec![(fingerprint.clone(), "Alice <alice@example.org>".to_string())];
            guard.se_input = Some(input.clone());
        }

        // Live, both paths sign — otherwise the refusals below would prove
        // nothing about the revocation.
        let signed =
            run_notepad(&state, 0, "the treaty text", 0, "", "").expect("a live key signs");
        assert!(signed.0.contains("-----BEGIN PGP SIGNED MESSAGE-----"));
        run_sign_encrypt(&state, false, true, 0, "", "", None)
            .expect("a live key signs a file too");
        std::fs::remove_file(&output).unwrap();

        // The owner retires the key on another machine, and this one meets the
        // result the way Import does: as a public certificate, which `insert`
        // writes to cert-d and nowhere else.
        let elsewhere_dir = tempfile::tempdir().unwrap();
        let elsewhere = Store::open(
            elsewhere_dir.path().join("certs.d"),
            elsewhere_dir.path().join("secrets"),
        )
        .unwrap();
        elsewhere.insert_secret(&cert).unwrap();
        let mut request = rpgp_core::revoke::RevokeRequest::new(&fingerprint);
        request.reason = rpgp_core::revoke::Reason::Retired;
        rpgp_core::revoke::revoke_cert(&elsewhere, &request).unwrap();
        let store = lock(&state).store.clone();
        store
            .insert(&elsewhere.lookup(&fingerprint).unwrap())
            .unwrap();
        assert!(
            store.secret_cert(&fingerprint).is_ok(),
            "the secret half is still there, and still unaware — the premise here"
        );

        let refused = run_notepad(&state, 0, "the treaty text", 0, "", "")
            .map(|_| ())
            .expect_err("signed with a key its owner had retired");
        assert!(
            refused.contains("Alice <alice@example.org>") && refused.contains("has been revoked"),
            "the status bar has to say whose key and why: {refused}"
        );

        let refused = run_sign_encrypt(&state, false, true, 0, "", "", None)
            .map(|_| ())
            .expect_err("signed a file with a key its owner had retired");
        assert!(
            refused.contains("has been revoked"),
            "the status bar has to say why: {refused}"
        );
        assert!(
            !output.exists(),
            "a refused signature must leave no file behind"
        );
    }

    /// The pickers are built from the summary's capability flags, so a key the
    /// core will refuse must not be in them.
    ///
    /// Both lists come from `build_signing_targets`, which filters on
    /// `can_encrypt` for recipients and on `can_sign` for signers and does not
    /// look at `validity` at all. A revoked certificate kept whichever
    /// capabilities sat on its subkeys, so a key the user had just retired was
    /// still offered as a signer and as a recipient, with the red `revoked`
    /// pill against its row in the list behind the dialog.
    #[test]
    fn the_pickers_offer_only_the_keys_the_operations_will_use() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let generate = |user_id: &str| {
            rpgp_core::keygen::generate(&rpgp_core::keygen::KeyGenRequest::new(user_id))
                .unwrap()
                .cert
        };
        let live = generate("Live <live@example.org>");
        let retired = generate("Retired <retired@example.org>");
        store.insert_secret(&live).unwrap();
        store.insert_secret(&retired).unwrap();
        let (live, retired) = (live.fingerprint().to_hex(), retired.fingerprint().to_hex());
        revoke::revoke_cert(&store, &RevokeRequest::new(&retired)).unwrap();

        let loaded = read_store(&store).expect("a healthy store reads");
        let state = state_for(store);
        let mut guard = lock(&state);
        guard.all = loaded.all;
        build_signing_targets(&mut guard, None);

        let offered_to = |fingerprint: &str| {
            guard
                .se_recipients
                .iter()
                .any(|r| r.fingerprint == fingerprint)
        };
        let signs_with = |fingerprint: &str| guard.se_signers.iter().any(|(f, _)| f == fingerprint);

        assert!(
            offered_to(&live) && signs_with(&live),
            "a live key with a secret half belongs in both lists, or this test proves nothing"
        );
        assert!(
            !offered_to(&retired),
            "a revoked key must not be offered as a recipient: encrypt refuses it"
        );
        assert!(
            !signs_with(&retired),
            "nor as a signer: signing refuses it too"
        );
    }

    /// A Flatpak sandbox is recognised by the file Flatpak puts at its root,
    /// and without that file nothing changes: a native build writes its
    /// outputs beside the input, as it always has.
    #[test]
    fn a_flatpak_sandbox_is_recognised_by_the_file_at_its_root() {
        let root = tempfile::tempdir().unwrap();
        assert!(!flatpak_sandbox(root.path()));
        std::fs::write(
            root.path().join(".flatpak-info"),
            b"[Application]\nname=app.rpgp.rpgp\n",
        )
        .unwrap();
        assert!(flatpak_sandbox(root.path()));
    }

    /// An output chosen in the save dialog is written exactly where it was
    /// chosen, over the file already there, and nothing is written beside the
    /// input.
    ///
    /// Inside a Flatpak that dialog is the only way an output reaches the
    /// host under its own name: the document portal puts the chosen name on
    /// disk and no other, so `notes.txt (1).asc`, the name a derived output
    /// steps to when its own is taken, would reach the host only as a hidden
    /// `.xdp-` file. And the dialog has already asked whether to replace a
    /// file at that name, so refusing it as "already exists" would overrule
    /// the user's answer.
    #[test]
    fn an_output_chosen_in_the_save_dialog_is_written_exactly_there() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let alice = generated("Alice <alice@example.org>").cert;
        store.insert_secret(&alice).unwrap();
        let fingerprint = alice.fingerprint().to_hex();

        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"the plaintext").unwrap();
        // In another folder, as the dialog may well choose, and each already
        // holding a file the user has agreed to replace.
        let saved = dir.path().join("saved");
        std::fs::create_dir(&saved).unwrap();
        let (encrypted, signature, decrypted) = (
            saved.join("notes.txt.asc"),
            saved.join("notes.txt.sig"),
            saved.join("notes.txt"),
        );
        for path in [&encrypted, &signature, &decrypted] {
            std::fs::write(path, b"AN EARLIER FILE").unwrap();
        }

        let loaded = read_store(&store).expect("a healthy store reads");
        let state = state_for(store);
        {
            let mut guard = lock(&state);
            guard.all = loaded.all;
            build_signing_targets(&mut guard, Some(&fingerprint));
            guard.se_input = Some(input.clone());
        }

        let wrote = run_sign_encrypt(&state, true, false, 0, "", "", Some(encrypted.clone()))
            .expect("encrypting replaces the chosen file");
        assert_eq!(wrote, encrypted, "the status line names the file written");
        assert_eq!(ops::classify_file(&encrypted), InputKind::Message);

        let wrote = run_sign_encrypt(&state, false, true, 0, "", "", Some(signature.clone()))
            .expect("signing replaces the chosen file");
        assert_eq!(wrote, signature);
        let store = lock(&state).store.clone();
        assert!(
            ops::verify_detached_files(&store, &signature, &input)
                .unwrap()
                .all_good()
        );

        {
            let mut guard = lock(&state);
            guard.dv_input = Some(encrypted.clone());
            guard.dv_kind = InputKind::Message;
        }
        let (_, outcome) = run_decrypt_verify(&state, "", Some(decrypted.clone()));
        let (summary, _, _) = outcome.expect("decrypting replaces the chosen file");
        assert!(
            summary.starts_with(&format!("Decrypted to {}.", decrypted.display())),
            "the status line names the file written: {summary}"
        );
        assert_eq!(std::fs::read(&decrypted).unwrap(), b"the plaintext");

        let names = |dir: &Path| {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with("notes"))
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(dir.path()), ["notes.txt"], "written beside the input");
        assert_eq!(
            names(&saved),
            ["notes.txt", "notes.txt.asc", "notes.txt.sig"],
            "written somewhere other than the chosen names"
        );
    }

    fn generated(user_id: &str) -> rpgp_core::keygen::GeneratedKey {
        rpgp_core::keygen::generate(&rpgp_core::keygen::KeyGenRequest::new(user_id)).unwrap()
    }

    /// The window `run` builds, over `state`, wired by every `wire_*` function
    /// `run` calls and showing the list a finished reload leaves on screen.
    /// Only the About link is not wired, because it would open a browser.
    ///
    /// The caller sets up the Slint platform first, because which backend a
    /// test needs depends on whether it runs an event loop.
    fn window_for(state: &Shared) -> AppWindow {
        let ui = AppWindow::new().expect("the window builds on the testing backend");
        let store = lock(state).store.clone();
        lock(state).all = read_store(&store).expect("a healthy store reads").all;
        apply_filter(&ui, state);
        wire_list(&ui, state);
        wire_keygen(&ui, state);
        wire_sign_encrypt(&ui, state);
        wire_decrypt_verify(&ui, state);
        wire_certify(&ui, state);
        wire_revoke(&ui, state);
        wire_delete(&ui, state);
        wire_notepad(&ui, state);
        wire_lifecycle(&ui, state);
        wire_lookup(&ui, state);
        ui
    }

    /// Click the list row showing `fingerprint`, as `CertListRow` does.
    fn click_row(ui: &AppWindow, state: &Shared, fingerprint: &str) {
        let row = {
            let guard = lock(state);
            guard
                .shown
                .iter()
                .position(|&i| guard.all[i].fingerprint == fingerprint)
                .expect("the certificate is in the list")
        };
        ui.set_current_row(row as i32);
        ui.invoke_row_selected(row as i32);
    }

    /// The row the details pane would show for `fingerprint`.
    fn row_for(state: &Shared, fingerprint: &str) -> CertRow {
        lock(state)
            .all
            .iter()
            .find(|c| c.fingerprint == fingerprint)
            .map(to_row)
            .expect("the certificate is in the list")
    }

    /// Wait for a worker, judged by what it leaves behind.
    ///
    /// With no event loop a worker's completion is never delivered, so a test
    /// that starts one watches for its effect instead.
    fn wait_for(what: &str, done: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !done() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The delete dialog names one certificate, so the delete removes that
    /// one, even when the details pane behind it has moved to another by the
    /// time the button is pressed.
    ///
    /// The pane is moved by hand here, standing in for what used to move it: a
    /// reload landing behind the scrim with a row of its own to select. The
    /// delete read the pane afresh when pressed, so the dialog went on saying
    /// "Remove Bob" while it removed Alice.
    #[test]
    fn deleting_removes_the_certificate_the_dialog_named() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let (certs, secrets) = (dir.path().join("certs.d"), dir.path().join("secrets"));
        let store = Store::open(&certs, &secrets).unwrap();
        let alice = generated("Alice <alice@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert(&alice).unwrap();
        store.insert(&bob).unwrap();
        let (alice, bob) = (alice.fingerprint().to_hex(), bob.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &bob);
        ui.invoke_open_delete();
        assert!(ui.get_delete_open());
        assert_eq!(ui.get_delete_target(), "Bob <bob@example.org>");

        ui.set_detail(row_for(&state, &alice));
        ui.invoke_delete_run();
        // Seen by the store the window goes on using, which the delete no
        // longer replaces.
        let store = lock(&state).store.clone();
        wait_for("the delete", || store.certs().unwrap().len() == 1);

        let after = Store::open(&certs, &secrets).unwrap();
        assert!(
            after.lookup(&bob).is_err(),
            "the certificate the dialog named should be gone"
        );
        assert!(
            after.lookup(&alice).is_ok(),
            "the one the pane moved to should not have been touched"
        );
    }

    /// A delete that has gone through is reported as done, and the list
    /// leaves the certificate out, even where the store could not have been
    /// opened a second time.
    ///
    /// The delete used to reopen the store in order to see its own deletion,
    /// and a reopen that failed after the files were gone reported the delete
    /// as a failure and kept the old store, which went on listing the deleted
    /// certificate on every reload. Opening fails here because a directory
    /// stands where cert-d's index goes, while the store already open keeps
    /// the index it has. Unix only, since Windows refuses to rename a file
    /// that is open, as that index is.
    #[cfg(unix)]
    #[test]
    fn a_delete_is_seen_by_the_store_in_use_even_where_opening_another_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (certs, secrets) = (dir.path().join("certs.d"), dir.path().join("secrets"));
        let store = Store::open(&certs, &secrets).unwrap();
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert(&bob).unwrap();
        let fingerprint = bob.fingerprint().to_hex();
        let state = state_for(store);
        let listed = || {
            let store = lock(&state).store.clone();
            read_store(&store)
                .expect("the store in use reads")
                .all
                .iter()
                .any(|c| c.fingerprint == fingerprint)
        };
        assert!(listed());

        let index = std::fs::read_dir(&certs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("_sequoia_cert_store_index") && name.ends_with(".sqlite")
                    })
            })
            .expect("cert-d keeps an index");
        std::fs::rename(&index, index.with_extension("moved")).unwrap();
        std::fs::create_dir(&index).unwrap();
        assert!(
            Store::open(&certs, &secrets).is_err(),
            "the store still opens a second time, so this proves nothing"
        );

        let message =
            run_delete(&state, &fingerprint, false).expect("the files are gone, so it was done");
        assert_eq!(message, "Certificate deleted.");
        assert!(!listed(), "the deleted certificate is still listed");
    }

    /// A key stored without its revocation certificate closes the dialog, as
    /// one stored with it does, and a generation that kept nothing leaves the
    /// dialog open for another try.
    ///
    /// The first used to be reported as a failed generation, with the dialog
    /// left open and every field still filled in, and its button, pressed
    /// again, made a second key with the same user ID. The outcomes are handed
    /// over directly, since only an event loop delivers a worker's; which one
    /// `keygen::save` returns when is rpgp-core's to test.
    #[test]
    fn a_key_kept_without_its_revocation_certificate_closes_the_dialog() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        let full = || rpgp_core::Error::invalid("no space left on device");

        ui.set_keygen_open(true);
        ui.set_busy(true);
        finish_keygen(&ui, &state, Err(full()));
        assert!(
            ui.get_keygen_open(),
            "a generation that kept nothing closed its dialog"
        );
        assert!(!ui.get_busy());
        assert_eq!(
            ui.get_status(),
            "Key generation failed: no space left on device"
        );

        ui.set_busy(true);
        let asked = lock(&state).reload_generation;
        finish_keygen(
            &ui,
            &state,
            Ok(("AB".repeat(20), keygen::Saved::WithoutRevocation(full()))),
        );
        assert!(
            !ui.get_keygen_open(),
            "a key that was kept left the dialog open to make another"
        );
        assert!(!ui.get_busy());
        assert!(
            lock(&state).reload_generation > asked,
            "the list was not read again to show the key"
        );
    }

    /// A keyring whose import stops partway is reported as that, and not
    /// taken for a revocation certificate.
    ///
    /// A failed import falls back to reading the file as a revocation
    /// certificate, which is for a file with no certificate in it. A keyring
    /// that had stored a revoked certificate before it stopped was taken for
    /// one, and the status line said that certificate had been revoked and
    /// nothing about the import. Here the second certificate cannot be stored
    /// because a file stands where cert-d wants a directory for it.
    #[test]
    fn a_keyring_that_stops_partway_is_not_taken_for_a_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = Store::open(
            dir.path().join("elsewhere"),
            dir.path().join("elsewhere-secrets"),
        )
        .unwrap();
        let retired = generated("Retired <retired@example.org>").cert;
        let retired_fp = retired.fingerprint().to_hex();
        elsewhere.insert_secret(&retired).unwrap();
        revoke::revoke_cert(&elsewhere, &RevokeRequest::new(&retired_fp)).unwrap();
        // One whose file goes in another of cert-d's directories.
        let prefix = |fingerprint: &str| fingerprint.to_lowercase()[..2].to_string();
        let other_fp = std::iter::repeat_with(|| generated("Other <other@example.org>").cert)
            .find(|cert| prefix(&cert.fingerprint().to_hex()) != prefix(&retired_fp))
            .map(|cert| {
                elsewhere.insert(&cert).unwrap();
                cert.fingerprint().to_hex()
            })
            .unwrap();
        let keyring = dir.path().join("keyring.asc");
        elsewhere
            .export_file(&[retired_fp.clone(), other_fp.clone()], &keyring)
            .unwrap();

        let certs = dir.path().join("certs.d");
        let store = Store::open(&certs, dir.path().join("secrets")).unwrap();
        std::fs::write(certs.join(prefix(&other_fp)), b"").unwrap();

        match import_into(&store, &keyring) {
            Err(e @ rpgp_core::Error::ImportStopped { stored: 1, .. }) => assert!(
                e.to_string().starts_with("1 certificate(s) were stored"),
                "{e}"
            ),
            other => panic!("expected the import to stop after one certificate: {other:?}"),
        }
        let listed: Vec<String> = read_store(&store)
            .expect("the store reads")
            .all
            .into_iter()
            .map(|c| c.fingerprint)
            .collect();
        assert_eq!(listed, [retired_fp], "what was stored should be listed");
    }

    /// A lifecycle action changes the key its dialog was opened for, not
    /// whichever key the details pane has moved to since.
    ///
    /// Adding a user ID stands in for every mode, since they all take the key
    /// from the same place and this is the one whose result is easy to read
    /// back; Publish would upload. Both keys are the user's own and neither has
    /// a passphrase, so the wrong one is not saved by failing to unlock — the
    /// case of an old and a new key kept for the same address.
    #[test]
    fn a_lifecycle_action_changes_the_key_its_dialog_opened_for() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let old = generated("Jo Old <jo@example.org>").cert;
        let new = generated("Jo New <jo@example.org>").cert;
        store.insert_secret(&old).unwrap();
        store.insert_secret(&new).unwrap();
        let (old, new) = (old.fingerprint().to_hex(), new.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &new);
        ui.invoke_open_add_user_id();
        assert!(ui.get_lifecycle_open());

        ui.set_detail(row_for(&state, &old));
        ui.invoke_lifecycle_run(
            1,
            "0".into(),
            "Jo Work <jo@work.example>".into(),
            SharedString::new(),
            0,
        );

        let store = lock(&state).store.clone();
        let added = |fingerprint: &str| {
            store.secret_cert(fingerprint).is_ok_and(|cert| {
                rpgp_core::cert::user_ids(&cert)
                    .iter()
                    .any(|uid| uid.text == "Jo Work <jo@work.example>")
            })
        };
        wait_for("the user ID to be added", || added(&old) || added(&new));
        assert!(
            added(&new),
            "the key the dialog opened for should carry the user ID"
        );
        assert!(!added(&old), "the key the pane moved to should not");
    }

    /// The Publish warning is given the key its dialog was opened for, and
    /// keeps it after the details pane behind the scrim has moved.
    ///
    /// Asked of the two properties the opener sets for the warning rather than
    /// of the warning's text, because the window is compiled without the debug
    /// information the testing backend needs to read its element tree. What
    /// the dialog says with them is the accessibility suite's
    /// `the_publish_warning_names_the_key_it_uploads`; the window's binding
    /// that hands them from one to the other is covered by neither. Nothing is
    /// uploaded, since the dialog is only opened, never run.
    #[test]
    fn the_publish_warning_is_given_the_key_its_dialog_opened_for() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let old = generated("Jo Old <jo@example.org>").cert;
        let new = generated("Jo New <jo@example.org>").cert;
        store.insert_secret(&old).unwrap();
        store.insert_secret(&new).unwrap();
        let (old, new) = (old.fingerprint().to_hex(), new.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &new);
        ui.invoke_open_publish();
        assert!(ui.get_lifecycle_open());
        assert_eq!(ui.get_lifecycle_mode(), 3);

        ui.set_detail(row_for(&state, &old));
        let opened_for = row_for(&state, &new);
        assert_eq!(
            ui.get_lifecycle_key_name(),
            opened_for.primary_user_id,
            "the warning should name the key the dialog opened for"
        );
        assert_eq!(
            ui.get_lifecycle_key_id(),
            opened_for.key_id,
            "and give that key's ID"
        );
    }

    /// Publish refuses a certificate that is not one of the user's own keys,
    /// as the button that opens it does.
    ///
    /// Asked of the check itself rather than of a Publish run: a test that
    /// went through the upload would reach a real keyserver the day the check
    /// stopped working.
    #[test]
    fn only_your_own_keys_are_published() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let mine = generated("Me <me@example.org>").cert;
        let theirs = generated("Them <them@example.org>").cert;
        store.insert_secret(&mine).unwrap();
        store.insert(&theirs).unwrap();

        assert!(own_key_or_refuse(&store, &mine.fingerprint().to_hex()).is_ok());
        let refused = own_key_or_refuse(&store, &theirs.fingerprint().to_hex())
            .expect_err("someone else's certificate must not be uploaded");
        assert!(refused.contains("not one of your keys"), "{refused}");
    }

    /// Two clicks on a toggle leave the certificate where it started, however
    /// soon the second follows the first.
    ///
    /// No event loop runs here, so the reload each click starts never lands.
    /// That is the state a second click meets whenever the store takes longer
    /// to read than a double-click takes to make: the list still holds the
    /// value from before the first click.
    #[test]
    fn two_clicks_on_a_toggle_before_the_list_catches_up_cancel_out() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let cert = generated("Old <old@example.org>").cert;
        store.insert(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &fingerprint);
        let store = lock(&state).store.clone();

        let is_root = || store.trust_roots().unwrap().contains(&fingerprint);
        ui.invoke_toggle_trust_root();
        assert!(is_root(), "the first click makes it a trust root");
        ui.invoke_toggle_trust_root();
        assert!(
            !is_root(),
            "the second, before the list has caught up, should take it back"
        );

        let accepted = || store.sha1_accepted().unwrap().contains(&fingerprint);
        ui.invoke_toggle_sha1_accepted();
        assert!(accepted(), "the first click accepts SHA-1");
        ui.invoke_toggle_sha1_accepted();
        assert!(
            !accepted(),
            "the second, before the list has caught up, should withdraw it"
        );
    }

    /// A Decrypt / Verify result is shown in the dialog only beside the files
    /// it was about, and otherwise only on the status line, naming them.
    ///
    /// Each run here is made first and its result handed back afterwards, with
    /// the dialog's files changed in between: the order a picker opened before
    /// Run would produce if what it brought back during the run were taken.
    /// The pickers refuse it while `busy` is set, which a run does and this
    /// test does not, so what is tested here is the check that holds whatever
    /// else changes the files. Changing the signed file, the signature, and
    /// closing and reopening the dialog are each tried, since each is its own
    /// way for the files to change.
    #[test]
    fn a_verdict_is_not_shown_beside_files_chosen_while_it_ran() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let alice = generated("Alice <alice@example.org>").cert;
        store.insert_secret(&alice).unwrap();

        let (release, other) = (dir.path().join("a.tar"), dir.path().join("b.tar"));
        std::fs::write(&release, b"the release").unwrap();
        std::fs::write(&other, b"something else entirely").unwrap();
        let signature = dir.path().join("a.tar.sig");
        ops::sign_detached_file(&alice, None, &release, &signature, Existing::Refuse).unwrap();
        let kind = ops::classify_file(&signature);
        assert_eq!(kind, InputKind::DetachedSignature);

        let state = state_for(store);
        let ui = window_for(&state);
        let not_shown = |ui: &AppWindow, how: &str| {
            assert_eq!(
                ui.get_dv_result(),
                "",
                "{how}: the verdict was shown beside files it never read"
            );
            assert_eq!(ui.get_dv_tone(), 0, "{how}");
            assert_eq!(slint::Model::row_count(&ui.get_dv_signatures()), 0, "{how}");
            // What it is not about first, then what it is about: a verify's
            // summary names no file, and the old signature can be the one
            // still chosen.
            let status = ui.get_status();
            assert!(
                status.starts_with("Not for the files now chosen")
                    && status.contains("a.tar.sig against a.tar"),
                "{how}: the status line should say whose result it was: {status}"
            );
        };

        // The signed file is changed while the signature is being checked.
        ui.invoke_open_decrypt_verify();
        choose_dv_input(&ui, &state, signature.clone(), kind);
        choose_dv_data(&ui, &state, release.clone());
        let (read, outcome) = run_decrypt_verify(&state, "", None);
        assert!(outcome.is_ok(), "the release does verify: {outcome:?}");
        choose_dv_data(&ui, &state, other.clone());
        show_decrypt_verify(&ui, &state, read, outcome);
        not_shown(&ui, "a new signed file");

        // With nothing changed in between, the result is shown — and for the
        // file now chosen it is the opposite of the one just withheld.
        let (read, outcome) = run_decrypt_verify(&state, "", None);
        show_decrypt_verify(&ui, &state, read, outcome);
        assert_eq!(ui.get_dv_result(), "Signature is NOT valid");
        assert_eq!(ui.get_dv_tone(), 3);

        // The signature is changed instead.
        ui.invoke_open_decrypt_verify();
        choose_dv_input(&ui, &state, signature.clone(), kind);
        choose_dv_data(&ui, &state, release.clone());
        let (read, outcome) = run_decrypt_verify(&state, "", None);
        choose_dv_input(&ui, &state, other.clone(), ops::classify_file(&other));
        show_decrypt_verify(&ui, &state, read, outcome);
        not_shown(&ui, "a new signature");

        // The dialog is closed and opened again.
        choose_dv_input(&ui, &state, signature.clone(), kind);
        choose_dv_data(&ui, &state, release.clone());
        let (read, outcome) = run_decrypt_verify(&state, "", None);
        ui.invoke_open_decrypt_verify();
        show_decrypt_verify(&ui, &state, read, outcome);
        not_shown(&ui, "a reopened dialog");
    }

    /// While an operation is in flight no handler starts another, however it
    /// is reached, the running operation's own button included.
    ///
    /// `busy` is set by hand, as the running operation's handler would have
    /// set it. Past the check, each handler writes the status line, or Lookup
    /// its dialog's line, before it hands anything to a worker, to say what it
    /// is starting or why it cannot. So a line left as it was means the
    /// handler returned at the check. Each is then invoked again with `busy`
    /// clear, so that the unchanged line is known to mean something. Add user
    /// ID stands in for the lifecycle modes, which share one handler.
    ///
    /// Nothing is set up for that second pass, so nothing it starts reaches
    /// the store or the network. Add user ID and Delete have no target and
    /// start no worker at all. The rest, key generation apart, start workers
    /// that fail at once, for want of a file, a key, a target or a query. Key
    /// generation does make a key, but only its completion would store it,
    /// and that never gets so far: this thread has no event loop to run it,
    /// and on another test's loop it returns at once, since this window
    /// cannot be upgraded on a thread other than its own.
    #[test]
    fn nothing_starts_while_an_operation_is_in_flight() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);

        let empty = SharedString::new;
        let starts: [(&str, &dyn Fn()); 9] = [
            ("Create key pair", &|| {
                ui.invoke_generate_key("Alice".into(), "alice@example.org".into(), empty(), 0, 0, 0)
            }),
            ("Sign", &|| {
                ui.invoke_se_run(false, true, 0, empty(), empty())
            }),
            ("Decrypt / Verify", &|| ui.invoke_dv_run(empty())),
            ("Certify", &|| {
                ui.invoke_certify_run(0, false, false, 0, empty())
            }),
            ("Look up", &|| ui.invoke_lookup_run(empty())),
            ("Add user ID", &|| {
                ui.invoke_lifecycle_run(1, "0".into(), "Jo <jo@example.org>".into(), empty(), 0)
            }),
            ("the notepad's Sign", &|| {
                ui.invoke_np_run(0, "a note".into(), 0, empty(), empty())
            }),
            ("Delete", &|| ui.invoke_delete_run()),
            ("Revoke", &|| ui.invoke_revoke_run(0, empty(), empty())),
        ];
        // What an import in flight has on the line, which none of these says.
        let running = "Importing…";
        let reset = |busy: bool| {
            ui.set_busy(busy);
            ui.set_status(running.into());
            ui.set_lookup_status(empty());
        };

        for (what, start) in &starts {
            reset(true);
            start();
            assert_eq!(
                ui.get_status(),
                running,
                "{what} started while another operation was in flight"
            );
            assert_eq!(
                ui.get_lookup_status(),
                "",
                "{what} started while another operation was in flight"
            );
        }

        for (what, start) in &starts {
            reset(false);
            start();
            assert!(
                ui.get_status() != running || ui.get_lookup_status() != "",
                "{what} did nothing with nothing in flight either, so the check above proves nothing"
            );
        }
    }

    /// A file the Import dialog comes back with while another operation is
    /// in flight is not imported, and the status line says so.
    ///
    /// The dialog is not modal, so a key generation, say, can be started
    /// behind it. Import used to start its worker anyway, and whichever
    /// finished first cleared `busy` with the other still running.
    #[test]
    fn a_file_chosen_for_import_while_an_operation_is_in_flight_is_not_imported() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let bob = generated("Bob <bob@example.org>").cert;
        let fingerprint = bob.fingerprint().to_hex();
        let file = dir.path().join("bob.asc");
        let elsewhere = Store::open(
            dir.path().join("elsewhere"),
            dir.path().join("elsewhere-secrets"),
        )
        .unwrap();
        elsewhere.insert(&bob).unwrap();
        elsewhere
            .export_file(std::slice::from_ref(&fingerprint), &file)
            .unwrap();

        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        let store = lock(&state).store.clone();

        ui.set_busy(true);
        ui.set_status("Generating key…".into());
        import_chosen_file(&ui, &state, file.clone());
        let status = ui.get_status();
        assert!(
            status.starts_with("Nothing was imported"),
            "the user should be told the import did not happen: {status}"
        );
        assert!(
            ui.get_busy(),
            "the running operation still holds the window"
        );
        assert!(store.lookup(&fingerprint).is_err(), "and nothing went in");

        // With nothing in flight the same file goes in, so the refusal above
        // is the only thing that kept it out.
        ui.set_busy(false);
        import_chosen_file(&ui, &state, file);
        assert_eq!(ui.get_status(), "Importing…");
        wait_for("the import", || store.lookup(&fingerprint).is_ok());
    }

    /// A file dialog that answers while a run is in flight changes nothing the
    /// run is using, and the run's verdict lands beside the files it read.
    ///
    /// On Linux and Windows a file dialog left open does not stop the window
    /// behind it, so Run can be pressed while a picker is still up. The run is
    /// made here directly, since without an event loop its result would never
    /// land, and `busy` is set as the Verify handler sets it.
    #[test]
    fn a_file_chosen_while_a_run_is_in_flight_is_not_taken() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let alice = generated("Alice <alice@example.org>").cert;
        store.insert_secret(&alice).unwrap();

        let (release, other) = (dir.path().join("a.tar"), dir.path().join("b.tar"));
        std::fs::write(&release, b"the release").unwrap();
        std::fs::write(&other, b"something else entirely").unwrap();
        let signature = dir.path().join("a.tar.sig");
        ops::sign_detached_file(&alice, None, &release, &signature, Existing::Refuse).unwrap();
        let kind = ops::classify_file(&signature);

        let state = state_for(store);
        let ui = window_for(&state);
        let shown = |path: &Path| SharedString::from(path.display().to_string());

        ui.invoke_open_decrypt_verify();
        choose_dv_input(&ui, &state, signature.clone(), kind);
        choose_dv_data(&ui, &state, release.clone());
        ui.set_busy(true);
        let (read, outcome) = run_decrypt_verify(&state, "", None);

        choose_dv_data(&ui, &state, other.clone());
        assert_eq!(
            ui.get_dv_data(),
            shown(&release),
            "the signed file changed under a running verify"
        );
        choose_dv_input(&ui, &state, other.clone(), ops::classify_file(&other));
        assert_eq!(
            ui.get_dv_input(),
            shown(&signature),
            "the signature changed under a running verify"
        );

        ui.set_busy(false);
        show_decrypt_verify(&ui, &state, read, outcome);
        assert_eq!(
            ui.get_dv_result(),
            "Signature verified",
            "the verdict belongs beside the files it read, which are still the ones shown"
        );

        // Sign / Encrypt's picker is refused the same way.
        choose_se_input(&ui, &state, release.clone());
        ui.set_busy(true);
        choose_se_input(&ui, &state, other);
        assert_eq!(
            ui.get_se_input(),
            shown(&release),
            "the file to sign changed under a running operation"
        );
        assert_eq!(lock(&state).se_input.as_deref(), Some(release.as_path()));
    }

    /// A recipient toggled while a run is in flight is not taken, and the run
    /// encrypts to the recipients ticked when Run was pressed.
    ///
    /// Inside a Flatpak, Sign / Encrypt reads its recipients only once the
    /// save dialog has answered, and that dialog has no parent window, so the
    /// list behind it stays live for as long as it is open. `busy` is set here
    /// as `ask_where_to_save` sets it, and the worker is handed the path the
    /// dialog would return. The rows refuse in Slint as well, which
    /// tests/accessibility.rs checks; this is the handler they call.
    #[test]
    fn a_recipient_toggled_while_a_run_is_in_flight_is_not_taken() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        // Alice's secret is in the store and Bob's is not, so the message
        // opens here only if it was encrypted to Alice.
        store
            .insert_secret(&generated("Alice <alice@example.org>").cert)
            .unwrap();
        store
            .insert(&generated("Bob <bob@example.org>").cert)
            .unwrap();
        let input = dir.path().join("notes.txt");
        std::fs::write(&input, b"for Alice alone").unwrap();

        let state = state_for(store);
        let ui = window_for(&state);
        ui.invoke_open_sign_encrypt();
        choose_se_input(&ui, &state, input);
        // With no filter typed, a row's index is the recipient's position.
        let row = |label: &str| {
            let guard = lock(&state);
            let position = guard.se_recipients.iter().position(|r| r.label == label);
            position.expect("both can receive encrypted mail") as i32
        };
        let ticked = || {
            let guard = lock(&state);
            let mut labels: Vec<String> = guard
                .se_recipients
                .iter()
                .filter(|r| r.selected)
                .map(|r| r.label.clone())
                .collect();
            labels.sort();
            labels
        };
        // Alice alone, as the user leaves the list before pressing Run.
        for label in ["Alice", "Bob"] {
            if ticked().contains(&label.to_string()) != (label == "Alice") {
                ui.invoke_se_toggle_recipient(row(label));
            }
        }
        assert_eq!(ticked(), ["Alice"]);

        ui.set_busy(true);
        ui.invoke_se_toggle_recipient(row("Alice"));
        ui.invoke_se_toggle_recipient(row("Bob"));
        assert_eq!(
            ticked(),
            ["Alice"],
            "the recipients changed under a run in flight"
        );
        assert_eq!(ui.get_se_selected_count(), 1);

        let saved = dir.path().join("saved.asc");
        let wrote = run_sign_encrypt(&state, true, false, 0, "", "", Some(saved.clone()))
            .expect("the file encrypts");
        assert_eq!(wrote, saved);
        let store = lock(&state).store.clone();
        let opened = dir.path().join("opened.txt");
        ops::decrypt_file(&store, &saved, &[], &opened, Existing::Refuse)
            .expect("the message should open with Alice's key");
        assert_eq!(std::fs::read(&opened).unwrap(), b"for Alice alone");

        // With nothing in flight the same toggle goes through, so the refusal
        // above is the only thing that kept it out.
        ui.set_busy(false);
        ui.invoke_se_toggle_recipient(row("Bob"));
        assert_eq!(ticked(), ["Alice", "Bob"]);
    }

    /// Inside a Flatpak the Sign / Encrypt and Decrypt dialogs are told that
    /// Run will ask where to save, and are given the output as the file name
    /// the save dialog will offer. Outside, they are given the path beside the
    /// input, as they always were.
    ///
    /// Inside the sandbox the input is a document-portal path, which names
    /// nothing the user could find on the host, and "Writes" a path beside it
    /// was the promise the sandbox never kept. What the dialogs make of these
    /// properties is tested in tests/accessibility.rs, since the window here
    /// is compiled without the debug information the element tree needs.
    #[test]
    fn inside_a_flatpak_the_dialogs_are_told_that_run_will_ask_where_to_save() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        // Shaped like what the file chooser portal hands back in the sandbox.
        // Nothing is read from either, so neither needs to exist.
        let portal = dir.path().join("doc").join("1a2b3c4d");
        let (input, message) = (portal.join("notes.txt"), portal.join("reply.txt.asc"));

        for inside in [true, false] {
            lock(&state).choose_outputs = inside;
            let name = |file: &str| {
                if inside {
                    file.to_string()
                } else {
                    portal.join(file).display().to_string()
                }
            };

            ui.invoke_open_sign_encrypt();
            choose_se_input(&ui, &state, input.clone());
            assert_eq!(ui.get_choose_outputs(), inside);
            assert_eq!(ui.get_se_output_encrypt(), name("notes.txt.asc"));
            assert_eq!(ui.get_se_output_sign(), name("notes.txt.sig"));
            ui.set_signenc_open(false);

            // Set afresh by the Decrypt / Verify dialog, which can be the
            // first one opened.
            ui.set_choose_outputs(!inside);
            ui.invoke_open_decrypt_verify();
            choose_dv_input(&ui, &state, message.clone(), InputKind::Message);
            assert_eq!(ui.get_choose_outputs(), inside);
            assert_eq!(ui.get_dv_output(), name("reply.txt"));
            ui.set_verify_open(false);
        }
    }

    /// Neither details-pane toggle writes the store while an operation is in
    /// flight.
    ///
    /// Both checkboxes are disabled while `busy` is set, which is not enough
    /// on its own, for the reasons [`refuse_while_busy`] gives. A delete in
    /// flight writes the trust-root list too.
    #[test]
    fn the_details_toggles_write_nothing_while_an_operation_is_in_flight() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let cert = generated("Old <old@example.org>").cert;
        store.insert(&cert).unwrap();
        let fingerprint = cert.fingerprint().to_hex();

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &fingerprint);
        let store = lock(&state).store.clone();
        let is_root = || store.trust_roots().unwrap().contains(&fingerprint);
        let accepted = || store.sha1_accepted().unwrap().contains(&fingerprint);

        ui.set_busy(true);
        ui.invoke_toggle_trust_root();
        assert!(!is_root(), "a trust root was written while busy");
        ui.invoke_toggle_sha1_accepted();
        assert!(!accepted(), "SHA-1 was accepted while busy");

        // Both still work once nothing is in flight.
        ui.set_busy(false);
        ui.invoke_toggle_trust_root();
        assert!(is_root());
        ui.invoke_toggle_sha1_accepted();
        assert!(accepted());
    }

    /// A secret key restored from a backup reaches the details pane as a key
    /// that is not yet a trust root, and the pane's toggle makes it one and
    /// takes it back.
    ///
    /// The pane used to read "trust root" off the secret half, so an imported
    /// key was drawn ticked, with its box locked, while the web of trust left
    /// it out. Nothing in the window could make it a root, which is what the
    /// import's own status line tells the user to do. A key generated here is
    /// the one whose box stays locked.
    ///
    /// A root vouches for its own identity, so each row's verdict shows which
    /// keys the reload's web of trust started from, and those should be the
    /// keys the pane draws ticked.
    #[test]
    fn a_restored_secret_key_can_be_made_a_trust_root_from_the_details_pane() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let mine = generated("Me <me@example.org>").cert;
        let restored = generated("Restored <restored@example.org>").cert;
        store.insert_secret(&mine).unwrap();
        // Stored the way Import stores a secret key that arrives in a file.
        store.insert_imported_secret(&restored).unwrap();
        let (mine, restored) = (mine.fingerprint().to_hex(), restored.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);
        let store = lock(&state).store.clone();
        let is_root = |fingerprint: &str| {
            store
                .effective_roots()
                .unwrap()
                .contains(&fingerprint.to_uppercase())
        };

        click_row(&ui, &state, &mine);
        let detail = ui.get_detail();
        assert!(
            detail.implicit_root,
            "a key generated here is a root whatever the list says"
        );
        assert!(is_root(&mine));
        assert_eq!(
            detail.authentication, "verified",
            "the reload's web of trust left out a key generated here"
        );

        click_row(&ui, &state, &restored);
        let detail = ui.get_detail();
        assert!(detail.has_secret);
        assert!(
            !detail.implicit_root && !detail.is_trust_root,
            "the pane drew an imported key as a trust root the web of trust does not use"
        );
        assert!(!is_root(&restored));
        assert_eq!(detail.authentication, "unverified");

        ui.invoke_toggle_trust_root();
        assert!(is_root(&restored), "ticking Trust root should make it one");

        // The pane as the reload that toggle started would leave it: ticked
        // by the list, and so still free to be unticked.
        lock(&state).all = read_store(&store).expect("a healthy store reads").all;
        apply_filter(&ui, &state);
        click_row(&ui, &state, &restored);
        let detail = ui.get_detail();
        assert!(detail.is_trust_root && !detail.implicit_root);
        assert_eq!(
            detail.authentication, "verified",
            "the reload's web of trust left out a key the pane draws ticked"
        );

        ui.invoke_toggle_trust_root();
        assert!(!is_root(&restored), "unticking should take it back");
    }

    /// Run the event loop until `done`, or give up after a minute.
    fn run_until(done: impl Fn() -> bool + 'static) {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            Duration::from_millis(5),
            move || {
                if done() || std::time::Instant::now() > deadline {
                    let _ = slint::quit_event_loop();
                }
            },
        );
        slint::run_event_loop().expect("the testing backend runs an event loop");
    }

    /// A reload that lands after the user has moved leaves them where they
    /// moved to, even when it was asked for with a row of its own to select,
    /// and the confirmation it brings names the certificate it was about.
    ///
    /// Accepting SHA-1 asks for a reload that puts the selection back on that
    /// certificate, and nothing stops the user clicking another row before it
    /// lands. Put back regardless, it took the details pane off the row they
    /// had moved to, and off whatever a dialog opened since then was naming.
    /// Left where they are, they read the confirmation beside another
    /// certificate, which is why it has to name the one it was about.
    ///
    /// The one test here that runs an event loop, because a reload's result
    /// only lands through one. The testing backend gives an event loop to a
    /// single thread per process, and a second test setting one up would
    /// panic, so the others drive the two halves of an operation directly.
    ///
    /// It is also the one GUI test that can talk to gpg-agent. A reload that
    /// lands starts the agent survey on a thread of its own, which asks
    /// whichever agent `GNUPGHOME` names for the keys it holds and may start
    /// one if none is running; whether it gets that far before the test
    /// process exits varies from run to run. That is the same `KEYINFO
    /// --list` rpgp-core's `lists_whatever_the_local_agent_holds` sends, and
    /// as with that test, GnuPG 2.4.9's agent starts scdaemon to answer it.
    /// Run with `GNUPGHOME` unset, it is the developer's own agent that
    /// answers.
    #[test]
    fn a_reload_leaves_the_selection_where_the_user_moved_it() {
        i_slint_backend_testing::init_integration_test_with_system_time();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let alice = generated("Alice <alice@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert(&alice).unwrap();
        store.insert(&bob).unwrap();
        let (alice, bob) = (alice.fingerprint().to_hex(), bob.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &alice);
        ui.invoke_toggle_sha1_accepted();
        // The event loop has not run, so the reload cannot have landed yet.
        click_row(&ui, &state, &bob);

        // Its list is the first to show SHA-1 accepted for Alice.
        let landed = {
            let (state, alice) = (state.clone(), alice.clone());
            move || {
                lock(&state)
                    .all
                    .iter()
                    .any(|c| c.fingerprint == alice && c.sha1_accepted)
            }
        };
        run_until(landed.clone());
        assert!(landed(), "the reload never landed");

        assert!(ui.get_has_selection());
        assert_eq!(
            ui.get_detail().fingerprint,
            bob,
            "the reload took the selection back from the row the user moved to"
        );
        let row = usize::try_from(ui.get_current_row()).expect("a row is highlighted");
        assert_eq!(
            lock(&state).shown_at(row).map(|c| c.fingerprint.clone()),
            Some(bob),
            "the highlighted row should be the one the pane shows"
        );
        let status = ui.get_status();
        assert!(
            status.starts_with("SHA-1 accepted for Alice <alice@example.org>."),
            "the confirmation, shown beside Bob, should say it was about Alice: {status}"
        );
    }
}
