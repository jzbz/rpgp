//! The rPGP interface, as a library so its pure parts can be measured.
//!
//! Everything here used to live in `main.rs`. A binary crate has no library
//! target, so nothing inside it can be reached from a benchmark — and the row
//! building and list ordering that a keystroke pays for are exactly what wants
//! measuring. `main.rs` is now a wrapper around [`run_app`]; this module is
//! unchanged otherwise.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rpgp_core::cert::format_time;
use rpgp_core::certify::{self, Certification, CertifyRequest, Standing};
use rpgp_core::keygen::{self, KeyGenRequest, KeyType};
use rpgp_core::lifecycle;
use rpgp_core::ops::{self, Existing, InputKind, VerifyResult};
use rpgp_core::revoke::{self, Reason, RevokeRequest};
use rpgp_core::{CertSummary, Needle, Sha1Policy, Store, wot};
use slint::{ModelRc, SharedString, VecModel};
use zeroize::Zeroizing;

mod clipboard;
mod display;
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
///
/// The name and address are the certificate's own, as the filter matches
/// them; [`push_sign_encrypt`] makes them safe to show.
struct Recipient {
    fingerprint: String,
    /// The name, or the whole user ID where it has none.
    label: String,
    /// The address, or nothing.
    sublabel: String,
    key_id: String,
    initials: String,
    tint: i32,
    selected: bool,
}

/// One of the user's own keys, offered in a Sign as or Certify with list.
///
/// The key ID goes with it because a person's old and new key, or the Modern
/// and Compatible pair the key generator offers, commonly carry the same user
/// ID, and the lists showed that alone: two identical entries, with nothing to
/// say which would sign.
#[derive(Debug, Clone)]
struct OwnKey {
    fingerprint: String,
    /// The primary user ID as the certificate has it, with "(smartcard)"
    /// in front of it where a card will be asked: in front, because the key
    /// ID beside it can leave too little room for the whole user ID, and the
    /// end is what is elided. [`display::text`] is applied where it is shown.
    label: String,
    key_id: String,
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
    /// The confirmation the newest reload is to show when it lands, from
    /// [`AfterReload::status`].
    ///
    /// Held here rather than by the reload that carried it, because that
    /// reload can be overtaken. A mutation asks for its reload once its worker
    /// is done, when nothing is busy any more, so Refresh, or Trust root ticked
    /// on another row, can ask for another while the first read is in flight.
    /// The overtaken reload rightly shows nothing of what it read, and its
    /// confirmation used to go with it: "Key revoked. Publish or send the
    /// certificate so others stop using it." gave way to the newer read's
    /// count before anyone saw it. A newer confirmation replaces one still
    /// waiting, as it would have replaced it on the status line had the older
    /// read landed first.
    pending_status: Option<String>,
    /// Bumped every time the user picks a row, so a reload can tell whether
    /// they have moved since it was asked for. One that carries a row of its
    /// own to select only gets to select it if they have not.
    selection_generation: u64,
    /// Which reading of certifications the details pane is waiting for.
    /// Bumped whenever a row is selected, by the user or by a reload putting
    /// it back, and checked when the worker reading them comes back, so that
    /// a slower read for a row the user has since left, or one made before a
    /// change to the same certificate, is never shown; see
    /// [`ask_for_certifications`].
    certifications_generation: u64,
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
    /// Every certificate that can sign and has a secret key in the store, or
    /// in gpg-agent.
    se_signers: Vec<OwnKey>,

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
    /// Our own keys that can certify, from the store or through gpg-agent
    /// (see [`can_certify_with`]), the target excepted.
    certify_certifiers: Vec<OwnKey>,

    /// Certificates found on the network, not yet in the store.
    lookup_results: Vec<rpgp_core::keyserver::Found>,

    /// Fingerprint the revoke dialog is about, and whether it is withdrawing a
    /// certification rather than revoking the key itself.
    revoke_target: Option<String>,
    revoke_certification: bool,
    /// Whether that key was revoked already when the dialog opened, which
    /// leaves a hard revocation the only one that adds anything.
    revoke_upgrade: bool,
    /// A revocation certificate that Import read for one of the user's own
    /// keys: what its dialog lists, and what its Revoke button stores.
    import_revocations: Option<revoke::RevocationFile>,

    /// (fingerprint, warned): the certificate the delete dialog is about, and
    /// whether it warned that a secret key goes with it.
    delete_target: Option<(String, bool)>,
    /// Fingerprint of the certificate the lifecycle dialog is about.
    lifecycle_fingerprint: Option<String>,
    /// The user ID or subkey a revoke mode of that dialog is about, exactly
    /// as the certificate has it. The dialog shows it through
    /// [`display::text`], so what is revoked is taken from here rather than
    /// read back from the dialog.
    lifecycle_target: String,
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

/// Matches the basename of `desktop/app.rpgp.rPGP.desktop`, which is how a
/// Wayland compositor finds the icon for this window.
const APP_ID: &str = "app.rpgp.rPGP";

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
///
/// The second field is where the operation says that it failed, and a panic
/// is said there as well: in the dialog that started it, through
/// [`report_in_dialog`] or the line of its own that Decrypt / Verify, the
/// notepad and Lookup keep, or on the status line alone for an import, which
/// no dialog starts. Saying it in whichever dialog happened to be open would
/// put an import's panic into a dialog opened while Import's file dialog was
/// still up, as the answer to an operation that dialog never started.
struct BusyGuard(slint::Weak<AppWindow>, fn(&AppWindow, String));

impl Drop for BusyGuard {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let (ui_weak, report) = (self.0.clone(), self.1);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                after_a_panic(&ui, report);
            }
        });
    }
}

/// The event-loop half of [`BusyGuard`]. Split out so that a test can reach
/// it: without an event loop the testing backend drops what another thread
/// sends, and it gives an event loop to one test per process.
fn after_a_panic(ui: &AppWindow, report: fn(&AppWindow, String)) {
    ui.set_busy(false);
    report(
        ui,
        "That operation failed unexpectedly. Nothing was changed.".to_string(),
    );
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
        pending_status: None,
        selection_generation: 0,
        certifications_generation: 0,
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
        revoke_upgrade: false,
        import_revocations: None,
        delete_target: None,
        lifecycle_fingerprint: None,
        lifecycle_target: String::new(),
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
            refilter(&ui, &state, |state| state.filter = text.to_string());
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
            refilter(&ui, &state, |state| state.sort = Sort::from_index(index));
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
            refilter(&ui, &state, |state| state.scope = Scope::from_index(index));
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
            let asked = ask_for_certifications(&ui, &mut guard, &summary, false);
            drop(guard);
            read_certifications_for(&ui, &state, asked);
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
        // No dialog starts an import, so its failures, a panic among them, go
        // to the status line alone.
        let _busy = BusyGuard(ui_weak.clone(), |ui, message| ui.set_status(message.into()));
        let outcome = run_import(&state, &path);

        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            finish_import(&ui, &state, outcome);
        });
    });
}

/// The event-loop half of Import: show what [`run_import`] came back with.
///
/// Split out of the closure that carries it there, so that a test can reach
/// the step that turns a revocation certificate for the user's own key into a
/// question rather than a revoked key.
fn finish_import(ui: &AppWindow, state: &Shared, outcome: rpgp_core::Result<Imported>) {
    ui.set_busy(false);
    // One refresh at the end rather than progressive updates: the list stays
    // as it was until the import is complete, which is what it did when this
    // ran inline. A failure refreshes it too, since an import that stops
    // partway has stored what came before it. A revocation certificate
    // waiting on the user has stored nothing, so there is nothing to refresh
    // until they answer.
    match outcome {
        Ok(Imported::Done(after)) => reload_after(ui, state, after),
        Ok(Imported::Confirm(file)) => ask_to_store_revocations(ui, state, file),
        Err(e) => report_and_reload(ui, state, format!("Import failed: {e}")),
    }
}

/// What the blocking half of Import comes back with.
#[derive(Debug)]
enum Imported {
    /// Done, with what the list and the status line should then show.
    Done(AfterReload),
    /// A revocation certificate for one of the user's own keys, read and
    /// checked, of which nothing is stored until they say so.
    Confirm(revoke::RevocationFile),
}

/// The worker's half of Import: what it needs from the state, and then
/// [`import_into`].
fn run_import(state: &Shared, path: &Path) -> rpgp_core::Result<Imported> {
    // Cloned out under a brief lock, exactly as the comment on State::store
    // describes. Importing a GnuPG pubring parses and writes thousands of
    // certificates, and holding the mutex across all of it blocked every
    // other worker for the duration. Nothing below touches the State the
    // lock protects — `all` is rebuilt by the reload in the completion
    // closure.
    let (store, held_by_agent) = {
        let guard = lock(state);
        (guard.store.clone(), guard.held_by_agent())
    };
    import_into(&store, path, &held_by_agent)
}

/// The blocking half of Import: store what is in the file, and say what
/// arrived. A revocation certificate for one of the user's own keys is read
/// and not stored, and comes back to be put to them.
///
/// `held_by_agent` names the certificates whose secret key gpg-agent holds,
/// as [`State::held_by_agent`] gives them, since the store knows only of the
/// secret keys it holds itself.
fn import_into(
    store: &Store,
    path: &Path,
    held_by_agent: &std::collections::HashSet<String>,
) -> rpgp_core::Result<Imported> {
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
            let mut message = if secrets == 0 {
                format!("Imported {} certificate(s)", certs.len())
            } else {
                format!(
                    "Imported {} certificate(s), {secrets} with a secret key. A \
                     secret key that arrives in a file is not made a trust root; \
                     tick Trust root in its details pane if you meant to trust it.",
                    certs.len()
                )
            };
            // A designated revoker's revocation arrives with the certificate
            // it revokes, as GnuPG writes it, and is stored with it but not
            // applied. Said here, because nothing else would say it: the list
            // goes on showing the key as valid.
            if let Some(note) = revoke::designated_revocations_note(&certs) {
                append_sentence(&mut message, &note);
            }
            Ok(Imported::Done(AfterReload {
                status: Some(message),
                ..Default::default()
            }))
        }
        // The file held a certificate, or is a GnuPG Keybox, so it is no
        // revocation certificate, and what came before the point where the
        // import stopped is stored. Handed to the fallback below as well, a
        // keyring that had stored a revoked certificate before it stopped was
        // reported as that certificate revoked, and the reason the import
        // stopped went unsaid.
        Err(stopped @ rpgp_core::Error::ImportStopped { .. }) => Err(stopped),
        Err(import_error) => {
            // A file holding no revocation of a key is neither a keyring nor
            // a revocation certificate, and the import's error says what it
            // lacks.
            let Ok(mut file) = revoke::read_revocation_file(store, path) else {
                return Err(import_error);
            };
            // One that revokes nothing here is told why. That used to be the
            // import's complaint that the file held no readable certificate,
            // which is true of every revocation certificate, and was all
            // anyone heard about a revocation that did not take, a designated
            // revoker's among them.
            if file.revocations.is_empty() {
                return Err(rpgp_core::Error::invalid(format!(
                    "nothing was revoked: {}",
                    file.refused.join("; ")
                )));
            }
            // Asked first when the file revokes one of the user's own keys.
            // The app saves a revocation certificate for every key it
            // generates, as a plain public key block this button takes, and
            // one chosen by mistake, beside the key it belongs to in a backup
            // being restored, used to revoke that key there and then. Nothing
            // is written until the user says so, and what is then stored is
            // what was read here. Only a bare revocation certificate reaches
            // this question: a certificate carrying its own revocation, an
            // export of a revoked key say, was merged by `import_file` above
            // like any other.
            //
            // A key whose secret gpg-agent holds, in its own store or on a
            // card, is the user's own as well. GnuPG's --gen-revoke writes a
            // revocation certificate for one on request, to be put away until
            // it is needed, as a plain public key block that reads here just
            // as the app's own does. The agent is not asked again: the survey
            // that follows every reload has asked it already, for the keys
            // that sign, certify and decrypt, which are what the sign and
            // certify dialogs offer and decryption asks it for, and a key
            // counts as held when it holds any of them. So until that survey
            // hears from the agent, and whenever no agent answers, a key the
            // agent holds is taken for someone else's.
            for pending in &mut file.revocations {
                pending.yours |= held_by_agent.contains(&pending.fingerprint);
            }
            // Someone else's revocation is applied without asking. It is
            // theirs to make, it verifies as theirs, and the same signature
            // reaches the store unasked with their certificate, from a
            // keyserver refresh or an import of the certificate itself; a
            // question whose one sensible answer is yes would only teach the
            // user to wave through the one that matters.
            if file.revocations.iter().any(|pending| pending.yours) {
                return Ok(Imported::Confirm(file));
            }
            store_revocations(store, &file)
                .map(Imported::Done)
                .map_err(|e| rpgp_core::Error::invalid(format!("nothing was revoked: {e}")))
        }
    }
}

/// Add `sentence` to a status line as a sentence of its own.
///
/// A status line of one sentence carries no full stop, as "Imported 1
/// certificate(s)" does not, so one is put in before a second sentence
/// follows; joined by a space alone, the two would read as one.
fn append_sentence(message: &mut String, sentence: &str) {
    if !message.ends_with('.') {
        message.push('.');
    }
    message.push(' ');
    message.push_str(sentence);
}

/// Store the revocations Import read from a file, and say what became of
/// them: the list is to select the first certificate revoked. An error means
/// none was stored, and says why for each.
fn store_revocations(
    store: &Store,
    file: &revoke::RevocationFile,
) -> rpgp_core::Result<AfterReload> {
    let outcomes = revoke::apply_revocations(store, &file.revocations);
    let (mut revoked, mut behind, mut failed) = (Vec::new(), Vec::new(), Vec::new());
    for (pending, outcome) in file.revocations.iter().zip(outcomes) {
        match outcome {
            Ok(_) => revoked.push(pending),
            // Stored, in the half the list and every export read, so saying
            // that the revocation failed, as this used to, would be false.
            Err(rpgp_core::Error::SecretKeyNotUpdated(e)) => {
                revoked.push(pending);
                behind.push(format!(
                    "the secret key file of {} could not be updated to match ({e})",
                    pending.name
                ));
            }
            Err(e) => failed.push(format!("{}: {e}", pending.name)),
        }
    }

    let Some(first) = revoked.first() else {
        return Err(rpgp_core::Error::invalid(failed.join("; ")));
    };
    let mut message = match revoked.as_slice() {
        [one] => format!("Revoked {}: {}", one.name, one.describe()),
        many => format!(
            "Revoked {} certificates: {}",
            many.len(),
            many.iter()
                .map(|pending| pending.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    // Most pressing first. The status line holds a few lines and elides what
    // goes past them, and a file revoking many keys can run longer than that.
    if !behind.is_empty() {
        message.push_str(&format!(", but {}", behind.join("; ")));
    }
    if !failed.is_empty() {
        message.push_str(&format!(". Not revoked: {}", failed.join("; ")));
    }
    if !file.refused.is_empty() {
        message.push_str(&format!(
            ". Also in the file, and not applied: {}",
            file.refused.join("; ")
        ));
    }
    if revoked.iter().any(|pending| pending.yours) {
        message.push_str(". Publish or send the certificate so others stop using it.");
    }
    Ok(AfterReload {
        select: Some(first.fingerprint.clone()),
        status: Some(message),
    })
}

/// Put a revocation certificate Import read for one of the user's own keys in
/// front of them, before any of it is stored.
///
/// The file is kept as it was read: the dialog lists it, and its Revoke button
/// stores exactly that, the way Delete acts on what its dialog named. Written
/// afresh each time the dialog opens, which only Import does, and dropped once
/// its revocations are stored, so it never answers for an earlier file.
///
/// Not asked while another dialog is open, when nothing is stored and the user
/// is told to import the file again.
fn ask_to_store_revocations(ui: &AppWindow, state: &Shared, file: revoke::RevocationFile) {
    let rows: Vec<PendingRevocationRow> = file
        .revocations
        .iter()
        .map(|pending| PendingRevocationRow {
            name: display::text(&pending.name).into(),
            reason: pending.reason.label().into(),
            note: display::text(&pending.message).into(),
            hard: pending.reason.is_hard(),
            yours: pending.yours,
        })
        .collect();
    let yours = rows.iter().filter(|row| row.yours).count();
    let keys = if yours > 1 { "keys" } else { "key" };
    // Import's file dialog is not modal, so another dialog can have been
    // opened while it was up, and still be open when it answers. The window
    // keeps Tab and assistive technology inside an open dialog by disabling
    // what is behind it, and a dialog this one opened over would not be: its
    // controls, Delete key and Create key pair among them, could be reached
    // from this one, and Decrypt / Verify, which is drawn above this one,
    // would hide it while it held focus. So it is not asked over another
    // dialog. Nothing has been stored, and the user is told to import the
    // file again, as when another operation was running.
    if ui.get_dialog_open() {
        ui.set_status(
            format!(
                "Nothing was revoked: the file is a revocation certificate for your own \
                 {keys}, and another dialog is open. Close it and import the file again."
            )
            .into(),
        );
        return;
    }
    lock(state).import_revocations = Some(file);
    ui.set_import_revocations(ModelRc::new(VecModel::from(rows)));
    ui.set_import_revocation_yours(yours as i32);
    ui.set_import_revocation_open(true);
    ui.set_status(
        format!(
            "Nothing is revoked yet: the file is a revocation certificate for your own {keys}."
        )
        .into(),
    );
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
            // Refused here, before anything starts and with the dialog left
            // open, as well as by keygen::generate. The dialog cannot do it:
            // Slint has no trim, so a field of spaces looks filled in there,
            // and this used to format two of them into the user ID "<>".
            let user_id = match keygen::user_id(&name, &email) {
                Ok(user_id) => user_id,
                Err(e) => {
                    report_in_dialog(&ui, format!("Key generation failed: {e}"));
                    return;
                }
            };

            let request = KeyGenRequest {
                user_ids: vec![user_id],
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
                let _busy = BusyGuard(ui_weak.clone(), report_in_dialog);
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
        // What went wrong ahead of the fingerprint, which is the part a
        // reader needs least.
        Ok((fingerprint, keygen::Saved::WithoutRevocation(e))) => format!(
            "Key created, but its revocation certificate could not be saved ({e}): {fingerprint}"
        ),
        Err(e) => {
            report_in_dialog(ui, format!("Key generation failed: {e}"));
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
            // toolkit's memory — but ours can be. So every callback that takes
            // a passphrase or a message password wraps its copy the moment it
            // leaves Slint's string, and it stays wrapped, or borrowed from the
            // wrapped copy, until Sequoia seals it in a Password of its own.
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
                        let _busy = BusyGuard(ui_weak.clone(), report_in_dialog);
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
                                Err(message) => report_in_dialog(&ui, message),
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
        let fingerprint = &signers
            .get(signer_index.max(0) as usize)
            .ok_or_else(|| "Choose a key to sign with".to_string())?
            .fingerprint;
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
///
/// Matched as the main list's search is, so a fingerprint typed in groups
/// finds its recipient here too; see [`Needle`].
fn visible_recipients(state: &State) -> Vec<usize> {
    let needle = Needle::new(&state.se_filter);
    state
        .se_recipients
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            needle.is_empty()
                || needle.in_text(&r.label)
                || needle.in_text(&r.sublabel)
                || needle.in_hex(&r.fingerprint)
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
            label: display::text(&r.label).into(),
            sublabel: display::text(&r.sublabel).into(),
            key_id: r.key_id.clone().into(),
            initials: r.initials.clone().into(),
            tint_index: r.tint,
            selected: r.selected,
        })
        .collect();
    let (signers, signer_key_ids) = own_key_models(&state.se_signers);

    // Counted over every recipient, not the shown ones: a selection hidden by
    // the filter is still encrypted to, and a count that dropped when you
    // typed would say the opposite.
    ui.set_se_selected_count(state.se_recipients.iter().filter(|r| r.selected).count() as i32);
    ui.set_se_recipients(ModelRc::new(VecModel::from(rows)));
    ui.set_se_signers(signers);
    ui.set_se_signer_key_ids(signer_key_ids);

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
            clear_dv_verdict(&ui);
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

            // Wiped when the worker is done with it, as in Sign / Encrypt. It
            // can be a key's passphrase or a message's password, and it waits
            // here as well while a save dialog is open.
            let password = Zeroizing::new(password.to_string());
            let start = {
                let state = state.clone();
                move |ui: &AppWindow, chosen: Option<PathBuf>| {
                    ui.set_busy(true);
                    ui.set_status("Working…".into());
                    let ui_weak = ui.as_weak();
                    std::thread::spawn(move || {
                        let _busy = BusyGuard(ui_weak.clone(), report_in_decrypt_verify);
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
    clear_dv_verdict(ui);
    push_decrypt_verify(ui, &guard);
}

/// Take a newly chosen signed file, as the data picker does once the file
/// dialog answers.
fn choose_dv_data(ui: &AppWindow, state: &Shared, path: PathBuf) {
    // Refused while busy, and a new generation and no verdict otherwise, for
    // the reasons given for the input. The verdict used to stay: after a good
    // verify, choosing another signed file left "Signature verified" and its
    // pills beside a file nothing had checked, with nothing on screen to say
    // which file they were about.
    if refuse_while_busy(ui) {
        return;
    }
    let mut guard = lock(state);
    guard.dv_data = Some(path);
    guard.dv_generation += 1;
    clear_dv_verdict(ui);
    push_decrypt_verify(ui, &guard);
}

/// Take the last run's verdict out of the Decrypt / Verify dialog: the banner,
/// its tone and the signature rows, all of which are about the files that run
/// read. One function for the opener and both pickers, which used to clear
/// different parts of it each, and the signed-file picker none.
fn clear_dv_verdict(ui: &AppWindow) {
    ui.set_dv_result(SharedString::new());
    ui.set_dv_tone(0);
    ui.set_dv_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
}

/// The event-loop half of Decrypt / Verify: show what a run found.
///
/// In the dialog only if the files it read are still the ones chosen. They
/// should be. A picker opened before Run can come back during it, because on
/// Linux and Windows the file dialog has no parent window and the main window
/// stays live behind it, but [`choose_dv_input`] and [`choose_dv_data`] refuse
/// what it brings while the run is in flight. This check does not depend on
/// those refusals, nor on the dialog staying open until the run is done, as
/// Close, Escape and the scrim now leave it; its opener does not ask whether
/// a run is in flight. Painted beside the new files, a verdict about the old
/// ones reads as "Signature verified" next to a file nothing checked. It
/// still goes on the status line, because a decrypt has already written its
/// output by the time it gets here and hiding that would hide a plaintext
/// file. There it says first that it is not about the files now chosen,
/// which is the part not to miss, and then names the files it is about.
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
        ui.set_status(display::text(&format!("Not for the files now chosen. {message}")).into());
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
        Err(message) => report_in_decrypt_verify(ui, message),
    }
}

/// Say why a Decrypt / Verify run failed, in the dialog's result line, which
/// is announced, and on the status line, which is not while a dialog covers
/// it.
///
/// A worker's panic comes here too, through [`BusyGuard`], rather than
/// leaving the line with the verdict of the run before. The files cannot have
/// changed since the run began, as the pickers refuse what they bring while
/// it is in flight, so the check in [`show_decrypt_verify`] is not needed.
fn report_in_decrypt_verify(ui: &AppWindow, message: String) {
    let message = display::text(&message);
    ui.set_dv_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
    ui.set_dv_result(message.as_str().into());
    ui.set_dv_tone(3);
    ui.set_status(message.into());
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

            // The keys the Certify button was offered for, less the one being
            // certified, which core refuses as a certificate vouching for
            // itself: a key the agent alone holds is the user's own, and yet
            // has no secret key file to disable the button on its row, as one
            // in the store has. "(smartcard)" goes by the key certifying uses,
            // the primary, and only where the agent is what signs with it: a
            // usable one in the store is taken first.
            let certifiers: Vec<OwnKey> = guard
                .all
                .iter()
                .filter(|c| can_certify_with(c) && c.fingerprint != target.fingerprint)
                .map(|c| {
                    let on_card = !c.primary_secret
                        && c.agent
                            .certify
                            .as_ref()
                            .is_some_and(rpgp_core::agent::AgentKey::is_on_card);
                    let label = if on_card {
                        format!("(smartcard) {}", c.primary_user_id)
                    } else {
                        c.primary_user_id.clone()
                    };
                    OwnKey {
                        fingerprint: c.fingerprint.clone(),
                        label,
                        key_id: c.key_id.clone(),
                    }
                })
                .collect();

            guard.certify_target = Some(target.fingerprint.clone());
            guard.certify_user_ids = user_ids;
            guard.certify_certifiers = certifiers;

            ui.set_certify_target(display::text(&target.primary_user_id).into());
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
            // Wiped when the worker is done with it, as in Sign / Encrypt.
            let password = Zeroizing::new(password.to_string());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone(), report_in_dialog);
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
                        Err(message) => report_in_dialog(&ui, message),
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
        let certifier = guard
            .certify_certifiers
            .get(certifier_index.max(0) as usize)
            .map(|key| key.fingerprint.clone())
            .ok_or_else(|| "Choose a key to certify with".to_string())?;
        let user_ids: Vec<String> = guard
            .certify_user_ids
            .iter()
            .filter(|(_, selected)| *selected)
            .map(|(uid, _)| uid.clone())
            .collect();
        (guard.store.clone(), target, certifier, user_ids)
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

/// Show the Certify dialog's user IDs and keys.
///
/// The user IDs are shown with [`display::text`] and toggled by position, and
/// what is certified is the text kept in `state`, so a user ID with a hidden
/// character in it is both told apart from its neighbours and certified as the
/// certificate has it.
fn push_certify(ui: &AppWindow, state: &State) {
    let rows: Vec<UserIdRow> = state
        .certify_user_ids
        .iter()
        .map(|(text, selected)| UserIdRow {
            text: display::text(text).into(),
            selected: *selected,
        })
        .collect();
    let (certifiers, key_ids) = own_key_models(&state.certify_certifiers);

    ui.set_certify_chosen(state.certify_user_ids.iter().filter(|(_, s)| *s).count() as i32);
    ui.set_certify_user_ids(ModelRc::new(VecModel::from(rows)));
    ui.set_certify_certifiers(certifiers);
    ui.set_certify_certifier_key_ids(key_ids);
}

/// A Sign as or Certify with list as its Select takes it: the labels, and the
/// key IDs drawn beside them, which are what tell two keys with the same user
/// ID apart.
fn own_key_models(keys: &[OwnKey]) -> (ModelRc<SharedString>, ModelRc<SharedString>) {
    let labels: Vec<SharedString> = keys
        .iter()
        .map(|key| display::text(&key.label).into())
        .collect();
    let key_ids: Vec<SharedString> = keys.iter().map(|key| key.key_id.as_str().into()).collect();
    (
        ModelRc::new(VecModel::from(labels)),
        ModelRc::new(VecModel::from(key_ids)),
    )
}

/// A reading of one certificate's certifications, as the details pane asked
/// for it.
struct AskedCertifications {
    store: Arc<Store>,
    fingerprint: String,
    /// Whether the certificate has more than one user ID, so that each row
    /// names the one it certifies.
    show_user_id: bool,
    /// [`State::certifications_generation`] as this reading set it.
    generation: u64,
}

/// Start showing `summary`'s certifications in the details pane, until
/// [`land_certifications`] puts them there: empty it and say they are being
/// read, or, `again`, keep what it shows of the same certificate.
///
/// They are read by a worker, through [`read_certifications_for`], and not
/// here on the event loop. Reading them looks up every certifier the store
/// holds and verifies every certification against it, and it used to happen
/// here, with the state lock held, on every click on a row and after every
/// reload that put one back. A key certified by three hundred others in the
/// store, each certified forty to 150 times itself, held the window for 25
/// to 49ms a click, and 41 to 61ms the first time, before it could repaint.
/// With its certificates borrowed through [`Store::lookup_ref`] rather than
/// copied, the same reading now takes 11 to 12ms, on the worker.
///
/// On a move to another row the pane is emptied rather than left showing the
/// last reading, which was of the row before; and Withdraw with it, so that it
/// cannot be offered for a certification that is not there. When a reload
/// puts back the row the pane already shows, what it shows is kept until the
/// new reading lands, since emptying it there too would take the Withdraw
/// button away on every reload, from under the keyboard focus if it was
/// there, and make everything below the rows jump, for every key and not
/// only a much-certified one. What is kept can be the reading from before
/// whatever changed the store, for as long as the new one takes. Withdraw
/// pressed in that time reaches [`run_revoke`], which reads the
/// certifications again and refuses when none of ours stands. Whether a
/// revocation certificate is on disk is one look at a file, and is still
/// answered here.
fn ask_for_certifications(
    ui: &AppWindow,
    state: &mut State,
    summary: &CertSummary,
    again: bool,
) -> AskedCertifications {
    state.certifications_generation += 1;
    if !again {
        ui.set_detail_certifications(ModelRc::new(VecModel::from(Vec::<CertificationRow>::new())));
        ui.set_can_withdraw(false);
        ui.set_certifications_pending(true);
    }
    ui.set_has_revocation_cert(
        summary.has_secret && state.store.has_revocation(&summary.fingerprint),
    );
    AskedCertifications {
        store: state.store.clone(),
        fingerprint: summary.fingerprint.clone(),
        show_user_id: summary.user_ids.len() > 1,
        generation: state.certifications_generation,
    }
}

/// Read the certifications [`ask_for_certifications`] asked for on a worker,
/// and land them.
fn read_certifications_for(ui: &AppWindow, state: &Shared, asked: AskedCertifications) {
    let (ui_weak, state) = (ui.as_weak(), state.clone());
    std::thread::spawn(move || {
        let certifications = read_certifications(&asked.store, &asked.fingerprint);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                land_certifications(&ui, &state, &asked, &certifications);
            }
        });
    });
}

/// The blocking half of showing a certificate's certifications: every
/// certification on it, verified and judged.
fn read_certifications(store: &Store, fingerprint: &str) -> Vec<Certification> {
    match store.lookup_ref(fingerprint) {
        Ok(cert) => certify::certifications(store, &cert).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Put the certifications a worker read in the details pane, unless another
/// reading has been asked for since.
///
/// Split from the reading so that a test can land readings in an order of its
/// choosing, as a race between two would.
fn land_certifications(
    ui: &AppWindow,
    state: &Shared,
    asked: &AskedCertifications,
    certifications: &[Certification],
) {
    if lock(state).certifications_generation != asked.generation {
        return;
    }

    // Offer to withdraw only what a withdrawal would take back, per key and per
    // user ID: what stands, or will once its date comes. That is the question
    // `certify::withdrawable` answers for `run_revoke` as well. The test here
    // used to be its own: whether a key had made any withdrawal on a user ID,
    // whatever its date, so certifying again after withdrawing left a
    // certification in force that the app offered no way to withdraw.
    let withdrawable = !certify::withdrawable(certifications).is_empty();

    let rows: Vec<CertificationRow> = certifications
        .iter()
        .map(|c| certification_row(c, asked.show_user_id))
        .collect();

    ui.set_detail_certifications(ModelRc::new(VecModel::from(rows)));
    ui.set_can_withdraw(withdrawable);
    ui.set_certifications_pending(false);
}

fn certification_row(certification: &Certification, show_user_id: bool) -> CertificationRow {
    let mut parts: Vec<String> = Vec::new();

    if show_user_id {
        parts.push(display::text(&certification.user_id));
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
    // Why a certification that verified draws no tick, so that the row gives
    // the reason the pill above it already acts on.
    let discounted = match certification.standing {
        None | Some(Standing::Stands) => None,
        Some(Standing::Superseded) => Some("since replaced by a newer one"),
        Some(Standing::Withdrawn) => Some("since withdrawn"),
        Some(Standing::NotYet) => Some("dated in the future, so it does not count yet"),
        Some(Standing::Expired) => Some("expired"),
        Some(Standing::CertifierRevoked) => Some("certifier's key revoked"),
        Some(Standing::NotByPrimaryKey) => Some("made by a subkey, so it does not count"),
        Some(Standing::WeakHash) => Some("made with a hash no longer accepted, such as SHA-1"),
        Some(Standing::TargetNotValid) => Some(
            "key unusable when certified, or since revoked as compromised or refused by the policy",
        ),
        Some(Standing::Rejected) => Some("does not count"),
    };
    parts.extend(discounted.map(str::to_string));

    CertificationRow {
        certifier: display::text(&certification.certifier).into(),
        user_id: display::text(&certification.user_id).into(),
        detail: parts.join(" · ").into(),
        good: certification.is_good(),
        by_me: certification.by_me,
        is_revocation: certification.is_revocation,
    }
}

/// Re-select the row for `fingerprint` after the list has been rebuilt.
fn reselect(ui: &AppWindow, state: &Shared, fingerprint: &str) {
    let mut guard = lock(state);
    let Some(index) = guard.shown_position(fingerprint) else {
        return;
    };

    let Some(summary) = guard.shown_at(index).cloned() else {
        return;
    };
    // Whether the pane already shows this certificate, and so has its
    // certifications to keep while they are read again. By fingerprint, since
    // apply_filter, which comes first, has cleared has_selection but left the
    // pane as it was.
    let again = ui.get_detail().fingerprint == fingerprint;
    ui.set_current_row(index as i32);
    ui.set_detail(to_row(&summary));
    ui.set_has_selection(true);
    // Read again, although the row is the same one: a reload puts it back
    // because the store changed, often by a certification of it made or
    // withdrawn.
    let asked = ask_for_certifications(ui, &mut guard, &summary, again);
    drop(guard);
    read_certifications_for(ui, state, asked);
}

// --------------------------------------------------------------------- lookup

/// Say why a search failed, in Lookup's own line, which is announced, in
/// place of the results.
///
/// Not on the status line, which a search has never used. A worker's panic
/// comes here too, through [`BusyGuard`], rather than leaving "Searching…"
/// there for good.
fn report_in_lookup(ui: &AppWindow, message: String) {
    ui.set_lookup_results(ModelRc::new(VecModel::from(Vec::<LookupRow>::new())));
    ui.set_lookup_status(display::text(&message).into());
}

/// The row Lookup shows for a certificate a search found, its primary user ID
/// through [`display::text`]: whoever published the certificate wrote it.
///
/// Split from the search, which goes to the network, so that a test can see
/// the row without one.
fn lookup_row(store: &Store, found: &rpgp_core::keyserver::Found) -> LookupRow {
    let summary = rpgp_core::CertSummary::from_cert(&found.cert);
    let (name, email) = split_user_id(&summary.primary_user_id);
    LookupRow {
        primary_user_id: display::text(&summary.primary_user_id).into(),
        fingerprint_pretty: summary.fingerprint_pretty().into(),
        source: found.source.as_str().into(),
        initials: initials(&name, &email, &summary.key_id).into(),
        tint_index: tint_index(&summary.fingerprint),
        already_known: store.lookup_ref(&summary.fingerprint).is_ok(),
    }
}

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
                let _busy = BusyGuard(ui_weak.clone(), report_in_lookup);
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
                            let rows: Vec<LookupRow> =
                                found.iter().map(|f| lookup_row(&guard.store, f)).collect();
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
                        Err(e) => report_in_lookup(&ui, format!("Lookup failed: {e}")),
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
                    Some(found) => guard.store.insert(&found.cert).map(|()| {
                        display::text(
                            &rpgp_core::CertSummary::from_cert(&found.cert).primary_user_id,
                        )
                    }),
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
    // long as this dialog is open the two belong together. They could
    // disagree when it opened: the Details dialog's lists, which the user ID
    // or subkey was picked from, were filled when that dialog opened, and an
    // assistive-technology activation of a list row could move the pane
    // behind its scrim in between. The window now disables every control
    // behind an open dialog, the list's rows among them, and a disabled row
    // refuses that activation, which closes it.
    //
    // The run used to read the pane again when its button was pressed, and a
    // reload landing behind the scrim put the selection back wherever it had
    // been asked to. An expiry or a new user ID could then go to another of
    // the user's keys, and Publish could upload a certificate the dialog was
    // never opened for, which cannot be taken back. Reloads now defer to a row
    // the user has picked, and nothing behind a dialog takes input, but what
    // the dialog acts on must not depend on nothing else moving the pane: a
    // reload can still be asked to select a row read from a highlight that
    // has drifted away from the pane. The name the dialog shows comes from
    // the same read, rather than being bound to the pane, for the same
    // reason.
    //
    // The user ID a revoke mode is about is kept here as well, as it came:
    // the dialog shows it with its hidden characters written out, which is
    // not the text the certificate carries, so the run cannot take it back
    // from the dialog.
    let open = |ui: &AppWindow, state: &Shared, mode: i32, target: SharedString| {
        let detail = ui.get_detail();
        if detail.fingerprint.is_empty() {
            return;
        }
        {
            let mut guard = lock(state);
            guard.lifecycle_fingerprint = Some(detail.fingerprint.to_string());
            guard.lifecycle_target = target.to_string();
        }
        ui.set_lifecycle_key_name(detail.primary_user_id);
        ui.set_lifecycle_key_id(detail.key_id);
        ui.set_lifecycle_mode(mode);
        ui.set_lifecycle_target(display::text(&target).into());
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
            let (fingerprint, target) = {
                let guard = lock(&state);
                (
                    guard.lifecycle_fingerprint.clone(),
                    guard.lifecycle_target.clone(),
                )
            };
            let Some(fingerprint) = fingerprint else {
                report_in_dialog(&ui, "No certificate selected".to_string());
                return;
            };
            ui.set_busy(true);
            ui.set_status("Working…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            let input = LifecycleInput {
                mode,
                fingerprint,
                target,
                expiry: expiry.to_string(),
                value: value.to_string(),
                password: Zeroizing::new(password.to_string()),
                reason,
            };
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone(), report_in_dialog);
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
                        Err(message) => report_in_dialog_and_reload(&ui, &state, message),
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
    /// The key's passphrase, wiped when the worker drops this, as in Sign /
    /// Encrypt. The lifecycle functions only borrow it, so this is the one
    /// copy rPGP makes.
    password: Zeroizing<String>,
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
            let Ok(cert) = guard.store.lookup_ref(&fingerprint) else {
                return;
            };

            let user_ids: Vec<UserIdDetailRow> = rpgp_core::cert::user_ids(&cert)
                .iter()
                .map(|u| UserIdDetailRow {
                    text: display::text(&u.text).into(),
                    user_id: u.text.clone().into(),
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
            clear_notepad(&ui);
            ui.set_notepad_open(true);
        }
    });

    // Every way of closing the notepad comes here: Close, Escape and a click
    // on the scrim. What it showed lives in the window's properties rather
    // than the dialog's, so closing the dialog alone left the last decrypted
    // message referenced from the window, in full, for as long as rPGP ran or
    // until the notepad was opened again.
    ui.on_close_notepad({
        let ui_weak = ui.as_weak();
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            clear_notepad(&ui);
            ui.set_notepad_open(false);
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
            // case the clipboard refuses, which is otherwise invisible. A
            // fingerprint or a user ID is public, so it goes out unmarked, as
            // any other copy would.
            match clipboard::copy(text.to_string(), clipboard::Content::Public) {
                Ok(_) => ui.set_status("Copied to the clipboard".into()),
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
            // Marked private whatever it holds: see clipboard::Content.
            let text = ui.get_np_output().to_string();
            match clipboard::copy(text, clipboard::Content::Private) {
                Ok(copied) => {
                    ui.set_np_copied(true);
                    ui.set_status(
                        match copied {
                            clipboard::Copied::AsAsked => "Copied to the clipboard",
                            // Said, because nothing else would tell the user
                            // that a decrypted message may now be kept in a
                            // clipboard manager's history.
                            clipboard::Copied::Unmarked => {
                                "Copied to the clipboard, where clipboard history may keep it: \
                                 it cannot be marked private here"
                            }
                        }
                        .into(),
                    );
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
                let _busy = BusyGuard(ui_weak.clone(), report_in_notepad);
                let outcome = run_notepad(&state, action, &text, signer_index, &password, &secret);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    finish_notepad(&ui, &state, outcome);
                });
            });
        }
    });
}

/// Empty what the notepad shows, which lives in the window's properties, not
/// the dialog's, and so outlives the dialog unless it is emptied.
fn clear_notepad(ui: &AppWindow) {
    show_np_output(ui, String::new());
    ui.set_np_result(SharedString::new());
    ui.set_np_tone(0);
    ui.set_np_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
    ui.set_np_copied(false);
}

/// What a notepad run gives back: the output text, a summary line, a tone for
/// the banner, and any signatures found; or the line saying why it failed.
type NpOutcome = Result<(String, String, i32, Vec<rpgp_core::ops::SignatureReport>), String>;

/// Show what became of a notepad run, on the event loop.
///
/// Escape and a click on the scrim used to close the notepad while a run was
/// still in flight, a decrypt waiting at a card's PIN prompt, say. Now they
/// wait for it, as Close does, but should a result land with the notepad
/// closed all the same, it is not put back into the window, where closing has
/// emptied it, and nothing would show it; the status line still says how it
/// went.
fn finish_notepad(ui: &AppWindow, state: &Shared, outcome: NpOutcome) {
    ui.set_busy(false);
    if !ui.get_notepad_open() {
        let line = match outcome {
            Ok((_, summary, ..)) => summary,
            Err(message) => message,
        };
        ui.set_status(display::text(&line).into());
        return;
    }
    match outcome {
        Ok((output, summary, tone, signatures)) => {
            let rows = signature_rows(&lock(state).all, &signatures);
            ui.set_np_signatures(ModelRc::new(VecModel::from(rows)));
            show_np_output(ui, output);
            ui.set_np_result(summary.clone().into());
            ui.set_np_tone(tone);
            ui.set_status(summary.into());
        }
        Err(message) => report_in_notepad(ui, message),
    }
}

/// How much of a notepad run's output its output box is given to lay out at
/// a scale factor of one: no more than this many bytes, and no more than
/// [`NP_SHOWN_LINES`] lines. [`np_shown`] divides both by the window's scale
/// factor.
///
/// The box is a word-wrapping text input, and Slint lays the whole of what it
/// holds out on the event loop, every paragraph and every line break, when it
/// is set and again on every repaint of the dialog. A decrypted message can
/// be up to [`ops::MAX_IN_MEMORY_PLAINTEXT`], 64 MiB, and a few hundred bytes
/// of compressed message can expand to that. Measured in review, laying out
/// 64 MiB took 7 to 12 seconds and 3.6 to 4.5 GiB each time, and on the
/// software renderer 64 KiB already took 29ms for its first frame, over one
/// frame's time.
///
/// That renderer, which a machine without a usable GPU falls back to, also
/// panics drawing text that reaches 32,767 physical pixels down the box,
/// since it places each glyph in 16-bit coordinates. Rows of this box's 13px
/// monospace are 16.4 pixels apart at a scale factor of one, so that is
/// about 2,000 rows there, and at two it is half that: in a nested sway
/// scaled to two, the thousand short lines this cut allowed when it ignored
/// the scale took the app down. Rows stay that far apart whatever font a
/// character in them falls back to, since Slint pins every run's line height
/// to the metrics of the font asked for (`ranged_builder` in i-slint-core
/// 1.17's textlayout/sharedparley.rs). But how many rows a text wraps into
/// depends on how wide its characters are, which the cut cannot see, so the
/// limits are set for the widest text found.
///
/// Where the box wraps, the row it ends and the word it moves down are
/// together wider than the box, so at worst every row holds one word just
/// over half its width of about 92 columns. In this monospace that is 48
/// bytes, a word of 47 letters and a space, but a character another font
/// draws can be far wider for its bytes. U+FDFD, three bytes, is 127 pixels
/// wide in Noto Sans Arabic, which the app fell back to for it on the Linux
/// machine this was measured on, so three of them and a space fill a row in
/// ten bytes, and 32 KiB of them, which this cut once allowed, took the app
/// down at a scale factor of one. Of the 394 font files there, only Noto
/// Naskh Arabic drew it wider, at 159 pixels, still three to a row, and no
/// other character came to more than 16 pixels a byte, against 42 for U+FDFD
/// and 8 for this monospace. At 8 KiB and 500 lines that comes to at most
/// about 1,270 rows, 499 empty lines and then U+FDFD, and 660 for text in
/// this monospace however it is crafted; ordinary text takes fewer.
///
/// Divided by the scale factor, that leaves the widest text found about 1.5
/// times under the limit at any scale, and text in this monospace about 3
/// times; a debug build, which also counts the box's place in the window,
/// has a little less. The margin is for what the cut cannot see. The scale
/// is read when the output is set, so a window then moved, with the output
/// open, to a screen scaled more than 1.5 times as much, from 100% to 175%
/// say, could reach the limit with a crafted text. At the scale it was set
/// at, a text would have to fill rows in five bytes or fewer to reach it,
/// which takes a character wider than any found: 180 pixels in two bytes,
/// or 360 in three or four.
///
/// Two limits, because either alone lets the other through: 8 KiB of short
/// lines is more lines than that renderer can draw, and 500 long lines are
/// far more than 8 KiB. A line ends wherever the box has to start a new
/// row, which is not only at a line feed: Slint splits the text into
/// paragraphs at line feeds alone, and parley, laying each one out, breaks
/// the row at every character Unicode makes a mandatory break, as
/// [`is_hard_break`] lists them. 32,000 bytes of `x` and a carriage return,
/// or of `x` and U+2028, was 16,000 or 8,000 rows with not one line feed, and
/// each took the app down in review at a scale factor of one.
const NP_SHOWN_BYTES: usize = 8 * 1024;
/// See [`NP_SHOWN_BYTES`].
const NP_SHOWN_LINES: usize = 500;

/// Put a notepad run's output in the window: all of it where Copy reads it,
/// and as much of it as [`NP_SHOWN_BYTES`] allows in the output box, with a
/// note under the box when that is not all.
///
/// Copy still copies the whole, since cutting what it copies would put a
/// part of a message on the clipboard as though it were all of it, and the
/// note says so. Cutting what is shown instead of refusing a long output
/// keeps an ordinary long message readable where it fits and copyable where
/// it does not.
fn show_np_output(ui: &AppWindow, output: String) {
    let shown = np_shown(&output, ui.window().scale_factor());
    ui.set_np_output_note(
        if shown.len() < output.len() {
            "Only the start is shown: the rest is too long for this box. Copy copies all of it."
        } else {
            ""
        }
        .into(),
    );
    ui.set_np_output_shown(shown.into());
    ui.set_np_output(output.into());
}

/// The start of `output` that the notepad's output box shows in a window at
/// `scale`, cut at a character boundary; see [`NP_SHOWN_BYTES`].
fn np_shown(output: &str, scale: f32) -> &str {
    // Never more than at a scale of one, and a NaN scale is taken as one too,
    // since `max` returns its other operand.
    let scale = scale.max(1.0);
    let bytes = (NP_SHOWN_BYTES as f32 / scale) as usize;
    let lines = ((NP_SHOWN_LINES as f32 / scale) as usize).max(1);
    let head = &output[..output.floor_char_boundary(bytes)];
    // A break that ends the output adds only an empty row after it, so an
    // output of exactly `lines` lines, ending in one, is shown whole rather
    // than cut at that break with a note that leaves nothing out.
    let counted = if head.len() == output.len() {
        head.strip_suffix("\r\n")
            .or_else(|| head.strip_suffix(is_hard_break))
            .unwrap_or(head)
    } else {
        head
    };
    let mut breaks = counted
        .char_indices()
        .filter(|&(at, c)| is_hard_break(c) && !(c == '\n' && counted[..at].ends_with('\r')))
        .map(|(at, _)| at);
    match breaks.nth(lines - 1) {
        Some(at) => &head[..at],
        None => head,
    }
}

/// Whether the notepad's output box starts a new row at `c`, whatever its
/// width: the characters Unicode's line breaking makes a mandatory break.
/// These seven are every character parley_data 0.10's table marks as one,
/// which is what parley, under Slint 1.17, breaks a row at; worth checking
/// again when either is upgraded. A carriage return before a line feed makes
/// one break with it, not two, since Slint drops it from the end of the
/// paragraph the line feed closes; [`np_shown`] counts the pair once.
fn is_hard_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// Say why a notepad run failed, in the notepad's result line, which is
/// announced, and on the status line; or on the status line alone once the
/// notepad has closed, for the reason [`finish_notepad`] gives. A worker's
/// panic comes here too, through [`BusyGuard`].
fn report_in_notepad(ui: &AppWindow, message: String) {
    let message = display::text(&message);
    if ui.get_notepad_open() {
        // Clear the previous run's verdict and output, as a failed Decrypt /
        // Verify run does. Both last for as long as the dialog is open, so a
        // failed run left the last message's "good signature (verified) —
        // Alice" row and her plaintext on screen under a red banner
        // describing a different message.
        ui.set_np_signatures(ModelRc::new(VecModel::from(Vec::<SignatureRow>::new())));
        show_np_output(ui, String::new());
        ui.set_np_result(message.as_str().into());
        ui.set_np_tone(3);
    }
    ui.set_status(message.into());
}

/// The blocking half of the notepad.
fn run_notepad(
    state: &Shared,
    action: i32,
    text: &str,
    signer_index: i32,
    password: &str,
    secret: &str,
) -> NpOutcome {
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
        let fingerprint = &signers
            .get(signer_index.max(0) as usize)
            .ok_or_else(|| "Choose a key to sign with".to_string())?
            .fingerprint;
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
                sublabel: email,
                key_id: c.key_id.clone(),
                fingerprint: c.fingerprint.clone(),
            }
        })
        .collect();

    // A card key has no local secret: the agent holds it. Label those so it is
    // obvious which choice will ask for a PIN.
    let signers: Vec<OwnKey> = state
        .all
        .iter()
        .filter(|c| c.can_sign && (c.has_secret || c.agent.sign.is_some()))
        .map(|c| OwnKey {
            fingerprint: c.fingerprint.clone(),
            label: match c.card_serial() {
                Some(_) => format!("(smartcard) {}", c.primary_user_id),
                None => c.primary_user_id.clone(),
            },
            key_id: c.key_id.clone(),
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
                // another. Reloads now defer to a row the user has picked, and
                // the controls behind an open dialog take no input, but the
                // delete must not depend on nothing else moving the pane: a
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
                report_in_dialog(&ui, "No certificate selected".to_string());
                return;
            };
            ui.set_busy(true);
            ui.set_status("Deleting…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone(), report_in_dialog);
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
                        Err(message) => report_in_dialog_and_reload(&ui, &state, message),
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
    // one is not something this can know. What to do comes first, and it names
    // the buttons it is shown beside, in the dialog a failed delete leaves
    // open: dismissing that is what makes reopening re-read the store and put
    // the warning back. The state is read here rather than before the call so that
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
            // The passphrase is wiped when the worker is done with it, as in
            // Sign / Encrypt. Withdrawing a certification only borrows it, so
            // there this is the one copy rPGP makes. The message is public: it
            // goes into the revocation for anyone to read.
            let (message, password) = (message.to_string(), Zeroizing::new(password.to_string()));
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone(), report_in_dialog);
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
                        Err(message) => report_in_dialog_and_reload(&ui, &state, message),
                    }
                });
            });
        }
    });

    ui.on_import_revocation_run({
        let (ui_weak, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui_weak.upgrade() else {
                return;
            };
            if refuse_while_busy(&ui) {
                return;
            }
            // What the dialog listed, as Import read it, and not the file read
            // again, which may have changed since.
            let (store, file) = {
                let guard = lock(&state);
                (guard.store.clone(), guard.import_revocations.clone())
            };
            let Some(file) = file else {
                report_in_dialog(
                    &ui,
                    "No revocation certificate is waiting to be applied".to_string(),
                );
                return;
            };
            ui.set_busy(true);
            ui.set_status("Revoking…".into());

            let (ui_weak, state) = (ui_weak.clone(), state.clone());
            std::thread::spawn(move || {
                let _busy = BusyGuard(ui_weak.clone(), report_in_dialog);
                let outcome = store_revocations(&store, &file);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui_weak.upgrade() else {
                        return;
                    };
                    ui.set_busy(false);
                    match outcome {
                        Ok(after) => {
                            lock(&state).import_revocations = None;
                            ui.set_import_revocation_open(false);
                            reload_after(&ui, &state, after);
                        }
                        // Nothing was stored; the dialog stays open to try
                        // again or to cancel.
                        Err(e) => report_in_dialog_and_reload(
                            &ui,
                            &state,
                            format!("Revocation failed: {e}"),
                        ),
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

    // Recorded with the target and from the same read: a key revoked when the
    // dialog opened is offered the hard reasons alone, and the run is held to
    // that.
    let upgrade = !certification && target.revocation.is_some();
    guard.revoke_target = Some(target.fingerprint.clone());
    guard.revoke_certification = certification;
    guard.revoke_upgrade = upgrade;
    drop(guard);

    ui.set_revoke_target(display::text(&target.primary_user_id).into());
    ui.set_revoke_is_certification(certification);
    ui.set_revoke_upgrade(upgrade);
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
    let (store, target, is_certification, upgrade) = {
        let guard = lock(state);
        (
            guard.store.clone(),
            guard.revoke_target.clone(),
            guard.revoke_certification,
            guard.revoke_upgrade,
        )
    };
    let target = target.ok_or_else(|| "No certificate selected".to_string())?;
    let reason = Reason::from_index(reason);
    let password = Some(password).filter(|p| !p.is_empty());

    if is_certification {
        // Withdrawing our own endorsement: the certifier is whichever of our
        // keys actually made a certification on this certificate.
        let cert = store
            .lookup_ref(&target)
            .map_err(|e| format!("Certificate unavailable: {e}"))?;
        let certifications = certify::certifications(&store, &cert).unwrap_or_default();

        // Grouped by which of our keys made each certification, because a
        // revocation only retracts a certification made by the same key. This
        // used to sign every withdrawal with whichever key happened to sort
        // first, so when two of our keys had certified the same person one
        // endorsement quietly survived while the status line said it had been
        // withdrawn. Only what still stands is taken, the same answer the button
        // that opened this was given: a key whose certification had already
        // been withdrawn used to be asked to sign again, first if it sorted
        // first, so a passphrase that opened only the key with something
        // standing stopped on the other and never reached it.
        let by_certifier = certify::withdrawable(&certifications);
        if by_certifier.is_empty() {
            return Err("You have no certification of this key in force".to_string());
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

    // A key revoked already is offered the hard reasons alone, since only a
    // hard revocation adds anything to it. The reason arrives as a bare index
    // into Reason::ALL, where a dialog that mislaid its offset would send a
    // retirement, so a soft one is refused here rather than signed.
    if upgrade && !reason.is_hard() {
        return Err(
            "This key is revoked already; only marking it compromised adds anything.".to_string(),
        );
    }

    let mut request = RevokeRequest::new(&target);
    request.reason = reason;
    request.message = message.to_string();
    request.password = password.map(|p| Zeroizing::new(p.to_owned()));

    let done = if upgrade {
        "Key marked as compromised"
    } else {
        "Key revoked"
    };
    let publish = "Publish or send the certificate so others stop using it.";
    match revoke::revoke_cert(&store, &request) {
        Ok(_) => Ok((target, format!("{done}. {publish}"))),
        // Revoked in the half the list, exports and Publish read, which is
        // what the user acts on next; reported as a failure it read as a key
        // still unrevoked.
        Err(rpgp_core::Error::SecretKeyNotUpdated(e)) => Ok((
            target,
            format!(
                "{done}, but its secret key file could not be updated to match ({e}). {publish}"
            ),
        )),
        Err(e) => Err(format!("Revocation failed: {e}")),
    }
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
#[derive(Debug, Default)]
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
    /// was before. Shown when the newest reload lands, which is this one
    /// unless another is asked for before it does; see
    /// [`State::pending_status`].
    status: Option<String>,
}

/// A reload as it was asked for: what its landing holds against how things
/// stand by the time the read comes back.
struct AskedReload {
    store: Arc<Store>,
    /// [`State::reload_generation`] as this reload set it.
    generation: u64,
    /// [`State::selection_generation`] when it was asked for.
    selection: u64,
    /// [`AfterReload::select`].
    select: Option<String>,
}

/// Everything a reload reads, with nothing in it that touches the window.
struct Loaded {
    all: Vec<CertSummary>,
    /// Bookkeeping files that would not read. Named rather than counted, so
    /// the status line can say which badge may be missing.
    degraded: Vec<&'static str>,
    /// The certificates `all` was made from, for [`survey_agent_and_secrets`]
    /// to hold what the agent has against.
    certs: Vec<rpgp_core::store::CertRef>,
}

/// Re-read the store from disk and rebuild the list.
///
/// Everything here is local — cert-d, the trust graph, the secret-key
/// directory — and all of it now happens on a worker, because it does not fit
/// in a frame. Measured by `benches/reload.rs`, the read was 18ms at a
/// thousand certificates and 127ms at five thousand, against a 16ms budget,
/// when it moved; it is about 16ms and 100ms now that the web of trust is not
/// asked about certificates no path can reach, which cut its share of the
/// second figure from about 60ms to 24ms. It ran on the event loop because
/// the list had to exist before the call returned, several callers following it
/// straight away with `reselect` — [`AfterReload`] carries that intent across
/// the gap instead.
///
/// Which certificates have a secret half is answered from the filenames in the
/// secrets directory, via [`Store::secret_fingerprints`]. The keys in it are
/// opened for one question only, whether each holds its primary key's secret
/// or a stub ([`Store::primary_secret_fingerprints`]), which the Certify button
/// needs; `read_store` says why there. The parts that leave the machine, and
/// the damaged-file survey that re-parses every secret key again, are handed
/// to [`survey_agent_and_secrets`].
fn reload(ui: &AppWindow, state: &Shared) {
    reload_after(ui, state, AfterReload::default());
}

/// [`reload`], with something to do when it lands.
fn reload_after(ui: &AppWindow, state: &Shared, after: AfterReload) {
    let asked = ask_for_reload(ui, state, after);
    let (ui_weak, state) = (ui.as_weak(), state.clone());
    std::thread::spawn(move || {
        let loaded = read_store(&asked.store);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                land_reload(&ui, &state, asked, loaded);
            }
        });
    });
}

/// What [`reload_after`] does on the event loop before its read starts: make
/// this the newest reload, and leave its confirmation for the newest reload to
/// show when it lands.
///
/// Split from the read and the landing so that a test can ask for reloads and
/// land them in an order of its choosing, as a race between two reads would.
fn ask_for_reload(ui: &AppWindow, state: &Shared, after: AfterReload) -> AskedReload {
    let (asked, first) = {
        let mut guard = lock(state);
        guard.reload_generation += 1;
        if let Some(status) = after.status {
            guard.pending_status = Some(status);
        }
        (
            AskedReload {
                store: guard.store.clone(),
                generation: guard.reload_generation,
                selection: guard.selection_generation,
                select: after.select,
            },
            guard.all.is_empty(),
        )
    };

    // Only when there is nothing on screen yet, which in practice means
    // startup. A refresh of a list already showing keeps showing them, and
    // replacing the count with this for one frame would just be a flicker.
    if first {
        ui.set_status("Reading the certificate store…".into());
    }
    asked
}

/// What [`reload_after`] does on the event loop once its read is back: put
/// what [`read_store`] came back with on screen, unless a newer reload has
/// been asked for since, and start the survey that follows.
fn land_reload(
    ui: &AppWindow,
    state: &Shared,
    asked: AskedReload,
    loaded: std::result::Result<Loaded, String>,
) {
    // A read that a newer one has already overtaken says nothing at all — not
    // even its error, which would otherwise sit on the status line describing
    // a store the newer read is about to succeed at. Without this the list
    // could also go backwards: delete then import, and if the delete's read
    // finishes second it puts the deleted certificate back on screen until
    // something forces another reload.
    //
    // Its confirmation is not lost with it: that waits in pending_status for
    // the newest reload, which takes it here. Taken whether or not the read
    // worked, since a failed one puts its own error on the line instead, and a
    // confirmation left waiting would turn up on some later reload, long after
    // what it confirms.
    let status = {
        let mut guard = lock(state);
        if guard.reload_generation != asked.generation {
            return;
        }
        guard.pending_status.take()
    };

    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(e) => {
            ui.set_status(format!("Cannot read the certificate store: {e}").into());
            return;
        }
    };
    lock(state).all = loaded.all;

    // Read before apply_filter, which clears it. The caller's row is honoured
    // only while the user is where they were when the reload was asked for.
    // Put back regardless, it took the details pane off a row the user had
    // moved to in the meantime — and off the certificate a dialog they had
    // opened since then was naming, behind that dialog's back.
    let moved = lock(state).selection_generation != asked.selection;
    let select = asked.select.filter(|_| !moved).or_else(|| {
        ui.get_has_selection()
            .then(|| ui.get_detail().fingerprint.to_string())
    });

    apply_filter(ui, state);
    if let Some(fingerprint) = &select {
        reselect(ui, state, fingerprint);
    }

    // After apply_filter, never before: that sets the status line itself, so
    // a message written earlier would be overwritten by the ordinary count and
    // the reader would never see it.
    if let Some(status) = landed_status(status, loaded.degraded) {
        ui.set_status(status.into());
    }

    survey_agent_and_secrets(ui, state, asked.store, loaded.certs, asked.generation);
}

/// What the status line says once a reload has landed, in place of the count
/// `apply_filter` put there: the caller's confirmation, through
/// [`display::text`], since one can quote a user ID or a revocation's note;
/// or else which parts of the store could not be read; or nothing.
///
/// The caller's own confirmation wins over the degraded notice, which is the
/// order these two arrived in when the caller set its status on the line after
/// `reload`. Kept apart from [`land_reload`], which needs a window and a read
/// of the store, so that a test can read the line with neither.
fn landed_status(status: Option<String>, mut degraded: Vec<&'static str>) -> Option<String> {
    if let Some(status) = status {
        return Some(display::text(&status));
    }
    if degraded.is_empty() {
        return None;
    }
    // Two reads can land under one name: the SHA-1 list is read twice, and the
    // trust roots come from two files. So dedupe rather than name one part of
    // the store twice.
    degraded.sort_unstable();
    degraded.dedup();
    Some(format!(
        "Loaded, but could not read: {}. Badges for those may be missing.",
        degraded.join(", ")
    ))
}

/// Report a failure of the operation the open dialog started, in that dialog
/// as well as on the status line.
///
/// A dialog stays open when its operation fails, so that what was wrong can be
/// put right and the button pressed again, and the reason used to go to the
/// status line alone: under the dialog's scrim, where it could hardly be read,
/// and never announced. The dialog now shows it and announces it; see
/// `DialogError` in widgets.slint. The window takes it out of the dialog again
/// when a dialog opens or closes and when an operation starts, so it never
/// answers for an earlier attempt. A worker's panic is reported here as well;
/// see [`BusyGuard`]. Decrypt / Verify, the notepad and Lookup do not come
/// here: each says how its run went, failures and panics included, in a line
/// of its own; see [`report_in_decrypt_verify`], [`report_in_notepad`] and
/// [`report_in_lookup`].
///
/// The message is shown through [`display::text`], as each of those lines and
/// the status line after a reload are: a failure can quote a user ID, as
/// rpgp-core's refusals of a revoked key or of a user ID it cannot find do,
/// and a status line can quote a revocation's note. The app's own words have
/// nothing in them to write out.
fn report_in_dialog(ui: &AppWindow, message: String) {
    let message = display::text(&message);
    ui.set_dialog_error(message.as_str().into());
    ui.set_status(message.into());
}

/// [`report_in_dialog`], for an operation whose failure also reloads the
/// store; see [`report_and_reload`].
fn report_in_dialog_and_reload(ui: &AppWindow, state: &Shared, message: String) {
    ui.set_dialog_error(display::text(&message).into());
    report_and_reload(ui, state, message);
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
    let message = display::text(&message);
    ui.set_status(message.as_str().into());
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
    // Which of those hold the primary key's secret, rather than the GnuPG stub
    // left for a primary kept offline or on a card. Certifying signs with the
    // primary alone, so the Certify button turns on this and not on the
    // listing. It is the one read here that opens the secret key files, a
    // parse of each, where the listing opens none; a user holds few, and this
    // is the reload's worker. Asked here, and not by the survey that follows
    // and parses them again, so that the button is right for the store's own
    // keys when the list appears, and only the agent's can come late.
    let primary_secrets = store.primary_secret_fingerprints().unwrap_or_else(|_| {
        degraded.push("secret keys");
        Default::default()
    });
    for summary in all.iter_mut() {
        let key = summary.fingerprint.to_uppercase();
        summary.has_secret = secrets.contains(&key);
        summary.primary_secret = primary_secrets.contains(&key);
        summary.is_trust_root = explicit_roots.contains(&key);
        summary.implicit_root = implicit_roots.contains(&key);
        summary.sha1_accepted = sha1_accepted.contains(&key);
        // The verdict for the identity actually shown on the row, not the
        // best over every identity on the certificate.
        summary.authentication = wot::for_user_id(&authenticated, &key, &summary.primary_user_id);
    }

    // Ordering belongs to apply_filter, so changing the sort does not
    // require re-reading the store.
    Ok(Loaded {
        all,
        degraded,
        certs,
    })
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
///
/// The signer's user ID, and the reason a bad signature is bad, go through
/// [`display::text`]: the notepad draws the name in one line with its
/// verdict, and an override left open in the name turned the verdict round.
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
                signer: display::text(&s.signer).into(),
                detail: display::text(&s.detail).into(),
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
/// appears immediately, and the smartcard badges, and the Certify button for a
/// key only the agent holds, arrive when the agent answers, or never, with
/// nothing waiting on it. See [`land_survey`] for what arrives.
///
/// The damaged-file survey rides along because it re-parses every secret key,
/// which is the other thing in a reload that has no business on the UI thread.
///
/// `certs` are the certificates the reload this follows read, handed over
/// from it, so that what the agent holds is matched against exactly the rows
/// on screen. They used to be read here again, on the grounds that naming
/// their type would put a `sequoia_openpgp` type in this crate, which the GUI
/// keeps free of them; but `Store::certs` hands out rpgp-core's own
/// [`CertRef`](rpgp_core::store::CertRef), and the second read, 24 to 29ms
/// of a worker's time at five thousand certificates by `benches/reload.rs`,
/// was thrown away on every machine without an agent, before one was asked.
///
/// `generation` is that of the reload this follows, which [`land_survey`]
/// holds against the newest.
fn survey_agent_and_secrets(
    ui: &AppWindow,
    state: &Shared,
    store: std::sync::Arc<Store>,
    certs: Vec<rpgp_core::store::CertRef>,
    generation: u64,
) {
    let (ui_weak, state) = (ui.as_weak(), state.clone());
    std::thread::spawn(move || {
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
            if let Some(ui) = ui_weak.upgrade() {
                land_survey(&ui, &state, generation, &agent_keys, &damaged);
            }
        });
    });
}

/// Put what [`survey_agent_and_secrets`] found on screen: `agent_keys`, what
/// the agent holds of each certificate by fingerprint, and `damaged`, the
/// secret key files that would not parse, for the survey that followed the
/// reload `generation`.
///
/// Split from the survey, which asks the agent, so that a test can land what a
/// survey would find without one.
fn land_survey(
    ui: &AppWindow,
    state: &Shared,
    generation: u64,
    agent_keys: &std::collections::HashMap<String, rpgp_core::agent::AgentHolds>,
    damaged: &[String],
) {
    if !agent_keys.is_empty() {
        // Of what the survey sets, only the signing key's card serial reaches
        // a row: CertRow carries card-serial, while the rest is read straight
        // off State when the certify and sign dialogs build their key lists,
        // and when the Certify button is decided just below. So the rows only
        // need rebuilding when a card serial actually changed — otherwise
        // reload's own apply_filter already produced exactly the rows this
        // would produce again, and for anyone whose key is merely in gpg-agent
        // rather than on a card, that second pass rebuilt every row to no
        // effect.
        let mut rows_changed = false;
        let can_certify = {
            let mut guard = lock(state);
            for summary in guard.all.iter_mut() {
                if let Some(holds) = agent_keys.get(&summary.fingerprint) {
                    let before = summary.card_serial().map(str::to_owned);
                    summary.agent = holds.clone();
                    rows_changed |= summary.card_serial() != before.as_deref();
                }
            }
            guard.all.iter().any(can_certify_with)
        };
        // The Certify button, whether or not a row changed. The reload that
        // spawned this survey decided it before the agent had answered, from
        // the store's keys alone, so a key only the agent holds, in its own
        // store or on a card, opens it from here, and until here the button
        // is disabled for a user who has no other, and a dialog opened by
        // another key does not list it. A key the agent holds only subkeys
        // of does not open it at all.
        ui.set_can_certify(can_certify);

        if rows_changed {
            // Read the selection now rather than before the agent was asked:
            // the user may have moved since. apply_filter clears the
            // selection, so it has to be put back.
            let selected = ui
                .get_has_selection()
                .then(|| ui.get_detail().fingerprint.to_string());

            // And the status line with it. Every mutation sets its own
            // confirmation — "Imported 3 certificates" — and reload then
            // spawns this survey, which ends in apply_filter, which
            // overwrites the status with its generic count. from_cert leaves
            // the agent's keys unmarked on every reload, so for anyone whose
            // agent reports a card this fired every time: the confirmation
            // was replaced before it could be read.
            let status = ui.get_status();

            apply_filter(ui, state);
            if let Some(fingerprint) = selected {
                reselect(ui, state, &fingerprint);
            }
            ui.set_status(status);
        }
    }

    // A secret key file that will not parse is skipped rather than allowed to
    // hide every other key, but skipping silently would turn "my key is gone"
    // into a mystery, so the status line names it.
    //
    // Added to what the line says rather than written over it. That is most
    // often the confirmation of the operation that caused the reload, which
    // this used to replace a few milliseconds after it went up: "Key revoked.
    // Publish or send the certificate so others stop using it.", or Import's
    // word that a revoked key's secret key file, the very file that will not
    // parse, could not be updated to match. When the agent's timeouts kept the
    // survey waiting, it replaced whatever had been written there since.
    //
    // And said only by the survey of the newest reload. One whose reload has
    // been overtaken would add it to the line the newer reload leaves, whose
    // own survey adds it again, or to that reload's error; the newer survey
    // finds the damaged files as they are by then.
    if !damaged.is_empty() && lock(state).reload_generation == generation {
        let mut status = ui.get_status().to_string();
        append_sentence(
            &mut status,
            &format!(
                "{} secret key file{} could not be read and {} skipped: {}",
                damaged.len(),
                if damaged.len() == 1 { "" } else { "s" },
                if damaged.len() == 1 { "was" } else { "were" },
                damaged.join(", ")
            ),
        );
        ui.set_status(status.into());
    }
}

impl State {
    /// The summary a displayed row refers to, resolving the index in `shown`.
    fn shown_at(&self, row: usize) -> Option<&CertSummary> {
        self.all.get(*self.shown.get(row)?)
    }

    /// The row showing `fingerprint`, if one does.
    fn shown_position(&self, fingerprint: &str) -> Option<usize> {
        self.shown.iter().position(|&i| {
            self.all
                .get(i)
                .is_some_and(|c| c.fingerprint == fingerprint)
        })
    }

    /// The certificates whose secret key gpg-agent holds, in its own store or
    /// on a card, as [`survey_agent_and_secrets`] last found them: a key of
    /// theirs that signs, the primary that certifies or a key that decrypts,
    /// any one of the three. A reload reads every certificate afresh with none
    /// marked, so this is empty until the survey that follows it hears from
    /// the agent, and stays so when no agent answers.
    fn held_by_agent(&self) -> std::collections::HashSet<String> {
        self.all
            .iter()
            .filter(|c| !c.agent.is_empty())
            .map(|c| c.fingerprint.clone())
            .collect()
    }
}

/// Which certificates the list shows, in the order it shows them, for the
/// search text `filter` as it was typed.
///
/// The pure half of [`apply_filter`], split out so it can be measured: this is
/// what a keystroke pays for, and it was unreachable from a benchmark while it
/// lived inside a function that takes an `AppWindow`.
pub fn visible(all: &[CertSummary], filter: &str, scope: Scope, sort: Sort) -> Vec<usize> {
    let needle = Needle::new(filter);
    let mut shown: Vec<usize> = all
        .iter()
        .enumerate()
        .filter(|(_, c)| scope.accepts(c) && c.matches(&needle))
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
    let can_certify = guard.all.iter().any(can_certify_with);
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

/// Apply a new search, sort or scope, and keep the user on the row they
/// were on while it is still in the list.
///
/// [`apply_filter`] clears the selection, since a row index means nothing
/// against a new set of rows, and these three used to leave it cleared: a
/// letter typed into the search box, a change of Sort by or a click on a
/// scope emptied the details pane and disabled Export, even with the
/// certificate still listed. Only the index is put back. Nothing the details
/// pane shows has changed, since the store has not been read, so it is left
/// as it is rather than read again, as [`reselect`] does after a reload; for
/// the search box that would be on every keystroke. A certificate the new
/// view leaves out stays unselected, so that nothing acts on a row that is
/// not shown.
fn refilter(ui: &AppWindow, state: &Shared, change: impl FnOnce(&mut State)) {
    let selected = ui
        .get_has_selection()
        .then(|| ui.get_detail().fingerprint.to_string());
    change(&mut lock(state));
    apply_filter(ui, state);

    let Some(fingerprint) = selected else {
        return;
    };
    if let Some(index) = lock(state).shown_position(&fingerprint) {
        ui.set_current_row(index as i32);
        ui.set_has_selection(true);
    }
}

/// Whether `summary`'s certificate can certify someone else's from where its
/// keys are held: the Certify button is offered when any can, and the dialog
/// lists those that can.
///
/// [`certify::certify`] signs with the primary key alone, from the store when
/// its secret there is key material this build can use, and otherwise through
/// gpg-agent, which has to hold it, on a card or in its own store. Those are
/// `primary_secret` and what the survey found the agent holds for certifying,
/// asked the same way. A certificate whose secret key file stubs the primary,
/// or whose card holds only its subkeys, as when the primary is kept offline,
/// signs and decrypts but cannot certify, and is not offered. The button used
/// to count any secret key file and ignore the agent, and the dialog to count
/// any key the agent could sign with: a card-only user could not open the
/// dialog at all, while a card holding only subkeys was listed in it, and
/// failed at the last step for want of the primary.
fn can_certify_with(summary: &CertSummary) -> bool {
    summary.can_certify && (summary.primary_secret || summary.agent.certify.is_some())
}

/// A certificate as the list and the details pane show it.
///
/// Every user ID, and the note left with a revocation, goes through
/// [`display::text`]: all of them are written by whoever made the certificate
/// or revoked it. The user IDs are joined a line each, which is why a newline
/// inside one has to be written out, or one user ID read as two. The reason a
/// certificate was revoked is the app's own label and needs nothing.
pub fn to_row(summary: &CertSummary) -> CertRow {
    let (name, email) = split_user_id(&summary.primary_user_id);
    CertRow {
        fingerprint: summary.fingerprint.clone().into(),
        fingerprint_pretty: summary.fingerprint_pretty().into(),
        key_id: summary.key_id.clone().into(),
        primary_user_id: display::text(&summary.primary_user_id).into(),
        initials: initials(&name, &email, &summary.key_id).into(),
        tint_index: tint_index(&summary.fingerprint),
        name: display::text(&name).into(),
        email: display::text(&email).into(),
        user_ids: summary
            .user_ids
            .iter()
            .map(|user_id| display::text(user_id))
            .collect::<Vec<_>>()
            .join("\n")
            .into(),
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
        revocation_note: display::text(&summary.revocation_note).into(),
        revocation_hard: summary.revocation_hard,
        card_serial: summary
            .card_serial()
            .map(display::card_number)
            .unwrap_or_default()
            .into(),
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
///
/// A word gives the first of its characters that [`display::text`] leaves as
/// it is. Its first character, whatever it was, used to go in the circle, and
/// a word that began with an override or a control put there something that
/// drew nothing, or broke the line.
fn initials(name: &str, email: &str, key_id: &str) -> String {
    let from_name: String = name
        .split_whitespace()
        .filter_map(|word| word.chars().find(|&c| !display::hidden(c)))
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

/// The binary's entry point, here so `main.rs` stays a wrapper.
pub fn run_app() -> ExitCode {
    // First, before the renderer brings up wgpu and long before any key
    // material exists: on Linux and macOS everything after this point is
    // inside a process that will not dump core. On Windows `harden` protects
    // nothing; its documentation says what that leaves open.
    hardening::harden();
    configure_renderer();

    // After the backend is selected and before any window is created: it needs
    // a platform to talk to, and the id is read when the window is built.
    //
    // On Wayland an application cannot set its own taskbar icon at all. The
    // compositor matches this id against an installed .desktop file and takes
    // the Icon= from there, so this and desktop/app.rpgp.rPGP.desktop have to
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
    use std::collections::HashSet;

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
    ///
    /// It also points the test process away from every gpg-agent, which the
    /// operations a state drives would otherwise ask: the survey after a
    /// reload, and the decrypt, sign and certify fallbacks. rpgp-core's own
    /// tests start that way, but this crate links it without them, and an
    /// agent reached from here is the developer's, with its keys and its PIN
    /// prompts. Every test that can reach an agent builds its state here.
    fn state_for(store: Store) -> Shared {
        rpgp_core::agent::set_home(rpgp_core::agent::AgentHome::Nowhere);
        Arc::new(Mutex::new(State {
            store: Arc::new(store),
            all: Vec::new(),
            shown: Vec::new(),
            reload_generation: 0,
            pending_status: None,
            selection_generation: 0,
            certifications_generation: 0,
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
            revoke_upgrade: false,
            import_revocations: None,
            delete_target: None,
            lifecycle_fingerprint: None,
            lifecycle_target: String::new(),
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
            guard.se_signers = vec![OwnKey {
                fingerprint: fingerprint.clone(),
                label: "Alice <alice@example.org>".to_string(),
                key_id: cert.keyid().to_hex(),
            }];
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
        let signs_with = |fingerprint: &str| {
            guard
                .se_signers
                .iter()
                .any(|key| key.fingerprint == fingerprint)
        };

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
            b"[Application]\nname=app.rpgp.rPGP\n",
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

    /// A message for a passphrase-protected key, run with the passphrase left
    /// out, says in the dialog and on the status line that the key wants its
    /// passphrase and whose key it is, where it used to say that no secret key
    /// opened it. Run again with the passphrase, it opens. Nothing is tried
    /// again on the user's behalf: each Run is one decryption.
    #[test]
    fn a_message_for_a_protected_key_asks_for_its_passphrase() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let mut request = rpgp_core::keygen::KeyGenRequest::new("Alice <alice@example.org>");
        request.password = Some("correct horse".to_string().into());
        let alice = rpgp_core::keygen::generate(&request).unwrap().cert;
        store.insert_secret(&alice).unwrap();

        let mut ciphertext = Vec::new();
        ops::encrypt(
            std::slice::from_ref(&alice),
            &[],
            None,
            b"for Alice",
            &mut ciphertext,
        )
        .unwrap();
        let message = dir.path().join("note.txt.asc");
        std::fs::write(&message, &ciphertext).unwrap();
        let opened = dir.path().join("note.txt");

        let state = state_for(store);
        let ui = window_for(&state);
        ui.invoke_open_decrypt_verify();
        choose_dv_input(&ui, &state, message.clone(), ops::classify_file(&message));

        let (read, outcome) = run_decrypt_verify(&state, "", Some(opened.clone()));
        show_decrypt_verify(&ui, &state, read, outcome);
        let status = ui.get_status();
        assert!(
            status.starts_with(
                "Decryption failed: this message is for a passphrase-protected key: \
                 enter its passphrase"
            ) && status.contains("Alice <alice@example.org>"),
            "{status}"
        );
        assert_eq!(ui.get_dv_result(), status);
        assert_eq!(ui.get_dv_tone(), 3);
        assert!(!opened.exists(), "a failed decryption wrote its output");

        let (read, outcome) = run_decrypt_verify(&state, "correct horse", Some(opened.clone()));
        show_decrypt_verify(&ui, &state, read, outcome);
        let status = ui.get_status();
        assert!(status.starts_with("Decrypted to"), "{status}");
        assert_eq!(std::fs::read(&opened).unwrap(), b"for Alice");
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

    /// Click the list row showing `fingerprint`, and put its certifications
    /// in the details pane as the worker the click starts would, if there
    /// were an event loop to take its answer.
    fn select_row(ui: &AppWindow, state: &Shared, fingerprint: &str) {
        click_row(ui, state, fingerprint);
        let summary = lock(state)
            .all
            .iter()
            .find(|c| c.fingerprint == fingerprint)
            .cloned()
            .expect("the certificate is in the list");
        let asked = ask_for_certifications(ui, &mut lock(state), &summary, false);
        let certifications = read_certifications(&asked.store, &asked.fingerprint);
        land_certifications(ui, state, &asked, &certifications);
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

        match import_into(&store, &keyring, &HashSet::new()) {
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

    /// Whether cert-d's copy of `fingerprint` is revoked.
    fn revoked(store: &Store, fingerprint: &str) -> bool {
        store.lookup(fingerprint).is_ok_and(|cert| {
            CertSummary::from_cert(&cert).validity == rpgp_core::Validity::Revoked
        })
    }

    /// A revocation certificate for one of the user's own keys is read and
    /// put to them, and stored only when they say so. It used to be stored as
    /// soon as Import was handed it: the one the app saves for every key it
    /// generates, chosen by mistake while restoring a backup, hard-revoked the
    /// key in both halves of the store with no question asked. What the
    /// dialog's button stores is what Import read, the way Delete acts on
    /// what its dialog named. Import's outcome goes through the step that
    /// hands it to the event loop, which is what opens the dialog.
    #[test]
    fn a_revocation_certificate_for_your_own_key_waits_for_you_to_confirm_it() {
        use slint::Model;

        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let mine = generated("Me <me@example.org>");
        let fingerprint = mine.cert.fingerprint().to_hex();
        store.insert_secret(&mine.cert).unwrap();
        store
            .save_revocation(&fingerprint, &revoke::armor(&mine.revocation).unwrap())
            .unwrap();
        let path = store.revocation_path(&fingerprint);

        let outcome = import_into(&store, &path, &HashSet::new());
        assert!(
            matches!(outcome, Ok(Imported::Confirm(_))),
            "the user was not asked first: {outcome:?}"
        );
        assert!(
            !revoked(&store, &fingerprint),
            "the key was revoked before the user was asked"
        );

        let state = state_for(store);
        let ui = window_for(&state);
        finish_import(&ui, &state, outcome);
        assert!(
            ui.get_import_revocation_open(),
            "the import finished without asking"
        );
        assert_eq!(ui.get_import_revocation_yours(), 1);
        let rows = ui.get_import_revocations();
        assert_eq!(rows.row_count(), 1);
        let row = rows.row_data(0).unwrap();
        assert_eq!(row.name, "Me <me@example.org>");
        assert!(
            row.yours && row.hard,
            "the dialog should say it is yours, and hard"
        );

        // Both halves, since the secret key file is written after cert-d.
        ui.invoke_import_revocation_run();
        let store = lock(&state).store.clone();
        wait_for("the revocation to be stored in both halves", || {
            revoked(&store, &fingerprint)
                && store.secret_cert(&fingerprint).is_ok_and(|secret| {
                    CertSummary::from_cert(&secret).validity == rpgp_core::Validity::Revoked
                })
        });
    }

    /// A revocation certificate for a key whose secret gpg-agent holds, in
    /// its own store or on a card, is put to the user as one for a key held
    /// here is. The store knows only of the secret keys it holds itself, and
    /// GnuPG's --gen-revoke writes one for an agent's key as a plain public
    /// key block that Import reads like the app's own. Taken for someone
    /// else's, it would revoke the key with no question asked. No agent is
    /// reached: the key is marked as the survey marks one the agent reports,
    /// and Import learns of it from the state the survey leaves.
    #[test]
    fn a_revocation_certificate_for_a_key_in_gpg_agent_waits_for_you_to_confirm_it() {
        use slint::Model;

        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        // The public half alone, as a key the agent holds is stored here.
        let mine = generated("Me <me@example.org>");
        let fingerprint = mine.cert.fingerprint().to_hex();
        store.insert(&mine.cert).unwrap();
        let path = dir.path().join("me.rev");
        std::fs::write(&path, revoke::armor(&mine.revocation).unwrap()).unwrap();

        let state = state_for(store);
        let ui = window_for(&state);
        lock(&state)
            .all
            .iter_mut()
            .find(|c| c.fingerprint == fingerprint)
            .expect("the key is listed")
            .agent
            .sign = agent_key(None);
        let store = lock(&state).store.clone();
        assert!(!store.has_secret(&fingerprint));

        let outcome = run_import(&state, &path);
        assert!(
            matches!(outcome, Ok(Imported::Confirm(_))),
            "the user was not asked first: {outcome:?}"
        );
        assert!(
            !revoked(&store, &fingerprint),
            "the key was revoked before the user was asked"
        );

        finish_import(&ui, &state, outcome);
        assert!(
            ui.get_import_revocation_open(),
            "the import finished without asking"
        );
        assert_eq!(ui.get_import_revocation_yours(), 1);
        assert!(
            ui.get_import_revocations().row_data(0).unwrap().yours,
            "the dialog should say the key is the user's"
        );

        // What the dialog's Revoke button stores, and what it then says.
        let file = lock(&state)
            .import_revocations
            .clone()
            .expect("the dialog holds what Import read");
        let status = store_revocations(&store, &file)
            .expect("the revocation is stored")
            .status
            .unwrap_or_default();
        assert!(revoked(&store, &fingerprint));
        assert!(
            status.ends_with("Publish or send the certificate so others stop using it."),
            "the user's own key revoked should be published: {status}"
        );
    }

    /// The same holds for a key of which the agent holds no signing key: only
    /// the primary, which certifies, or only a key that decrypts. The survey
    /// used to look at signing keys alone, so a revocation of such a key was
    /// taken for someone else's and stored with no question asked.
    #[test]
    fn a_revocation_certificate_for_a_key_the_agent_cannot_sign_with_waits_for_you_to_confirm_it() {
        let certifies_only = rpgp_core::agent::AgentHolds {
            certify: agent_key(Some("D2760001240100000006")),
            ..Default::default()
        };
        let decrypts_only = rpgp_core::agent::AgentHolds {
            decrypt: agent_key(None),
            ..Default::default()
        };
        for holds in [certifies_only, decrypts_only] {
            let dir = tempfile::tempdir().unwrap();
            let store =
                Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
            let mine = generated("Me <me@example.org>");
            let fingerprint = mine.cert.fingerprint().to_hex();
            store.insert(&mine.cert).unwrap();
            let path = dir.path().join("me.rev");
            std::fs::write(&path, revoke::armor(&mine.revocation).unwrap()).unwrap();

            let state = state_for(store);
            {
                let mut guard = lock(&state);
                let loaded = read_store(&guard.store).expect("a healthy store reads");
                guard.all = loaded.all;
                guard
                    .all
                    .iter_mut()
                    .find(|c| c.fingerprint == fingerprint)
                    .expect("the key is listed")
                    .agent = holds.clone();
            }

            let outcome = run_import(&state, &path);
            assert!(
                matches!(outcome, Ok(Imported::Confirm(_))),
                "the user was not asked first when the agent holds {holds:?}: {outcome:?}"
            );
            let store = lock(&state).store.clone();
            assert!(!revoked(&store, &fingerprint));
        }
    }

    /// Someone else's revocation certificate is applied without a question,
    /// and the list goes to the certificate it revoked.
    #[test]
    fn someone_elses_revocation_certificate_is_applied_without_asking() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let theirs = generated("Bob <bob@example.org>");
        let fingerprint = theirs.cert.fingerprint().to_hex();
        store.insert(&theirs.cert).unwrap();
        let path = dir.path().join("bob.rev");
        std::fs::write(&path, revoke::armor(&theirs.revocation).unwrap()).unwrap();

        match import_into(&store, &path, &HashSet::new()) {
            Ok(Imported::Done(after)) => {
                assert_eq!(after.select.as_deref(), Some(fingerprint.as_str()));
                let status = after.status.unwrap_or_default();
                assert!(
                    status.starts_with("Revoked Bob <bob@example.org>"),
                    "{status}"
                );
            }
            other => panic!("expected the revocation applied: {other:?}"),
        }
        assert!(revoked(&store, &fingerprint));
    }

    /// A revocation certificate that revokes nothing here says why. The
    /// import's own error was all that used to be said, that the file held no
    /// readable certificate, which is true of every revocation certificate and
    /// says nothing about this one.
    #[test]
    fn a_revocation_certificate_that_revokes_nothing_here_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let stranger = generated("Stranger <stranger@example.org>");
        let path = dir.path().join("stranger.rev");
        std::fs::write(&path, revoke::armor(&stranger.revocation).unwrap()).unwrap();

        let refused = import_into(&store, &path, &HashSet::new())
            .map(|_| ())
            .expect_err("nothing here is revoked by it")
            .to_string();
        assert_eq!(
            refused,
            "nothing was revoked: the revocation is for a certificate that is not in this store"
        );
    }

    /// What Import adds after its count, the note about a designated
    /// revoker's revocation, is a sentence of its own, whichever way the count
    /// ends. The count of certificates alone carries no full stop, and joined
    /// to the note by a space it would read as one sentence running on into
    /// the next.
    #[test]
    fn a_note_after_the_import_count_is_a_sentence_of_its_own() {
        let note = "Alice <alice@example.org> carries a revocation naming a key it \
                    designates to revoke it, which rPGP does not apply.";

        let mut plain = "Imported 1 certificate(s)".to_string();
        append_sentence(&mut plain, note);
        assert_eq!(plain, format!("Imported 1 certificate(s). {note}"));

        let mut with_secret = "Imported 1 certificate(s), 1 with a secret key. A secret key \
                               that arrives in a file is not made a trust root; tick Trust \
                               root in its details pane if you meant to trust it."
            .to_string();
        append_sentence(&mut with_secret, note);
        assert!(
            with_secret.ends_with(&format!("if you meant to trust it. {note}")),
            "a sentence that has its full stop should not get a second: {with_secret}"
        );
    }

    /// A key revoked already is offered only the hard reasons, and a soft one
    /// that reaches the run anyway is refused rather than signed. The dialog
    /// sends a bare index into Reason::ALL, and one sent from a shorter list
    /// without its offset is a retirement, the revocation this is meant to go
    /// past.
    #[test]
    fn marking_a_retired_key_compromised_takes_only_a_hard_reason() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let mine = generated("Me <me@example.org>").cert;
        let fingerprint = mine.fingerprint().to_hex();
        store.insert_secret(&mine).unwrap();
        revoke::revoke_cert(&store, &RevokeRequest::new(&fingerprint)).unwrap();
        let reason = |store: &Store| {
            revoke::revocation_reason(&store.lookup(&fingerprint).unwrap()).map(|(r, _)| r)
        };

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &fingerprint);
        ui.invoke_open_revoke();
        assert!(ui.get_revoke_open());
        assert!(
            ui.get_revoke_upgrade(),
            "the dialog should open to mark a retired key compromised"
        );

        let store = lock(&state).store.clone();
        let refused = run_revoke(&state, 0, "", "").expect_err("a second retirement was signed");
        assert!(refused.contains("revoked already"), "{refused}");
        assert_eq!(reason(&store), Some(Reason::Retired));

        let (_, message) = run_revoke(&state, 2, "laptop stolen", "").unwrap();
        assert!(
            message.starts_with("Key marked as compromised"),
            "{message}"
        );
        assert_eq!(reason(&store), Some(Reason::Compromised));
    }

    /// A revocation that cert-d took is reported as made when the secret key
    /// file could not follow. The run used to say it had failed, over a key
    /// that the list, exports and Publish all read as revoked.
    #[test]
    fn a_revocation_the_secret_key_file_missed_is_still_reported_as_made() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let mine = generated("Me <me@example.org>").cert;
        let fingerprint = mine.fingerprint().to_hex();
        store.insert_secret(&mine).unwrap();
        // Every write to the secrets directory takes the store's lock, and a
        // directory where its file goes fails the open.
        let lock_file = dir.path().join("write.lock");
        std::fs::remove_file(&lock_file).unwrap();
        std::fs::create_dir(&lock_file).unwrap();

        let state = state_for(store);
        lock(&state).revoke_target = Some(fingerprint.clone());
        let (target, message) =
            run_revoke(&state, 2, "", "").expect("the key was revoked, so the run should say so");
        assert_eq!(target, fingerprint);
        assert!(
            message.starts_with("Key revoked, but its secret key file could not be updated"),
            "{message}"
        );
        assert!(revoked(&lock(&state).store, &fingerprint));
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

    /// Withdrawing is offered again once a certification made after a
    /// withdrawal stands. The button used to ask whether the key had withdrawn
    /// anything on the user ID, whatever its date, so certifying, withdrawing
    /// and certifying again left a certification in force that the details
    /// pane offered no way to withdraw.
    #[test]
    fn withdrawing_is_offered_again_after_certifying_again() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let me = generated("Me <me@example.org>").cert;
        let them = generated("Them <them@example.org>").cert;
        store.insert_secret(&me).unwrap();
        store.insert(&them).unwrap();
        let (me_fp, them_fp) = (me.fingerprint().to_hex(), them.fingerprint().to_hex());
        let user_id = "Them <them@example.org>".to_string();
        let mut request = CertifyRequest::new(&me_fp, &them_fp);
        request.user_ids = vec![user_id.clone()];

        let state = state_for(store);
        let ui = window_for(&state);
        let store = lock(&state).store.clone();
        // Clicking the row again is what reads its certifications afresh.
        let offered = || {
            select_row(&ui, &state, &them_fp);
            ui.get_can_withdraw()
        };

        certify::certify(&store, &request).unwrap();
        assert!(offered(), "a certification that stands is offered");
        revoke::revoke_certification(
            &store,
            &me_fp,
            &them_fp,
            std::slice::from_ref(&user_id),
            Reason::Retired,
            "",
            None,
        )
        .unwrap();
        assert!(!offered(), "a withdrawn one is not");
        certify::certify(&store, &request).unwrap();
        assert!(
            offered(),
            "a certification made after the withdrawal stands, and has to be offered"
        );
    }

    /// Withdrawing asks only the keys whose certifications still stand.
    ///
    /// Of two of the user's keys that certified the same person, one had
    /// already withdrawn. The run signed for both all the same: the first key
    /// was asked to withdraw again, the status line counted two withdrawals
    /// where one had stood, and where the two keys had different passphrases,
    /// the passphrase for the key with something standing failed on the other
    /// and, if that one sorted first, never reached its own.
    #[test]
    fn withdrawing_asks_only_the_keys_whose_certifications_still_stand() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let one = generated("One <one@example.org>").cert;
        let two = generated("Two <two@example.org>").cert;
        let them = generated("Them <them@example.org>").cert;
        store.insert_secret(&one).unwrap();
        store.insert_secret(&two).unwrap();
        store.insert(&them).unwrap();
        let (one_fp, two_fp, them_fp) = (
            one.fingerprint().to_hex(),
            two.fingerprint().to_hex(),
            them.fingerprint().to_hex(),
        );
        let user_id = "Them <them@example.org>".to_string();
        for certifier in [&one_fp, &two_fp] {
            let mut request = CertifyRequest::new(certifier, &them_fp);
            request.user_ids = vec![user_id.clone()];
            certify::certify(&store, &request).unwrap();
        }
        revoke::revoke_certification(
            &store,
            &one_fp,
            &them_fp,
            std::slice::from_ref(&user_id),
            Reason::Retired,
            "",
            None,
        )
        .unwrap();

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &them_fp);
        ui.invoke_open_withdraw();
        assert_eq!(
            run_revoke(&state, 0, "", ""),
            Ok((them_fp.clone(), "Certification withdrawn.".to_string())),
            "only the key whose certification stood had anything to withdraw"
        );

        let store = lock(&state).store.clone();
        let listed = certify::certifications(&store, &store.lookup(&them_fp).unwrap()).unwrap();
        let withdrawals_by = |fingerprint: &str| {
            listed
                .iter()
                .filter(|c| c.is_revocation)
                .filter(|c| c.certifier_fingerprint.as_deref() == Some(fingerprint))
                .count()
        };
        assert_eq!(withdrawals_by(&one_fp), 1, "the first key withdrew again");
        assert_eq!(withdrawals_by(&two_fp), 1);
        assert!(certify::withdrawable(&listed).is_empty());
    }

    /// An entry of the agent's listing, as far as the list and the dialogs
    /// care: on the card `card` names, or in the agent's own store.
    fn agent_key(card: Option<&str>) -> Option<rpgp_core::agent::AgentKey> {
        Some(rpgp_core::agent::AgentKey {
            keygrip: "0".repeat(40),
            card_serial: card.map(str::to_owned),
        })
    }

    /// What a survey finds when the agent holds `holds` of `fingerprint`, and
    /// nothing else.
    fn found(
        fingerprint: &str,
        holds: rpgp_core::agent::AgentHolds,
    ) -> std::collections::HashMap<String, rpgp_core::agent::AgentHolds> {
        std::collections::HashMap::from([(fingerprint.to_string(), holds)])
    }

    /// Land what the survey after the newest reload found in the agent, with
    /// every secret key file reading.
    fn land_agent_survey(
        ui: &AppWindow,
        state: &Shared,
        agent_keys: &std::collections::HashMap<String, rpgp_core::agent::AgentHolds>,
    ) {
        let generation = lock(state).reload_generation;
        land_survey(ui, state, generation, agent_keys, &[]);
    }

    /// The certifiers the dialog lists once opened on `fingerprint`'s row.
    fn certifiers_for(ui: &AppWindow, state: &Shared, fingerprint: &str) -> Vec<(String, String)> {
        click_row(ui, state, fingerprint);
        ui.invoke_open_certify();
        lock(state)
            .certify_certifiers
            .iter()
            .map(|key| (key.fingerprint.clone(), key.label.clone()))
            .collect()
    }

    /// A key whose primary only gpg-agent holds opens Certify when the survey
    /// after a reload finds it there, and the dialog lists it, although no
    /// row changes: the agent keeps it in its own store, so there is no card
    /// serial to show.
    ///
    /// The button counted secret key files alone, and the survey, which
    /// learns what the agent holds after the reload has drawn the list,
    /// touched the rows and nothing else, and those only for a card. So a
    /// user whose only key was in the agent, or on a card, could never open
    /// the dialog that would have certified with it.
    #[test]
    fn a_primary_only_the_agent_holds_opens_certify_once_the_survey_finds_it() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        // The public halves alone, as a key the agent holds is stored here.
        let me = generated("Me <me@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert(&me).unwrap();
        store.insert(&bob).unwrap();
        let (me_fp, bob_fp) = (me.fingerprint().to_hex(), bob.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);
        assert!(
            !ui.get_can_certify(),
            "premise: nothing in the store itself can certify"
        );

        let survey = found(
            &me_fp,
            rpgp_core::agent::AgentHolds {
                certify: agent_key(None),
                ..Default::default()
            },
        );
        land_agent_survey(&ui, &state, &survey);
        assert!(
            ui.get_can_certify(),
            "the survey found a primary in the agent and left Certify closed"
        );
        assert_eq!(
            certifiers_for(&ui, &state, &bob_fp),
            [(me_fp, "Me <me@example.org>".to_string())]
        );
    }

    /// A key whose card holds only its subkeys, the primary being kept
    /// offline as most YubiKey guides advise, is not offered to certify with:
    /// it opens no Certify button, and the dialog another key opens does not
    /// list it. It can sign, and the sign dialog still offers it, marked as
    /// on a card.
    ///
    /// The dialog listed every certificate the agent could sign for, labelled
    /// "(smartcard)", and certifying with it failed at the last step for want
    /// of the primary key.
    #[test]
    fn a_card_holding_only_the_subkeys_is_not_offered_to_certify_with() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let card = generated("Card <card@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert(&card).unwrap();
        store.insert(&bob).unwrap();
        let (card_fp, bob_fp) = (card.fingerprint().to_hex(), bob.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);
        let subkeys_only = rpgp_core::agent::AgentHolds {
            sign: agent_key(Some("D2760001240100000006")),
            decrypt: agent_key(Some("D2760001240100000006")),
            certify: None,
        };
        land_agent_survey(&ui, &state, &found(&card_fp, subkeys_only.clone()));
        assert!(
            !ui.get_can_certify(),
            "a card without the primary key opened Certify"
        );

        // With a key in the store that can certify, the dialog opens, and
        // lists that key alone.
        let local = generated("Local <local@example.org>").cert;
        let local_fp = local.fingerprint().to_hex();
        let store = lock(&state).store.clone();
        store.insert_secret(&local).unwrap();
        lock(&state).all = read_store(&store).expect("a healthy store reads").all;
        apply_filter(&ui, &state);
        land_agent_survey(&ui, &state, &found(&card_fp, subkeys_only));
        assert!(ui.get_can_certify(), "premise: the local key can certify");
        assert_eq!(
            certifiers_for(&ui, &state, &bob_fp),
            [(local_fp, "Local <local@example.org>".to_string())],
            "the dialog offered a key that cannot certify"
        );

        ui.invoke_open_sign_encrypt();
        assert!(
            lock(&state)
                .se_signers
                .iter()
                .any(|key| key.fingerprint == card_fp
                    && key.label == "(smartcard) Card <card@example.org>"),
            "the card signs, and should be offered as a signer, marked as on a card"
        );
    }

    /// A certificate is not offered to certify itself, which core refuses. A
    /// key the agent alone holds is the user's own, yet the details pane has
    /// no secret key file to disable Certify by on its row, as it does for a
    /// key in the store; so its own dialog can open, and must not list it.
    #[test]
    fn a_certificate_is_not_offered_to_certify_itself() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let me = generated("Me <me@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert(&me).unwrap();
        store.insert(&bob).unwrap();
        let (me_fp, bob_fp) = (me.fingerprint().to_hex(), bob.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);
        let survey = found(
            &me_fp,
            rpgp_core::agent::AgentHolds {
                certify: agent_key(Some("D2760001240100000006")),
                ..Default::default()
            },
        );
        land_agent_survey(&ui, &state, &survey);
        assert!(ui.get_can_certify());

        assert!(
            certifiers_for(&ui, &state, &me_fp).is_empty(),
            "a certificate was offered to certify itself"
        );
        assert_eq!(certifiers_for(&ui, &state, &bob_fp).len(), 1);
    }

    /// "(smartcard)" before a certifier says that certifying with it will ask
    /// for the card, so it goes by where the agent holds the primary key,
    /// which certifies, and not the signing key, which the list's badge
    /// shows; and not at all where the store holds a usable primary, which is
    /// signed with first.
    #[test]
    fn a_certifier_is_labelled_smartcard_when_its_primary_is_on_one() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let card = generated("Card <card@example.org>").cert;
        let file = generated("File <file@example.org>").cert;
        let local = generated("Local <local@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert(&card).unwrap();
        store.insert(&file).unwrap();
        store.insert_secret(&local).unwrap();
        store.insert(&bob).unwrap();
        let (card_fp, file_fp, local_fp, bob_fp) = (
            card.fingerprint().to_hex(),
            file.fingerprint().to_hex(),
            local.fingerprint().to_hex(),
            bob.fingerprint().to_hex(),
        );

        let state = state_for(store);
        let ui = window_for(&state);
        let on_card = || agent_key(Some("D2760001240100000006"));
        let survey = std::collections::HashMap::from([
            (
                card_fp.clone(),
                rpgp_core::agent::AgentHolds {
                    certify: on_card(),
                    ..Default::default()
                },
            ),
            // The signing key on a card, the primary in the agent's store.
            (
                file_fp.clone(),
                rpgp_core::agent::AgentHolds {
                    sign: on_card(),
                    certify: agent_key(None),
                    ..Default::default()
                },
            ),
            // The primary on a card, and usable in the store as well.
            (
                local_fp.clone(),
                rpgp_core::agent::AgentHolds {
                    certify: on_card(),
                    ..Default::default()
                },
            ),
        ]);
        land_agent_survey(&ui, &state, &survey);

        let mut listed = certifiers_for(&ui, &state, &bob_fp);
        listed.sort();
        let mut expected = vec![
            (card_fp, "(smartcard) Card <card@example.org>".to_string()),
            (file_fp, "File <file@example.org>".to_string()),
            (local_fp, "Local <local@example.org>".to_string()),
        ];
        expected.sort();
        assert_eq!(listed, expected);
    }

    /// A secret key file whose primary is a GnuPG stub, as `gpg
    /// --export-secret-subkeys` writes one for a primary kept offline, does
    /// not open Certify, and the dialog does not list it: certifying signs
    /// with the primary, and there is none here to sign with. The full
    /// export of the same key, imported over it, does both.
    ///
    /// The button counted any secret key file, and the dialog too, so the
    /// key was offered and certifying with it failed at the last step.
    #[test]
    fn a_secret_key_file_whose_primary_is_a_stub_does_not_open_certify() {
        const SUBKEYS_ONLY: &[u8] =
            include_bytes!("../../rpgp-core/tests/fixtures/gnupg-secret-subkeys.asc");
        const FULL: &[u8] = include_bytes!("../../rpgp-core/tests/fixtures/gnupg-secret-keys.asc");
        const STUBBED: &str = "B44CCCCF9992862E40561636268C734A550768D8";

        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let import = |store: &Store, name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            store.import_file(&path).unwrap();
        };
        import(&store, "subkeys.asc", SUBKEYS_ONLY);
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert(&bob).unwrap();
        let bob_fp = bob.fingerprint().to_hex();

        let state = state_for(store);
        let ui = window_for(&state);
        let summary = |state: &Shared| {
            lock(state)
                .all
                .iter()
                .find(|c| c.fingerprint == STUBBED)
                .cloned()
                .expect("the fixture is listed")
        };
        assert!(
            summary(&state).has_secret && summary(&state).can_certify,
            "premise: a secret key file, for a key whose flags certify"
        );
        assert!(!ui.get_can_certify(), "a stubbed primary opened Certify");
        assert!(certifiers_for(&ui, &state, &bob_fp).is_empty());

        let store = lock(&state).store.clone();
        import(&store, "full.asc", FULL);
        lock(&state).all = read_store(&store).expect("a healthy store reads").all;
        apply_filter(&ui, &state);
        assert!(ui.get_can_certify(), "the full export should open Certify");
        assert_eq!(
            certifiers_for(&ui, &state, &bob_fp)
                .into_iter()
                .map(|(fingerprint, _)| fingerprint)
                .collect::<Vec<_>>(),
            [STUBBED]
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

    /// Choosing another signed file takes the last verdict out of the dialog,
    /// and so does choosing another signature, signature rows and all.
    ///
    /// The signed-file picker used to change the path and nothing else. After
    /// a good verify, "Signature verified" and its good and verified pills
    /// stayed up beside a file nothing had checked, one that fails when it is
    /// checked, as this test goes on to show.
    #[test]
    fn choosing_another_file_takes_the_last_verdict_away() {
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
        let verify = |ui: &AppWindow| {
            let (read, outcome) = run_decrypt_verify(&state, "", None);
            show_decrypt_verify(ui, &state, read, outcome);
        };
        let verdict = |ui: &AppWindow| {
            (
                ui.get_dv_result().to_string(),
                ui.get_dv_tone(),
                slint::Model::row_count(&ui.get_dv_signatures()),
            )
        };
        let verified = || ("Signature verified".to_string(), 1, 1);
        let none = || (String::new(), 0, 0);

        ui.invoke_open_decrypt_verify();
        choose_dv_input(&ui, &state, signature.clone(), kind);
        choose_dv_data(&ui, &state, release.clone());
        verify(&ui);
        assert_eq!(verdict(&ui), verified());

        choose_dv_data(&ui, &state, other.clone());
        assert_eq!(
            verdict(&ui),
            none(),
            "the verdict on a.tar stayed up beside b.tar"
        );
        verify(&ui);
        assert_eq!(
            verdict(&ui).0,
            "Signature is NOT valid",
            "b.tar is not what was signed"
        );

        choose_dv_data(&ui, &state, release.clone());
        verify(&ui);
        assert_eq!(verdict(&ui), verified());
        choose_dv_input(&ui, &state, signature.clone(), kind);
        assert_eq!(
            verdict(&ui),
            none(),
            "choosing the signature again left something of its verdict"
        );
    }

    /// Create key pair refuses fields that make no user ID, before anything
    /// starts, and the status line says why.
    ///
    /// The dialog's button can only ask whether the fields hold text, since
    /// Slint has no trim, and the handler used to format both into `{} <{}>`
    /// whatever they held: spaces in both made a key whose only user ID was
    /// `<>`, and a word in the e-mail field made `Alice <alice>`.
    #[test]
    fn create_key_pair_refuses_fields_that_make_no_user_id() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);

        for (name, email, why) in [
            (" ", "  ", "a name or an e-mail address"),
            ("Alice", "alice", "alice is not an e-mail address"),
            ("Alice <>", "", "between < and >"),
        ] {
            ui.set_status(SharedString::new());
            ui.invoke_generate_key(name.into(), email.into(), SharedString::new(), 0, 0, 0);
            let status = ui.get_status();
            assert!(
                status.starts_with("Key generation failed") && status.contains(why),
                "{name:?} and {email:?} should be refused ({why}): {status}"
            );
            assert!(
                !ui.get_busy(),
                "{name:?} and {email:?} started a generation"
            );
        }
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
    /// the network, and only key generation reaches the store. Add user ID
    /// and Delete have no target and start no worker at all. The rest, key
    /// generation apart, start workers that fail at once, for want of a file,
    /// a key, a target or a query. Key generation's worker makes a key and
    /// stores it itself, through `keygen::save`, in this test's temporary
    /// store. Its completion, which would reload the list, never gets so far:
    /// this thread has no event loop to run it, and on another test's loop it
    /// returns at once, since this window cannot be upgraded on a thread other
    /// than its own.
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
    /// The one test here that runs an event loop, which is how a reload's
    /// result reaches the window. The testing backend gives an event loop to
    /// a single thread per process, and a second test setting one up would
    /// panic, so the others drive the two halves of an operation directly,
    /// and land a reload by hand, with `land_reload`, where they need one.
    ///
    /// A reload that lands starts the agent survey on a thread of its own. It
    /// used to ask whichever agent `GNUPGHOME` named, the developer's own when
    /// it was unset, and start one if none was running, and GnuPG 2.4.9's
    /// agent starts scdaemon to answer. `state_for` points the process at no
    /// agent, so the survey here finds none and changes nothing.
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

    /// A reload overtaken by a newer one hands the confirmation it carries to
    /// that one, which shows it when it lands. A newer confirmation replaces
    /// one still waiting, and a read that fails shows its error and drops the
    /// confirmation rather than leave it for some later reload.
    ///
    /// A mutation asks for its reload once its worker is done and the window
    /// is no longer busy, so Refresh can be pressed while that read is in
    /// flight. The overtaken reload showed nothing, its confirmation included,
    /// and the newer read's count replaced "Key revoked. Publish or send the
    /// certificate so others stop using it." before it was ever shown. The
    /// reads land here by hand, in the order a race between them gives.
    #[test]
    fn a_reload_overtaken_by_another_hands_its_confirmation_on() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        store
            .insert_secret(&generated("Me <me@example.org>").cert)
            .unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        let count = ui.get_status();
        assert_eq!(count, "1 certificate(s), 1 with a secret key", "premise");

        const REVOKED: &str =
            "Key revoked. Publish or send the certificate so others stop using it.";
        const DELETED: &str = "Key and secret key deleted. The revocation certificate was kept.";
        const IMPORTED: &str = "Imported 1 certificate(s)";
        let confirming = |status: &str| AfterReload {
            status: Some(status.to_string()),
            ..Default::default()
        };
        let land = |asked: AskedReload| {
            let loaded = read_store(&asked.store);
            land_reload(&ui, &state, asked, loaded);
        };

        // The revocation's reload, overtaken by Refresh's.
        let revoked = ask_for_reload(&ui, &state, confirming(REVOKED));
        let refreshed = ask_for_reload(&ui, &state, AfterReload::default());
        land(revoked);
        assert_eq!(
            ui.get_status(),
            count,
            "a reload that was overtaken wrote to the status line"
        );
        land(refreshed);
        assert_eq!(
            ui.get_status(),
            REVOKED,
            "the confirmation of the reload that was overtaken was dropped"
        );

        // A delete's, overtaken by an import's.
        let deleted = ask_for_reload(&ui, &state, confirming(DELETED));
        let imported = ask_for_reload(&ui, &state, confirming(IMPORTED));
        land(deleted);
        land(imported);
        assert_eq!(
            ui.get_status(),
            IMPORTED,
            "the newer confirmation should replace the one still waiting"
        );

        // A revocation's, whose read fails.
        let failed = ask_for_reload(&ui, &state, confirming(REVOKED));
        land_reload(&ui, &state, failed, Err("the disk went away".to_string()));
        assert_eq!(
            ui.get_status(),
            "Cannot read the certificate store: the disk went away"
        );
        land(ask_for_reload(&ui, &state, AfterReload::default()));
        assert_eq!(
            ui.get_status(),
            count,
            "a confirmation whose read failed turned up on a later reload"
        );
    }

    /// A secret key file that will not parse is named on the status line
    /// after the confirmation of the operation that caused the reload, rather
    /// than in its place, and only by the survey of the newest reload.
    ///
    /// The survey's notice replaced the confirmation a few milliseconds after
    /// it went up. That hit hardest in the emergency a revocation certificate
    /// is kept for, where the key's own secret key file no longer reads: the
    /// status line said the key was revoked, that its secret key file could
    /// not be updated to match and that the certificate should be published,
    /// and the next moment only that a file had been skipped.
    #[test]
    fn a_damaged_secret_key_file_is_named_after_the_confirmation_not_over_it() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let key = generated("Me <me@example.org>");
        store.insert_secret(&key.cert).unwrap();
        let revocation = dir.path().join("me.rev");
        std::fs::write(&revocation, revoke::armor(&key.revocation).unwrap()).unwrap();
        // Cut short, as rpgp-core's own test of this case cuts it.
        let name = format!("{}.pgp", key.cert.fingerprint().to_hex());
        let secret = dir.path().join("secrets").join(&name);
        let whole = std::fs::read(&secret).unwrap();
        std::fs::write(&secret, &whole[..40]).unwrap();

        let state = state_for(store);
        let ui = window_for(&state);
        let store = lock(&state).store.clone();
        assert_eq!(
            store.damaged_secret_files(),
            [secret],
            "premise: the survey finds the file damaged"
        );
        // Named as the survey names it.
        let damaged = [name.clone()];
        let notice = format!("1 secret key file could not be read and was skipped: {name}");
        let nothing_in_the_agent = std::collections::HashMap::new();

        // Import asks first, the key being the user's, and the answer stores
        // the revocation and asks for a reload.
        let file = match import_into(&store, &revocation, &HashSet::new()) {
            Ok(Imported::Confirm(file)) => file,
            other => panic!("expected to be asked about the user's own key: {other:?}"),
        };
        let asked = ask_for_reload(&ui, &state, store_revocations(&store, &file).unwrap());
        let imported = asked.generation;
        land_reload(&ui, &state, asked, read_store(&store));
        let confirmation = ui.get_status();
        assert!(
            confirmation.contains("could not be updated to match")
                && confirmation
                    .ends_with("Publish or send the certificate so others stop using it."),
            "premise: {confirmation}"
        );
        land_survey(&ui, &state, imported, &nothing_in_the_agent, &damaged);
        assert_eq!(
            ui.get_status(),
            format!("{confirmation} {notice}"),
            "the damaged file should be named after the confirmation"
        );

        // Refresh, and the import's survey landing only after it was pressed.
        let refreshed = ask_for_reload(&ui, &state, AfterReload::default());
        let newest = refreshed.generation;
        let before = ui.get_status();
        land_survey(&ui, &state, imported, &nothing_in_the_agent, &damaged);
        assert_eq!(
            ui.get_status(),
            before,
            "the survey of a reload that was overtaken wrote to the status line"
        );
        land_reload(&ui, &state, refreshed, read_store(&store));
        let count = ui.get_status();
        land_survey(&ui, &state, newest, &nothing_in_the_agent, &damaged);
        land_survey(&ui, &state, imported, &nothing_in_the_agent, &damaged);
        assert_eq!(
            ui.get_status(),
            format!("{count}. {notice}"),
            "the damaged file should be named once, after the count"
        );
    }

    /// The notepad's Copy marks what it copies private, a fingerprint's Copy
    /// leaves it unmarked, and where the clipboard cannot mark a copy the
    /// notepad says so.
    ///
    /// The notepad's output can be a decrypted message, and it used to go on
    /// the clipboard as a fingerprint does: into every clipboard manager's
    /// history, and on X11 handed to one to keep when rPGP let go of the
    /// clipboard. No test has a display server to copy to, so the clipboard
    /// here records what each copy asked for instead.
    #[test]
    fn the_notepad_copies_its_output_marked_private_and_says_when_it_cannot() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        ui.set_np_output("TOP SECRET".into());

        // arboard, which can mark a copy on every platform it runs on.
        clipboard::record(true);
        ui.invoke_np_copy();
        assert_eq!(ui.get_status(), "Copied to the clipboard");
        ui.invoke_copy_value("0123 4567".into());
        assert_eq!(
            clipboard::recorded(),
            [
                ("TOP SECRET".to_string(), clipboard::Content::Private),
                ("0123 4567".to_string(), clipboard::Content::Public),
            ],
            "the notepad's output must be copied as private, and a fingerprint as public"
        );

        // smithay-clipboard, which can mark nothing.
        clipboard::record(false);
        ui.invoke_np_copy();
        assert!(
            ui.get_np_copied(),
            "the copy still went, so the button should say so"
        );
        let status = ui.get_status();
        assert!(
            status.contains("clipboard history may keep it"),
            "a decrypted message copied without the mark should say so: {status}"
        );
        ui.invoke_copy_value("0123 4567".into());
        assert_eq!(
            ui.get_status(),
            "Copied to the clipboard",
            "a public copy is never marked, so it lacks nothing"
        );
    }

    /// Closing the notepad empties what it showed from the window, and a run
    /// that lands after it closed does not put its result back.
    ///
    /// The output, both whole and as much of it as the box shows, the note
    /// under the box, the verdict and the signer rows are the window's
    /// properties rather than the dialog's, and closing only closed the
    /// dialog, so the last decrypted message stayed referenced from the window
    /// for as long as rPGP ran, or until the notepad was opened again. Escape
    /// and a click on the scrim used to close it with a run in flight, and that
    /// run's result then landed in the same properties. They no longer close it
    /// until the run is done, so the run is made to land here on a notepad
    /// closed before it started.
    #[test]
    fn closing_the_notepad_takes_what_it_showed_out_of_the_window() {
        use slint::Model;
        use slint::platform::{PointerEventButton, WindowEvent};

        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        ui.window().set_size(slint::LogicalSize::new(1000.0, 700.0));
        ui.show().unwrap();
        // Long enough that the output box is given only its start, with a
        // note saying so, so that the plaintext is in two properties and the
        // note in a third, and closing has all of them to empty.
        let plaintext = "TOP SECRET\n".repeat(2 * NP_SHOWN_LINES);
        let decrypted = || -> NpOutcome {
            Ok((
                plaintext.clone(),
                "Decrypted. Good signature.".to_string(),
                1,
                vec![report("0123", true)],
            ))
        };
        let shown = |ui: &AppWindow| {
            (
                ui.get_np_output().to_string(),
                ui.get_np_output_shown().to_string(),
                ui.get_np_output_note().to_string(),
                ui.get_np_result().to_string(),
                ui.get_np_signatures().row_count(),
            )
        };
        let empty = (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            0,
        );

        ui.invoke_open_notepad();
        finish_notepad(&ui, &state, decrypted());
        let (output, output_shown, note, result, signatures) = shown(&ui);
        assert_eq!(
            (output.as_str(), result.as_str(), signatures),
            (plaintext.as_str(), "Decrypted. Good signature.", 1)
        );
        assert!(
            output_shown.starts_with("TOP SECRET")
                && output_shown.len() < plaintext.len()
                && !note.is_empty(),
            "the premise: the box shows the start of the plaintext, and says so"
        );

        // A click beside the card, on the scrim, the way Close and Escape
        // close it too.
        let position = slint::LogicalPosition::new(4.0, 4.0);
        let button = PointerEventButton::Left;
        ui.window()
            .dispatch_event(WindowEvent::PointerPressed { position, button });
        ui.window()
            .dispatch_event(WindowEvent::PointerReleased { position, button });
        assert!(
            !ui.get_notepad_open(),
            "the click should have closed the notepad"
        );
        assert_eq!(
            shown(&ui),
            empty,
            "closing the notepad left what it showed in the window"
        );

        // A run that lands on the closed notepad.
        ui.set_busy(true);
        finish_notepad(&ui, &state, decrypted());
        assert_eq!(
            shown(&ui),
            empty,
            "a run that landed after the notepad closed put its output back"
        );
        assert!(!ui.get_busy());
        assert_eq!(
            ui.get_status(),
            "Decrypted. Good signature.",
            "the status line should still say how the run went"
        );
    }

    /// Send a key to whatever has focus in the window, as the windowing
    /// backend does.
    fn press(ui: &AppWindow, key: impl Into<SharedString>) {
        let text = key.into();
        let window = ui.window();
        window.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
        window.dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
    }

    /// Opens or closes one of the window's dialogs.
    type Open = fn(&AppWindow, bool);
    /// Whether one of the window's dialogs is open.
    type IsOpen = fn(&AppWindow) -> bool;

    /// Point at the top-left corner of the window, beside any dialog's card,
    /// and click there if asked. Moving the pointer is also what has Slint
    /// build a dialog opened since the last event, and run its `init`, which
    /// gives it focus.
    fn at_the_corner(ui: &AppWindow, click: bool) {
        use slint::platform::{PointerEventButton, WindowEvent};
        let position = slint::LogicalPosition::new(4.0, 4.0);
        let button = PointerEventButton::Left;
        let window = ui.window();
        window.dispatch_event(WindowEvent::PointerMoved { position });
        if click {
            window.dispatch_event(WindowEvent::PointerPressed { position, button });
            window.dispatch_event(WindowEvent::PointerReleased { position, button });
        }
    }

    /// Tab and Shift+Tab stay among an open dialog's own controls, and no key
    /// pressed in it reaches anything behind its scrim.
    ///
    /// The dialogs are children of the window rather than popups, and Slint's
    /// Tab goes to any control on screen, covered or not, wrapping around the
    /// whole window. So Tab walked out of the notepad to the rail, where Enter
    /// on Sign / Encrypt opened that dialog underneath and replaced the
    /// notepad's recipients, and Shift+Tab reached the details pane's Trust
    /// root and SHA-1 boxes, each a write to the store.
    ///
    /// The window is not wired to Rust here. The callbacks of the controls
    /// behind the notepad are counted, and no callback does anything else,
    /// the notepad's own Close included, which leaves the notepad open for
    /// the whole walk. Enter is pressed at every stop, which every control
    /// behind the notepad answers to.
    #[test]
    fn keys_pressed_in_an_open_dialog_reach_nothing_behind_it() {
        use slint::platform::Key;
        use std::cell::RefCell;
        use std::rc::Rc;

        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("the window builds on the testing backend");
        ui.window().set_size(slint::LogicalSize::new(1180.0, 760.0));

        // A selection whose details pane shows every control it can: the
        // SHA-1 box, Trust root, Certify, Withdraw, Save revocation, Delete,
        // All details, Export and Encrypt to, and three copy buttons.
        let someone = CertRow {
            fingerprint: "AAAA".into(),
            primary_user_id: "Bob <bob@example.org>".into(),
            validity: "unusable".into(),
            authentication: "unverified".into(),
            sha1_blocked: true,
            ..Default::default()
        };
        ui.set_certs(ModelRc::new(VecModel::from(vec![
            someone.clone(),
            CertRow {
                fingerprint: "BBBB".into(),
                primary_user_id: "Carol <carol@example.org>".into(),
                ..someone.clone()
            },
        ])));
        ui.set_current_row(0);
        ui.set_has_selection(true);
        ui.set_detail(someone);
        ui.set_can_certify(true);
        ui.set_can_withdraw(true);
        ui.set_has_revocation_cert(true);

        let reached = Rc::new(RefCell::new(Vec::<&str>::new()));
        let hit = |what: &'static str| {
            let reached = reached.clone();
            move || reached.borrow_mut().push(what)
        };
        ui.on_open_sign_encrypt(hit("Sign / Encrypt"));
        ui.on_open_decrypt_verify(hit("Decrypt / Verify"));
        ui.on_open_notepad(hit("Notepad"));
        ui.on_import_file(hit("Import"));
        ui.on_open_lookup(hit("Look up"));
        ui.on_export_selected(hit("Export"));
        ui.on_refresh(hit("Refresh"));
        ui.on_open_certify(hit("Certify"));
        ui.on_open_withdraw(hit("Withdraw"));
        ui.on_open_publish(hit("Publish"));
        ui.on_save_revocation_cert(hit("Save revocation certificate"));
        ui.on_open_revoke(hit("Revoke"));
        ui.on_open_delete(hit("Delete"));
        ui.on_open_details(hit("All details"));
        ui.on_toggle_trust_root(hit("Trust root"));
        ui.on_toggle_sha1_accepted(hit("Accept SHA-1"));
        ui.on_filter_changed({
            let hit = hit("the search field");
            move |_| hit()
        });
        ui.on_scope_changed({
            let hit = hit("a scope tab");
            move |_| hit()
        });
        ui.on_sort_changed({
            let hit = hit("Sort by");
            move |_| hit()
        });
        ui.on_row_selected({
            let hit = hit("the certificate list");
            move |_| hit()
        });
        ui.on_copy_value({
            let hit = hit("a copy button");
            move |_| hit()
        });
        ui.show().unwrap();

        // With no dialog open the same keys reach the rail's first tab, so
        // that nothing reached below means the dialog held them.
        press(&ui, Key::Tab);
        press(&ui, Key::Return);
        assert_eq!(*reached.borrow(), ["a scope tab"]);
        reached.borrow_mut().clear();

        ui.set_notepad_open(true);
        at_the_corner(&ui, false);
        for key in [Key::Tab, Key::Backtab] {
            for _ in 0..40 {
                press(&ui, key);
                press(&ui, Key::Return);
            }
        }
        assert!(
            reached.borrow().is_empty(),
            "keys pressed in the notepad reached {:?} behind it",
            reached.borrow()
        );
        assert!(ui.get_notepad_open());
        assert!(
            !ui.get_keygen_open() && !ui.get_about_open(),
            "a second dialog opened behind the notepad"
        );
    }

    /// Escape and a click on the scrim leave each dialog open while its
    /// operation runs, as its Cancel or Close does, and close it once the
    /// operation is done.
    ///
    /// They used to close it whatever was running. A delete, a revocation or
    /// a publish then looked cancelled, and went on to happen. The window
    /// hands `busy` to every dialog that runs something, which is what is
    /// checked here, one dialog at a time.
    #[test]
    fn escape_and_the_scrim_leave_every_dialog_open_while_its_operation_runs() {
        use slint::platform::Key;

        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("the window builds on the testing backend");
        ui.window().set_size(slint::LogicalSize::new(1180.0, 760.0));
        // The notepad asks Rust to close it, which empties it first.
        ui.on_close_notepad({
            let ui = ui.as_weak();
            move || ui.unwrap().set_notepad_open(false)
        });
        ui.show().unwrap();

        let dialogs: [(&str, Open, IsOpen); 10] = [
            (
                "New key pair",
                AppWindow::set_keygen_open,
                AppWindow::get_keygen_open,
            ),
            (
                "Sign / Encrypt",
                AppWindow::set_signenc_open,
                AppWindow::get_signenc_open,
            ),
            (
                "Decrypt / Verify",
                AppWindow::set_verify_open,
                AppWindow::get_verify_open,
            ),
            (
                "Certify",
                AppWindow::set_certify_open,
                AppWindow::get_certify_open,
            ),
            (
                "Delete",
                AppWindow::set_delete_open,
                AppWindow::get_delete_open,
            ),
            (
                "Revoke",
                AppWindow::set_revoke_open,
                AppWindow::get_revoke_open,
            ),
            (
                "Import revocation",
                AppWindow::set_import_revocation_open,
                AppWindow::get_import_revocation_open,
            ),
            (
                "Notepad",
                AppWindow::set_notepad_open,
                AppWindow::get_notepad_open,
            ),
            (
                "Lifecycle",
                AppWindow::set_lifecycle_open,
                AppWindow::get_lifecycle_open,
            ),
            (
                "Look up",
                AppWindow::set_lookup_open,
                AppWindow::get_lookup_open,
            ),
        ];
        for (dialog, open, is_open) in dialogs {
            ui.set_busy(true);
            open(&ui, true);
            at_the_corner(&ui, false);
            press(&ui, Key::Escape);
            at_the_corner(&ui, true);
            at_the_corner(&ui, true);
            assert!(is_open(&ui), "{dialog} was closed while its operation ran");

            ui.set_busy(false);
            press(&ui, Key::Escape);
            assert!(
                !is_open(&ui),
                "Escape should close {dialog} once it is done"
            );
            open(&ui, true);
            at_the_corner(&ui, false);
            at_the_corner(&ui, true);
            assert!(
                !is_open(&ui),
                "the scrim should close {dialog} once it is done"
            );
        }
    }

    /// Why an operation started from a dialog failed is put in that dialog as
    /// well as on the status line, and taken out again once an operation
    /// starts or the dialog closes.
    ///
    /// It went on the status line alone, which the dialog's scrim covers,
    /// where it read at 1.5:1 in the dark theme and was never announced. The
    /// failures reached here are the ones that come before a worker starts,
    /// and key generation's, whose worker hands its outcome to a function a
    /// test can call; the other workers' failures go through the same two
    /// functions.
    #[test]
    fn a_failure_is_reported_in_its_dialog_until_the_user_moves_on() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        // Where Slint runs `changed` handlers, which are what clear the line.
        let settle = slint::platform::update_timers_and_animations;
        let reported = |what: &str| {
            let error = ui.get_dialog_error();
            assert!(
                error.contains(what),
                "the dialog should say {what:?}, not {error:?}"
            );
            assert_eq!(
                ui.get_status(),
                error,
                "the status line should say it as well"
            );
        };

        // Refused before anything starts.
        ui.set_keygen_open(true);
        settle();
        ui.invoke_generate_key(" ".into(), "  ".into(), SharedString::new(), 0, 0, 0);
        reported("Key generation failed");
        // Cleared once an operation starts, so that a retry is not shown the
        // last attempt's reason.
        ui.set_busy(true);
        settle();
        assert_eq!(
            ui.get_dialog_error(),
            "",
            "starting again left the old failure"
        );
        // A generation that failed on its worker.
        finish_keygen(
            &ui,
            &state,
            Err(rpgp_core::Error::invalid("no space left on device")),
        );
        reported("no space left on device");
        assert!(
            ui.get_keygen_open(),
            "a failure should leave the dialog open"
        );
        // Cleared when the dialog closes, so that the next one opens clean.
        ui.set_keygen_open(false);
        settle();
        assert_eq!(ui.get_dialog_error(), "", "closing left the failure behind");

        // The other dialogs' refusals before a worker starts: nothing opened
        // them, so each has nothing to act on.
        let refusals: [(&str, Open, &dyn Fn()); 3] = [
            ("Delete", AppWindow::set_delete_open, &|| {
                ui.invoke_delete_run()
            }),
            ("Lifecycle", AppWindow::set_lifecycle_open, &|| {
                ui.invoke_lifecycle_run(
                    1,
                    "0".into(),
                    "Jo <jo@example.org>".into(),
                    SharedString::new(),
                    0,
                )
            }),
            (
                "Import revocation",
                AppWindow::set_import_revocation_open,
                &|| ui.invoke_import_revocation_run(),
            ),
        ];
        for (dialog, open, run) in refusals {
            open(&ui, true);
            settle();
            run();
            assert!(
                ui.get_dialog_error().starts_with("No "),
                "{dialog} refused without saying why in the dialog: {:?}",
                ui.get_dialog_error()
            );
            open(&ui, false);
            settle();
            assert_eq!(ui.get_dialog_error(), "");
        }
    }

    /// A worker that panics clears `busy` and says so where its operation says
    /// that it failed: in the dialog's error line for the seven dialogs that
    /// have one, and in the line of their own that Decrypt / Verify, the
    /// notepad and Lookup keep.
    ///
    /// Every panic went to the window's `dialog-error`, which those three do
    /// not show, and to the status line, which is not announced while a
    /// dialog covers it. So Lookup went on saying "Searching…", and Decrypt /
    /// Verify showed the verdict of the run before. No test makes a worker
    /// panic: this calls what [`BusyGuard`] hands the event loop, with the
    /// reporter each of those workers' guards names.
    #[test]
    fn a_worker_that_panics_says_so_where_its_operation_says_it_failed() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        const PANICKED: &str = "That operation failed unexpectedly. Nothing was changed.";
        let panicked = |report: fn(&AppWindow, String)| {
            ui.set_busy(true);
            after_a_panic(&ui, report);
            assert!(!ui.get_busy(), "a panic left the window busy");
        };

        // Over the verdict of the run before.
        ui.invoke_open_decrypt_verify();
        ui.set_dv_result("Signature verified".into());
        ui.set_dv_tone(1);
        panicked(report_in_decrypt_verify);
        assert_eq!(
            (ui.get_dv_result().as_str(), ui.get_dv_tone()),
            (PANICKED, 3),
            "Decrypt / Verify did not say that its run failed"
        );
        ui.set_verify_open(false);

        ui.invoke_open_notepad();
        ui.set_np_result("Signed".into());
        panicked(report_in_notepad);
        assert_eq!(
            (ui.get_np_result().as_str(), ui.get_np_tone()),
            (PANICKED, 3),
            "the notepad did not say that its run failed"
        );
        ui.invoke_close_notepad();

        ui.invoke_open_lookup();
        ui.set_lookup_status("Searching…".into());
        panicked(report_in_lookup);
        assert_eq!(
            ui.get_lookup_status(),
            PANICKED,
            "Lookup did not say that its search failed"
        );
        ui.set_lookup_open(false);

        ui.set_certify_open(true);
        panicked(report_in_dialog);
        assert_eq!(ui.get_dialog_error(), PANICKED);
        assert_eq!(
            ui.get_status(),
            PANICKED,
            "the status line should say it as well"
        );
    }

    /// A revocation certificate for the user's own key is not asked about
    /// over another dialog, and nothing of it is stored.
    ///
    /// Import's file dialog is not modal, so another dialog can have been
    /// opened while it was up, and the question opened over that one when it
    /// answered. The window keeps Tab and assistive technology inside an open
    /// dialog by disabling what is behind it, and the dialog under the
    /// question was not disabled: its controls, Delete key and Create key pair
    /// among them, could be reached from the question, and Decrypt / Verify,
    /// which is drawn above the question, hid it while it held focus. The
    /// question itself can be open, when a second Import's file dialog
    /// answers. With nothing else open, the file is asked about as before.
    #[test]
    fn a_revocation_certificate_for_your_own_key_is_not_asked_about_over_another_dialog() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let mine = generated("Me <me@example.org>");
        let fingerprint = mine.cert.fingerprint().to_hex();
        store.insert_secret(&mine.cert).unwrap();
        store
            .save_revocation(&fingerprint, &revoke::armor(&mine.revocation).unwrap())
            .unwrap();
        let path = store.revocation_path(&fingerprint);
        let state = state_for(store);
        let ui = window_for(&state);
        let store = lock(&state).store.clone();

        let dialogs: [(&str, Open); 3] = [
            ("New key pair", AppWindow::set_keygen_open),
            ("Decrypt / Verify", AppWindow::set_verify_open),
            ("the question itself", AppWindow::set_import_revocation_open),
        ];
        for (dialog, open) in dialogs {
            open(&ui, true);
            let asking = ui.get_import_revocation_open();
            finish_import(&ui, &state, run_import(&state, &path));
            // Looked at with the dialog still open, since closing the question
            // would hide a second one put over it. Over the question, the
            // window has only the one to show, and what gives a second away is
            // the import it leaves waiting: this test opened the question by
            // hand, with nothing waiting.
            assert!(
                ui.get_import_revocation_open() == asking
                    && lock(&state).import_revocations.is_none(),
                "the question was put over {dialog}"
            );
            assert_eq!(
                ui.get_status(),
                "Nothing was revoked: the file is a revocation certificate for your own key, \
                 and another dialog is open. Close it and import the file again.",
                "over {dialog}"
            );
            assert!(
                !revoked(&store, &fingerprint),
                "the key was revoked over {dialog}"
            );
            open(&ui, false);
        }

        finish_import(&ui, &state, run_import(&state, &path));
        assert!(
            ui.get_import_revocation_open(),
            "with no other dialog open, the import should ask"
        );
    }

    #[global_allocator]
    static WATCH: freed::Watch = freed::Watch;

    /// What the allocator is handed back, watched while
    /// [`every_worker_wipes_its_copy_of_a_passphrase`] asks: whether a copy of
    /// a passphrase is freed with the passphrase still in it.
    ///
    /// A plain `String` is freed as it stands, and its bytes stay in the heap
    /// until something reuses them; `Zeroizing` wipes them first. Only byte
    /// buffers are read, the alignment of a `String` or a `Vec<u8>`. Slint's
    /// own strings carry a header aligned for their reference count, and those
    /// cannot be wiped at all, as the README says, so they are not what the
    /// test asks about. Every test in this binary pays for the watch: an
    /// atomic load for each allocation, and a byte buffer zeroed as it is
    /// handed out or grown, for the reason `dealloc` gives.
    mod freed {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
        use std::time::{Duration, Instant};

        /// The passphrase the test hands every callback. A byte buffer of
        /// exactly its length, allocated on the test's thread while it calls
        /// a callback, is taken for that callback's copy of it, so the length
        /// is an unusual one.
        pub const MARKER: &str = "a passphrase no other test uses, 7f3a9c51, of an unusual length";

        pub struct Watch;

        static WATCHING: AtomicBool = AtomicBool::new(false);
        /// Byte buffers freed with the marker still in them.
        static UNWIPED: AtomicUsize = AtomicUsize::new(0);
        /// How many copies the callback made.
        static MADE: AtomicUsize = AtomicUsize::new(0);
        /// The addresses of the copies not yet freed.
        static COPIES: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];

        thread_local! {
            /// Set on the test's thread while it calls a callback.
            static CALLING: Cell<bool> = const { Cell::new(false) };
        }

        fn is_copy(layout: Layout) -> bool {
            layout.align() == 1 && layout.size() == MARKER.len()
        }

        unsafe impl GlobalAlloc for Watch {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                // SAFETY: passed through as it came.
                let block = unsafe { System.alloc(layout) };
                if block.is_null() {
                    return block;
                }
                if layout.align() == 1 {
                    // SAFETY: the block was just allocated, and this long.
                    unsafe { block.write_bytes(0, layout.size()) };
                }
                if WATCHING.load(SeqCst)
                    && is_copy(layout)
                    && CALLING.with(Cell::get)
                    && COPIES.iter().any(|slot| {
                        slot.compare_exchange(0, block as usize, SeqCst, SeqCst)
                            .is_ok()
                    })
                {
                    MADE.fetch_add(1, SeqCst);
                }
                block
            }

            unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
                if WATCHING.load(SeqCst) {
                    if layout.align() == 1 && (MARKER.len()..=(1 << 16)).contains(&layout.size()) {
                        // SAFETY: the block is still allocated, and this long,
                        // and every byte of it has been written: `alloc`
                        // zeroes a byte buffer as it hands it out, and
                        // `realloc` what one grows by. Without that, a
                        // String's spare capacity would be bytes never
                        // written, which Rust does not allow to be read as
                        // `u8`, and could still hold the marker left by a
                        // block freed before it, such as one of Slint's
                        // copies, and fail the test falsely.
                        let bytes = unsafe { std::slice::from_raw_parts(block, layout.size()) };
                        if bytes
                            .windows(MARKER.len())
                            .any(|window| window == MARKER.as_bytes())
                        {
                            UNWIPED.fetch_add(1, SeqCst);
                        }
                    }
                    let _ = COPIES.iter().any(|slot| {
                        slot.compare_exchange(block as usize, 0, SeqCst, SeqCst)
                            .is_ok()
                    });
                }
                // SAFETY: passed through as it came.
                unsafe { System.dealloc(block, layout) }
            }

            unsafe fn realloc(&self, block: *mut u8, layout: Layout, size: usize) -> *mut u8 {
                if !WATCHING.load(SeqCst) {
                    // SAFETY: passed through as it came.
                    let moved = unsafe { System.realloc(block, layout, size) };
                    if !moved.is_null() && layout.align() == 1 && size > layout.size() {
                        // Zeroed as `alloc` zeroes a new block.
                        // SAFETY: the block is `size` long now.
                        unsafe {
                            moved
                                .add(layout.size())
                                .write_bytes(0, size - layout.size())
                        };
                    }
                    return moved;
                }
                // As GlobalAlloc's own default does it, so that a buffer that
                // grows or shrinks by moving is read as its old place is freed.
                // SAFETY: the caller promises `size` is valid at this alignment.
                let grown = unsafe { Layout::from_size_align_unchecked(size, layout.align()) };
                // SAFETY: as for alloc and dealloc above.
                unsafe {
                    let moved = self.alloc(grown);
                    if !moved.is_null() {
                        std::ptr::copy_nonoverlapping(block, moved, layout.size().min(size));
                        self.dealloc(block, layout);
                    }
                    moved
                }
            }
        }

        /// Call `invoke`, which hands [`MARKER`] to a callback, and wait until
        /// every copy of it the callback made has been freed, on whichever
        /// thread that happens. Returns how many copies it made, and how many
        /// byte buffers were freed with the marker still in them meanwhile.
        pub fn run(invoke: impl FnOnce()) -> (usize, usize) {
            for slot in &COPIES {
                slot.store(0, SeqCst);
            }
            UNWIPED.store(0, SeqCst);
            MADE.store(0, SeqCst);
            WATCHING.store(true, SeqCst);
            CALLING.with(|calling| calling.set(true));
            invoke();
            CALLING.with(|calling| calling.set(false));

            let outstanding = || COPIES.iter().any(|slot| slot.load(SeqCst) != 0);
            let deadline = Instant::now() + Duration::from_secs(30);
            while outstanding() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            let freed = !outstanding();
            WATCHING.store(false, SeqCst);
            assert!(freed, "a copy of the passphrase was never freed");
            (MADE.load(SeqCst), UNWIPED.load(SeqCst))
        }
    }

    /// Every callback that takes a passphrase wipes its copy of it before the
    /// copy is freed.
    ///
    /// The copy is made the moment the passphrase leaves Slint's string, and
    /// moves to a worker, where it lives for the whole operation, a card's
    /// PIN prompt included. Key generation, Sign / Encrypt and the notepad
    /// held theirs in `Zeroizing`; Decrypt / Verify, Certify, the lifecycle
    /// actions and Revoke held a plain `String`, and freed it with the
    /// passphrase in it. Every run here but key generation stops early, with
    /// no file or no certificate to act on, so the callback's copy is all
    /// there is to see. A run that goes further only borrows it, or copies it
    /// into a `Zeroizing` of its own, and Sequoia's `Password` wipes what it
    /// takes. Key generation shows that for one whole run: it makes a key
    /// protected by the passphrase and stores it, and nothing on the way,
    /// rpgp-core's or Sequoia's, may free a copy unwiped either.
    #[test]
    fn every_worker_wipes_its_copy_of_a_passphrase() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        // The lifecycle callback starts no worker without one.
        lock(&state).lifecycle_fingerprint = Some("0123456789ABCDEF".to_string());

        let marker = || SharedString::from(freed::MARKER);
        let none = SharedString::new;
        let runs: [(&str, usize, &dyn Fn()); 7] = [
            ("Sign / Encrypt", 2, &|| {
                ui.invoke_se_run(false, true, 0, marker(), marker())
            }),
            ("The notepad", 2, &|| {
                ui.invoke_np_run(0, "a note".into(), 0, marker(), marker())
            }),
            ("Decrypt / Verify", 1, &|| ui.invoke_dv_run(marker())),
            ("Certify", 1, &|| {
                ui.invoke_certify_run(0, false, false, 0, marker())
            }),
            // Mode 99 is no action at all, so nothing is written.
            ("A lifecycle action", 1, &|| {
                ui.invoke_lifecycle_run(99, "0".into(), none(), marker(), 0)
            }),
            ("Revoke", 1, &|| ui.invoke_revoke_run(0, none(), marker())),
            // Last, so that no run before it has a key to act on.
            ("Key generation", 1, &|| {
                ui.invoke_generate_key("Wipe".into(), "wipe@example.org".into(), marker(), 0, 0, 0)
            }),
        ];
        for (what, copies, invoke) in runs {
            // Each run leaves busy set, since the completion that would clear
            // it runs on an event loop this backend does not have.
            ui.set_busy(false);
            let (made, unwiped) = freed::run(invoke);
            assert_eq!(
                made, copies,
                "{what} made {made} copies of the passphrase where {copies} were expected, \
                 so this cannot tell whether they were wiped"
            );
            assert_eq!(
                unwiped, 0,
                "{what} freed a copy of the passphrase without wiping it"
            );
        }

        // Key generation went the whole way, so its copy was followed through
        // rpgp-core and Sequoia and not only through the callback.
        let keys = lock(&state).store.secret_certs().expect("the store reads");
        assert_eq!(keys.len(), 1, "key generation should have stored its key");
        assert!(
            keys[0]
                .keys()
                .secret()
                .all(|key| key.key().secret().is_encrypted()),
            "the key should be protected by the passphrase"
        );
    }

    /// A key generated here with every user ID in `user_ids`, the first
    /// primary, under `standard`. Key generation refuses a control character
    /// but not a format character, such as an override, and reads a user ID
    /// with no angle brackets as a name, whatever it holds.
    fn generated_with(
        user_ids: &[&str],
        standard: rpgp_core::keygen::Standard,
    ) -> rpgp_core::keygen::GeneratedKey {
        let mut request = KeyGenRequest::new(user_ids[0]);
        request.user_ids = user_ids.iter().map(|uid| uid.to_string()).collect();
        request.standard = standard;
        rpgp_core::keygen::generate(&request).unwrap()
    }

    /// A user ID is shown with whatever in it draws nothing, or turns the
    /// text around it round, written out as its code point, everywhere the
    /// window shows one: the list and the details pane, the Certify and
    /// Revoke dialogs, the recipient and signer lists, a signature's signer.
    ///
    /// They were shown as the certificate had them, and Slint applies the
    /// bidirectional algorithm in full: an override drew an address
    /// backwards, one left open reversed the notepad's own verdict after the
    /// name, and a newline made one user ID read as two in the details pane.
    #[test]
    fn a_user_id_is_shown_with_what_it_hides_written_out() {
        i_slint_backend_testing::init_no_event_loop();
        use slint::Model;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        // An address drawn backwards by an override that is never closed, and
        // a second user ID that differs from a third by a zero-width space.
        const SPOOF: &str = "Mallory \u{202E}gro.elpmaxe@ecila";
        const SHOWN: &str = "Mallory [U+202E]gro.elpmaxe@ecila";
        let mallory = generated_with(
            &[SPOOF, "Mal", "M\u{200B}al"],
            rpgp_core::keygen::Standard::default(),
        )
        .cert;
        let me = generated("Me <me@example.org>").cert;
        store.insert_secret(&mallory).unwrap();
        store.insert_secret(&me).unwrap();
        let mallory = mallory.fingerprint().to_hex();

        let state = state_for(store);
        let ui = window_for(&state);
        let row = row_for(&state, &mallory);
        assert_eq!(row.primary_user_id, SHOWN);
        assert_eq!(row.name, SHOWN, "the name is the whole user ID here");
        // In the order the certificate keeps them, which is by their bytes.
        let each = ["Mal", SHOWN, "M[U+200B]al"];
        assert_eq!(
            row.user_ids.split('\n').collect::<Vec<_>>(),
            each,
            "one user ID a line, and those that differ shown differently"
        );
        assert_eq!(
            row.initials, "MG",
            "the monogram took the override for a letter"
        );

        // Certify, on Mallory's row, by another of the user's keys.
        click_row(&ui, &state, &mallory);
        ui.invoke_open_certify();
        assert_eq!(ui.get_certify_target(), SHOWN);
        let offered: Vec<String> = ui
            .get_certify_user_ids()
            .iter()
            .map(|row| row.text.to_string())
            .collect();
        assert_eq!(offered, each);

        // Revoke.
        ui.invoke_open_revoke();
        assert_eq!(ui.get_revoke_target(), SHOWN);

        // Sign / Encrypt, where it is both a recipient and a signer.
        ui.invoke_open_sign_encrypt();
        let recipients = ui.get_se_recipients();
        assert!(
            recipients.iter().any(|r| r.label == SHOWN),
            "no recipient reads {SHOWN:?}: {:?}",
            recipients.iter().map(|r| r.label).collect::<Vec<_>>()
        );
        assert!(ui.get_se_signers().iter().any(|signer| signer == SHOWN));

        // A signature it made.
        let rows = signature_rows(
            &lock(&state).all,
            &[ops::SignatureReport {
                good: true,
                signer: SPOOF.to_string(),
                fingerprint: Some(mallory.clone()),
                detail: String::new(),
                sha1: false,
            }],
        );
        assert_eq!(rows[0].signer, SHOWN);
    }

    /// A user ID shown with a hidden character written out is certified, and
    /// revoked, as the certificate has it: what the dialogs show is for the
    /// user to read, and what they act on stays the certificate's own text,
    /// by which rpgp-core finds the user ID.
    #[test]
    fn a_user_id_shown_written_out_is_acted_on_as_the_certificate_has_it() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        const HIDDEN: &str = "M\u{200B}al";
        let mallory = generated_with(&["Mal", HIDDEN], rpgp_core::keygen::Standard::default()).cert;
        let me = generated_with(&["Me", HIDDEN], rpgp_core::keygen::Standard::default()).cert;
        store.insert(&mallory).unwrap();
        store.insert_secret(&me).unwrap();
        let (mallory, me) = (mallory.fingerprint().to_hex(), me.fingerprint().to_hex());

        let state = state_for(store);
        let ui = window_for(&state);

        // Certify the second of Mallory's user IDs alone.
        click_row(&ui, &state, &mallory);
        ui.invoke_open_certify();
        ui.invoke_certify_toggle_user_id(0);
        assert_eq!(ui.get_certify_chosen(), 1);
        run_certify(&state, 0, true, false, 0, "").expect("the user ID should be certified");
        let store = lock(&state).store.clone();
        let certified: Vec<String> =
            certify::certifications(&store, &store.lookup(&mallory).unwrap())
                .unwrap()
                .into_iter()
                .map(|certification| certification.user_id)
                .collect();
        assert_eq!(certified, [HIDDEN]);

        // Revoke the same user ID on the user's own key, as the Details
        // dialog's Revoke button opens it.
        click_row(&ui, &state, &me);
        ui.invoke_open_revoke_user_id(HIDDEN.into());
        assert_eq!(ui.get_lifecycle_target(), "M[U+200B]al");
        ui.invoke_lifecycle_run(2, "0".into(), SharedString::new(), SharedString::new(), 0);
        let retired = || {
            store.secret_cert(&me).is_ok_and(|cert| {
                rpgp_core::cert::user_ids(&cert)
                    .iter()
                    .any(|uid| uid.text == HIDDEN && uid.revoked)
            })
        };
        wait_for("the user ID to be revoked", retired);
    }

    /// A failure that quotes a user ID shows it written out as well, on
    /// every line that reports one: rpgp-core names what it refused by the
    /// certificate's own text. Those are the open dialog's line and the
    /// status line; Decrypt / Verify's, the notepad's and Lookup's own lines;
    /// the status line a result goes to once its files have been changed or
    /// the notepad closed; and the status line a reload leaves. The reason a
    /// bad signature is bad is written out the same way.
    #[test]
    fn a_failure_quoting_a_user_id_shows_it_written_out() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let me = generated("Me <me@example.org>").cert;
        store.insert_secret(&me).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);

        let failed = run_lifecycle(
            &state,
            &LifecycleInput {
                mode: 2,
                fingerprint: me.fingerprint().to_hex(),
                target: "Nobody \u{202E}ereh".to_string(),
                expiry: "0".to_string(),
                value: String::new(),
                password: Zeroizing::new(String::new()),
                reason: 0,
            },
        )
        .expect_err("there is no such user ID to revoke");
        assert!(failed.contains('\u{202E}'), "the premise: {failed:?}");
        let shown = |line: SharedString, on: &str| {
            assert!(
                line.contains("Nobody [U+202E]ereh") && !line.contains('\u{202E}'),
                "{on}: {line:?}"
            );
        };
        // Each line is emptied first, so that what it shows is what the next
        // report put there.
        let clear = || {
            ui.set_dialog_error(SharedString::new());
            ui.set_status(SharedString::new());
        };

        report_in_dialog(&ui, failed.clone());
        shown(ui.get_dialog_error(), "the dialog");
        assert_eq!(ui.get_status(), ui.get_dialog_error());

        // A failure that reads the store again behind it. With no event loop
        // the reload never lands, so what it would leave on the status line
        // is asked of landed_status.
        clear();
        report_in_dialog_and_reload(&ui, &state, failed.clone());
        shown(ui.get_dialog_error(), "the dialog, before a reload");
        shown(ui.get_status(), "the status line, before a reload");
        clear();
        report_and_reload(&ui, &state, failed.clone());
        shown(ui.get_status(), "the status line, before a reload");
        shown(
            landed_status(Some(failed.clone()), Vec::new())
                .unwrap_or_default()
                .into(),
            "the status line a reload leaves",
        );

        clear();
        report_in_decrypt_verify(&ui, failed.clone());
        shown(ui.get_dv_result(), "Decrypt / Verify");
        shown(ui.get_status(), "the status line, with Decrypt / Verify");
        clear();
        let changed = DvRead {
            generation: lock(&state).dv_generation + 1,
            names: "a.txt.sig".to_string(),
        };
        show_decrypt_verify(&ui, &state, changed, Err(failed.clone()));
        shown(
            ui.get_status(),
            "the status line, for files no longer chosen",
        );

        clear();
        ui.set_notepad_open(true);
        report_in_notepad(&ui, failed.clone());
        shown(ui.get_np_result(), "the notepad");
        shown(ui.get_status(), "the status line, with the notepad");
        clear();
        ui.set_notepad_open(false);
        finish_notepad(&ui, &state, Err(failed.clone()));
        shown(ui.get_status(), "the status line, the notepad closed");

        report_in_lookup(&ui, failed.clone());
        shown(ui.get_lookup_status(), "Lookup");

        let bad = signature_rows(
            &[],
            &[ops::SignatureReport {
                good: false,
                signer: "unknown".to_string(),
                fingerprint: None,
                detail: failed,
                sha1: false,
            }],
        );
        shown(bad[0].detail.clone(), "a bad signature's reason");
    }

    /// R2-012's own case, an address drawn backwards by an override inside
    /// its angle brackets, is shown written out wherever the window shows a
    /// user ID or a part of one: the address line of the list and the details
    /// pane, a recipient's address, the Details dialog's user IDs, both user
    /// IDs of a certification, and Lookup's row and the line saying it was
    /// imported.
    ///
    /// `Mallory <\u{202E}gro.elpmaxe@ecila\u{202C}>` drew as Mallory over
    /// "alice@example.org".
    #[test]
    fn an_address_drawn_backwards_is_shown_with_its_override_written_out() {
        i_slint_backend_testing::init_no_event_loop();
        use slint::Model;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        const SPOOF: &str = "Mallory <\u{202E}gro.elpmaxe@ecila\u{202C}>";
        const SHOWN: &str = "Mallory <[U+202E]gro.elpmaxe@ecila[U+202C]>";
        const ADDRESS: &str = "[U+202E]gro.elpmaxe@ecila[U+202C]";
        // The user's key hides a character as well, for the certification's
        // certifier.
        let mallory = generated_with(&[SPOOF, "Mal"], rpgp_core::keygen::Standard::default()).cert;
        let me = generated_with(
            &["M\u{200B}e <me@example.org>"],
            rpgp_core::keygen::Standard::default(),
        )
        .cert;
        store.insert(&mallory).unwrap();
        store.insert_secret(&me).unwrap();
        let fingerprint = mallory.fingerprint().to_hex();

        let state = state_for(store);
        let ui = window_for(&state);
        let row = row_for(&state, &fingerprint);
        assert_eq!(row.primary_user_id, SHOWN);
        assert_eq!(
            (row.name.as_str(), row.email.as_str()),
            ("Mallory", ADDRESS)
        );

        ui.invoke_open_sign_encrypt();
        let recipient = ui
            .get_se_recipients()
            .iter()
            .find(|r| r.fingerprint == fingerprint)
            .expect("Mallory can be encrypted to");
        assert_eq!(
            (recipient.label.as_str(), recipient.sublabel.as_str()),
            ("Mallory", ADDRESS)
        );

        // Shown written out in the Details dialog, and handed to Revoke user
        // ID as the certificate has it.
        click_row(&ui, &state, &fingerprint);
        ui.invoke_open_details();
        let user_ids: Vec<(String, String)> = ui
            .get_detail_user_ids()
            .iter()
            .map(|uid| (uid.text.to_string(), uid.user_id.to_string()))
            .collect();
        assert!(
            user_ids.contains(&(SHOWN.to_string(), SPOOF.to_string())),
            "{user_ids:?}"
        );

        // Certified by the user's key, and shown in the details pane's
        // certifications, which name the user ID when there is more than one.
        ui.invoke_open_certify();
        run_certify(&state, 0, true, false, 0, "").expect("the user IDs should be certified");
        select_row(&ui, &state, &fingerprint);
        let certification = ui
            .get_detail_certifications()
            .iter()
            .find(|c| c.user_id == SHOWN)
            .expect("a certification should show the user ID written out");
        assert_eq!(certification.certifier, "M[U+200B]e <me@example.org>");
        assert!(
            certification.detail.starts_with(&format!("{SHOWN} · ")),
            "{:?}",
            certification.detail
        );

        // Found by a lookup, and imported from it.
        let found = rpgp_core::keyserver::Found {
            cert: mallory,
            source: rpgp_core::keyserver::Source::Keyserver,
        };
        let listed = lookup_row(&lock(&state).store, &found);
        assert_eq!(listed.primary_user_id, SHOWN);
        lock(&state).lookup_results = vec![found];
        ui.invoke_lookup_import(0);
        assert_eq!(
            ui.get_lookup_status(),
            format!("Imported {SHOWN}. It is unverified until you certify it.")
        );
    }

    /// Two of the user's keys with the same user ID, a Modern and a
    /// Compatible one say, are told apart by their key IDs wherever one is
    /// chosen: as a recipient, as the key to sign with and as the key to
    /// certify with. A version 6 key's ID is the head of its fingerprint, and
    /// a version 4 key's its tail.
    ///
    /// The recipient list showed the name and the address, and the other two
    /// lists the user ID alone, so the two keys read the same in all three.
    #[test]
    fn two_keys_with_the_same_user_id_are_told_apart_wherever_one_is_chosen() {
        i_slint_backend_testing::init_no_event_loop();
        use slint::Model;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        const ALICE: &str = "Alice <alice@example.org>";
        let modern = generated_with(&[ALICE], rpgp_core::keygen::Standard::Rfc9580).cert;
        let compatible = generated_with(&[ALICE], rpgp_core::keygen::Standard::Rfc4880).cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert_secret(&modern).unwrap();
        store.insert_secret(&compatible).unwrap();
        store.insert(&bob).unwrap();
        let (modern, compatible, bob) = (
            modern.fingerprint().to_hex(),
            compatible.fingerprint().to_hex(),
            bob.fingerprint().to_hex(),
        );
        let (modern_id, compatible_id) = (&modern[..16], &compatible[24..]);
        let mut expected = vec![modern_id.to_string(), compatible_id.to_string()];
        expected.sort();

        let state = state_for(store);
        let ui = window_for(&state);
        let sorted = |model: ModelRc<SharedString>| {
            let mut ids: Vec<String> = model.iter().map(|id| id.to_string()).collect();
            ids.sort();
            ids
        };

        ui.invoke_open_sign_encrypt();
        let mut recipients: Vec<String> = ui
            .get_se_recipients()
            .iter()
            .filter(|r| r.label == "Alice")
            .map(|r| {
                assert_eq!(r.sublabel, "alice@example.org");
                r.key_id.to_string()
            })
            .collect();
        recipients.sort();
        assert_eq!(recipients, expected, "the recipient rows");
        assert_eq!(
            ui.get_se_signers()
                .iter()
                .map(|signer| signer.to_string())
                .collect::<Vec<_>>(),
            [ALICE, ALICE],
            "the premise: the signers read alike"
        );
        assert_eq!(sorted(ui.get_se_signer_key_ids()), expected, "Sign as");

        click_row(&ui, &state, &bob);
        ui.invoke_open_certify();
        assert_eq!(
            sorted(ui.get_certify_certifier_key_ids()),
            expected,
            "Certify with"
        );
    }

    /// The note left with a revocation is kept apart from its reason, which
    /// is the app's own words, and shown with what it hides written out, in
    /// the details pane and in the dialog that asks before a revocation of
    /// the user's own key is stored, which names the key written out as well;
    /// the status line quotes it, written out too.
    ///
    /// Anyone holding the key writes the note, and it was joined on after the
    /// reason, in the banner's red, as one sentence of the app's.
    #[test]
    fn a_revocation_note_is_kept_apart_from_its_reason() {
        i_slint_backend_testing::init_no_event_loop();
        use slint::Model;
        let dir = tempfile::tempdir().unwrap();
        let (theirs, store) = (
            Store::open(dir.path().join("theirs.d"), dir.path().join("theirs")).unwrap(),
            Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap(),
        );
        const NOTE: &str = "rPGP: import 0x1234 instead\n\u{202E}detrevni";
        const SHOWN: &str = "rPGP: import 0x1234 instead[U+000A][U+202E]detrevni";
        // The name the dialog gives the key, its primary user ID, hides a
        // character as well.
        let key = generated_with(
            &["M\u{200B}e <me@example.org>"],
            rpgp_core::keygen::Standard::default(),
        )
        .cert;
        let fingerprint = key.fingerprint().to_hex();
        store.insert_secret(&key).unwrap();

        // The revocation, made by another copy of the key and read from a
        // file, as Import reads one.
        theirs.insert_secret(&key).unwrap();
        let mut request = RevokeRequest::new(&fingerprint);
        request.reason = Reason::Superseded;
        request.message = NOTE.to_string();
        let revoked = revoke::revoke_cert(&theirs, &request).unwrap();
        let signature = revoked.primary_key().self_revocations().next().unwrap();
        let path = dir.path().join("me.rev");
        std::fs::write(&path, revoke::armor(signature).unwrap()).unwrap();

        let state = state_for(store);
        let ui = window_for(&state);
        let file = match import_into(&lock(&state).store, &path, &HashSet::new()) {
            Ok(Imported::Confirm(file)) => file,
            other => panic!("expected to be asked about the user's own key: {other:?}"),
        };
        ask_to_store_revocations(&ui, &state, file.clone());
        let asked = ui.get_import_revocations();
        let asked = asked.row_data(0).unwrap();
        assert_eq!(asked.name, "M[U+200B]e <me@example.org>");
        assert_eq!(asked.reason, "Replaced by a newer key");
        assert_eq!(asked.note, SHOWN);

        // The status line the reload after storing it leaves.
        let after = store_revocations(&lock(&state).store, &file).unwrap();
        let status = landed_status(after.status, Vec::new()).unwrap_or_default();
        assert!(
            status.starts_with(&format!(
                "Revoked M[U+200B]e <me@example.org>: Replaced by a newer key — “{SHOWN}”."
            )),
            "the status line should quote the note: {status}"
        );

        let summary = CertSummary::from_cert(&lock(&state).store.lookup(&fingerprint).unwrap());
        assert_eq!(
            summary.revocation.as_deref(),
            Some("Replaced by a newer key")
        );
        assert_eq!(summary.revocation_note, NOTE);
        let row = to_row(&summary);
        assert_eq!(row.revocation, "Replaced by a newer key");
        assert_eq!(row.revocation_note, SHOWN);
    }

    /// A key on an OpenPGP card is shown with the card's number as `gpg -K`
    /// gives it, not the 32 digits of its application identifier, which ran
    /// the details pane's smartcard pill past the pane's edge.
    #[test]
    fn a_card_is_shown_by_its_number() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let card = generated("Card <card@example.org>").cert;
        store.insert(&card).unwrap();
        let card = card.fingerprint().to_hex();

        let state = state_for(store);
        let ui = window_for(&state);
        let survey = found(
            &card,
            rpgp_core::agent::AgentHolds {
                sign: agent_key(Some("D2760001240103040006181329630000")),
                ..Default::default()
            },
        );
        land_agent_survey(&ui, &state, &survey);
        assert_eq!(row_for(&state, &card).card_serial, "0006 18132963");
    }

    /// Selecting a row reads its certifications on a worker, not on the event
    /// loop, and of two readings the one asked for last is the one shown,
    /// whichever comes back first.
    ///
    /// The reading looks up every certifier and verifies every certification,
    /// and it ran inside the click, with the state lock held, freezing the
    /// window for as long as a much-certified key took. No event loop runs
    /// here, so the click's own worker never lands, and the pane is left
    /// saying the certifications are being read; the readings a race would
    /// bring back are landed by hand.
    #[test]
    fn a_rows_certifications_are_read_off_the_event_loop_and_the_newest_shown() {
        use slint::Model;
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let me = generated("Me <me@example.org>").cert;
        let alice = generated("Alice <alice@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert_secret(&me).unwrap();
        store.insert(&alice).unwrap();
        store.insert(&bob).unwrap();
        let me = me.fingerprint().to_hex();
        let (alice, bob) = (alice.fingerprint().to_hex(), bob.fingerprint().to_hex());
        // Only Alice is certified, so her reading and Bob's differ.
        let mut request = CertifyRequest::new(&me, &alice);
        request.user_ids = vec!["Alice <alice@example.org>".to_string()];
        certify::certify(&store, &request).unwrap();

        let state = state_for(store);
        let ui = window_for(&state);
        let shown = |ui: &AppWindow| {
            ui.get_detail_certifications()
                .iter()
                .map(|c| c.certifier.to_string())
                .collect::<Vec<_>>()
        };

        click_row(&ui, &state, &alice);
        assert!(
            ui.get_certifications_pending() && shown(&ui).is_empty() && !ui.get_can_withdraw(),
            "the click read the certifications itself, on the event loop: {:?}",
            shown(&ui)
        );

        // Alice's reading is slow, and the user moves to Bob before it is back.
        let summary = |fingerprint: &str| {
            lock(&state)
                .all
                .iter()
                .find(|c| c.fingerprint == fingerprint)
                .cloned()
                .unwrap()
        };
        let (of_alice, of_bob) = (summary(&alice), summary(&bob));
        let for_alice = ask_for_certifications(&ui, &mut lock(&state), &of_alice, false);
        let alices = read_certifications(&for_alice.store, &for_alice.fingerprint);
        assert_eq!(alices.len(), 1, "the premise: Alice is certified");
        click_row(&ui, &state, &bob);
        let for_bob = ask_for_certifications(&ui, &mut lock(&state), &of_bob, false);
        let bobs = read_certifications(&for_bob.store, &for_bob.fingerprint);

        land_certifications(&ui, &state, &for_alice, &alices);
        assert_eq!(ui.get_detail().fingerprint, bob);
        assert!(
            shown(&ui).is_empty() && !ui.get_can_withdraw() && ui.get_certifications_pending(),
            "Alice's certifications were shown under Bob: {:?}",
            shown(&ui)
        );

        land_certifications(&ui, &state, &for_bob, &bobs);
        assert!(!ui.get_certifications_pending());
        assert!(shown(&ui).is_empty(), "nobody has certified Bob");

        // And a reading that is the newest is shown, Withdraw with it.
        select_row(&ui, &state, &alice);
        assert_eq!(shown(&ui), ["Me <me@example.org>"]);
        assert!(ui.get_can_withdraw());
        assert!(!ui.get_certifications_pending());
    }

    /// A reload that puts back the row the details pane shows keeps its
    /// certifications, and Withdraw, until they are read again; one that
    /// puts back another row empties the pane, as a click does.
    ///
    /// Emptied on every reload, the pane took Withdraw away from under the
    /// keyboard focus each time, whatever the reload was for, and everything
    /// below the rows jumped until the reading landed.
    #[test]
    fn a_reload_keeps_the_certifications_of_the_row_it_puts_back_until_read_again() {
        use slint::Model;
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let me = generated("Me <me@example.org>").cert;
        let alice = generated("Alice <alice@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert_secret(&me).unwrap();
        store.insert(&alice).unwrap();
        store.insert(&bob).unwrap();
        let me = me.fingerprint().to_hex();
        let (alice, bob) = (alice.fingerprint().to_hex(), bob.fingerprint().to_hex());
        let mut request = CertifyRequest::new(&me, &alice);
        request.user_ids = vec!["Alice <alice@example.org>".to_string()];
        certify::certify(&store, &request).unwrap();

        let state = state_for(store);
        let ui = window_for(&state);
        let shown = |ui: &AppWindow| {
            ui.get_detail_certifications()
                .iter()
                .map(|c| c.certifier.to_string())
                .collect::<Vec<_>>()
        };
        let of_alice = lock(&state)
            .all
            .iter()
            .find(|c| c.fingerprint == alice)
            .cloned()
            .unwrap();

        select_row(&ui, &state, &alice);
        assert_eq!(shown(&ui), ["Me <me@example.org>"], "the premise");
        assert!(ui.get_can_withdraw());
        // A reading asked for before the reload, which the reload overtakes.
        let before = ask_for_certifications(&ui, &mut lock(&state), &of_alice, true);

        // What a reload does once it has read the store.
        apply_filter(&ui, &state);
        reselect(&ui, &state, &alice);
        assert_eq!(ui.get_detail().fingerprint, alice);
        assert!(
            shown(&ui) == ["Me <me@example.org>"]
                && ui.get_can_withdraw()
                && !ui.get_certifications_pending(),
            "the reload emptied the certifications of the row it put back: {:?}",
            shown(&ui)
        );
        land_certifications(&ui, &state, &before, &[]);
        assert_eq!(
            shown(&ui),
            ["Me <me@example.org>"],
            "a reading the reload overtook was shown"
        );

        // A reload that puts back a row other than the one the pane shows, as
        // one after an import selects what it brought in.
        select_row(&ui, &state, &bob);
        apply_filter(&ui, &state);
        reselect(&ui, &state, &alice);
        assert_eq!(ui.get_detail().fingerprint, alice);
        assert!(
            shown(&ui).is_empty() && !ui.get_can_withdraw() && ui.get_certifications_pending(),
            "what the pane showed of Bob was kept under Alice"
        );
    }

    /// A search, a change of Sort by or of scope keeps the user on the row
    /// they were on, while that row is still listed, and leaves nothing
    /// selected once it is not.
    ///
    /// Each cleared the selection, since a row index means nothing against a
    /// new set of rows, and put nothing back: one letter typed into the search
    /// box emptied the details pane and disabled Export.
    #[test]
    fn a_search_sort_or_scope_change_keeps_the_row_the_user_is_on() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let me = generated("Me <me@example.org>").cert;
        let alice = generated("Alice <alice@example.org>").cert;
        let bob = generated("Bob <bob@example.org>").cert;
        store.insert_secret(&me).unwrap();
        store.insert(&alice).unwrap();
        store.insert(&bob).unwrap();
        let alice = alice.fingerprint().to_hex();

        let state = state_for(store);
        let ui = window_for(&state);
        let on_alice = |ui: &AppWindow| {
            let row = usize::try_from(ui.get_current_row()).ok();
            ui.get_has_selection()
                && ui.get_detail().fingerprint == alice
                && row.and_then(|r| lock(&state).shown_at(r).map(|c| c.fingerprint.clone()))
                    == Some(alice.clone())
        };
        click_row(&ui, &state, &alice);
        assert!(on_alice(&ui));

        ui.invoke_filter_changed("a".into());
        assert!(on_alice(&ui), "a search Alice still matches lost her row");
        ui.invoke_sort_changed(1);
        assert!(on_alice(&ui), "a change of Sort by lost her row");
        ui.invoke_scope_changed(2);
        assert!(on_alice(&ui), "a scope she is in lost her row");

        ui.invoke_scope_changed(1);
        assert!(
            !ui.get_has_selection(),
            "Alice is not one of the user's own keys, so nothing is selected"
        );
    }

    /// A fingerprint typed or pasted in groups of four, as the details pane
    /// and gpg print it, finds its certificate in the list and among the
    /// recipients, where it used to find nothing in either; and typed a
    /// character at a time, it goes on finding it, and keeping it selected,
    /// all the way.
    #[test]
    fn a_fingerprint_typed_in_groups_finds_its_row_and_its_recipient() {
        use slint::Model;
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let alice = generated("Alice <alice@example.org>").cert;
        store.insert(&alice).unwrap();
        store
            .insert(&generated("Bob <bob@example.org>").cert)
            .unwrap();
        let grouped = CertSummary::from_cert(&alice).fingerprint_pretty();

        let state = state_for(store);
        let ui = window_for(&state);
        click_row(&ui, &state, &alice.fingerprint().to_hex());
        for end in 1..=grouped.len() {
            ui.invoke_filter_changed(grouped[..end].into());
            assert!(
                ui.get_has_selection()
                    && ui.get_detail().fingerprint == alice.fingerprint().to_hex(),
                "typing {:?} lost the row",
                &grouped[..end]
            );
        }
        assert_eq!(ui.get_certs().row_count(), 1, "{grouped} found no row");
        let grouped: SharedString = grouped.into();

        ui.invoke_open_sign_encrypt();
        ui.invoke_filter_recipients(grouped.clone());
        let recipients: Vec<String> = ui
            .get_se_recipients()
            .iter()
            .map(|r| r.fingerprint.to_string())
            .collect();
        assert_eq!(recipients, [alice.fingerprint().to_hex()], "{grouped}");
    }

    /// The rows the notepad's output box lays `text` out in before any
    /// wrapping: one, and one more at each character Unicode makes a
    /// mandatory line break, a CR LF pair counting once. Written out here
    /// rather than through `is_hard_break`, so that a character missing from
    /// that list is not missing from the count as well.
    fn np_rows(text: &str) -> usize {
        1 + text
            .replace("\r\n", "\n")
            .chars()
            .filter(|c| {
                [
                    '\n', '\r', '\u{0B}', '\u{0C}', '\u{85}', '\u{2028}', '\u{2029}',
                ]
                .contains(c)
            })
            .count()
    }

    /// A long output is shown in part, with a note saying so, and copied
    /// whole; a short one is shown whole, with no note.
    ///
    /// The whole of it went into the output box, which Slint lays out on the
    /// event loop, all of it, on every repaint: a 64 MiB decrypted message,
    /// which a message of a few hundred bytes can expand to, froze the window
    /// for seconds at a time, and on the software renderer an output of about
    /// 144 KiB panicked. What is shown is cut, never what Copy copies.
    ///
    /// Lines are counted as the box breaks them, at every mandatory break and
    /// not at line feeds alone: 32,000 bytes of `x` and a lone carriage
    /// return, or of `x` and U+2028, fitted a cut that allowed 32 KiB and
    /// counted only line feeds, and was 16,000 or 8,000 rows, enough to panic
    /// that renderer.
    #[test]
    fn a_long_notepad_output_is_shown_in_part_and_copied_whole() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        ui.invoke_open_notepad();
        let decrypted = |output: &str| -> NpOutcome {
            Ok((output.to_string(), "Decrypted.".to_string(), 2, Vec::new()))
        };

        // Short lines, many of them; one long line; characters three bytes
        // long, so the cut falls inside one unless it is made at a boundary;
        // and short lines ended by each of the other mandatory breaks, and by
        // CR LF.
        let many_lines = "a line of an ordinary message\n".repeat(20_000);
        let one_line = "x".repeat(200_000);
        let wide = "€".repeat(100_000);
        let crlf = "a line\r\n".repeat(20_000);
        let mut outputs = vec![many_lines, one_line, wide];
        for other in ['\r', '\u{0B}', '\u{0C}', '\u{85}', '\u{2028}', '\u{2029}'] {
            outputs.push(format!("x{other}").repeat(8_000));
        }
        outputs.push(crlf.clone());
        for output in &outputs {
            finish_notepad(&ui, &state, decrypted(output));
            let shown = ui.get_np_output_shown().to_string();
            assert!(
                shown.len() <= NP_SHOWN_BYTES && np_rows(&shown) <= NP_SHOWN_LINES,
                "{} bytes and {} rows were given to the output box: {:?}…",
                shown.len(),
                np_rows(&shown),
                output.chars().take(4).collect::<String>()
            );
            assert!(!shown.is_empty() && output.starts_with(&shown));
            assert!(
                !ui.get_np_output_note().is_empty(),
                "the box shows only the start, and has to say so"
            );

            clipboard::record(true);
            ui.invoke_np_copy();
            assert_eq!(
                clipboard::recorded(),
                [(output.to_string(), clipboard::Content::Private)],
                "Copy has to copy the whole output"
            );
        }

        // A CR LF pair is one break, as Slint lays it out, so text written on
        // Windows is given as many lines as any other.
        finish_notepad(&ui, &state, decrypted(&crlf));
        assert_eq!(np_rows(&ui.get_np_output_shown()), NP_SHOWN_LINES);

        // As many lines as the box is given, the last one ended by a line
        // feed like the rest, are all shown, with no note saying otherwise.
        let exactly = "a line\n".repeat(NP_SHOWN_LINES);
        finish_notepad(&ui, &state, decrypted(&exactly));
        assert_eq!(ui.get_np_output_shown(), exactly.as_str());
        assert_eq!(ui.get_np_output_note(), "", "nothing was left out");

        finish_notepad(&ui, &state, decrypted("Short and sweet."));
        assert_eq!(ui.get_np_output_shown(), "Short and sweet.");
        assert_eq!(ui.get_np_output(), "Short and sweet.");
        assert_eq!(ui.get_np_output_note(), "");
    }

    /// On a screen scaled to two, the notepad's output box is given half as
    /// many lines and bytes, and Copy still copies all of it.
    ///
    /// The software renderer's limit is in physical pixels, and rows are
    /// twice as tall in them at that scale: in a nested sway scaled to two,
    /// the thousand short lines the box was then given at every scale took
    /// the app down.
    #[test]
    fn a_long_notepad_output_is_cut_shorter_on_a_screen_scaled_up() {
        i_slint_backend_testing::init_no_event_loop();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("certs.d"), dir.path().join("secrets")).unwrap();
        let state = state_for(store);
        let ui = window_for(&state);
        ui.window()
            .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged { scale_factor: 2.0 });
        assert_eq!(ui.window().scale_factor(), 2.0, "the premise");
        ui.invoke_open_notepad();

        let many_lines = "x\n".repeat(20_000);
        let one_line = "x".repeat(200_000);
        for output in [&many_lines, &one_line] {
            finish_notepad(
                &ui,
                &state,
                Ok((output.clone(), "Decrypted.".to_string(), 2, Vec::new())),
            );
            let shown = ui.get_np_output_shown().to_string();
            assert!(
                shown.len() <= NP_SHOWN_BYTES / 2 && np_rows(&shown) <= NP_SHOWN_LINES / 2,
                "{} bytes and {} rows were given to the output box at twice the scale",
                shown.len(),
                np_rows(&shown)
            );
            assert!(!shown.is_empty() && output.starts_with(&shown));
            assert!(!ui.get_np_output_note().is_empty());

            clipboard::record(true);
            ui.invoke_np_copy();
            assert_eq!(
                clipboard::recorded(),
                [(output.to_string(), clipboard::Content::Private)],
                "Copy has to copy the whole output"
            );
        }
    }

    /// However a text is crafted, the notepad's output box is given fewer rows
    /// than the software renderer can draw, at any scale, with room for a
    /// window then moved to a screen scaled half as much again; or three times
    /// as much, for a text in the box's own monospace.
    ///
    /// Nothing is laid out in a test, so the rows are counted for the two
    /// texts found to wrap into the most of them, as they wrapped in the real
    /// box: any number of empty lines, and then U+FDFD three to a row, drawn
    /// 127 pixels wide in Noto Sans Arabic, or words of 47 letters one to a
    /// row. In a nested sway, 32 KiB of the first took the app down at a scale
    /// factor of one, and 32 KiB of the second in a window moved from one to
    /// one and a quarter. With the cut as it is, a debug build went down only
    /// in a window moved from one to 1.75 with the first, and from one to
    /// three with the second.
    #[test]
    fn a_crafted_notepad_output_is_cut_to_rows_the_software_renderer_can_draw() {
        // Rows are 16.4 pixels apart at a scale factor of one, and a glyph
        // 32,767 physical pixels down the box panics that renderer.
        let (row, limit) = (16.4_f32, 32_767.0_f32);
        let long_word = format!("{} ", "m".repeat(47));
        let crafted = [
            ("\u{FDFD}\u{FDFD}\u{FDFD} ", 4, 1.5_f32),
            (long_word.as_str(), 48, 3.0),
        ];
        for (words, per_row, margin) in crafted {
            for scale in [1.0_f32, 1.25, 1.5, 2.0, 3.0] {
                for empty in 0..=NP_SHOWN_LINES {
                    let text = "\n".repeat(empty) + &words.repeat(NP_SHOWN_BYTES / words.len() + 1);
                    let shown = np_shown(&text, scale);
                    let rows: usize = shown
                        .split('\n')
                        .map(|line| line.chars().count().div_ceil(per_row).max(1))
                        .sum();
                    let reach = rows as f32 * row * scale;
                    assert!(
                        reach * margin < limit,
                        "{empty} empty lines and then {words:?} came to {rows} rows, \
                         {reach} pixels down at a scale of {scale}"
                    );
                }
            }
        }
    }
}
