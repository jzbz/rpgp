//! The clipboard behind the Copy buttons.
//!
//! Slint exposes no clipboard API, only a platform trait for backend authors
//! (slint-ui/slint#2570), so rPGP keeps a clipboard of its own. It is arboard
//! wherever arboard can be built, as it always was: through the data-control
//! protocols on a Wayland compositor that offers them to the app, through X11
//! (XWayland included) otherwise, and on Windows and macOS.
//!
//! A window on Wayland for which arboard cannot be built copies through
//! Slint's own clipboard instead, reached through a TextInput nobody sees
//! (`Copier` in ui/widgets.slint). In practice it is the Flatpak on a
//! compositor that withholds data-control from it: GNOME implements neither
//! protocol, and KDE Plasma and sway hide both from a sandboxed client.
//! arboard falls back to X11 there, which the Flatpak does not have on a
//! Wayland session, because `--socket=fallback-x11` grants X11 only where
//! there is no Wayland, so every Copy used to fail.
//!
//! On Wayland, Slint's clipboard is smithay-clipboard on the event loop's own
//! connection, over the core `wl_data_device` protocol, which every
//! compositor offers every client. Slint 1.17 copied that way, and 1.19 does
//! again; 1.18 gave its text fields arboard with nothing behind it, so until
//! 1.19 it is the patched winit backend the root Cargo.toml names. Going
//! through it, rather than through a smithay-clipboard of rPGP's own as the
//! Copy buttons once did, keeps the process to one `wl_data_device`, which is
//! all mutter serves: it keeps only a client's newest data device, and offers
//! the clipboard only to the devices there when the window took focus. With
//! the Copy buttons' second device, Slint's text fields could copy out but
//! not paste in, which is how the Flatpak shipped with Slint 1.17.1 behaved
//! on GNOME (measured on a nested mutter 51.1).
//!
//! What the notepad copies can be a decrypted message, so it goes out marked
//! private: with each platform's hint asking clipboard managers to leave it
//! out of their history (see [`Content::Private`]). A fingerprint or a user ID
//! from the details pane is public and goes out as any other copy does. The
//! mark only asks. It cannot stop a program reading the clipboard while the
//! text is on it, and Slint's clipboard cannot give it at all, which the
//! notepad then says. On X11 a private copy is taken back when the window
//! closes, if nothing has been copied over it since and the X server can show
//! that the clipboard is still rPGP's (see `withdraw`), rather than left for a
//! clipboard manager to keep. Nothing takes one back after a while, as a
//! password manager does with a password. History records a copy the moment
//! it is made, so a timer would not keep it out of that, and a message is
//! copied to be pasted somewhere, perhaps minutes later. Off X11 there is
//! also no telling whether the clipboard still holds the copy: arboard has no
//! way to say short of reading it back, which reads whatever the user has
//! copied since, from any program.
//!
//! The Wayland half, and the X11 withdrawal, exist only under
//! `cfg(wayland_target)`, which build.rs sets on the targets where a window
//! can be on Wayland. They are the targets where it can be on X11 as well.

use std::cell::RefCell;

use crate::AppWindow;

#[cfg(wayland_target)]
use {
    raw_window_handle::{HandleError, HasDisplayHandle, RawDisplayHandle},
    slint::ComponentHandle,
    std::cell::Cell,
    std::time::Duration,
};

/// The one clipboard for the process, not one per click.
///
/// On X11 arboard serves the selection from a window it owns, and dropping the
/// last handle destroys that window after a single 100ms attempt to hand the
/// contents to a clipboard manager — so a handle created and dropped inside a
/// callback loses the text immediately on any session without one running.
/// Through data-control arboard serves each copy from a thread and connection
/// of its own, which last until another client takes the selection, whatever
/// becomes of the handle.
enum Clipboard {
    /// There is no window to copy from: it has not been given its clipboard
    /// yet, or it has closed.
    NoWindow,
    /// A window on Wayland for which arboard could not be built: Slint's own
    /// clipboard, through the window's copier. Once settled on, it stays for
    /// as long as the window does.
    #[cfg(wayland_target)]
    Slint,
    /// arboard, built at the first copy, and again at the copy after one that
    /// failed; see [`attach`] for why not sooner.
    Arboard(Option<arboard::Clipboard>),
    /// Stands in for either in the tests, none of which has a display server:
    /// it keeps each copy and what it was asked to be, and marks a private one
    /// as arboard does, or leaves it unmarked as Slint's clipboard does.
    #[cfg(test)]
    Recording {
        copies: Vec<(String, Content)>,
        marks: bool,
    },
}

/// What a copy holds, as far as the desktop's clipboard managers are
/// concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    /// A fingerprint, a key ID or a user ID: public, and as welcome in a
    /// clipboard manager's history as anything else the user copies.
    Public,
    /// The notepad's output, which can be a decrypted message, and is marked
    /// with the platform's hint asking clipboard managers to leave it out of
    /// their history. Ciphertext and signed text are marked as well: which one
    /// the output holds is not tracked, and marking them costs nothing.
    ///
    /// On X11 and through data-control the mark is the
    /// `x-kde-passwordManagerHint` type, which KDE's Klipper honours, as do
    /// some other clipboard managers. On X11 it is also what `withdraw` looks
    /// for when the window closes, and what has arboard withdraw a copy
    /// rather than hand it to a clipboard manager when its last handle goes.
    /// On Windows it is `ExcludeClipboardContentFromMonitorProcessing`, which
    /// keeps a copy out of Windows' clipboard history and its cloud sync
    /// alike, and which arboard advises against combining with its narrower
    /// history and cloud marks. On macOS it is
    /// `org.nspasteboard.ConcealedType`, which the clipboard managers that
    /// follow nspasteboard.org's conventions honour.
    Private,
}

/// How a copy went, when it went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Copied {
    /// On the clipboard, marked private if it was asked to be.
    AsAsked,
    /// On the clipboard, but without the private mark it asked for, which
    /// Slint's clipboard has no way to give: it offers plain text alone.
    ///
    /// Only a window on Wayland goes through Slint's clipboard, so on Windows
    /// and macOS nothing makes this, and the notepad's arm for it is never
    /// taken. The arm stays rather than being gated as well, so that the
    /// notepad's handling of a copy reads the same on every platform.
    #[cfg_attr(
        not(any(wayland_target, test)),
        expect(
            dead_code,
            reason = "only Slint's clipboard, on Wayland, copies without the mark"
        )
    )]
    Unmarked,
}

thread_local! {
    // Both copy callbacks, and the close handler and the guard that empty it,
    // all run on the event loop's thread, so a thread-local is enough.
    static CLIPBOARD: RefCell<Clipboard> = const { RefCell::new(Clipboard::NoWindow) };
    // Whether the last copy that went through arboard was private and made
    // from a window on X11, and so whether `withdraw` may have a private copy
    // on the X11 clipboard to take back. Kept apart from CLIPBOARD so that it
    // outlives the arboard handle, which a failed copy drops, while the
    // private copy before it can still be on the clipboard.
    #[cfg(wayland_target)]
    static PRIVATE_COPY: Cell<bool> = const { Cell::new(false) };
}

/// Keeps the clipboard for as long as it lives; see [`attach`].
#[must_use = "the clipboard is dropped with this guard"]
pub struct Attached(());

impl Drop for Attached {
    fn drop(&mut self) {
        // Here rather than in the thread-local's destructor, which is not
        // guaranteed to run for the main thread and, where it does, runs at
        // exit in an order set by which thread-local was touched first.
        release();
    }
}

/// Let go of the clipboard, whichever kind it is, after taking a private copy
/// back off the X11 clipboard if one may still be there.
///
/// Dropping arboard's handle, where it copies through X11 and the handle is
/// the last in the process, makes the handover to a clipboard manager of a
/// public copy, which belongs where the window closes or the process exits
/// anyway, and withdraws a private one instead. Since Slint 1.18 it is never
/// the last on an X11 session, which is why `withdraw` exists; it is the last
/// for a window on Wayland whose copies went through XWayland, as Slint's
/// clipboard there is not arboard. Through data-control it holds nothing to
/// let go of, and Slint's clipboard is Slint's to let go of.
///
/// Where any of that talks to an X server, it runs on a thread of its own,
/// and the close waits for it for at most [`RELEASE_LIMIT`]; see [`within`].
fn release() {
    let clipboard = CLIPBOARD.with(|slot| slot.replace(Clipboard::NoWindow));
    #[cfg(wayland_target)]
    {
        let private = PRIVATE_COPY.take();
        if private || matches!(clipboard, Clipboard::Arboard(Some(_))) {
            // Whether it finished in time changes nothing here: the window
            // closes either way.
            let _ = within(RELEASE_LIMIT, move || {
                if private {
                    withdraw();
                }
                drop(clipboard);
            });
            return;
        }
    }
    drop(clipboard);
}

/// The longest a closing window waits for its clipboard to be let go of.
///
/// That is `withdraw`'s round trips to the X server and the answer from
/// arboard's thread, which put about 3 ms more between a close and the
/// window's unmapping on Xvfb, then arboard's own work as its last handle
/// goes, which waits up to 100 ms for a clipboard manager to take a public
/// copy. The limit is for an X server that has stopped answering, or that
/// another client keeps grabbed, either of which would otherwise hold the
/// window open for as long as it lasted.
#[cfg(wayland_target)]
const RELEASE_LIMIT: Duration = Duration::from_secs(1);

/// Run `work` on a thread of its own, and wait for it to finish for at most
/// `limit`: whether it did.
///
/// None of `release`'s work can be given a deadline of its own. x11rb waits
/// for a reply for as long as it takes, and arboard, as its last handle goes,
/// waits on the X server too and then joins its own thread. Past the limit
/// the work goes on until it finishes or the process exits, and `withdraw`'s
/// checks hold however late it runs. A thread that cannot be started drops
/// what `work` holds without running it, which leaves a private copy where it
/// is.
#[cfg(wayland_target)]
fn within(limit: Duration, work: impl FnOnce() + Send + 'static) -> bool {
    let (finished, done) = std::sync::mpsc::channel();
    let started = std::thread::Builder::new()
        .name("rpgp-clipboard".to_string())
        .spawn(move || {
            work();
            let _ = finished.send(());
        });
    started.is_ok() && done.recv_timeout(limit).is_ok()
}

/// Give `ui`'s window its clipboard, and keep it until the window closes or
/// the returned guard is dropped, whichever comes first.
///
/// Which clipboard it is gets settled at the first copy, not here. Only the
/// window's display handle says whether it is on Wayland, since a window can
/// be on XWayland with WAYLAND_DISPLAY set, and winit has not made the window
/// yet when this runs; by the time a Copy button can be pressed, it has.
/// Building arboard waits as well, since it connects to a display server,
/// which a launch that never copies anything has no need of.
///
/// The Copy buttons' smithay-clipboard could not wait: it had to be told the
/// window had focus, so it had to exist before the window took it, and a
/// timer built it, and arboard to decide whether it was needed, as soon as
/// the window existed. Slint's clipboard exists from the moment its event
/// loop does, and has seen the focus by the time a Copy button is pressed.
///
/// Call this before the event loop runs, and drop the guard before `run`
/// returns.
#[cfg(wayland_target)]
pub fn attach(ui: &AppWindow) -> Attached {
    CLIPBOARD.with(|slot| *slot.borrow_mut() = Clipboard::Arboard(None));

    // Let go of the clipboard as the window closes, which on X11 takes a
    // private copy back then rather than when the process gets round to
    // exiting. Nothing can be copied from a closed window. Slint keeps one
    // close handler per window, so this has to stay the only one.
    ui.window().on_close_requested(|| {
        release();
        slint::CloseRequestResponse::HideWindow
    });

    Attached(())
}

/// Give `ui`'s window its clipboard, and keep it until the returned guard is
/// dropped.
///
/// No window here can be on Wayland or X11, so the clipboard is arboard, built
/// on the first copy, and nothing has to be done as the window closes.
#[cfg(not(wayland_target))]
pub fn attach(_ui: &AppWindow) -> Attached {
    CLIPBOARD.with(|slot| *slot.borrow_mut() = Clipboard::Arboard(None));
    Attached(())
}

/// Whether a window with this display handle is on Wayland.
///
/// An error means winit has not made the window yet, which no Copy button can
/// be pressed before. It counts as not being on Wayland, so that the copy
/// reports why arboard could not be built rather than settling on Slint's
/// clipboard for a window whose display server is not known, and the next
/// copy asks again. Until winit has made it, Slint's handle falls back to
/// asking the window adapter, which the winit backend does not implement, so
/// the error is NotSupported rather than Unavailable.
#[cfg(wayland_target)]
fn on_wayland(display: Result<RawDisplayHandle, HandleError>) -> bool {
    matches!(display, Ok(RawDisplayHandle::Wayland(_)))
}

/// Whether a window with this display handle is on X11, XWayland included,
/// which is the only kind of window whose private copy `withdraw` takes back.
///
/// A window on Wayland needs nothing of it. Slint's clipboard there is
/// smithay-clipboard rather than arboard, so rPGP's arboard handle is the
/// only one in the process: where arboard copies through XWayland, dropping
/// it as the window closes has arboard take a private copy back itself, and
/// through data-control arboard serves each copy from a thread of its own,
/// which nothing on X11 can stand in for. Asking X11 anyway would connect to
/// DISPLAY as the window closes, which on a compositor that starts XWayland
/// only for its first client would start it, and keep the close waiting on
/// it, for nothing. A window whose display handle cannot be read counts as
/// on neither, and nothing is taken back for it.
#[cfg(wayland_target)]
fn on_x11(display: Result<RawDisplayHandle, HandleError>) -> bool {
    matches!(
        display,
        Ok(RawDisplayHandle::Xlib(_) | RawDisplayHandle::Xcb(_))
    )
}

/// Build arboard with `arboard`, or, for a window on Wayland for which that
/// fails, choose Slint's clipboard instead, which is `Ok(None)`.
///
/// `on_wayland` is asked only once arboard has failed, and arboard's error is
/// what comes back off Wayland, where arboard is all there is. Both are
/// closures so that the tests can stand in for arboard and for the window,
/// neither of which they can have without a display server.
#[cfg(wayland_target)]
fn build<A, E>(
    arboard: impl FnOnce() -> Result<A, E>,
    on_wayland: impl FnOnce() -> bool,
) -> Result<Option<A>, E> {
    match arboard() {
        Ok(arboard) => Ok(Some(arboard)),
        Err(_) if on_wayland() => Ok(None),
        Err(e) => Err(e),
    }
}

/// Where a copy went, or, for Slint's clipboard, has yet to go.
enum Step {
    Done(std::result::Result<Copied, String>),
    #[cfg(wayland_target)]
    ThroughSlint(String),
}

/// Put `text` on the clipboard of `ui`'s window, marked private if it is
/// [`Content::Private`] and the clipboard can mark it.
pub fn copy(
    #[cfg_attr(
        not(wayland_target),
        expect(
            unused_variables,
            reason = "only a window that can be on Wayland copies through Slint's clipboard"
        )
    )]
    ui: &AppWindow,
    text: String,
    content: Content,
) -> std::result::Result<Copied, String> {
    let step = CLIPBOARD.with(|slot| {
        let mut slot = slot.borrow_mut();
        match &mut *slot {
            // No Copy button can be pressed before its window exists or after
            // it has closed, so this is not expected.
            Clipboard::NoWindow => Step::Done(Err("there is no window to copy from".to_string())),
            #[cfg(wayland_target)]
            Clipboard::Slint => Step::ThroughSlint(text),
            Clipboard::Arboard(handle) => {
                #[cfg(wayland_target)]
                let display = || {
                    ui.window()
                        .window_handle()
                        .display_handle()
                        .map(|d| d.as_raw())
                };
                if handle.is_none() {
                    #[cfg(wayland_target)]
                    match build(arboard::Clipboard::new, || on_wayland(display())) {
                        Ok(Some(built)) => *handle = Some(built),
                        Ok(None) => {
                            *slot = Clipboard::Slint;
                            return Step::ThroughSlint(text);
                        }
                        Err(e) => return Step::Done(Err(e.to_string())),
                    }
                    #[cfg(not(wayland_target))]
                    match arboard::Clipboard::new() {
                        Ok(built) => *handle = Some(built),
                        Err(e) => return Step::Done(Err(e.to_string())),
                    }
                }
                // A clipboard that has stopped working — the X server went
                // away, say — is dropped so the next copy builds a fresh one
                // rather than failing forever. A copy that failed leaves on
                // the clipboard whatever was there, so only one that went
                // says whether a private copy is there now, and only one from
                // a window on X11 can be taken back at the close (see
                // `on_x11`).
                let result = set(handle.as_mut().expect("just populated"), text, content)
                    .map(|()| Copied::AsAsked)
                    .map_err(|e| e.to_string());
                match result {
                    #[cfg(wayland_target)]
                    Ok(_) => PRIVATE_COPY.set(content == Content::Private && on_x11(display())),
                    #[cfg(not(wayland_target))]
                    Ok(_) => {}
                    Err(_) => *handle = None,
                }
                Step::Done(result)
            }
            #[cfg(test)]
            Clipboard::Recording { copies, marks } => {
                copies.push((text, content));
                Step::Done(Ok(if *marks {
                    Copied::AsAsked
                } else {
                    unmarked(content)
                }))
            }
        }
    });
    match step {
        Step::Done(result) => result,
        // Out here, once the clipboard is no longer borrowed: the copier runs
        // Slint code, and nothing it sets off may find the clipboard borrowed.
        //
        // Nothing comes back: Slint hands the text to smithay-clipboard's
        // thread, which offers it to the compositor, and reports nothing if
        // that thread has stopped, as none of it is reported for Slint's own
        // text fields either. A copy of nothing sets nothing, but no Copy
        // button offers one.
        //
        // The text goes as plain text and nothing else, so a private copy
        // goes without its mark, and the caller is told. It still goes rather
        // than being refused, since nothing else would take it: Ctrl+C on the
        // notepad's output goes through this same clipboard.
        #[cfg(wayland_target)]
        Step::ThroughSlint(text) => {
            ui.invoke_copy_through_slint(text.into());
            Ok(unmarked(content))
        }
    }
}

/// How a copy of `content` went on a clipboard that cannot mark anything.
#[cfg(any(wayland_target, test))]
fn unmarked(content: Content) -> Copied {
    match content {
        Content::Public => Copied::AsAsked,
        Content::Private => Copied::Unmarked,
    }
}

/// Put `text` on arboard's clipboard, with the mark [`Content::Private`]
/// describes if it is private.
fn set(
    clipboard: &mut arboard::Clipboard,
    text: String,
    content: Content,
) -> std::result::Result<(), arboard::Error> {
    let set = clipboard.set();
    match content {
        Content::Public => set.text(text),
        Content::Private => mark_private(set).text(text),
    }
}

// Under the conditions arboard itself puts on each extension trait.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
fn mark_private(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtLinux;
    set.exclude_from_history()
}

#[cfg(windows)]
fn mark_private(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtWindows;
    set.exclude_from_monitoring()
}

#[cfg(target_os = "macos")]
fn mark_private(set: arboard::Set<'_>) -> arboard::Set<'_> {
    use arboard::SetExtApple;
    set.exclude_from_history()
}

/// Take rPGP's private copy back off the X11 clipboard if the clipboard still
/// holds it, so that no clipboard manager keeps it once the window is gone.
///
/// arboard does this itself as its last handle in the process is dropped. But
/// Slint 1.18's winit backend keeps two arboard handles of its own on an X11
/// session, its text fields' clipboard and primary selection, until the
/// process exits, and every handle in a process shares the one X11 clipboard,
/// so rPGP's is never the last any more. Slint 1.17's text fields had an X11
/// clipboard of their own, so rPGP's handle used to be the last. Measured on
/// Xvfb, watching from another process: without this, a private copy stayed
/// on the clipboard after rPGP's window had been unmapped and destroyed, and
/// went only as the process exited, about 20 ms later, when the thread-local
/// destructors dropped Slint's platform and with it the last arboard handle.
/// A process that outlived its window, or ended without running thread-local
/// destructors, would have left it there. With this it goes before the
/// window is unmapped.
///
/// Clearing the clipboard regardless would wipe whatever anyone has copied
/// since, so it is cleared only if all of this holds, asked on a connection of
/// this function's own:
/// - That connection is over a Unix-domain socket, so the X server is on this
///   machine and the kernel can tell it which process is at the other end. A
///   display reached over TCP is left alone, as is any display ssh -X or -Y
///   forwards, which sshd offers over TCP alone: what the X server sees
///   behind it is the ssh client, the same for every client forwarded through
///   it, rPGP and whatever else alike. A private copy there goes only as rPGP
///   exits, with the last arboard handle in the process.
/// - The X server names this process for that connection. It says which
///   process a client is through the X-Resource extension, and what it gives
///   is the process that opened the client's connection, as the kernel tells
///   the server. Through a forwarder on a Unix socket that is the forwarder,
///   again the same for every client it forwards, so a program forwarded
///   alongside rPGP would pass for rPGP and could have its copy wiped. So the
///   server's number for this connection has to be this process's own, and
///   where it is not, nothing is cleared: through such a forwarder; without
///   the extension, where the server names no process at all; and in a
///   sandbox with a PID namespace of its own, such as the Flatpak's, whose
///   numbers are not the server's. That leaves one case open: a forwarder on
///   a Unix socket in another PID namespace than rPGP's, whose number in the
///   server's namespace happens to be rPGP's in its own. A copy marked
///   private that another program made through that forwarder would then
///   pass for rPGP's.
/// - The window that owns the clipboard belongs to this process too, by the
///   server's account, which is then the kernel's. Nothing in rPGP but arboard
///   takes the clipboard, so that window is arboard's.
/// - What it holds is offered with the private mark. That tells rPGP's
///   private copy from a later Ctrl+C in one of Slint's text fields, which
///   goes through the same arboard, and so the same window, unmarked. Asking
///   reads the list of types offered and nothing else, and asks only this
///   process's own arboard.
/// - The owner is still the same when the clipboard is cleared, which is done
///   under a grab of the X server, so that no other client can take the
///   clipboard between the two.
///
/// Nothing of what was copied is read, from rPGP or from anyone else, and any
/// failure leaves the clipboard as it is. It runs only when the last copy
/// through arboard was private and made from a window on X11 (see
/// [`on_x11`]), so a window that never copied anything private, and any
/// window on Wayland, never connects to X11 for it. It runs on a thread of
/// its own, and the close waits for it for at most [`RELEASE_LIMIT`].
#[cfg(wayland_target)]
fn withdraw() {
    let Ok((connection, screen)) = x11rb::rust_connection::RustConnection::connect(None) else {
        return;
    };
    if !over_unix_socket(connection.stream()) {
        return;
    }
    let _ = withdraw_on(&connection, screen);
}

/// Whether `stream` is a Unix-domain socket, the only kind of connection to
/// the X server that [`withdraw`] goes on over. Not being able to tell counts
/// as not.
#[cfg(wayland_target)]
fn over_unix_socket(stream: impl std::os::fd::AsFd) -> bool {
    matches!(
        rustix::net::sockopt::socket_domain(stream),
        Ok(rustix::net::AddressFamily::UNIX)
    )
}

/// [`withdraw`]'s work on an open connection: whether it cleared the
/// clipboard, or why it could not tell.
#[cfg(wayland_target)]
fn withdraw_on(
    connection: &impl x11rb::connection::Connection,
    screen: usize,
) -> std::result::Result<bool, Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};
    use x11rb::protocol::Event;
    use x11rb::protocol::res::{ClientIdMask, ClientIdSpec, ConnectionExt as _};
    use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, CreateWindowAux, WindowClass};
    use x11rb::{COPY_DEPTH_FROM_PARENT, COPY_FROM_PARENT, CURRENT_TIME, NONE};

    let clipboard = connection.intern_atom(false, b"CLIPBOARD")?.reply()?.atom;
    let owner = connection.get_selection_owner(clipboard)?.reply()?.owner;
    if owner == NONE {
        return Ok(false);
    }

    // The process the X server has for the client that made `resource`, any
    // of that client's IDs naming the client.
    let process = |resource: u32| -> std::result::Result<Option<u32>, Box<dyn std::error::Error>> {
        let spec = ClientIdSpec {
            client: resource,
            mask: ClientIdMask::LOCAL_CLIENT_PID,
        };
        let reply = connection.res_query_client_ids(&[spec])?.reply()?;
        Ok(reply
            .ids
            .iter()
            .find(|id| id.spec.mask == ClientIdMask::LOCAL_CLIENT_PID)
            .and_then(|id| id.value.first().copied()))
    };
    let ours = process(connection.setup().resource_id_base)?;
    if !same_process(std::process::id(), ours, process(owner)?) {
        return Ok(false);
    }

    // Whether the owner, this process's arboard, offers the copy with the
    // private mark. Only interned if something has offered it, which arboard
    // does as it starts.
    let mark = connection
        .intern_atom(true, b"x-kde-passwordManagerHint")?
        .reply()?
        .atom;
    if mark == NONE {
        return Ok(false);
    }
    let targets = connection.intern_atom(false, b"TARGETS")?.reply()?.atom;
    let requestor = connection.generate_id()?;
    // Indexed with get: this runs on the clipboard thread as the window
    // closes, and nothing here should panic.
    let Some(root) = connection.setup().roots.get(screen).map(|s| s.root) else {
        return Ok(false);
    };
    connection.create_window(
        COPY_DEPTH_FROM_PARENT,
        requestor,
        root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_ONLY,
        COPY_FROM_PARENT,
        &CreateWindowAux::new(),
    )?;
    connection.convert_selection(requestor, clipboard, targets, targets, CURRENT_TIME)?;
    connection.flush()?;
    // arboard answers from a thread of its own, within milliseconds. The
    // limit is for an arboard whose thread has stopped, and costs the close
    // that long.
    let deadline = Instant::now() + Duration::from_millis(500);
    let answered = loop {
        match connection.poll_for_event()? {
            Some(Event::SelectionNotify(event)) if event.requestor == requestor => {
                break event.property != NONE;
            }
            Some(_) => {}
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
            None => break false,
        }
    };
    let marked = answered && {
        let reply = connection
            .get_property(true, requestor, targets, AtomEnum::ATOM, 0, 1024)?
            .reply()?;
        reply
            .value32()
            .is_some_and(|mut offered| offered.any(|atom| atom == mark))
    };
    connection.destroy_window(requestor)?;
    if !marked {
        return Ok(false);
    }

    // The grab is released with the connection should anything below fail.
    connection.grab_server()?;
    let still = connection.get_selection_owner(clipboard)?.reply()?.owner == owner;
    if still {
        connection.set_selection_owner(NONE, clipboard, CURRENT_TIME)?;
    }
    connection.ungrab_server()?;
    // A round trip, so that the server has done all of the above before the
    // connection closes.
    connection.get_input_focus()?.reply()?;
    Ok(still)
}

/// Whether the clipboard's owner is in this process, numbered `this`, from the
/// process the X server has for `withdraw`'s own connection and for the
/// owner's, where it knows one.
///
/// Its number for its own connection has to be `this`, not merely equal to
/// the owner's: a forwarder opens every connection it forwards, and then the
/// server gives its number for all of them.
#[cfg(wayland_target)]
fn same_process(this: u32, ours: Option<u32>, theirs: Option<u32>) -> bool {
    ours == Some(this) && theirs == Some(this)
}

/// Have [`copy`] record what it is given instead of copying it, marking a
/// private copy only if `marks` says to.
#[cfg(test)]
pub(crate) fn record(marks: bool) {
    CLIPBOARD.with(|slot| {
        *slot.borrow_mut() = Clipboard::Recording {
            copies: Vec::new(),
            marks,
        }
    });
}

/// Everything [`copy`] has recorded since [`record`], in order.
#[cfg(test)]
pub(crate) fn recorded() -> Vec<(String, Content)> {
    CLIPBOARD.with(|slot| match &*slot.borrow() {
        Clipboard::Recording { copies, .. } => copies.clone(),
        _ => panic!("the clipboard is not recording"),
    })
}

/// Have [`copy`] go through Slint's clipboard, as a window on Wayland does
/// when arboard cannot be built for it; on the testing backend, that is the
/// backend's own clipboard.
#[cfg(all(test, wayland_target))]
pub(crate) fn through_slint() {
    CLIPBOARD.with(|slot| *slot.borrow_mut() = Clipboard::Slint);
}

// Where no window can be on Wayland only the guard's test and the lockfile's
// run: the rest exists only where one can.
#[cfg(test)]
mod tests {
    use super::{CLIPBOARD, Clipboard, attach};
    use crate::AppWindow;
    use slint::ComponentHandle;
    #[cfg(wayland_target)]
    use {
        super::{build, on_wayland, on_x11, over_unix_socket, same_process, within},
        raw_window_handle::{
            HandleError, RawDisplayHandle, WaylandDisplayHandle, XcbDisplayHandle,
            XlibDisplayHandle,
        },
        std::cell::Cell,
        std::ptr::NonNull,
    };

    /// Stands in for arboard's handle, which no test can build without a
    /// display server.
    #[cfg(wayland_target)]
    const ARBOARD: &str = "arboard";

    /// A display handle tells a window on Wayland from one on anything else,
    /// and one winit has not made yet counts as anything else.
    ///
    /// A window winit has not made yet reports NotSupported, and settling on
    /// Slint's clipboard for it would settle for a window whose display
    /// server is not known.
    #[cfg(wayland_target)]
    #[test]
    fn a_display_handle_tells_a_wayland_window_from_any_other() {
        // Never dereferenced: on_wayland only looks at which kind it is.
        let display = NonNull::dangling();
        let wayland = RawDisplayHandle::Wayland(WaylandDisplayHandle::new(display));
        assert!(
            on_wayland(Ok(wayland)),
            "a window on Wayland must be told apart"
        );

        let xlib = RawDisplayHandle::Xlib(XlibDisplayHandle::new(None, 0));
        assert!(!on_wayland(Ok(xlib)));
        let xcb = RawDisplayHandle::Xcb(XcbDisplayHandle::new(None, 0));
        assert!(!on_wayland(Ok(xcb)));

        assert!(
            !on_wayland(Err(HandleError::NotSupported)),
            "a window winit has not made yet must not be taken for one on Wayland"
        );
        assert!(!on_wayland(Err(HandleError::Unavailable)));
    }

    /// Only a window on X11 has its private copy taken back by `withdraw`,
    /// and one whose display handle cannot be read is not taken for one.
    ///
    /// On Wayland arboard takes its own copy back, or serves it from a thread
    /// of its own, and asking X11 at the close would connect to DISPLAY for
    /// nothing.
    #[cfg(wayland_target)]
    #[test]
    fn only_a_window_on_x11_has_its_private_copy_taken_back_at_the_close() {
        let xlib = RawDisplayHandle::Xlib(XlibDisplayHandle::new(None, 0));
        assert!(on_x11(Ok(xlib)));
        let xcb = RawDisplayHandle::Xcb(XcbDisplayHandle::new(None, 0));
        assert!(on_x11(Ok(xcb)));

        // Never dereferenced: on_x11 only looks at which kind it is.
        let wayland = RawDisplayHandle::Wayland(WaylandDisplayHandle::new(NonNull::dangling()));
        assert!(
            !on_x11(Ok(wayland)),
            "a window on Wayland must never have X11 asked about its copies"
        );
        assert!(!on_x11(Err(HandleError::NotSupported)));
        assert!(!on_x11(Err(HandleError::Unavailable)));
    }

    /// A window on Wayland keeps arboard wherever arboard can be built, and
    /// is not asked where it is.
    ///
    /// That is wherever Copy has always worked: through data-control where
    /// the compositor offers it, and through XWayland where it does not.
    /// Only arboard can mark a private copy there.
    #[cfg(wayland_target)]
    #[test]
    fn a_wayland_window_keeps_arboard_wherever_arboard_can_be_built() {
        let asked = Cell::new(false);
        let built = build(
            || Ok::<_, ()>(ARBOARD),
            || {
                asked.set(true);
                true
            },
        );
        assert_eq!(
            built,
            Ok(Some(ARBOARD)),
            "a window on Wayland must keep an arboard that could be built"
        );
        assert!(
            !asked.get(),
            "with arboard built, where the window is is moot"
        );
    }

    /// A window on Wayland for which arboard cannot be built copies through
    /// Slint's clipboard.
    ///
    /// That is the Flatpak on a compositor that withholds data-control from
    /// it, where arboard's X11 fallback has no X server to reach. Before, it
    /// was given a smithay-clipboard of rPGP's own, a second data device
    /// that cost Slint's text fields their paste on GNOME.
    #[cfg(wayland_target)]
    #[test]
    fn a_wayland_window_copies_through_slints_clipboard_where_arboard_cannot_be_built() {
        assert_eq!(
            build(|| Err::<&str, _>("no data-control and no X11"), || true),
            Ok(None),
            "a window on Wayland without arboard must copy through Slint's clipboard"
        );
    }

    /// Any other window reports why arboard cannot be built.
    ///
    /// arboard is all there is off Wayland: Slint's own clipboard there is
    /// arboard too. The slot stays empty, so the next Copy builds it again
    /// and reports why it cannot, as a Copy after any failure does.
    #[cfg(wayland_target)]
    #[test]
    fn any_other_window_reports_why_arboard_cannot_be_built() {
        assert_eq!(
            build(|| Err::<&str, _>("no X server"), || false),
            Err("no X server")
        );
        assert_eq!(build(|| Ok::<_, ()>(ARBOARD), || false), Ok(Some(ARBOARD)));
    }

    /// The X11 clipboard is only ever cleared for an owner the X server
    /// numbers as this process, and only where it numbers `withdraw`'s own
    /// connection as this process too.
    ///
    /// Two clients through one forwarder, as with ssh -X, both get the
    /// forwarder's number, and two the server cannot number, as over TCP,
    /// would both be None: either way they would compare equal, and anyone's
    /// copy could be wiped.
    #[cfg(wayland_target)]
    #[test]
    fn only_an_owner_the_x_server_numbers_as_this_process_counts_as_this_one() {
        const THIS: u32 = 4242;
        assert!(same_process(THIS, Some(THIS), Some(THIS)));
        assert!(!same_process(THIS, Some(THIS), Some(4243)));
        assert!(!same_process(THIS, Some(THIS), None));
        assert!(
            !same_process(THIS, Some(777), Some(777)),
            "a forwarder's number, the same for every client it forwards, is not this process's"
        );
        assert!(
            !same_process(2, Some(THIS), Some(THIS)),
            "inside a PID namespace the server's numbers are not this process's"
        );
        assert!(!same_process(THIS, None, Some(THIS)));
        assert!(
            !same_process(THIS, None, None),
            "two processes the X server cannot name are not this one"
        );
    }

    /// `over_unix_socket`, which `withdraw` asks right after connecting, counts
    /// a Unix-domain socket as local and a TCP one, as with ssh -X, as not.
    ///
    /// sshd offers a forwarded display over TCP alone, and behind it the X
    /// server sees the ssh client for every client forwarded through it, which
    /// could pass the process check whenever the ssh client's number on one
    /// machine was rPGP's on the other, and have another program's private
    /// copy wiped. The Unix socket is wrapped as x11rb wraps the one it
    /// connects over. The TCP socket needs no network to tell, and none to be
    /// made: it is never connected. This checks the predicate only; that
    /// `withdraw` returns on its answer was checked against a live X server,
    /// where taking the check out let a forwarded program's copy be wiped.
    #[cfg(wayland_target)]
    #[test]
    fn only_a_unix_domain_socket_counts_as_local() {
        use rustix::net::{AddressFamily, SocketType};
        use x11rb::rust_connection::DefaultStream;

        let (unix, _peer) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
        let (unix, _) = DefaultStream::from_unix_stream(unix).expect("x11rb wraps a Unix socket");
        assert!(
            over_unix_socket(&unix),
            "a connection over a Unix-domain socket must go on to the process check"
        );

        let tcp = rustix::net::socket(AddressFamily::INET, SocketType::STREAM, None)
            .expect("a TCP socket");
        assert!(
            !over_unix_socket(&tcp),
            "a connection over TCP, as ssh -X forwards a display, must be left alone"
        );
        // IPv6 can be compiled out of a kernel, or turned off at boot.
        if let Ok(tcp6) = rustix::net::socket(AddressFamily::INET6, SocketType::STREAM, None) {
            assert!(!over_unix_socket(&tcp6));
        }
    }

    /// Letting go of the clipboard holds a closing window for no longer than
    /// the limit, however long the work takes, and the work still finishes.
    ///
    /// The work stands in for `withdraw` waiting on an X server that does not
    /// answer, which x11rb would wait on for as long as it took.
    #[cfg(wayland_target)]
    #[test]
    fn letting_go_of_the_clipboard_holds_the_close_for_no_longer_than_the_limit() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let (answer, answered) = mpsc::channel::<()>();
        let (finish, finished) = mpsc::channel();
        let start = Instant::now();
        // Waiting at most 10 s, so that a `within` that waited for the work
        // itself fails the assertions below rather than hanging the test.
        let in_time = within(Duration::from_millis(50), move || {
            let _ = answered.recv_timeout(Duration::from_secs(10));
            let _ = finish.send(());
        });
        let waited = start.elapsed();
        assert!(!in_time, "work still waiting must not count as finished");
        assert!(
            (Duration::from_millis(50)..Duration::from_secs(5)).contains(&waited),
            "the close must wait for the limit and no longer, not {waited:?}"
        );

        answer.send(()).expect("the work is still waiting");
        finished
            .recv_timeout(Duration::from_secs(5))
            .expect("the work must go on past the limit");
        assert!(
            within(Duration::from_secs(5), || {}),
            "work that finishes in time must count as finished"
        );
    }

    /// A close request lets go of the clipboard, and still closes the window.
    ///
    /// The close handler is where a private copy is taken back off the X11
    /// clipboard, as the window closes. The testing backend has no display,
    /// so an arboard slot stands in for whatever the first copy would have
    /// chosen; letting go does not depend on the kind.
    #[cfg(wayland_target)]
    #[test]
    fn a_close_request_lets_go_of_the_clipboard_and_still_closes_the_window() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("the window builds on the testing backend");
        ui.show().expect("the testing backend shows a window");
        let _attached = attach(&ui);
        assert!(
            CLIPBOARD.with(|slot| matches!(*slot.borrow(), Clipboard::Arboard(None))),
            "a shown window has a clipboard to settle at its first copy"
        );

        ui.window()
            .dispatch_event(slint::platform::WindowEvent::CloseRequested);

        assert!(
            CLIPBOARD.with(|slot| matches!(*slot.borrow(), Clipboard::NoWindow)),
            "the close request must let go of the clipboard"
        );
        assert!(
            !ui.window().is_visible(),
            "letting go of the clipboard must not keep the window open"
        );
    }

    /// Dropping the guard lets go of the clipboard, with no close request.
    ///
    /// That is how `run` lets go of it when winit's run fails or a panic
    /// unwinds through the event loop, when no close request comes.
    #[test]
    fn dropping_the_guard_lets_go_of_the_clipboard_without_a_close_request() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("the window builds on the testing backend");
        ui.show().expect("the testing backend shows a window");
        let attached = attach(&ui);

        drop(attached);

        assert!(
            CLIPBOARD.with(|slot| matches!(*slot.borrow(), Clipboard::NoWindow)),
            "dropping the guard must let go of the clipboard"
        );
    }

    /// Slint's winit backend is the patched one under vendor/ for as long as
    /// rPGP is on Slint 1.18, and the patch is gone once it is on 1.19.
    ///
    /// cargo applies a [patch] only while the graph asks for the very version
    /// it names, and otherwise warns and records it in Cargo.lock as
    /// `[[patch.unused]]`. A slint that moved to a 1.18.x without
    /// slint-ui/slint#14248 would quietly take copy and paste out of the
    /// Flatpak's text fields again, which this catches on top of the =1.18.1
    /// pins. Only `[[package]]` tables count as the package: an unused patch's
    /// table also names the crate with no source line. On 1.19, which carries
    /// the fix itself, it fails until vendor/ and the [patch] are gone, as
    /// the root Cargo.toml asks.
    #[test]
    fn the_winit_backend_is_the_patched_one_until_slint_1_19() {
        let lock = include_str!("../../../Cargo.lock");
        let tables = lock_tables(lock);
        let packages = |name: &str| -> Vec<&LockTable> {
            tables
                .iter()
                .filter(|table| table.kind == "package" && table.name == name)
                .collect()
        };
        let unused = tables
            .iter()
            .any(|table| table.kind == "patch.unused" && table.name == "i-slint-backend-winit");

        let slint = packages("slint");
        assert_eq!(slint.len(), 1, "expected one slint in Cargo.lock");
        let mut version = slint[0].version.split('.').map(|part| part.parse::<u32>());
        let (major, minor) = match (version.next(), version.next()) {
            (Some(Ok(major)), Some(Ok(minor))) => (major, minor),
            _ => panic!("slint's version in Cargo.lock reads {:?}", slint[0].version),
        };
        let winit = packages("i-slint-backend-winit");
        assert_eq!(
            winit.len(),
            1,
            "expected one i-slint-backend-winit in Cargo.lock"
        );

        if (major, minor) < (1, 19) {
            assert!(
                !unused,
                "Cargo.lock records the patched winit backend under vendor/ as unused, so the \
                 graph has crates.io's, without slint-ui/slint#14248, and the Flatpak's text \
                 fields cannot copy or paste: the patch has to be the very version slint {} \
                 asks for",
                slint[0].version
            );
            assert_eq!(
                (winit[0].version, winit[0].source),
                ("1.18.1", None),
                "i-slint-backend-winit must be the patched crate under vendor/, not crates.io's"
            );
        } else {
            let vendored = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../vendor/i-slint-backend-winit");
            assert!(
                !unused && !vendored.exists(),
                "slint {} carries slint-ui/slint#14248 itself: delete vendor/ and the root \
                 Cargo.toml's [patch.crates-io] table with the comment above it; delete this \
                 test with the LockTable and lock_tables helpers only it uses, and its \
                 mention in the comment over this tests module; turn the three =1.18.1 pins \
                 in crates/rpgp-gui/Cargo.toml (slint, i-slint-backend-testing, slint-build) \
                 back into plain 1.19 requirements, and take out the comments there that \
                 explain the pins; reword the sentence in this file's module doc that says \
                 Slint's clipboard is the patched winit backend until 1.19; and remove the \
                 vendor/ paragraph from README.md's Licence section and the vendor/ mention \
                 in packaging/cargo-sources.py",
                slint[0].version
            );
        }
    }

    /// One `[[...]]` table of Cargo.lock, with the fields the lockfile test
    /// reads.
    struct LockTable<'a> {
        kind: &'a str,
        name: &'a str,
        version: &'a str,
        source: Option<&'a str>,
    }

    /// The `[[package]]` and `[[patch.unused]]` tables of a lockfile, read
    /// line by line, which is all its format needs.
    fn lock_tables(lock: &str) -> Vec<LockTable<'_>> {
        let mut tables: Vec<LockTable<'_>> = Vec::new();
        for line in lock.lines() {
            if let Some(kind) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
                tables.push(LockTable {
                    kind,
                    name: "",
                    version: "",
                    source: None,
                });
                continue;
            }
            let (Some(table), Some((key, value))) = (tables.last_mut(), line.split_once(" = "))
            else {
                continue;
            };
            let value = value.trim_matches('"');
            match key {
                "name" => table.name = value,
                "version" => table.version = value,
                "source" => table.source = Some(value),
                _ => {}
            }
        }
        tables
    }
}
