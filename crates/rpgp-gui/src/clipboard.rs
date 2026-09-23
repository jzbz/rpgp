//! The clipboard behind the Copy buttons.
//!
//! Slint exposes no clipboard API, only a platform trait for backend authors,
//! so rPGP keeps a clipboard of its own. It is arboard wherever arboard can be
//! built, as it always was: through the data-control protocols on a Wayland
//! compositor that offers them to the app, through X11 (XWayland included)
//! otherwise, and on Windows and macOS.
//!
//! A window on Wayland for which arboard cannot be built copies through
//! smithay-clipboard instead, on the window's own connection, over the core
//! `wl_data_device` protocol. That is how Slint's own text fields copy, and
//! every compositor offers it to every client. In practice it is the Flatpak
//! on a compositor that withholds data-control from it: GNOME implements
//! neither protocol, and sway hides both from any client in a Flatpak.
//! arboard falls back to X11 there, which the Flatpak does not have on a
//! Wayland session, because `--socket=fallback-x11` grants X11 only where
//! there is no Wayland, so every Copy used to fail.
//!
//! smithay-clipboard comes second rather than first because it needs what
//! arboard does not: its own keyboard to have been told the window has focus,
//! and the serial of a key or pointer button event (see [`attach`]). Wherever
//! arboard can be built, Copy works as it did before smithay-clipboard came
//! in, and smithay-clipboard's gaps are confined to where every Copy failed.
//!
//! The Wayland half exists only under `cfg(wayland_target)`, which build.rs
//! sets on the targets where a window can be on Wayland.

use std::cell::RefCell;

use crate::AppWindow;

#[cfg(wayland_target)]
use {
    raw_window_handle::{HandleError, HasDisplayHandle, RawDisplayHandle},
    slint::ComponentHandle,
    std::ffi::c_void,
    std::ptr::NonNull,
    std::rc::Rc,
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
/// becomes of the handle. smithay-clipboard serves it from a thread of its
/// own, which stops when the handle is dropped, so there rPGP serves the text
/// only while the handle lives.
enum Clipboard {
    /// There is no window to copy from. Either the windowing system has not
    /// created it yet, so which display server it is on is not known yet
    /// either, or it has closed.
    NoWindow,
    /// A window on Wayland for which arboard could not be built; see
    /// [`attach`] for why this handle is safe to hold.
    #[cfg(wayland_target)]
    Wayland(smithay_clipboard::Clipboard),
    /// Every other window: one on Wayland for which arboard could be built,
    /// and one on anything else, whether it could or not. Where a window can
    /// be on Wayland, [`attach`] builds it as soon as the window exists;
    /// elsewhere the first copy does. After a failure, the next copy builds
    /// it again.
    Arboard(Option<arboard::Clipboard>),
}

thread_local! {
    // Both copy callbacks, the timer in `attach` that fills this, and the
    // close handler and the guard that empty it all run on the event loop's
    // thread, so a thread-local is enough.
    static CLIPBOARD: RefCell<Clipboard> = const { RefCell::new(Clipboard::NoWindow) };
}

/// Keeps the clipboard for as long as it lives; see [`attach`].
#[must_use = "the clipboard is dropped with this guard"]
pub struct Attached {
    #[cfg(wayland_target)]
    _wait: Rc<slint::Timer>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        // Here rather than in the thread-local's destructor, which is not
        // guaranteed to run for the main thread and, where it does, runs at
        // exit in an order set by which thread-local was touched first.
        release();
    }
}

/// Let go of the clipboard, whichever kind it is.
///
/// Dropping smithay-clipboard's handle tells its thread to stop and joins it.
/// Dropping arboard's, where it copies through X11, makes the handover to a
/// clipboard manager, which belongs where the window closes or the process
/// exits anyway; through data-control it holds nothing to let go of.
fn release() {
    let clipboard = CLIPBOARD.with(|slot| slot.replace(Clipboard::NoWindow));
    drop(clipboard);
}

/// Choose the clipboard for `ui`'s window once the windowing system has
/// created it, and keep it until the window closes or the returned guard is
/// dropped, whichever comes first.
///
/// The choice waits for the window because only its display handle says which
/// display server it is on. WAYLAND_DISPLAY does not: a window can be on
/// XWayland with it set. Nothing tells the application when winit has created
/// the window, which happens in a later turn of the event loop than `show`,
/// and up to half a second later while Slint waits on the desktop portal for
/// the colour scheme, so a timer asks until there is an answer, then stops.
///
/// With the answer the timer builds arboard, and keeps it wherever that
/// works, whatever the display server. Where it does not, a window on Wayland
/// gets smithay-clipboard, and any other window an empty arboard slot, so that
/// the first Copy tries again and reports why it cannot, as every Copy after
/// a failure always has.
///
/// The choice is not revisited. A Copy that fails through arboard later on,
/// once the X server behind XWayland has gone, say, reports that, and the
/// next Copy builds arboard again, as before. Moving a window on Wayland to
/// smithay-clipboard then would build it inside a Copy, which is too late for
/// that Copy, for the reasons below, and would trade a failure that is
/// reported for gaps that are not.
///
/// None of this can wait for the first Copy. Whether smithay-clipboard is
/// needed is known only once arboard has been tried, and smithay-clipboard
/// offers the selection with the serial of the last key or pointer button
/// event its own seat listeners saw, and only once its own keyboard listener
/// has been told the window has focus. One created inside a Copy callback has
/// seen neither, and silently sets nothing. It takes no serial from touch
/// events, so a Copy tapped on a touchscreen offers whatever serial came
/// before, and on a seat with no keyboard sets nothing at all.
///
/// Nor can smithay-clipboard count on being there by the time the window
/// takes focus. The first frame can map the window, and the compositor focus
/// it, before the timer next runs, and asking every millisecond does not
/// change that. It is an ordinary start rather than an edge case, and a Copy
/// then rests on the compositor telling a keyboard created while its client
/// already has focus that it has it. mutter and KWin do; wlroots does only
/// while the seat has an active keyboard. On a wlroots seat with none, which
/// is how sway leaves a seat whose active keyboard was removed, every Copy
/// reports success and sets nothing until the window next takes focus.
///
/// Trying arboard costs the event loop once what the first Copy used to cost
/// it, now paid at start whether or not anything is ever copied. With
/// WAYLAND_DISPLAY set that is a data-control probe, a round trip or two on a
/// connection of its own that is closed again, and without data-control, or
/// WAYLAND_DISPLAY, an X11 connection and the thread that serves it. With no
/// X server that fails at once: before any I/O with DISPLAY unset, as in the
/// Flatpak on a Wayland session, and on refused connections with DISPLAY
/// naming a local display nothing serves.
///
/// Call this before the event loop runs, and drop the guard before `run`
/// returns.
#[cfg(wayland_target)]
pub fn attach(ui: &AppWindow) -> Attached {
    let wait = Rc::new(slint::Timer::default());
    let (weak_ui, stop) = (ui.as_weak(), Rc::downgrade(&wait));
    wait.start(
        slint::TimerMode::Repeated,
        Duration::from_millis(10),
        move || {
            let Some(ui) = weak_ui.upgrade() else {
                return;
            };
            let handle = ui.window().window_handle();
            let route = route(handle.display_handle().map(|d| d.as_raw()));
            let clipboard = match choose(route, arboard::Clipboard::new) {
                Choice::Wait => return,
                Choice::Arboard(arboard) => Clipboard::Arboard(arboard),
                // SAFETY: smithay-clipboard needs this `wl_display` to stay
                // valid for as long as the handle lives. It is the display of
                // the connection winit opened: its Wayland window hands out
                // that connection's own display object as the display handle
                // (winit 0.30, wayland/window/mod.rs). winit opened the
                // connection rather than adopting one, so wayland-backend
                // disconnects it, freeing the display, only when the last
                // clone of the connection is dropped (0.3, the sys client's
                // ConnectionState::drop). winit's event loop holds one clone,
                // and the state of each winit window another
                // (wayland/window/state.rs).
                //
                // The window's clone is the one this rests on. The event
                // loop's is not enough: Slint's winit backend puts the event
                // loop back in its platform, a thread-local that lasts until
                // exit, when winit's run returns normally, but drops it when
                // winit's run fails or a panic unwinds through it
                // (i-slint-backend-winit 1.17, EventLoopState::run). The
                // window exists now, since this handle came from it, and
                // lasts until Slint hides it, which on Wayland destroys it
                // (the adapter's set_visibility). Nothing in rPGP hides it,
                // so while the event loop runs only a close request does,
                // and the close handler below lets go of this handle first.
                // AppWindow::run hides the window itself only once the loop
                // has returned normally, by which time the event loop is back
                // in the platform. On an error or an unwind it skips that, so
                // the window, which `ui` holds in `run`, is still there when
                // the guard lets go of this handle on the way out. Either way
                // this handle, and the thread using the display, are gone
                // before the display is. A process killed or aborted runs no
                // destructors, so it disconnects nothing.
                Choice::Wayland(display) => Clipboard::Wayland(unsafe {
                    smithay_clipboard::Clipboard::new(display.as_ptr())
                }),
            };
            CLIPBOARD.with(|slot| *slot.borrow_mut() = clipboard);
            if let Some(wait) = stop.upgrade() {
                wait.stop();
            }
        },
    );

    // Let go of the clipboard, whichever kind it is, as the window closes and
    // before Slint hides it, which on Wayland destroys it: see the SAFETY
    // comment above for why that order matters. Nothing can be copied from a
    // closed window, and there is no window left to choose a clipboard for, so
    // the timer stops as well if it is still asking. Slint keeps one close
    // handler per window, so this has to stay the only one.
    let stop = Rc::downgrade(&wait);
    ui.window().on_close_requested(move || {
        if let Some(wait) = stop.upgrade() {
            wait.stop();
        }
        release();
        slint::CloseRequestResponse::HideWindow
    });

    Attached { _wait: wait }
}

/// Choose the clipboard for `ui`'s window, and keep it until the returned
/// guard is dropped.
///
/// No window here can be on Wayland, so the choice is arboard from the start,
/// built on the first copy, and nothing has to be let go of before the window
/// closes.
#[cfg(not(wayland_target))]
pub fn attach(_ui: &AppWindow) -> Attached {
    CLIPBOARD.with(|slot| *slot.borrow_mut() = Clipboard::Arboard(None));
    Attached {}
}

/// What a window's display handle says about it.
#[cfg(wayland_target)]
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// No answer yet: winit has not created the window.
    Wait,
    /// The window is on Wayland, through this `wl_display`.
    Wayland(NonNull<c_void>),
    /// The window is on anything else, which on these targets is X11,
    /// XWayland included.
    Other,
}

#[cfg(wayland_target)]
fn route(display: Result<RawDisplayHandle, HandleError>) -> Route {
    match display {
        Ok(RawDisplayHandle::Wayland(wayland)) => Route::Wayland(wayland.display),
        Ok(_) => Route::Other,
        // Every error means the window does not exist yet, whichever error it
        // is. Until winit has created it, Slint's handle falls back to asking
        // the window adapter, which the winit backend does not implement, so
        // it reports NotSupported rather than Unavailable. Settling then would
        // take a window about to appear on Wayland for one that is not, and
        // leave the Flatpak's window with only the arboard that fails there.
        Err(_) => Route::Wait,
    }
}

/// What the timer in [`attach`] settles on, if anything.
#[cfg(wayland_target)]
#[derive(Debug, PartialEq, Eq)]
enum Choice<A> {
    /// Ask again: winit has not created the window.
    Wait,
    /// arboard, built, or left for the first copy to build.
    Arboard(Option<A>),
    /// smithay-clipboard, on the window's own connection through this
    /// `wl_display`.
    Wayland(NonNull<c_void>),
}

/// Choose between arboard and smithay-clipboard for a window on `route`, from
/// what building arboard gives.
///
/// `arboard` builds it, and is called only once the route is known: while the
/// timer waits it would otherwise open and close a connection every tick. The
/// handle is generic so that the tests can stand in for arboard, which none of
/// them can build without a display server.
#[cfg(wayland_target)]
fn choose<A, E>(route: Route, arboard: impl FnOnce() -> Result<A, E>) -> Choice<A> {
    match route {
        Route::Wait => Choice::Wait,
        Route::Wayland(display) => match arboard() {
            Ok(arboard) => Choice::Arboard(Some(arboard)),
            Err(_) => Choice::Wayland(display),
        },
        // arboard is all there is off Wayland, so its error is not kept: the
        // first copy builds it again and reports what it gets then.
        Route::Other => Choice::Arboard(arboard().ok()),
    }
}

/// Put `text` on the clipboard chosen by [`attach`].
pub fn copy(text: String) -> std::result::Result<(), String> {
    CLIPBOARD.with(|slot| match &mut *slot.borrow_mut() {
        // No Copy button can be pressed before its window exists or after it
        // has closed, so this is not expected. It is refused rather than
        // handed to arboard because the window may yet turn out to be on
        // Wayland, with no arboard to be had.
        Clipboard::NoWindow => Err("there is no window to copy from".to_string()),
        #[cfg(wayland_target)]
        Clipboard::Wayland(clipboard) => {
            // Nothing comes back: this hands the text to smithay-clipboard's
            // thread, which offers it to the compositor, or drops it if it has
            // not been told the window has focus (see `attach`). If that
            // thread has stopped, as it does when its connection fails, or
            // when a store finds the seat's keyboard gone while it still
            // believes the window has focus, which panics it, nothing receives
            // the text, and this and every later Copy set nothing. None of it
            // is reported, as none of it is for Slint's own text fields.
            clipboard.store(text);
            Ok(())
        }
        Clipboard::Arboard(handle) => {
            if handle.is_none() {
                *handle = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
            }
            // A clipboard that has stopped working — the X server went away,
            // say — is dropped so the next copy builds a fresh one rather than
            // failing forever.
            let result = handle
                .as_mut()
                .expect("just populated")
                .set_text(text)
                .map_err(|e| e.to_string());
            if result.is_err() {
                *handle = None;
            }
            result
        }
    })
}

// Where no window can be on Wayland only the guard's test runs: the choice and
// the close handler exist only where one can.
#[cfg(test)]
mod tests {
    use super::{CLIPBOARD, Clipboard, attach};
    use crate::AppWindow;
    use slint::ComponentHandle;
    #[cfg(wayland_target)]
    use {
        super::{Choice, Route, choose, route},
        raw_window_handle::{
            HandleError, RawDisplayHandle, WaylandDisplayHandle, XcbDisplayHandle,
            XlibDisplayHandle,
        },
        std::cell::Cell,
        std::ffi::c_void,
        std::ptr::NonNull,
    };

    /// Stands in for arboard's handle, which no test can build without a
    /// display server.
    #[cfg(wayland_target)]
    const ARBOARD: &str = "arboard";

    /// A display handle tells a window on Wayland from one on anything else,
    /// and a window that does not exist yet has no answer to give.
    ///
    /// A window winit has not created yet reports NotSupported, so settling on
    /// anything for an error would choose for a window whose display server is
    /// not known.
    #[cfg(wayland_target)]
    #[test]
    fn a_display_handle_tells_a_wayland_window_from_any_other_and_an_error_waits() {
        // Never dereferenced: route only passes it along.
        let display = NonNull::<c_void>::dangling();
        let wayland = RawDisplayHandle::Wayland(WaylandDisplayHandle::new(display));
        assert_eq!(
            route(Ok(wayland)),
            Route::Wayland(display),
            "a window on Wayland must be told apart, with its own connection"
        );

        let xlib = RawDisplayHandle::Xlib(XlibDisplayHandle::new(None, 0));
        assert_eq!(route(Ok(xlib)), Route::Other);
        let xcb = RawDisplayHandle::Xcb(XcbDisplayHandle::new(None, 0));
        assert_eq!(route(Ok(xcb)), Route::Other);

        assert_eq!(
            route(Err(HandleError::NotSupported)),
            Route::Wait,
            "a window winit has not created yet must not be settled on"
        );
        assert_eq!(route(Err(HandleError::Unavailable)), Route::Wait);
    }

    /// A window on Wayland keeps arboard wherever arboard can be built.
    ///
    /// That is wherever Copy worked before smithay-clipboard came in: through
    /// data-control where the compositor offers it, and through XWayland where
    /// it does not. smithay-clipboard there would bring in its gaps, a touch
    /// Copy and a keyboard bound after the focus, where arboard has neither.
    #[cfg(wayland_target)]
    #[test]
    fn a_wayland_window_keeps_arboard_wherever_arboard_can_be_built() {
        let display = NonNull::<c_void>::dangling();
        assert_eq!(
            choose(Route::Wayland(display), || Ok::<_, ()>(ARBOARD)),
            Choice::Arboard(Some(ARBOARD)),
            "a window on Wayland must keep an arboard that could be built"
        );
    }

    /// A window on Wayland for which arboard cannot be built copies over its
    /// own connection.
    ///
    /// That is the Flatpak on a compositor that withholds data-control from
    /// it, where arboard's X11 fallback has no X server to reach and every
    /// Copy failed.
    #[cfg(wayland_target)]
    #[test]
    fn a_wayland_window_copies_over_its_own_connection_where_arboard_cannot_be_built() {
        let display = NonNull::<c_void>::dangling();
        assert_eq!(
            choose(Route::Wayland(display), || Err::<&str, _>(())),
            Choice::Wayland(display),
            "a window on Wayland without arboard must copy over its own connection"
        );
    }

    /// A window on anything else keeps arboard whether it can be built or not.
    ///
    /// arboard is all there is off Wayland. Where it cannot be built yet, the
    /// slot is left empty, so that the first Copy builds it again and reports
    /// why it cannot, as a Copy after any failure does.
    #[cfg(wayland_target)]
    #[test]
    fn any_other_window_keeps_arboard_and_builds_it_again_at_a_copy_after_failing() {
        assert_eq!(
            choose(Route::Other, || Ok::<_, ()>(ARBOARD)),
            Choice::Arboard(Some(ARBOARD))
        );
        assert_eq!(
            choose(Route::Other, || Err::<&str, _>(())),
            Choice::Arboard(None),
            "a window off Wayland must keep arboard even when it cannot be built"
        );
    }

    /// A window winit has not created yet waits, without building arboard.
    ///
    /// The timer asks every 10ms until the window exists, and building arboard
    /// on each of those ticks would open and close a connection every time.
    #[cfg(wayland_target)]
    #[test]
    fn a_window_winit_has_not_created_yet_waits_without_building_arboard() {
        let built = Cell::new(false);
        let choice = choose(Route::Wait, || {
            built.set(true);
            Ok::<_, ()>(ARBOARD)
        });
        assert_eq!(choice, Choice::Wait);
        assert!(!built.get(), "waiting must not build arboard");
    }

    /// A close request lets go of the clipboard, and still closes the window.
    ///
    /// On Wayland hiding the window destroys it, and after that nothing but
    /// Slint's event loop may be keeping the connection open, which Slint
    /// drops when winit's run fails or a panic unwinds through it. The
    /// clipboard's thread has to be gone by then, so it goes in the close
    /// handler, which Slint runs before it hides the window. The testing
    /// backend has no display, so an arboard slot stands in for the clipboard
    /// the timer would have chosen; letting go does not depend on the kind.
    #[cfg(wayland_target)]
    #[test]
    fn a_close_request_lets_go_of_the_clipboard_and_still_closes_the_window() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("the window builds on the testing backend");
        ui.show().expect("the testing backend shows a window");
        let _attached = attach(&ui);
        CLIPBOARD.with(|slot| *slot.borrow_mut() = Clipboard::Arboard(None));

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
    /// unwinds through the event loop. No close request comes then, and Slint
    /// may have dropped the event loop, and with it the loop's clone of the
    /// connection, so the clipboard has to go while the window, which holds a
    /// clone of its own, still exists: `run` drops the guard before the
    /// window. As in the close request's test, an arboard slot stands in for
    /// the Wayland handle; where no window can be on Wayland, it is the slot
    /// `attach` fills anyway.
    #[test]
    fn dropping_the_guard_lets_go_of_the_clipboard_without_a_close_request() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = AppWindow::new().expect("the window builds on the testing backend");
        ui.show().expect("the testing backend shows a window");
        let attached = attach(&ui);
        CLIPBOARD.with(|slot| *slot.borrow_mut() = Clipboard::Arboard(None));

        drop(attached);

        assert!(
            CLIPBOARD.with(|slot| matches!(*slot.borrow(), Clipboard::NoWindow)),
            "dropping the guard must let go of the clipboard"
        );
    }
}
