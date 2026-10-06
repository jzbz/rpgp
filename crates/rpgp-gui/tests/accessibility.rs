//! A passphrase must not reach the accessibility bus.
//!
//! Slint's `lower_accessibility` pass binds `accessible-value` to a
//! TextInput's raw `text` for every TextInput, with no exception for
//! `InputType.password`, and the AccessKit adapter publishes that verbatim to
//! AT-SPI on Linux and NSAccessibility on macOS. `input-type` only masks the
//! glyphs on screen. This crate enables Slint's `accessibility` feature, so
//! without an explicit binding of our own a typed passphrase goes out in
//! cleartext to anything watching the bus.
//!
//! Verified to reproduce: before the `accessible-value` binding in
//! `ui/widgets.slint`, this test reported the passphrase back verbatim.
//!
//! Nor may it reach a clipboard, which `input-type` does not stop either; see
//! [`a_secret_field_puts_nothing_on_either_clipboard`].

include!(concat!(env!("OUT_DIR"), "/field-probe.rs"));

const PASSPHRASE: &str = "correct horse battery staple";
const ORDINARY: &str = "alice@example.org";

/// The two Fields in the probe, in declaration order: secret, then plain.
fn probe_inputs(probe: &FieldProbe) -> Vec<i_slint_backend_testing::ElementHandle> {
    let inputs: Vec<_> =
        i_slint_backend_testing::ElementHandle::find_by_element_type_name(probe, "TextInput")
            .collect();
    assert_eq!(inputs.len(), 2, "expected two TextInputs in the probe");
    inputs
}

#[test]
fn a_secret_field_does_not_publish_its_contents() {
    i_slint_backend_testing::init_no_event_loop();

    let probe = FieldProbe::new().unwrap();
    probe.set_secret_text(PASSPHRASE.into());

    let published = probe_inputs(&probe)[0]
        .accessible_value()
        .unwrap_or_default();
    assert!(
        !published.contains(PASSPHRASE),
        "the passphrase is on the accessibility bus: accessible-value = {published:?}",
    );
}

/// The fix must not be a blanket one: silencing every field would trade a leak
/// for an unusable app under a screen reader.
#[test]
fn an_ordinary_field_still_publishes_its_contents() {
    i_slint_backend_testing::init_no_event_loop();

    let probe = FieldProbe::new().unwrap();
    probe.set_plain_text(ORDINARY.into());

    let inputs = probe_inputs(&probe);
    assert_eq!(
        inputs[1].accessible_value().unwrap_or_default().as_str(),
        ORDINARY,
    );
    // And a secret field is still announced by name, rather than as an
    // anonymous unlabelled control.
    assert_eq!(
        inputs[0].accessible_label().unwrap_or_default().as_str(),
        "Passphrase",
    );
}

/// The testing backend, with every text Slint puts on either clipboard kept.
///
/// The backend's own clipboard keeps the ordinary one and drops the primary
/// selection, which is where a mouse selection goes.
struct RecordingPlatform {
    backend: i_slint_backend_testing::TestingBackend,
    copies: std::rc::Rc<std::cell::RefCell<Vec<(slint::platform::Clipboard, String)>>>,
}

impl slint::platform::Platform for RecordingPlatform {
    fn create_window_adapter(
        &self,
    ) -> Result<std::rc::Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError> {
        self.backend.create_window_adapter()
    }

    fn duration_since_start(&self) -> std::time::Duration {
        self.backend.duration_since_start()
    }

    fn set_clipboard_text(&self, text: &str, clipboard: slint::platform::Clipboard) {
        self.copies.borrow_mut().push((clipboard, text.to_string()));
    }
}

/// A secret field puts nothing on either clipboard, however its text is
/// selected, and an ordinary field still copies.
///
/// `input-type: password` only masks the glyphs on screen. Slint's TextInput
/// copied a selection to the clipboard on Ctrl+C and Ctrl+X, and to the
/// primary selection on Linux whenever the left button came up over one, as
/// it does after a double or triple click or a drag, all without looking at
/// the input type. On X11 any program can read the primary selection, and
/// clipboard managers record both.
#[test]
fn a_secret_field_puts_nothing_on_either_clipboard() {
    use slint::platform::{Clipboard, Key, PointerEventButton, WindowEvent};

    let copies = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    slint::platform::set_platform(Box::new(RecordingPlatform {
        backend: i_slint_backend_testing::TestingBackend::new(
            i_slint_backend_testing::TestingBackendOptions {
                mock_time: true,
                ..Default::default()
            },
        ),
        copies: copies.clone(),
    }))
    .expect("no platform is set on a test's own thread");

    let probe = FieldProbe::new().unwrap();
    probe.show().unwrap();
    probe.set_secret_text(PASSPHRASE.into());
    probe.set_plain_text(ORDINARY.into());
    let window = probe.window();
    let with_control = |key: &str| {
        window.dispatch_event(WindowEvent::KeyPressed {
            text: Key::Control.into(),
        });
        press(&probe, key);
        window.dispatch_event(WindowEvent::KeyReleased {
            text: Key::Control.into(),
        });
    };

    let text_of = |secret: bool| {
        if secret {
            probe.get_secret_text()
        } else {
            probe.get_plain_text()
        }
    };
    let set_text = |secret: bool, text: &str| {
        if secret {
            probe.set_secret_text(text.into());
        } else {
            probe.set_plain_text(text.into());
        }
    };

    for (field, text) in probe_inputs(&probe).iter().zip([PASSPHRASE, ORDINARY]) {
        let secret = text == PASSPHRASE;
        copies.borrow_mut().clear();
        // Three clicks in a row, which the mock clock never lets drift apart:
        // the second selects a word and the third the whole line, and each
        // release copies whatever is selected.
        let (at, size) = (field.absolute_position(), field.size());
        let position = slint::LogicalPosition::new(at.x + size.width / 2., at.y + size.height / 2.);
        let button = PointerEventButton::Left;
        for _ in 0..3 {
            window.dispatch_event(WindowEvent::PointerPressed { position, button });
            window.dispatch_event(WindowEvent::PointerReleased { position, button });
        }
        // The clicks gave the field focus, or the keys below would go nowhere
        // and copy nothing whatever the field allowed.
        press(&probe, "!");
        assert_ne!(text_of(secret), text, "a click should give the field focus");
        set_text(secret, text);
        with_control("a");
        with_control("c");
        with_control("x");

        let copied = copies.borrow().clone();
        if secret {
            assert_eq!(copied, [], "a secret field put its text on a clipboard");
            assert_eq!(
                probe.get_secret_text(),
                PASSPHRASE,
                "Ctrl+X in a secret field should do nothing at all"
            );
        } else {
            // The same gestures on an ordinary field, so that nothing above is
            // the gestures going nowhere.
            for clipboard in [Clipboard::SelectionClipboard, Clipboard::DefaultClipboard] {
                assert!(
                    copied.contains(&(clipboard.clone(), text.to_string())),
                    "an ordinary field should still copy to {clipboard:?}: {copied:?}"
                );
            }
            assert_eq!(
                probe.get_plain_text(),
                "",
                "Ctrl+X should cut an ordinary field"
            );
        }
    }
}

/// Every interactive control says what it is, what it is called, and can be
/// operated without a mouse.
///
/// Before this, nothing in the app declared a role or an action: a screen
/// reader saw unlabelled geometry, and an icon-only button — including the
/// destructive ones — announced nothing at all. Labels leaked through by
/// accident where a control happened to contain a Text, which is why this
/// asserts on roles and actions rather than on names alone.
#[test]
fn controls_are_announced_and_operable() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let probe = ControlProbe::new().unwrap();
    probe.show().unwrap();

    let by_label = |label: &str| {
        ElementHandle::find_by_accessible_label(&probe, label)
            .next()
            .unwrap_or_else(|| panic!("nothing is called {label:?}"))
    };

    for (label, role) in [
        ("Save", AccessibleRole::Button),
        // The icon-only one: no text to leak a name, so this fails outright
        // without an explicit label.
        ("Revoke user ID alice", AccessibleRole::Button),
        ("Encrypt", AccessibleRole::Checkbox),
        ("Standard", AccessibleRole::Combobox),
        ("Copy Fingerprint", AccessibleRole::Button),
    ] {
        assert_eq!(
            by_label(label).accessible_role(),
            Some(role),
            "role of {label:?}"
        );
    }

    // A row with nothing to copy must not pretend to be a button.
    assert!(
        ElementHandle::find_by_accessible_label(&probe, "Copy Algorithm")
            .next()
            .is_none(),
        "a non-copyable row should expose no copy button"
    );

    // State a screen reader cannot infer from the drawing — and, more to the
    // point, state that *tracks*. Asserting the initial values alone proved
    // nothing: they are the defaults of an untouched probe, so a hardcoded
    // `accessible-checked: false` would have satisfied them just as well. Each
    // is therefore moved and read back.
    assert_eq!(by_label("Encrypt").accessible_checked(), Some(false));
    assert_eq!(
        by_label("Standard")
            .accessible_value()
            .unwrap_or_default()
            .as_str(),
        "Modern"
    );

    probe.set_standard(1);
    assert_eq!(
        by_label("Standard")
            .accessible_value()
            .unwrap_or_default()
            .as_str(),
        "Compatible",
        "the published value must follow the control, not be a constant"
    );

    // And each one can actually be operated through the accessibility layer.
    by_label("Save").invoke_accessible_default_action();
    by_label("Encrypt").invoke_accessible_default_action();
    by_label("Copy Fingerprint").invoke_accessible_default_action();
    assert_eq!(
        by_label("Encrypt").accessible_checked(),
        Some(true),
        "toggling through the accessibility layer must move the published state"
    );
    assert_eq!(
        (probe.get_clicks(), probe.get_toggles(), probe.get_copies()),
        (1, 1, 1),
        "default actions must reach the callbacks"
    );
}

/// The control called `label` in the given role. A button's own Text carries
/// the same name as the button, so the name alone can find the wrong one, and
/// an action invoked on the Text does nothing whether or not the button would
/// have — which would pass every assertion that nothing happened.
fn control(
    root: &impl i_slint_backend_testing::ElementRoot,
    label: &str,
    role: i_slint_backend_testing::AccessibleRole,
) -> i_slint_backend_testing::ElementHandle {
    i_slint_backend_testing::ElementHandle::find_by_accessible_label(root, label)
        .find(|element| element.accessible_role() == Some(role))
        .unwrap_or_else(|| panic!("no {role:?} is called {label:?}"))
}

/// Send a key to whatever has focus, the way the windowing backend does.
fn press(probe: &impl slint::ComponentHandle, key: impl Into<slint::SharedString>) {
    let text = key.into();
    let window = probe.window();
    window.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
    window.dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
}

/// Whether the Select's list is open. Each option is a Text of its own, so
/// the two names are on screen three times with the list open and once, as
/// the current choice, with it closed.
fn list_is_open(probe: &EnabledProbe) -> bool {
    let shown = |name: &str| {
        i_slint_backend_testing::ElementHandle::find_by_accessible_label(probe, name).count()
    };
    shown("Modern") + shown("Compatible") > 1
}

/// A disabled control does nothing when assistive technology activates it.
///
/// Slint hands the activation to the control's handler without looking at
/// `enabled`, and of the AccessKit adapters only the Windows one refuses a
/// control it has published as disabled. On Linux and macOS a screen reader
/// could press a greyed-out Delete key before the key ID had been typed, or a
/// Run button whose operation was already under way. The testing backend
/// invokes the same entry point the winit adapter does.
#[test]
fn a_disabled_control_ignores_an_assistive_technology_action() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;

    let probe = EnabledProbe::new().unwrap();
    probe.show().unwrap();
    let run = || control(&probe, "Run", AccessibleRole::Button);
    let sign = || control(&probe, "Sign", AccessibleRole::Checkbox);
    let mode = || control(&probe, "Mode", AccessibleRole::Combobox);

    probe.set_live(false);
    for control in [run(), sign(), mode()] {
        assert_eq!(control.accessible_enabled(), Some(false));
        control.invoke_accessible_default_action();
    }
    assert_eq!(
        (probe.get_clicks(), probe.get_toggles()),
        (0, 0),
        "a control published as disabled acted on an assistive-technology action"
    );
    assert!(!list_is_open(&probe), "a disabled Select opened its list");

    // The same actions on the same elements, enabled, so that the nothing
    // above is the controls refusing and not the actions going nowhere.
    probe.set_live(true);
    for control in [run(), sign(), mode()] {
        control.invoke_accessible_default_action();
    }
    assert_eq!((probe.get_clicks(), probe.get_toggles()), (1, 1));
    assert!(
        list_is_open(&probe),
        "an enabled Select should open its list"
    );
}

/// A control that had keyboard focus before it was disabled stops answering
/// the keys that operate it.
///
/// Slint's FocusScope checks `enabled` only when focus arrives, and nothing
/// takes focus away from a control that is disabled while it holds it. A
/// button pressed with Enter is disabled by the operation it starts, so a
/// second Enter, or the auto-repeat of a held one, reached the same button's
/// handler again, leaving only the busy check in Rust to stop a second run.
#[test]
fn a_focused_control_stops_answering_keys_once_it_is_disabled() {
    i_slint_backend_testing::init_no_event_loop();
    use slint::platform::Key;

    let probe = EnabledProbe::new().unwrap();
    probe.show().unwrap();

    // Tab visits the controls in the order the probe declares them. Each is
    // operated once while it is enabled, which is also what shows that the
    // keys below reach it.
    press(&probe, Key::Tab);
    press(&probe, Key::Return);
    assert_eq!(probe.get_clicks(), 1, "Enter should press a focused button");
    probe.set_live(false);
    press(&probe, Key::Return);
    press(&probe, Key::Space);
    assert_eq!(probe.get_clicks(), 1, "a disabled button answered a key");

    probe.set_live(true);
    press(&probe, Key::Tab);
    press(&probe, Key::Space);
    assert_eq!(
        probe.get_toggles(),
        1,
        "Space should toggle a focused checkbox"
    );
    probe.set_live(false);
    press(&probe, Key::Space);
    press(&probe, Key::Return);
    assert_eq!(probe.get_toggles(), 1, "a disabled checkbox answered a key");

    probe.set_live(true);
    press(&probe, Key::Tab);
    press(&probe, Key::DownArrow);
    assert_eq!(probe.get_changes(), 1, "Down should move a focused Select");
    probe.set_live(false);
    press(&probe, Key::UpArrow);
    press(&probe, Key::DownArrow);
    press(&probe, Key::Space);
    press(&probe, Key::Return);
    assert_eq!(probe.get_changes(), 1, "a disabled Select answered a key");
    assert!(!list_is_open(&probe), "a disabled Select opened its list");
}

/// A Select's list, opened before the Select was disabled, takes no choice
/// afterwards. Nothing closes the list when `enabled` changes, so its options
/// are one more way in.
#[test]
fn an_open_list_takes_no_choice_once_its_select_is_disabled() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use slint::platform::{PointerEventButton, WindowEvent};

    let probe = EnabledProbe::new().unwrap();
    probe.show().unwrap();
    let select = || control(&probe, "Mode", AccessibleRole::Combobox);
    // An item in the open list reports its position within the list rather
    // than within the window, and the list opens under the Select, so the
    // click is aimed from there. The gap between the two is a few pixels,
    // well inside an option's height.
    let choose_compatible = || {
        let option = ElementHandle::find_by_accessible_label(&probe, "Compatible")
            .next()
            .expect("the list should be open and offer Compatible");
        let (under, within) = (select().absolute_position(), option.absolute_position());
        let position = slint::LogicalPosition::new(
            under.x + within.x + option.size().width / 2.,
            under.y + select().size().height + within.y + option.size().height / 2.,
        );
        let button = PointerEventButton::Left;
        let window = probe.window();
        window.dispatch_event(WindowEvent::PointerMoved { position });
        window.dispatch_event(WindowEvent::PointerPressed { position, button });
        window.dispatch_event(WindowEvent::PointerReleased { position, button });
    };

    select().invoke_accessible_default_action();
    probe.set_live(false);
    choose_compatible();
    assert_eq!(probe.get_changes(), 0, "a disabled Select took a choice");

    // And the same click with the Select enabled, so the one above is known
    // to have landed on the option.
    probe.set_live(true);
    if !list_is_open(&probe) {
        select().invoke_accessible_default_action();
    }
    choose_compatible();
    assert_eq!(
        probe.get_changes(),
        1,
        "clicking an option should choose it"
    );
}

/// A disabled text field takes no text from assistive technology, and is
/// published as disabled rather than only read-only.
///
/// Slint gives every TextInput a set-value action that writes the text with no
/// check of `read-only`, and the macOS adapter passes it on for a disabled
/// field as readily as for an enabled one. Disabling the input itself is also
/// what stops an input method's composed text, which read-only does not;
/// composition cannot be sent through the testing backend's public API, so
/// that half is asserted only as the published state.
#[test]
fn a_disabled_text_field_takes_no_text_from_assistive_technology() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;

    let probe = EnabledProbe::new().unwrap();
    probe.show().unwrap();
    // The Field's and then the TextArea's.
    let inputs: Vec<_> = ElementHandle::find_by_element_type_name(&probe, "TextInput").collect();
    assert_eq!(inputs.len(), 2, "expected the Field and the TextArea");

    probe.set_live(false);
    for input in &inputs {
        assert_eq!(
            input.accessible_enabled(),
            Some(false),
            "a disabled field's input should be published as disabled"
        );
        input.set_accessible_value("REPLACED");
        assert_eq!(
            input.accessible_value().unwrap_or_default().as_str(),
            "",
            "a disabled field took text from assistive technology"
        );
    }
    assert_eq!(probe.get_edits(), 0, "a disabled field reported an edit");

    probe.set_live(true);
    for input in &inputs {
        input.set_accessible_value("TYPED");
        assert_eq!(
            input.accessible_value().unwrap_or_default().as_str(),
            "TYPED"
        );
    }
    assert_eq!(
        probe.get_edits(),
        2,
        "an enabled field should take the text"
    );
}

/// The recipient and user-ID lists draw a tick box by hand instead of using
/// `Check`. None of that drawing reaches assistive technology, so each row has
/// to declare the checkbox contract itself — otherwise choosing who can read a
/// file is a screen reader's blind spot: unlabelled geometry, with no way to
/// tell a chosen recipient from an unchosen one or to change the answer.
///
/// Driven through the shipped dialogs rather than a copy of their rows, so
/// this fails if the real ones lose the contract again.
#[test]
fn a_selection_row_says_what_it_is_and_whether_it_is_chosen() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let recipient = |label: &str, mail: &str, key_id: &str, selected: bool| RecipientRow {
        fingerprint: label.into(),
        label: label.into(),
        sublabel: mail.into(),
        key_id: key_id.into(),
        initials: label[..1].into(),
        tint_index: 0,
        selected,
    };

    let probe = SelectionProbe::new().unwrap();
    probe.set_recipients(slint::ModelRc::new(slint::VecModel::from(vec![
        recipient("Alice", "alice@example.org", "A11CE00000000001", false),
        recipient("Bob", "bob@example.org", "B0B0000000000002", true),
    ])));
    probe.show().unwrap();

    // The address and the key ID are part of the name, not decoration: the key
    // ID is what separates two keys held for the same person, which usually
    // share the address too.
    let row = |name: &str| {
        ElementHandle::find_by_accessible_label(&probe, name)
            .next()
            .unwrap_or_else(|| panic!("no recipient row is called {name:?}"))
    };
    let alice = || row("Alice, alice@example.org, key ID A11CE00000000001");
    let bob = || row("Bob, bob@example.org, key ID B0B0000000000002");

    assert_eq!(alice().accessible_role(), Some(AccessibleRole::Checkbox));
    assert_eq!(bob().accessible_role(), Some(AccessibleRole::Checkbox));

    // Distinct values from the same binding: a hardcoded constant passes one of
    // these two and fails the other, whichever it is set to.
    assert_eq!(alice().accessible_checked(), Some(false));
    assert_eq!(bob().accessible_checked(), Some(true));

    alice().invoke_accessible_default_action();
    assert_eq!(
        probe.get_toggled_recipient(),
        0,
        "a row must be operable through the accessibility layer, not the mouse alone"
    );
}

/// The same contract on the certify dialog's list, where the stakes are a
/// signature over someone else's identity.
#[test]
fn a_user_id_row_says_what_it_is_and_whether_it_is_chosen() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let probe = CertifyProbe::new().unwrap();
    probe.set_user_ids(slint::ModelRc::new(slint::VecModel::from(vec![
        UserIdRow {
            text: "Alice <alice@example.org>".into(),
            selected: false,
        },
        UserIdRow {
            text: "Alice <alice@work.example>".into(),
            selected: true,
        },
    ])));
    probe.show().unwrap();

    let row = |name: &str| {
        ElementHandle::find_by_accessible_label(&probe, name)
            .next()
            .unwrap_or_else(|| panic!("no user-ID row is called {name:?}"))
    };
    let home = || row("Alice <alice@example.org>");
    let work = || row("Alice <alice@work.example>");

    assert_eq!(home().accessible_role(), Some(AccessibleRole::Checkbox));
    assert_eq!(home().accessible_checked(), Some(false));
    assert_eq!(work().accessible_checked(), Some(true));

    home().invoke_accessible_default_action();
    assert_eq!(probe.get_toggled_user_id(), 0);
}

/// And the notepad's copy of the recipient row, which is a third instance of
/// the same hand-drawn tick box rather than a shared component.
#[test]
fn the_notepad_recipient_row_carries_the_same_contract() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let probe = NotepadProbe::new().unwrap();
    probe.set_recipients(slint::ModelRc::new(slint::VecModel::from(vec![
        RecipientRow {
            fingerprint: "AAAA".into(),
            label: "Alice".into(),
            sublabel: "alice@example.org".into(),
            key_id: "A11CE00000000001".into(),
            initials: "A".into(),
            tint_index: 0,
            selected: true,
        },
    ])));
    probe.show().unwrap();

    let row = ElementHandle::find_by_accessible_label(
        &probe,
        "Alice, alice@example.org, key ID A11CE00000000001",
    )
    .next()
    .expect("the notepad's recipient row announces nothing");
    assert_eq!(row.accessible_role(), Some(AccessibleRole::Checkbox));
    assert_eq!(row.accessible_checked(), Some(true));

    row.invoke_accessible_default_action();
    assert_eq!(probe.get_toggled_recipient(), 0);
}

/// A recipient row takes no toggle while a run is in flight, whether it is
/// clicked or activated by assistive technology, in Sign / Encrypt and in the
/// notepad alike.
///
/// The rows draw their own tick box rather than using `Check`, so nothing
/// made them honour `busy`, and inside a Flatpak Sign / Encrypt reads its
/// recipients only once the save dialog has answered. That dialog has no
/// parent window and leaves this one live behind it, so a row that still
/// answered then changed who the file was encrypted to after Run had been
/// pressed. The handler in Rust refuses too; this is the half that the
/// pointer and a screen reader meet.
#[test]
fn a_recipient_row_takes_no_toggle_while_a_run_is_in_flight() {
    i_slint_backend_testing::init_no_event_loop();

    let alice = || {
        slint::ModelRc::new(slint::VecModel::from(vec![RecipientRow {
            fingerprint: "AAAA".into(),
            label: "Alice".into(),
            sublabel: "alice@example.org".into(),
            key_id: "A11CE00000000001".into(),
            initials: "A".into(),
            tint_index: 0,
            selected: true,
        }]))
    };

    let probe = SelectionProbe::new().unwrap();
    probe.set_recipients(alice());
    probe.show().unwrap();
    row_is_inert_while_busy(
        "Sign / Encrypt",
        &probe,
        |busy| probe.set_busy(busy),
        || probe.get_toggled_recipient(),
        || probe.set_toggled_recipient(-1),
    );
    probe.hide().unwrap();

    let probe = NotepadProbe::new().unwrap();
    probe.set_recipients(alice());
    probe.show().unwrap();
    row_is_inert_while_busy(
        "the notepad",
        &probe,
        |busy| probe.set_busy(busy),
        || probe.get_toggled_recipient(),
        || probe.set_toggled_recipient(-1),
    );
}

/// Click Alice's recipient row and activate it as assistive technology does,
/// once with `busy` set and once without, and check that only the second
/// pair reached the dialog's toggle. `toggled` reads which row was toggled,
/// and `reset` forgets it.
fn row_is_inert_while_busy(
    dialog: &str,
    root: &impl i_slint_backend_testing::ElementRoot,
    set_busy: impl Fn(bool),
    toggled: impl Fn() -> i32,
    reset: impl Fn(),
) {
    use i_slint_backend_testing::AccessibleRole;
    use slint::platform::PointerEventButton;

    let row = || {
        control(
            root,
            "Alice, alice@example.org, key ID A11CE00000000001",
            AccessibleRole::Checkbox,
        )
    };

    set_busy(true);
    assert_eq!(
        row().accessible_enabled(),
        Some(false),
        "{dialog}: a recipient row said it could be changed during a run"
    );
    row().mock_single_click(PointerEventButton::Left);
    assert_eq!(
        toggled(),
        -1,
        "{dialog}: a click changed a recipient during a run"
    );
    row().invoke_accessible_default_action();
    assert_eq!(
        toggled(),
        -1,
        "{dialog}: assistive technology changed a recipient during a run"
    );

    // The same click and the same action with nothing in flight, so that the
    // nothing above is the row refusing and not the click missing it.
    set_busy(false);
    assert_eq!(row().accessible_enabled(), Some(true));
    row().mock_single_click(PointerEventButton::Left);
    assert_eq!(toggled(), 0, "{dialog}: a click should toggle a recipient");
    reset();
    row().invoke_accessible_default_action();
    assert_eq!(
        toggled(),
        0,
        "{dialog}: assistive technology should toggle a recipient"
    );
}

/// The Publish warning names the key it is about to upload.
///
/// It is the one lifecycle step that cannot be taken back, and the dialog asks
/// for nothing that ties it to a particular key: no passphrase, no key ID to
/// type. Before it carried the name, the only thing saying which key was
/// about to become public was the details pane behind the scrim, which can
/// move while the dialog is open.
#[test]
fn the_publish_warning_names_the_key_it_uploads() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementQuery;

    let probe = PublishProbe::new().unwrap();
    probe.show().unwrap();

    let warning = ElementQuery::from_root(&probe)
        .match_predicate(|element| {
            element
                .accessible_label()
                .is_some_and(|label| label.contains("cannot be undone"))
        })
        .find_first()
        .expect("the publish dialog should warn that it cannot be undone");
    let warning = warning.accessible_label().unwrap_or_default();
    assert!(
        warning.contains("Alice <alice@example.org>") && warning.contains("0123456789ABCDEF"),
        "the warning should say which key is being published: {warning:?}"
    );
}

/// Inside a Flatpak the Sign / Encrypt and Decrypt dialogs say that Run will
/// ask where to save, where outside they say which path they write.
///
/// Inside the sandbox the path beside the input is a document-portal path, and
/// an output written there never reached the host under its own name:
/// "Writes" it was a promise the sandbox did not keep, read out by a screen
/// reader like any other line.
#[test]
fn the_file_dialogs_say_when_run_will_ask_where_to_save() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;

    let probe = OutputProbe::new().unwrap();
    probe.show().unwrap();
    let says = |line: &str| {
        ElementHandle::find_by_accessible_label(&probe, line)
            .next()
            .is_some()
    };

    probe.set_encrypted("/tmp/message.txt.asc".into());
    probe.set_decrypted("/tmp/message.txt".into());
    assert!(says("Writes /tmp/message.txt.asc"));
    assert!(says("Writes /tmp/message.txt"));

    // As Rust sets them inside the sandbox: the flag, and bare file names.
    probe.set_choose_output(true);
    probe.set_encrypted("message.txt.asc".into());
    probe.set_decrypted("message.txt".into());
    assert!(says("Asks where to save message.txt.asc"));
    assert!(says("Asks where to save message.txt"));
    assert!(!says("Writes message.txt.asc") && !says("Writes message.txt"));
}

/// Inside a Flatpak each file field shows the chosen file by its name, which
/// Rust gives apart from the path, the document portal's: the file Sign /
/// Encrypt works on, the message or signature, and the file a detached
/// signature signs. The paths stay the dialogs' to tell one choice from the
/// next, and are shown nowhere.
#[test]
fn inside_a_flatpak_the_file_fields_show_names_not_portal_paths() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;

    let probe = OutputProbe::new().unwrap();
    probe.show().unwrap();
    let says = |line: &str| {
        ElementHandle::find_by_accessible_label(&probe, line)
            .next()
            .is_some()
    };
    let portal = |id: &str, name: &str| format!("/run/user/1000/doc/{id}/{name}");
    let files = [
        (portal("1a2b3c4d", "report.pdf"), "report.pdf"),
        (portal("5e6f7a8b", "report.pdf.sig"), "report.pdf.sig"),
        (portal("9c0d1e2f", "report-copy.pdf"), "report-copy.pdf"),
    ];

    // As Rust sets them inside the sandbox.
    probe.set_choose_output(true);
    probe.set_se_input(files[0].0.as_str().into());
    probe.set_se_input_shown(files[0].1.into());
    probe.set_dv_input(files[1].0.as_str().into());
    probe.set_dv_input_shown(files[1].1.into());
    probe.set_needs_data(true);
    probe.set_dv_data(files[2].0.as_str().into());
    probe.set_dv_data_shown(files[2].1.into());

    for (path, name) in &files {
        assert!(says(name), "{name} is not shown");
        assert!(!says(path), "{path} is shown");
    }
}

/// The details pane offers to revoke a key held here until a revocation of it
/// is hard, and once the key is retired, offers to mark it compromised.
///
/// The button used to go with the first revocation of any kind, so a key
/// retired with the dialog's default, soft, reason could never be marked
/// compromised from the app, and every signature it made before the
/// retirement, or that a thief dated to then, went on verifying. Asked of the
/// rule the pane draws the button by, since the window has no debug
/// information to find the button itself.
#[test]
fn the_revoke_button_stays_until_a_revocation_is_hard() {
    i_slint_backend_testing::init_no_event_loop();

    let probe = TrustRootProbe::new().unwrap();
    let offer = probe.global::<RevokeOffer>();
    let yours = CertRow {
        has_secret: true,
        ..Default::default()
    };
    let retired = CertRow {
        revocation: "No longer used".into(),
        ..yours.clone()
    };
    let compromised = CertRow {
        revocation: "Secret key may be compromised".into(),
        revocation_hard: true,
        ..yours.clone()
    };

    assert!(offer.invoke_shown(yours.clone()));
    assert_eq!(offer.invoke_label(yours), "Revoke this key…");
    assert!(
        offer.invoke_shown(retired.clone()),
        "a retired key has to stay revocable, to be marked compromised"
    );
    assert_eq!(offer.invoke_label(retired), "Mark as compromised…");
    assert!(
        !offer.invoke_shown(compromised),
        "a hard revocation leaves nothing harder to give"
    );
    assert!(
        !offer.invoke_shown(CertRow::default()),
        "someone else's key is not ours to revoke"
    );
}

/// Marking a retired key compromised offers only the two hard reasons, and
/// hands back each as its index in Reason::ALL.
///
/// The list is the last two of the usual four, and the index it reports is
/// its own. Handed back as it stands, its first entry would reach run_revoke
/// as Reason::ALL's first, a retirement, and sign the very soft revocation
/// the dialog was opened to go past.
#[test]
fn marking_a_key_compromised_offers_only_the_hard_reasons() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use slint::platform::{PointerEventButton, WindowEvent};

    let probe = RevokeUpgradeProbe::new().unwrap();
    probe.show().unwrap();
    let select = || control(&probe, "Reason for revocation", AccessibleRole::Combobox);
    let run = || control(&probe, "Mark as compromised", AccessibleRole::Button);
    let shown = |name: &str| ElementHandle::find_by_accessible_label(&probe, name).count();

    assert_eq!(
        select().accessible_value().unwrap_or_default().as_str(),
        "Secret key may be compromised"
    );
    run().invoke_accessible_default_action();
    assert_eq!(
        (probe.get_runs(), probe.get_reason()),
        (1, 2),
        "the first reason offered should reach the run as Compromised"
    );

    select().invoke_accessible_default_action();
    assert_eq!(shown("No longer used"), 0, "a soft reason was offered");
    assert_eq!(
        shown("Replaced by a newer key"),
        0,
        "a soft reason was offered"
    );

    // Aimed from the Select, as in an_open_list_takes_no_choice_once_its_select_is_disabled.
    let option =
        ElementHandle::find_by_accessible_label(&probe, "No reason given (treated as compromised)")
            .next()
            .expect("the list should offer the other hard reason");
    let (under, within) = (select().absolute_position(), option.absolute_position());
    let position = slint::LogicalPosition::new(
        under.x + within.x + option.size().width / 2.,
        under.y + select().size().height + within.y + option.size().height / 2.,
    );
    let button = PointerEventButton::Left;
    let window = probe.window();
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerPressed { position, button });
    window.dispatch_event(WindowEvent::PointerReleased { position, button });
    assert_eq!(
        select().accessible_value().unwrap_or_default().as_str(),
        "No reason given (treated as compromised)"
    );

    run().invoke_accessible_default_action();
    assert_eq!(
        (probe.get_runs(), probe.get_reason()),
        (2, 3),
        "the second reason offered should reach the run as Unspecified"
    );
}

/// The dialog that asks before a revocation certificate for the user's own
/// keys is stored keeps its buttons inside the window however many
/// revocations the file holds, and says "keys" when more than one is the
/// user's own.
///
/// Listed straight into the card, which the window clamps, the revocations
/// of a file holding more than fit would push Cancel and Revoke off the
/// bottom and out of the item tree, where neither the pointer nor the
/// keyboard could reach them.
#[test]
fn the_revocation_import_dialog_keeps_its_buttons_however_many_keys_it_lists() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let probe = ImportRevocationProbe::new().unwrap();
    probe.show().unwrap();
    assert!(
        ElementHandle::find_by_accessible_label(&probe, "Revoke your keys")
            .next()
            .is_some(),
        "the title should say that the file revokes more than one of your keys"
    );

    let window = probe.window();
    let height = window.size().to_logical(window.scale_factor()).height;
    for label in ["Cancel", "Revoke"] {
        let button = control(&probe, label, AccessibleRole::Button);
        let bottom = button.absolute_position().y + button.size().height;
        assert!(
            bottom <= height,
            "{label} ends {bottom}px down a window {height}px tall"
        );
    }
    control(&probe, "Revoke", AccessibleRole::Button).invoke_accessible_default_action();
    assert_eq!(probe.get_runs(), 1);
}

/// Delete key does nothing, however it is activated, until the key ID has
/// been typed, and nothing again once the delete is under way.
///
/// Typing the key ID is the confirmation for deleting a secret key, and the
/// disabled button is all that enforces it: the delete itself is told only
/// whether the dialog warned about a secret key, not what was typed. Before
/// the button checked `enabled` for itself, a screen reader's activation went
/// straight through on Linux and macOS.
#[test]
fn delete_key_does_nothing_until_the_key_id_is_typed() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;

    let probe = DeleteProbe::new().unwrap();
    probe.show().unwrap();
    let delete = || control(&probe, "Delete key", AccessibleRole::Button);

    assert_eq!(delete().accessible_enabled(), Some(false));
    delete().invoke_accessible_default_action();
    assert_eq!(
        probe.get_runs(),
        0,
        "Delete key ran before the key ID was typed"
    );

    // The confirmation field is labelled with the key ID it asks for.
    control(&probe, "0123456789ABCDEF", AccessibleRole::TextInput)
        .set_accessible_value("0123456789ABCDEF");
    assert_eq!(delete().accessible_enabled(), Some(true));
    delete().invoke_accessible_default_action();
    assert_eq!(probe.get_runs(), 1, "a confirmed Delete key should run");

    // What the handler does next, before its worker starts.
    probe.set_busy(true);
    let working = control(&probe, "Deleting…", AccessibleRole::Button);
    assert_eq!(working.accessible_enabled(), Some(false));
    working.invoke_accessible_default_action();
    assert_eq!(
        probe.get_runs(),
        1,
        "a second delete started while the first was under way"
    );
}

/// The notepad's output can still be selected, and cannot be rewritten by
/// assistive technology.
///
/// It used to be a disabled TextArea, which in practice meant only read-only,
/// and Slint's set-value action ignores read-only: assistive technology could
/// replace the text on screen, which also cut it loose from the output it was
/// bound to, so the next run's result never appeared there while Copy went on
/// copying it. A TextArea that is actually disabled refuses that, but it also
/// refuses a selection, which is why the output is read-only instead.
///
/// Read-only does not cover everything. Slint's middle-click paste of the
/// primary selection does not look at it, so on Linux a middle click still
/// rewrites the output, as it did before; the testing backend has no primary
/// selection with which to show that.
#[test]
fn the_notepad_output_can_be_selected_but_not_rewritten_by_assistive_technology() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;

    let probe = NotepadProbe::new().unwrap();
    probe.set_output("PLAINTEXT".into());
    probe.show().unwrap();

    let output = ElementHandle::find_by_element_type_name(&probe, "TextInput")
        .find(|input| input.accessible_value().as_deref() == Some("PLAINTEXT"))
        .expect("the notepad should show its output");
    assert_eq!(output.accessible_read_only(), Some(true));
    assert_eq!(
        output.accessible_enabled(),
        Some(true),
        "a disabled TextInput ignores the pointer, so the output could not be selected"
    );

    output.set_accessible_value("SET-BY-AT");
    assert_eq!(
        output.accessible_value().unwrap_or_default().as_str(),
        "PLAINTEXT",
        "assistive technology rewrote the notepad's output"
    );
    probe.set_output("PLAINTEXT-2".into());
    assert_eq!(
        output.accessible_value().unwrap_or_default().as_str(),
        "PLAINTEXT-2",
        "the output area should go on showing the output"
    );
}

/// Create key pair does nothing, however it is reached, until the passphrase
/// has been typed twice alike, and says so when the two differ.
///
/// A passphrase mistyped behind the mask used to become the key's, with no
/// way in the app to learn what it was or to set another, so the key was
/// locked for good. A key with no passphrase needs nothing repeated.
#[test]
fn a_new_key_waits_for_its_passphrase_to_be_typed_twice_alike() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let probe = KeygenProbe::new().unwrap();
    probe.show().unwrap();
    let field = |label: &str| control(&probe, label, AccessibleRole::TextInput);
    let create = || control(&probe, "Create key pair", AccessibleRole::Button);
    let differ = || {
        ElementHandle::find_by_accessible_label(&probe, "The passphrases do not match.")
            .next()
            .is_some()
    };

    field("Name").set_accessible_value("Alice");
    field("name@example.org").set_accessible_value("alice@example.org");
    assert_eq!(
        create().accessible_enabled(),
        Some(true),
        "a key with no passphrase has nothing to repeat"
    );

    field("Passphrase (optional)").set_accessible_value(PASSPHRASE);
    assert_eq!(
        create().accessible_enabled(),
        Some(false),
        "Create key pair was offered with the passphrase typed once"
    );
    assert!(!differ(), "nothing has been typed twice yet to disagree");

    field("Repeat the passphrase").set_accessible_value("correct horse battery stapel");
    assert!(differ(), "two passphrases that differ should say so");
    assert_eq!(create().accessible_enabled(), Some(false));
    create().invoke_accessible_default_action();
    assert_eq!(
        probe.get_runs(),
        0,
        "a key was made with two passphrases that differ"
    );

    field("Repeat the passphrase").set_accessible_value(PASSPHRASE);
    assert!(!differ());
    assert_eq!(create().accessible_enabled(), Some(true));
    create().invoke_accessible_default_action();
    assert_eq!(
        (probe.get_runs(), probe.get_passphrase().as_str()),
        (1, PASSPHRASE),
        "with both alike the key should be made, with that passphrase"
    );
}

/// The new-key dialog keeps its buttons inside the smallest window the app
/// allows, the note under the passphrases included.
///
/// Asking for the passphrase twice makes the dialog taller than the card that
/// window leaves it, and unless the form scrolls, Cancel and Create key pair
/// are pushed off the bottom of the card.
#[test]
fn the_new_key_dialog_keeps_its_buttons_in_the_smallest_window() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let probe = KeygenProbe::new().unwrap();
    // The main window's minimum height, all of which the dialog's scrim covers.
    probe.set_probe_height(520.);
    probe.show().unwrap();
    control(&probe, "Passphrase (optional)", AccessibleRole::TextInput)
        .set_accessible_value(PASSPHRASE);
    control(&probe, "Repeat the passphrase", AccessibleRole::TextInput).set_accessible_value("x");
    assert!(
        ElementHandle::find_by_accessible_label(&probe, "The passphrases do not match.")
            .next()
            .is_some()
    );

    let window = probe.window();
    let height = window.size().to_logical(window.scale_factor()).height;
    assert_eq!(height, 520.);
    for label in ["Cancel", "Create key pair"] {
        let button = control(&probe, label, AccessibleRole::Button);
        let bottom = button.absolute_position().y + button.size().height;
        assert!(
            bottom <= height,
            "{label} ends {bottom}px down a window {height}px tall"
        );
    }
}

/// Create key pair is offered for a name alone or an address alone, as GnuPG
/// makes keys for either, and not for neither.
///
/// The dialog used to want both. Slint has no trim, so a field of spaces
/// still counts as filled in here; the handler in Rust refuses that.
#[test]
fn a_name_alone_or_an_address_alone_is_enough_for_a_new_key() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;

    let probe = KeygenProbe::new().unwrap();
    probe.show().unwrap();
    let name = || control(&probe, "Name", AccessibleRole::TextInput);
    let address = || control(&probe, "name@example.org", AccessibleRole::TextInput);
    let offered = || {
        control(&probe, "Create key pair", AccessibleRole::Button).accessible_enabled()
            == Some(true)
    };

    assert!(!offered(), "offered with neither a name nor an address");
    name().set_accessible_value("Alice");
    assert!(offered(), "a name alone should make a key");
    name().set_accessible_value("");
    address().set_accessible_value("alice@example.org");
    assert!(offered(), "an address alone should make a key");
    address().set_accessible_value("");
    assert!(!offered(), "offered once both were emptied again");
}

/// With no key here that can sign, Sign / Encrypt still encrypts, and says
/// that it can only encrypt.
///
/// Sign started ticked and was disabled when no key could sign, so it could
/// not be unticked, and Run needed it unticked or a key to sign with. Run
/// stayed disabled whatever recipients were chosen: anyone who had only other
/// people's certificates could not encrypt a file at all.
#[test]
fn sign_encrypt_encrypts_alone_when_no_key_here_can_sign() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let probe = SelectionProbe::new().unwrap();
    probe.set_signers(slint::ModelRc::new(slint::VecModel::from(Vec::<
        slint::SharedString,
    >::new())));
    probe.set_recipients(slint::ModelRc::new(slint::VecModel::from(vec![
        RecipientRow {
            fingerprint: "AAAA".into(),
            label: "Alice".into(),
            sublabel: "alice@example.org".into(),
            key_id: "A11CE00000000001".into(),
            initials: "A".into(),
            tint_index: 0,
            selected: true,
        },
    ])));
    probe.set_chosen_recipients(1);
    probe.show().unwrap();
    let sign = || control(&probe, "Sign", AccessibleRole::Checkbox);
    let run = || control(&probe, "Run", AccessibleRole::Button);
    let says = |line: &str| {
        ElementHandle::find_by_accessible_label(&probe, line)
            .next()
            .is_some()
    };
    const ONLY_ENCRYPT: &str = "No key of yours here can sign, so this can only encrypt.";
    const SIGNING_PASSPHRASE: &str = "Passphrase for the signing key (if any)";

    assert_eq!(
        (sign().accessible_checked(), sign().accessible_enabled()),
        (Some(false), Some(false)),
        "Sign should show that it is off, with no key to sign with"
    );
    assert!(says(ONLY_ENCRYPT));
    assert!(
        !says(SIGNING_PASSPHRASE),
        "a passphrase was asked for a key there is not"
    );
    assert_eq!(
        run().accessible_enabled(),
        Some(true),
        "Run stayed disabled with a recipient chosen"
    );
    run().invoke_accessible_default_action();
    assert_eq!(
        (probe.get_runs(), probe.get_encrypted(), probe.get_signed()),
        (1, true, false),
        "Run should encrypt, and not ask to sign"
    );

    // With a key that can sign, Sign is ticked, as it always was, and Run
    // signs as well.
    probe.set_signers(slint::ModelRc::new(slint::VecModel::from(vec![
        slint::SharedString::from("Me <me@example.org>"),
    ])));
    assert_eq!(
        (sign().accessible_checked(), sign().accessible_enabled()),
        (Some(true), Some(true))
    );
    assert!(!says(ONLY_ENCRYPT));
    assert!(says(SIGNING_PASSPHRASE));
    run().invoke_accessible_default_action();
    assert_eq!(
        (probe.get_runs(), probe.get_encrypted(), probe.get_signed()),
        (2, true, true)
    );
}

/// A passphrase typed for one message is not kept for the next: choosing
/// another input empties the field, as well as what Decrypt sends.
///
/// Going from one message to another leaves the field's condition true, so
/// Slint keeps the field it has. Only the property behind it was cleared, so
/// the field went on showing the last passphrase, masked, while Decrypt sent
/// nothing, and a key typed into it then sent the old passphrase with that
/// key on the end.
#[test]
fn choosing_another_message_empties_the_passphrase_field() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use slint::platform::PointerEventButton;

    const LABEL: &str = "Passphrase for the secret key (if any)";
    let probe = DecryptProbe::new().unwrap();
    probe.show().unwrap();
    let field = || control(&probe, LABEL, AccessibleRole::TextInput);
    // The field's placeholder is a Text of the same name, drawn only while
    // the field is empty; a secret field's value is published as nothing
    // either way, so this is how an empty one is told from a full one.
    let looks_empty = || ElementHandle::find_by_accessible_label(&probe, LABEL).count() == 2;
    let decrypt = || {
        control(&probe, "Decrypt", AccessibleRole::Button).invoke_accessible_default_action();
        probe.get_sent()
    };

    field().set_accessible_value(PASSPHRASE);
    assert!(!looks_empty());
    assert_eq!(decrypt(), PASSPHRASE);

    probe.set_input_path("/tmp/other.pgp".into());
    // Where Slint runs `changed` handlers.
    slint::platform::update_timers_and_animations();
    assert!(
        looks_empty(),
        "the field went on showing the last message's passphrase"
    );
    assert_eq!(decrypt(), "");

    field().mock_single_click(PointerEventButton::Left);
    press(&probe, "x");
    assert_eq!(
        decrypt(),
        "x",
        "what was typed for the next message should be all that is sent"
    );
    assert_eq!(probe.get_runs(), 3);
}

/// Inside a Flatpak the file field shows the chosen file's name rather than
/// the document-portal path it came back as, and the dialog still tells two
/// files of one name apart: one chosen from another folder empties the
/// passphrase field as any other choice does, because what is compared is the
/// path, which differs, and not the name, which does not.
#[test]
fn a_file_of_the_same_name_from_another_folder_still_empties_the_passphrase_field() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    const LABEL: &str = "Passphrase for the secret key (if any)";
    const NAME: &str = "message.txt.asc";
    const FIRST: &str = "/run/user/1000/doc/1a2b3c4d/message.txt.asc";
    const SECOND: &str = "/run/user/1000/doc/5e6f7a8b/message.txt.asc";
    let probe = DecryptProbe::new().unwrap();
    probe.set_input_path(FIRST.into());
    probe.set_input_shown(NAME.into());
    probe.show().unwrap();
    let shows = |text: &str| ElementHandle::find_by_accessible_label(&probe, text).count() > 0;
    let field = || control(&probe, LABEL, AccessibleRole::TextInput);
    let looks_empty = || ElementHandle::find_by_accessible_label(&probe, LABEL).count() == 2;
    let decrypt = || {
        control(&probe, "Decrypt", AccessibleRole::Button).invoke_accessible_default_action();
        probe.get_sent()
    };

    assert!(shows(NAME), "the field should show the file's name");
    assert!(!shows(FIRST), "the field should not show the portal's path");

    field().set_accessible_value(PASSPHRASE);
    assert!(!looks_empty());
    assert_eq!(decrypt(), PASSPHRASE);

    probe.set_input_path(SECOND.into());
    slint::platform::update_timers_and_animations();
    assert!(shows(NAME));
    assert!(
        looks_empty(),
        "a file of the same name from another folder kept the last passphrase"
    );
    assert_eq!(decrypt(), "");
}

/// The suppression has two halves: the binding inside `Field`, which the two
/// tests at the top cover, and the `secret: true` at each call site, which they
/// do not — they exercise the probe's own copy of a passphrase field, so every
/// dialog in the app could have lost its flag with all three still passing.
///
/// This drives the shipped dialogs. It types into every text input each one
/// has, through the same accessibility action a screen reader would use, and
/// asks what the bus was told: a field the dialog itself labels as taking a
/// passphrase must answer nothing, and every other field must still answer.
#[test]
fn every_passphrase_field_in_the_real_dialogs_suppresses_its_value() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{ElementHandle, ElementRoot};

    fn check(dialog: &str, probe: &impl ElementRoot) -> usize {
        let mut suppressed = 0;
        for field in ElementHandle::find_by_element_type_name(probe, "TextInput") {
            let label = field.accessible_label().unwrap_or_default().to_string();
            // Slint gives every TextInput an accessible-action-set-value that
            // assigns `text`, so this is the field being typed into.
            field.set_accessible_value(PASSPHRASE);
            let published = field.accessible_value().unwrap_or_default();
            let lower = label.to_lowercase();
            if lower.contains("passphrase") || lower.contains("password") {
                assert!(
                    !published.contains(PASSPHRASE),
                    "{dialog}: {label:?} takes a passphrase and publishes it: {published:?}"
                );
                suppressed += 1;
            } else {
                assert!(
                    published.contains(PASSPHRASE),
                    "{dialog}: {label:?} is not a passphrase field but announces nothing"
                );
            }
        }
        suppressed
    }

    let mut reached = 0;
    let probe = KeygenProbe::new().unwrap();
    probe.show().unwrap();
    reached += check("KeygenDialog", &probe);
    let probe = DecryptProbe::new().unwrap();
    probe.show().unwrap();
    reached += check("DecryptVerifyDialog", &probe);
    let probe = RevokeProbe::new().unwrap();
    probe.show().unwrap();
    reached += check("RevokeDialog", &probe);
    let probe = LifecycleProbe::new().unwrap();
    probe.show().unwrap();
    reached += check("LifecycleDialog", &probe);
    let probe = SelectionProbe::new().unwrap();
    probe.show().unwrap();
    reached += check("SignEncryptDialog", &probe);
    let probe = CertifyProbe::new().unwrap();
    probe.show().unwrap();
    reached += check("CertifyDialog", &probe);
    let probe = NotepadProbe::new().unwrap();
    probe.show().unwrap();
    reached += check("NotepadDialog", &probe);

    // A passphrase field in a dialog no probe instantiates, or behind a
    // condition no probe satisfies, is never reached above. Counting
    // `secret: true` in the source, as this used to, could not make up for
    // that where it matters: a field that forgot the flag adds nothing to the
    // count, and passed unseen. So every Field is read from the source too,
    // and the flag has to agree with the placeholder, which is the label the
    // check above classifies by, wherever the field is.
    let mut declared = 0;
    for file in ["ui/dialogs.slint", "ui/app-window.slint"] {
        let source = std::fs::read_to_string(format!("{}/{file}", env!("CARGO_MANIFEST_DIR")))
            .unwrap_or_else(|e| panic!("reading {file}: {e}"));
        for field in fields_in(&source) {
            let lower = field.placeholder.to_lowercase();
            let takes_passphrase = lower.contains("passphrase") || lower.contains("password");
            assert!(
                field.secret || !takes_passphrase,
                "{file}:{}: the Field {} takes a passphrase but is not marked `secret: true`",
                field.line,
                field.placeholder
            );
            assert!(
                takes_passphrase || !field.secret,
                "{file}:{}: the Field {} is marked secret, but its placeholder does not say \
                 it takes a passphrase or a password, which is all it is announced by",
                field.line,
                field.placeholder
            );
            if field.secret && file == "ui/dialogs.slint" {
                declared += 1;
            }
        }
    }
    // And every one in the dialogs is reached through a probe as well, so the
    // suppression is seen working and not only declared.
    assert_eq!(
        reached, declared,
        "ui/dialogs.slint has {declared} passphrase fields but only {reached} were reached \
         through a probe — add a probe for the dialog holding the new one"
    );
}

/// A `Field` as a `.slint` file declares it.
struct DeclaredField {
    /// The line it starts on, from 1.
    line: usize,
    /// What its `placeholder:` is set to, as written: a string literal, or
    /// the expression it is bound to.
    placeholder: String,
    secret: bool,
}

/// Every `Field` instantiated in `source`.
///
/// Read from the text rather than parsed, which is enough for how this
/// interface is written: a placeholder is one statement, and a Field's block
/// holds no string with a brace of its own outside an interpolation.
fn fields_in(source: &str) -> Vec<DeclaredField> {
    let mut fields = Vec::new();
    for (start, _) in source.match_indices("Field") {
        let line_start = source[..start].rfind('\n').map_or(0, |at| at + 1);
        let commented = source[line_start..start].contains("//");
        // A name that only ends in Field is another component, and one that
        // only starts with it, FieldRow, has no brace straight after.
        let named = source[..start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_');
        let rest = source[start + "Field".len()..].trim_start();
        if commented || named || !rest.starts_with('{') {
            continue;
        }
        let open = source.len() - rest.len();
        let body = &source[open..block_end(source, open)];
        let placeholder = body
            .split_once("placeholder:")
            .and_then(|(_, after)| after.split(';').next())
            .unwrap_or_default()
            .trim()
            .to_string();
        fields.push(DeclaredField {
            line: source[..start].matches('\n').count() + 1,
            placeholder,
            secret: body.contains("secret: true"),
        });
    }
    fields
}

/// Where the block opened by the `{` at `open` ends, just past its `}`.
fn block_end(source: &str, open: usize) -> usize {
    let mut depth = 0;
    let mut chars = source[open..].char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            // A string's braces are its own: `\{…}` is how Slint interpolates.
            '"' => {
                while let Some((_, c)) = chars.next() {
                    match c {
                        '\\' => {
                            chars.next();
                        }
                        '"' => break,
                        _ => {}
                    }
                }
            }
            '/' if source[open + at..].starts_with("//") => {
                for (_, c) in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + at + 1;
                }
            }
            _ => {}
        }
    }
    panic!("the block opened at byte {open} is never closed");
}

/// The Trust root box is locked only for a key generated here. A secret key
/// that arrived by import can be ticked, and unticked again.
///
/// The box used to follow the secret half: ticked and disabled for every key
/// the store held one for. An imported key is not a trust root until the user
/// makes it one, and this box is the only way to, so a restored backup could
/// never vouch for anyone while the pane said it already did.
#[test]
fn only_a_key_generated_here_has_its_trust_root_box_locked() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    let probe = TrustRootProbe::new().unwrap();
    probe.show().unwrap();
    let trust_root = || control(&probe, "Trust root", AccessibleRole::Checkbox);
    // Ticked and enabled, as assistive technology is told them.
    let shown = || {
        let check = trust_root();
        (check.accessible_checked(), check.accessible_enabled())
    };
    let says = |line: &str| {
        ElementHandle::find_by_accessible_label(&probe, line)
            .next()
            .is_some()
    };

    // The four kinds of certificate the pane can be showing.
    let generated = CertRow {
        has_secret: true,
        implicit_root: true,
        ..Default::default()
    };
    let imported = CertRow {
        has_secret: true,
        ..Default::default()
    };
    let promoted = CertRow {
        has_secret: true,
        is_trust_root: true,
        ..Default::default()
    };
    let foreign = CertRow::default();

    // Generated here: ticked, and nothing to untick.
    probe.set_cert(generated.clone());
    assert_eq!(shown(), (Some(true), Some(false)));
    assert!(says("Keys you generate here are always trust roots."));
    trust_root().invoke_accessible_default_action();
    assert_eq!(probe.get_toggles(), 0);

    // Imported: held, not a root, and the box is how it becomes one.
    probe.set_cert(imported.clone());
    assert_eq!(
        shown(),
        (Some(false), Some(true)),
        "an imported secret key was drawn as a trust root, with no way to make it one"
    );
    assert!(says(
        "An imported key is a trust root only while this is ticked."
    ));
    trust_root().invoke_accessible_default_action();
    assert_eq!(
        probe.get_toggles(),
        1,
        "ticking the box should reach the toggle"
    );

    // Imported and made a root: ticked, and still free to be unticked.
    probe.set_cert(promoted.clone());
    assert_eq!(shown(), (Some(true), Some(true)));

    // Someone else's certificate, as before.
    probe.set_cert(foreign.clone());
    assert_eq!(shown(), (Some(false), Some(true)));
    assert!(says("Certifications made by this key count as evidence."));

    // And none of them while an operation is in flight, each keeping its tick.
    probe.set_busy(true);
    for (kind, cert, ticked) in [
        ("a key generated here", generated, true),
        ("an imported key", imported, false),
        ("an imported key made a root", promoted, true),
        ("someone else's certificate", foreign, false),
    ] {
        probe.set_cert(cert);
        assert_eq!(
            shown(),
            (Some(ticked), Some(false)),
            "the box was left free while busy for {kind}"
        );
        trust_root().invoke_accessible_default_action();
    }
    assert_eq!(
        probe.get_toggles(),
        1,
        "a box reached the toggle while busy"
    );
}

/// The rail's scope tabs are a tab list, and the current one is announced as
/// the selected tab, as Slint's own tab widget announces its current tab.
///
/// The current tab used to be marked checked, which AccessKit turns into a
/// toggle: AT-SPI reports a checked page tab and UI Automation a toggle, where
/// a screen reader looks for the selected tab to call current. Nothing grouped
/// the three as a tab list either, so there was no set to count them in.
#[test]
fn the_scope_tabs_are_a_tab_list_whose_current_tab_is_selected() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementQuery};

    let probe = ScopeTabsProbe::new().unwrap();
    probe.show().unwrap();
    let names = ["All certificates", "My keys", "Other people"];
    let tab = |name: &str| control(&probe, name, AccessibleRole::Tab);

    let lists = ElementQuery::from_root(&probe)
        .match_accessible_role(AccessibleRole::TabList)
        .find_all();
    assert_eq!(lists.len(), 1, "the tabs should make up one tab list");
    assert_eq!(lists[0].accessible_item_count(), Some(3));
    for (index, name) in names.into_iter().enumerate() {
        let listed = lists[0]
            .query_descendants()
            .match_accessible_role(AccessibleRole::Tab)
            .match_predicate(move |element| element.accessible_label().as_deref() == Some(name))
            .find_first();
        assert!(listed.is_some(), "{name} should be in the tab list");
        assert_eq!(tab(name).accessible_item_index(), Some(index));
        assert_eq!(tab(name).accessible_item_selectable(), Some(true));
        assert_eq!(
            (
                tab(name).accessible_checkable(),
                tab(name).accessible_checked()
            ),
            (None, None),
            "{name} should be selected or not, not checked or not"
        );
    }

    // Distinct answers from one binding, each time the scope moves: a
    // constant would pass one of these and fail the rest.
    for scope in [0, 2, 1] {
        probe.set_scope(scope);
        for (index, name) in names.into_iter().enumerate() {
            assert_eq!(
                tab(name).accessible_item_selected(),
                Some(index == scope as usize),
                "with scope {scope}, {name}"
            );
        }
    }
}

/// The scope tabs take Tab, Space and Enter, and none of them once disabled.
///
/// They had a pointer path and an assistive-technology one only, so without a
/// screen reader the list could not be switched from the keyboard at all.
#[test]
fn the_scope_tabs_work_from_the_keyboard_and_not_while_disabled() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;
    use slint::platform::Key;

    let probe = ScopeTabsProbe::new().unwrap();
    probe.show().unwrap();

    // Tab visits the tabs in order, from the first.
    press(&probe, Key::Tab);
    press(&probe, Key::Tab);
    press(&probe, Key::Space);
    assert_eq!(
        (probe.get_scope(), probe.get_changes()),
        (1, 1),
        "Space on the second tab should switch to it"
    );
    press(&probe, Key::Tab);
    press(&probe, Key::Return);
    assert_eq!(
        (probe.get_scope(), probe.get_changes()),
        (2, 2),
        "Enter on the third tab should switch to it"
    );

    // Disabled, as the window disables them behind a dialog and while an
    // operation runs, with focus left on the third.
    probe.set_live(false);
    press(&probe, Key::Space);
    press(&probe, Key::Return);
    control(&probe, "My keys", AccessibleRole::Tab).invoke_accessible_default_action();
    assert_eq!(
        (probe.get_scope(), probe.get_changes()),
        (2, 2),
        "a disabled tab switched the scope"
    );
}

/// A certificate for the list, told apart by its number.
fn listed(number: usize) -> CertRow {
    CertRow {
        primary_user_id: format!("User {number:02} <user{number:02}@example.org>").into(),
        name: format!("User {number:02}").into(),
        email: format!("user{number:02}@example.org").into(),
        key_id: format!("{number:016X}").into(),
        validity: "valid".into(),
        authentication: "unverified".into(),
        ..Default::default()
    }
}

/// The certificate list takes focus from Tab, moves its selection with the
/// arrow keys, Page Up and Down, Home and End, keeps the selected row in view,
/// and does none of it once disabled.
///
/// Its rows had only a pointer path and an assistive-technology one, and the
/// ListView under them adds no keys, so without a screen reader nothing could
/// be selected from the keyboard, and with nothing selected, nothing that
/// acts on a certificate could be reached either.
#[test]
fn the_certificate_list_is_worked_from_the_keyboard() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;
    use slint::platform::{Key, PointerEventButton};

    let probe = CertListProbe::new().unwrap();
    probe.set_certs(slint::ModelRc::new(slint::VecModel::from(
        (0..30).map(listed).collect::<Vec<_>>(),
    )));
    probe.show().unwrap();
    let row = |number: usize| {
        control(
            &probe,
            &format!("User {number:02} <user{number:02}@example.org>"),
            AccessibleRole::ListItem,
        )
    };
    // Wholly inside the 400px window, which the list fills.
    let in_view = |number: usize| {
        let row = row(number);
        let top = row.absolute_position().y;
        top >= 0. && top + row.size().height <= 400.
    };
    let at = |expected: i32, what: &str| {
        assert_eq!(
            (probe.get_current_row(), probe.get_selected()),
            (expected, expected),
            "{what}"
        );
    };

    // Named, since it is what assistive technology is told has focus.
    control(&probe, "Certificates", AccessibleRole::List);

    press(&probe, Key::Tab);
    press(&probe, Key::DownArrow);
    at(0, "Down with nothing selected should select the first row");
    press(&probe, Key::DownArrow);
    press(&probe, Key::DownArrow);
    at(2, "Down should move the selection a row");
    press(&probe, Key::End);
    at(29, "End should select the last row");
    assert!(in_view(29), "the last row should be scrolled into view");
    // Focus leaving and coming back, which is the list's only stop, leaves
    // the list where it was scrolled to.
    press(&probe, Key::Tab);
    assert!(in_view(29), "taking focus again scrolled the list");
    // Six whole rows fit in the window.
    press(&probe, Key::PageUp);
    at(23, "Page Up should move a screenful");
    assert!(in_view(23));
    press(&probe, Key::Home);
    at(0, "Home should select the first row");
    assert!(
        in_view(0),
        "the first row should be scrolled back into view"
    );
    let asked = probe.get_selections();
    press(&probe, Key::UpArrow);
    at(0, "Up on the first row should stay there");
    assert_eq!(
        probe.get_selections(),
        asked,
        "a key that moved nowhere asked for the same row again"
    );
    press(&probe, Key::PageDown);
    at(6, "Page Down should move a screenful");
    assert!(in_view(6));

    // A click focuses the list, so the keys go on from the row clicked.
    row(3).mock_single_click(PointerEventButton::Left);
    at(3, "a click should select its row");
    press(&probe, Key::DownArrow);
    at(4, "Down after a click should go on from the row clicked");

    // Disabled, as the window disables it behind a dialog and while an
    // operation runs, with focus left on it.
    probe.set_live(false);
    let asked = probe.get_selections();
    for key in [
        Key::DownArrow,
        Key::UpArrow,
        Key::End,
        Key::Home,
        Key::PageDown,
    ] {
        press(&probe, key);
    }
    row(5).invoke_accessible_default_action();
    assert_eq!(
        (probe.get_current_row(), probe.get_selections()),
        (4, asked),
        "a disabled list moved its selection"
    );
}

/// A copy button in a details row copies with Space and Enter, and nothing
/// once disabled, however it is reached.
///
/// It had a pointer path and an assistive-technology one only, so a keyboard
/// user with no screen reader could not put a fingerprint on the clipboard,
/// which is the one thing the row is for.
#[test]
fn a_copy_button_copies_from_the_keyboard_and_not_while_disabled() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;
    use slint::platform::{Key, PointerEventButton};

    let probe = CopyProbe::new().unwrap();
    probe.show().unwrap();
    let copy = || control(&probe, "Copy Fingerprint", AccessibleRole::Button);

    press(&probe, Key::Tab);
    press(&probe, Key::Space);
    assert_eq!(probe.get_copies(), 1, "Space should copy");
    press(&probe, Key::Return);
    assert_eq!(probe.get_copies(), 2, "Enter should copy");
    // The row with nothing to copy is no stop, so Tab comes back here.
    press(&probe, Key::Tab);
    press(&probe, Key::Space);
    assert_eq!(probe.get_copies(), 3);

    // Disabled, as the details pane's rows are behind a dialog.
    probe.set_live(false);
    assert_eq!(copy().accessible_enabled(), Some(false));
    press(&probe, Key::Space);
    press(&probe, Key::Return);
    copy().invoke_accessible_default_action();
    copy().mock_single_click(PointerEventButton::Left);
    assert_eq!(probe.get_copies(), 3, "a disabled copy button copied");

    // And enabled again, so that the nothing above is the button refusing.
    probe.set_live(true);
    copy().invoke_accessible_default_action();
    copy().mock_single_click(PointerEventButton::Left);
    assert_eq!(probe.get_copies(), 5);
}

/// A control disabled while it had focus lets go of it once focus moves on.
///
/// Slint's FocusScope ignores being told that focus has left it while it is
/// disabled, so a control disabled with focus on it went on reporting focus
/// after focus had moved elsewhere, and drew its ring. The window disables
/// everything behind an open dialog, the control that opened it included, so
/// that ring stayed on under the scrim and was still there once the dialog
/// had closed, beside the ring of whatever had focus by then. A copy button
/// shows focus by lighting its icon, whose opacity can be read here; a
/// button, a checkbox, a drop-down, a scope tab and the certificate list draw
/// a ring only while they have focus, so whether the ring is there at all
/// says the same.
#[test]
fn a_control_disabled_while_it_had_focus_lets_go_of_it() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;
    use slint::platform::Key;

    const RINGS: [&str; 3] = ["Btn::ring", "Check::ring", "Select::ring"];
    // In the probe's Tab order.
    for (stop, ring) in RINGS.iter().enumerate() {
        let probe = EnabledProbe::new().unwrap();
        probe.show().unwrap();
        let rings = || RINGS.map(|ring| ElementHandle::find_by_element_id(&probe, ring).count());
        for _ in 0..=stop {
            press(&probe, Key::Tab);
        }
        assert_eq!(
            ElementHandle::find_by_element_id(&probe, ring).count(),
            1,
            "Tab should put {ring} on"
        );
        probe.set_live(false);
        press(&probe, Key::Tab);
        probe.set_live(true);
        assert_eq!(
            rings(),
            [0; 3],
            "{ring} was still drawn after focus had left its control"
        );
    }

    let tabs = ScopeTabsProbe::new().unwrap();
    tabs.show().unwrap();
    let ring = || ElementHandle::find_by_element_id(&tabs, "RailItem::ring").count();
    press(&tabs, Key::Tab);
    assert_eq!(ring(), 1, "Tab should put RailItem::ring on");
    tabs.set_live(false);
    press(&tabs, Key::Tab);
    tabs.set_live(true);
    assert_eq!(
        ring(),
        0,
        "RailItem::ring was still drawn after focus had left its tab"
    );

    // The list draws its ring round itself with nothing selected, and on the
    // selected row otherwise.
    let list = CertListProbe::new().unwrap();
    list.set_certs(slint::ModelRc::new(slint::VecModel::from(
        (0..3).map(listed).collect::<Vec<_>>(),
    )));
    list.show().unwrap();
    let rings = || {
        ["CertList::ring", "CertListRow::ring"]
            .map(|ring| ElementHandle::find_by_element_id(&list, ring).count())
    };
    press(&list, Key::Tab);
    assert_eq!(rings(), [1, 0], "Tab should put CertList::ring on");
    press(&list, Key::DownArrow);
    assert_eq!(rings(), [0, 1], "Down should put the ring on the row");
    list.set_live(false);
    press(&list, Key::Tab);
    list.set_live(true);
    assert_eq!(
        rings(),
        [0, 0],
        "the list's ring was still drawn after focus had left it"
    );

    let probe = CopyProbe::new().unwrap();
    probe.show().unwrap();
    // After the icon's fade.
    let lit = || {
        i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(500));
        ElementHandle::find_by_element_id(&probe, "FieldRow::icon")
            .next()
            .expect("the copyable row draws a copy icon")
            .computed_opacity()
            > 0.5
    };

    assert!(!lit(), "the icon should be dark with nothing on it");
    press(&probe, Key::Tab);
    assert!(lit(), "focus on the copy button should light its icon");

    // Disabled with focus on it, as opening a dialog disables what is behind
    // it, and then focus moves on; there is nowhere else for it to go here.
    probe.set_live(false);
    press(&probe, Key::Tab);
    probe.set_live(true);
    assert!(
        !lit(),
        "the copy button still showed focus after focus had left it"
    );
    assert_eq!(probe.get_copies(), 0);
}

/// In the Details dialog, a user ID's copy button covers its text and no
/// more, with Revoke beside it rather than inside it, and it copies from the
/// keyboard.
///
/// The button was the whole row, so Revoke user ID was a button inside the
/// copy button, where some screen readers do not look, and the copy button's
/// bounds lay over Revoke's. It had no keyboard path either.
#[test]
fn a_user_ids_copy_button_is_its_text_alone_and_takes_the_keyboard() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};
    use slint::platform::Key;

    const PRIMARY: &str = "Alice <alice@example.org>";
    const WORK: &str = "Alice <alice@work.example>";
    let probe = DetailsProbe::new().unwrap();
    probe.show().unwrap();

    let copies: Vec<_> = ElementHandle::find_by_accessible_label(&probe, "Copy user ID")
        .filter(|element| element.accessible_role() == Some(AccessibleRole::Button))
        .collect();
    assert_eq!(copies.len(), 2, "each user ID should have a copy button");
    let work = copies
        .iter()
        .find(|copy| copy.accessible_description().as_deref() == Some(WORK))
        .expect("the copy button should say which user ID it copies");
    let revoke = control(
        &probe,
        &format!("Revoke user ID {WORK}"),
        AccessibleRole::Button,
    );
    let inside = work
        .query_descendants()
        .match_accessible_role(AccessibleRole::Button)
        .find_first();
    assert!(
        inside.is_none(),
        "the copy button holds another button: {:?}",
        inside.and_then(|button| button.accessible_label())
    );
    let copy_right = work.absolute_position().x + work.size().width;
    assert!(
        copy_right <= revoke.absolute_position().x,
        "the copy button reaches {copy_right}px, over Revoke at {}px",
        revoke.absolute_position().x
    );

    // Tab goes through the dialog in order: the fingerprint's copy button,
    // Change and Add, then each user ID's copy button and its Revoke.
    press(&probe, Key::Tab);
    press(&probe, Key::Space);
    assert_eq!(
        probe.get_copied(),
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "the fingerprint's copy button should take the keyboard in the dialog too"
    );
    press(&probe, Key::Tab);
    press(&probe, Key::Tab);
    press(&probe, Key::Tab);
    press(&probe, Key::Space);
    assert_eq!(
        probe.get_copied(),
        PRIMARY,
        "Space should copy the first user ID"
    );
    press(&probe, Key::Tab);
    press(&probe, Key::Return);
    assert_eq!(probe.get_copied(), WORK, "Enter should copy the second");
    press(&probe, Key::Tab);
    press(&probe, Key::Space);
    assert_eq!(
        (probe.get_revoked().as_str(), probe.get_copies()),
        (WORK, 3),
        "Revoke should come next, and copy nothing"
    );

    // And assistive technology's action on the copy button, which moved with
    // the role.
    work.invoke_accessible_default_action();
    assert_eq!((probe.get_copied().as_str(), probe.get_copies()), (WORK, 4));
}

/// Each dialog that runs something says in itself why its operation failed,
/// above its buttons, and announces it; and the three dialogs with a result
/// line of their own announce that.
///
/// A failure used to go to the status line alone, under the dialog's scrim,
/// where it read at 2.4:1 in the light theme and 1.5:1 in the dark, and was
/// never announced: the button went from "Certifying…" back to "Certify" and
/// nothing said why.
#[test]
fn a_dialog_says_in_itself_why_its_operation_failed_and_announces_it() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleLiveness, AccessibleRole, ElementHandle, ElementRoot};

    const FAILED: &str = "It failed: the passphrase does not unlock the key.";

    fn said(
        dialog: &str,
        root: &impl ElementRoot,
    ) -> Option<i_slint_backend_testing::ElementHandle> {
        let mut lines = ElementHandle::find_by_accessible_label(root, FAILED);
        let line = lines.next();
        assert!(
            lines.next().is_none(),
            "{dialog}: the failure is shown twice"
        );
        line
    }

    fn check(dialog: &str, root: &impl ElementRoot, set: impl Fn(&str), button: &str) {
        assert!(
            said(dialog, root).is_none(),
            "{dialog}: a failure shown before any"
        );
        set(FAILED);
        let line = said(dialog, root)
            .unwrap_or_else(|| panic!("{dialog} does not show why its operation failed"));
        assert_eq!(line.accessible_role(), Some(AccessibleRole::Text));
        assert_eq!(
            line.accessible_live_region(),
            Some(AccessibleLiveness::Assertive),
            "{dialog}: the failure is not announced"
        );
        let button = control(root, button, AccessibleRole::Button);
        let bottom = line.absolute_position().y + line.size().height;
        assert!(
            bottom <= button.absolute_position().y,
            "{dialog}: the failure ends at {bottom}px, below the top of its buttons"
        );
        set("");
        assert!(said(dialog, root).is_none(), "{dialog}: the failure stayed");
    }

    let probe = KeygenProbe::new().unwrap();
    probe.show().unwrap();
    check(
        "New key pair",
        &probe,
        |e| probe.set_error(e.into()),
        "Create key pair",
    );
    let probe = SelectionProbe::new().unwrap();
    probe.show().unwrap();
    check(
        "Sign / Encrypt",
        &probe,
        |e| probe.set_error(e.into()),
        "Run",
    );
    let probe = CertifyProbe::new().unwrap();
    probe.show().unwrap();
    check("Certify", &probe, |e| probe.set_error(e.into()), "Certify");
    let probe = RevokeProbe::new().unwrap();
    probe.show().unwrap();
    check(
        "Revoke",
        &probe,
        |e| probe.set_error(e.into()),
        "Revoke key",
    );
    let probe = DeleteProbe::new().unwrap();
    probe.show().unwrap();
    check(
        "Delete",
        &probe,
        |e| probe.set_error(e.into()),
        "Delete key",
    );
    let probe = ImportRevocationProbe::new().unwrap();
    probe.show().unwrap();
    check(
        "Import revocation",
        &probe,
        |e| probe.set_error(e.into()),
        "Revoke",
    );
    let probe = LifecycleProbe::new().unwrap();
    probe.show().unwrap();
    check(
        "Change expiry",
        &probe,
        |e| probe.set_error(e.into()),
        "Set expiry",
    );

    // The dialogs that say how a run went in a line of their own, failures
    // included, announce it there, since the status line is not announced
    // while a dialog covers it.
    let announced = |dialog: &str, root: &dyn Fn() -> Option<AccessibleLiveness>| {
        assert_eq!(
            root(),
            Some(AccessibleLiveness::Polite),
            "{dialog}: how the run went is not announced"
        );
    };
    let probe = VerifyBannerProbe::new().unwrap();
    probe.set_result(FAILED.into());
    probe.show().unwrap();
    announced("Decrypt / Verify", &|| {
        said("Decrypt / Verify", &probe).and_then(|line| line.accessible_live_region())
    });
    let probe = NotepadProbe::new().unwrap();
    probe.set_result(FAILED.into());
    probe.show().unwrap();
    announced("the notepad", &|| {
        said("the notepad", &probe).and_then(|line| line.accessible_live_region())
    });
    let probe = LookupProbe::new().unwrap();
    probe.set_status(FAILED.into());
    probe.show().unwrap();
    announced("Lookup", &|| {
        said("Lookup", &probe).and_then(|line| line.accessible_live_region())
    });
}

/// Each dialog that says why its operation failed keeps the failure and its
/// buttons inside its card in the smallest window the app allows, when the
/// failure takes three lines; Certify does so for a certificate with several
/// user IDs.
///
/// The failure is drawn above the buttons, and Certify's form did not
/// scroll, so in that window any failure pushed Cancel and Certify partly out
/// of the card, and one of three lines pushed them out of the item tree,
/// where neither the pointer nor the keyboard could reach them. A second user
/// ID pushed them partly out with no failure at all.
#[test]
fn a_long_failure_leaves_each_dialog_its_buttons_in_the_smallest_window() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle, ElementRoot};

    const FAILED: &str = "Certification failed: the passphrase does not unlock the key \
        0123456789ABCDEF, or the key is on a card that is not inserted. Nothing was \
        written to the store, so the certificate is as it was.";
    // The main window's minimum height, all of which a dialog's scrim covers.
    const SMALLEST: f32 = 520.;

    fn fits(dialog: &str, root: &impl ElementRoot, buttons: [&str; 2]) {
        let card = ElementHandle::find_by_element_id(root, "DialogShell::card")
            .next()
            .expect("every dialog draws a card");
        let bottom = card.absolute_position().y + card.size().height;
        let line = ElementHandle::find_by_accessible_label(root, FAILED)
            .next()
            .unwrap_or_else(|| panic!("{dialog}: the failure is not in the item tree"));
        // Three lines of its 12px Geist are 47px, and two are 32px.
        assert!(
            line.size().height > 40.,
            "{dialog}: the failure takes {}px, less than three lines",
            line.size().height
        );
        let mut shown = vec![("the failure", line)];
        for label in buttons {
            let button = ElementHandle::find_by_accessible_label(root, label)
                .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
                .unwrap_or_else(|| panic!("{dialog}: {label} is not in the item tree"));
            shown.push((label, button));
        }
        for (what, element) in shown {
            let end = element.absolute_position().y + element.size().height;
            assert!(
                end <= bottom,
                "{dialog}: {what} ends {end}px down, past the card's bottom at {bottom}px"
            );
        }
    }

    let probe = KeygenProbe::new().unwrap();
    probe.set_probe_height(SMALLEST);
    probe.set_error(FAILED.into());
    probe.show().unwrap();
    fits("New key pair", &probe, ["Cancel", "Create key pair"]);

    let probe = SelectionProbe::new().unwrap();
    probe.set_probe_height(SMALLEST);
    probe.set_error(FAILED.into());
    probe.show().unwrap();
    fits("Sign / Encrypt", &probe, ["Cancel", "Run"]);

    let probe = CertifyProbe::new().unwrap();
    probe.set_probe_height(SMALLEST);
    probe.set_user_ids(slint::ModelRc::new(slint::VecModel::from(
        ["Alice", "Alice (work)", "Alice (home)"]
            .map(|name| UserIdRow {
                text: format!("{name} <alice@example.org>").into(),
                selected: true,
            })
            .to_vec(),
    )));
    probe.set_error(FAILED.into());
    probe.show().unwrap();
    fits("Certify", &probe, ["Cancel", "Certify"]);

    let probe = RevokeProbe::new().unwrap();
    probe.set_probe_height(SMALLEST);
    probe.set_error(FAILED.into());
    probe.show().unwrap();
    fits("Revoke", &probe, ["Cancel", "Revoke key"]);

    let probe = DeleteProbe::new().unwrap();
    probe.set_probe_height(SMALLEST);
    probe.set_error(FAILED.into());
    probe.show().unwrap();
    fits("Delete", &probe, ["Cancel", "Delete key"]);

    // Already the smallest window's size.
    let probe = ImportRevocationProbe::new().unwrap();
    probe.set_error(FAILED.into());
    probe.show().unwrap();
    fits("Import revocation", &probe, ["Cancel", "Revoke"]);

    // Revoking a subkey, the tallest of the lifecycle dialogs.
    let probe = LifecycleProbe::new().unwrap();
    probe.set_probe_height(SMALLEST);
    probe.set_mode(4);
    probe.set_error(FAILED.into());
    probe.show().unwrap();
    fits("Revoke a subkey", &probe, ["Cancel", "Revoke subkey"]);
}

/// Escape and a click on the scrim leave a dialog open while the operation it
/// started runs, as its Cancel does, and close it otherwise.
///
/// Every dialog's Cancel or Close is disabled while its operation runs, since
/// nothing can call one back, but Escape and the scrim closed the dialog
/// anyway. That looked like cancelling a delete, a revocation or a publish,
/// which then went on to happen.
#[test]
fn escape_and_the_scrim_leave_a_dialog_open_while_its_operation_runs() {
    i_slint_backend_testing::init_no_event_loop();
    use slint::platform::{Key, PointerEventButton, WindowEvent};

    let probe = DeleteProbe::new().unwrap();
    probe.show().unwrap();
    // Beside the card, on the scrim.
    let click_scrim = || {
        let position = slint::LogicalPosition::new(4., 4.);
        let button = PointerEventButton::Left;
        probe
            .window()
            .dispatch_event(WindowEvent::PointerPressed { position, button });
        probe
            .window()
            .dispatch_event(WindowEvent::PointerReleased { position, button });
    };

    probe.set_busy(true);
    press(&probe, Key::Escape);
    click_scrim();
    click_scrim();
    assert_eq!(
        probe.get_dismissals(),
        0,
        "the dialog was closed while its operation ran"
    );

    probe.set_busy(false);
    press(&probe, Key::Escape);
    assert_eq!(
        probe.get_dismissals(),
        1,
        "Escape should close it once done"
    );
    click_scrim();
    assert_eq!(
        probe.get_dismissals(),
        2,
        "the scrim should close it once done"
    );
}

/// A key pressed after Tab during an operation reaches no control that shows
/// no focus, and Tab goes on round the dialog's own controls once the
/// operation is over.
///
/// Everything in a dialog is disabled while its operation runs, so Tab then
/// found nothing to take it, and Slint left keys going to the control Tab had
/// left: the button that started the operation, drawn with no ring. When the
/// operation failed and the button was enabled again, one Enter ran it a
/// second time. Here a delete is started from the keyboard and fails.
#[test]
fn tabbing_while_an_operation_runs_leaves_no_button_taking_keys_unseen() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;
    use slint::platform::Key;

    let probe = DeleteProbe::new().unwrap();
    probe.show().unwrap();
    control(&probe, "0123456789ABCDEF", AccessibleRole::TextInput)
        .set_accessible_value("0123456789ABCDEF");
    // The confirmation field, Cancel, then Delete key, and Enter on it.
    let delete_from_the_keyboard = || {
        for _ in 0..3 {
            press(&probe, Key::Tab);
        }
        press(&probe, Key::Return);
    };
    delete_from_the_keyboard();
    assert_eq!(
        probe.get_runs(),
        1,
        "Tab should reach Delete key, and Enter press it"
    );

    // What the handler does as the delete starts, and what its failure does
    // when it lands.
    probe.set_busy(true);
    press(&probe, Key::Tab);
    probe.set_busy(false);
    probe.set_error("Delete failed: permission denied".into());
    press(&probe, Key::Return);
    assert_eq!(
        probe.get_runs(),
        1,
        "Enter after the failure ran the delete again, from a button showing no focus"
    );

    // Tab goes on from the frame into the dialog, and on the next round the
    // frame is no stop, since nothing is running.
    delete_from_the_keyboard();
    assert_eq!(probe.get_runs(), 2, "Tab should go on into the dialog");
    delete_from_the_keyboard();
    assert_eq!(
        (probe.get_runs(), probe.get_dismissals()),
        (3, 0),
        "the frame was a Tab stop with nothing running"
    );
}

/// A long status message is shown in full, the bar growing to hold it, up to
/// a limit past which it elides, as
/// [`a_message_too_long_for_the_status_bar_is_shown_from_its_beginning`]
/// says; and the line is announced unless the window says not to.
///
/// The bar was one line that elided, and several messages end with what to
/// do: a publish whose confirmation mail could not be asked for ends "Publish
/// again to retry", which at the window's usual width was cut off, with no way
/// to read the rest. Measured at the smallest width the window allows.
#[test]
fn a_long_status_message_is_shown_in_full() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleLiveness, ElementHandle};

    // What a publish says when the upload went through and the request for
    // the confirmation mail did not, with the error reqwest gives.
    const PUBLISHED: &str = "Published 0123456789ABCDEF0123456789ABCDEF01234567. The key is \
        uploaded, but asking for the confirmation mail to alice@example.org failed (upload \
        failed: error sending request for url \
        (https://keys.openpgp.org/vks/v1/request-verify)); until that succeeds the address is \
        stored and not served. Publish again to retry.";
    let probe = StatusProbe::new().unwrap();
    probe.show().unwrap();
    let bar = || {
        ElementHandle::find_by_element_type_name(&probe, "StatusBar")
            .next()
            .expect("the probe shows a status bar")
            .size()
            .height
    };
    let line = |text: &str| {
        ElementHandle::find_by_accessible_label(&probe, text)
            .next()
            .expect("the status bar shows the message")
    };

    probe.set_text("3 certificate(s), 1 with a secret key".into());
    let short = bar();
    assert_eq!(short, 28., "a short message takes one line");
    assert_eq!(
        line("3 certificate(s), 1 with a secret key").accessible_live_region(),
        Some(AccessibleLiveness::Polite)
    );

    // Three lines at this width, which in the bar's 12px Geist make it 57px
    // tall, where two would make it 42px. Below the limit means none of it
    // was cut.
    probe.set_text(PUBLISHED.into());
    let long = bar();
    assert!(
        long >= short + 2. * 12.,
        "the publish message was given {long}px, less than three lines"
    );
    let limit = {
        probe.set_text(PUBLISHED.repeat(8).into());
        bar()
    };
    assert!(
        long < limit,
        "the publish message reached the limit, {limit}px, and was cut"
    );
    assert_eq!(
        line(&PUBLISHED.repeat(8)).size().height,
        limit - 2. * 5.,
        "a message longer than the limit should be given all of the bar inside its inset"
    );

    // While a dialog covers it, the window stops it being announced.
    probe.set_announce(false);
    assert_eq!(
        line(&PUBLISHED.repeat(8)).accessible_live_region(),
        Some(AccessibleLiveness::Off)
    );
}

/// The probes lay text out as the window does: in the fonts the app bundles,
/// with AppWindow's default family and size.
///
/// The tests here that measure text depend on it. Laid out in the platform's
/// sans-serif instead, three lines of a dialog's failure were 50px tall on
/// Linux and 36px on macOS, where two of those tests failed alone. A probe
/// that slips back to the platform's font passes every test on Linux and
/// Windows, so this reads the sources: the probes import every font the
/// window imports, their base Probe sets the window's two defaults, and every
/// probe is built on it.
#[test]
fn the_probes_lay_text_out_as_the_window_does() {
    let read = |file: &str| {
        std::fs::read_to_string(format!("{}/{file}", env!("CARGO_MANIFEST_DIR")))
            .unwrap_or_else(|e| panic!("reading {file}: {e}"))
    };
    let window = read("ui/app-window.slint");
    let probes = read("ui/testing/field-probe.slint");

    let fonts: Vec<&str> = window
        .lines()
        .filter_map(|line| line.strip_prefix("import \"fonts/")?.strip_suffix("\";"))
        .collect();
    assert!(
        !fonts.is_empty(),
        "no font import found in app-window.slint, so this test no longer reads it right"
    );
    for font in fonts {
        assert!(
            probes.contains(&format!("import \"../fonts/{font}\";")),
            "field-probe.slint does not import {font}, which app-window.slint does"
        );
    }

    // What the component declared by `head` sets its two defaults to.
    let defaults = |source: &str, head: &str| -> [String; 2] {
        let start = source
            .find(head)
            .unwrap_or_else(|| panic!("`{head}` not found"));
        let open = start + source[start..].find('{').expect("a component has a body");
        let body = &source[open..block_end(source, open)];
        ["default-font-family:", "default-font-size:"].map(|property| {
            body.split_once(property)
                .and_then(|(_, after)| after.split(';').next())
                .unwrap_or_else(|| panic!("`{head}` sets no {property}"))
                .trim()
                .to_string()
        })
    };
    assert_eq!(
        defaults(&probes, "component Probe inherits Window"),
        defaults(&window, "export component AppWindow inherits Window"),
        "Probe's default font family and size, left, are not AppWindow's, right"
    );

    for line in probes
        .lines()
        .filter(|line| line.starts_with("export component "))
    {
        assert!(
            line.contains(" inherits Probe "),
            "field-probe.slint: `{line}` is not built on Probe, so it lays its text out in \
             the platform's font"
        );
    }
}

/// A window that Slint's software renderer draws into memory, for a test that
/// has to see what is drawn: the testing backend lays text out but draws
/// nothing. A platform belongs to the thread that sets it, and each test runs
/// on a thread of its own, so the other tests keep the testing backend.
struct CanvasPlatform(std::rc::Rc<slint::platform::software_renderer::MinimalSoftwareWindow>);

impl slint::platform::Platform for CanvasPlatform {
    fn create_window_adapter(
        &self,
    ) -> Result<std::rc::Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

/// A message too long for the status bar is shown from its beginning, and
/// what the bar cuts is its end.
///
/// Centred, as a message the bar holds is, a longer one would lose lines off
/// the top as well as the bottom, which is where Slint drops what does not fit
/// a centred text: a refused user ID, quoted back as it was typed, would be
/// shown from somewhere in the middle, without the words that say what was
/// refused. The accessibility tree has the whole message either way, so this
/// looks at the pixels.
#[test]
fn a_message_too_long_for_the_status_bar_is_shown_from_its_beginning() {
    use i_slint_backend_testing::ElementHandle;
    use slint::Rgb8Pixel;
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(CanvasPlatform(window.clone())))
        .expect("no platform is set on a test's own thread");
    let probe = StatusProbe::new().unwrap();
    // The first line is a paragraph of its own and short, which is what tells
    // it apart: every line after it runs to the width of the bar. Many times
    // more than the bar holds.
    probe.set_text(format!("Refused.\n{}", "and a great deal more after it ".repeat(60)).into());
    probe.show().unwrap();
    let (width, height) = (860, 200);
    window.set_size(slint::PhysicalSize::new(width as u32, height as u32));
    let mut pixels = vec![Rgb8Pixel::default(); width * height];
    assert!(window.draw_if_needed(|renderer| {
        renderer.render(&mut pixels, width);
    }));

    let bar = ElementHandle::find_by_element_type_name(&probe, "StatusBar")
        .next()
        .expect("the probe shows a status bar");
    let top = bar.absolute_position().y as usize;
    let bottom = top + bar.size().height as usize;
    // The bar's own colour, from its right margin, which no text reaches.
    let ground = pixels[(bottom - 2) * width + width - 4];
    let ink = |x: usize, y: usize| {
        let pixel = pixels[y * width + x];
        pixel.r.abs_diff(ground.r) as u32
            + pixel.g.abs_diff(ground.g) as u32
            + pixel.b.abs_diff(ground.b) as u32
            > 150
    };
    let rightmost = |y: usize| (0..width).rev().find(|&x| ink(x, y));

    // Below the border along the bar's top edge.
    let first = (top + 1..bottom)
        .find(|&y| rightmost(y).is_some())
        .expect("the status bar draws nothing");
    // Not as far as a whole line, so as to stay clear of the one below.
    let reach = (first..first + 8).filter_map(rightmost).max().unwrap();
    assert!(
        reach < width / 4,
        "the first line drawn runs to {reach}px, so it is not \"Refused.\": the \
         beginning of the message was cut"
    );
}

/// A row in the certificate list says what its description carries: the key
/// ID, which its second line shows where there is no address. The comment on
/// it promised the fingerprint while it published the key ID, and nothing
/// held the two to each other.
#[test]
fn a_certificate_row_describes_itself_by_its_key_id() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;

    let probe = CertListProbe::new().unwrap();
    probe.set_certs(slint::ModelRc::new(slint::VecModel::from(vec![listed(1)])));
    probe.show().unwrap();
    let row = control(
        &probe,
        "User 01 <user01@example.org>",
        AccessibleRole::ListItem,
    );
    assert_eq!(
        row.accessible_description().as_deref(),
        Some("Key ID 0000000000000001")
    );
}

/// Two keys with the same user ID read differently wherever one is chosen,
/// to the eye and to a screen reader: the recipient rows of Sign / Encrypt
/// and the notepad, and the Sign as and Certify with lists, each show every
/// key's ID beside it, and announce it.
///
/// A person's old and new key usually carry the same user ID, and so do the
/// Modern and Compatible pair the key generator offers. The recipient rows
/// showed the name and the address, and the two lists the user ID alone, so
/// the two keys read alike in all of them.
#[test]
fn keys_with_the_same_user_id_read_differently_wherever_one_is_chosen() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle, ElementRoot};

    const ALICE: &str = "Alice <alice@example.org>";
    const KEYS: [&str; 2] = ["A11CE00000000001", "A11CE00000000002"];
    let twins = || {
        slint::ModelRc::new(slint::VecModel::from(
            KEYS.iter()
                .map(|key_id| RecipientRow {
                    fingerprint: (*key_id).into(),
                    label: "Alice".into(),
                    sublabel: "alice@example.org".into(),
                    key_id: (*key_id).into(),
                    initials: "A".into(),
                    tint_index: 0,
                    selected: false,
                })
                .collect::<Vec<_>>(),
        ))
    };
    let labels = || {
        slint::ModelRc::new(slint::VecModel::from(vec![
            slint::SharedString::from(ALICE);
            2
        ]))
    };
    let key_ids = || {
        slint::ModelRc::new(slint::VecModel::from(
            KEYS.map(slint::SharedString::from).to_vec(),
        ))
    };

    // Each recipient row is announced with its key ID, and draws it.
    fn rows_differ(dialog: &str, root: &impl ElementRoot) {
        for key_id in KEYS {
            control(
                root,
                &format!("Alice, alice@example.org, key ID {key_id}"),
                AccessibleRole::Checkbox,
            );
            assert_eq!(
                ElementHandle::find_by_accessible_label(root, key_id).count(),
                1,
                "{dialog}: the recipient row should show {key_id}"
            );
        }
    }
    // The list's value names the chosen key's ID after its user ID, in the
    // words a recipient row uses, the closed list draws it, and the open list
    // draws every key's.
    fn choices_differ(dialog: &str, root: &impl ElementRoot, label: &str) {
        let count = |key_id: &str| ElementHandle::find_by_accessible_label(root, key_id).count();
        let select = control(root, label, AccessibleRole::Combobox);
        assert_eq!(
            select.accessible_value().as_deref(),
            Some(format!("{ALICE}, key ID {}", KEYS[0]).as_str()),
            "{dialog}: {label} should announce the chosen key's ID"
        );
        assert_eq!(
            (count(KEYS[0]), count(KEYS[1])),
            (1, 0),
            "{dialog}: {label} should show the chosen key's ID"
        );
        select.invoke_accessible_default_action();
        assert_eq!(
            (count(KEYS[0]), count(KEYS[1])),
            (2, 1),
            "{dialog}: {label}'s list should show each key's ID"
        );
    }

    let probe = SelectionProbe::new().unwrap();
    probe.set_signers(slint::ModelRc::default());
    probe.set_recipients(twins());
    probe.show().unwrap();
    rows_differ("Sign / Encrypt", &probe);
    probe.hide().unwrap();

    let probe = SelectionProbe::new().unwrap();
    probe.set_signers(labels());
    probe.set_signer_key_ids(key_ids());
    probe.show().unwrap();
    choices_differ("Sign / Encrypt", &probe, "Sign as");
    probe.hide().unwrap();

    let probe = NotepadProbe::new().unwrap();
    probe.set_recipients(twins());
    probe.show().unwrap();
    rows_differ("The notepad", &probe);
    probe.hide().unwrap();

    let probe = NotepadProbe::new().unwrap();
    probe.set_signers(labels());
    probe.set_signer_key_ids(key_ids());
    probe.show().unwrap();
    choices_differ("The notepad", &probe, "Sign as");
    probe.hide().unwrap();

    let probe = CertifyProbe::new().unwrap();
    probe.set_certifiers(labels());
    probe.set_certifier_key_ids(key_ids());
    probe.show().unwrap();
    choices_differ("Certify", &probe, "Certify with");
}

/// A recipient with no address has its name in the middle of its row in
/// Sign / Encrypt, with no empty line under it.
///
/// The key ID used to take the address's line where there was none. Once it
/// had a column of its own that line was left empty, and an empty line still
/// takes its height, so the name sat above the middle of the row.
#[test]
fn a_recipient_with_no_address_has_its_name_in_the_middle_of_its_row() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    const KEY_ID: &str = "3A11000000000001";
    let probe = SelectionProbe::new().unwrap();
    probe.set_signers(slint::ModelRc::default());
    probe.set_recipients(slint::ModelRc::new(slint::VecModel::from(vec![
        RecipientRow {
            fingerprint: KEY_ID.into(),
            label: "Mallory".into(),
            sublabel: "".into(),
            key_id: KEY_ID.into(),
            initials: "M".into(),
            tint_index: 0,
            selected: false,
        },
    ])));
    probe.show().unwrap();

    let row = control(
        &probe,
        &format!("Mallory, key ID {KEY_ID}"),
        AccessibleRole::Checkbox,
    );
    let name = ElementHandle::find_by_accessible_label(&probe, "Mallory")
        .next()
        .expect("the row shows the name");
    let middle =
        |element: &ElementHandle| element.absolute_position().y + element.size().height / 2.0;
    assert!(
        (middle(&name) - middle(&row)).abs() <= 1.0,
        "the name's middle is at {}, the row's at {}",
        middle(&name),
        middle(&row)
    );
}

/// The note left with a revocation is shown under the reason, as a note of
/// its own in quotation marks, and the banner grows to hold it however long
/// it runs; the dialog that asks before a revocation is stored shows it the
/// same way.
///
/// Whoever holds a key writes the note, a thief included. It used to follow
/// the app's reason after a dash, in the same red, as one sentence, so that
/// "Replaced by a newer key — use 0x… instead" read as the app's advice.
#[test]
fn a_revocation_note_is_quoted_apart_from_its_reason() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;

    const REASON: &str = "Replaced by a newer key";
    let probe = RevocationBannerProbe::new().unwrap();
    probe.show().unwrap();
    let find = |label: &str| {
        ElementHandle::find_by_accessible_label(&probe, label)
            .next()
            .unwrap_or_else(|| panic!("nothing in the banner reads {label:?}"))
    };
    let quoted = |note: &str| format!("Note left with the revocation: “{note}”");
    assert_eq!(
        ElementHandle::find_by_accessible_label(&probe, &quoted("")).count(),
        0,
        "with no note there is no note line"
    );

    for note in [
        "use 0x1234 instead".to_string(),
        "and a great deal more after it ".repeat(12),
    ] {
        probe.set_note(note.as_str().into());
        let banner = ElementHandle::find_by_element_type_name(&probe, "RevocationBanner")
            .next()
            .expect("the probe shows the banner");
        let (reason, note) = (find(REASON), find(&quoted(&note)));
        let bottom =
            |element: &ElementHandle| element.absolute_position().y + element.size().height;
        assert!(
            bottom(&reason) <= note.absolute_position().y,
            "the note should be on lines of its own under the reason"
        );
        assert!(
            bottom(&note) <= bottom(&banner),
            "the note runs out of the banner: {} past {}",
            bottom(&note),
            bottom(&banner)
        );
    }

    let probe = ImportRevocationProbe::new().unwrap();
    probe.set_revocations(slint::ModelRc::new(slint::VecModel::from(vec![
        PendingRevocationRow {
            name: "Me <me@example.org>".into(),
            reason: REASON.into(),
            note: "use 0x1234 instead".into(),
            hard: false,
            yours: true,
        },
    ])));
    probe.show().unwrap();
    assert!(
        ElementHandle::find_by_accessible_label(&probe, REASON)
            .next()
            .is_some()
            && ElementHandle::find_by_accessible_label(&probe, &quoted("use 0x1234 instead"))
                .next()
                .is_some(),
        "the import dialog should show the reason and the note apart"
    );
}

/// The notepad gives its verdict on a signature before the signer's name,
/// and nothing of its own after it.
///
/// The name is the signer's to choose. Followed by the verdict, a user ID
/// ending in "(verified)" put a verdict of its own where the app's belonged,
/// and pushed the real one after it.
#[test]
fn the_notepad_gives_its_verdict_before_the_signers_name() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;

    let probe = NotepadProbe::new().unwrap();
    probe.set_result("Valid signature, but the signer's identity is not verified".into());
    probe.set_signatures(slint::ModelRc::new(slint::VecModel::from(vec![
        SignatureRow {
            good: true,
            signer: "Alice <alice@example.org> (verified)".into(),
            authentication: "unverified".into(),
            ..Default::default()
        },
        SignatureRow {
            good: true,
            signer: "Bob <bob@example.org>".into(),
            authentication: "unverified".into(),
            sha1: true,
            ..Default::default()
        },
    ])));
    probe.show().unwrap();
    for line in [
        "good signature (unverified) — Alice <alice@example.org> (verified)",
        "good signature (unverified, SHA-1) — Bob <bob@example.org>",
    ] {
        assert!(
            ElementHandle::find_by_accessible_label(&probe, line)
                .next()
                .is_some(),
            "the notepad should read {line:?}"
        );
    }
}

/// In the Details dialog, a user ID with a hidden character in it is shown,
/// announced and copied written out, and Revoke user ID names it as the
/// certificate has it, which is how rpgp-core finds it.
#[test]
fn a_user_id_is_shown_written_out_and_revoked_as_the_certificate_has_it() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle};

    const SHOWN: &str = "M[U+200B]al";
    const STORED: &str = "M\u{200B}al";
    let probe = DetailsProbe::new().unwrap();
    probe.set_user_ids(slint::ModelRc::new(slint::VecModel::from(vec![
        UserIdDetailRow {
            text: "Mal".into(),
            user_id: "Mal".into(),
            is_primary: true,
            ..Default::default()
        },
        UserIdDetailRow {
            text: SHOWN.into(),
            user_id: STORED.into(),
            ..Default::default()
        },
    ])));
    probe.show().unwrap();

    assert!(
        ElementHandle::find_by_accessible_label(&probe, SHOWN)
            .next()
            .is_some(),
        "the user ID should be shown written out"
    );
    let copy = ElementHandle::find_by_accessible_label(&probe, "Copy user ID")
        .find(|copy| copy.accessible_description().as_deref() == Some(SHOWN))
        .expect("the copy button should say which user ID it copies, as shown");
    copy.invoke_accessible_default_action();
    assert_eq!(probe.get_copied(), SHOWN);

    control(
        &probe,
        &format!("Revoke user ID {SHOWN}"),
        AccessibleRole::Button,
    )
    .invoke_accessible_default_action();
    assert_eq!(probe.get_revoked(), STORED);
}

/// The relative luminance WCAG weighs a colour by.
fn luminance(colour: slint::Color) -> f64 {
    let channel = |value: u8| {
        let value = f64::from(value) / 255.;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(colour.red())
        + 0.7152 * channel(colour.green())
        + 0.0722 * channel(colour.blue())
}

/// The WCAG contrast ratio between two opaque colours, from 1 to 21.
fn contrast(a: slint::Color, b: slint::Color) -> f64 {
    let (a, b) = (luminance(a), luminance(b));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// `top` drawn over the opaque `base`, as a translucent surface is.
fn over(top: slint::Color, base: slint::Color) -> slint::Color {
    let alpha = f32::from(top.alpha()) / 255.;
    let mix =
        |top: u8, base: u8| (f32::from(top) * alpha + f32::from(base) * (1. - alpha)).round() as u8;
    slint::Color::from_rgb_u8(
        mix(top.red(), base.red()),
        mix(top.green(), base.green()),
        mix(top.blue(), base.blue()),
    )
}

/// The label of a filled button, and text in `text` or `text-dim`, reach 4.5:1
/// against what they are drawn on, in the light theme and the dark: a button
/// at rest, under the pointer and pressed, and the inks on every surface, a
/// hovered or selected row and the warn-soft banner over it included.
///
/// WCAG asks 4.5:1 of text under 18px, and a button's label is 13px. The dark
/// theme's fills are light, and its white labels came to 3.0:1 on a primary
/// button, 2.5:1 on one under the pointer and 2.4:1 on Delete key. text-faint
/// is left out on purpose: it is under 4.5:1 everywhere and kept for what
/// need not be read, which is why the lines it used to carry are text-dim.
/// Nor are pill labels checked: several fall short, as README.md says.
#[test]
fn text_and_the_labels_on_filled_buttons_reach_four_and_a_half_to_one_in_both_themes() {
    i_slint_backend_testing::init_no_event_loop();

    let probe = ThemeProbe::new().unwrap();
    let mut faint = Vec::new();
    for dark in [false, true] {
        probe.invoke_use_dark(dark);
        let theme = if dark { "dark" } else { "light" };
        let mut check = |what: String, ink: slint::Color, ground: slint::Color| {
            let ratio = contrast(ink, ground);
            if ratio < 4.5 {
                faint.push(format!("{theme}: {what} is {ratio:.2}:1"));
            }
        };

        let label = probe.get_accent_ink().color();
        for (fill, colour) in [
            ("accent", probe.get_accent()),
            ("accent-hover", probe.get_accent_hover()),
            ("danger", probe.get_danger()),
            ("danger-hover", probe.get_danger_hover()),
        ] {
            check(format!("accent-ink on {fill}"), label, colour.color());
        }

        let (hover, selected) = (probe.get_hover().color(), probe.get_selected().color());
        let mut surfaces = Vec::new();
        for (name, base) in [
            ("bg", probe.get_bg().color()),
            ("surface", probe.get_surface().color()),
            ("surface-sunken", probe.get_surface_sunken().color()),
        ] {
            surfaces.push((name.to_string(), base));
            surfaces.push((format!("hover over {name}"), over(hover, base)));
            surfaces.push((format!("selected over {name}"), over(selected, base)));
        }
        surfaces.push((
            "warn-soft over surface".to_string(),
            over(probe.get_warn_soft().color(), probe.get_surface().color()),
        ));
        for (ink, colour) in [
            ("text", probe.get_text()),
            ("text-dim", probe.get_text_dim()),
        ] {
            for (surface, ground) in &surfaces {
                check(format!("{ink} on {surface}"), colour.color(), *ground);
            }
        }
    }
    assert!(faint.is_empty(), "too faint to read:\n{}", faint.join("\n"));
}

/// A danger button stays red under the pointer and while it is pressed, and a
/// primary one still takes accent-hover.
///
/// Every filled button took accent-hover, so Delete key, Revoke key and
/// Publish permanently turned blue under the pointer, and lost the red that
/// says they cannot be undone at the moment they were pressed.
#[test]
fn a_danger_button_stays_red_under_the_pointer_and_while_pressed() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;
    use slint::platform::{PointerEventButton, WindowEvent};

    let probe = ThemeProbe::new().unwrap();
    probe.show().unwrap();
    // Past the fill's animation.
    let settle =
        || i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(500));
    let centre = |label: &str| {
        let button = control(&probe, label, AccessibleRole::Button);
        let (at, size) = (button.absolute_position(), button.size());
        slint::LogicalPosition::new(at.x + size.width / 2., at.y + size.height / 2.)
    };
    let away = slint::LogicalPosition::new(290., 110.);
    let button = PointerEventButton::Left;

    for dark in [false, true] {
        probe.invoke_use_dark(dark);
        let theme = if dark { "dark" } else { "light" };
        let window = probe.window();

        window.dispatch_event(WindowEvent::PointerMoved { position: away });
        settle();
        assert_eq!(
            probe.get_danger_fill().color(),
            probe.get_danger().color(),
            "{theme}: Delete key at rest"
        );

        let position = centre("Delete key");
        window.dispatch_event(WindowEvent::PointerMoved { position });
        settle();
        let hovered = probe.get_danger_fill().color();
        window.dispatch_event(WindowEvent::PointerPressed { position, button });
        settle();
        let pressed = probe.get_danger_fill().color();
        window.dispatch_event(WindowEvent::PointerReleased { position, button });
        for (state, fill) in [("under the pointer", hovered), ("pressed", pressed)] {
            assert_eq!(
                fill,
                probe.get_danger_hover().color(),
                "{theme}: Delete key {state} is filled {fill:?}, not danger-hover (accent-hover is \
                 {:?})",
                probe.get_accent_hover().color()
            );
        }

        let position = centre("Certify");
        window.dispatch_event(WindowEvent::PointerMoved { position });
        settle();
        assert_eq!(
            probe.get_primary_fill().color(),
            probe.get_accent_hover().color(),
            "{theme}: Certify under the pointer"
        );
    }
}

/// The status bar's dot pulses while an operation runs.
///
/// Its opacity carried an endless animation, but on a constant, and Slint
/// compiles a constant binding to a plain value and drops its animation: the
/// dot sat at 40% for as long as the app was busy, and nothing on screen moved.
#[test]
fn the_busy_dot_pulses_while_an_operation_runs() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;

    let probe = StatusProbe::new().unwrap();
    probe.set_text("Generating a key pair…".into());
    probe.set_busy(true);
    probe.show().unwrap();
    let dot = ElementHandle::find_by_element_id(&probe, "StatusBar::dot")
        .next()
        .expect("a busy status bar draws its dot");

    // Eight looks, evenly over one pulse, 1.4s.
    let mut seen = Vec::new();
    for _ in 0..8 {
        seen.push(dot.computed_opacity());
        i_slint_backend_testing::mock_elapsed_time(std::time::Duration::from_millis(175));
    }
    let low = seen.iter().copied().fold(f32::MAX, f32::min);
    let high = seen.iter().copied().fold(f32::MIN, f32::max);
    assert!(
        high - low >= 0.5,
        "over a pulse the dot's opacity went only from {low} to {high}: {seen:?}"
    );
}

/// A lookup result shows the whole of its fingerprint: on one line where it
/// fits, as a v4 one does, and wrapped where it does not, as a v6 one does,
/// with its second line inside the list rather than below it.
///
/// Each row put the fingerprint beside a pill naming where it was found and
/// the Import button, and elided it once those had taken their share: as much
/// as the last eight digits of a v4 fingerprint and half of a v6 one, under a
/// line asking the user to check the fingerprint against its owner.
#[test]
fn a_lookup_result_shows_the_whole_of_its_fingerprint() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::ElementHandle;

    const V4: &str = "0D76 F9AE 2567 80A2 AFC5 8A6A 3D82 7887 1C1A F2DB";
    const V6: &str = "26E9 A366 5CEB 35DD DF5E 24A9 7EBE E2F5 FE05 6B93 1257 209F 4D40 C5A2 \
        BE8B 16D1";
    let found = |user_id: &str, fingerprint: &str, source: &str| LookupRow {
        primary_user_id: user_id.into(),
        fingerprint_pretty: fingerprint.into(),
        source: source.into(),
        initials: "A".into(),
        ..Default::default()
    };
    let probe = LookupProbe::new().unwrap();
    probe.set_results(slint::ModelRc::new(slint::VecModel::from(vec![
        found("Bob <bob@example.org>", V4, "web key directory"),
        found("Alice <alice@example.org>", V6, "keyserver"),
    ])));
    probe.set_measured(V4.into());
    probe.show().unwrap();

    let shown = |fingerprint: &str| {
        ElementHandle::find_by_accessible_label(&probe, fingerprint)
            .next()
            .unwrap_or_else(|| panic!("the results should show {fingerprint}"))
    };
    let (v4, v6) = (shown(V4), shown(V6));
    assert!(
        v4.size().width >= probe.get_one_line(),
        "the v4 fingerprint was given {}px of the {}px it takes on one line",
        v4.size().width,
        probe.get_one_line()
    );
    assert!(
        v6.size().height >= 2. * v4.size().height,
        "the v6 fingerprint was given {}px, not the two lines of {}px it takes",
        v6.size().height,
        v4.size().height
    );
    let bottom = |element: &ElementHandle| element.absolute_position().y + element.size().height;
    let list = ElementHandle::find_by_element_id(&probe, "LookupDialog::found")
        .next()
        .expect("the results are listed");
    assert!(
        bottom(&v6) <= bottom(&list),
        "the v6 fingerprint ends {}px down, below the list, which ends at {}px",
        bottom(&v6),
        bottom(&list)
    );
}

/// The notepad after a run, and Lookup with more results than fit, keep their
/// buttons inside the card in the smallest window the app allows, as the
/// dialogs with a long failure above do.
///
/// Neither scrolled. A run adds its verdict and its output to the notepad,
/// which then asked for 748px, more than even the default window leaves the
/// card, and in the smallest one the buttons were out of the item tree, where
/// neither the pointer nor the keyboard reaches. Lookup lists however many
/// certificates a search returns, and lost Close the same way at eight.
#[test]
fn the_notepad_after_a_run_and_a_long_lookup_keep_their_buttons_in_the_smallest_window() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::{AccessibleRole, ElementHandle, ElementRoot};

    // The main window's minimum height, all of which a dialog's scrim covers.
    const SMALLEST: f32 = 520.;

    fn inside(dialog: &str, root: &impl ElementRoot, buttons: &[&str]) {
        let card = ElementHandle::find_by_element_id(root, "DialogShell::card")
            .next()
            .expect("every dialog draws a card");
        let bottom = card.absolute_position().y + card.size().height;
        for label in buttons {
            let button = ElementHandle::find_by_accessible_label(root, label)
                .find(|element| element.accessible_role() == Some(AccessibleRole::Button))
                .unwrap_or_else(|| panic!("{dialog}: {label} is not in the item tree"));
            let end = button.absolute_position().y + button.size().height;
            assert!(
                end <= bottom,
                "{dialog}: {label} ends {end}px down, past the card's bottom at {bottom}px"
            );
        }
    }

    let probe = NotepadProbe::new().unwrap();
    probe.set_probe_height(SMALLEST);
    probe.set_signers(slint::ModelRc::new(slint::VecModel::from(vec![
        slint::SharedString::from("Alice <alice@example.org>"),
    ])));
    probe.set_result("Decrypted. The message was signed.".into());
    probe.set_signatures(slint::ModelRc::new(slint::VecModel::from(vec![
        SignatureRow {
            good: true,
            signer: "Bob <bob@example.org>".into(),
            authentication: "unverified".into(),
            ..Default::default()
        },
    ])));
    probe.set_output("The meeting is at noon.\n".repeat(12).into());
    probe.show().unwrap();
    inside(
        "the notepad",
        &probe,
        &[
            "Close",
            "Decrypt / Verify",
            "Sign",
            "Encrypt",
            "Sign & Encrypt",
        ],
    );

    let probe = LookupProbe::new().unwrap();
    probe.set_probe_height(SMALLEST);
    probe.set_status(
        "8 certificate(s) found. Check the fingerprint against the owner before trusting it."
            .into(),
    );
    probe.set_results(slint::ModelRc::new(slint::VecModel::from(
        (1..=8)
            .map(|number| LookupRow {
                primary_user_id: format!("Bob {number} <bob@example.org>").into(),
                fingerprint_pretty: "0D76 F9AE 2567 80A2 AFC5 8A6A 3D82 7887 1C1A F2DB".into(),
                source: "keyserver".into(),
                initials: "B".into(),
                ..Default::default()
            })
            .collect::<Vec<_>>(),
    )));
    probe.show().unwrap();
    inside("Lookup", &probe, &["Close"]);
}

/// Where `x`, `y` within LongSelectProbe's open list is in the window. An
/// option reports where it is within the list, which opens 4px under the
/// Select, as `an_open_list_takes_no_choice_once_its_select_is_disabled` has
/// it.
fn in_long_list(probe: &LongSelectProbe, x: f32, y: f32) -> slint::LogicalPosition {
    let select = control(
        probe,
        "Sign as",
        i_slint_backend_testing::AccessibleRole::Combobox,
    );
    let (at, size) = (select.absolute_position(), select.size());
    slint::LogicalPosition::new(at.x + x, at.y + size.height + 4. + y)
}

/// Click the option called `label` in LongSelectProbe's open list.
fn click_in_long_list(probe: &LongSelectProbe, label: &str) {
    use slint::platform::{PointerEventButton, WindowEvent};
    let option = i_slint_backend_testing::ElementHandle::find_by_accessible_label(probe, label)
        .next()
        .unwrap_or_else(|| panic!("the open list does not show {label} where it can be clicked"));
    let (at, size) = (option.absolute_position(), option.size());
    let position = in_long_list(probe, at.x + size.width / 2., at.y + size.height / 2.);
    let button = PointerEventButton::Left;
    let window = probe.window();
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerPressed { position, button });
    window.dispatch_event(WindowEvent::PointerReleased { position, button });
}

/// How many times `label` is on screen in LongSelectProbe: once more than the
/// Select shows for an option in view in the open list. An option scrolled out
/// of view is not counted.
fn times_shown(probe: &LongSelectProbe, label: &str) -> usize {
    i_slint_backend_testing::ElementHandle::find_by_accessible_label(probe, label).count()
}

/// A list longer than its popup scrolls to its later options, and opens at
/// the chosen one, so that every option can be chosen with the pointer.
///
/// The popup is 240px tall, and its options were a plain column, so from the
/// ninth on they were drawn below it, where a click counts as outside the
/// popup and closes the list without choosing. The lists of keys to sign and
/// certify with hold every key that can, however many there are.
#[test]
fn a_long_list_scrolls_to_its_later_options_and_opens_at_the_chosen_one() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;
    use slint::platform::WindowEvent;

    // Opened at the first option, scrolled down with the wheel, and the last
    // one clicked.
    let probe = LongSelectProbe::new().unwrap();
    probe.show().unwrap();
    control(&probe, "Sign as", AccessibleRole::Combobox).invoke_accessible_default_action();
    assert_eq!(
        times_shown(&probe, "Key 1"),
        2,
        "the list should open at its first option"
    );
    probe.window().dispatch_event(WindowEvent::PointerScrolled {
        position: in_long_list(&probe, 40., 100.),
        delta_x: 0.,
        delta_y: -400.,
    });
    click_in_long_list(&probe, "Key 12");
    assert_eq!(
        (probe.get_current(), probe.get_changes()),
        (11, 1),
        "clicking the twelfth option, scrolled to, should choose it"
    );
    assert_eq!(
        times_shown(&probe, "Key 12"),
        1,
        "choosing an option should close the list"
    );

    // Opened with the last option chosen: far enough down to show it, and the
    // options just above it with it.
    let probe = LongSelectProbe::new().unwrap();
    probe.set_current(11);
    probe.show().unwrap();
    control(&probe, "Sign as", AccessibleRole::Combobox).invoke_accessible_default_action();
    click_in_long_list(&probe, "Key 10");
    assert_eq!(
        (probe.get_current(), probe.get_changes()),
        (9, 1),
        "the list should open at the twelfth option, chosen, with the tenth in reach"
    );

    // Opened with a choice past the end of the list, as one left over from a
    // longer list would be: at the end, and not scrolled past it to nothing.
    let probe = LongSelectProbe::new().unwrap();
    probe.set_current(20);
    probe.show().unwrap();
    control(&probe, "Sign as", AccessibleRole::Combobox).invoke_accessible_default_action();
    assert_eq!(
        times_shown(&probe, "Key 12"),
        1,
        "a choice past the end should open the list at its last option"
    );
}

/// Dragging an open list's scrollbar scrolls the list and leaves it open.
///
/// A popup closes by default on a click that ends inside it as well as on one
/// outside, so the list went away as its scrollbar was let go, having chosen
/// nothing. It now closes on a click outside it, or once an option is chosen.
#[test]
fn dragging_an_open_lists_scrollbar_scrolls_it_and_leaves_it_open() {
    i_slint_backend_testing::init_no_event_loop();
    use i_slint_backend_testing::AccessibleRole;
    use slint::platform::{PointerEventButton, WindowEvent};

    let probe = LongSelectProbe::new().unwrap();
    probe.show().unwrap();
    let select = control(&probe, "Sign as", AccessibleRole::Combobox);
    select.invoke_accessible_default_action();

    // std-widgets' scrollbar lies along the right edge of the scrolling area,
    // 14px wide; the area is inset 4px in the popup, which is as wide as the
    // Select. Pressed near its top, and let go well inside the popup, which is
    // 240px tall: a click inside that chooses nothing.
    let x = select.size().width - 4. - 7.;
    let button = PointerEventButton::Left;
    let window = probe.window();
    let position = in_long_list(&probe, x, 30.);
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerPressed { position, button });
    let position = in_long_list(&probe, x, 200.);
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerReleased { position, button });

    let options_shown: usize = (1..=12)
        .map(|number| times_shown(&probe, &format!("Key {number}")))
        .sum();
    assert!(
        options_shown > 1,
        "letting go of the scrollbar closed the list"
    );
    assert_eq!(
        (times_shown(&probe, "Key 1"), times_shown(&probe, "Key 12")),
        (1, 1),
        "the drag should have scrolled the list from its first option to its last"
    );
    click_in_long_list(&probe, "Key 12");
    assert_eq!(
        (probe.get_current(), probe.get_changes()),
        (11, 1),
        "the last option, dragged to, should be chosen by a click"
    );
}

/// Each line that says something, rather than naming a section or counting,
/// is drawn at 4.5:1 or more against what is behind it.
///
/// Explanations, details and identifiers were drawn in text-faint, which comes
/// to 2.4 to 3.1:1 in the light theme: the line under Trust root, the names of
/// the details pane's fields, the capabilities and expiry of each certificate
/// in the list, the self-signature date of a user ID, the key IDs and
/// addresses that tell recipients and signers apart, and the fingerprint
/// Lookup asks the user to check. The theme test holds text-dim to 4.5:1; this
/// looks at the pixels, so that a line put back in text-faint is caught too.
/// Drawn at three times the size, so that a glyph's stems cover whole pixels
/// and its inkiest pixel is its ink rather than a blend of ink and ground. The
/// probes are in the light theme, where text-faint falls short everywhere.
#[test]
fn lines_that_say_something_are_drawn_at_four_and_a_half_to_one() {
    use i_slint_backend_testing::{AccessibleRole, ElementHandle, ElementRoot};
    use slint::platform::WindowEvent;
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
    use slint::{ComponentHandle, Rgb8Pixel};

    const SCALE: f32 = 3.;

    /// Draw `probe`, `width` by `height` as it declares itself, and give the
    /// contrast of each of `lines` against the colour most of its box is.
    fn measure(
        window: &MinimalSoftwareWindow,
        probe: &(impl ComponentHandle + ElementRoot),
        (width, height): (f32, f32),
        lines: &[&str],
    ) -> Vec<(String, f64)> {
        probe.show().unwrap();
        let (across, down) = ((width * SCALE) as usize, (height * SCALE) as usize);
        window.set_size(slint::PhysicalSize::new(across as u32, down as u32));
        let mut pixels = vec![Rgb8Pixel::default(); across * down];
        window.request_redraw();
        assert!(window.draw_if_needed(|renderer| {
            renderer.render(&mut pixels, across);
        }));
        let colour = |x: usize, y: usize| {
            let pixel = pixels[y * across + x];
            slint::Color::from_rgb_u8(pixel.r, pixel.g, pixel.b)
        };

        let measured = lines
            .iter()
            .map(|line| {
                let text = ElementHandle::find_by_accessible_label(probe, line)
                    .find(|element| element.accessible_role() == Some(AccessibleRole::Text))
                    .unwrap_or_else(|| panic!("nothing shows {line:?}"));
                let (at, size) = (text.absolute_position(), text.size());
                let xs =
                    (at.x * SCALE) as usize..(((at.x + size.width) * SCALE) as usize).min(across);
                let ys =
                    (at.y * SCALE) as usize..(((at.y + size.height) * SCALE) as usize).min(down);
                let mut counts = std::collections::HashMap::new();
                for y in ys.clone() {
                    for x in xs.clone() {
                        let c = colour(x, y);
                        *counts.entry((c.red(), c.green(), c.blue())).or_insert(0) += 1;
                    }
                }
                let ((r, g, b), _) = counts
                    .into_iter()
                    .max_by_key(|&(_, count)| count)
                    .unwrap_or_else(|| panic!("{line:?} has no box to draw in"));
                let ground = slint::Color::from_rgb_u8(r, g, b);
                let ink = ys
                    .flat_map(|y| xs.clone().map(move |x| (x, y)))
                    .map(|(x, y)| contrast(colour(x, y), ground))
                    .fold(1., f64::max);
                (line.to_string(), ink)
            })
            .collect();
        probe.hide().unwrap();
        measured
    }

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(CanvasPlatform(window.clone())))
        .expect("no platform is set on a test's own thread");
    window.dispatch_event(WindowEvent::ScaleFactorChanged {
        scale_factor: SCALE,
    });
    let mut measured = Vec::new();

    let probe = TrustRootProbe::new().unwrap();
    measured.extend(measure(
        &window,
        &probe,
        (360., 160.),
        &["Certifications made by this key count as evidence."],
    ));

    let probe = CopyProbe::new().unwrap();
    measured.extend(measure(
        &window,
        &probe,
        (400., 120.),
        &["Fingerprint", "Algorithm"],
    ));

    // The first row selected, the second not.
    let probe = CertListProbe::new().unwrap();
    probe.set_certs(slint::ModelRc::new(slint::VecModel::from(vec![
        CertRow {
            capabilities: "CSE".into(),
            ..listed(1)
        },
        CertRow {
            capabilities: "CS".into(),
            expires: "2028-03-14".into(),
            ..listed(2)
        },
    ])));
    probe.set_current_row(0);
    measured.extend(measure(
        &window,
        &probe,
        (600., 400.),
        &["CSE · never expires", "CS · until 2028-03-14"],
    ));

    let probe = DetailsProbe::new().unwrap();
    measured.extend(measure(
        &window,
        &probe,
        (760., 720.),
        &["self-signed 2026-01-01"],
    ));

    let probe = LookupProbe::new().unwrap();
    probe.set_results(slint::ModelRc::new(slint::VecModel::from(vec![
        LookupRow {
            primary_user_id: "Bob <bob@example.org>".into(),
            fingerprint_pretty: "0D76 F9AE 2567 80A2 AFC5 8A6A 3D82 7887 1C1A F2DB".into(),
            source: "keyserver".into(),
            initials: "B".into(),
            ..Default::default()
        },
    ])));
    measured.extend(measure(
        &window,
        &probe,
        (620., 720.),
        &["0D76 F9AE 2567 80A2 AFC5 8A6A 3D82 7887 1C1A F2DB"],
    ));

    // A recipient's address and key ID, and the signer's key ID.
    let probe = SelectionProbe::new().unwrap();
    probe.set_recipients(slint::ModelRc::new(slint::VecModel::from(vec![
        RecipientRow {
            label: "Bob".into(),
            sublabel: "bob@example.org".into(),
            key_id: "0123456789ABCDEF".into(),
            initials: "B".into(),
            ..Default::default()
        },
    ])));
    probe.set_signer_key_ids(slint::ModelRc::new(slint::VecModel::from(vec![
        slint::SharedString::from("FEDCBA9876543210"),
    ])));
    measured.extend(measure(
        &window,
        &probe,
        (620., 720.),
        &["bob@example.org", "0123456789ABCDEF", "FEDCBA9876543210"],
    ));

    let faint: Vec<_> = measured
        .iter()
        .filter(|(_, ratio)| *ratio < 4.5)
        .map(|(line, ratio)| format!("{line:?} at {ratio:.2}:1"))
        .collect();
    assert!(
        faint.is_empty(),
        "drawn too faint to read:\n{}",
        faint.join("\n")
    );
}
