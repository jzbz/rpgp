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

    let recipient = |label: &str, mail: &str, selected: bool| RecipientRow {
        fingerprint: label.into(),
        label: label.into(),
        sublabel: mail.into(),
        initials: label[..1].into(),
        tint_index: 0,
        selected,
    };

    let probe = SelectionProbe::new().unwrap();
    probe.set_recipients(slint::ModelRc::new(slint::VecModel::from(vec![
        recipient("Alice", "alice@example.org", false),
        recipient("Bob", "bob@example.org", true),
    ])));
    probe.show().unwrap();

    // The address is part of the name, not decoration: it is the only thing
    // separating two keys held for the same person.
    let row = |name: &str| {
        ElementHandle::find_by_accessible_label(&probe, name)
            .next()
            .unwrap_or_else(|| panic!("no recipient row is called {name:?}"))
    };
    let alice = || row("Alice, alice@example.org");
    let bob = || row("Bob, bob@example.org");

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
            initials: "A".into(),
            tint_index: 0,
            selected: true,
        },
    ])));
    probe.show().unwrap();

    let row = ElementHandle::find_by_accessible_label(&probe, "Alice, alice@example.org")
        .next()
        .expect("the notepad's recipient row announces nothing");
    assert_eq!(row.accessible_role(), Some(AccessibleRole::Checkbox));
    assert_eq!(row.accessible_checked(), Some(true));

    row.invoke_accessible_default_action();
    assert_eq!(probe.get_toggled_recipient(), 0);
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

    // A passphrase field in a dialog no probe instantiates, or one behind a
    // condition no probe satisfies, would be silently uncovered — so hold the
    // count against the source rather than against a number written here.
    let declared =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ui/dialogs.slint"))
            .expect("reading ui/dialogs.slint")
            .matches("secret: true")
            .count();
    assert_eq!(
        reached, declared,
        "ui/dialogs.slint marks {declared} fields secret but only {reached} were reached \
         through a probe — add a probe for the dialog holding the new one"
    );
}
