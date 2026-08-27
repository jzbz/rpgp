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
