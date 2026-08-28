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
