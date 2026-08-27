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
