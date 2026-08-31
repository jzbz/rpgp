//! Render the Decrypt/Verify banner in a REAL window, for eyeballing layout.
//!
//! Not a test. Slint's headless test backend does not wrap text, so a geometry
//! assertion there passes whether or not the banner is clipped; this puts the
//! same component in front of an actual renderer so a screenshot can settle it.
//!
//!   env -u WAYLAND_DISPLAY DISPLAY=:99 cargo run -p rpgp-gui --example banner_probe
//!
//! Unsetting WAYLAND_DISPLAY matters: with it set, winit connects to the real
//! compositor and the window lands on the developer's desktop rather than on
//! the virtual display being captured.

include!(concat!(env!("OUT_DIR"), "/field-probe.rs"));

fn main() {
    let probe = VerifyBannerProbe::new().unwrap();

    // Two cases at once, because they stress opposite things: a short signer
    // that must stay neatly inline beside its pills, and a long failure that
    // must wrap without being clipped.
    let long = std::env::args().any(|a| a == "--fail");
    if long {
        probe.set_result("Signature is NOT valid".into());
        probe.set_signatures(slint::ModelRc::new(slint::VecModel::from(vec![
            SignatureRow {
                good: false,
                signer: "unknown".into(),
                detail: "Subkey of FD13B6835E248FAF4BD1838D6DF634AA7608AF04 not bound: primary key"
                    .into(),
                authentication: "".into(),
                authenticated: false,
                sha1: false,
            },
        ])));
    } else {
        probe.set_result(
            "Valid only because you accepted SHA-1 — this shows the key was involved, not that its holder signed this"
                .into(),
        );
        probe.set_signatures(slint::ModelRc::new(slint::VecModel::from(vec![
            SignatureRow {
                good: true,
                signer: "Decred Release <release@decred.org>".into(),
                detail: "".into(),
                authentication: "unverified".into(),
                authenticated: false,
                sha1: true,
            },
        ])));
    }

    probe.run().unwrap();
}
