fn main() {
    // Pin the widget style. The app draws its own controls, but std-widgets'
    // ListView still supplies the scrollbars, and leaving the style to the
    // platform default would give macOS cupertino scrollbars and Linux fluent
    // ones inside an otherwise identical window.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    // A test-only harness for tests/accessibility.rs. Compiled unconditionally
    // because a build script cannot tell that it is building for `cargo test`;
    // it is one small component and nothing in the binary refers to it.
    //
    // Compiled *before* the app, because each call overwrites the variable
    // that slint::include_modules!() reads: the last one compiled is the one
    // main.rs gets. The test include!s its own file by name.
    // with_debug_info is what makes the ElementHandle API able to see the
    // element tree. Set on the probe alone so the shipped binary does not
    // carry it.
    slint_build::compile_with_config(
        "ui/testing/field-probe.slint",
        config.clone().with_debug_info(true),
    )
    .expect("compiling ui/testing/field-probe.slint");

    slint_build::compile_with_config("ui/app-window.slint", config)
        .expect("compiling ui/app-window.slint");

    wayland_target();
    windows_resources();
}

/// Set `cfg(wayland_target)` on the targets where a window can be on Wayland.
///
/// The clipboard has a Wayland half only there, and writing the whole
/// condition out at every place that half is gated would bury the code it
/// gates. The condition is the one copypasta puts on smithay-clipboard, and
/// Cargo.toml gates the Wayland dependencies on the same one, written out,
/// because a manifest cannot use a build script's cfg; the two have to agree.
/// Read from CARGO_CFG_*, which describe the target rather than the host this
/// script runs on.
fn wayland_target() {
    println!("cargo:rustc-check-cfg=cfg(wayland_target)");
    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if family.split(',').any(|family| family == "unix")
        && !["macos", "android", "ios", "emscripten"].contains(&os.as_str())
    {
        println!("cargo:rustc-cfg=wayland_target");
    }
}

/// Give the Windows binary an icon, a version tab and a manifest.
///
/// Without this the .exe carries no resource section whatsoever, which shows up
/// three ways: the taskbar and title bar draw a generic placeholder because
/// WM_GETICON returns nothing, Explorer's Details tab is empty, and the process
/// is DPI-unaware so Windows bitmap-scales the window on any display above 100%
/// and the whole app renders blurry.
///
/// Two guards, because they answer different questions. The `cfg(windows)` on
/// the function matches how Cargo gates the dependency itself: a build script
/// is compiled for the *host*, and so are its build-dependencies, so winresource
/// only exists to be called when the build machine is Windows. The
/// CARGO_CFG_TARGET_OS check inside is the one about the *target*, and it is
/// what stops a Windows host cross-compiling for Linux from embedding a PE
/// resource into an ELF binary.
#[cfg(windows)]
fn windows_resources() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    println!("cargo:rerun-if-changed=rpgp.exe.manifest");
    println!("cargo:rerun-if-changed=desktop/app.rpgp.rpgp.ico");

    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("desktop/app.rpgp.rpgp.ico");
    resource.set_manifest_file("rpgp.exe.manifest");
    // Shown on Explorer's Details tab. FileDescription is what Task Manager
    // lists the process as, so it is the name a user looks for, not "rpgp.exe".
    resource.set("FileDescription", "rPGP — OpenPGP certificate manager");
    resource.set("ProductName", "rPGP");
    resource.set(
        "LegalCopyright",
        "Copyright © 2026 Jonathan Zeppettini. MIT licensed.",
    );
    resource
        .compile()
        .expect("embedding the Windows icon, manifest and version info");
}

#[cfg(not(windows))]
fn windows_resources() {}
