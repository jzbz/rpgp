fn main() {
    // Pin the widget style. The app draws its own controls, but std-widgets'
    // ListView and ScrollView still supply the scrollbars, and pinning keeps
    // them alike on every platform. Slint 1.17 compiles with fluent when
    // nothing names a style, but SLINT_STYLE in the build's environment can
    // name another: `native` would give a macOS build cupertino scrollbars.
    // with_style takes precedence over that variable.
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    // A test-only harness for tests/accessibility.rs. Compiled unconditionally
    // because a build script cannot tell that it is building for `cargo test`;
    // nothing in the binary refers to it, so its windows stay out of the
    // binary, and so does the second copy of the bundled fonts they embed to
    // lay text out as the app does.
    //
    // Compiled *before* the app, because each call overwrites the variable
    // that slint::include_modules!() reads: the last one compiled is the one
    // src/lib.rs gets. The test include!s its own file by name.
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
/// in Explorer: it draws a generic icon for the file and for any shortcut to
/// it, the Start Menu entry the installer makes among them, and its Details
/// tab is empty. The running window is unaffected, since Slint gives it
/// AppWindow's `icon`, which its title bar and taskbar button draw (see
/// app-window.slint). The version resource is not only for Explorer either:
/// release.yml reads its ProductVersion to version the installer.
///
/// The manifest's DPI awareness makes no visible difference to the window.
/// winit's Windows event loop makes the process per-monitor aware itself, and
/// Slint builds that loop before any window exists, so without the manifest
/// the window would still be scaled sharply rather than blurred. The manifest
/// declares the same awareness from the moment the process starts, so it does
/// not rest on a default of winit's that an event loop built
/// `with_dpi_aware(false)` turns off.
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
    println!("cargo:rerun-if-changed=desktop/app.rpgp.rPGP.ico");

    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("desktop/app.rpgp.rPGP.ico");
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
