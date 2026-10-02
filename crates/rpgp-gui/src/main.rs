// This attribute is what makes a Windows release build a GUI-subsystem
// program, so that launching it opens no console window behind the app. rpgp
// ships for Windows, and the .exe the release workflow publishes is such a
// build. That process has no console for a message to reach, so report_fatal
// in lib.rs shows its message there in a dialog instead.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The binary is a wrapper: everything it does lives in the library beside it,
//! so the parts worth benchmarking can be reached from `benches/`.

fn main() -> std::process::ExitCode {
    rpgp_gui::run_app()
}
