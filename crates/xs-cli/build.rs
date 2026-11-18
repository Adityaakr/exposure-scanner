//! Makes a release build of `exposure` the same bytes wherever it is built
//! (design report, task 14: two clean builds of one commit give the same
//! binary).
//!
//! On macOS the linker writes a debug map that names the folder each object
//! file was built in, and derives the binary's UUID from it. The release
//! profile strips that map after linking, but the UUID stays, and with it a
//! trace of the build folder: two checkouts of one commit gave binaries
//! that differ in 48 bytes, the UUID and the code-signature hash of the page
//! that holds it. Telling the linker to write no debug map at all (`-S`)
//! leaves nothing that depends on the path. Debug builds keep their map, so
//! a debugger still finds the code.
#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    reason = "a build script reads cargo's variables and speaks to cargo on standard output"
)]

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let apple = std::env::var("CARGO_CFG_TARGET_VENDOR").is_ok_and(|vendor| vendor == "apple");
    let release = std::env::var("PROFILE").is_ok_and(|profile| profile == "release");
    if apple && release {
        println!("cargo:rustc-link-arg-bins=-Wl,-S");
    }
}
