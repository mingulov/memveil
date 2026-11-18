//! `memveil` binary entry point (scaffold: `--version`/`version` only).

use memveil::ENGINE_VERSION;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version" | "version") => {
            println!("{ENGINE_VERSION}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: memveil [--version|version]");
            ExitCode::from(2)
        }
    }
}
