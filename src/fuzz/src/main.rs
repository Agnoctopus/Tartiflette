//! Fuzz

#![warn(missing_docs)]

mod cli;
mod config;
mod fuzz;
mod input;
mod mangle;
mod random;

extern crate bits;

use chrono::Local;
use config::Config;
use input::input_init;
use std::path::Path;
use std::{fs, thread};

/* Persistent-binary signature - if found within file, it means it's a persistent mode binary */
const PERSISTENT_SIG: &[u8] = b"\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF";
/* HF NetDriver signature - if found within file, it means it's a NetDriver-based binary */
const NETDRIVER_SIG: &[u8] = b"\x01_LIBHFUZZ_NETDRIVER_BINARY_SIGNATURE_\x02\xFF";

const MAX_JOBS: usize = 1024;

fn check(config: &mut Config) {
    assert!(config.exe_config.cmdline.is_some());

    let exe_path = Path::new(&config.exe_config.cmdline.as_ref().unwrap()[0]);

    let exe_data = std::fs::read(exe_path).unwrap();

    if exe_data
        .windows(PERSISTENT_SIG.len())
        .any(|window| window == PERSISTENT_SIG)
    {
        println!(
            "Peristent signature found in {:?}. Enabling persistent fuzzing mode.",
            exe_path
        );
        config.app_config.persistent = true;
    }
    if exe_data
        .windows(NETDRIVER_SIG.len())
        .any(|window| window == NETDRIVER_SIG)
    {
        println!("Netdriver signature found in {:?}.", exe_path);
        config.app_config.netdriver = true;
    }

    if config.app_config.socket_fuzzer {
        config.app_config.timeout = 0;
    }

    if config.app_config.jobs == 0 {
        eprint!("Too few fuzzing threads specified");
    }

    if let Some(output_dir) = config.io_config.output_dir.as_ref() {
        let output_dir = Path::new(output_dir);
        if !output_dir.exists() {
            if let Err(error) = std::fs::create_dir(output_dir) {
                eprintln!("error: {}", error);
            }
        }
        return;
    }

    if let Some(crash_dir) = config.io_config.crash_dir.as_ref() {
        let crash_dir = Path::new(crash_dir);
        if !crash_dir.exists() {
            if let Err(error) = std::fs::create_dir(crash_dir) {
                eprintln!("error: {}", error);
            }
        }
        return;
    }

    if config.app_config.jobs >= MAX_JOBS {
        eprintln!(
            "Too many fuzzing threads specified {} >= {}",
            config.app_config.jobs, MAX_JOBS
        );
        return;
    }
}

/// Launch the program
fn launch(mut config: Config) {
    let cmdline = config
        .exe_config
        .cmdline
        .as_ref()
        .expect("No command line provided");
    assert!(cmdline.len() > 0);
    assert!(std::path::Path::new(&cmdline[0]).exists());

    if let Some(input_dir) = config.io_config.input_dir.as_ref() {
        // Check readble input diecrtotry no readable.
    }
    if let Some(output_dir) = config.io_config.output_dir.as_ref() {
        // Check readble input diecrtotry no readable.
    }

    let localtime = Local::now();
    println!(
        "Start time: {}",
        localtime.format("%Y-%m-%d %H:%M:%S").to_string()
    );
    println!(
        "Program command line: {}",
        config
            .exe_config
            .cmdline
            .as_ref()
            .map(|args| args.join(" "))
            .as_deref()
            .unwrap_or("")
    );
    println!(
        "Input: {}",
        config.io_config.input_dir.as_deref().unwrap_or("")
    );
    println!(
        "Ouput: {}",
        config.io_config.output_dir.as_deref().unwrap_or("")
    );
    println!("Minimize: {}", config.app_config.minimize);
    println!("Jobs: {}", config.app_config.jobs);

    if let Err(error) = input_init(&mut config) {
        eprintln!("{}", error);
        return;
    }

    check(&mut config);

    let child = thread::spawn(move || {
        fuzz::fuzz(config);
    });

    child.join().unwrap();
}

/// Main function
fn main() {
    // Get the program args as Vec<&str>
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_ref).collect();

    // Parse the command line
    match cli::CLI::parse(args) {
        Ok(config) => launch(config),
        Err(error) => {
            eprintln!("Error while parsing the command line.");
            eprintln!("{}", error)
        }
    }
}
