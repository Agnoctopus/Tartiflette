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

fn check_sig(config: &mut Config) {
    let exe_path = Path::new(&config.exe_config.cmdline.as_ref().unwrap()[0]);

    let exe_data = std::fs::read(exe_path).unwrap();

    if exe_data
        .windows(config::PERSISTENT_SIG.len())
        .any(|window| window == config::PERSISTENT_SIG)
    {
        println!(
            "Peristent signature found in {:?}. Enabling persistent fuzzing mode.",
            exe_path
        );
        config.app_config.persistent = true;
    }
    if exe_data
        .windows(config::NETDRIVER_SIG.len())
        .any(|window| window == config::NETDRIVER_SIG)
    {
        println!("Netdriver signature found in {:?}.", exe_path);
        config.app_config.netdriver = true;
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

    config.validate();

    fuzz::fuzz(config);
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
