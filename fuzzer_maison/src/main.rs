//! Fuzz

#![warn(missing_docs)]

mod app;
mod cli;
mod config;
mod corpus;
mod dico;
mod feedback;
mod fuzz;
mod input;
mod mangle;
mod random;
mod sanitize;
mod utils;

extern crate bits;
extern crate tartiflette;

use std::path::Path;

use chrono::Local;

use crate::config::Config;

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

fn launch_program(mut config: Config) {
    let cmdline = config.exe_config.cmdline.as_ref().unwrap();
    assert!(cmdline.len() > 0);

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
    check_sig(&mut config);

    todo!();
}

fn launch_snapshot(mut config: Config) {
    fuzz::fuzz(config);
}

/// Launch the program
fn launch(mut config: Config) {
    if let Err(error) = config.validate() {
        eprintln!("Failed to validate the configuration.");
        eprintln!("{}", error);
        return;
    }

    let localtime = Local::now();
    let start_time = localtime.format("%Y-%m-%d %H:%M:%S").to_string();
    println!("Start time: {}", start_time);
    println!("Input: {}", config.io_config.input_dir);
    println!("Ouput: {}", config.io_config.output_dir);
    println!("Jobs: {}", config.app_config.jobs);

    if config.exe_config.cmdline.is_some() {
        launch_program(config);
    } else if config.exe_config.snapshot.is_some() {
        launch_snapshot(config);
    } else {
        eprintln!("Nothing to do.");
    }
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
            eprintln!("{}", error)
        }
    }
}
