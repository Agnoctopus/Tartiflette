//! Fuzz

#![warn(missing_docs)]

mod cli;
mod config;
mod fuzz;

use chrono::Local;
use config::Config;
use std::thread;

/// Launch the program
fn launch(config: Config) {
    let cmdline = config.exe_config.cmdline.as_ref().expect("No command line provided");
    assert!(cmdline.len() > 0);
    assert!(std::path::Path::new(&cmdline[0]).exists());

    if let Some(input_dir) = config.io_config.input_dir.as_ref() {
        // Check radble input diecrtotry no readable.
    }
    if let Some(output_dir) = config.io_config.output_dir.as_ref() {
        // Check radble input diecrtotry no readable.
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
