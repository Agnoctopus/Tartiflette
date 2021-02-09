//! Fuzz

#![warn(missing_docs)]

mod cli;
mod config;

/// Main function
fn main() {
    // Get the program args as Vec<&str>
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_ref).collect();

    // Parse the command line
    match cli::CLI::parse(args) {
        Ok(_config) => {

        }
        Err(error) => {
            eprintln!("Error while parsing the command line.");
            eprint!("{}", error)
        }
    }
}
