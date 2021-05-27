extern crate libafl;

mod cli;
mod config;

use config::Config;

fn main() {
    // Get the program args as Vec<&str>
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_ref).collect();

    // Parse the command line
    match cli::CLI::parse(args) {
        Ok(config) => fuzz(config),
        Err(error) => eprintln!("{}", error),
    }
}

fn fuzz(mut config: Config) {
    if let Err(error) = config.validate() {
        eprintln!("Failed to validate the configuration.");
        eprintln!("{}", error);
        return;
    }
}
