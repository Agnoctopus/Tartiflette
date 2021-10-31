//! Token based fuzzer for quickjs

mod executor;
mod fuzz;
mod sysemu;

use clap::{App, Arg};
use fuzz::FuzzerConfig;

fn main() {
    // Get the program args as Vec<&str>
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_ref).collect();

    // Create the `App` CLI parsing object
    let app = App::new("quickjs-fuzzer")
        .version("0.0.1")
        .author(clap::crate_authors!("\n"))
        .about(clap::crate_description!())
        .arg(
            Arg::with_name("cores")
                .short("c")
                .long("core")
                .value_name("CORES")
                .takes_value(true)
                .default_value("1")
                .help("cores on wich to run the fuzzer"),
        )
        .arg(
            Arg::with_name("broker_address")
                .short("a")
                .long("address")
                .value_name("BROKER_ADDRESS")
                .takes_value(true)
                .help("ip address of the broker"),
        )
        .arg(
            Arg::with_name("broker_port")
                .short("p")
                .long("port")
                .value_name("BROKER_PORT")
                .help("port of the broker")
                .default_value("1337")
                .takes_value(true),
        );

    // Get the program args matches
    let matches = app
        .get_matches_from_safe(args)
        .map_err(|error| format!("{}", error))
        .unwrap();

    // Compute the fuzzer configuration
    let config = FuzzerConfig {
        cores: matches.value_of("cores").unwrap(),
        broker_address: matches.value_of("broker_address"),
        broker_port: matches.value_of("broker_port").unwrap(),
    };

    fuzz::fuzz(config);
}
