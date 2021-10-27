mod fuzz;
mod executor;
mod sysemu;

use clap::{App, Arg};
use fuzz::FuzzerConfig;

fn main() {
    let matches = App::new("quickjs-fuzzer")
        .version("0.0.1")
        .about("Token based fuzzer for quickjs")
        .arg(Arg::with_name("cores")
            .short("c")
            .long("core")
            .value_name("CORES")
            .help("cores on wich to run the fuzzer")
            .default_value("1")
            .takes_value(true)
        )
        .arg(Arg::with_name("broker_address")
            .short("a")
            .long("address")
            .value_name("BROKER_ADDRESS")
            .help("ip address of the broker")
            .takes_value(true)
        )
        .arg(Arg::with_name("broker_port")
            .short("p")
            .long("port")
            .value_name("BROKER_PORT")
            .help("port of the broker")
            .default_value("1337")
            .takes_value(true)
        )
        .get_matches();

    let config = FuzzerConfig {
        cores: matches.value_of("cores").unwrap(),
        broker_address: matches.value_of("broker_address"),
        broker_port: matches.value_of("broker_port").unwrap()
    };

    fuzz::fuzz(config);
}
