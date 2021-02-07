//! Command line interface

use crate::config::Config;
use clap;

/// CLI manager
pub struct CLI;

impl CLI {
    /// Parse the command line
    pub fn parse(args: Vec<&str>) -> Result<Config, String> {
        // Create the `App` instance
        let app = clap::App::new(args[0].to_string())
            .version("1.0")
            .author("César Belley <cesar.belley@lse.epita.fr>")
            .author("Tanguy Dubroca <tanguy.dubroca@lse.epita.fr>")
            .arg(
                clap::Arg::with_name("vcpu")
                    .long("vcpu")
                    .takes_value(true)
                    .default_value("1")
                    .help("Set the number of VCPUs to use"),
            );

        // Match the program args
        let matches = app
            .get_matches_from_safe(args)
            .map_err(|error| format!("{}", error))?;

        // Create the program `Config`
        Ok(Config::new(
            matches
                .value_of("vcpu")
                .unwrap()
                .parse::<u32>()
                .expect("Failed to parse VCPUs number"),
        ))
    }
}
