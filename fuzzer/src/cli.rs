//! Command line interface

use std::convert::TryFrom;

use clap::{App, Arg};

use crate::config::Config;

/// CLI manager
pub struct CLI;

impl CLI {
    /// Parse the command line
    pub fn parse(args: Vec<&str>) -> Result<Config, String> {
        // Create the `App` instance
        let app = App::new(args[0].to_string())
            .version(clap::crate_version!())
            .author(clap::crate_authors!("\n"))
            .about(clap::crate_description!())
            .arg(
                Arg::with_name("corpus")
                    .long("corpus")
                    .takes_value(true)
                    .default_value("./corpus")
                    .help("Path to a directory containing corpus"),
            )
            .arg(
                Arg::with_name("obj")
                    .long("obj")
                    .takes_value(true)
                    .default_value("./obj")
                    .help("Path to a directory containing obj"),
            )
            .arg(
                Arg::with_name("crash")
                    .long("crash")
                    .takes_value(true)
                    .default_value("./crashes")
                    .help("Path to a directory containing crashes"),
            );

        // Match the program args
        let matches = app
            .get_matches_from_safe(args)
            .map_err(|error| format!("{}", error))?;

        // Create the program `Config`
        Ok(Config::try_from(&matches).unwrap())
    }
}
