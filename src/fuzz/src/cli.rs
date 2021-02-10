//! Command line interface

use std::convert::TryFrom;

use crate::config;
use crate::config::Config;
use clap::{self, crate_description};
use clap::{App, Arg, ArgMatches};
use config::IOConfig;

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
                Arg::with_name("input")
                    .short("i")
                    .long("input")
                    .takes_value(true)
                    .help("Path to a directory containing initial corpus"),
            )
            .arg(
                Arg::with_name("output")
                    .short("o")
                    .long("output")
                    .takes_value(true)
                    .help("Path to a directory used to write corpus"),
            )
            .arg(
                Arg::with_name("crashdir")
                    .long("crashdir")
                    .takes_value(true)
                    .help("Path to a directory used to write crashes"),
            )
            .arg(
                Arg::with_name("jobs")
                    .short("j")
                    .long("jobs")
                    .takes_value(true)
                    .default_value("1")
                    .help("Number of concurrent jobs"),
            )
            .arg(
                Arg::with_name("verbose")
                    .short("v")
                    .long("verbose")
                    .multiple(true)
                    .help("Set verbose mode"),
            )
            .arg(
                Arg::with_name("minimize")
                    .long("minimize")
                    .help("Minimize the corpus"),
            )
            .arg(
                Arg::with_name("program")
                    .multiple(true)
                    .last(true)
                    .help("Program command line"),
            );

        // Match the program args
        let matches = app
            .get_matches_from_safe(args)
            .map_err(|error| format!("{}", error))?;

        // Create the program `Config`
        let config = Config::try_from(&matches).unwrap();
        Ok(config)
    }
}
