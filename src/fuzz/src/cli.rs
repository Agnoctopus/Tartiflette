//! Command line interface

use crate::config::Config;

use std::convert::TryFrom;

use clap::{self, App, Arg};

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
                Arg::with_name("max_file_size")
                    .long("max_file_size")
                    .takes_value(true)
                    .help("Maximal file size in bytes [default: 128 Mio]"),
            )
            .arg(
                Arg::with_name("persistent")
                    .long("persistent")
                    .help("Enable persitent fuzzing mode"),
            )
            .arg(
                Arg::with_name("netdriver")
                    .long("netdriver")
                    .help("Use netdriver"),
            )
            .arg(
                Arg::with_name("mutation_per_run")
                    .long("mutation_per_run")
                    .takes_value(true)
                    .default_value("5")
                    .help("Maximal number of mutations per run"),
            )
            .arg(
                Arg::with_name("mutation_num")
                    .long("mutation_num")
                    .takes_value(true)
                    .help("Number of mutations to do"),
            )
            .arg(
                Arg::with_name("crash_exit")
                    .long("crash_exit")
                    .help("Exit on crash"),
            )
            .arg(
                Arg::with_name("socket_fuzzer")
                    .long("socket_fuzzer")
                    .help("Fuzz using socket"),
            )
            .arg(
                Arg::with_name("timeout")
                    .long("timeout")
                    .takes_value(true)
                    .default_value("1")
                    .help("Timeout in second"),
            )
            .arg(
                Arg::with_name("random_ascii")
                    .long("random_ascii")
                    .help("Force ascci byte generation on random"),
            )
            .arg(
                Arg::with_name("mutation_cmdline")
                    .long("mutation_cmdline")
                    .takes_value(true)
                    .help("Mutation command line"),
            )
            .arg(
                Arg::with_name("post_mutation_cmdline")
                    .long("post_mutation_cmdline")
                    .takes_value(true)
                    .help("Post mutation command line"),
            )
            .arg(
                Arg::with_name("fb_mutation_cmdline")
                    .long("fb_mutation_cmdline")
                    .takes_value(true)
                    .help("Mutation command line on effective cov feedback files"),
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
