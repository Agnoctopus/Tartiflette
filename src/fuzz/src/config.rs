//! Configuration

use crate::fuzz;
use clap::ArgMatches;
use std::{convert::TryFrom, str::FromStr};

#[derive(Debug)]
pub enum ConfigError {
    Conversion,
}

/// Config regarding I/O
#[derive(Debug)]
pub struct IOConfig {
    pub input_dir: Option<String>,
    pub input_file_count: usize,
    pub output_dir: Option<String>,
    pub crash_dir: Option<String>,
    pub cov_dir: Option<String>,
    pub max_file_size: usize,
}

impl TryFrom<&ArgMatches<'_>> for IOConfig {
    type Error = ConfigError;

    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        let input_dir = matches.value_of("input").map(String::from);
        let output_dir = matches
            .value_of("output")
            .map(String::from)
            .or(input_dir.clone());
        let crash_dir = matches
            .value_of("crashdir")
            .map(String::from)
            .or(output_dir.clone());
        let cov_dir = matches
            .value_of("crashdir")
            .map(String::from)
            .or(output_dir.clone());
        let max_file_size = matches
            .value_of("max_file_size")
            .map(|s| s.parse::<usize>().unwrap())
            .unwrap_or(128 * 1024 * 1024);

        Ok(Self {
            input_dir: input_dir,
            input_file_count: 0,
            output_dir: output_dir,
            crash_dir: crash_dir,
            cov_dir: cov_dir,
            max_file_size: max_file_size,
        })
    }
}

#[derive(Debug)]
pub struct ExeConfig {
    pub cmdline: Option<Vec<String>>,
    pub mutation_cmdline: Option<String>,
    pub post_mutation_cmdline: Option<String>,
    pub fb_mutation_cmdline: Option<String>,
}

impl TryFrom<&ArgMatches<'_>> for ExeConfig {
    type Error = ConfigError;

    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        let cmdline = matches
            .values_of("program")
            .map(|vals| vals.map(String::from).collect::<Vec<_>>());

        Ok(Self {
            cmdline: cmdline,
            mutation_cmdline: matches.value_of("mutation_cmdline").map(String::from),
            post_mutation_cmdline: matches.value_of("post_mutation_cmdline").map(String::from),
            fb_mutation_cmdline: matches.value_of("fb_mutation_cmdline").map(String::from),
        })
    }
}

#[derive(Debug)]
pub struct AppConfig {
    pub verbose: u64,
    pub jobs: usize,
    pub minimize: bool,
    pub feedback_method: fuzz::FeedBackMethod,
    pub persistent: bool,
    pub netdriver: bool,
    pub crash_exit: bool,
    pub mutation_per_run: usize,
    pub mutation_num: Option<usize>,
    pub socket_fuzzer: bool,
    pub timeout: usize,
    pub max_input_size: usize,
    pub random_ascii: bool,
}

impl TryFrom<&ArgMatches<'_>> for AppConfig {
    type Error = ConfigError;

    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        Ok(Self {
            verbose: matches.occurrences_of("verbose"),
            jobs: matches.value_of("jobs").unwrap().parse::<usize>().unwrap(),
            minimize: matches.is_present("minimize"),
            feedback_method: fuzz::FeedBackMethod::SOFT,
            persistent: matches.is_present("persistent"),
            netdriver: matches.is_present("netdriver"),
            crash_exit: matches.is_present("crash_exit"),
            mutation_per_run: matches
                .value_of("mutation_per_run")
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            mutation_num: matches
                .value_of("mutation_num")
                .map(|val| val.parse::<usize>().unwrap()),
            socket_fuzzer: matches.is_present("socket_fuzzer"),
            timeout: matches
                .value_of("timeout")
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            max_input_size: 0,
            random_ascii: matches.is_present("random_ascii"),
        })
    }
}

#[derive(Debug)]
// Global configuration
pub struct Config {
    /// I/O configuration
    pub io_config: IOConfig,
    /// Executable configuration
    pub exe_config: ExeConfig,
    /// Application config
    pub app_config: AppConfig,
}

impl TryFrom<&ArgMatches<'_>> for Config {
    type Error = ConfigError;

    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        Ok(Self {
            io_config: IOConfig::try_from(matches)?,
            exe_config: ExeConfig::try_from(matches)?,
            app_config: AppConfig::try_from(matches)?,
        })
    }
}
