//! Configuration

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
    pub output_dir: Option<String>,
    pub crash_dir: Option<String>,
    pub cov_dir: Option<String>,
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

        Ok(Self {
            input_dir: input_dir,
            output_dir: output_dir,
            crash_dir: crash_dir,
            cov_dir: cov_dir,
        })
    }
}

#[derive(Debug)]
pub struct ExeConfig {
    pub cmdline: Option<Vec<String>>,
}

impl TryFrom<&ArgMatches<'_>> for ExeConfig {
    type Error = ConfigError;

    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        let cmdline = matches
            .values_of("program")
            .map(|vals| vals.map(String::from).collect::<Vec<_>>());

        Ok(Self { cmdline: cmdline })
    }
}

#[derive(Debug)]
pub struct AppConfig {
    pub minimize: bool,
    pub verbose: u64,
    pub jobs: usize,
}

impl TryFrom<&ArgMatches<'_>> for AppConfig {
    type Error = ConfigError;

    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        Ok(Self {
            verbose: matches.occurrences_of("verbose"),
            minimize: matches.is_present("minimize"),
            jobs: matches.value_of("jobs").unwrap().parse::<usize>().unwrap(),
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
