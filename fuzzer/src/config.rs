//! Configuration

use std::convert::TryFrom;
use std::fs;
use std::path::Path;

use clap::ArgMatches;

/// Error that can occured during the cli config parsing
#[derive(Debug)]
pub enum ConfigError {
    /// A configuration `field` is required
    Required(String),
    /// A `field` conversion error occured
    Conversion(String),
}

/// Config regarding I/O
#[derive(Debug)]
pub struct IOConfig {
    /// Corpus directory
    pub corpus_dir: String,
    /// Obj directory
    pub obj_dir: String,
}

impl IOConfig {
    /// Validate the `IOConfig`
    pub fn validate(&mut self) -> Result<(), String> {
        let corpus_dir = Path::new(&self.corpus_dir);
        if !corpus_dir.exists() {
            if let Err(error) = fs::create_dir(corpus_dir) {
                return Err(format!("{}", error));
            }
        }

        let obj_dir = Path::new(&self.obj_dir);
        if !obj_dir.exists() {
            if let Err(error) = fs::create_dir(obj_dir) {
                return Err(format!("{}", error));
            }
        }
        Ok(())
    }
}

impl TryFrom<&ArgMatches<'_>> for IOConfig {
    type Error = ConfigError;

    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        let corpus_dir = matches
            .value_of("corpus")
            .map(String::from)
            .ok_or(ConfigError::Required("corpus".to_string()))?;
        let obj_dir = matches
            .value_of("obj")
            .map(String::from)
            .ok_or(ConfigError::Required("obj".to_string()))?;

        Ok(Self {
            corpus_dir: corpus_dir,
            obj_dir: obj_dir,
        })
    }
}

#[derive(Debug)]
/// Global configuration
pub struct Config {
    /// I/O configuration
    pub io_config: IOConfig,
}

impl Config {
    /// Validate the `IOConfig`
    pub fn validate(&mut self) -> Result<(), String> {
        self.io_config.validate()
    }
}

impl TryFrom<&ArgMatches<'_>> for Config {
    type Error = ConfigError;

    fn try_from(matches: &ArgMatches) -> Result<Self, Self::Error> {
        Ok(Self {
            io_config: IOConfig::try_from(matches)?,
        })
    }
}
