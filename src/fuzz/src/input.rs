//! Input subsystem

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::Config;

pub const INPUT_MIN_SIZE: usize = 8 * 1024;
pub const INPUT_MAX_SIZE: usize = 1024 * 1024;

/// Error that can occured during in the input subsystem
#[derive(Debug)]
pub enum Error {
    /// A file was not found
    NotFound(PathBuf),
    /// A file is not a dir
    NotDir(PathBuf),
    /// An IOError occured
    IOError(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::IOError(error)
    }
}

/// Input manager
#[derive(Debug)]
pub struct Input {
    /// Input directory
    dir: PathBuf,

    /// Entries filename
    entries: Vec<String>,

    /// Max entry size
    max_entry_size: usize,
}

impl Input {
    /// Create a new `Input` instance
    pub fn new(config: &Config) -> Result<Self, Error> {
        // Compute input dir path
        let dir = Path::new(&config.io_config.input_dir);

        // Check the directory exist
        if !dir.exists() {
            return Err(Error::NotFound(dir.to_path_buf()));
        }
        // Check the directory is a
        if !dir.is_dir() {
            return Err(Error::NotDir(dir.to_path_buf()));
        }

        // Create `Input` object
        let mut input = Self {
            dir: dir.to_path_buf(),
            entries: Vec::new(),
            max_entry_size: config.io_config.max_file_size.min(INPUT_MAX_SIZE),
        };

        // Get entries
        input.entries = input.get_entries()?;
        if input.entries.len() == 0 {
            eprintln!(
                "[INPUT] No usable files in: {}",
                input.dir.to_str().unwrap()
            );
        }

        // Set max entry size
        input.max_entry_size = input.max_entry_size.min(input.get_max_entry_size());
        eprintln!(
            "[INPUT] Dir: {} | entries: {} | max size: {}",
            input.dir.to_str().unwrap(),
            input.entries.len(),
            input.max_entry_size
        );

        Ok(input)
    }

    /// Returns the direcotry path
    #[inline]
    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    /// Returns the entries
    #[inline]
    pub fn entries(&self) -> &Vec<String> {
        &self.entries
    }

    /// Returns the path for a filename
    #[inline]
    pub fn get_path_to(&self, filename: &str) -> PathBuf {
        self.dir.join(filename)
    }

    /// Returns the max entries size
    #[inline]
    pub fn max_entries_size(&self) -> usize {
        self.max_entry_size
    }

    /// Get max entry size
    fn get_max_entry_size(&self) -> usize {
        // Max entry size
        let mut max_entry_size = 0;

        // Loop through entries
        for entry in &self.entries {
            let entry_path = self.dir.join(entry);

            // Retrieve metadata
            let metadata = fs::metadata(&entry_path);
            if let Err(error) = metadata {
                eprintln!(
                    "[INPUT] Failed to get metadata: {} - {}",
                    entry_path.to_str().unwrap(),
                    error
                );
                continue;
            }
            let metadata = metadata.unwrap();

            max_entry_size = max_entry_size.max(metadata.len() as usize);
        }

        max_entry_size.clamp(INPUT_MIN_SIZE, INPUT_MAX_SIZE)
    }

    /// Get filename entries
    fn get_entries(&self) -> Result<Vec<String>, Error> {
        // Create entries vector
        let mut entries = Vec::new();

        // Read dir
        let read_dir = fs::read_dir(&self.dir)?;

        // Loop through entries
        for entry in read_dir {
            let entry = entry?;
            let entry_path = entry.path();

            // Check regular file
            if !entry_path.is_file() {
                eprintln!(
                    "[INPUT] Not a regular file: {}",
                    entry_path.to_str().unwrap()
                );
                continue;
            }

            // Retrieve metadata
            let metadata = std::fs::metadata(&entry_path);
            if let Err(error) = metadata {
                eprintln!(
                    "[INPUT] Failed to get metadata: {} - {}",
                    entry_path.to_str().unwrap(),
                    error
                );
                continue;
            }
            let metadata = metadata.unwrap();

            // Check file size
            if metadata.len() as usize > self.max_entry_size {
                eprintln!(
                    "[INPUT] File bigger than limit: {} - ({} > {})",
                    entry_path.to_str().unwrap(),
                    metadata.len(),
                    self.max_entry_size
                );
                continue;
            }

            // Add entry filename
            let filename: String = entry
                .path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            entries.push(filename);
        }
        Ok(entries)
    }
}
