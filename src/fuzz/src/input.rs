use std::{char::ParseCharError, path::PathBuf, sync::atomic::Ordering};

use chrono::format;

use crate::fuzz::FuzzCase;
use crate::{
    config::{self, AppConfig, Config},
};
use crate::app::App;
use std::path::Path;

pub const INPUT_MIN_SIZE: usize = 8 * 1024;
pub const INPUT_MAX_SIZE: usize = 1024 * 1024;

pub fn input_get_entries(config: &Config) -> Result<Vec<PathBuf>, String> {
    if config.io_config.input_file_count == 0 {
        return Err(format!("No useful files in the input directory"));
    }

    let input_dir = Path::new(&config.io_config.input_dir);
    if !input_dir.exists() {
        return Err(format!(
            "Cannot find the input directory specified: {:?}",
            input_dir
        ));
    }
    if !input_dir.is_dir() {
        return Err(format!(
            "The input directory specified is not a directory: {:?}",
            input_dir
        ));
    }

    let mut entries = Vec::new();
    let read_dir = std::fs::read_dir(input_dir).map_err(|error| format!("{}", error))?;

    for entry in read_dir {
        if let Err(error) = entry {
            eprintln!("Failed to read dir entry: {}", error);
            continue;
        }
        let entry = entry.unwrap();
        println!("Analysing {:?}", entry.path());

        if !entry.path().is_file() {
            eprintln!("{:?} not a regular file", entry.path());
            continue;
        }

        let metadata = std::fs::metadata(entry.path());
        if let Err(error) = metadata {
            eprintln!("Failed to get metadata dir entry: {}", error);
            continue;
        }
        let metadata = metadata.unwrap();

        if metadata.len() as usize > config.io_config.max_file_size {
            eprintln!(
                "{:?} is bigger than the maximal file size: {} > {} bytes",
                entry.path(),
                metadata.len(),
                config.io_config.max_file_size
            );
            continue;
        }

        entries.push(entry.path());
    }
    Ok(entries)
}

pub fn input_init(config: &mut Config) -> Result<(), String> {
    let input_dir = Path::new(&config.io_config.input_dir);
    if !input_dir.exists() {
        return Err(format!(
            "Cannot find the input directory specified: {:?}",
            input_dir
        ));
    }
    if !input_dir.is_dir() {
        return Err(format!(
            "The input directory specified is not a directory: {:?}",
            input_dir
        ));
    }

    let read_dir = std::fs::read_dir(input_dir).map_err(|error| format!("{}", error))?;

    let mut file_count: usize = 0;
    let mut max_size: usize = 0;

    for entry in read_dir {
        if let Err(error) = entry {
            eprintln!("Failed to read dir entry: {}", error);
            continue;
        }
        let entry = entry.unwrap();
        println!("Analysing {:?}", entry.path());

        if !entry.path().is_file() {
            eprintln!("{:?} not a regular file", entry.path());
            continue;
        }

        let metadata = std::fs::metadata(entry.path());
        if let Err(error) = metadata {
            eprintln!("Failed to get metadata dir entry: {}", error);
            continue;
        }
        let metadata = metadata.unwrap();

        if metadata.len() as usize > config.io_config.max_file_size {
            eprintln!(
                "{:?} is bigger than the maximal file size: {} > {} bytes",
                entry.path(),
                metadata.len(),
                config.io_config.max_file_size
            );
            continue;
        }
        max_size = std::cmp::max(max_size, metadata.len() as usize);

        file_count += 1;
    }

    if file_count == 0 {
        println!("No usable files in the input directory: {:?}", input_dir);
    }

    if config.app_config.max_input_size == 0 {
        config.app_config.max_input_size =
            core::cmp::min(core::cmp::max(max_size, INPUT_MIN_SIZE), INPUT_MAX_SIZE);
    }
    config.io_config.input_file_count = file_count;

    println!(
        "Analysed {:?}, max input size: {}, number of usable files: {}",
        input_dir, config.app_config.max_input_size, file_count
    );

    Ok(())
}

pub fn get_random_input(app: &App) -> Vec<u8> {
    if app.metrics.fuzz_input_count.load(Ordering::Relaxed) == 0 {}

    let corpus = app.corpus.lock().unwrap();
    let mut files = match *app.current_file.lock().unwrap() {
        Some(ref path) => corpus.iter_from(path),
        None => corpus.iter(),
    };

    let mut file = files.next().unwrap();
    *app.current_file.lock().unwrap() = files.next().map(|file| file.path.clone());

    return file.data[..file.size].to_vec();
}
