use serde::de;
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::iter::FromIterator;
use std::path::Path;

#[derive(Debug)]
pub enum SnapshotError {
    FileError(std::io::Error),
    ParsingError,
}

impl From<std::io::Error> for SnapshotError {
    fn from(err: std::io::Error) -> SnapshotError {
        SnapshotError::FileError(err)
    }
}

impl From<serde_json::Error> for SnapshotError {
    fn from(err: serde_json::Error) -> SnapshotError {
        SnapshotError::ParsingError
    }
}

fn u64_from_json<'de, D>(deserializer: D) -> core::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    u64::from_str_radix(&s, 16).map_err(de::Error::custom)
}

fn map_strstr_to_stru64<'de, D>(
    deserializer: D,
) -> core::result::Result<BTreeMap<String, u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let m: BTreeMap<String, String> = BTreeMap::deserialize(deserializer)?;

    let converted_values: Vec<u64> = m
        .values()
        .map(|x| u64::from_str_radix(x, 16))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(de::Error::custom)?;

    Ok(BTreeMap::from_iter(
        m.keys().cloned().zip(converted_values.iter().cloned()),
    ))
}

type Result<T> = std::result::Result<T, SnapshotError>;

/// Memory mapping from a snapshot
#[derive(Deserialize, Debug)]
pub struct Mapping {
    /// Starting address of the mapping in virtual memory
    #[serde(deserialize_with = "u64_from_json")]
    start: u64,
    /// Ending address of the mapping in virtual memory
    #[serde(deserialize_with = "u64_from_json")]
    end: u64,
    /// Physical offset inside the snapshot dump
    #[serde(deserialize_with = "u64_from_json")]
    physical_offset: u64,
    /// Optional path to the image to which the page belongs
    image: Option<String>,
}

/// Snapshot of a virtual address space
#[derive(Deserialize, Debug)]
pub struct Snapshot {
    /// Relative path the the raw memory contents
    memory_file: String,
    /// List of virtual memory mappings
    mappings: Vec<Mapping>,
    /// Registers state
    #[serde(deserialize_with = "map_strstr_to_stru64")]
    #[serde(default)]
    registers: BTreeMap<String, u64>,
    /// List of symbols
    #[serde(deserialize_with = "map_strstr_to_stru64")]
    #[serde(default)]
    symbols: BTreeMap<String, u64>,
    /// List of basic block addresses used for coverage
    #[serde(default)]
    coverage: Vec<u64>,
}

impl Snapshot {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Snapshot> {
        let info_file = File::open(path)?;
        let mut reader = BufReader::new(info_file);
        let mut json = String::new();

        reader.read_to_string(&mut json)?;

        Snapshot::from(&json)
    }

    pub fn from(json: &str) -> Result<Snapshot> {
        serde_json::from_str(json).map_err(|_| SnapshotError::ParsingError)
    }
}

#[cfg(test)]
mod tests {
    use super::{Result, Snapshot, SnapshotError};

    #[test]
    fn test_simple_parse() -> Result<()> {
        let sample_info = r#"
        {
            "memory_file": "snapshot_data.bin",
            "mappings": [
                {
                    "start": "1337000",
                    "end": "1338000",
                    "physical_offset": "0",
                    "permissions": "r-x"
                },
                {
                    "start": "2000000",
                    "end": "2001000",
                    "physical_offset": "1000",
                    "permissions": "rw-p"
                }
            ],
            "registers": {
                "rax": "0",
                "rbx": "1337",
                "rip": "deadbeef"
            },
            "symbols": {
                "__start": "555555558030",
                "main": "400000"
            }
        }
        "#;

        Snapshot::from(sample_info)?;
        Ok(())
    }
}
