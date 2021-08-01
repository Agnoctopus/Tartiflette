use std::path::Path;
use std::cmp;
use std::fs;
use std::collections::BTreeMap;
use serde::{de::Error, Deserialize};
use crate::memory::PagePermissions;

fn parse_u64<'de, D>(d: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>
{
    let s: &str = Deserialize::deserialize(d)?;
    u64::from_str_radix(s, 16).map_err(D::Error::custom)
}

fn parse_perms<'de, D>(d: D) -> std::result::Result<PagePermissions, D::Error>
where
    D: serde::Deserializer<'de>
{
    let s: &str = Deserialize::deserialize(d)?;
    let mut perms = PagePermissions::new(0);

    // TODO: Proper checking instead of this hack
    perms.set_readable(true); // No execute only in x64 iirc
    perms.set_writable(s.contains('w'));
    perms.set_executable(s.contains('x'));

    Ok(perms)
}

#[derive(Deserialize, Debug)]
pub struct SnapshotRegisters {
    #[serde(deserialize_with = "parse_u64")]
    pub rax: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rbx: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rcx: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rdx: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rsi: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rdi: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rsp: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rbp: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub r8: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub r9: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub r10: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub r11: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub r12: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub r13: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub r14: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub r15: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rip: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub rflags: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub fs_base: u64,
    #[serde(deserialize_with = "parse_u64")]
    pub gs_base: u64
}

#[derive(Deserialize, Debug)]
pub struct SnapshotMapping {
    /// Starting address
    #[serde(deserialize_with = "parse_u64")]
    pub start: u64,
    /// Ending address (excluded)
    #[serde(deserialize_with = "parse_u64")]
    pub end: u64,
    /// Offset in the binary dump
    #[serde(deserialize_with = "parse_u64")]
    pub physical_offset: u64,
    /// Page permissions
    #[serde(deserialize_with = "parse_perms")]
    pub permissions: PagePermissions,
    /// File image owning this mapping
    pub image: Option<String>
}

#[derive(Deserialize)]
struct SnapshotInfoRaw {
    pub mappings: Vec<SnapshotMapping>,
    pub registers: SnapshotRegisters,
    pub symbols: Option<BTreeMap<String, String>>
}

/// Mapped code object
#[derive(Debug)]
pub struct SnapshotModule {
    /// Starting address of the module
    pub start: u64,
    /// Ending address of the module (excluded)
    pub end: u64,
    /// Name of the loaded object
    pub name: String
}

/// Error during snapshot loading
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    IoError(String),
    ParsingError(String)
}

impl From<std::io::Error> for SnapshotError {
    fn from(err: std::io::Error) -> Self {
        SnapshotError::IoError(err.to_string())
    }
}

type Result<T> = std::result::Result<T, SnapshotError>;

/// Tartiflette snapshot info
#[derive(Debug)]
pub struct SnapshotInfo {
    /// List of all memory mappings
    pub mappings: Vec<SnapshotMapping>,
    /// Current register state
    pub registers: SnapshotRegisters,
    /// List of named code modules
    pub modules: BTreeMap<String, SnapshotModule>,
    /// Map of symbols
    pub symbols: BTreeMap<String, u64>
}

impl SnapshotInfo {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<SnapshotInfo> {
        let contents = fs::read_to_string(path)?;
        SnapshotInfo::from_string(contents)
    }

    pub fn from_string<S: AsRef<str>>(data: S) -> Result<SnapshotInfo> {
        let info: SnapshotInfoRaw = serde_json::from_str(data.as_ref())
            .map_err(|e| SnapshotError::ParsingError(e.to_string()))?;

        // Process the modules and symbols
        let mut symbols: BTreeMap<String, u64> = BTreeMap::new();

        if let Some(syms) = info.symbols {
            for (k, v) in syms.iter() {
                let address = u64::from_str_radix(v, 16)
                    .map_err(|e| SnapshotError::ParsingError(e.to_string()))?;

                symbols.insert(k.clone(), address);
            }
        }

        let mut modules: BTreeMap<String, SnapshotModule> = BTreeMap::new();

        for mapping in info.mappings.iter() {
            if let Some(module_path) = mapping.image.as_deref() {
                // This should never crash
                let module_name = module_path.split("/").last().unwrap().to_string();

                if let Some(module) = modules.get_mut(&module_name) {
                    module.start = cmp::min(module.start, mapping.start);
                    module.end = cmp::max(module.end, mapping.end);
                } else {
                    modules.insert(module_name.clone(), SnapshotModule {
                        start: mapping.start,
                        end: mapping.end,
                        name: module_name
                    });
                }
            }
        }

        Ok(SnapshotInfo {
            mappings: info.mappings,
            registers: info.registers,
            modules,
            symbols
        })
    }
}
