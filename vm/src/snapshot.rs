use crate::memory::PagePermissions;
use serde::{de::Error, Deserialize};
use std::cmp;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Error during snapshot manipulation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// IO Error
    IoError(String),
    /// Parsing error
    ParsingError(String),
}

impl From<std::io::Error> for SnapshotError {
    fn from(err: std::io::Error) -> Self {
        SnapshotError::IoError(err.to_string())
    }
}

/// Result type in snapshot manipulation
type Result<T> = std::result::Result<T, SnapshotError>;

/// Parse an unsigned 64 bits number in hex form
fn parse_u64<'de, D>(d: D) -> std::result::Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(d)?;
    u64::from_str_radix(s, 16).map_err(D::Error::custom)
}

/// Parse permission in string form
fn parse_perms<'de, D>(d: D) -> std::result::Result<PagePermissions, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(d)?;
    let mut perms = PagePermissions::new(0);

    // TODO: Proper checking instead of this hack
    perms.set_readable(true); // No execute only in x64 iirc
    perms.set_writable(s.contains('w'));
    perms.set_executable(s.contains('x'));

    Ok(perms)
}

/// Snapshot registers
#[derive(Deserialize, Debug)]
pub struct SnapshotRegisters {
    /// RAX
    #[serde(deserialize_with = "parse_u64")]
    pub rax: u64,
    /// RBX
    #[serde(deserialize_with = "parse_u64")]
    pub rbx: u64,
    /// RCX
    #[serde(deserialize_with = "parse_u64")]
    pub rcx: u64,
    /// RDX
    #[serde(deserialize_with = "parse_u64")]
    pub rdx: u64,
    /// RSI
    #[serde(deserialize_with = "parse_u64")]
    pub rsi: u64,
    /// RDI
    #[serde(deserialize_with = "parse_u64")]
    pub rdi: u64,
    /// RSP
    #[serde(deserialize_with = "parse_u64")]
    pub rsp: u64,
    /// RBP
    #[serde(deserialize_with = "parse_u64")]
    pub rbp: u64,
    /// R8
    #[serde(deserialize_with = "parse_u64")]
    pub r8: u64,
    /// R9
    #[serde(deserialize_with = "parse_u64")]
    pub r9: u64,
    /// R10
    #[serde(deserialize_with = "parse_u64")]
    pub r10: u64,
    /// R11
    #[serde(deserialize_with = "parse_u64")]
    pub r11: u64,
    /// R12
    #[serde(deserialize_with = "parse_u64")]
    pub r12: u64,
    /// R13
    #[serde(deserialize_with = "parse_u64")]
    pub r13: u64,
    /// R14
    #[serde(deserialize_with = "parse_u64")]
    pub r14: u64,
    /// R15
    #[serde(deserialize_with = "parse_u64")]
    pub r15: u64,
    /// RIP
    #[serde(deserialize_with = "parse_u64")]
    pub rip: u64,
    /// RFLAGS
    #[serde(deserialize_with = "parse_u64")]
    pub rflags: u64,
    /// FS BASE
    #[serde(deserialize_with = "parse_u64")]
    pub fs_base: u64,
    /// GS BASE
    #[serde(deserialize_with = "parse_u64")]
    pub gs_base: u64,
}

/// Snapshot mapping
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
    pub image: Option<String>,
}

/// Snapshot raw information contained in JSON form
#[derive(Deserialize)]
struct SnapshotInfoRaw {
    /// List of all memory mappings
    pub mappings: Vec<SnapshotMapping>,
    /// Register state
    pub registers: SnapshotRegisters,
    /// Map of symbols
    pub symbols: Option<BTreeMap<String, String>>,
}

/// Mapped code object
#[derive(Debug)]
pub struct SnapshotModule {
    /// Starting address of the module
    pub start: u64,
    /// Ending address of the module (excluded)
    pub end: u64,
    /// Name of the loaded object
    pub name: String,
}

/// Tartiflette snapshot info
#[derive(Debug)]
pub struct SnapshotInfo {
    /// List of all memory mappings
    pub mappings: Vec<SnapshotMapping>,
    /// Register state
    pub registers: SnapshotRegisters,
    /// List of named code modules
    pub modules: BTreeMap<String, SnapshotModule>,
    /// Map of symbols
    pub symbols: BTreeMap<String, u64>,
}

impl SnapshotInfo {
    /// Create a new `SnapshotInfo` instance from a snapshot path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<SnapshotInfo> {
        let contents = fs::read_to_string(path)?;
        SnapshotInfo::from_string(contents)
    }

    /// Create a new `SnapshotInfo` from str data
    pub fn from_string<S: AsRef<str>>(data: S) -> Result<SnapshotInfo> {
        // Get a `SnapshotInfoRaw` from parsing
        let info: SnapshotInfoRaw = serde_json::from_str(data.as_ref())
            .map_err(|e| SnapshotError::ParsingError(e.to_string()))?;

        // Process the symbols
        let mut symbols: BTreeMap<String, u64> = BTreeMap::new();

        // Handle symbols if present
        if let Some(syms) = info.symbols {
            // Loop through symbols
            for (k, v) in syms.iter() {
                // Convert hex address into integer
                let address = u64::from_str_radix(v, 16)
                    .map_err(|e| SnapshotError::ParsingError(e.to_string()))?;

                // Add the symbol
                symbols.insert(k.clone(), address);
            }
        }

        // Process the modules
        let mut modules: BTreeMap<String, SnapshotModule> = BTreeMap::new();

        // Loop through mappings
        for mapping in info.mappings.iter() {
            if let Some(module_path) = mapping.image.as_deref() {
                // Get the module name, equivalent ton path basename
                let module_name = module_path.split("/").last().unwrap().to_string();

                // Handle module
                match modules.get_mut(&module_name) {
                    Some(module) => {
                        // Update module mapping region
                        module.start = cmp::min(module.start, mapping.start);
                        module.end = cmp::max(module.end, mapping.end);
                    }
                    None => {
                        // Add module
                        modules.insert(
                            module_name.clone(),
                            SnapshotModule {
                                start: mapping.start,
                                end: mapping.end,
                                name: module_name,
                            },
                        );
                    }
                }
            }
        }

        // Return a new `SnapshotInfo`
        Ok(SnapshotInfo {
            mappings: info.mappings,
            registers: info.registers,
            modules: modules,
            symbols: symbols,
        })
    }
}
