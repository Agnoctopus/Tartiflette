//! Configuration

// Global configuration
pub struct Config {
    /// Number of VCPUs to use
    pub vcpu_num: u32,
    /// Snapshot pathname
    pub snapshot: Option<String>,
}

impl Config {
    /// Create a new `Config` instance
    pub fn new(vcpu_num: u32, snapshot: Option<String>) -> Self {
        Self {
            vcpu_num: vcpu_num,
            snapshot: snapshot,
        }
    }
}
