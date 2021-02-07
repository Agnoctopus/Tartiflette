//! Configuration

// Global configuration
pub struct Config {
    /// Number of VCPUs to use
    pub vcpu_num: u32,
}

impl Config {
    /// Create a new `Config` instance
    pub fn new(vcpu_num: u32) -> Self {
        Self { vcpu_num: vcpu_num }
    }
}
