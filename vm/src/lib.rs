//! Virtual Machine low-level management

#![warn(missing_docs)]

#[cfg(target_os = "linux")]
#[macro_use]
extern crate vmm_sys_util;

mod backends;
mod bits;
mod memory;
mod snapshot;
mod vm;
mod x64;

pub use memory::{Mapping, PagePermissions};
pub use snapshot::{
    SnapshotError, SnapshotInfo, SnapshotMapping, SnapshotModule, SnapshotRegisters,
};

pub use vm::{PageFaultDetail, Register, VmError, VmExit};

#[cfg(target_os = "linux")]
pub use backends::kvm::Vm;

#[cfg(target_os = "windows")]
pub use backends::hyperv::Vm;
