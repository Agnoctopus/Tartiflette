//! Virtual Memory Library

#![warn(missing_docs)]

mod paging;
mod phys;
mod virt;

pub use paging::{PagePermissions, PAGE_SIZE};
pub use virt::{VirtualMemory, Mapping};

use std::{error, fmt};

/// Result type
pub type Result<T> = std::result::Result<T, MemoryError>;

/// Error type on VM memory system
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MemoryError {
    /// No more memory present
    OutOfMemory,
    /// Could not allocate memory
    PhysmemAlloc,
    /// The `address` was already mapped
    AddressAlreadyMapped(u64),
    /// The `address` is not mapped
    AddressUnmapped(u64),
    /// Physical out of bound access on a read at the `address` of `size`
    PhysReadOutOfBounds(u64, usize),
    /// Physical out of bound access on a write at the `address` of `size`
    PhysWriteOutOfBounds(u64, usize),
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MemoryError::OutOfMemory => write!(f, "Out of memory"),
            MemoryError::PhysmemAlloc => write!(f, "Physmem mmap failed"),
            MemoryError::AddressAlreadyMapped(addr) => {
                write!(f, "Virtual address already mapped 0x{:x}", addr)
            }
            MemoryError::PhysReadOutOfBounds(addr, len) => {
                write!(
                    f,
                    "Physical read out of bounds 0x{:x} (len 0x{:x})",
                    addr, len
                )
            }
            MemoryError::PhysWriteOutOfBounds(addr, len) => {
                write!(
                    f,
                    "Physical write out of bounds 0x{:x} (len 0x{:x})",
                    addr, len
                )
            }
            MemoryError::AddressUnmapped(addr) => {
                write!(f, "Trying to access unmapped address: 0x{:x}", addr)
            }
        }
    }
}

impl error::Error for MemoryError {
    fn description(&self) -> &str {
        match *self {
            MemoryError::OutOfMemory => "Out of memory",
            MemoryError::PhysmemAlloc => "Physmem mmap failed",
            MemoryError::AddressAlreadyMapped(_) => "Virtual address already exists",
            MemoryError::PhysReadOutOfBounds(_, _) => "Physical read out of bounds",
            MemoryError::PhysWriteOutOfBounds(_, _) => "Physical write out of bounds",
            MemoryError::AddressUnmapped(_) => "Tried to access unmapped memory",
        }
    }
}
