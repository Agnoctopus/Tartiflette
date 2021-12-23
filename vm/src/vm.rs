//! Virtual machine

use crate::bits::BitField;
use crate::memory::MemoryError;
use crate::snapshot::SnapshotError;

/// List of available registers
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Register {
    /// RAX
    Rax,
    /// RBX
    Rbx,
    /// RCX
    Rcx,
    /// RDX
    Rdx,
    /// RSI
    Rsi,
    /// RDI
    Rdi,
    /// RSP
    Rsp,
    /// RBP
    Rbp,
    /// R8
    R8,
    /// R9
    R9,
    /// R10
    R10,
    /// R11
    R11,
    /// R12
    R12,
    /// R13
    R13,
    /// R14
    R14,
    /// R15
    R15,
    /// RIP
    Rip,
    /// RFLAGS
    Rflags,
    /// FS BASE
    FsBase,
    /// GS BASE
    GsBase,
}

/// Additional details behind a PageFault exception
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PageFaultDetail {
    /// Page fault status code (from the exception frame)
    pub status: u32,
    /// Address of the access which caused the fault
    pub address: u64,
}

impl PageFaultDetail {
    /// Returns true if the faulty access was made to unmapped memory.
    #[inline]
    pub fn unmapped(&self) -> bool {
        self.status.is_bit_set(0)
    }

    /// Returns true if the faulty access was a read.
    #[inline]
    pub fn read(&self) -> bool {
        self.status.is_bit_set(1)
    }

    /// Returns true if the faulty access was a write.
    #[inline]
    pub fn write(&self) -> bool {
        !self.read()
    }

    /// Returns true if the faulty access was an instruction fetch.
    #[inline]
    pub fn instruction_fetch(&self) -> bool {
        self.status.is_bit_set(15)
    }
}

/// Vm exit reason
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmExit {
    /// Vm stopped on a halt instruction
    Hlt,
    /// Vm stopped on a breakpoint instruction or singlestep
    Breakpoint,
    /// Vm interrupted by the hypervisor
    Interrupted,
    /// Vm stopped on an invalid instruction
    InvalidInstruction,
    /// Vm stopped on a page fault
    PageFault(PageFaultDetail),
    /// Vm stopped on an unhandled exception
    Exception(u64),
    /// Vm stopped on a syscall instruction
    Syscall,
    /// Vmexit unhandled by tartiflette
    Unhandled,
}

/// Vm manipulation error
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmError {
    /// Error during a memory access
    MemoryError(MemoryError),
    /// Error during snapshot loading
    SnapshotError(SnapshotError),
    /// Hypervisor error
    HvError(&'static str),
}

impl From<MemoryError> for VmError {
    fn from(err: MemoryError) -> VmError {
        VmError::MemoryError(err)
    }
}

impl From<std::io::Error> for VmError {
    fn from(err: std::io::Error) -> VmError {
        VmError::SnapshotError(SnapshotError::IoError(err.to_string()))
    }
}

impl From<SnapshotError> for VmError {
    fn from(err: SnapshotError) -> VmError {
        VmError::SnapshotError(err)
    }
}
