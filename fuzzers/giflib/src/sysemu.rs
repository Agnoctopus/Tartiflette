use tartiflette_vm::{Vm, Register};

/// Linux syscall emulation state
pub struct SysEmu {
    /// Base address of the mmap area
    mmap_start: u64,
    /// End address of the mmap area
    mmap_end: u64,
    /// Current address in the mmap are
    mmap_current: u64
}

impl SysEmu {
    /// Creates a new state
    pub fn new(start: u64, end: u64) -> SysEmu {
        SysEmu {
            mmap_start: start,
            mmap_end: end,
            mmap_current: start
        }
    }

    /// Handles a syscall. Returns whether execution should continue
    pub fn syscall(&mut self, vm: &mut Vm) -> bool {
        let syscall_code = vm.get_reg(Register::Rax);
        println!("syscall[{}] exiting", syscall_code);
        false
    }

    /// Resets the internal state of emulation layer
    pub fn reset(&mut self) {
        self.mmap_current = self.mmap_start;
    }
}
