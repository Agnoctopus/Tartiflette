use tartiflette_vm::{Vm, Register};
use std::convert::From;

/// Linux syscall emulation state
pub struct SysEmu {
    /// Base address of the mmap area
    mmap_start: u64,
    /// End address of the mmap area
    mmap_end: u64,
    /// Current address in the mmap are
    mmap_current: u64
}

/// Supported linux syscalls
enum Syscall {
    Mmap,
    Munmap,
    Ioctl,
    ExitGroup,
    Unknown
}

impl From<u64> for Syscall {
    fn from(value: u64) -> Self {
        match value {
            9 => Syscall::Mmap,
            11 => Syscall::Munmap,
            16 => Syscall::Ioctl,
            231 => Syscall::ExitGroup,
            _ => Syscall::Unknown
        }
    }
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

        let result = match syscall_code.into() {
            Syscall::Mmap => {
                let addr = vm.get_reg(Register::Rdi);
                let len = vm.get_reg(Register::Rsi);
                let fd = vm.get_reg(Register::R8) as i64;

                if fd != -1 {
                    panic!("mmaping from a fd is not supported");
                }

                if len & 0xff != 0 {
                    panic!("len is not aligned");
                }

                if addr != 0 {
                    panic!("Mapping to a fixed address (0x{:x}) is not supported", addr);
                }

                if self.mmap_current + len > self.mmap_end {
                    panic!("Mmap allocator out of memory");
                }

                vm.set_reg(Register::Rax, self.mmap_current);
                self.mmap_current += len;
                true
            }
            Syscall::Munmap => {
                // Do a nop
                vm.set_reg(Register::Rax, 0);
                true
            }
            Syscall::Ioctl => {
                // ioctl(1, TIOCGWINSZ, {ws_row=58, ws_col=239, ws_xpixel=0, ws_ypixel=0}) = 0
                vm.set_reg(Register::Rax, 0);
                true
            }
            Syscall::ExitGroup => {
                // Simply stop the execution
                false
            }
            Syscall::Unknown => {
                panic!("Unhandled syscall: {}", syscall_code);
            }
        };

        result
    }

    /// Resets the internal state of emulation layer
    pub fn reset(&mut self) {
        self.mmap_current = self.mmap_start;
    }
}
