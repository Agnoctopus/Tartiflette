use kvm_bindings::kvm_regs;
use kvm_ioctls::{Kvm, VmFd, VcpuFd};

type Result<T> = std::result::Result<T, VmError>;

/// Vm manipulation error
pub enum VmError {
    OutOfMemory
}

/// List of available registers
pub enum Register {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rsp,
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Rflags
}

/// Vm exit reason
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmExit {
    /// Stopped on a halt instruction
    Hlt,
    /// Stopped on a breakpoint instruction or singlestep
    Breakpoint,
    /// Vm received was interrupted by the hypervisor
    Interrupted,
    /// Vm exit unhandled by tartiflette
    Unhandled(u64)
}

/// Tartiflette vm state
pub struct Vm {
    /// Kvm device file descriptor
    kvm: Kvm,
    /// Kvm vm file descriptor
    kvm_vm: VmFd,
    /// Kvm vm vcpu file descriptor
    kvm_vcpu: VcpuFd,
    /// Local copy of kvm registers
    registers: kvm_regs
}

impl Vm {
    /// Creates a vm with a given memory size (the size will be aligned to
    /// the nearest page multiple).
    pub fn new(memory_size: usize) -> Result<Vm> {
        // 1 - Allocate the memory
        // 2 - Create the Kvm handles
        // TODO: Properly convert errors (or just return an opaque VmError:Kvm(...)
        let mut kvm_fd = Kvm::new().expect("Could not open kvm device");
        let mut vm_fd = kvm_fd.create_vm().expect("Could not create vm fd");
        let mut vcpu_fd = vm_fd.create_vcpu(0).expect("Could not create vm vcpu");

        // 3 - Setup the interrupt handling inside the vm
        // 4 - Setup specials registers (segments, CrX)

        Ok(Vm {
            kvm: kvm_fd,
            kvm_vm: vm_fd,
            kvm_vcpu: vcpu_fd,
            registers: Default::default()
        })
    }

    /// Gets a register from the vm state
    pub fn get_reg(&self, regid: Register) -> u64 {
        match regid {
            Register::Rax => self.registers.rax,
            Register::Rbx => self.registers.rbx,
            Register::Rcx => self.registers.rcx,
            Register::Rdx => self.registers.rdx,
            Register::Rsi => self.registers.rsi,
            Register::Rdi => self.registers.rdi,
            Register::Rsp => self.registers.rsp,
            Register::Rbp => self.registers.rbp,
            Register::R8  => self.registers.r8,
            Register::R9  => self.registers.r9,
            Register::R10 => self.registers.r10,
            Register::R11 => self.registers.r11,
            Register::R12 => self.registers.r12,
            Register::R13 => self.registers.r13,
            Register::R14 => self.registers.r14,
            Register::R15 => self.registers.r15,
            Register::Rip => self.registers.rip,
            Register::Rflags => self.registers.rflags
        }
    }

    /// Sets a register in the vm state
    pub fn set_reg(&mut self, regid: Register, regval: u64) {
        match regid {
            Register::Rax => self.registers.rax = regval,
            Register::Rbx => self.registers.rbx = regval,
            Register::Rcx => self.registers.rcx = regval,
            Register::Rdx => self.registers.rdx = regval,
            Register::Rsi => self.registers.rsi = regval,
            Register::Rdi => self.registers.rdi = regval,
            Register::Rsp => self.registers.rsp = regval,
            Register::Rbp => self.registers.rbp = regval,
            Register::R8  => self.registers.r8 = regval,
            Register::R9  => self.registers.r9 = regval,
            Register::R10 => self.registers.r10 = regval,
            Register::R11 => self.registers.r11 = regval,
            Register::R12 => self.registers.r12 = regval,
            Register::R13 => self.registers.r13 = regval,
            Register::R14 => self.registers.r14 = regval,
            Register::R15 => self.registers.r15 = regval,
            Register::Rip => self.registers.rip = regval,
            Register::Rflags => self.registers.rflags = regval
        }
    }

    /// Maps memory with given permissions in the vm address space.
    pub fn mmap(&mut self, vaddr: u64, size: usize, perms: u64) -> Result<()> {
        Ok(())
    }

    /// Writes to given data to the vm memory.
    pub fn write(&mut self, vaddr: u64, data: &[u8]) -> Result<()> {
        Ok(())
    }

    /// Reads data from the given vm memory.
    pub fn read(&self, vaddr: u64, data: &[u8]) -> Result<()> {
        Ok(())
    }
}
