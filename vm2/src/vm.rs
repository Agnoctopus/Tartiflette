use kvm_bindings::{kvm_regs, kvm_sregs, kvm_segment, kvm_userspace_memory_region, kvm_guest_debug, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP};
use kvm_ioctls::{Kvm, VmFd, VcpuFd, VcpuExit};
use nix::errno::Errno;
use crate::bits::BitField;
use crate::memory::{VirtualMemory, MemoryError, PagePermissions, Mapping, PAGE_SIZE};
use crate::x64::{Tss, TssEntry, PrivilegeLevel, IdtEntry, IdtEntryType, IdtEntryBuilder, ExceptionFrame, ExceptionType};

type Result<T> = std::result::Result<T, VmError>;

/// Vm manipulation error
#[derive(Debug)]
pub enum VmError {
    /// Error during a memory access
    MemoryError(MemoryError),
    /// Hypervisor error
    HvError(&'static str)
}

impl From<MemoryError> for VmError {
    fn from(err: MemoryError) -> VmError {
        VmError::MemoryError(err)
    }
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
    Unhandled
}

/// Tartiflette vm state
pub struct Vm {
    /// Kvm device file descriptor
    _kvm: Kvm,
    /// Kvm vm file descriptor
    kvm_vm: VmFd,
    /// Kvm vm vcpu file descriptor
    kvm_vcpu: VcpuFd,
    /// Local copy of kvm registers
    registers: kvm_regs,
    /// Local copy of kvm special registers
    special_registers: kvm_sregs,
    /// VM Memory
    memory: VirtualMemory
}

impl Vm {
    /// Creates a vm with a given memory size (the size will be aligned to
    /// the nearest page multiple).
    pub fn new(memory_size: usize) -> Result<Vm> {
        // Create minimal vm
        let mut vm = Vm::setup_barebones(memory_size)?;

        // Setup special registers
        vm.setup_registers()?;

        // Setup exception handling
        vm.setup_exception_handling()?;

        Ok(vm)
    }

    /// Sets up a minimal vm (kvm init + memory + sregs)
    fn setup_barebones(memory_size: usize) -> Result<Vm> {
        // 1 - Allocate the memory
        let vm_memory = VirtualMemory::new(memory_size)?;

        // 2 - Create the Kvm handles and setup guest memory
        let kvm_fd = Kvm::new().map_err(|_| VmError::HvError("Could not open kvm device"))?;
        let vm_fd = kvm_fd.create_vm().map_err(|_| VmError::HvError("Could not create vm fd"))?;
        let vcpu_fd = vm_fd.create_vcpu(0).map_err(|_| VmError::HvError("Could not create vm vcpu"))?;

        unsafe {
            vm_fd.set_user_memory_region(kvm_userspace_memory_region {
                slot: 0,
                guest_phys_addr: 0,
                memory_size: vm_memory.host_memory_size() as u64,
                userspace_addr: vm_memory.host_address(),
                flags: 0
            }).map_err(|_| VmError::HvError("Could not set memory region for guest"))?
        }

        let sregs = vcpu_fd.get_sregs()
            .map_err(|_| VmError::HvError("Could not get special registers"))?;

        Ok(Vm {
            _kvm: kvm_fd,
            kvm_vm: vm_fd,
            kvm_vcpu: vcpu_fd,
            registers: Default::default(),
            special_registers: sregs,
            memory: vm_memory
        })
    }

    /// Configures the Vm special registers
    fn setup_registers(&mut self) -> Result<()> {
        // Initialize system registers
        const CR0_PG: u64 = 1 << 31;
        const CR0_PE: u64 = 1 << 0;
        const CR0_ET: u64 = 1 << 4;
        const CR0_WP: u64 = 1 << 16;

        const CR4_PAE: u64 = 1 << 5;
        const CR4_OSXSAVE: u64 = 1 << 18; // TODO: Maybe check for support with cpuid
        const IA32_EFER_LME: u64 = 1 << 8;
        const IA32_EFER_LMA: u64 = 1 << 10;
        const IA32_EFER_NXE: u64 = 1 << 11;

        // 64 bits code segment
        let mut seg = kvm_segment {
            base: 0,
            limit: 0,
            selector: 1 << 3, // Index 1, GDT, RPL = 0
            present: 1,
            type_: 11, /* Code: execute, read, accessed */
            dpl: 0,
            db: 0,
            s: 1, /* Code/data */
            l: 1,
            g: 0,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        self.special_registers.cs = seg;

        // seg.selector = 0;
        seg.type_ = 3;

        self.special_registers.ds = seg;
        self.special_registers.es = seg;
        self.special_registers.fs = seg;
        self.special_registers.gs = seg;
        self.special_registers.ss = seg;

        // Paging enable and paging
        self.special_registers.cr0 = CR0_PE | CR0_PG | CR0_ET | CR0_WP;
        // Physical address extension (necessary for x64)
        self.special_registers.cr4 = CR4_PAE | CR4_OSXSAVE;
        // Sets x64 mode enabled (LME), active (LMA), executable disable bit support (NXE), syscall
        // support (SCE)
        self.special_registers.efer = IA32_EFER_LME | IA32_EFER_LMA | IA32_EFER_NXE;
        // Sets the page table root address
        self.special_registers.cr3 = self.memory.page_directory() as u64;

        // Set tss
        self.kvm_vm.set_tss_address(0xfffb_d000)
            .map_err(|_| VmError::HvError("Could not set tss address"))?;

        // Enable vm exit on software breakpoints
        let dregs = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
            pad: 0,
            arch: Default::default(),
        };

        self.kvm_vcpu.set_guest_debug(&dregs)
            .map_err(|_| VmError::HvError("Could not set debug registers"))?;

        Ok(())
    }

    /// Setups the necessary pieces for handling interrupts (TSS, TSS Stack, GDT slots, IDT)
    fn setup_exception_handling(&mut self) -> Result<()> {
        const IDT_ADDRESS: u64 = 0xffffffffff000000;
        const IDT_HANDLERS: u64 = IDT_ADDRESS + PAGE_SIZE as u64;
        const GDT_ADDRESS: u64 = IDT_ADDRESS + (PAGE_SIZE * 2) as u64;
        const TSS_ADDRESS: u64 = IDT_ADDRESS + (PAGE_SIZE * 3) as u64;
        const STACK_ADDRESS: u64 = IDT_ADDRESS + (PAGE_SIZE * 4) as u64;

        // 4kb should be enough for simply handling interrupts
        const STACK_SIZE: usize = PAGE_SIZE;

        // Setting up the GDT
        self.memory.mmap(
            GDT_ADDRESS,
            PAGE_SIZE,
            PagePermissions::READ | PagePermissions::WRITE
        )?;

        // Setting up segments
        self.memory.write_val(GDT_ADDRESS, 0u64)?; // Null
        self.memory.write_val(GDT_ADDRESS + 8, 0x00209a0000000000u64)?; // Code

        // TSS GDT entry
        self.memory.write_val(
            GDT_ADDRESS + 16,
            TssEntry::new(TSS_ADDRESS, PrivilegeLevel::Ring0)
        )?;

        // TSS structure
        let mut tss = Tss::new();
        tss.set_ist(1, STACK_ADDRESS + (STACK_SIZE - 0x100) as u64);

        self.memory.mmap(TSS_ADDRESS, PAGE_SIZE, PagePermissions::READ)?;
        self.memory.write_val(TSS_ADDRESS, tss)?;

        // Set the tr register to the tss
        self.special_registers.tr = kvm_segment {
            base: TSS_ADDRESS,
            limit: (core::mem::size_of::<Tss>() - 1) as u32,
            selector: 2 << 3, // Index 2, GDT, RPL = 0
            present: 1,
            type_: 11,
            dpl: 0,
            db: 0,
            s: 0,
            l: 1,
            g: 0,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        // Setting up exception handlers
        self.memory.mmap(
            IDT_HANDLERS,
            PAGE_SIZE,
            PagePermissions::READ | PagePermissions::EXECUTE
        )?;

        for i in 0..32 {
            let handler_code: &[u8] = &[
                0x6a, i as u8, // push <exception index>
                0xf4,          // hlt -> our hypercall
            ];

            self.memory.write(IDT_HANDLERS + (i * 32), handler_code)?;
        }

        // Setting up the IDT
        self.memory.mmap(
            IDT_ADDRESS,
            PAGE_SIZE,
            PagePermissions::READ
        )?;

        let mut entries = [IdtEntry::new(); 32];
        let entries_size = entries.len() * std::mem::size_of::<IdtEntry>();

        for i in 0..32 {
            entries[i] = IdtEntryBuilder::new()
                .base(IDT_HANDLERS + (i * 32) as u64)
                .dpl(PrivilegeLevel::Ring0)
                .segment_selector(1, PrivilegeLevel::Ring0)
                .gate_type(IdtEntryType::Trap)
                .ist(1)
                .collect();
        }

        self.special_registers.idt.base = IDT_ADDRESS;
        self.special_registers.idt.limit = (entries_size - 1) as u16;
        self.special_registers.gdt.base = GDT_ADDRESS;
        self.special_registers.gdt.limit = 0xFF;

        self.memory.write_val(IDT_ADDRESS, entries)?;

        // Allocate stack for exception handling
        self.memory.mmap(
            STACK_ADDRESS,
            STACK_SIZE,
            PagePermissions::READ | PagePermissions::WRITE
        )?;

        Ok(())
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
    pub fn mmap(&mut self, vaddr: u64, size: usize, perms: PagePermissions) -> Result<()> {
        self.memory.mmap(vaddr, size, perms).map_err(VmError::MemoryError)
    }

    /// Writes to given data to the vm memory.
    pub fn write(&mut self, vaddr: u64, data: &[u8]) -> Result<()> {
        self.memory.write(vaddr, data).map_err(VmError::MemoryError)
    }

    pub fn write_value<T>(&mut self, address: u64, val: T) -> Result<()> {
        self.memory.write_val::<T>(address, val).map_err(VmError::MemoryError)
    }

    /// Reads data from the given vm memory.
    pub fn read(&self, vaddr: u64, data: &mut [u8]) -> Result<()> {
        self.memory.read(vaddr, data).map_err(VmError::MemoryError)
    }

    /// Returns a copy of the current vm
    pub fn clone(&self) -> Result<Vm> {
        let mut new_vm = Vm::setup_barebones(self.memory.host_memory_size())?;

        new_vm.registers = self.registers.clone();
        new_vm.special_registers = self.special_registers.clone();
        new_vm.memory = self.memory.clone()?;

        Ok(new_vm)
    }

    /// Returns an iterator over all mappings
    pub fn mappings(&self) -> impl Iterator<Item=Mapping> + '_ {
        self.memory.mappings()
    }

    /// Returns an iterator over all dirty mappings
    pub fn dirty_mappings(&self) -> impl Iterator<Item=Mapping> + '_ {
        self.mappings().filter(|m| m.dirty)
    }

    /// Clear dirty mappings status
    pub fn clear_dirty_mappings(&mut self) {
        for (_, pte) in self.memory.raw_pages_mut() {
            pte.set_dirty(false);
        }
    }

    /// Commit local copy of registers to kvm
    fn commit_registers(&mut self) -> Result<()> {
        // The second bit of rflags must always be set.
        self.registers.rflags |= 1 << 1;
        self.kvm_vcpu.set_regs(&self.registers)
            .map_err(|_| VmError::HvError("Could not commit registers"))?;
        self.kvm_vcpu.set_sregs(&self.special_registers)
            .map_err(|_| VmError::HvError("Could not commit special registers"))?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<VmExit> {
        let result = loop {
            self.commit_registers()?;

            let exit = self.kvm_vcpu.run();

            self.registers = self.kvm_vcpu.get_regs()
                .map_err(|_| VmError::HvError("Could not get registers"))?;
            self.special_registers = self.kvm_vcpu.get_sregs()
                .map_err(|_| VmError::HvError("Could not get special registers"))?;

            if let Err(err) = exit {
                match Errno::from_i32(err.errno()) {
                    Errno::EINTR | Errno::EAGAIN => break VmExit::Interrupted,
                    _ => return Err(VmError::HvError("Unexpected errno in KVM_RUN"))
                }
            }


            match exit.unwrap() {
                VcpuExit::Debug => {
                    break VmExit::Breakpoint
                }
                VcpuExit::Hlt => {
                    // TODO: Handling hlt outside of hypercall context
                    let exception_code: u64 = self.memory.read_val(self.registers.rsp)?;

                    let error_code: Option<u64> = match ExceptionType::from(exception_code) {
                        ExceptionType::DoubleFault |
                        ExceptionType::InvalidTSS  |
                        ExceptionType::SegmentNotPresent |
                        ExceptionType::StackFault |
                        ExceptionType::GeneralProtection |
                        ExceptionType::PageFault |
                        ExceptionType::AlignmentCheck |
                        ExceptionType::ControlProtection
                        => Some(self.memory.read_val(self.registers.rsp + 8)?),
                        _ => None
                    };

                    let exception_frame: ExceptionFrame = if error_code.is_some() {
                        self.memory.read_val(self.registers.rsp + 16)?
                    } else {
                        self.memory.read_val(self.registers.rsp + 8)?
                    };

                    // Reset register context to before exception
                    self.registers.rsp = exception_frame.rsp;
                    self.registers.rip = exception_frame.rip;

                    match ExceptionType::from(exception_code) {
                        ExceptionType::PageFault => {
                            break VmExit::PageFault(PageFaultDetail {
                                status: error_code.unwrap() as u32,
                                address: self.special_registers.cr2
                            });
                        },
                        ExceptionType::InvalidOpcode => {
                            // As IA32_EFER.SCE is not enabled, a syscall instruction will trigger
                            // a #UD exception. We cannot enable the SCE bit in EFER as it would
                            // require us to setup the whole syscall machinery as well as the LSTAR
                            // register.
                            // To give the opportunity to the Vm user to emulate the syscall, we try
                            // to detect the instruction bytes, set the rip to after the syscall
                            // and return with a special `Syscall` VmExit.
                            let mut code_bytes: [u8; 2] = [0; 2];

                            if self.memory.read(self.registers.rip, &mut code_bytes).is_ok() {
                                //  0f 05 -> syscall
                                if code_bytes == [0x0f, 0x05] {
                                    // We advance rip by two bytes to move over the syscall
                                    // instruction.
                                    self.registers.rip += 2;
                                    break VmExit::Syscall;
                                }
                            }

                            break VmExit::InvalidInstruction;
                        }
                        _ => break VmExit::Exception(exception_code)
                    }
                }
                _ => break VmExit::Unhandled
            }
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::{Result, Vm, VmExit, Register};
    use crate::memory::{PagePermissions, PAGE_SIZE};

    #[test]
    /// Runs a simple piece of code until completion
    fn test_simple_exec() -> Result<()> {
        let mut vm = Vm::new(512 * PAGE_SIZE)?;

        // Simple shellcode
        let shellcode: &[u8] = &[
            0x48, 0x01, 0xc2, // add rdx, rax
            0xcc, // breakpoint
        ];

        // Mapping the code
        vm.mmap(0x1337000, PAGE_SIZE, PagePermissions::EXECUTE)?;
        vm.write(0x1337000, shellcode)?;

        // Set registers to known values
        vm.set_reg(Register::Rax, 0x1000);
        vm.set_reg(Register::Rdx, 0x337);

        // Execute from beginning of shellcode
        vm.set_reg(Register::Rip, 0x1337000);

        let vmexit = vm.run()?;

        assert_eq!(vmexit, VmExit::Breakpoint);
        assert_eq!(vm.get_reg(Register::Rip), 0x1337003);

        Ok(())
    }

    #[test]
    /// Tests the collection and clearing of dirty pages
    fn test_dirty_status() -> Result<()> {
        let mut vm = Vm::new(512 * PAGE_SIZE)?;

        // Simple shellcode
        let shellcode: &[u8] = &[
            0x48, 0x89, 0x10, // mov [rax], rdx
            0xcc // int3
        ];

        // Mapping the code
        vm.mmap(0x1337000, PAGE_SIZE, PagePermissions::EXECUTE)?;
        vm.write(0x1337000, shellcode)?;

        // Mapping the target page of the write
        vm.mmap(0xdeadb000, PAGE_SIZE, PagePermissions::READ | PagePermissions::WRITE)?;

        // Set registers to known values
        vm.set_reg(Register::Rax, 0xdeadbeef);
        vm.set_reg(Register::Rdx, 0x42424242);

        // Execute from beginning of shellcode
        vm.set_reg(Register::Rip, 0x1337000);

        let vmexit = vm.run()?;

        // Sanity check
        assert_eq!(vmexit, VmExit::Breakpoint);
        assert_eq!(vm.get_reg(Register::Rip), 0x1337003);

        // Check that the target page was dirtied
        assert!(vm.dirty_mappings().any(|m| m.address == 0xdeadb000));

        // Reset the pages dirty status
        vm.clear_dirty_mappings();

        // Check again the dirty pages
        assert!(vm.dirty_mappings().count() == 0);

        Ok(())
    }

    #[test]
    /// Runs a simple piece of code until completion
    fn test_simple_syscall() -> Result<()> {
        let mut vm = Vm::new(512 * PAGE_SIZE)?;

        // The syscall in the shellcode will add rax and rdx together
        let shellcode: &[u8] = &[
            0x0f, 0x05, // syscall
            0xcc, // breakpoint
        ];

        // Mapping the code
        vm.mmap(0x1337000, PAGE_SIZE, PagePermissions::EXECUTE)?;
        vm.write(0x1337000, shellcode)?;

        // Set registers to known values
        vm.set_reg(Register::Rax, 0x1000);
        vm.set_reg(Register::Rdx, 0x337);

        // Execute from beginning of shellcode
        vm.set_reg(Register::Rip, 0x1337000);

        let vmexit = vm.run()?;

        assert_eq!(vmexit, VmExit::Syscall);

        // Emulated syscall doing rax = rax + rdx
        vm.set_reg(Register::Rax, vm.get_reg(Register::Rax) + vm.get_reg(Register::Rdx));

        let vmexit_end = vm.run()?;

        assert_eq!(vmexit_end, VmExit::Breakpoint);
        assert_eq!(vm.get_reg(Register::Rip), 0x1337002);
        assert_eq!(vm.get_reg(Register::Rax), 0x1337);

        Ok(())
    }
}
