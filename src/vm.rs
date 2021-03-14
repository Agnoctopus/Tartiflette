//! Virtual Machine system
use crate::x64::{IdtEntry, IdtEntryBuilder, IdtEntryType, PrivilegeLevel, Tss, TssEntry};
use std::collections::BTreeMap;

use kvm_bindings::{
    kvm_guest_debug, kvm_regs, kvm_segment, kvm_sregs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP,
    KVM_MEM_LOG_DIRTY_PAGES,
};
use kvm_ioctls;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use nix::errno::Errno;

use bits::{Alignement, BitField};
use memory::{MemoryError, PagePermissions, VirtualMemory, PAGE_SIZE};
use snapshot::Snapshot;

type Result<T> = std::result::Result<T, VmError>;

/// Error type on VM execution subsystem
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum VmError {
    /// Memory subsystem error
    Memory(MemoryError),
    /// Kvm error
    Kvm(kvm_ioctls::Error),
}

/// Vm exit reason showed by tartiflette
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmExit {
    /// Stopped on a halt instruction
    Hlt(u64),
    /// Stopped on a debug instruction that is not coverage
    Breakpoint(u64),
    /// Raw vmexit unhandled by tartiflette
    Unhandled(u64),
    /// Vm was interrupted by the host (timeout)
    Interrupted,
    /// VM Exited normally
    Exit,
    /// CPU Exception
    Exception(u8),
}

impl From<kvm_ioctls::Error> for VmError {
    fn from(err: kvm_ioctls::Error) -> VmError {
        VmError::Kvm(err)
    }
}

impl From<MemoryError> for VmError {
    fn from(err: MemoryError) -> VmError {
        VmError::Memory(err)
    }
}

fn string_perms_to_perms(perms: &str) -> PagePermissions {
    let mut perm_flags = PagePermissions::new(0);

    for c in perms.chars() {
        match c {
            'r' => perm_flags |= PagePermissions::READ,
            'w' => perm_flags |= PagePermissions::WRITE,
            'x' => perm_flags |= PagePermissions::EXECUTE,
            _ => (),
        }
    }

    perm_flags
}

/// Represents the actual purpose of a breakpoint.
#[derive(Copy, Clone, Debug)]
pub enum SuspensionPoint {
    /// Coverage suspension point. Contains the original byte overwritten by the breakpoint.
    Coverage(u8),
    /// Exit suspension point. Signifies that the execution has stopped without errors.
    Exit,
    /// Hook suspension point. Signifies that a handler should be executed before restoring execution.
    /// Contains the original byte overwritten by the breakpoint.
    Hook(u8),
}

/// Temporary implementation
pub struct Vm {
    /// kvm vm file descriptor
    vm: VmFd,
    /// VM cpu
    cpu: VcpuFd,
    /// VM virtual memory
    memory: VirtualMemory,
    /// General purpose registers used for the run
    regs: kvm_regs,
    /// Special purpose registers used for the run
    sregs: kvm_sregs,
    /// Coverage collected during the last run
    coverage: Vec<u64>,
    /// Breakpoints with the associated original bytes
    suspension_points: BTreeMap<u64, SuspensionPoint>,
}

impl Vm {
    /// Create a new `Vm` instance
    pub fn new(kvm: &Kvm, memory: VirtualMemory) -> Result<Vm> {
        // Barebones setup of the vm state
        let mut vm = Vm::barebones_setup(kvm, memory)?;

        // Finally, we setup the idt, tss and exception handlers
        vm.setup_exception_handling()?;

        Ok(vm)
    }

    fn setup_exception_handling(&mut self) -> Result<()> {
        // TODO: Change this to an option or something
        const IDT_ADDRESS: u64 = 0xffffffffff000000;
        const HANDLERS_ADDR: u64 = IDT_ADDRESS + PAGE_SIZE as u64;
        const GDT_ADDRESS: u64 = HANDLERS_ADDR + PAGE_SIZE as u64;
        const TSS_ADDRESS: u64 = GDT_ADDRESS + PAGE_SIZE as u64;

        const STACK_ADDRESS: u64 = TSS_ADDRESS + PAGE_SIZE as u64;
        const STACK_SIZE: usize = PAGE_SIZE * 64; // 64Kb of stack

        // GDT setup
        self.memory.mmap(
            GDT_ADDRESS,
            PAGE_SIZE,
            PagePermissions::READ | PagePermissions::WRITE,
        )?;

        // TODO: Properly setup GDT (code segment entry + TSS entry)
        //       Setup the tr sreg properly as well
        self.memory.write_val(GDT_ADDRESS, 0u64)?;

        // Code segment
        self.memory
            .write_val(GDT_ADDRESS + 8, 0x00209a0000000000u64)?;
        // TSS
        self.memory.write_val(
            GDT_ADDRESS + 16,
            TssEntry::new(TSS_ADDRESS, PrivilegeLevel::Ring0),
        )?;

        // Setup the tr register
        self.sregs.tr = kvm_segment {
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

        // Exception handlers setup
        self.memory.mmap(
            HANDLERS_ADDR,
            PAGE_SIZE,
            PagePermissions::READ | PagePermissions::EXECUTE,
        )?;

        for i in 0..32 {
            let handler_code: &[u8] = &[
                0x6a, i as u8, // push <exception index>
                0xf4,    // hlt -> our hypercall
            ];
            let sc_addr = HANDLERS_ADDR + (i * 32);
            self.memory.write(sc_addr, handler_code)?;
        }

        // IDT Setup
        self.memory
            .mmap(IDT_ADDRESS, PAGE_SIZE, PagePermissions::READ)?;

        let mut entries: [IdtEntry; 32] = [IdtEntry::new(); 32];
        let entries_size = entries.len() * std::mem::size_of::<IdtEntry>();

        // Redirect everything to our vmcall as a test
        for i in 0..32 {
            entries[i] = IdtEntryBuilder::new()
                .base(HANDLERS_ADDR + (i * 32) as u64)
                .dpl(PrivilegeLevel::Ring0)
                .segment_selector(1, PrivilegeLevel::Ring0)
                .gate_type(IdtEntryType::Trap)
                .ist(1)
                .collect();
        }

        self.sregs.idt.base = IDT_ADDRESS;
        self.sregs.idt.limit = (entries_size - 1) as u16;
        self.sregs.gdt.base = GDT_ADDRESS;
        self.sregs.gdt.limit = 0xFF;

        self.memory.write_val(IDT_ADDRESS, entries)?;

        // Allocate the stack used for interrupt handling
        self.memory.mmap(
            STACK_ADDRESS,
            STACK_SIZE,
            PagePermissions::READ | PagePermissions::WRITE,
        )?;

        // Setup the TSS and the IST
        self.memory
            .mmap(TSS_ADDRESS, PAGE_SIZE, PagePermissions::READ)?;

        let mut tss = Tss::new();
        tss.set_ist(1, STACK_ADDRESS + (STACK_SIZE - 0x100) as u64);

        self.memory.write_val(TSS_ADDRESS, tss)?;

        Ok(())
    }

    fn barebones_setup(kvm: &Kvm, memory: VirtualMemory) -> Result<Vm> {
        // Create the vm file descriptor
        let vm_fd = kvm.create_vm()?;
        let vm_vcpu_fd = vm_fd.create_vcpu(0)?;

        // Set the vm memory
        let mem_region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: memory.pmem.guest_address() as u64,
            memory_size: memory.pmem.size() as u64,
            userspace_addr: memory.pmem.host_address() as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        unsafe { vm_fd.set_user_memory_region(mem_region) }?;

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

        let mut sregs: kvm_sregs = vm_vcpu_fd.get_sregs()?;

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

        sregs.cs = seg;

        // seg.selector = 0;
        seg.type_ = 3;

        sregs.ds = seg;
        sregs.es = seg;
        sregs.fs = seg;
        sregs.gs = seg;
        sregs.ss = seg;

        // Paging enable and paging
        sregs.cr0 = CR0_PE | CR0_PG | CR0_ET | CR0_WP;
        // Physical address extension (necessary for x64)
        sregs.cr4 = CR4_PAE | CR4_OSXSAVE;
        // Sets x64 mode enabled (LME), active (LMA), and executable disable bit support (NXE)
        sregs.efer = IA32_EFER_LME | IA32_EFER_LMA | IA32_EFER_NXE;
        // Sets the page table root address
        sregs.cr3 = memory.page_directory() as u64;

        // Set tss
        vm_fd.set_tss_address(0xfffb_d000)?;

        // Enable vm exit on software breakpoints
        let dregs = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
            pad: 0,
            arch: Default::default(),
        };

        vm_vcpu_fd.set_guest_debug(&dregs)?;

        Ok(Vm {
            vm: vm_fd,
            cpu: vm_vcpu_fd,
            memory: memory,
            regs: Default::default(),
            sregs: sregs,
            coverage: Vec::new(),
            suspension_points: BTreeMap::new(),
        })
    }

    /// Creates a Virtual machine from a given snapshot
    pub fn from_snapshot(kvm: &Kvm, snapshot: &Snapshot, memory_size: usize) -> Result<Vm> {
        let mut memory = VirtualMemory::new(memory_size)?;

        // TODO: Load the pages into memory
        for mapping in snapshot.mappings() {
            let perms = string_perms_to_perms(&mapping.permissions);

            let size = mapping.size().align_power2(PAGE_SIZE);
            memory.mmap(mapping.start, size, perms)?;

            if let Some(data) = snapshot.read(mapping.physical_offset as u64, size) {
                if data.len() != size {
                    return Err(VmError::Memory(MemoryError::OutOfMemory));
                }
                memory.write(mapping.start as u64, &data)?;
            }
        }

        // Load the register state
        let mut vm = Vm::new(kvm, memory)?;
        let mut regs = vm.get_initial_regs();

        // Loop through registers
        for (register, &value) in snapshot.registers.iter() {
            match register.as_str() {
                "r15" => regs.r15 = value,
                "r14" => regs.r14 = value,
                "r13" => regs.r13 = value,
                "r12" => regs.r12 = value,
                "rbp" => regs.rbp = value,
                "rbx" => regs.rbx = value,
                "r11" => regs.r11 = value,
                "r10" => regs.r10 = value,
                "r9" => regs.r9 = value,
                "r8" => regs.r8 = value,
                "rax" => regs.rax = value,
                "rcx" => regs.rcx = value,
                "rdx" => regs.rdx = value,
                "rsi" => regs.rsi = value,
                "rdi" => regs.rdi = value,
                "rip" => regs.rip = value,
                "rsp" => regs.rsp = value,
                _ => (),
            }
        }

        vm.set_initial_regs(regs);
        vm.commit_registers()?;

        Ok(vm)
    }

    /// Sets up the registers that will be used as the vm starting state.
    #[inline]
    pub fn set_initial_regs(&mut self, regs: kvm_regs) {
        self.regs = regs;
    }

    /// Gets the initial registers used for a reset.
    #[inline]
    pub fn get_initial_regs(&self) -> kvm_regs {
        self.regs
    }

    /// Commit the local registers to the kvm vcpu
    pub fn commit_registers(&mut self) -> Result<()> {
        // The second bit of rflags must always be set.
        self.regs.rflags |= 1 << 1;
        self.cpu.set_regs(&self.regs)?;
        self.cpu.set_sregs(&self.sregs)?;

        Ok(())
    }

    /// Returns the list of coverage points hit during the program execution.
    #[inline]
    pub fn get_coverage(&self) -> &Vec<u64> {
        &self.coverage
    }

    /// Returns the current registers of the virtual machine.
    #[inline]
    pub fn get_registers(&self) -> Result<kvm_regs> {
        self.cpu.get_regs().map_err(|err| VmError::Kvm(err))
    }

    /// Installs a coverage point (breakpoint). Returns true if the breakpoint was
    /// inserted, false if it already existed.
    pub fn add_coverage_point(&mut self, addr: u64) -> Result<bool> {
        if self.suspension_points.contains_key(&addr) {
            return Ok(false);
        }

        // Get original byte.
        let mut orig_bytes: [u8; 1] = [0; 1];
        self.memory.read(addr, &mut orig_bytes)?;

        // Write the breakpoint
        self.memory.write(addr, &mut [0xcc])?;
        self.suspension_points
            .insert(addr, SuspensionPoint::Coverage(orig_bytes[0]));

        Ok(true)
    }

    /// Installs an Exit suspension point.
    /// Returns true if the breakpoint was inserted, false if it already existed.
    pub fn add_exit_point(&mut self, addr: u64) -> Result<bool> {
        if self.suspension_points.contains_key(&addr) {
            return Ok(false);
        }

        self.memory.write(addr, &mut [0xcc])?;
        self.suspension_points.insert(addr, SuspensionPoint::Exit);

        Ok(true)
    }

    /// Resets the current vm to a state identical to the provided other
    pub fn reset(&mut self, other: &Vm) -> Result<()> {
        // Check that the vms have the same memory size
        assert!(
            self.memory.pmem.size() == other.memory.pmem.size(),
            "Vm memory size mismatch"
        );

        // Restore original memory state
        let log = self.vm.get_dirty_log(0, self.memory.pmem.size())?;

        // Loop through bitmap of pages dirtied
        for (bm_idx, bm) in log.into_iter().enumerate() {
            for bit_idx in 0..64 {
                if bm.is_bit_set(bit_idx) {
                    let frame_index = (bm_idx * 64) + bit_idx;
                    let pa = frame_index * PAGE_SIZE;

                    let orig_data = other.memory.pmem.raw_slice(pa, PAGE_SIZE)?;
                    self.memory.pmem.write(pa, orig_data)?;
                }
            }
        }

        // copy registers from other state
        self.regs = other.regs;
        self.sregs = other.sregs;
        self.coverage.clear();

        // Sets the original registers into kvm vcpu
        self.commit_registers()?;

        Ok(())
    }

    /// Starts the vcpu and respond to events
    pub fn run(&mut self) -> Result<VmExit> {
        let result = loop {
            let exit = self.cpu.run();
            let regs = self.cpu.get_regs()?;

            if let Err(err) = exit {
                match Errno::from_i32(err.errno()) {
                    Errno::EINTR | Errno::EAGAIN => break VmExit::Interrupted,
                    _ => break VmExit::Unhandled(regs.rip),
                }
            }

            let vmexit = exit.unwrap();
            println!("VcpuExit: {:?}", vmexit);

            match vmexit {
                VcpuExit::Debug => {
                    if let Some(&point) = self.suspension_points.get(&regs.rip) {
                        match point {
                            SuspensionPoint::Coverage(orig_byte) => {
                                self.memory.write(regs.rip, &[orig_byte])?;
                                self.coverage.push(regs.rip);
                            }
                            SuspensionPoint::Exit => break VmExit::Exit,
                            _ => break VmExit::Breakpoint(regs.rip),
                        }
                    } else {
                        break VmExit::Breakpoint(regs.rip);
                    }
                }
                // -1 as hlt takes the ip after its instruction
                VcpuExit::Hlt => {
                    let mut output: [u8; 16] = [0; 16];
                    self.memory.read(regs.rsp, output.as_mut())?;

                    for e in output.iter() {
                        print!("{:02x} ", e);
                    }

                    println!("");

                    break VmExit::Hlt(regs.rip - 1);
                }
                _ => break VmExit::Unhandled(regs.rip),
            }
        };

        Ok(result)
    }

    /// Creates a copy of the current Vm state. Does not copy the coverage points.
    pub fn fork(&self, kvm: &Kvm) -> Result<Self> {
        // Copy the initial memory state
        let memory = self.memory.clone()?;

        // Create new vm instance. We do a barebones setup as all of the exception
        // handling code is already in the forker's memory.
        let mut vm = Vm::barebones_setup(kvm, memory)?;

        // Copy the registers state
        vm.regs = self.regs;
        vm.sregs = self.sregs;

        Ok(vm)
    }
}

#[cfg(test)]
mod tests {
    use kvm_ioctls::Kvm;
    use memory::{PagePermissions, VirtualMemory, PAGE_SIZE};

    use super::{Result, Vm, VmExit};

    #[test]
    /// Runs a simple piece of code until completion
    fn test_simple_exec() -> Result<()> {
        let mut memory = VirtualMemory::new(512 * PAGE_SIZE)?;

        // Maps a simple `add rdx, rax; hlt`
        let shellcode: &[u8] = &[
            0x48, 0x01, 0xc2, // add rdx, rax
        ];

        memory.mmap(0x1337000, 0x1000, PagePermissions::EXECUTE)?;
        memory.write(0x1337000, shellcode)?;

        // Create the vm
        let kvm = Kvm::new()?;
        let mut vm = Vm::new(&kvm, memory)?;
        let mut regs = vm.get_initial_regs();

        regs.rax = 0x337;
        regs.rdx = 0x1000;
        regs.rip = 0x1337000;

        vm.set_initial_regs(regs);
        vm.commit_registers()?;

        // Add exit point
        vm.add_exit_point(0x1337003)?;

        // Runs the vm until completion (hlt)
        let vmexit = vm.run()?;

        assert_eq!(vmexit, VmExit::Exit);
        Ok(())
    }

    #[test]
    /// Runs a sample of linear code and collect coverage.
    fn test_simple_coverage() -> Result<()> {
        let mut memory = VirtualMemory::new(512 * 0x1000)?;

        // Maps a simple `add rdx, rax; hlt`
        let shellcode: &[u8] = &[
            0x48, 0x01, 0xc2, // add rdx, rax
            0x48, 0x01, 0xd8, // add rax, rbx
            0x31, 0xc0, // xor eax, eax
        ];

        memory.mmap(0x1337000, 0x1000, PagePermissions::EXECUTE)?;
        memory.write(0x1337000, shellcode)?;

        // Create the vm
        let kvm = Kvm::new()?;
        let mut vm = Vm::new(&kvm, memory)?;

        // Initialize registers
        let mut regs = vm.get_initial_regs();
        regs.rip = 0x1337000;
        vm.set_initial_regs(regs);
        vm.commit_registers()?;
        let original_vm = vm.fork(&kvm)?;

        // Add breakpoints
        let breakpoints: Vec<u64> = vec![0x1337000, 0x1337003];

        for bkpt in breakpoints.iter().cloned() {
            vm.add_coverage_point(bkpt)?;
        }

        // Add exit point
        vm.add_exit_point(0x1337008)?;

        // Runs the vm until completion (hlt)
        let vmexit = vm.run()?;
        let coverage = vm.get_coverage();

        assert_eq!(vmexit, VmExit::Exit, "Wrong exit address");
        assert_eq!(breakpoints, *coverage, "Coverage does not match");

        // Check that a reset does not reset the breakpoints in memory
        vm.reset(&original_vm)?;

        let mut shellcode_read_back: [u8; 8] = [0; 8];
        vm.memory.read(0x1337000, &mut shellcode_read_back)?;

        assert_eq!(shellcode, shellcode_read_back);

        Ok(())
    }
}
