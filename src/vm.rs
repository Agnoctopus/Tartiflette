//! Virtual Machine system

use std::collections::BTreeMap;

use bits::{Alignement, BitField};
use kvm_bindings::{
    kvm_guest_debug, kvm_regs, kvm_segment, kvm_sregs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP,
    KVM_MEM_LOG_DIRTY_PAGES,
};
use kvm_ioctls;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use nix::errno::Errno;

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

/// Temporary implementation
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
struct Idt64Entry {
    /// First part of the handler offset
    offset_0: u16,
    /// Segment selector to use
    segment_selector: u16,
    /// Entry flags (present, DPL, type, IST)
    flags: u16,
    /// Second part of the offset
    offset_1: u16,
    /// Last part of the offset
    offset_2: u32,
    /// Reserved (should be 0 ?)
    reserved: u64,
}

impl Idt64Entry {
    pub fn new() -> Self {
        Idt64Entry {
            offset_0: 0,
            segment_selector: 0,
            flags: 0,
            offset_1: 0,
            offset_2: 0,
            reserved: 0,
        }
    }
}

#[derive(Debug, Copy, Clone)]
enum Dpl {
    Ring0 = 0,
    Ring3 = 3,
}

#[derive(Debug, Copy, Clone)]
enum Idt64EntryType {
    Interrupt = 0b1110,
    Trap = 0b1111,
}

struct Idt64EntryBuilder {
    offset: u64,
    segment_selector: u16,
    ist: u8,
    dpl: Dpl,
    gate_type: Idt64EntryType,
}

impl Idt64EntryBuilder {
    pub fn new() -> Self {
        Idt64EntryBuilder {
            offset: 0,
            segment_selector: 0,
            ist: 0,
            dpl: Dpl::Ring0,
            gate_type: Idt64EntryType::Interrupt,
        }
    }

    pub fn offset(&mut self, offset: u64) -> &mut Self {
        self.offset = offset;
        self
    }

    pub fn ist(&mut self, ist: u8) -> &mut Self {
        assert!(ist <= 7, "IST mut be in the range 0-7, got {}", ist);
        self.ist = ist;
        self
    }

    pub fn dpl(&mut self, dpl: Dpl) -> &mut Self {
        self.dpl = dpl;
        self
    }

    pub fn segment_selector(&mut self, segment: u16) -> &mut Self {
        self.segment_selector = segment;
        self
    }

    pub fn gate_type(&mut self, gate_type: Idt64EntryType) -> &mut Self {
        self.gate_type = gate_type;
        self
    }

    pub fn collect(&self) -> Idt64Entry {
        let mut flags: u16 = 1 << 15; // Present
        flags |= (self.dpl as u16) << 13; // Dpl
        flags |= (self.gate_type as u16) << 8; // Gate Type
        flags |= self.ist as u16;

        Idt64Entry {
            offset_0: (self.offset & 0xffff) as u16,
            segment_selector: self.segment_selector,
            flags: flags,
            offset_1: ((self.offset >> 16) & 0xffff) as u16,
            offset_2: ((self.offset >> 32) & 0xffffffff) as u32,
            reserved: 0,
        }
    }
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
    coverage_points: BTreeMap<u64, u8>,
}

impl Vm {
    /// Create a new `Vm` instance
    pub fn new(kvm: &Kvm, memory: VirtualMemory) -> Result<Vm> {
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
            limit: 0xffffffff,
            selector: 1 << 3,
            present: 1,
            type_: 11, /* Code: execute, read, accessed */
            dpl: 0,
            db: 0,
            s: 1, /* Code/data */
            l: 1,
            g: 1, /* 4KB granularity */
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        sregs.cs = seg;

        seg.selector = 0;
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

        let vm = Vm {
            vm: vm_fd,
            cpu: vm_vcpu_fd,
            memory: memory,
            regs: Default::default(),
            sregs: sregs,
            coverage: Vec::new(),
            coverage_points: BTreeMap::new(),
        };

        // Finally, we setup the idt, tss and exception handlers
        vm.setup_exception_handling()
    }

    fn setup_exception_handling(mut self) -> Result<Vm> {
        // TODO: Change this to an option or something
        const IDT_ADDRESS: u64 = 0xffffffffffa00000;
        const HANDLERS_ADDR: u64 = IDT_ADDRESS + PAGE_SIZE as u64;

        // Handlers setup
        self.memory.mmap(
            HANDLERS_ADDR,
            PAGE_SIZE,
            PagePermissions::READ | PagePermissions::EXECUTE,
        )?;

        const SHELLCODE: &[u8] = &[
            0x48, 0xc7, 0xc0, 0x37, 0x13, 0x03, 0x00, // mov rax, 0x31337
            0x0f, 0x01, 0xc1, // vmcall
        ];

        self.memory.write(HANDLERS_ADDR, SHELLCODE)?;

        // IDT Setup
        self.memory
            .mmap(IDT_ADDRESS, PAGE_SIZE, PagePermissions::READ)?;

        let mut entries: [Idt64Entry; 32] = [Idt64Entry::new(); 32];
        let entries_size = entries.len() * std::mem::size_of::<Idt64Entry>();

        // Redirect everything to our vmcall as a test
        for i in 0..32 {
            entries[i] = Idt64EntryBuilder::new()
                .offset(HANDLERS_ADDR)
                .dpl(Dpl::Ring0)
                .segment_selector(self.sregs.cs.selector)
                .gate_type(Idt64EntryType::Trap)
                .collect();
        }

        self.sregs.idt.base = IDT_ADDRESS;
        self.sregs.idt.limit = (entries_size - 1) as u16;

        // Write the handlers to memory
        let entries_data: &[u8] =
            unsafe { std::slice::from_raw_parts(entries.as_ptr() as *const u8, entries_size) };

        self.memory.write(IDT_ADDRESS, entries_data)?;

        Ok(self)
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
    #[inline]
    pub fn add_coverage_point(&mut self, addr: u64) -> Result<bool> {
        if self.coverage_points.contains_key(&addr) {
            return Ok(false);
        }

        // Get original byte.
        let mut orig_bytes: [u8; 1] = [0; 1];
        self.memory.read(addr, &mut orig_bytes)?;

        // Write the breakpoint
        self.memory.write(addr, &mut [0xcc])?;
        self.coverage_points.insert(addr, orig_bytes[0]);

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
                    if let Some(&orig_byte) = self.coverage_points.get(&regs.rip) {
                        self.memory.write(regs.rip, &[orig_byte])?;
                        self.coverage.push(regs.rip);
                    } else {
                        break VmExit::Breakpoint(regs.rip);
                    }
                }
                // -1 as hlt takes the ip after its instruction
                VcpuExit::Hlt => break VmExit::Hlt(regs.rip - 1),
                _ => break VmExit::Unhandled(regs.rip),
            }
        };

        Ok(result)
    }

    /// Creates a copy of the current Vm state
    pub fn fork(&self, kvm: &Kvm) -> Result<Self> {
        // Copy the initial memory state
        let memory = self.memory.clone()?;

        // Create new vm instance
        let mut vm = Vm::new(kvm, memory)?;

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
            0xf4, // hlt
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

        // Runs the vm until completion (hlt)
        let vmexit = vm.run()?;

        assert_eq!(vmexit, VmExit::Hlt(0x1337003));
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
            0xf4, // hlt
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

        // Runs the vm until completion (hlt)
        let vmexit = vm.run()?;
        let coverage = vm.get_coverage();

        assert_eq!(vmexit, VmExit::Hlt(0x1337008), "Wrong exit address");
        assert_eq!(breakpoints, *coverage, "Coverage does not match");

        // Check that a reset does not reset the breakpoints in memory
        vm.reset(&original_vm)?;

        let mut shellcode_read_back: [u8; 9] = [0; 9];
        vm.memory.read(0x1337000, &mut shellcode_read_back)?;

        assert_eq!(shellcode, shellcode_read_back);

        Ok(())
    }
}
