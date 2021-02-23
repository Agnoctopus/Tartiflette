//! Virtual Machine system

use std::collections::BTreeMap;

use bits::BitField;
use kvm_bindings::{
    kvm_guest_debug, kvm_regs, kvm_segment, kvm_sregs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_USE_SW_BP,
    KVM_MEM_LOG_DIRTY_PAGES,
};
use kvm_ioctls;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};

use memory::{MemoryError, VirtualMemory};

type Result<T> = std::result::Result<T, VmError>;

/// Error type on VM execution subsystem
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum VmError {
    /// Memory subsystem error
    Memory(MemoryError),
    /// Kvm error
    Kvm(kvm_ioctls::Error),
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum VmExit {
    /// Stopped on a halt instruction
    Hlt(u64),
    /// Stopped on a debug instruction that it not coverage.
    Breakpoint(u64),
    /// Raw vmexit unhandled by tartiflette
    Unhandled(u64)
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
    /// Breakpoints with the associated original bytes.
    coverage_points: BTreeMap<u64, u8>
}

impl Vm {
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
        sregs.cr4 = CR4_PAE;
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
            coverage_points: BTreeMap::new()
        })
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

    #[inline]
    pub fn get_coverage(&self) -> &Vec<u64> {
        &self.coverage
    }

    #[inline]
    /// Returns the current registers of the virtual machine.
    pub fn get_registers(&self) -> Result<kvm_regs> {
        self.cpu.get_regs().map_err(|err| VmError::Kvm(err))
    }

    #[inline]
    /// Installs a coverage point (breakpoint). Returns true if the breakpoint was
    /// inserted, false if it already existed.
    pub fn add_coverage_point(&mut self, addr: u64) -> Result<bool> {
        if self.coverage_points.contains_key(&addr) {
            return Ok(false)
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

        println!("Source memory size: 0x{:x}", self.memory.pmem.size());

        // Restore original memory state
        let used_mem = self.memory.pmem.used();
        let log = self.vm.get_dirty_log(0, used_mem)?;

        // Loop through bitmap of pages dirtied
        // for (bm_idx, bm) in log.into_iter().enumerate() {
        //     for bit_idx in 0..64 {
        //         if bm.is_bit_set(bit_idx) {
        //             let frame_index = (bm_idx * 64) + bit_idx;
        //             let pa = frame_index * 0x1000;

        //             println!("Restoring dirty frame 0x{:x}", pa);

        //             let orig_data = other.memory.pmem.raw_slice(pa, 0x1000)?;
        //             // self.memory.pmem.write(pa, orig_data)?;
        //         }
        //     }
        // }

        // copy registers from other state
        // self.regs = other.regs;
        // self.sregs = other.sregs;
        // self.coverage.clear();

        Ok(())
    }

    /// Runs the virtual memory
    pub fn run(&mut self) -> Result<VmExit> {
        // The second bit of rflags must always be set.
        self.regs.rflags |= 2;
        self.cpu.set_regs(&self.regs)?;
        self.cpu.set_sregs(&self.sregs)?;
        self.vm.get_dirty_log(0, self.memory.pmem.size())?;

        let result = loop {
            let exit = self.cpu.run()?;
            let regs = self.cpu.get_regs()?;

            println!("VcpuExit: {:?}", exit);

            match exit {
                VcpuExit::Debug => {
                    if let Some(orig_byte) = self.coverage_points.get(&regs.rip) {
                        self.memory.write(regs.rip, &[*orig_byte])?;
                        self.coverage.push(regs.rip);
                    } else {
                        break VmExit::Breakpoint(regs.rip)
                    }
                },
                // -1 as hlt takes the ip after its instruction
                VcpuExit::Hlt => break VmExit::Hlt(regs.rip - 1),
                _ => break VmExit::Unhandled(regs.rip)
            }
        };

        Ok(result)
    }

    // Creates a copy of the current Vm state
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
    use memory::{PagePermissions, VirtualMemory};
    use kvm_ioctls::{Kvm, VcpuExit};

    use super::{Result, Vm, VmExit};

    #[test]
    /// Runs a simple piece of code until completion
    fn test_simple_exec() -> Result<()> {
        let mut memory = VirtualMemory::new(512 * 0x1000)?;

        // Maps a simple `add rdx, rax; hlt`
        let shellcode: &[u8] = &[
            0x48, 0x01, 0xc2, // add rdx, rax
            0xf4              // hlt
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
            0x31, 0xc0,       // xor eax, eax
            0xf4              // hlt
        ];

        memory.mmap(0x1337000, 0x1000, PagePermissions::EXECUTE)?;
        memory.write(0x1337000, shellcode)?;

        // Create the vm
        let kvm = Kvm::new()?;
        let mut vm = Vm::new(&kvm, memory)?;
        let original_vm = vm.fork(&kvm)?;

        // Initialize registers
        let mut regs = vm.get_initial_regs();
        regs.rip = 0x1337000;
        vm.set_initial_regs(regs);

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

        // Check that a reset does reset the breakpoints
        vm.reset(&original_vm)?;

        Ok(())
    }
}
