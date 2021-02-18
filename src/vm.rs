//! Virtual Machine system

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
        })
    }

    /// Sets up the registers that will be used as the vm starting state.
    pub fn set_initial_regs(&mut self, regs: kvm_regs) {
        self.regs = regs;
    }

    /// Gets the initial registers used for a reset.
    pub fn get_initial_regs(&self) -> kvm_regs {
        self.regs
    }

    /// Resets the current vm to a state identical to the provided other
    pub fn reset(&mut self, other: &Vm) -> Result<()> {
        // Check that the vms have the same memory size
        assert!(
            self.memory.pmem.size() == other.memory.pmem.size(),
            "Vm memory size mismatch"
        );

        // Restore original memory state
        let used_mem = self.memory.pmem.used();
        let log = self.vm.get_dirty_log(0, used_mem)?;

        for (bm_idx, bm) in log.into_iter().enumerate() {
            for bit_idx in 0..8 {
                let pa = (bm_idx * 8) + bit_idx;

                if bm & (1 << bit_idx) != 0 {
                    println!("Restoring dirty frame 0x{:x}", pa);

                    let orig_data = other.memory.pmem.raw_slice(pa, 0x1000)?;
                    self.memory.pmem.write(pa, orig_data)?;
                }
            }
        }

        // copy registers from other state
        self.regs = other.regs;
        self.sregs = other.sregs;

        Ok(())
    }

    /// Resets the vm
    /// Problem: - We need differential reset from a bitmap (should we collect it from kvm ?)
    /// pub fn reset(&mut self, other: &Vmm) {}

    /// Runs the virtual memory
    pub fn run(&mut self) -> Result<VcpuExit> {
        // 1) Set registers for the VM (effectively reset the kernel object) + rflags second bit must be set
        // 2) Execute code

        // The second bit of rflags must always be set.
        self.regs.rflags |= 2;
        self.cpu.set_regs(&self.regs)?;
        self.cpu.set_sregs(&self.sregs)?;
        self.vm.get_dirty_log(0, self.memory.pmem.size())?;

        self.cpu.run().map_err(|err| VmError::Kvm(err))
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
