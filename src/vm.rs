//! Virtual Machine system

use kvm_bindings::{kvm_sregs, kvm_regs};
use kvm_ioctls;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};

use libc;

use crate::memory::{VMPhysMem, VMMemory};

/// Temporary implementation
pub struct Vm {
    /// kvm vm file descriptor
    vm: VmFd,
    /// VM cpu
    cpu: VcpuFd,
    /// VM virtual memory
    memory: VMMemory,
    /// General purpose registers used for the run
    regs: kvm_regs,
}

impl Vm {
    pub fn new(kvm: &Kvm, memory: VMMemory) -> Vm {
        // Create the vm file descriptor
        let vm_fd = kvm.create_vm().expect("Could not create vm");
        let vm_vcpu_fd = vm_fd.create_vcpu(0).expect("Could not create vm vcpu");

        // Set the vm memory
        let mem_region = kvm_bindings::kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: memory.pmem.guest_address() as u64,
            memory_size: memory.pmem.size() as u64,
            userspace_addr: memory.pmem.host_address() as u64,
            flags: kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES,
        };

        unsafe {
            vm_fd
                .set_user_memory_region(mem_region)
                .expect("Failed to set user memory region")
        };

        // Initialize system registers
        const CR0_PG: u64 = 1 << 31;
        const CR0_PE: u64 = 1 << 0;
        const CR4_PAE: u64 = 1 << 5;
        const IA32_EFER_LME: u64 = 1 << 8;
        const IA32_EFER_LMA: u64 = 1 << 10;
        const IA32_EFER_NXE: u64 = 1 << 11;

        let mut sregs: kvm_sregs = Default::default();

        // 64 bits code segment
        sregs.cs.l = 1;
        // Paging enable and paging
        sregs.cr0 = CR0_PE | CR0_PG;
        // Physical address extension (necessary for x64)
        sregs.cr4 = CR4_PAE;
        // Sets x64 mode enabled (LME), active (LMA), and executable disable bit support (NXE)
        sregs.efer = IA32_EFER_LME | IA32_EFER_LMA | IA32_EFER_NXE;
        // Sets the page table root address
        sregs.cr3 = memory.pmem.guest_address() as u64;

        vm_vcpu_fd.set_sregs(&sregs).unwrap();

        Vm {
            vm: vm_fd,
            cpu: vm_vcpu_fd,
            memory: memory,
            regs: Default::default()
        }
    }

    /// Resets the vm
    /// Problem: - We need differential reset from a bitmap (should we collect it from kvm ?)
    /// pub fn reset(&mut self, other: &Vmm) {}

    /// Runs the virtual memory
    pub fn run(&mut self) /* -> Some kind of Vm exit */ {
        // 1) Set registers for the VM (effectively reset the kernel object) + rflags second bit must be set
        // 2) Execute code
        let mut regs: kvm_regs = Default::default();
        regs.rip = 0x1337000;
        regs.rax = 0x1000;
        regs.rdx = 0x337;
        regs.rflags = 2;

        self.cpu.set_regs(&regs).unwrap();

        match self.cpu.run().expect("run failed") {
            exit_reason => panic!("exit reason: {:?}", exit_reason),
        }
    }
}