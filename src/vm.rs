//! Virtual Machine system

use kvm_bindings;
use kvm_ioctls;
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};

use libc;

use crate::memory::VMPhysMem;

/// Virtual machine
pub struct VM {
    vm_fd: VmFd,
}

impl VM {
    /// Create a new `VM` instance
    pub fn new(kvm: &Kvm) -> Self {
        let vm_fd = kvm.create_vm().expect("Failed to create a VM");

        Self { vm_fd: vm_fd }
    }

    /// Return the `VmFd`
    pub fn vm_fd(&self) -> &VmFd {
        &self.vm_fd
    }

    /// Initialize the guest memory
    pub fn memory_init(&self, pmem: &VMPhysMem) {
        let slot = 0;
        let mem_region = kvm_bindings::kvm_userspace_memory_region {
            slot,
            guest_phys_addr: pmem.guest_address() as u64,
            memory_size: pmem.size() as u64,
            userspace_addr: pmem.host_address() as u64,
            flags: kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES,
        };
        unsafe {
            self.vm_fd
                .set_user_memory_region(mem_region)
                .expect("Failed to set user memory region")
        };
    }

    /// Return the number of pages dirtied
    pub fn pages_dirtied(&self, pmem: &VMPhysMem) -> usize {
        let slot = 0;
        let dirty_pages_bitmap = self.vm_fd.get_dirty_log(slot, pmem.size()).unwrap();
        let dirty_pages = dirty_pages_bitmap
            .into_iter()
            .map(|page| page.count_ones())
            .fold(0, |dirty_page_count, i| dirty_page_count + i as usize);
        dirty_pages
    }
}

/// Virtual CPU
pub struct VCPU {
    vcpu_fd: VcpuFd,
    id: u8,
}

impl VCPU {
    /// Create a new `VCPU` instance
    pub fn new(vm_fd: &VmFd, id: u8) -> Self {
        let vcpu_fd = vm_fd.create_vcpu(id).expect("Failed to create a VCPU");

        Self {
            vcpu_fd: vcpu_fd,
            id: id,
        }
    }

    /// Configure the `VCPU`
    pub fn configure(&self, entry: u64) {
        let mut vcpu_sregs = self.vcpu_fd.get_sregs().unwrap();
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        self.vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

        let mut vcpu_regs = self.vcpu_fd.get_regs().unwrap();
        vcpu_regs.rip = entry as u64;
        vcpu_regs.rflags = 2;
        self.vcpu_fd.set_regs(&vcpu_regs).unwrap();
    }

    /// Run
    pub fn run(&self) {
        loop {
            match self.vcpu_fd.run().expect("run failed") {
                VcpuExit::IoIn(addr, data) => {
                    println!("[I/O in    ] Address: {:#08x} Data: {:#x}", addr, data[0]);
                }
                VcpuExit::IoOut(addr, _data) => {
                    println!("[I/O out   ] Address: {:#08x}", addr);
                }
                VcpuExit::MmioRead(addr, _data) => {
                    println!("[MMIO read ] Address: {:#08x}", addr);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    println!("[MMIO write] Address: {:#08x} Data: {:#x}", addr, data[0]);
                }
                VcpuExit::Hlt => {
                    println!("[Halted    ]",);
                    break;
                }
                r => panic!("Unexpected exit reason: {:?}", r),
            }
        }
    }
}
