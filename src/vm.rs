//! Virtual Machine system

use kvm_bindings;
use kvm_ioctls;
use kvm_ioctls::{Kvm, VmFd};

/// Virtual machine
pub struct VM {
    vm_fd: VmFd,
}

impl VM {
    /// Create a new `VM` instance
    pub fn new(kvm: Kvm) -> Self {
        // Create a KVM VM
        let vm_fd = kvm.create_vm().expect("Failed to create a VM");

        Self {
            vm_fd: vm_fd,
        }
    }
}
