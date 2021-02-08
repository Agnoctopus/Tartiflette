//! Tartiflette

#![warn(missing_docs)]

extern crate bits;
extern crate paging;

mod cli;
mod config;
mod memory;
mod vm;

extern crate kvm_bindings;
extern crate kvm_ioctls;
extern crate libc;

#[allow(unused)]
use kvm_ioctls::{Kvm, VcpuFd, VmFd};

const MEM_SIZE: usize = 0x4000;
const GUEST_ADDRESS: usize = 0x1000;
const ASM_BYTES: &[u8] = &[
    0xba, 0xf8, 0x03, // mov dx, 0x3f8
    0x30, 0xc0, // xor al, al
    0x04, 0x42, // add al, 0x42
    0xee, // out dx, al
    0xec, // in  al, dx
    0x8a, 0x16, 0x00, 0x80, // mov dl, [0x8000] (MMIO Read)
    0xc6, 0x06, 0x00, 0x80, 0x42, // mov [0x8000], 0x42  (MMIO Write)
    0xfa, // cli
    0xf4, // hlt
];

fn run() {
    // Instantiate KVM
    let kvm = Kvm::new().expect("Failed to instantiate KVM");

    // Setup a physical memory
    let mut vm_mem =
        memory::VMMemory::new(4 * paging::PAGE_SIZE).expect("Could not allocate Vm memory");
    vm_mem.pmem.write(0x1000, ASM_BYTES);

    // Create a vm
    let vm = vm::VM::new(&kvm);
    vm.memory_init(&vm_mem.pmem);

    let vcpu = vm::VCPU::new(vm.vm_fd(), 0);
    vcpu.configure(0x1000);
    vcpu.run();
    assert!(vm.pages_dirtied(&vm_mem.pmem) == 1);
}

/// Main function
fn main() {
    // Get the program args as Vec<&str>
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_ref).collect();

    // Parse the command line
    match cli::CLI::parse(args) {
        Ok(_config) => {
            run();
        }
        Err(error) => {
            eprintln!("Error while parsing the command line.");
            eprint!("{}", error)
        }
    }
}
