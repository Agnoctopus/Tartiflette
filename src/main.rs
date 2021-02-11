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

const ASM_64_SHELLCODE: &[u8] = &[
    0x48, 0x01, 0xc2, // add rdx, rax
    0xf4, // hlt
];

use paging::PagePermissions;
use vm::Vm;

fn run() {
    // Instantiate KVM
    let kvm = Kvm::new().expect("Failed to instantiate KVM");
    assert!(kvm.get_api_version() >= 12);

    // Setup physical memory
    let mut vm_mem =
        memory::VMMemory::new(512 * paging::PAGE_SIZE).expect("Could not allocate Vm memory");

    vm_mem
        .mmap(0x1337000, 0x1000, PagePermissions::EXECUTE)
        .unwrap();
    vm_mem.write(0x1337000, ASM_64_SHELLCODE).unwrap();

    let mut vm = Vm::new(&kvm, vm_mem);
    vm.run();
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
