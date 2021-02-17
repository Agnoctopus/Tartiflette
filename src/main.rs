//! Tartiflette

#![warn(missing_docs)]

mod cli;
mod config;
mod memory;
mod utils;
mod vm;

#[allow(unused)]
use kvm_ioctls::{Kvm, VcpuFd, VmFd};

const ASM_64_SHELLCODE: &[u8] = &[
    0x48, 0x01, 0xc2, // add rdx, rax
    0xcc, // breakpoint
];

use memory::{PagePermissions, VirtualMemory};
use vm::Vm;

fn run() {
    // Instantiate KVM
    let kvm = Kvm::new().expect("Failed to instantiate KVM");
    assert!(kvm.get_api_version() >= 12);

    // Setup physical memory
    let mut vm_mem = VirtualMemory::new(512 * 0x1000).expect("Could not allocate Vm memory");

    vm_mem
        .mmap(0x1337000, 0x1000, PagePermissions::EXECUTE)
        .unwrap();
    vm_mem.write(0x1337000, ASM_64_SHELLCODE).unwrap();

    let mut vm = Vm::new(&kvm, vm_mem).unwrap();

    let mut regs = vm.get_initial_regs();
    regs.rip = 0x1337000;
    regs.rax = 0x1000;
    regs.rdx = 0x337;

    vm.set_initial_regs(regs);
    match vm.run().expect("Run failed") {
        kvm_ioctls::VcpuExit::Debug => println!("Breakpoint hits !"),
        error_code => println!("Failed: {:?}", error_code),
    }

    // vm.reset().unwrap();
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
