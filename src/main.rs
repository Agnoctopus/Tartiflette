//! Tartiflette

#![warn(missing_docs)]

mod cli;
mod config;
mod vm;

#[allow(unused)]
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use memory::{PagePermissions, VirtualMemory};
use nix::sys::signal::{kill, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::Pid;
use snapshot::Snapshot;
use std::thread;
use std::time::Duration;
use vm::{Vm, VmExit};

const ASM_64_SHELLCODE: &[u8] = &[0xeb, 0xfe];

extern "C" fn vm_tock(_: i32) {
    // No-op
    println!("VM TOCK");
}

fn run() {
    // Setup exception handler
    let sigstuff = SigAction::new(
        SigHandler::Handler(vm_tock),
        SaFlags::empty(),
        SigSet::empty(),
    );

    unsafe { sigaction(Signal::SIGUSR2, &sigstuff) }.unwrap();

    // Instantiate KVM
    let kvm = Kvm::new().expect("Failed to instantiate KVM");
    assert!(kvm.get_api_version() >= 12);

    // Setup virtual memory
    let mut vm_mem = VirtualMemory::new(512 * 0x1000).expect("Could not allocate Vm memory");

    vm_mem
        .mmap(0x1337000, 0x1000, PagePermissions::EXECUTE)
        .unwrap();
    vm_mem.write(0x1337000, ASM_64_SHELLCODE).unwrap();

    // Setup virtual machine
    let mut vm = Vm::new(&kvm, vm_mem).unwrap();

    let mut regs = vm.get_initial_regs();
    regs.rip = 0x1337000;
    regs.rax = 0x1000;
    regs.rdx = 0x337;
    vm.set_initial_regs(regs);
    vm.commit_registers();

    // Start timer thread to interrupt vm
    thread::spawn(|| loop {
        thread::sleep(Duration::from_millis(1000));
        kill(Pid::from_raw(0), Signal::SIGUSR2);
    });

    let result = vm.run().expect("Run failed");

    println!("Exit status: {:x?}", result);

    // // Loading from a snapshot
    // let mut snapshot = Snapshot::new("/home/sideway/sources/Tartiflette/snapshot_info.json")
    // .expect("snapshot loading failed");

    // let snapshot_size = snapshot.size();

    // println!("Snapshot size: {}", snapshot_size);

    // let vm2 = Vm::from_snapshot(&kvm, &mut snapshot, snapshot_size * 2).expect("vm failed");
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
