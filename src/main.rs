//! Tartiflette

#![warn(missing_docs)]

use kvm_ioctls::Kvm;
use nix::sys::signal::{kill, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::Pid;

use std::thread;
use std::time::Duration;

use memory::{PagePermissions, VirtualMemory};
use snapshot::Snapshot;

use tartiflette::vm::Vm;

const ASM_64_SHELLCODE: &[u8] = &[
    0x48, 0x31, 0xc0, // xor rax, rax
    0x66, 0xc7, 0x00, 0x37, 0x13, // mov word [rax], 0x1337
];

extern "C" fn vm_tock(_: i32) {
    // No-op
    println!("VM TOCK");
}

fn setup_timer() {
    // Setup exception handler
    let sigstuff = SigAction::new(
        SigHandler::Handler(vm_tock),
        SaFlags::empty(),
        SigSet::empty(),
    );

    unsafe { sigaction(Signal::SIGUSR2, &sigstuff) }.unwrap();

    // Start timer thread to interrupt vm
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(1000));
        kill(Pid::from_raw(0), Signal::SIGUSR2).unwrap();
    });
}

/// Run a VM from a `snapshot`
fn run_snapshot(snapshot: String) {
    // Instantiate KVM
    let kvm = Kvm::new().expect("Failed to instantiate KVM");
    assert!(kvm.get_api_version() >= 12);
    setup_timer();

    // Retrieve the snapsh9ot
    let mut snapshot = Snapshot::new(snapshot).expect("snapshot loading failed");
    let snapshot_size = snapshot.size();
    println!("Snapshot size: {}", snapshot_size);

    // Setup the VM
    let mut vm = Vm::from_snapshot(&kvm, &mut snapshot, snapshot_size * 2).expect("vm failed");

    // Run the vm
    let result = vm.run().expect("Run failed");
    println!("Exit status: {:x?}", result);
}

/// Run some shellcode
fn run() {
    // Instantiate KVM
    let kvm = Kvm::new().expect("Failed to instantiate KVM");
    assert!(kvm.get_api_version() >= 12);
    setup_timer();

    // Setup virtual memory
    let mut vm_mem = VirtualMemory::new(512 * 0x1000).expect("Could not allocate Vm memory");
    vm_mem
        .mmap(0x1337000, 0x1000, PagePermissions::EXECUTE)
        .expect("Failed to mmap");
    vm_mem
        .write(0x1337000, ASM_64_SHELLCODE)
        .expect("Failed to write shellcode");
    vm_mem
        .mmap(
            0x1331000,
            0x1000,
            PagePermissions::READ | PagePermissions::WRITE,
        )
        .expect("Failed to map stack memory");

    // Setup virtual machine
    let mut vm = Vm::new(&kvm, vm_mem).expect("Failed to instantiate a new VM");

    let mut regs = vm.get_initial_regs();
    regs.rip = 0x1337000;
    regs.rax = 0x1000;
    regs.rdx = 0x337;
    regs.rsp = 0x1331500;
    regs.rflags = 1 << 9; // IF
    vm.set_initial_regs(regs);
    vm.commit_registers()
        .expect("Failed to commit VM registres");

    // Run the vm
    let result = vm.run().expect("Run failed");
    println!("Exit status: {:x?}", result);
    let regs = vm.get_registers().expect("could not get registers");

    println!("Regs: {:#X?}", regs);

    // Try to load vm from snapshot
    let snapshot = Snapshot::new("/home/sideway/sources/Tartiflette/snapshot_info.json")
        .expect("could not load snapshot");
}

/// Main function
fn main() {
    // Get the program args as Vec<&str>
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_ref).collect();

    if args.len() >= 2 {
        run_snapshot(args[1].to_string());
    } else {
        run();
    }
}
