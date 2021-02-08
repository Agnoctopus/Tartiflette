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

use kvm_ioctls::VcpuExit;
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
    // 1. Instantiate KVM.
    let kvm = Kvm::new().expect("Failed to instantiate KVM");

    // 2. Create a VM.
    let vm = kvm.create_vm().expect("Failed to create a VM");

    // 3. Initialize Guest Memory.
    let load_addr: *mut u8 = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            MEM_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
    };

    // When initializing the guest memory slot specify the
    // KVM_MEM_LOG_DIRTY_PAGES` to enable the dirty log.
    let slot = 0;
    let mem_region = kvm_bindings::kvm_userspace_memory_region {
        slot,
        guest_phys_addr: GUEST_ADDRESS as u64,
        memory_size: MEM_SIZE as u64,
        userspace_addr: load_addr as u64,
        flags: kvm_bindings::KVM_MEM_LOG_DIRTY_PAGES,
    };
    unsafe { vm.set_user_memory_region(mem_region).unwrap() };

    // Write the code in the guest memory. This will generate a dirty page.
    unsafe {
        let slice = core::slice::from_raw_parts_mut(load_addr, MEM_SIZE);
        slice[..ASM_BYTES.len()].copy_from_slice(&ASM_BYTES);
    }

    // 4. Create one vCPU.
    let vcpu_fd = vm.create_vcpu(0).unwrap();

    // 5. Initialize general purpose and special registers.
    // x86_64 specific registry setup.
    let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
    vcpu_sregs.cs.base = 0;
    vcpu_sregs.cs.selector = 0;
    vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

    let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
    vcpu_regs.rip = GUEST_ADDRESS as u64;
    vcpu_regs.rflags = 2;
    vcpu_fd.set_regs(&vcpu_regs).unwrap();

    // 6. Run code on the vCPU.
    loop {
        match vcpu_fd.run().expect("run failed") {
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
                // The code snippet dirties 1 page when it is loaded in memory
                let dirty_pages_bitmap = vm.get_dirty_log(slot, MEM_SIZE).unwrap();
                let dirty_pages = dirty_pages_bitmap
                    .into_iter()
                    .map(|page| page.count_ones())
                    .fold(0, |dirty_page_count, i| dirty_page_count + i);
                assert_eq!(dirty_pages, 1);
            }
            VcpuExit::Hlt => {
                break;
            }
            r => panic!("Unexpected exit reason: {:?}", r),
        }
    }
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
