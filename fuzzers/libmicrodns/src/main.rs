mod executor;

use tartiflette_vm::{Vm, Register, SnapshotInfo, PagePermissions};

use libafl::inputs::{BytesInput, HasBytesVec};
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list},
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    executors::ExitKind,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    stages::mutational::StdMutationalStage,
    state::StdState,
    stats::SimpleStats,
};
use std::path::PathBuf;

use crate::executor::{TartifletteExecutor, HookResult};

/// Coverage map used by libAFL
static mut COV: [u8; 4096] = [0; 4096];
/// Current position of mmap area (bump allocator)
static mut MMAP_HEAP_PTR: u64 = 0;

fn main() {
    // Snapshot setup
    let breakpoints: &[u64] = &[
        0x2000,
        0x2020,
        0x2026,
        0x2010,
        0x2030,
        0x2040,
        0x2050,
        0x2060,
        0x2070,
        0x2080,
        0x2090,
        0x20a0,
        0x20b0,
        0x20d0,
        0x20e0,
        0x20f0,
        0x2100,
        0x2120,
        0x2130,
        0x2140,
        0x2150,
        0x2160,
        0x2170,
        0x2180,
        0x2190,
        0x21a0,
        0x21b0,
        0x21c0,
        0x21d0,
        0x21e0,
        0x21f0,
        0x2200,
        0x2210,
        0x2220,
        0x2230,
        0x2240,
        0x2250,
        0x2260,
        0x2270,
        0x2280,
        0x2290,
        0x22a0,
        0x22b0,
        0x22c0,
        0x22e0,
        0x22e8,
        0x22f0,
        0x2300,
        0x2302,
        0x2304,
        0x2306,
        0x2308,
        0x230a,
        0x230c,
        0x230e,
        0x2310,
        0x2312,
        0x2314,
        0x2316,
        0x2318,
        0x231a,
        0x231c,
        0x2320,
        0x2348,
        0x2333,
        0x233f,
        0x2350,
        0x2388,
        0x2374,
        0x2380,
        0x2390,
        0x2430,
        0x239d,
        0x23ba,
        0x23ae,
        0x2403,
        0x23e2,
        0x241e,
        0x2412,
        0x23e8,
        0x2440,
        0x2470,
        0x244a,
        0x2480,
        0x2530,
        0x2489,
        0x24d5,
        0x249c,
        0x2506,
        0x24e6,
        0x2518,
        0x24b7,
        0x24f0,
        0x24a0,
        0x2525,
        0x2540,
        0x2f2d,
        0x258a,
        0x2e10,
        0x25ad,
        0x2f3a,
        0x2e27,
        0x260f,
        0x2e47,
        0x2643,
        0x2f19,
        0x2e71,
        0x2e3d,
        0x2661,
        0x2f02,
        0x2f0f,
        0x2ea3,
        0x2684,
        0x267f,
        0x2eb0,
        0x2ebc,
        0x26a2,
        0x26ac,
        0x2f23,
        0x26cd,
        0x2ef8,
        0x26db,
        0x2ee8,
        0x2707,
        0x2730,
        0x271d,
        0x2728,
        0x2739,
        0x2d1c,
        0x2790,
        0x2747,
        0x273e,
        0x2d10,
        0x2d25,
        0x2710,
        0x279d,
        0x2759,
        0x274c,
        0x2d33,
        0x2d2a,
        0x27b0,
        0x2765,
        0x2f6a,
        0x2d45,
        0x2d38,
        0x27cf,
        0x2773,
        0x2d62,
        0x2edf,
        0x27fb,
        0x2788,
        0x2d00,
        0x2ed7,
        0x2818,
        0x2d68,
        0x2d0b,
        0x2865,
        0x284d,
        0x2858,
        0x286e,
        0x2dd0,
        0x29bf,
        0x2884,
        0x287b,
        0x29e1,
        0x2def,
        0x2848,
        0x29d2,
        0x2896,
        0x2889,
        0x2f3f,
        0x2a18,
        0x2df0,
        0x2df9,
        0x28bc,
        0x2a28,
        0x2b0d,
        0x28c7,
        0x2eca,
        0x2b3a,
        0x2d80,
        0x28d0,
        0x2c50,
        0x2d8f,
        0x28d6,
        0x2e00,
        0x2c7e,
        0x28e0,
        0x2d99,
        0x2913,
        0x2906,
        0x2ca5,
        0x2daf,
        0x2da2,
        0x2925,
        0x2918,
        0x2b50,
        0x2cd9,
        0x2dc1,
        0x2db4,
        0x2937,
        0x2948,
        0x2b9d,
        0x2b70,
        0x2901,
        0x2971,
        0x2964,
        0x2bbd,
        0x2983,
        0x2976,
        0x2c00,
        0x2995,
        0x29a6,
        0x2c3a,
        0x2f70,
        0x3068,
        0x2f91,
        0x2f9e,
        0x3050,
        0x302c,
        0x3010,
        0x303c,
        0x3080,
        0x3183,
        0x30e1,
        0x3162,
        0x3102,
        0x30f0,
        0x318a,
        0x3175,
        0x3141,
        0x3160,
        0x30f8,
        0x3150,
        0x31c8,
        0x3195,
        0x31a0,
        0x31bc,
        0x31d0,
        0x33a8,
        0x31ef,
        0x33c7,
        0x32d4,
        0x3378,
        0x3303,
        0x3362,
        0x331e,
        0x32e8,
        0x3347,
        0x3390,
        0x33d0,
        0x3448,
        0x3413,
        0x3424,
        0x344f,
        0x3437,
        0x3460,
        0x3521,
        0x34da,
        0x36b7,
        0x353d,
        0x34f0,
        0x350e,
        0x36f9,
        0x36c6,
        0x3551,
        0x36a5,
        0x3596,
        0x3580,
        0x36d5,
        0x35cc,
        0x36e3,
        0x3691,
        0x35e4,
        0x35f5,
        0x367c,
        0x35ff,
        0x35f8,
        0x3622,
        0x3618,
        0x362a,
        0x362f,
        0x364a,
        0x365d,
        0x3700,
        0x372b,
        0x3713,
        0x3718,
        0x373a,
        0x3750,
        0x3760,
        0x39c1,
        0x37ad,
        0x398a,
        0x37e6,
        0x39c8,
        0x399a,
        0x3863,
        0x37f1,
        0x387a,
        0x381b,
        0x3870,
        0x38a9,
        0x3830,
        0x38c0,
        0x39b0,
        0x38e2,
        0x3922,
        0x3980,
        0x3930,
        0x3900,
        0x3950,
        0x3969,
        0x39d0,
        0x3a2a,
        0x39d5,
        0x3a23,
        0x39ff,
        0x3a18,
        0x3a30,
        0x3a97,
        0x3a41,
        0x3aa0,
        0x3a55,
        0x3aaa,
        0x3a60,
        0x3a8d,
        0x3ab0,
        0x3ab9,
        0x3a50,
        0x3ad0,
        0x3b80,
        0x3b1b,
        0x3bd6,
        0x3b89,
        0x3b3d,
        0x3d18,
        0x3bec,
        0x3deb,
        0x3b99,
        0x3b30,
        0x3b6c,
        0x3d76,
        0x3d21,
        0x3c51,
        0x3c14,
        0x3df9,
        0x3ba0,
        0x3bcc,
        0x3d78,
        0x3e0e,
        0x3d8b,
        0x3dce,
        0x3d31,
        0x3bda,
        0x3c69,
        0x3c20,
        0x3c3e,
        0x3e00,
        0x3e09,
        0x3b90,
        0x3dd7,
        0x3d40,
        0x3d6d,
        0x3dc5,
        0x3c7c,
        0x3de0,
        0x3de9,
        0x3d28,
        0x3cf9,
        0x3db1,
        0x3c8c,
        0x3c80,
        0x3dad,
        0x3ca7,
        0x3cb2,
        0x3da0,
        0x3cbf,
        0x3cd5,
        0x3cc8,
        0x3cd9,
        0x3e20,
        0x3e40,
        0x3e60,
        0x3ec0,
        0x3e7c,
        0x3ea5,
        0x3e88,
        0x3eb6,
        0x3ee0,
        0x3f00,
        0x3f20,
        0x3f60,
        0x3f26,
        0x3f3c,
        0x3f2f,
        0x3f4e,
        0x3f41,
        0x3f70,
        0x3fb0,
        0x3f76,
        0x3f8c,
        0x3f7f,
        0x3f9e,
        0x3f91,
        0x3fc0,
        0x4028,
        0x3fc8,
        0x3fde,
        0x3fd1,
        0x4018,
        0x3fe7,
        0x401d,
        0x400b,
        0x4040,
        0x412a,
        0x4070,
        0x40fb,
        0x40da,
        0x412e,
        0x410b,
        0x4080,
        0x40f4,
        0x4092,
        0x4089,
        0x40a7,
        0x409a,
        0x40b9,
        0x40ac,
        0x4120,
        0x4140,
        0x42a0,
        0x416e,
        0x42f9,
        0x42b2,
        0x417d,
        0x42c8,
        0x4189,
        0x42a2,
        0x4214,
        0x422b,
        0x4222,
        0x4247,
        0x4256,
        0x41a0,
        0x4274,
        0x41b2,
        0x41a5,
        0x41f0,
        0x41c4,
        0x41bb,
        0x420b,
        0x4280,
        0x41ce,
        0x42d0,
        0x41d8,
        0x41dd,
        0x42e8,
        0x41ec,
        0x4300,
        0x4438,
        0x4313,
        0x4330,
        0x43af,
        0x434c,
        0x4372,
        0x4365,
        0x4385,
        0x437c,
        0x43f0,
        0x438a,
        0x43a5,
        0x4420,
        0x4392,
        0x43c8,
        0x4396,
        0x4358,
        0x43e5,
        0x4450,
        0x4460,
        0x465d,
        0x4492,
        0x4558,
        0x44a6,
        0x46a4,
        0x456c,
        0x44c6,
        0x4668,
        0x44df,
        0x4590,
        0x4509,
        0x4650,
        0x459e,
        0x451d,
        0x45cf,
        0x4580,
        0x4545,
        0x45e7,
        0x44e0,
        0x4647,
        0x4619,
        0x4680,
        0x463f,
        0x46b0,
        0x4750,
        0x46bd,
        0x4760,
        0x47d0,
        0x4768,
        0x476f,
        0x4785,
        0x4778,
        0x47c0,
        0x478e,
        0x47c5,
        0x47b5,
        0x47e0,
        0x4870,
        0x47fe,
        0x4880,
        0x4813,
        0x4825,
        0x4818,
        0x4858,
        0x482a,
        0x4862,
        0x48a0,
        0x499e,
        0x48c9,
        0x495e,
        0x4980,
        0x48d6,
        0x4927,
        0x4939,
        0x492c,
        0x4970,
        0x493e,
        0x497a,
        0x49b0,
        0x4af0,
        0x49e4,
        0x4a98,
        0x4a09,
        0x4bc5,
        0x4aac,
        0x4af8,
        0x4a21,
        0x4b10,
        0x4a4d,
        0x4ae0,
        0x4b15,
        0x4a5d,
        0x4b41,
        0x4ac0,
        0x4a85,
        0x4b5b,
        0x4a28,
        0x4ad8,
        0x4b81,
        0x4ad0,
        0x4ba1,
        0x4bd0,
        0x4d20,
        0x4bf7,
        0x4c05,
        0x4d08,
        0x4c44,
        0x4c4e,
        0x4d7e,
        0x4cbe,
        0x4d32,
        0x4d2d,
        0x4cc3,
        0x4d53,
        0x4d69,
        0x4ccc,
        0x4ce0,
        0x4d70,
        0x4cd5,
        0x4ceb,
        0x4d77,
        0x4d90,
        0x5008,
        0x4dbc,
        0x4f1d,
        0x5018,
        0x4dd5,
        0x4de7,
        0x4dda,
        0x4f30,
        0x4df0,
        0x4f3d,
        0x4e19,
        0x4f10,
        0x4e66,
        0x4e70,
        0x4ea4,
        0x4f48,
        0x4eb1,
        0x4f5f,
        0x4f7a,
        0x4ebe,
        0x4f8e,
        0x4faa,
        0x4ecb,
        0x4fbe,
        0x4fda,
        0x4ed8,
        0x4fee,
        0x4ee1,
        0x4ef9,
        0x5030,
        0x5094,
        0x5062,
        0x50e0,
        0x50ae,
        0x506e,
        0x5100,
        0x50b3,
        0x507a,
        0x50e2,
        0x5110,
        0x50b8,
        0x5086,
        0x5117,
        0x50bd,
        0x511e,
        0x50c2,
        0x5130,
        0x51d0,
        0x5139,
        0x51a0,
        0x514c,
        0x5158,
        0x51a9,
        0x5190,
        0x5152,
        0x5170,
        0x5161,
        0x51b0,
        0x51c4,
        0x5199,
        0x5180,
        0x5189,
        0x51e0,
        0x5266,
        0x51e9,
        0x5230,
        0x51fe,
        0x525f,
        0x5244,
        0x5226,
        0x5205,
        0x520a,
        0x5270,
        0x52cc,
        0x52bf,
        0x52de,
        0x52d1,
        0x52f0,
        0x5301,
        0x5347,
        0x533f,
        0x5350,
        0x5390,
        0x535d,
        0x5370,
        0x5380,
        0x5391,
    ];

    // 32Mb of memory
    const MEMORY_SIZE: usize = 32 * 1024 * 1024;
    const MMAP_HEAP_START: u64 = 0x1337000;
    const MMAP_HEAP_END: u64 = MMAP_HEAP_START + 32 * 0x1000;

    let snapshot_info = SnapshotInfo::from_file("./data/snapshot_info.json")
        .expect("crash while parsing snapshot info");
    let program_module = snapshot_info.modules.get("harness")
        .expect("Could not find program module");
    let libmicrodns_module = snapshot_info.modules.get("libmicrodns.so.1.0.0")
        .expect("Could not find libmicrodns module");
    let mut orig_vm = Vm::from_snapshot("./data/snapshot_info.json", "./data/snapshot_data.bin", MEMORY_SIZE)
        .expect("Could not load data from snapshot");

    // Alloc MMAP region
    orig_vm.mmap(MMAP_HEAP_START, (MMAP_HEAP_END - MMAP_HEAP_START) as usize,
        PagePermissions::READ | PagePermissions::WRITE | PagePermissions::EXECUTE)
        .expect("Could not allocate mmap region");


    let mut harness = |vm: &mut Vm, input: &BytesInput| {
        // Write the input to memory
        let input_ptr = vm.get_reg(Register::Rdx);
        let input_len = input.bytes().len();

        vm.write(input_ptr, input.bytes())
            .expect("Could not write to vm memory");
        vm.set_reg(Register::Rcx, input_len as u64);

        // Reset the mmap bump alloc ptr
        unsafe {
            MMAP_HEAP_PTR = MMAP_HEAP_START;
        }

        ExitKind::Ok
    };

    // libAFL setup
    let observer = StdMapObserver::new("coverage", unsafe { &mut COV });
    let feedback_state = MapFeedbackState::with_observer(&observer);
    let feedback = MaxMapFeedback::new(&feedback_state, &observer);
    let objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(),
        OnDiskCorpus::new(PathBuf::from("/tmp/crashes")).unwrap(),
        tuple_list!(feedback_state),
    );

       // The Stats trait define how the fuzzer stats are reported to the user
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(stats);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueCorpusScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Setup executor
    let mut executor = TartifletteExecutor::new(&orig_vm, tuple_list!(observer), &mut harness)
        .expect("Could not create executor");

    // Add breakpoints for coverage
    for addr in breakpoints.iter().cloned() {
        executor.add_coverage(libmicrodns_module.start + addr)
            .expect("Could not add breakpoint");
    }

    // Add end of function hook
    let mut exit_hook = |_: &mut Vm| {
        HookResult::Exit
    };

    executor.add_hook(program_module.start + 0x1192, &mut exit_hook)
        .expect("Could not install exit hook");

    // Handle syscalls
    let mut syscall_hook = |vm: &mut Vm| {
        let syscall = vm.get_reg(Register::Rax);

        match syscall {
            0xe7 => {
                // exit_group(x)
                HookResult::Exit
            },
            0x9 => {
                // mmap(...)
                let addr = vm.get_reg(Register::Rdi);
                let len = vm.get_reg(Register::Rsi);
                let prot = vm.get_reg(Register::Rdx);
                let fd = vm.get_reg(Register::R8) as i64;

                if fd != -1 {
                    panic!("mmaping from a fd is not supported");
                }

                if len & 0xfff != 0 {
                    panic!("Len is not aligned: 0x{:x}", len);
                }

                if addr != 0 {
                    panic!("Mapping to fixed address (0x{:x}), is not supported", addr);
                }

                let mmap_heap = unsafe { MMAP_HEAP_PTR };

                if mmap_heap + len > MMAP_HEAP_END {
                    panic!("mmap request too large for reserved region");
                }

                // println!("sys_mmap(addr: 0x{:x}, len: 0x{:x}, prot: 0x{:x}, fd: {}) = 0x{:x}",
                //     addr, len, prot, fd, mmap_heap);

                vm.set_reg(Register::Rax, mmap_heap);

                unsafe {
                    MMAP_HEAP_PTR += len;
                }

                HookResult::Continue
            },
            0xb => {
                // munmap
                let addr = vm.get_reg(Register::Rdi);
                let len = vm.get_reg(Register::Rsi);

                // println!("sys_munmap(addr: 0x{:x}, len: 0x{:x}) = 0", addr, len);

                vm.set_reg(Register::Rax, 0);

                HookResult::Continue
            }
            _ => panic!("Unhandled syscall 0x{:x}", syscall)
        }
    };

    executor.add_syscall_hook(&mut syscall_hook);

    // Generator of printable bytearrays of max size 64
    let mut generator = RandPrintablesGenerator::new(64);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 64)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
