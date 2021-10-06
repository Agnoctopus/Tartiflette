mod executor;
mod sysemu;

use tartiflette_vm::{Vm, SnapshotInfo, PagePermissions};
use libafl::{
    bolts::{
        current_nanos,
        tuples::tuple_list,
        launcher::Launcher,
        os::parse_core_bind_arg,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider}
    },
    corpus::{InMemoryCorpus, QueueCorpusScheduler},
    inputs::{BytesInput, HasBytesVec},
    executors::ExitKind,
    state::StdState,
    fuzzer::{Fuzzer, StdFuzzer},
    observers::StdMapObserver,
    feedbacks::{MapFeedbackState, MaxMapFeedback, CrashFeedback},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    stages::mutational::StdMutationalStage,
    stats::MultiStats
};
use crate::executor::{TartifletteExecutor, HookResult};
use crate::sysemu::SysEmu;
use std::cmp;
use std::cell::RefCell;
use std::path::{PathBuf, Path};
use std::rc::Rc;
use std::fs::File;
use std::io::{
    prelude::*,
    BufReader,
    LineWriter
};

// TODO: Find how to have a coverage map without unsafe and static
static mut COVERAGE: [u8; 8192] = [0; 8192];

/// Loads breakpoints from a file
fn load_breakpoints<T: AsRef<Path>>(s: T) -> Vec<u64> {
    let bpkt_file = File::open(s)
        .expect("Could not open breakpoint file");
    let reader = BufReader::new(bpkt_file);
    let mut result = Vec::new();

    for line in reader.lines() {
        let l = line.expect("Got error while reading line in breakpoint file");

        if l.starts_with("0x") {
            result.push(u64::from_str_radix(l.trim_start_matches("0x"), 16).unwrap());
        }
    }

    result
}

// Starts a fuzzing run
fn main() {

    let mut run_client = |_: Option<StdState<_, _, _, _, _>>, mut mgr| {
        // Vm setup
        const MEMORY_SIZE: usize = 32 * 1024 * 1024; // 32Mb should be enough
        const FUZZ_INPUT_OFFSET: u64 = 0x8120;
        const FUZZ_INPUT_SIZE: usize = 1 << 16; // Keep in sync with the C code

        // Load the snapshot info (contains mappings and symbols)
        let snapshot_info = SnapshotInfo::from_file("./data/snapshot_info.json")
            .expect("Crash while parsing snapshot information");
        // Get the program module info. Userful for setting breakpoint when PIE
        // is enabled
        let program_module = snapshot_info.modules.get("giftext_fuzz")
            .expect("Could not find program module");
        // Load the VM state from the snapshot info + memory dump
        let mut orig_vm = Vm::from_snapshot(
            "./data/snapshot_info.json",
            "./data/snapshot_data.bin",
            MEMORY_SIZE
        )
        .expect("Could not create vm from snapshot");

        // Disabling *printf, puts and putchar by replacing plt jumps with ret
        let disabled_printf = vec![0x1030, 0x1040, 0x1060, 0x1080, 0x10b0, 0x1140];

        for off in disabled_printf.iter() {
            orig_vm.write(program_module.start + off, &[0xc3])
                .expect("Could not patch out import");
        }

        // mmap reserve area as well as the syscall emulation layer
        const MMAP_START: u64 = 0x1337000;
        const MMAP_SIZE: u64 = 0x100000;
        const MMAP_END: u64 = MMAP_START + MMAP_SIZE;

        orig_vm.mmap(MMAP_START, MMAP_SIZE as usize, PagePermissions::READ | PagePermissions::WRITE)
            .expect("Could not allocate mmap memory");

        let sysemu = Rc::new(RefCell::new(SysEmu::new(MMAP_START, MMAP_END)));

        // Create the fuzzing harness
        let hemu = Rc::clone(&sysemu);

        let mut harness = move |vm: &mut Vm, input: &BytesInput| {
            // Reset the emulaton layer state
            let mut emu = hemu.borrow_mut();
            emu.reset();

            let input_ptr = program_module.start + FUZZ_INPUT_OFFSET;
            let input_len = cmp::min(FUZZ_INPUT_SIZE, input.bytes().len());

            // Write the fuzz case to the vm memory
            vm.write(input_ptr, &input.bytes()[..input_len])
                .expect("Could not write fuzz case to vm memory");

            ExitKind::Ok
        };

        // Setup libAFL
        let observer = StdMapObserver::new("coverage", unsafe { &mut COVERAGE });
        let feedback_state = MapFeedbackState::with_observer(&observer);
        let feedback = MaxMapFeedback::new(&feedback_state, &observer);
        let objective = CrashFeedback::new();

        // The fuzzer's state
        let mut state = StdState::new(
            // First argument is the randomness sources
            StdRand::with_seed(current_nanos()),
            // Second argument is the corpus
            InMemoryCorpus::new(),
            // Third argument is the solutions corpus (here crashes)
            InMemoryCorpus::new(),
            // Fourth argument is the feedback states, used to evaluate the input
            tuple_list!(feedback_state)
        );

        // Setting up the fuzzer
        // The corpus fuzz case scheduling policy
        let corpus_scheduler = QueueCorpusScheduler::new();
        // The fuzzer itself
        let mut fuzzer = StdFuzzer::new(corpus_scheduler, feedback, objective);

        // Setup the executor and related hooks
        let mut executor = TartifletteExecutor::new(&orig_vm, tuple_list!(observer), &mut harness)
            .expect("Could not create executor");

        // Exit hook to end the fuzz case when the guest calls exit(...)
        let mut exit_hook = |_: &mut Vm| {
            HookResult::Exit
        };

        executor.add_hook(program_module.start + 0x1110, &mut exit_hook)
            .expect("Could not install exit hook");

        // Install syscall hook
        let semu = Rc::clone(&sysemu);

        let mut syscall_hook = move |vm: &mut Vm| {
            let mut emu = semu.borrow_mut();

            if emu.syscall(vm) {
                HookResult::Continue
            } else {
                HookResult::Exit
            }
        };

        executor.add_syscall_hook(&mut syscall_hook);

        // Load coverage breakponts
        let breakpoints = load_breakpoints("./data/breakpoints.txt");

        for bkpt in &breakpoints {
            executor.add_coverage(program_module.start + bkpt)
                .expect("Error while adding breakpoint");
        }

        println!("Added {} coverage breakpoints", breakpoints.len());

        // Collect coverage for lighthouse
        let cov_file = File::create("cov.txt")
            .expect("Could not create coverage file");
        let mut cov_file = LineWriter::new(cov_file);
        let mod_base = program_module.start;

        let mut coverage_hook = move |addr| {
            let offset = addr - mod_base;
            write!(cov_file, "giftext_fuzz+0x{:x}\n", offset)
                .expect("Could not write to file");
        };

        executor.add_coverage_hook(&mut coverage_hook);

        // Load initial inputs
        let corpus_folders = &[PathBuf::from("./data/corpus")];

        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, corpus_folders)
            .expect("Could not load corpus files");

        // Setup mutation stages
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        // Fuzz
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");

        Ok(())
    };

    // Launcher setup
    // List of cores on which to run the fuzzer, use "all" to run on all cores
    let cores = parse_core_bind_arg("1").unwrap();
    // Implementation of stats when in a multithreading context
    let stats = MultiStats::new(|s| println!("{}", s));
    // Provider for shared memory. Used by llmp for ipc
    let shmem_provider = StdShMemProvider::new().unwrap();

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .stats(stats)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(1337)
        .configuration("default".into())
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(err) => panic!("failed to run launcher: {:?}", err)
    }
}
