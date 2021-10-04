mod executor;

use tartiflette_vm::{Vm, Register, SnapshotInfo, PagePermissions};
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
    fuzzer::StdFuzzer,
    observers::StdMapObserver,
    feedbacks::{MapFeedbackState, MaxMapFeedback, CrashFeedback},
    stats::MultiStats
};
use crate::executor::{TartifletteExecutor, HookResult};
use std::cmp;

// Starts a fuzzing run
fn main() {
    let mut run_client = |_: Option<StdState<_, _, _, _, _>>, mut mgr| {
        // Vm setup
        const MEMORY_SIZE: usize = 16 * 1024 * 1024; // 16Mb should be enough
        const FUZZ_INPUT_OFFSET: u64 = 0x8120;
        const FUZZ_INPUT_SIZE: usize = 1 << 16; // Keep in sync with the C code
        const END_RIP: u64 = 0x1436;

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

        // Create the fuzzing harness
        let mut harness = |vm: &mut Vm, input: &BytesInput| {
            let input_ptr = program_module.start + FUZZ_INPUT_OFFSET;
            let input_len = cmp::min(FUZZ_INPUT_SIZE, input.bytes().len());

            // Write the fuzz case to the vm memory
            vm.write(input_ptr, &input.bytes()[..input_len])
                .expect("Could not write fuzz case to vm memory");

            ExitKind::Ok
        };

        // Setup libAFL
        let mut coverage: [u8; 8192] = [0; 8192];

        let observer = StdMapObserver::new("coverage", &mut coverage);
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
        executor.add_hook(program_module.start + 0x1110, &mut |_: &mut Vm| {
            HookResult::Exit
        })
        .expect("Could not install exit hook");

        // TODO: Rest of the owl

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
