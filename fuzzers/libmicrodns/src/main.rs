mod executor;

use tartiflette_vm::{Vm, Register, SnapshotInfo};

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

static mut COV: [u8; 4096] = [0; 4096];

fn main() {
    // Snapshot setup
    let breakpoints: &[u64] = &[
        0x1200, 0x1213, 0x1229, 0x123c,
        0x1252, 0x1265, 0x127b, 0x128e,
        0x129d, 0x12ac, 0x12be, 0x12d0,
        0x12df, 0x12ea, 0x12fc, 0x130b,
        0x11fa
    ];

    // 10Mb of memory
    const MEMORY_SIZE: usize = 0x1000 * 0x1000 * 10;

    let snapshot_info = SnapshotInfo::from_file("./data/snapshot_info.json")
        .expect("crash while parsing snapshot info");
    let program_module = snapshot_info.modules.get("prog")
        .expect("Could not find program module");
    let orig_vm = Vm::from_snapshot("./data/snapshot_info.json", "./data/snapshot_data.bin", MEMORY_SIZE)
        .expect("Could not load data from snapshot");

    let mut harness = |vm: &mut Vm, input: &BytesInput| {
        // Write the input to memory
        let rdi = vm.get_reg(Register::Rdi);

        vm.write(rdi, input.bytes())
            .expect("Could not write to vm memory");

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
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
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

    // Add breakpoints
    for addr in breakpoints.iter().cloned() {
        executor.add_coverage(program_module.start + addr)
            .expect("Could not add breakpoint");
    }

    // Add end of function hook
    let mut exit_hook = |_: &mut Vm| {
        HookResult::Exit
    };

    executor.add_hook(program_module.start + 0x131a, &mut exit_hook)
        .expect("Could not install exit hook");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(16);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 32)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
