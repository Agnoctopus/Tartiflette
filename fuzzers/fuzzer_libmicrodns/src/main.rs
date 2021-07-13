extern crate libafl;

mod cli;
mod config;

use std::path::PathBuf;

use config::Config;
use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list},
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback},
    generators::RandPrintablesGenerator,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    stages::StdMutationalStage,
    state::StdState,
    stats::SimpleStats,
    Fuzzer, StdFuzzer,
};

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut COV: [u8; 16] = [0; 16];

fn main() {
    // Get the program args as Vec<&str>
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_ref).collect();

    // Parse the command line
    match cli::CLI::parse(args) {
        Ok(config) => fuzz(config),
        Err(error) => eprintln!("{}", error),
    }
}

/// Assign a signal to the signals map
fn new_cov(idx: usize) {
    unsafe { COV[idx] = 1 };
}

fn harness(buf: &[u8]) -> ExitKind {
    new_cov(0);
    if !buf.is_empty() && buf[0] == b'a' {
        new_cov(1);
        if buf.len() > 1 && buf[1] == b'b' {
            new_cov(2);
            if buf.len() > 2 && buf[2] == b'c' {
                new_cov(3);
                if buf.len() > 3 && buf[3] == b'd' {
                    new_cov(4);
                    if buf.len() > 4 && buf[4] == b'e' {
                        panic!("=)");
                    }
                }
            }
        }
    }
    ExitKind::Ok
}

fn fuzz(mut config: Config) {
    if let Err(error) = config.validate() {
        eprintln!("Failed to validate the configuration.");
        eprintln!("{}", error);
        return;
    }
    let mut harness = harness;

    // Create an observation channel using the cov map
    let observer = StdMapObserver::new("coverage", unsafe { &mut COV });

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&observer);

    // Feedback to rate the interestingness of an input
    let feedback = MaxMapFeedback::new(&feedback_state, &observer);

    // A feedback to choose if an input is a solution or not
    let objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        OnDiskCorpus::new(PathBuf::from(config.io_config.corpus_dir)).unwrap(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from(config.io_config.crash_dir)).unwrap(),
        // States of the feedbacks.
        // They are the data related to the feedbacks that you want to persist in the State.
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

    // Create the executor for an in-process function with just one observer
    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
