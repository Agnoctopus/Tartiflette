use crate::executor::{install_alarm_handler, HookResult, TartifletteExecutor};
use crate::sysemu::SysEmu;

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::parse_core_bind_arg,
        rands::{Rand, StdRand},
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, tuple_list_type},
    },
    corpus::{Corpus, InMemoryCorpus, QueueCorpusScheduler},
    executors::ExitKind,
    feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::Input,
    inputs::{BytesInput, HasBytesVec},
    mutators::mutations::{
        ByteRandMutator, BytesExpandMutator, BytesInsertMutator, BytesSwapMutator,
        CrossoverInsertMutator, CrossoverReplaceMutator,
    },
    mutators::scheduled::StdScheduledMutator,
    observers::{StdMapObserver, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMaxSize, HasMetadata, HasRand, StdState},
    monitors::MultiMonitor,
};
use serde::Deserialize;

use std::cell::RefCell;
use std::fs::File;
use std::io::BufWriter;
use std::io::{prelude::*, BufReader, LineWriter};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use tartiflette_vm::{PagePermissions, Register, SnapshotInfo, Vm};

/// Configuration of the fuzzer
#[derive(Copy, Clone)]
pub struct FuzzerConfig<'a> {
    /// Cores configuration string
    pub cores: &'a str,
    /// Broker address
    pub broker_address: Option<&'a str>,
    /// Broker port
    pub broker_port: &'a str,
}

/// Encoded javascript tokens
#[derive(Deserialize)]
struct TokenCache {
    tokens: Vec<String>,
}

/// Coverage byte size
const COVERAGE_SIZE: usize = 1 << 15;
// TODO: Find how to have a coverage map without unsafe and static
static mut COVERAGE: [u8; COVERAGE_SIZE] = [0u8; COVERAGE_SIZE];

/// Loads breakpoints from a file
fn load_breakpoints<T: AsRef<Path>>(s: T) -> Vec<u64> {
    let bpkt_file = File::open(s).expect("Could not open breakpoint file");
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

/// Construct the list of mutator to be used for token fuzzing
fn token_mutations<C, I, R, S>() -> tuple_list_type!(
    ByteRandMutator<I, R, S>,
    BytesInsertMutator<I, R, S>,
    BytesSwapMutator<I, R, S>,
    BytesExpandMutator<I, R, S>,
    CrossoverReplaceMutator<C, I, R, S>,
    CrossoverInsertMutator<C, I, R, S>
   )
where
    I: Input + HasBytesVec,
    S: HasRand<R> + HasCorpus<C, I> + HasMetadata + HasMaxSize,
    C: Corpus<I>,
    R: Rand,
{
    tuple_list!(
        ByteRandMutator::new(),
        BytesInsertMutator::new(),
        BytesSwapMutator::new(),
        BytesExpandMutator::new(),
        CrossoverReplaceMutator::new(),
        CrossoverInsertMutator::new()
    )
}

/// Starts a fuzzing session given a `FuzzerConfig`
pub fn fuzz(config: FuzzerConfig) {
    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut mgr, _core_id| {
        // Install the SIGALRM handler
        install_alarm_handler();

        // Vm memory size, 32Mb should be enough
        const MEMORY_SIZE: usize = 32 * 1024 * 1024;

        // Load the snapshot info (contains mappings and symbols)
        let snapshot_info = SnapshotInfo::from_file("./data/snapshot_info.json")
            .expect("Crash while parsing snapshot information");
        // Get the program module info. Userful for setting breakpoint when PIE
        // is enabled
        let program_module = snapshot_info
            .modules
            .get("qjs")
            .expect("Could not find program module");

        // Load the VM state from the snapshot info + memory dump
        let mut orig_vm = Vm::from_snapshot(
            "./data/snapshot_info.json",
            "./data/snapshot_data.bin",
            MEMORY_SIZE,
        )
        .expect("Could not create vm from snapshot");

        // Reserve area for the syscall emulation layer
        const MMAP_START: u64 = 0x1337000;
        const MMAP_SIZE: u64 = 0x100000;
        const MMAP_END: u64 = MMAP_START + MMAP_SIZE;
        orig_vm
            .mmap(
                MMAP_START,
                MMAP_SIZE as usize,
                PagePermissions::READ | PagePermissions::WRITE,
            )
            .expect("Could not allocate mmap memory");

        let sysemu = Rc::new(RefCell::new(SysEmu::new(MMAP_START, MMAP_END)));

        // Reserve area for the harness input place
        const INPUT_START: u64 = 0x22000;
        const INPUT_SIZE: u64 = 0x2000;
        orig_vm
            .mmap(INPUT_START, INPUT_SIZE as usize, PagePermissions::READ)
            .expect("Could not allocate input memory");

        // Create the fuzzing harness
        let hemu = Rc::clone(&sysemu);

        // Setup the decoding objects
        let tokens_str = std::fs::read_to_string("./data/tokens.json").unwrap();
        let token_cache: TokenCache = serde_json::from_str(&tokens_str).unwrap();

        let mut harness = move |vm: &mut Vm, input: &BytesInput| {
            // Reset the emulaton layer state
            let mut emu = hemu.borrow_mut();
            emu.reset();

            // Decode the encoded input to text javascript
            let mut input_buffer = [0u8; (INPUT_SIZE - 1) as usize];
            let mut token_writer =
                BufWriter::with_capacity(INPUT_SIZE as usize - 1, input_buffer.as_mut());

            // TODO: Use a BytesInput of u16 instead of u8
            // Loop through chunk of u16 inside the libafl input
            for chunk in input.bytes().chunks_exact(2) {
                // Compute token index
                let token_index: u16 = chunk[0] as u16 | ((chunk[1] as u16) << 8);

                // Get the token str representation
                let token_str =
                    &token_cache.tokens[token_index as usize % token_cache.tokens.len()];

                // Make sure to not overfeed the input buffer
                if token_writer.buffer().len() + token_str.len() + 1 > token_writer.capacity() {
                    break;
                }

                // Write token to memory
                token_writer.write(token_str.as_bytes()).unwrap();
            }

            // Null terminate the fuzz case
            token_writer.write(&[0u8; 1]).unwrap();

            // Set vm registers
            let js_input = token_writer.buffer();
            vm.set_reg(Register::Rsi, INPUT_START);
            vm.set_reg(Register::Rdx, js_input.len() as u64 - 1);

            // Write the fuzz case to the vm memory
            vm.write(INPUT_START, &js_input)
                .expect("Could not write fuzz case to vm memory");

            ExitKind::Ok
        };

        // Setup LibAFL
        // Create an observation channel using the coverage map
        let cov = unsafe { &mut COVERAGE };
        let cov_observer = StdMapObserver::new("coverage", cov);
        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // The state of the coverage feedback
        let feedback_state = MapFeedbackState::with_observer(&cov_observer);

        // Feedback to rate the interestingness of an input
        let feedback = feedback_or!(
            MaxMapFeedback::new(&feedback_state, &cov_observer),
            TimeFeedback::new_with_observer(&time_observer)
        );

        // Feedback to choose if an input is a solution or not
        let objective = CrashFeedback::new();

        // The fuzzer's state, create a State from scratch if restarting
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // First argument is the randomness sources
                StdRand::with_seed(current_nanos()),
                // Second argument is the corpus
                InMemoryCorpus::new(),
                // Third argument is the solutions corpus (here crashes)
                InMemoryCorpus::new(),
                // Fourth argument is the feedback states, used to evaluate the input
                tuple_list!(feedback_state),
            )
        });

        // Setting up the fuzzer
        // The corpus fuzz case scheduling policy
        let corpus_scheduler = QueueCorpusScheduler::new();
        // The fuzzer itself
        let mut fuzzer = StdFuzzer::new(corpus_scheduler, feedback, objective);

        // Setup the executor and related hooks
        let mut executor = TartifletteExecutor::new(
            &orig_vm,
            Duration::from_millis(1000),
            tuple_list!(cov_observer, time_observer),
            &mut harness,
        )
        .expect("Could not create executor");

        // Exit hook to end the fuzz case when the guest calls exit(...)
        let mut exit_hook = |_: &mut Vm| HookResult::Exit;
        executor
            .add_hook(program_module.start + 0x1768e, &mut exit_hook)
            .expect("Could not install exit hook");

        // Install syscall hook
        let semu = Rc::clone(&sysemu);
        let mut syscall_hook = move |vm: &mut Vm| {
            // Get the syscall emulation layer
            let mut emu = semu.borrow_mut();

            // Emulate the syscall
            match emu.syscall(vm) {
                true => HookResult::Continue,
                false => HookResult::Exit,
            }
        };
        executor.add_syscall_hook(&mut syscall_hook);

        // Load coverage breakponts
        let breakpoints = load_breakpoints("./data/breakpoints.txt");
        for bkpt in &breakpoints {
            executor
                .add_coverage(program_module.start + bkpt)
                .expect("Error while adding breakpoint");
        }

        println!("Added {} coverage breakpoints", breakpoints.len());

        // Setup a coverage hook to output coverage for lightouse
        let cov_file = File::create("cov.txt").expect("Could not create coverage file");
        let mut cov_file = LineWriter::new(cov_file);
        let mod_base = program_module.start;

        let mut coverage_hook = move |addr| {
            let offset = addr - mod_base;
            write!(cov_file, "qjs+0x{:x}\n", offset).expect("Could not write to file");
        };
        executor.add_coverage_hook(&mut coverage_hook);

        // Load initial inputs
        let corpus_folders = &[PathBuf::from("./data/corpus")];
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, corpus_folders)
            .expect("Could not load corpus files");

        // Setup a mutator with a mutational stage
        let mutator = StdScheduledMutator::new(token_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        // Fuzz
        fuzzer
            .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
            .expect("Error in the fuzzing loop");

        Ok(())
    };

    // Launcher setup
    // List of cores on which to run the fuzzer, use "all" to run on all cores
    let cores = parse_core_bind_arg(config.cores).unwrap();
    // Port on which the broker will listen
    let port = config.broker_port.parse::<u16>().unwrap();
    // Address on which the broker is, None if it is local
    let address = config
        .broker_address
        .map_or(None, |a| Some(a.parse::<SocketAddr>().unwrap()));
    // Implementation of stats when in a multithreading context
    let monitor = MultiMonitor::new(|s| println!("{}", s));
    // Provider for shared memory. Used by llmp for ipc
    let shmem_provider = StdShMemProvider::new().unwrap();

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(port)
        .remote_broker_addr(address)
        .configuration("default".into())
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}
