use tartiflette_vm::{Vm, Register, SnapshotInfo, PagePermissions};
use libafl::{
    feedback_or,
    bolts::{
        current_nanos,
        tuples::tuple_list,
        launcher::Launcher,
        os::parse_core_bind_arg,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider}
    },
    corpus::{InMemoryCorpus, OnDiskCorpus, QueueCorpusScheduler},
    inputs::{BytesInput, HasBytesVec},
    executors::{TimeoutExecutor, ExitKind},
    state::StdState,
    fuzzer::{Fuzzer, StdFuzzer},
    observers::{StdMapObserver, TimeObserver},
    feedbacks::{MapFeedbackState, MaxMapFeedback, CrashFeedback, TimeFeedback},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    stages::mutational::StdMutationalStage,
    stats::MultiStats
};
use serde::Deserialize;
use crate::executor::{TartifletteExecutor, HookResult, install_alarm_handler};
use crate::sysemu::SysEmu;
use std::io::BufWriter;
use std::cell::RefCell;
use std::path::{PathBuf, Path};
use std::rc::Rc;
use std::fs::File;
use std::time::Duration;
use std::io::{
    prelude::*,
    BufReader,
    LineWriter
};
use std::net::SocketAddr;

/// Configuration of the fuzzer
#[derive(Copy, Clone)]
pub struct FuzzerConfig<'a> {
    pub cores: &'a str,
    pub broker_address: Option<&'a str>,
    pub broker_port: &'a str
}

/// Encoded javascript tokens
#[derive(Deserialize)]
struct TokenCache {
    tokens: Vec<String>
}

// TODO: Find how to have a coverage map without unsafe and static
static mut COVERAGE: [u8; 1 << 15] = [0u8; 1 << 15];

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
pub fn fuzz(config: FuzzerConfig) {
    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut mgr| {
        // XXX: Install the SIGALRM handler
        install_alarm_handler();

        // Vm memory size, 32Mb should be enough
        const MEMORY_SIZE: usize = 32 * 1024 * 1024;

        // Load the snapshot info (contains mappings and symbols)
        let snapshot_info = SnapshotInfo::from_file("./data/snapshot_info.json")
            .expect("Crash while parsing snapshot information");
        // Get the program module info. Userful for setting breakpoint when PIE
        // is enabled
        let program_module = snapshot_info.modules.get("qjs")
            .expect("Could not find program module");


        // Load the VM state from the snapshot info + memory dump
        let mut orig_vm = Vm::from_snapshot(
            "./data/snapshot_info.json",
            "./data/snapshot_data.bin",
            MEMORY_SIZE
        )
        .expect("Could not create vm from snapshot");

        // Reserve area for the syscall emulation layer
        const MMAP_START: u64 = 0x1337000;
        const MMAP_SIZE: u64 = 0x100000;
        const MMAP_END: u64 = MMAP_START + MMAP_SIZE;
        orig_vm.mmap(MMAP_START, MMAP_SIZE as usize, PagePermissions::READ | PagePermissions::WRITE)
            .expect("Could not allocate mmap memory");

        let sysemu = Rc::new(RefCell::new(SysEmu::new(MMAP_START, MMAP_END)));

        // Reserve area for the harness input place
        const INPUT_START: u64 = 0x22000;
        const INPUT_SIZE: u64 = 0x2000;
        orig_vm.mmap(INPUT_START, INPUT_SIZE as usize, PagePermissions::READ)
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
            let mut token_writer = BufWriter::new(&mut input_buffer[..]);

            // TODO: Use a BytesInput of u16 instead of u8
            for chunk in input.bytes().chunks_exact(2) {
                // Compute token index
                let token_index: u16 = chunk[0] as u16 | ((chunk[1] as u16) << 8);

                // Get the token str representation
                let token_str = &token_cache.tokens[token_index as usize % token_cache.tokens.len()];

                // Write token to memory
                token_writer.write(token_str.as_bytes())
                            .expect("Failed to write token");
            }

            // Set Vm registers
            let js_input = token_writer.buffer();

            // TODO: Investigate why the buffer returned by the BufWriter is sometimes bigger than
            //       its backing array.
            if (js_input.len() > (INPUT_START - 1) as usize) {
                return ExitKind::Ok;
            }

            vm.set_reg(Register::Rsi, INPUT_START);
            vm.set_reg(Register::Rdx, js_input.len() as u64);

            // Write the fuzz case to the vm memory
            vm.write(INPUT_START, js_input)
                .expect("Could not write fuzz case to vm memory");

            ExitKind::Ok
        };

        // Setup LibAFL
        let cov_observer = StdMapObserver::new("coverage", unsafe { &mut COVERAGE });
        let time_observer = TimeObserver::new("time");

        let feedback_state = MapFeedbackState::with_observer(&cov_observer);
        let feedback = feedback_or!(
            MaxMapFeedback::new(&feedback_state, &cov_observer),
            TimeFeedback::new_with_observer(&time_observer)
        );
        let objective = CrashFeedback::new();

        // The fuzzer's state
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
            &mut harness
        ).expect("Could not create executor");

        // Exit hook to end the fuzz case when the guest calls exit(...)
        let mut exit_hook = |_: &mut Vm| {
            HookResult::Exit
        };

        executor.add_hook(program_module.start + 0x1768e, &mut exit_hook)
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
            write!(cov_file, "qjs+0x{:x}\n", offset)
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
    let cores = parse_core_bind_arg(config.cores).unwrap();
    // Port on which the broker will listen
    let port = config.broker_port.parse::<u16>().unwrap();
    // Address on which the broker is, None if it is local
    let address = config.broker_address.map_or(None, |a| Some(a.parse::<SocketAddr>().unwrap()));
    // Implementation of stats when in a multithreading context
    let stats = MultiStats::new(|s| println!("{}", s));
    // Provider for shared memory. Used by llmp for ipc
    let shmem_provider = StdShMemProvider::new().unwrap();

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .stats(stats)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(port)
        .remote_broker_addr(address)
        .configuration("default".into())
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(err) => panic!("failed to run launcher: {:?}", err)
    }
}
