//! App state

use std::intrinsics::transmute;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use chrono::{DateTime, Local};
use kvm_ioctls::Kvm;
use memory::PagePermissions;
use snapshot::Snapshot;
use tartiflette::vm::Vm;

use crate::config::Config;
use crate::corpus::{Corpus, FuzzCov};
use crate::dico::Dico;
use crate::feedback::FeedBack;
use crate::input::Input;

/// Perfoming mode of the application
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Mode {
    Unset = 0,
    Static,
    DynamicDryRun,
    DynamicMain,
    DynamicMinimize,
}

/// App structure containing all application state
#[derive(Debug)]
pub struct App {
    /// Global configuration
    pub config: Config,

    /// Performing mode, atomic `Mode`
    pub mode: AtomicUsize,
    /// Terminiated elasped from the start instant
    pub terminated_elapsed: AtomicUsize,

    /// Metrics
    pub metrics: Metrics,
    /// Input
    pub input: Input,
    /// Corpus
    pub corpus: Mutex<Corpus>,
    /// FeedBack
    pub feedback: Mutex<FeedBack>,
    /// Executable
    pub exe: Mutex<Exe>,

    /// Next filename to be used as fuzz input
    pub current_file: Mutex<Option<String>>,
    /// Szitching mode in transition
    pub switching_feedback: AtomicBool,
    /// Max coverage value
    pub max_cov: Mutex<FuzzCov>,
    /// Mutation dictionnary
    pub dico: Mutex<Dico>,
}

impl App {
    /// Create a new `App` instance
    pub fn new(mut config: Config, mode: Mode) -> Self {
        let exe = Exe::new(&config);
        let input = Input::new(&config).expect("Failed to create the input manager.");
        config.app_config.max_input_size = input.max_entries_size();

        Self {
            config: config,

            mode: AtomicUsize::new(mode as usize),
            terminated_elapsed: AtomicUsize::new(0),

            metrics: Metrics::new(),
            input: input,
            corpus: Mutex::new(Corpus::new()),
            feedback: Mutex::new(FeedBack::new()),
            exe: Mutex::new(exe),

            current_file: Mutex::new(None),
            switching_feedback: AtomicBool::new(false),
            max_cov: Mutex::new(FuzzCov::default()),
            dico: Mutex::new(Dico::new()),
        }
    }

    /// Get the `Mode`
    #[inline]
    pub fn get_mode(&self) -> Mode {
        unsafe { transmute::<usize, Mode>(self.mode.load(Ordering::Relaxed)) }
    }

    /// Set the `Mode`
    #[inline]
    pub fn set_mode(&self, mode: Mode) {
        self.mode.store(mode as usize, Ordering::Relaxed);
    }

    /// Returns whether or not the application is termintating
    #[inline]
    pub fn is_terminating(&self) -> bool {
        self.terminated_elapsed.load(Ordering::Relaxed) > 0
    }

    /// Set the terminating state in `elapsed` time
    #[inline]
    pub fn set_terminating_to(&self, elapsed: usize) {
        self.terminated_elapsed
            .compare_exchange(0, elapsed, Ordering::Relaxed, Ordering::Relaxed)
            .unwrap();
    }

    /// Set the terminating state to now
    #[inline]
    pub fn set_terminating(&self) {
        self.terminated_elapsed.store(
            self.metrics.start_instant.elapsed().as_secs() as usize,
            Ordering::Relaxed,
        );
    }

    /// Returns whether or not we should terminate now
    #[inline]
    pub fn should_terminate(&self) -> bool {
        let elapsed = self.terminated_elapsed.load(Ordering::Relaxed);
        self.metrics.start_instant.elapsed().as_secs() as usize > elapsed
    }

    /// Get random bytes from the app corpus
    pub fn get_random_bytes(&self) -> Vec<u8> {
        let corpus = self.corpus.lock().unwrap();
        let mut current_file = self.current_file.lock().unwrap();

        let mut files = match *current_file {
            Some(ref path) => corpus.iter_from(path),
            None => corpus.iter(),
        };

        let file = files.next().unwrap();
        *current_file = files.next().map(|file| file.filename.clone());

        return file.data[..file.data.len()].to_vec();
    }
}

/// Application fuzzing executable
pub struct Exe {
    // Pure executable
    /// Executable binary data
    pub bin_data: Option<Vec<u8>>,

    // Snapshot
    /// KVM handle
    pub kvm: Option<Kvm>,
    /// Root vm
    pub vm: Option<Vm>,
    /// Snapshot
    pub snapshot: Option<Snapshot>,
}

unsafe impl Send for Exe {}

impl Exe {
    /// Create a new instance of `Exe`
    pub fn new(config: &Config) -> Self {
        let mut exe = Self {
            bin_data: None,

            kvm: None,
            vm: None,
            snapshot: None,
        };

        if config.exe_config.snapshot.is_some() {
            // Instantiate KVM
            let kvm = Kvm::new().expect("Failed to instantiate KVM");
            assert!(kvm.get_api_version() >= 12);

            let mut snapshot = Snapshot::new(config.exe_config.snapshot.as_ref().unwrap())
                .expect("Snapshot loading failed");
            let snapshot_size = snapshot.size();
            let mut vm =
                Vm::from_snapshot(&kvm, &mut snapshot, snapshot_size * 2).expect("vm failed");
            vm.add_exit_point(0x555555555267).unwrap();
            vm.memory
                .mmap(0x80_000, 0x1000, memory::PagePermissions::READ)
                .unwrap();
            let mut regs = vm.get_initial_regs();
            regs.rdi = 0x80_000;
            vm.set_initial_regs(regs);

            exe.kvm = Some(kvm);
            exe.snapshot = Some(snapshot);
            exe.vm = Some(vm);
        } else {
            let exe_path = std::path::Path::new(&config.exe_config.cmdline.as_ref().unwrap()[0]);
            let exe_data = std::fs::read(exe_path).unwrap();
            exe.bin_data = Some(exe_data);
        }

        exe
    }
}

impl core::fmt::Debug for Exe {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_tuple("Exe").finish()
    }
}

/// Application metrics
#[derive(Debug)]
pub struct Metrics {
    /// Start datetime
    pub start_datatime: DateTime<Local>,
    /// Start instant
    pub start_instant: Instant,

    /// Number of active jobs
    pub job_active_count: AtomicUsize,
    /// Number of job finished
    pub job_finished_count: AtomicUsize,

    /// Number of mutations performed
    pub mutations_count: AtomicUsize,
    /// Number of crashs
    pub crashes_count: AtomicUsize,
    /// Number of tested files
    pub tested_file_count: AtomicUsize,
    /// Number of fuzz cases run
    pub fuzz_case_count: AtomicUsize,

    /// Number of fuzz input
    pub fuzz_input_count: AtomicUsize,
    /// Max size of a fuzz input
    pub fuzz_input_max_size: Mutex<usize>,

    /// Last cov update time
    pub last_cov_update: AtomicUsize,
    /// Number of new units added
    pub new_units_added: AtomicUsize,

    /// Max time spent on a fuzz run
    pub max_fuzz_run_time_ms: Mutex<usize>,
}

impl Metrics {
    /// Create a new `Metrics` instance
    pub fn new() -> Self {
        Self {
            start_datatime: Local::now(),
            start_instant: Instant::now(),

            job_active_count: AtomicUsize::new(0),
            job_finished_count: AtomicUsize::new(0),

            mutations_count: AtomicUsize::new(0),
            crashes_count: AtomicUsize::new(0),
            tested_file_count: AtomicUsize::new(0),
            fuzz_case_count: AtomicUsize::new(0),

            fuzz_input_count: AtomicUsize::new(0),
            fuzz_input_max_size: Mutex::new(0),

            last_cov_update: AtomicUsize::new(0),
            new_units_added: AtomicUsize::new(0),

            max_fuzz_run_time_ms: Mutex::new(0),
        }
    }
}
