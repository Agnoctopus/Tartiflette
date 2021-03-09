//! App state

use std::intrinsics::transmute;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use chrono::{DateTime, Local};

use crate::config::Config;
use crate::corpus::{Corpus, FuzzCov};
use crate::dico::Dico;
use crate::feedback::FeedBack;

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
    /// Corpus
    pub corpus: Mutex<Corpus>,
    /// FeedBack
    pub feedback: Mutex<FeedBack>,

    /// Next filename to be used as fuzz input
    pub current_file: Mutex<Option<String>>,
    /// Executable binary data
    pub exe_data: Option<Vec<u8>>,
    /// Szitching mode in transition
    pub switching_feedback: AtomicBool,
    /// Max coverage value
    pub max_cov: Mutex<FuzzCov>,
    /// Mutation dictionnary
    pub dico: Mutex<Dico>,
}
/*
let app = Arc::new(App {
    mutex: Mutex::new(()),
    feedback_maps: Mutex::new(Vec::new()),
});
*/

impl App {
    /// Create a new `App` instance
    pub fn new(config: Config, mode: Mode) -> Self {
        Self {
            config: config,

            mode: AtomicUsize::new(mode as usize),
            terminated_elapsed: AtomicUsize::new(0),

            metrics: Metrics::new(),
            corpus: Mutex::new(Corpus::new()),
            feedback: Mutex::new(FeedBack::new()),

            current_file: Mutex::new(None),
            exe_data: None,
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
            .compare_exchange(0, elapsed, Ordering::Relaxed, Ordering::Relaxed);
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
    /// Number of mutations performed
    pub mutations_count: AtomicUsize,
    /// Number of crashs
    pub crashes_count: AtomicUsize,
    /// Number of tested files
    pub tested_file_count: AtomicUsize,

    /// Number of fuzz input
    pub fuzz_input_count: AtomicUsize,
    /// Max size of a fuzz input
    pub fuzz_input_max_size: Mutex<usize>,

    /// Last cov update time
    pub last_cov_update: AtomicUsize,
    /// Number of new units added
    pub new_units_added: AtomicUsize,
}

impl Metrics {
    /// Create a new `Metrics` instance
    pub fn new() -> Self {
        Self {
            start_datatime: Local::now(),
            start_instant: Instant::now(),

            job_active_count: AtomicUsize::new(0),
            mutations_count: AtomicUsize::new(0),
            crashes_count: AtomicUsize::new(0),
            tested_file_count: AtomicUsize::new(0),

            fuzz_input_count: AtomicUsize::new(0),
            fuzz_input_max_size: Mutex::new(0),

            last_cov_update: AtomicUsize::new(0),
            new_units_added: AtomicUsize::new(0),
        }
    }
}
