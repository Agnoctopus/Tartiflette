//! Fuzz

use crate::random::Rand;
use crate::{config::Config, input::input_get_entries};
use crate::{input::INPUT_MIN_SIZE, mangle};
use core::{num, panic};
use mangle::mangle_content;
use md5;
use std::{
    cmp,
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    hint::spin_loop,
    path::PathBuf,
    sync::atomic::AtomicBool,
    thread,
};
use std::{intrinsics::transmute, sync::Arc};
use std::{io::Read, sync::Mutex};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use bits::BitField;
use chrono::{DateTime, Local};
use thread::sleep;

const ASAN_COMMON_FLAGS: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=0:handle_segv=2:handle_sigbus=2:handle_abort=2:handle_sigill=2:handle_sigfpe=2:abort_on_error=1:log_path=/tmp/here";
const MASAN_COMMON_FLAGS: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=0:handle_segv=2:handle_sigbus=2:handle_abort=2:handle_sigill=2:handle_sigfpe=2:abort_on_error=1:wrap_signals=0:print_stats=1:log_path=/tmp/here";
const kSAN_REGULAR: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=1:handle_segv=0:handle_sigbus=0:handle_abort=0:handle_sigill=0:handle_sigfpe=0:abort_on_error=1";

#[derive(Debug)]
pub struct Corpus {
    files: Vec<FuzzFile>,
    filenames: BTreeMap<String, FuzzCov>,
}

#[derive(Debug)]
pub struct Dico {
    pub data: [u8; 256],
    pub len: usize,
}

impl Default for Dico {
    fn default() -> Self {
        Self {
            data: [0; 256],
            len: 0,
        }
    }
}

#[derive(Debug)]
pub struct FeedBackMap {
    pub val: [u8; 32],
    pub len: usize,
}

impl Corpus {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            filenames: BTreeMap::new(),
        }
    }

    pub fn add_file(&mut self, file: FuzzFile) {
        assert!(self.filenames.insert(file.path.clone(), file.cov).is_none());
        let index = match self
            .files
            .binary_search_by(|other| other.cov.cmp(&file.cov))
        {
            Ok(index) => index,
            Err(index) => index,
        };
        self.files.insert(index, file);
    }

    pub fn contains(&self, path: &str) -> bool {
        self.filenames.contains_key(path)
    }

    pub fn iter_from(&self, path: &str) -> std::slice::Iter<FuzzFile> {
        let cov = self.filenames.get(path).unwrap();
        let index = match self.files.binary_search_by(|other| other.cov.cmp(cov)) {
            Ok(index) => index,
            Err(index) => index,
        };
        let nb = self.files[index..]
            .iter()
            .enumerate()
            .find(|&(_, file)| file.path == path)
            .map(|(index, file)| index)
            .unwrap();

        self.files[nb..].iter()
    }

    pub fn iter(&self) -> std::slice::Iter<FuzzFile> {
        self.files.iter()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(usize)]
enum FuzzState {
    Unset = 0,
    Static,
    DynamicDryRun,
    DynamicMain,
    DynamicMinimize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FeedBackMethod(u32);

impl FeedBackMethod {
    pub const NONE: FeedBackMethod = FeedBackMethod(0);
    pub const INSTRUCTION_COUNTING: FeedBackMethod = FeedBackMethod(1);
    pub const BRANCH_COUNTING: FeedBackMethod = FeedBackMethod(2);
    pub const BRANCH_TRACE_STORE: FeedBackMethod = FeedBackMethod(4);
    pub const PT: FeedBackMethod = FeedBackMethod(8);
    pub const SOFT: FeedBackMethod = FeedBackMethod(16);

    const INSTRUCTION_COUNTING_BIT: usize = 1;
    const BRANCH_COUNTING_BIT: usize = 2;
    const BRANCH_TRACE_STORE_BIT: usize = 3;
    const PT_BIT: usize = 4;
    const SOFT_BIT: usize = 5;
}

impl FeedBackMethod {
    pub fn new(val: u32) -> Self {
        Self(val)
    }
}

impl core::ops::BitOr<FeedBackMethod> for FeedBackMethod {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: FeedBackMethod) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign<FeedBackMethod> for FeedBackMethod {
    #[inline]
    fn bitor_assign(&mut self, rhs: FeedBackMethod) {
        *self = *self | rhs;
    }
}

#[derive(Debug)]
pub struct App {
    pub config: Config,
    start_datatime: DateTime<Local>,
    pub start_instant: Instant,
    job_active_count: AtomicUsize,
    mutations_count: AtomicUsize,
    crashes_count: AtomicUsize,
    fuzz_state: AtomicUsize,
    exe_data: Vec<u8>,
    pub corpus: Mutex<Corpus>,
    tested_file_count: AtomicUsize,
    pub last_cov_update: AtomicUsize,
    mutex: Mutex<()>,
    switching_feedback: AtomicBool,
    terminated_elapsed: AtomicUsize,
    pub fuzz_file_count: AtomicUsize,
    max_cov: Mutex<FuzzCov>,
    fuzz_file_max_size: Mutex<usize>,
    new_units_added: AtomicUsize,
    pub current_file: Mutex<Option<String>>,
    pub dic_count: AtomicUsize,
    pub dico: Mutex<[Dico; 1024]>,
    pub feedback_maps: Mutex<Vec<FeedBackMap>>,
}

impl App {
    #[inline]
    pub fn get_fuzz_state(&self) -> FuzzState {
        unsafe { transmute::<usize, FuzzState>(self.fuzz_state.load(Ordering::Relaxed)) }
    }

    #[inline]
    pub fn set_fuzz_state(&self, fuzz_state: FuzzState) {
        self.fuzz_state
            .store(fuzz_state as usize, Ordering::Relaxed);
    }

    #[inline]
    pub fn is_terminating(&self) -> bool {
        self.terminated_elapsed.load(Ordering::Relaxed) > 0
    }

    #[inline]
    pub fn set_terminating_to(&self, elapsed: usize) {
        if self.is_terminating() {
            return;
        }
        self.terminated_elapsed.store(elapsed, Ordering::Relaxed);
    }

    #[inline]
    pub fn set_terminating(&self) {
        if self.is_terminating() {
            return;
        }
        self.terminated_elapsed.store(
            self.start_instant.elapsed().as_secs() as usize,
            Ordering::Relaxed,
        );
    }

    #[inline]
    pub fn should_terminate(&self) -> bool {
        let elapsed = self.terminated_elapsed.load(Ordering::Relaxed);
        self.start_instant.elapsed().as_secs() as usize > elapsed
    }
}

#[derive(Debug)]
pub struct FuzzCase {
    pub pid: usize,
    pub start_instant: Instant,
    pub input: FuzzFile,
    pub static_file_try_more: bool,
    pub mutations_per_run: usize,
    pub rand: Rand,
    pub tries: usize,
}
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct FuzzCov([usize; 4]);

impl FuzzCov {
    pub fn compute_local_max(&self, other: &Self) -> Self {
        let mut cov = Self::default();
        cov.0[0] = cmp::max(self.0[0], other.0[0]);
        cov.0[1] = cmp::max(self.0[1], other.0[1]);
        cov.0[2] = cmp::max(self.0[2], other.0[2]);
        cov.0[3] = cmp::max(self.0[3], other.0[3]);

        cov
    }
}

#[derive(Debug)]
pub struct FuzzFile {
    pub path: String,

    pub data: Vec<u8>,
    pub size: usize,

    pub cov: FuzzCov,
    pub idx: usize,
    pub refs: u32,

    pub exec_usec: usize,
}

impl Default for FuzzFile {
    fn default() -> Self {
        Self {
            path: String::from(""),
            data: Vec::new(),
            size: 0,
            cov: FuzzCov::default(),
            idx: 0,
            refs: 0,
            exec_usec: 0,
        }
    }
}

impl FuzzFile {
    pub fn generate_file_name(&self) -> String {
        format!(
            "{:x}.{:x}.cov",
            md5::compute(&self.data[..self.size]),
            self.data.len()
        )
    }

    pub fn fork(&self, exec_usec: usize, app: &App) -> Self {
        Self {
            path: self.generate_file_name(),
            data: self.data.clone(),
            size: self.size,
            cov: self.cov,
            idx: app.fuzz_file_count.fetch_add(1, Ordering::Relaxed),
            refs: 0,
            exec_usec: exec_usec,
        }
    }
}

impl FuzzCase {
    pub fn set_input_size(&mut self, size: usize, config: &Config) {
        if self.input.size == size {
            return;
        }

        if size > config.app_config.max_input_size {
            panic!(
                "Too large size requested: {} > {}",
                size, config.app_config.max_input_size
            );
        }
        self.input.size = size;
    }
}

fn write_cov_file(dir: &str, file: &FuzzFile) {
    let file_name = file.generate_file_name();
    let file_path_name = format!("{}/{}", dir, file_name);
    let file_path = std::path::Path::new(&file_path_name);

    if file_path.exists() {
        println!(
            "File {} already exists in the output corpus directory",
            file_name
        );
        panic!();
    }

    println!("Adding file {} to the corpus directory {}", file_name, dir);
    println!("Written {} bytes to {:?}", file.size, file_path);
    std::fs::write(file_path, &file.data[..file.size]).unwrap();
}

fn add_dynamic_input(case: &mut FuzzCase, app: &App) {
    app.last_cov_update.store(
        app.start_instant.elapsed().as_secs() as usize,
        Ordering::Relaxed,
    );
    let fuzz_file = case
        .input
        .fork(case.start_instant.elapsed().as_millis() as usize, app);

    // Max coverage
    {
        let mut max_cov = app.max_cov.lock().unwrap();
        *max_cov = max_cov.compute_local_max(&fuzz_file.cov);
    }

    // Max fuzz file size
    {
        let mut max_size = app.fuzz_file_max_size.lock().unwrap();
        *max_size = cmp::max(*max_size, fuzz_file.size);
    }

    if !app.config.app_config.socket_fuzzer {
        write_cov_file(&app.config.io_config.output_dir, &fuzz_file);
    }

    {
        let mut corpus = app.corpus.lock().unwrap();
        corpus.add_file(fuzz_file);
    }

    if app.config.app_config.socket_fuzzer {
        // Din't add coverage data to files in socket fuzzer mode
        return;
    }

    // No need to add files to the new coverage dir, if it's not the main phase
    if app.get_fuzz_state() != FuzzState::DynamicMain {
        return;
    }

    app.new_units_added.fetch_add(1, Ordering::Relaxed);

    if false {
        unimplemented!();
        // TODO covdirnew
    }
}

#[derive(Debug)]
pub struct FuzzWorker {
    id: usize,
}

fn set_dynamic_main_state(case: &mut FuzzCase, app: &App) {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.fetch_add(1, Ordering::Relaxed);

    let _lock = app.mutex.lock().unwrap();

    if app.get_fuzz_state() != FuzzState::DynamicDryRun {
        // Already switched out of the Dry Run
        return;
    }

    println!("Entering phase 2/3: Switching to the feedback driven mode.");
    app.switching_feedback.store(true, Ordering::Relaxed);

    loop {
        if COUNT.load(Ordering::Relaxed) == app.config.app_config.jobs {
            break;
        }
        if app.is_terminating() {
            return;
        }

        sleep(std::time::Duration::from_millis(10));
        spin_loop();
    }
    app.switching_feedback.store(false, Ordering::Relaxed);

    if app.config.app_config.minimize {
        println!("Entering phase 3/3: Coprus minimization");
        app.set_fuzz_state(FuzzState::DynamicMinimize);
        return;
    }

    /*
     * If the initial fuzzing yielded no useful coverage, just add a single empty file to the
     * dynamic corpus, so the dynamic phase doesn't fail because of lack of useful inputs
     */
    if app.fuzz_file_count.load(Ordering::Relaxed) == 0 {
        let mut fuzz_file = FuzzFile::default();
        fuzz_file.path = "[DYNAMIC-0-SIZE]".to_string();
        core::mem::swap(&mut fuzz_file, &mut case.input);
        add_dynamic_input(case, app);
        core::mem::swap(&mut fuzz_file, &mut case.input);
    }
    case.input.path = "[DYNAMIC]".to_string();

    if app.config.io_config.max_file_size == 0
        && app.config.app_config.max_input_size > INPUT_MIN_SIZE
    {
        let mut new_size = cmp::max(*app.fuzz_file_max_size.lock().unwrap(), INPUT_MIN_SIZE);
        new_size = cmp::min(new_size, app.config.app_config.max_input_size);
        println!(
            "Setting maximum input size to {} bytes, previously: {}",
            new_size, app.config.app_config.max_input_size
        );
        panic!();
    }

    println!("Enteing phase 3/3: Dynamic Main (Feedback driven Mode)");
    app.set_fuzz_state(FuzzState::DynamicMain);
}

fn minimize_remove_files(case: &mut FuzzCase) {
    panic!();
}

fn input_should_read_new_file(app: &App, case: &mut FuzzCase) -> bool {
    if app.get_fuzz_state() != FuzzState::DynamicDryRun {
        case.set_input_size(app.config.app_config.max_input_size, &app.config);
        return true;
    }

    if !case.static_file_try_more {
        case.static_file_try_more = true;
        // Start with 4 bytes, increase the size in following iterations
        case.set_input_size(
            std::cmp::min(4, app.config.app_config.max_input_size),
            &app.config,
        );
        return true;
    }

    let new_size = std::cmp::max(case.input.size * 2, app.config.app_config.max_input_size);
    if new_size == app.config.app_config.max_input_size {
        case.static_file_try_more = false;
    }

    case.set_input_size(new_size, &app.config);
    false
}

fn fuzz_prepare_static_file(app: &App, case: &mut FuzzCase, mangle: bool) -> bool {
    let mut ent = None;

    if input_should_read_new_file(&app, case) {
        let entries = match input_get_entries(&app.config) {
            Ok(entries) => entries,
            Err(_) => return false,
        };

        for entry in entries {
            println!("{:?}", entry);
            ent = Some(entry.clone());

            if !mangle {
                let corpus = app.corpus.lock().unwrap();
                if corpus.contains(entry.as_path().to_str().unwrap()) {
                    eprintln!(
                        "Skipping {:?}, as it's already in the dynamic corpus",
                        entry.as_path()
                    );
                    break;
                }
            }
            app.tested_file_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    let mut file = std::fs::File::open(ent.as_ref().unwrap()).unwrap();
    case.input.data = vec![0; case.input.size];
    let size = file.read(&mut case.input.data).unwrap();
    println!(
        "Read {} bytes / {} from {:?}",
        size,
        case.input.size,
        ent.as_ref().unwrap()
    );

    if case.static_file_try_more && size < case.input.size {
        // The file is smaller than the requested size, no need to reread it anymore
        case.static_file_try_more = false;
    }
    case.set_input_size(size, &app.config);
    case.input.cov = FuzzCov::default();
    case.input.idx = 0;
    case.input.refs = 0;

    if mangle {
        mangle::mangle_content(case, 0, app);
    }

    return true;
}

fn input_speed_factor(app: &App, case: &mut FuzzCase) -> isize {
    // Slower the input, lower the chance of it being tested
    let mut avg_usecs_per_input = app.start_instant.elapsed().as_micros() as usize;
    avg_usecs_per_input /= app.mutations_count.load(Ordering::Relaxed);
    avg_usecs_per_input /= app.config.app_config.jobs;
    avg_usecs_per_input = avg_usecs_per_input.clamp(1, 1000000);

    let mut sample_usecs = case
        .start_instant
        .saturating_duration_since(app.start_instant)
        .as_micros() as usize;
    sample_usecs = sample_usecs.clamp(1, 1000000);

    match sample_usecs >= avg_usecs_per_input {
        true => (sample_usecs / avg_usecs_per_input) as isize,

        false => -((avg_usecs_per_input / sample_usecs) as isize),
    }
}

fn input_skip_factor(app: &App, case: &mut FuzzCase, file: &FuzzFile) -> (isize, isize) {
    let mut penalty: isize = 0;
    let speed_factor = input_speed_factor(app, case).clamp(-10, 2);
    penalty += speed_factor;

    /* Older inputs -> lower chance of being tested */
    let percentile = (file.idx * 100) / app.fuzz_file_count.load(Ordering::Relaxed);
    if percentile <= 40 {
        penalty += 2;
    } else if percentile <= 70 {
        penalty += 1;
    } else if percentile <= 80 {
        penalty += 0;
    } else if percentile <= 90 {
        penalty += -1;
    } else if percentile <= 97 {
        penalty += -2;
    } else if percentile <= 199 {
        penalty += -3;
    } else {
        panic!();
    }

    /* Add penalty for the input being too big - 0 is for 1kB inputs */
    if file.size > 0 {
        let mut bias =
            ((core::mem::size_of::<isize>() * 8) as u32 - file.size.leading_zeros() - 1) as isize;
        bias -= 10;
        bias = bias.clamp(-5, 5);
        penalty += bias;
    }

    (speed_factor, penalty)
}

fn prepare_dynamic_input(app: &App, case: &mut FuzzCase, mangle: bool) -> bool {
    if app.fuzz_file_count.load(Ordering::Relaxed) == 0 {
        unreachable!();
    }
    let corpus = app.corpus.lock().unwrap();
    let mut files = match *app.current_file.lock().unwrap() {
        Some(ref path) => corpus.iter_from(path),
        None => corpus.iter(),
    };
    let mut speed_factor = 0;
    let mut file = files.next().unwrap();

    loop {
        if case.tries > 0 {
            case.tries -= 1;
            break;
        }

        let (a, b) = input_skip_factor(app, case, &file);
        speed_factor = a;

        let skip_factor = b;
        if skip_factor <= 0 {
            case.tries = (-skip_factor) as usize;
            break;
        }

        if case.rand.next() % skip_factor as u64 == 0 {
            break;
        }

        file = match files.next() {
            Some(file) => file,
            None => {
                files = corpus.iter();
                files.next().unwrap()
            }
        };
    }
    *app.current_file.lock().unwrap() = files.next().map(|file| file.path.clone());

    case.set_input_size(file.size, &app.config);
    case.input.idx = file.idx;
    case.input.exec_usec = file.exec_usec;
    //case.input.src = file;
    case.input.refs = 0;
    case.input.cov = file.cov;
    case.input.path = file.path.clone();
    case.input.data = file.data.clone();

    if mangle {
        mangle_content(case, speed_factor, app)
    }

    true
}

fn fuzz_fetch_input(app: &App, case: &mut FuzzCase) -> bool {
    if app.get_fuzz_state() == FuzzState::DynamicDryRun {
        case.mutations_per_run = 0;
        if fuzz_prepare_static_file(app, case, true) {
            return true;
        }
        set_dynamic_main_state(case, app);
        case.mutations_per_run = app.config.app_config.mutation_per_run;
    }

    if app.get_fuzz_state() == FuzzState::DynamicMinimize {
        minimize_remove_files(case);
        return false;
    }

    if app.get_fuzz_state() == FuzzState::DynamicMain {
        if app.config.exe_config.mutation_cmdline.is_some() {
            unimplemented!();
        } else if app.config.exe_config.fb_mutation_cmdline.is_some() {
            if !prepare_dynamic_input(app, case, false) {
                eprintln!("Failed");
                return false;
            }
        } else {
            if !prepare_dynamic_input(app, case, true) {
                eprintln!("Failed");
                return false;
            }
        }
    }

    if app.get_fuzz_state() == FuzzState::Static {
        panic!();
    }

    return true;
}

fn subproc_run(app: &App, case: &mut FuzzCase) -> bool {
    true
}

fn compute_feedback(app: &App, case: &mut FuzzCase) {}

fn report_save_report(app: &App, case: &mut FuzzCase) {}

fn fuzz_loop(app: &App, case: &mut FuzzCase) {
    case.mutations_per_run = app.config.app_config.mutation_per_run;

    if !fuzz_fetch_input(app, case) {
        if app.config.app_config.minimize && app.get_fuzz_state() == FuzzState::DynamicMinimize {
            app.set_terminating();
            return;
        }
        if !subproc_run(app, case) {
            eprintln!("Could not prepare input for fuzzing");
        }

        if app.config.app_config.feedback_method != FeedBackMethod::NONE {
            compute_feedback(app, case);
        }
        eprintln!("Could not prepare input for fuzzing");
        report_save_report(app, case);
    }
}

pub fn worker(app: Arc<App>, id: usize) {
    app.job_active_count.fetch_add(1, Ordering::Relaxed);
    println!("Launched fuzzing threads: no {}", id);

    let mapname = format!("tf-{}-input", id);
    println!("{}", mapname);
    let mut case = FuzzCase {
        start_instant: Instant::now(),
        pid: 0,
        input: FuzzFile::default(),
        static_file_try_more: false,
        mutations_per_run: app.config.app_config.mutation_per_run,
        rand: Rand::new_random_seed(),
        tries: 0,
    };

    let mapname = format!("tf-{}-perthreadmap", id);
    println!("{}", mapname);

    loop {
        let mutation_count = app.mutations_count.fetch_add(1, Ordering::Relaxed);

        if let Some(mutation_num) = app.config.app_config.mutation_num {
            if mutation_count >= mutation_num {
                break;
            }
        }

        fuzz_loop(&app, &mut case);

        if app.config.app_config.crash_exit {
            if app.crashes_count.load(Ordering::Relaxed) > 0 {
                println!("Global crash");
                break;
            }
        }
    }
}

fn sanitizer_init(config: &Config) {
    std::env::set_var("ASAN_OPTIONS", ASAN_COMMON_FLAGS);
    std::env::set_var("UBSAN_OPTIONS", ASAN_COMMON_FLAGS);
    std::env::set_var("MSAN_OPTIONS", MASAN_COMMON_FLAGS);
    std::env::set_var("LSAN_OPTIONS", ASAN_COMMON_FLAGS);
}

pub fn fuzz(config: Config) {
    //sanitizer_init(&config);

    let fuzz_state = if config.app_config.socket_fuzzer {
        println!("Entering phase - Feedbaclk drvier mode (SocketFuzzer)");
        FuzzState::DynamicMain
    } else if config.app_config.feedback_method != FeedBackMethod::NONE {
        println!("Entering phase 1/3: Dry run");
        FuzzState::DynamicDryRun
    } else {
        println!("Entering phase: Static");
        FuzzState::Static
    };

    let mut threads = Vec::new();
    assert!(config.exe_config.cmdline.is_some());

    let mut dicos: Vec<Dico> = Vec::new();
    for i in 0..1024 {
        dicos.push(Dico::default());
    }

    let exe_path = std::path::Path::new(&config.exe_config.cmdline.as_ref().unwrap()[0]);
    let exe_data = std::fs::read(exe_path).unwrap();
    let app = Arc::new(App {
        config: config,
        start_datatime: Local::now(),
        start_instant: Instant::now(),
        job_active_count: AtomicUsize::new(0),
        mutations_count: AtomicUsize::new(0),
        crashes_count: AtomicUsize::new(0),
        fuzz_state: AtomicUsize::new(fuzz_state as usize),
        exe_data: exe_data,
        corpus: Mutex::new(Corpus::new()),
        tested_file_count: AtomicUsize::new(0),
        last_cov_update: AtomicUsize::new(0),
        mutex: Mutex::new(()),
        switching_feedback: AtomicBool::new(false),
        terminated_elapsed: AtomicUsize::new(0),
        fuzz_file_count: AtomicUsize::new(0),
        max_cov: Mutex::new(FuzzCov::default()),
        fuzz_file_max_size: Mutex::new(0),
        new_units_added: AtomicUsize::new(0),
        current_file: Mutex::new(None),
        dic_count: AtomicUsize::new(0),
        dico: Mutex::new(dicos.try_into().unwrap()),
        feedback_maps: Mutex::new(Vec::new()),
    });

    for i in 0..app.config.app_config.jobs {
        let builder = thread::Builder::new()
            .stack_size(1024 * 1024)
            .name(format!("fuzz_worker({})", i));
        let app = Arc::clone(&app);

        threads.push(
            builder
                .spawn(move || {
                    worker(app, i);
                })
                .unwrap(),
        );
    }

    for thread in threads {
        thread.join().unwrap();
    }
}
