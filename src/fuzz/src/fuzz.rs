//! Fuzz

use crate::corpus::{Corpus, FuzzCov};
use crate::random::Rand;
use crate::{app::App, corpus::FuzzInput};
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

use crate::app::Mode;
use crate::dico::Dico;
use crate::feedback::FeedBackMethod;

use bits::BitField;
use chrono::{DateTime, Local};
use thread::sleep;

const ASAN_COMMON_FLAGS: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=0:handle_segv=2:handle_sigbus=2:handle_abort=2:handle_sigill=2:handle_sigfpe=2:abort_on_error=1:log_path=/tmp/here";
const MASAN_COMMON_FLAGS: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=0:handle_segv=2:handle_sigbus=2:handle_abort=2:handle_sigill=2:handle_sigfpe=2:abort_on_error=1:wrap_signals=0:print_stats=1:log_path=/tmp/here";
const kSAN_REGULAR: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=1:handle_segv=0:handle_sigbus=0:handle_abort=0:handle_sigill=0:handle_sigfpe=0:abort_on_error=1";

#[derive(Debug)]
pub struct FuzzCase {
    pub pid: usize,
    pub start_instant: Instant,
    pub input: FuzzInput,
    pub static_file_try_more: bool,
    pub mutations_per_run: usize,
    pub rand: Rand,
    pub tries: usize,
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

fn write_cov_file(dir: &str, file: &FuzzInput) {
    let file_name = file.generate_filename();
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
    app.metrics.last_cov_update.store(
        app.metrics.start_instant.elapsed().as_secs() as usize,
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
        let mut max_size = app.metrics.fuzz_input_max_size.lock().unwrap();
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
    if app.get_mode() != Mode::DynamicMain {
        return;
    }

    app.metrics.new_units_added.fetch_add(1, Ordering::Relaxed);

    if false {
        todo!("covdir new");
    }
}

#[derive(Debug)]
pub struct FuzzWorker {
    id: usize,
}

fn set_dynamic_main_state(case: &mut FuzzCase, app: &App) {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    COUNT.fetch_add(1, Ordering::Relaxed);

    // TODO let _lock = app.mutex.lock().unwrap();

    if app.get_mode() != Mode::DynamicDryRun {
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
        app.set_mode(Mode::DynamicMinimize);
        return;
    }

    /*
     * If the initial fuzzing yielded no useful coverage, just add a single empty file to the
     * dynamic corpus, so the dynamic phase doesn't fail because of lack of useful inputs
     */
    if app.metrics.fuzz_input_count.load(Ordering::Relaxed) == 0 {
        let mut fuzz_file = FuzzInput::default();
        fuzz_file.path = "[DYNAMIC-0-SIZE]".to_string();
        core::mem::swap(&mut fuzz_file, &mut case.input);
        add_dynamic_input(case, app);
        core::mem::swap(&mut fuzz_file, &mut case.input);
    }
    case.input.path = "[DYNAMIC]".to_string();

    if app.config.io_config.max_file_size == 0
        && app.config.app_config.max_input_size > INPUT_MIN_SIZE
    {
        let mut new_size = cmp::max(
            *app.metrics.fuzz_input_max_size.lock().unwrap(),
            INPUT_MIN_SIZE,
        );
        new_size = cmp::min(new_size, app.config.app_config.max_input_size);
        println!(
            "Setting maximum input size to {} bytes, previously: {}",
            new_size, app.config.app_config.max_input_size
        );
        panic!();
    }

    println!("Enteing phase 3/3: Dynamic Main (Feedback driven Mode)");
    app.set_mode(Mode::DynamicMain);
}

fn minimize_remove_files(case: &mut FuzzCase) {
    panic!();
}

fn input_should_read_new_file(app: &App, case: &mut FuzzCase) -> bool {
    if app.get_mode() != Mode::DynamicDryRun {
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
            app.metrics
                .tested_file_count
                .fetch_add(1, Ordering::Relaxed);
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
    let mut avg_usecs_per_input = app.metrics.start_instant.elapsed().as_micros() as usize;
    avg_usecs_per_input /= app.metrics.mutations_count.load(Ordering::Relaxed);
    avg_usecs_per_input /= app.config.app_config.jobs;
    avg_usecs_per_input = avg_usecs_per_input.clamp(1, 1000000);

    let mut sample_usecs = case
        .start_instant
        .saturating_duration_since(app.metrics.start_instant)
        .as_micros() as usize;
    sample_usecs = sample_usecs.clamp(1, 1000000);

    match sample_usecs >= avg_usecs_per_input {
        true => (sample_usecs / avg_usecs_per_input) as isize,

        false => -((avg_usecs_per_input / sample_usecs) as isize),
    }
}

fn input_skip_factor(app: &App, case: &mut FuzzCase, file: &FuzzInput) -> (isize, isize) {
    let mut penalty: isize = 0;
    let speed_factor = input_speed_factor(app, case).clamp(-10, 2);
    penalty += speed_factor;

    /* Older inputs -> lower chance of being tested */
    let percentile = (file.idx * 100) / app.metrics.fuzz_input_count.load(Ordering::Relaxed);
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
    if app.metrics.fuzz_input_count.load(Ordering::Relaxed) == 0 {
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
    if app.get_mode() == Mode::DynamicDryRun {
        case.mutations_per_run = 0;
        if fuzz_prepare_static_file(app, case, true) {
            return true;
        }
        set_dynamic_main_state(case, app);
        case.mutations_per_run = app.config.app_config.mutation_per_run;
    }

    if app.get_mode() == Mode::DynamicMinimize {
        minimize_remove_files(case);
        return false;
    }

    if app.get_mode() == Mode::DynamicMain {
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

    if app.get_mode() == Mode::Static {
        todo!();
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
        if app.config.app_config.minimize && app.get_mode() == Mode::DynamicMinimize {
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
    app.metrics.job_active_count.fetch_add(1, Ordering::Relaxed);
    println!("Launched fuzzing threads: no {}", id);

    let mapname = format!("tf-{}-input", id);
    println!("{}", mapname);
    let mut case = FuzzCase {
        start_instant: Instant::now(),
        pid: 0,
        input: FuzzInput::default(),
        static_file_try_more: false,
        mutations_per_run: app.config.app_config.mutation_per_run,
        rand: Rand::new_random_seed(),
        tries: 0,
    };

    let mapname = format!("tf-{}-perthreadmap", id);
    println!("{}", mapname);

    loop {
        let mutation_count = app.metrics.mutations_count.fetch_add(1, Ordering::Relaxed);

        if let Some(mutation_num) = app.config.app_config.mutation_num {
            if mutation_count >= mutation_num {
                break;
            }
        }

        fuzz_loop(&app, &mut case);

        if app.config.app_config.crash_exit {
            if app.metrics.crashes_count.load(Ordering::Relaxed) > 0 {
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

/// Compute the starting fuzz mode based on the config
fn compute_fuzz_mode(config: &Config) -> Mode {
    let mode = if config.app_config.socket_fuzzer {
        Mode::DynamicMain
    } else if config.app_config.feedback_method != FeedBackMethod::NONE {
        Mode::DynamicDryRun
    } else {
        Mode::Static
    };

    // Log mode
    match mode {
        Mode::DynamicMain => {
            println!("Entering phase - Feedbaclk drvier mode (SocketFuzzer)");
        }
        Mode::DynamicDryRun => {
            println!("Entering phase 1/3: Dry run");
        }
        Mode::Static => {
            println!("Entering phase: Static");
        }
        _ => unreachable!(),
    }

    mode
}

/// Start fuzzing
pub fn fuzz(config: Config) {
    // Get mode
    let mode = compute_fuzz_mode(&config);

    let mut threads = Vec::new();
    assert!(config.exe_config.cmdline.is_some());

    let exe_path = std::path::Path::new(&config.exe_config.cmdline.as_ref().unwrap()[0]);
    let exe_data = std::fs::read(exe_path).unwrap();
    let app = Arc::new(App::new(config, mode));

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
