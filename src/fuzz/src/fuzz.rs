//! Fuzz

use crate::config::Config;
use core::num;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::{cmp, thread};

pub struct App {
    config: Config,
    job_active_count: AtomicUsize,
}

pub fn worker(app: Arc<App>, id: usize) {
    app.job_active_count.fetch_add(1, Ordering::Relaxed);


    println!("worker!");
}

pub fn fuzz(config: Config) {
    let mut threads = Vec::new();

    let app = Arc::new(App {
        config: config,
        job_active_count: AtomicUsize::new(0),
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
