//! Sanitize utils

use std::env;

use crate::config::Config;

#[allow(unused)]
const ASAN_COMMON_FLAGS: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=0:handle_segv=2:handle_sigbus=2:handle_abort=2:handle_sigill=2:handle_sigfpe=2:abort_on_error=1:log_path=/tmp/here";
#[allow(unused)]
const MASAN_COMMON_FLAGS: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=0:handle_segv=2:handle_sigbus=2:handle_abort=2:handle_sigill=2:handle_sigfpe=2:abort_on_error=1:wrap_signals=0:print_stats=1:log_path=/tmp/here";
#[allow(unused)]
const KSAN_REGULAR: &str = "symbolize=1:detect_leaks=0:disable_coredump=0:detect_odr_violation=0:allocator_may_return_null=1:allow_user_segv_handler=1:handle_segv=0:handle_sigbus=0:handle_abort=0:handle_sigill=0:handle_sigfpe=0:abort_on_error=1";

/// Init sanitizer env variables
pub fn sanitizer_init(config: &Config) {
    env::set_var("ASAN_OPTIONS", ASAN_COMMON_FLAGS);
    env::set_var("UBSAN_OPTIONS", ASAN_COMMON_FLAGS);
    env::set_var("MSAN_OPTIONS", MASAN_COMMON_FLAGS);
    env::set_var("LSAN_OPTIONS", ASAN_COMMON_FLAGS);
}
