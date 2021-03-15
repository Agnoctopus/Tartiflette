//! Mangle subsystem

use std::convert::TryInto;
use std::sync::atomic::Ordering;

use crate::app::App;
use crate::config::Config;
use crate::fuzz::FuzzCase;
use crate::input;
use crate::random::Rand;

const MAGIC_TABLE: &[&[u8]] = &[
    // 1 byte no endianness
    b"\x00",
    b"\x01",
    b"\x02",
    b"\x03",
    b"\x04",
    b"\x05",
    b"\x06",
    b"\x07",
    b"\x08",
    b"\x09",
    b"\x0a",
    b"\x0b",
    b"\x0c",
    b"\x0d",
    b"\x0e",
    b"\x0f",
    b"\x10",
    b"\x20",
    b"\x40",
    b"\x7e",
    b"\x7f",
    b"\x80",
    b"\x81",
    b"\xc0",
    b"\xfe",
    b"\xff",
    // 2 bytes no endianness
    b"\x00\x00",
    b"\x01\x01",
    b"\x80\x80",
    b"\xff\xff",
    // 2 bytes big endinanness
    b"\x00\x01",
    b"\x00\x02",
    b"\x00\x03",
    b"\x00\x04",
    b"\x00\x05",
    b"\x00\x06",
    b"\x00\x07",
    b"\x00\x08",
    b"\x00\x09",
    b"\x00\x0A",
    b"\x00\x0B",
    b"\x00\x0C",
    b"\x00\x0D",
    b"\x00\x0E",
    b"\x00\x0F",
    b"\x00\x10",
    b"\x00\x20",
    b"\x00\x40",
    b"\x00\x7E",
    b"\x00\x7F",
    b"\x00\x80",
    b"\x00\x81",
    b"\x00\xC0",
    b"\x00\xFE",
    b"\x00\xFF",
    b"\x7E\xFF",
    b"\x7F\xFF",
    b"\x80\x00",
    b"\x80\x01",
    b"\xFF\xFE",
    // 2 bytes low endianness
    b"\x00\x00",
    b"\x01\x00",
    b"\x02\x00",
    b"\x03\x00",
    b"\x04\x00",
    b"\x05\x00",
    b"\x06\x00",
    b"\x07\x00",
    b"\x08\x00",
    b"\x09\x00",
    b"\x0A\x00",
    b"\x0B\x00",
    b"\x0C\x00",
    b"\x0D\x00",
    b"\x0E\x00",
    b"\x0F\x00",
    b"\x10\x00",
    b"\x20\x00",
    b"\x40\x00",
    b"\x7E\x00",
    b"\x7F\x00",
    b"\x80\x00",
    b"\x81\x00",
    b"\xC0\x00",
    b"\xFE\x00",
    b"\xFF\x00",
    b"\xFF\x7E",
    b"\xFF\x7F",
    b"\x00\x80",
    b"\x01\x80",
    b"\xFE\xFF",
    // 4 bytes no endianness
    b"\x00\x00\x00\x00",
    b"\x01\x01\x01\x01",
    b"\x80\x80\x80\x80",
    b"\xFF\xFF\xFF\xFF",
    // 4 bytes big endianness
    b"\x00\x00\x00\x01",
    b"\x00\x00\x00\x02",
    b"\x00\x00\x00\x03",
    b"\x00\x00\x00\x04",
    b"\x00\x00\x00\x05",
    b"\x00\x00\x00\x06",
    b"\x00\x00\x00\x07",
    b"\x00\x00\x00\x08",
    b"\x00\x00\x00\x09",
    b"\x00\x00\x00\x0A",
    b"\x00\x00\x00\x0B",
    b"\x00\x00\x00\x0C",
    b"\x00\x00\x00\x0D",
    b"\x00\x00\x00\x0E",
    b"\x00\x00\x00\x0F",
    b"\x00\x00\x00\x10",
    b"\x00\x00\x00\x20",
    b"\x00\x00\x00\x40",
    b"\x00\x00\x00\x7E",
    b"\x00\x00\x00\x7F",
    b"\x00\x00\x00\x80",
    b"\x00\x00\x00\x81",
    b"\x00\x00\x00\xC0",
    b"\x00\x00\x00\xFE",
    b"\x00\x00\x00\xFF",
    b"\x7E\xFF\xFF\xFF",
    b"\x7F\xFF\xFF\xFF",
    b"\x80\x00\x00\x00",
    b"\x80\x00\x00\x01",
    b"\xFF\xFF\xFF\xFE",
    // 4 bytes low endianness
    b"\x00\x00\x00\x00",
    b"\x01\x00\x00\x00",
    b"\x02\x00\x00\x00",
    b"\x03\x00\x00\x00",
    b"\x04\x00\x00\x00",
    b"\x05\x00\x00\x00",
    b"\x06\x00\x00\x00",
    b"\x07\x00\x00\x00",
    b"\x08\x00\x00\x00",
    b"\x09\x00\x00\x00",
    b"\x0A\x00\x00\x00",
    b"\x0B\x00\x00\x00",
    b"\x0C\x00\x00\x00",
    b"\x0D\x00\x00\x00",
    b"\x0E\x00\x00\x00",
    b"\x0F\x00\x00\x00",
    b"\x10\x00\x00\x00",
    b"\x20\x00\x00\x00",
    b"\x40\x00\x00\x00",
    b"\x7E\x00\x00\x00",
    b"\x7F\x00\x00\x00",
    b"\x80\x00\x00\x00",
    b"\x81\x00\x00\x00",
    b"\xC0\x00\x00\x00",
    b"\xFE\x00\x00\x00",
    b"\xFF\x00\x00\x00",
    b"\xFF\xFF\xFF\x7E",
    b"\xFF\xFF\xFF\x7F",
    b"\x00\x00\x00\x80",
    b"\x01\x00\x00\x80",
    b"\xFE\xFF\xFF\xFF",
    // 8 bytes no endianness
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x01\x01\x01\x01\x01\x01\x01\x01",
    b"\x80\x80\x80\x80\x80\x80\x80\x80",
    b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    // 8 bytes big endianness
    b"\x00\x00\x00\x00\x00\x00\x00\x01",
    b"\x00\x00\x00\x00\x00\x00\x00\x02",
    b"\x00\x00\x00\x00\x00\x00\x00\x03",
    b"\x00\x00\x00\x00\x00\x00\x00\x04",
    b"\x00\x00\x00\x00\x00\x00\x00\x05",
    b"\x00\x00\x00\x00\x00\x00\x00\x06",
    b"\x00\x00\x00\x00\x00\x00\x00\x07",
    b"\x00\x00\x00\x00\x00\x00\x00\x08",
    b"\x00\x00\x00\x00\x00\x00\x00\x09",
    b"\x00\x00\x00\x00\x00\x00\x00\x0A",
    b"\x00\x00\x00\x00\x00\x00\x00\x0B",
    b"\x00\x00\x00\x00\x00\x00\x00\x0C",
    b"\x00\x00\x00\x00\x00\x00\x00\x0D",
    b"\x00\x00\x00\x00\x00\x00\x00\x0E",
    b"\x00\x00\x00\x00\x00\x00\x00\x0F",
    b"\x00\x00\x00\x00\x00\x00\x00\x10",
    b"\x00\x00\x00\x00\x00\x00\x00\x20",
    b"\x00\x00\x00\x00\x00\x00\x00\x40",
    b"\x00\x00\x00\x00\x00\x00\x00\x7E",
    b"\x00\x00\x00\x00\x00\x00\x00\x7F",
    b"\x00\x00\x00\x00\x00\x00\x00\x80",
    b"\x00\x00\x00\x00\x00\x00\x00\x81",
    b"\x00\x00\x00\x00\x00\x00\x00\xC0",
    b"\x00\x00\x00\x00\x00\x00\x00\xFE",
    b"\x00\x00\x00\x00\x00\x00\x00\xFF",
    b"\x7E\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    b"\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
    b"\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\x80\x00\x00\x00\x00\x00\x00\x01",
    b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE",
    // 8 bytes low endianness
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x01\x00\x00\x00\x00\x00\x00\x00",
    b"\x02\x00\x00\x00\x00\x00\x00\x00",
    b"\x03\x00\x00\x00\x00\x00\x00\x00",
    b"\x04\x00\x00\x00\x00\x00\x00\x00",
    b"\x05\x00\x00\x00\x00\x00\x00\x00",
    b"\x06\x00\x00\x00\x00\x00\x00\x00",
    b"\x07\x00\x00\x00\x00\x00\x00\x00",
    b"\x08\x00\x00\x00\x00\x00\x00\x00",
    b"\x09\x00\x00\x00\x00\x00\x00\x00",
    b"\x0A\x00\x00\x00\x00\x00\x00\x00",
    b"\x0B\x00\x00\x00\x00\x00\x00\x00",
    b"\x0C\x00\x00\x00\x00\x00\x00\x00",
    b"\x0D\x00\x00\x00\x00\x00\x00\x00",
    b"\x0E\x00\x00\x00\x00\x00\x00\x00",
    b"\x0F\x00\x00\x00\x00\x00\x00\x00",
    b"\x10\x00\x00\x00\x00\x00\x00\x00",
    b"\x20\x00\x00\x00\x00\x00\x00\x00",
    b"\x40\x00\x00\x00\x00\x00\x00\x00",
    b"\x7E\x00\x00\x00\x00\x00\x00\x00",
    b"\x7F\x00\x00\x00\x00\x00\x00\x00",
    b"\x80\x00\x00\x00\x00\x00\x00\x00",
    b"\x81\x00\x00\x00\x00\x00\x00\x00",
    b"\xC0\x00\x00\x00\x00\x00\x00\x00",
    b"\xFE\x00\x00\x00\x00\x00\x00\x00",
    b"\xFF\x00\x00\x00\x00\x00\x00\x00",
    b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7E",
    b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F",
    b"\x00\x00\x00\x00\x00\x00\x00\x80",
    b"\x01\x00\x00\x00\x00\x00\x00\x80",
    b"\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
];

fn mangle_random_buf(rand: &mut Rand, buff: &mut [u8], config: &Config) {
    if config.app_config.random_ascii {
        for byte in buff.iter_mut() {
            *byte = ((rand.next() >> 32) as u8).clamp(32, 126);
        }
    } else {
        for byte in buff.iter_mut() {
            *byte = (rand.next() >> 32) as u8;
        }
    }
}

fn mangle_buf_to_ascii(rand: &mut Rand, buff: &mut [u8]) {
    for byte in buff.iter_mut() {
        *byte = (*byte % 95) + 32;
    }
}

fn mangle_len_left(case: &mut FuzzCase, off: usize) -> usize {
    if off >= case.input.size {
        panic!();
    }
    case.input.size - off - 1
}

/// Get a random value <1:max>, but prefer smaller ones
/// Based on an idea by https://twitter.com/gamozolabs
///
fn mangle_get_len(rand: &mut Rand, max: usize) -> usize {
    if max > input::INPUT_MIN_SIZE || max == 0 {
        panic!();
    }

    if max == 1 {
        return 1;
    }

    /* Give 50% chance the the uniform distribution */
    if rand.next() & 1 == 1 {
        return rand.random_in(1..max as u64) as usize;
    }

    /* effectively exprand() */
    let max = rand.random_in(1..max as u64);
    return rand.random_in(1..max) as usize;
}

fn mangle_get_offset(case: &mut FuzzCase) -> usize {
    // Prefer smaller values here, so use mangle_getLen()
    mangle_get_len(&mut case.rand, case.input.size) - 1
}

fn mangle_get_offset_inc(case: &mut FuzzCase) -> usize {
    // Offset which can be equal to the file size
    mangle_get_len(
        &mut case.rand,
        input::INPUT_MAX_SIZE.min(case.input.size + 1),
    ) - 1
}
fn mangle_move(case: &mut FuzzCase, off_from: usize, off_to: usize, mut len: usize) {
    if off_from >= case.input.size {
        return;
    }
    if off_to >= case.input.size {
        return;
    }
    if off_from == off_to {
        return;
    }

    let len_from = case.input.size - off_from;
    len = len_from.min(len);

    let len_to = case.input.size - off_to;
    len = len_to.min(len);

    case.input
        .data
        .copy_within(off_from..off_from + len, off_to)
}

fn mangle_overwrite(case: &mut FuzzCase, off: usize, src: &[u8], app: &App) {
    let mut len = src.len();
    if len == 0 {
        return;
    }

    let max_to_copy = case.input.size - off;
    len = len.min(max_to_copy);

    case.input.data[off..off + len].copy_from_slice(&src[..len]);
    if app.config.app_config.random_ascii {
        mangle_buf_to_ascii(&mut case.rand, &mut case.input.data[off..off + len]);
    }
}

fn mangle_inflate(case: &mut FuzzCase, off: usize, len: usize, app: &App) -> usize {
    if case.input.size >= app.config.app_config.max_input_size {
        return 0;
    }
    let len = len.min(app.config.app_config.max_input_size - case.input.size);

    case.set_input_size(case.input.size + len, &app.config);
    mangle_move(case, off, off + len, case.input.size);

    if app.config.app_config.random_ascii {
        for byte in case.input.data[off..off + len].iter_mut() {
            *byte = ' ' as u8;
        }
    }

    return len;
}

fn mangle_insert(case: &mut FuzzCase, off: usize, data: &[u8], app: &App) {
    let len = mangle_inflate(case, off, data.len(), app);
    mangle_overwrite(case, off, &data[..len], app);
}

fn mangle_use_value(case: &mut FuzzCase, data: &[u8], app: &App) {
    if case.rand.random_bool() {
        let off = mangle_get_offset_inc(case);
        mangle_insert(case, off, data, app);
    } else {
        let off = mangle_get_offset(case);
        mangle_overwrite(case, off, data, app);
    }
}

fn mangle_use_value_at(case: &mut FuzzCase, off: usize, data: &[u8], app: &App) {
    if case.rand.random_bool() {
        mangle_insert(case, off, data, app);
    } else {
        mangle_overwrite(case, off, data, app);
    }
}

fn mangle_mem_swap(case: &mut FuzzCase, _app: &App) {
    let off1 = mangle_get_offset(case);
    let max_len1 = case.input.size - off1;
    let off2 = mangle_get_offset(case);
    let max_len2 = case.input.size - off2;
    let len = mangle_get_len(&mut case.rand, core::cmp::min(max_len1, max_len2));

    if off1 == off2 {
        return;
    }

    for i in 0..(len / 2) {
        let tmp1 = case.input.data[off2 + i];
        case.input.data[off2 + i] = case.input.data[off1 + i];
        case.input.data[off1 + i] = tmp1;

        let tmp2 = case.input.data[off2 + (len - 1) - i];
        case.input.data[off2 + (len - 1) - i] = case.input.data[off1 + (len - 1) - i];
        case.input.data[off1 + (len - 1) - i] = tmp2;
    }
}

fn mangle_mem_copy(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    let len = mangle_get_len(&mut case.rand, case.input.size - off);

    let data = case.input.data[off..off + len].to_vec();

    mangle_use_value(case, &data, app);
}

fn mangle_bytes(case: &mut FuzzCase, app: &App) {
    let mut buf: [u8; 2] = [0; 2];
    mangle_random_buf(&mut case.rand, &mut buf, &app.config);

    /* Overwrite with random 1-2-byte values */
    let len = case.rand.random_in(1..2) as usize;
    mangle_use_value(case, &buf[..len], app);
}

fn mangle_byte_repeat_overwrite(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    let dest_off = off + 1;
    let max_size = case.input.size - dest_off;

    // No space to repeat
    if max_size == 0 {
        mangle_bytes(case, app);
    }

    let len = mangle_get_len(&mut case.rand, max_size);
    let b = case.input.data[off];
    for byte in case.input.data[dest_off..dest_off + len].iter_mut() {
        *byte = b;
    }
}

fn mangle_byte_repeat_insert(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    let dest_off = off + 1;
    let max_size = case.input.size - dest_off;

    // No space to repeat
    if max_size == 0 {
        mangle_bytes(case, app);
    }

    let len = mangle_get_len(&mut case.rand, max_size);
    let len = mangle_inflate(case, dest_off, len, app);
    let b = case.input.data[off];

    for byte in case.input.data[dest_off..dest_off + len].iter_mut() {
        *byte = b;
    }
}

fn mangle_bit(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    case.input.data[off] ^= (1 << case.rand.random_in(0..8)) as u8;

    if app.config.app_config.random_ascii {
        mangle_buf_to_ascii(&mut case.rand, &mut case.input.data[off..off + 1]);
    }
}

fn mangle_magic(case: &mut FuzzCase, app: &App) {
    let choice = case.rand.random_in(0..MAGIC_TABLE.len() as u64 - 1) as usize;
    mangle_use_value(case, MAGIC_TABLE[choice], app);
}

fn mangle_static_dict(case: &mut FuzzCase, app: &App) {
    let dico = app.dico.lock().unwrap();

    if dico.entries.len() == 0 {
        mangle_bytes(case, app);
    }

    let choice = case.rand.random_in(0..dico.entries.len() as u64) as usize;

    let entry = &dico.entries[choice];
    mangle_use_value(case, &entry.data[..entry.len], app);
}

fn mangle_feedback_dict(case: &mut FuzzCase, app: &App) -> Option<Vec<u8>> {
    let feedback = app.feedback.lock().unwrap();

    let map = &feedback.cmp_feedback_map;
    if map.entries.len() == 0 {
        return None;
    }

    let choice = case.rand.random_in(0..map.entries.len() as u64 - 1) as usize;
    let map = &map.entries[choice];
    if map.len == 0 {
        return None;
    }
    Some(map.val[..map.len].to_vec())
}

fn mangle_const_feedback_dict(case: &mut FuzzCase, app: &App) {
    match mangle_feedback_dict(case, app) {
        Some(val) => mangle_use_value(case, &val, app),
        None => mangle_bytes(case, app),
    }
}

fn mangle_memset(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    let len = mangle_get_len(&mut case.rand, case.input.size - off);
    let val = match app.config.app_config.random_ascii {
        true => case.rand.random_in(32..126) as u8,
        false => case.rand.random_in(0..256) as u8,
    };

    for byte in case.input.data[off..off + len].iter_mut() {
        *byte = val;
    }
}

fn mangle_memclear(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    let len = mangle_get_len(&mut case.rand, case.input.size - off);
    let val = match app.config.app_config.random_ascii {
        true => ' ' as u8,
        false => 0,
    };

    for byte in case.input.data[off..off + len].iter_mut() {
        *byte = val;
    }
}

fn mangle_random_overwrite(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    let len = mangle_get_len(&mut case.rand, case.input.size - off);

    mangle_random_buf(
        &mut case.rand,
        &mut case.input.data[off..off + len],
        &app.config,
    );
}

fn mangle_random_insert(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    let len = mangle_get_len(&mut case.rand, case.input.size - off);

    let len = mangle_inflate(case, off, len, app);
    mangle_random_buf(
        &mut case.rand,
        &mut case.input.data[off..off + len],
        &app.config,
    );
}

fn mangle_add_sub_with_range(
    case: &mut FuzzCase,
    off: usize,
    var_len: usize,
    range: usize,
    app: &App,
) {
    let delta = case.rand.random_in(0..range as u64 * 2) as isize - range as isize;

    match var_len {
        1 => {
            case.input.data[off] += delta as u8;
        }
        2 => {
            let mut val = i16::from_ne_bytes(case.input.data[off..off + 2].try_into().unwrap());
            if case.rand.random_bool() {
                val += delta as i16;
            } else {
                val.swap_bytes();
                val += delta as i16;
                val.swap_bytes();
            }
            mangle_overwrite(case, off, &val.to_ne_bytes(), app)
        }
        4 => {
            let mut val = i32::from_ne_bytes(case.input.data[off..off + 4].try_into().unwrap());
            if case.rand.random_bool() {
                val += delta as i32;
            } else {
                val.swap_bytes();
                val += delta as i32;
                val.swap_bytes();
            }
            mangle_overwrite(case, off, &val.to_ne_bytes(), app)
        }
        8 => {
            let mut val = i64::from_ne_bytes(case.input.data[off..off + 4].try_into().unwrap());
            if case.rand.random_bool() {
                val += delta as i64;
            } else {
                val.swap_bytes();
                val += delta as i64;
                val.swap_bytes();
            }
            mangle_overwrite(case, off, &val.to_ne_bytes(), app)
        }
        _ => unimplemented!(),
    }
}

fn mangle_add_sub(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);

    let mut var_len = 1 << case.rand.random_in(0..3);
    if case.input.size - off < var_len {
        var_len = 1
    }

    let range = match var_len {
        1 => 16,
        2 => 4086,
        4 => 1048576,
        8 => 268435456,
        _ => unimplemented!(),
    };

    mangle_add_sub_with_range(case, off, var_len, range, app);
}

fn mangle_inc_byte(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    if app.config.app_config.random_ascii {
        case.input.data[off] = (case.input.data[off] - 32 + 1) % 95 + 32;
    } else {
        case.input.data[off] += 1;
    }
}

fn mangle_dec_bytes(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    if app.config.app_config.random_ascii {
        case.input.data[off] = (case.input.data[off] - 32 + 94) % 95 + 32;
    } else {
        case.input.data[off] -= 1;
    }
}

fn mangle_neg_bytes(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    if app.config.app_config.random_ascii {
        case.input.data[off] = 94 - (case.input.data[off] - 32) + 32;
    } else {
        case.input.data[off] = !case.input.data[off];
    }
}

fn mangle_expand(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);
    let len = match case.rand.next() % 16 > 0 {
        true => mangle_get_len(
            &mut case.rand,
            core::cmp::min(16, app.config.app_config.max_input_size - off),
        ),
        false => mangle_get_len(&mut case.rand, app.config.app_config.max_input_size - off),
    };
    mangle_inflate(case, off, len, app);
}

fn mangle_shrink(case: &mut FuzzCase, app: &App) {
    if case.input.size <= 2 {
        return;
    }

    let off_start = mangle_get_offset(case);
    let mut len = mangle_len_left(case, off_start);
    if len == 0 {
        return;
    }

    if case.rand.next() % 16 != 0 {
        len = mangle_get_len(&mut case.rand, len.min(16));
    } else {
        len = mangle_get_len(&mut case.rand, len);
    }

    let off_end = off_start + len;
    let len_to_move = case.input.size - off_end;

    mangle_move(case, off_end, off_start, len_to_move);
    case.set_input_size(case.input.size - len, &app.config);
}

fn mangle_ascii_num(case: &mut FuzzCase, app: &App) {
    let mut len = case.rand.random_in(2..8) as usize;

    let num_string = format!("{}", case.rand.next());
    len = len.min(num_string.len());

    mangle_use_value(case, &num_string.as_bytes()[..len], app)
}

fn mangle_ascii_num_change(case: &mut FuzzCase, app: &App) {
    let off = mangle_get_offset(case);

    // Find a digit
    let index = match case.input.data[off..case.input.size]
        .iter()
        .position(|byte| byte.is_ascii_digit())
        .map(|position| position + off)
    {
        Some(index) => index,
        None => return,
    };

    // Compute left len
    let left = case.input.size - off;
    if left == 0 {
        return;
    }

    let mut len = 0;
    let mut val: usize = 0;

    for i in 0..left.min(20) {
        let c = case.input.data[off + i];
        if !c.is_ascii_digit() {
            break;
        }
        val *= 10;
        val += c as usize - '0' as usize;
        len += 1;
    }

    match case.rand.random_in(0..8) {
        0 => val += 1,
        1 => val -= 1,
        2 => val *= 2,
        3 => val /= 2,
        4 => val = case.rand.next() as usize,
        5 => val += case.rand.random_in(1..256) as usize,
        6 => val -= case.rand.random_in(1..256) as usize,
        7 => val = !val,
        _ => unimplemented!(),
    }

    let data = format!("{}", val);
    mangle_use_value_at(case, off, data.as_bytes(), app)
}

fn mangle_splice(case: &mut FuzzCase, app: &App) {
    let data = input::get_random_input(app);
    if data.len() == 0 {
        mangle_bytes(case, app);
        return;
    }

    let remote_off = mangle_get_len(&mut case.rand, data.len()) - 1;
    let len = mangle_get_len(&mut case.rand, data.len() - remote_off);
    mangle_use_value(case, &data[remote_off..remote_off + len], app);
}

fn mangle_resize(case: &mut FuzzCase, app: &App) {
    let old_size = case.input.size as u64;

    let choice = case.rand.random_in(0..32);
    let mut new_size = match choice {
        /* Set new size arbitrarily */
        0 => case
            .rand
            .random_in(1..app.config.app_config.max_input_size as u64),
        /* Increase size by a small value */
        1..=4 => case.rand.random_in(0..8),
        /* Increase size by a larger value */
        5 => case.rand.random_in(9..120),
        /* Decrease size by a small value */
        6..=9 => old_size - case.rand.random_in(0..8),
        /* Decrease size by a larger value */
        10 => old_size - case.rand.random_in(9..128),
        /* Do nothing */
        11..=32 => old_size,
        _ => unimplemented!(),
    };

    new_size = new_size.clamp(1, app.config.app_config.max_input_size as u64);
    case.set_input_size(new_size as usize, &app.config);

    if new_size > old_size {
        if app.config.app_config.random_ascii {
            for b in case.input.data[old_size as usize..(new_size - old_size) as usize].iter_mut() {
                *b = ' ' as u8;
            }
        }
    }
}

pub fn mangle_content(case: &mut FuzzCase, speed_factor: isize, app: &App) {
    let mangle_funcs = [
        mangle_shrink,
        mangle_shrink,
        mangle_shrink,
        mangle_shrink,
        mangle_expand,
        mangle_bit,
        mangle_inc_byte,
        mangle_dec_bytes,
        mangle_neg_bytes,
        mangle_add_sub,
        mangle_memset,
        mangle_memclear,
        mangle_mem_swap,
        mangle_mem_copy,
        mangle_bytes,
        mangle_ascii_num,
        mangle_ascii_num_change,
        mangle_byte_repeat_overwrite,
        mangle_byte_repeat_insert,
        mangle_magic,
        mangle_static_dict,
        mangle_const_feedback_dict,
        mangle_random_overwrite,
        mangle_random_insert,
        mangle_splice,
    ];

    if case.mutations_per_run == 0 {
        return;
    }

    if case.input.size == 0 {
        mangle_resize(case, app);
    }

    let mut change_count = app.config.app_config.mutation_per_run;

    if speed_factor < 5 {
        change_count = case.rand.random_in(1..change_count as u64) as usize;
    } else if speed_factor > 10 {
        change_count = core::cmp::min(speed_factor as usize, 12);
        change_count = core::cmp::max(change_count, app.config.app_config.mutation_per_run);
    }

    if app.metrics.start_instant.elapsed().as_secs() as usize
        - app.metrics.last_cov_update.load(Ordering::Relaxed)
        > 5
    {
        if case.rand.random_bool() {
            mangle_splice(case, app);
        }
    }

    for x in 0..change_count {
        let choice = case.rand.random_in(0..(mangle_funcs.len() - 1) as u64) as usize;
        println!("Mangle in {}", choice);
        let choice = 6;
        mangle_funcs[choice](case, app);
    }
}
