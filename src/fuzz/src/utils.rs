pub fn log2(val: usize) -> isize {
    (core::mem::size_of::<isize>() * 8) as isize - val.leading_zeros() as isize - 1
}
