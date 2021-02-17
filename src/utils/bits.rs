//! Bits manipulations utils

#![warn(missing_docs)]

use core::ops::{Bound, Range, RangeBounds};

/// Trait for bits operations
pub trait BitField {
    /// Number of bits
    const BIT_NUM: usize;

    /// Returns whether or not a bit is set
    fn is_bit_set(&self, bit: usize) -> bool;

    /// Set the value of a bit
    fn set_bit(&mut self, bit: usize, value: bool);

    /// Returns bits
    fn get_bits<T: RangeBounds<usize>>(&self, range: T) -> Self;

    /// Set the values of bits
    fn set_bits<T: RangeBounds<usize>>(&mut self, range: T, value: Self);
}

macro_rules! bitfield_impl {
    ($($t:ty)*) => ($(
            impl BitField for $t {
                const BIT_NUM: usize = 8 * core::mem::size_of::<Self>() as usize;

                #[inline]
                fn is_bit_set(&self, bit: usize) -> bool {
                    assert!(bit < Self::BIT_NUM);

                    (*self & (1 << bit)) != 0
                }

                #[inline]
                fn set_bit(&mut self, bit: usize, value: bool) {
                    assert!(bit < Self::BIT_NUM);

                    match value {
                        true => *self |= 1 << bit,
                        false => *self &= !(1 << bit),
                    }
                }

                #[inline]
                fn set_bits<T: RangeBounds<usize>>(&mut self, range: T, value: Self) {
                    let range = concrete_range(&range, Self::BIT_NUM);

                    assert! (range.start <= Self::BIT_NUM);
                    assert! (range.end <= Self::BIT_NUM);

                    if (range.start == range.end) {
                        assert!(false);
                        return;
                    }

                    let range_len = range.end - range.start;
                    let mut shifted_value = value;
                    shifted_value <<= (Self::BIT_NUM - range_len);
                    shifted_value >>= (Self::BIT_NUM - range_len);
                    assert!(shifted_value == value);

                    let mut bitmask = !0;
                    bitmask <<= (Self::BIT_NUM - range.end);
                    bitmask >>= (Self::BIT_NUM - range.end);
                    bitmask >>= range.start;
                    bitmask <<= range.start;
                    bitmask = !bitmask;

                    *self = (*self & bitmask) | (value << range.start);
                }

                #[inline]
                fn get_bits<T:RangeBounds<usize>>(&self, range: T) -> Self {
                    let range = concrete_range(&range, Self::BIT_NUM);

                    assert! (range.start <= Self::BIT_NUM);
                    assert! (range.end <= Self::BIT_NUM);

                    let mut value = *self;
                    value <<= (Self::BIT_NUM - range.end);
                    value >>= (Self::BIT_NUM - range.end);
                    value >>= range.start;

                    value
                }
            }
    )*)
}

bitfield_impl! { u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize }

/// Trait for bits alignements
pub trait Alignement {
    /// Align to a power of 2
    fn align_power2(&self, align: Self) -> Self;

    /// Align up to a power of 2
    fn align_up_power2(&self, align: Self) -> Self;

    /// Returns whether or not it is align to a power of 2
    fn is_align_power2(&self, align: Self) -> bool;
}

macro_rules! alignement_impl {
    ($($t:ty)*) => ($(
            impl Alignement for $t {

                #[inline]
                fn align_power2 (&self, align: Self) -> Self
                {
                    *self & !(align - 1)
                }

                #[inline]
                fn align_up_power2 (&self, align: Self) -> Self
                {
                    (*self + align - 1) & !(align - 1)
                }

                #[inline]
                fn is_align_power2 (&self, align: Self) -> bool
                {
                    self.align_power2(align) == *self
                }
    })*)
}

alignement_impl! { u8 u16 u32 u64 u128 usize i8 i16 i32 i64 i128 isize }

/// Convert a bound to an index
fn bound_to_index(bound: Bound<&usize>, limit: usize, left: bool) -> usize {
    match left {
        true => match bound {
            Bound::Excluded(&value) => value + 1,
            Bound::Included(&value) => value,
            Bound::Unbounded => limit,
        },
        false => match bound {
            Bound::Excluded(&value) => value,
            Bound::Included(&value) => value + 1,
            Bound::Unbounded => limit,
        },
    }
}

/// Convert an abstract range to a concrete one
fn concrete_range<T: RangeBounds<usize>>(range: &T, max: usize) -> Range<usize> {
    // Retrieve the bounds index
    let start = bound_to_index(range.start_bound(), 0, true);
    let end = bound_to_index(range.end_bound(), max, false);

    start..end
}
