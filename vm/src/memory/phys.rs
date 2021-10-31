//! Physical Memory Subsystem

use super::paging::FrameAllocator;
use super::MemoryError;
use super::{Result, PAGE_SIZE};

use crate::bits::Alignement;
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};

/// Virtual machine physical memory
#[derive(Debug)]
pub struct PhysicalMemory {
    /// Point to the start of the physical memory
    raw_data: *mut u8,
    /// Size of the physical memory
    size: usize,
    /// Top offset of the heap allocation
    top: usize,
}

impl PhysicalMemory {
    /// Create a new instance of `PhysicalMemory`
    pub fn new(memory_size: usize) -> Result<Self> {
        // Align size
        let size = memory_size.align_power2(PAGE_SIZE);

        // Mmap aligned requested size
        let raw_data = unsafe {
            mmap(
                core::ptr::null_mut(),
                size,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_PRIVATE,
                -1,
                0,
            )
        }
        .map_err(|_| MemoryError::PhysmemAlloc)?;

        Ok(Self {
            raw_data: raw_data as *mut u8,
            size: size,
            top: 0,
        })
    }

    /// Return the host region start address
    #[inline]
    pub fn host_address(&self) -> usize {
        self.raw_data as usize
    }

    /// Return the total size of the region
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns a slice covering an asked area
    #[inline]
    pub fn raw_slice(&self, pa: usize, length: usize) -> Result<&[u8]> {
        // Bound check access
        let end = pa.checked_add(length).ok_or(MemoryError::IntegerOverflow)?;
        if end > self.size() {
            return Err(MemoryError::PhysReadOutOfBounds(pa as u64, length));
        }
        if pa as isize > isize::MAX {
            return Err(MemoryError::IntegerOverflow);
        }

        // Get the slice
        let slice =
            unsafe { std::slice::from_raw_parts(self.raw_data.offset(pa as isize), length) };

        Ok(slice)
    }

    ///// Returns a mutable slice covering a requested area
    #[inline]
    pub fn raw_slice_mut(&mut self, pa: usize, length: usize) -> Result<&mut [u8]> {
        // Bound check access
        let end = pa.checked_add(length).ok_or(MemoryError::IntegerOverflow)?;
        if end > self.size() {
            return Err(MemoryError::PhysReadOutOfBounds(pa as u64, length));
        }
        if pa as isize > isize::MAX {
            return Err(MemoryError::IntegerOverflow);
        }

        // Get the slice
        let slice =
            unsafe { std::slice::from_raw_parts_mut(self.raw_data.offset(pa as isize), length) };

        Ok(slice)
    }

    /// Read bytes from an address
    #[inline]
    pub fn read(&self, pa: usize, output: &mut [u8]) -> Result<()> {
        // Get physical data slice
        let pdata = self.raw_slice(pa, output.len())?;

        // Copy from
        output.copy_from_slice(pdata);
        Ok(())
    }

    /// Write bytes to an address
    #[inline]
    pub fn write(&mut self, pa: usize, input: &[u8]) -> Result<()> {
        // Get physical data slice
        let pdata = self.raw_slice_mut(pa, input.len())?;

        // Copy to
        pdata.copy_from_slice(input);
        Ok(())
    }
}

/// Bump allocator
impl FrameAllocator for PhysicalMemory {
    /// Allocate a frame
    #[inline]
    fn allocate_frame(&mut self) -> Option<usize> {
        if self.top >= self.size {
            return None;
        }

        // Bump the heap top and return the last top
        let address = self.top;
        self.top += PAGE_SIZE;
        Some(address)
    }

    /// Deallocate a frame
    #[inline]
    fn deallocate_frame(&mut self, _frame_address: usize) {
        // TODO free capable allocator
    }

    // Translate a frame address to its virtual address
    #[inline]
    fn translate(&self, frame_address: usize) -> usize {
        self.raw_data as usize + frame_address
    }
}

impl Drop for PhysicalMemory {
    fn drop(&mut self) {
        unsafe { munmap(self.raw_data.cast(), self.size).unwrap() }
    }
}
