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
    pub fn raw_slice(&self, pa: usize, length: usize) -> Result<&[u8]> {
        if pa + length > self.size() {
            return Err(MemoryError::PhysReadOutOfBounds(pa as u64, length));
        }

        Ok(unsafe { std::slice::from_raw_parts(self.raw_data.offset(pa as isize), length) })
    }

    ///// Returns a mutable slice covering a requested area
    //pub fn raw_slice_mut(&mut self, pa: usize, length: usize) -> Result<&mut [u8]> {
    //    if pa + length > self.size() {
    //        return Err(MemoryError::PhysReadOutOfBounds(pa as u64, length));
    //    }

    //    Ok(unsafe { std::slice::from_raw_parts_mut(self.raw_data.offset(pa as isize), length) })
    //}

    /// Read bytes from an address
    #[inline]
    pub fn read(&self, pa: usize, output: &mut [u8]) -> Result<()> {
        if pa + output.len() > self.size {
            return Err(MemoryError::PhysReadOutOfBounds(pa as u64, output.len()));
        }

        let pdata =
            unsafe { std::slice::from_raw_parts(self.raw_data.offset(pa as isize), output.len()) };
        output.copy_from_slice(pdata);
        Ok(())
    }

    /// Write bytes to an address
    #[inline]
    pub fn write(&mut self, pa: usize, input: &[u8]) -> Result<()> {
        if pa + input.len() > self.size {
            return Err(MemoryError::PhysWriteOutOfBounds(pa as u64, input.len()));
        }

        let pdata = unsafe {
            std::slice::from_raw_parts_mut(self.raw_data.offset(pa as isize), input.len())
        };
        pdata.copy_from_slice(input);
        Ok(())
    }

    /// Returns a copy of the physical memory
    pub fn clone(&self) -> Result<Self> {
        let mut pmem = PhysicalMemory::new(self.size)?;

        // Copy old data
        let old_data = self.raw_slice(0, self.size())?;
        pmem.write(0, old_data)?;
        pmem.top = self.top;

        Ok(pmem)
    }
}

/// Bump allocator
impl FrameAllocator for PhysicalMemory {
    #[inline]
    /// Allocate a frame
    fn allocate_frame(&mut self) -> Option<usize> {
        if self.top >= self.size {
            None
        } else {
            let address = self.top;

            // Bump the heap top
            self.top += PAGE_SIZE;

            Some(address)
        }
    }

    #[inline]
    /// Deallocate a frame
    fn deallocate_frame(&mut self, _frame_address: usize) {}

    #[inline]
    // Translate a frame address to its virtual address
    fn translate(&self, frame_address: usize) -> usize {
        self.raw_data as usize + frame_address
    }
}

impl Drop for PhysicalMemory {
    fn drop(&mut self) {
        unsafe { munmap(self.raw_data.cast(), self.size).unwrap() }
    }
}
