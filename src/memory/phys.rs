use super::paging::FrameAllocator;
use super::MemoryError;
use super::{Result, PAGE_SIZE};
use crate::utils::bits::Alignement;

/// Virtual machine physical memory
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

        // Create the physical memory area
        let raw_data = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                -1,
                0,
            ) as *mut u8
        };

        // Failed to mmap
        if raw_data.is_null() {
            return Err(MemoryError::PhysmemAlloc);
        }

        Ok(Self {
            raw_data: raw_data,
            size: size,
            top: 0,
        })
    }

    /// Return the guest physical region start address
    pub fn guest_address(&self) -> usize {
        0
    }

    /// Return the host region start address
    pub fn host_address(&self) -> usize {
        self.raw_data as usize
    }

    /// Return the total size of the region
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the amount of memory used inside the region
    pub fn used(&self) -> usize {
        self.top
    }

    pub fn raw_slice(&self, pa: usize, length: usize) -> Result<&[u8]> {
        if pa + length > self.size() {
            Err(MemoryError::PhysReadOutOfBounds(pa as u64, length))
        } else {
            Ok(unsafe { std::slice::from_raw_parts(self.raw_data.offset(pa as isize), length) })
        }
    }

    pub fn raw_slice_mut(&mut self, pa: usize, length: usize) -> Result<&mut [u8]> {
        if pa + length > self.size() {
            Err(MemoryError::PhysReadOutOfBounds(pa as u64, length))
        } else {
            Ok(
                unsafe {
                    std::slice::from_raw_parts_mut(self.raw_data.offset(pa as isize), length)
                },
            )
        }
    }

    /// Read a value from an address
    #[inline]
    pub fn read_val<T>(&self, pa: usize) -> Result<T> {
        let read_size = core::mem::size_of::<T>();

        if pa + read_size > self.size {
            return Err(MemoryError::PhysReadOutOfBounds(pa as u64, read_size));
        }

        let val = unsafe {
            let val_ptr = self.raw_data.offset(pa as isize) as *const T;
            val_ptr.read()
        };
        Ok(val)
    }

    /// Write a value to an address
    #[inline]
    pub fn write_val<T>(&self, pa: usize, val: T) -> Result<()> {
        let write_size = core::mem::size_of::<T>();

        if pa + write_size > self.size {
            return Err(MemoryError::PhysWriteOutOfBounds(pa as u64, write_size));
        }

        unsafe {
            let val_ptr = self.raw_data.offset(pa as isize) as *mut T;
            val_ptr.write(val);
        };
        Ok(())
    }

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
