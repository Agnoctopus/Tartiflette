//! Memory management

use bits::Alignement;
use paging::{self, FrameAllocator, PageTable, VirtAddr, VirtRange};

/// Virtual machine physical memory
pub struct VMPhysMem {
    /// Point to the start of the physical memory
    raw_data: *mut u8,
    /// Size of the physical memory
    size: usize,
    /// Top offset of the heap allocation
    top: usize,
}

impl VMPhysMem {
    /// Create a new instance of `VmPhysMem`
    pub fn new(memory_size: usize) -> Option<Self> {
        // Align size
        let size = memory_size.align_power2(paging::PAGE_SIZE);

        // Create the physical memory area
        let raw_data = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            ) as *mut u8
        };

        // Failed to mmap
        if raw_data.is_null() {
            return None;
        }

        Some(Self {
            raw_data: raw_data,
            size: size,
            top: 0,
        })
    }

    /// Read a value from an address
    #[inline]
    pub fn read_val<T>(&self, pa: usize) -> T {
        assert!(pa + core::mem::size_of::<T>() <= self.size);

        unsafe {
            let val_ptr = self.raw_data.offset(pa as isize) as *const T;
            val_ptr.read()
        }
    }

    /// Write a value to an address
    #[inline]
    pub fn write_val<T>(&self, pa: usize, val: T) {
        assert!(pa + core::mem::size_of::<T>() <= self.size);

        unsafe {
            let val_ptr = self.raw_data.offset(pa as isize) as *mut T;
            val_ptr.write(val);
        }
    }

    /// Read bytes from an address
    #[inline]
    pub fn read(&self, pa: usize, output: &mut [u8]) {
        assert!(pa + output.len() <= self.size);

        let pdata =
            unsafe { std::slice::from_raw_parts(self.raw_data.offset(pa as isize), output.len()) };

        output.copy_from_slice(pdata);
    }

    /// Write bytes to an address
    #[inline]
    pub fn write(&mut self, pa: usize, input: &[u8]) {
        assert!(pa + input.len() <= self.size);

        let pdata = unsafe {
            std::slice::from_raw_parts_mut(self.raw_data.offset(pa as isize), input.len())
        };

        pdata.copy_from_slice(input);
    }
}

/// Bump allocator
impl FrameAllocator for VMPhysMem {
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

/// Virtual machine memory manager
pub struct VMMemory {
    /// Physical memory of the VM
    pmem: VMPhysMem,
    /// Current page_directory
    page_directory: usize,
}

const PAGE_SIZE: usize = 0x1000;

impl VMMemory {
    /// Create a new `VMMemory instance`
    pub fn new(memory_size: usize) -> Option<VMMemory> {
        assert!(
            memory_size >= PAGE_SIZE,
            "Memory size must be at least a page"
        );

        // Create the physical memory manager
        let mut pmem = VMPhysMem::new(memory_size).expect("Could not allocate physical memory");

        // Setup the page directory
        let page = pmem
            .allocate_frame()
            .expect("Could not allocate page directory");
        pmem.write(page, &[0; PAGE_SIZE]);

        Some(VMMemory {
            pmem: pmem,
            page_directory: page,
        })
    }

    /// Map a page to a frame
    fn map_page(&mut self, addr: VirtAddr) {
        let p4 = PageTable::from_addr(self.pmem.raw_data as usize);
        let p3 = p4.next_table_create(addr.p4_index(), &mut self.pmem);
        let p2 = p3.next_table_create(addr.p3_index(), &mut self.pmem);
        let p1 = p2.next_table_create(addr.p2_index(), &mut self.pmem);

        assert!(p1.entries[addr.p1_index()].unused(), "Page already mapped");

        let frame = self.pmem.allocate_frame().expect("Could not allocate page");

        // Set p1 entry
        p1.entries[addr.p1_index()].set_address(frame as u64);
        p1.entries[addr.p1_index()].set_writable(true);
        p1.entries[addr.p1_index()].set_present(true);
    }

    /// Map virtual memory area
    pub fn mmap(&mut self, addr: VirtAddr, size: usize) {
        assert!(addr.aligned(), "Page address must be aligned");

        // Compute pages range
        let start = addr;
        let end = VirtAddr::new(start.address() + size as u64);
        let pages = VirtRange::new(start, end);

        // Loop through pages to map
        for page in pages {
            self.map_page(page);
        }
    }

    /*
     * TODO: Provide write/read functions
     */
}

#[cfg(test)]
mod tests {
    use super::{VMMemory, PAGE_SIZE};
    use paging::VirtAddr;

    #[test]
    fn test_alloc_single() {
        let mut vm = VMMemory::new(512 * PAGE_SIZE).expect("Could not create VmMemory");

        vm.mmap(VirtAddr::new(0x1337000), PAGE_SIZE);
    }

    #[test]
    fn test_alloc_multiple() {
        let mut vm = VMMemory::new(512 * PAGE_SIZE).expect("Could not create VmMemory");

        vm.mmap(VirtAddr::new(0x1337000), PAGE_SIZE * 1);
        vm.mmap(VirtAddr::new(0x1000), PAGE_SIZE * 1);
    }
}
