//! Memory management

use std::cmp::min;

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
    pub fn mmap(&mut self, addr: u64, size: usize) {
        // Compute pages range
        let start = VirtAddr::new(addr);
        assert!(start.aligned(), "Page address must be aligned");

        let end = VirtAddr::new(start.address() + size as u64);
        let pages = VirtRange::new(start, end);

        // Loop through pages to map
        for page in pages {
            self.map_page(page);
        }
    }

    /// Returns the physical address of a page. Or nothing if the address is not mapped.
    fn get_page_pa(&self, address: VirtAddr) -> Option<usize> {
        let p4 = PageTable::from_addr(self.pmem.translate(self.page_directory));
        let p3 = p4.next_table(address.p4_index(), &self.pmem)?;
        let p2 = p3.next_table(address.p3_index(), &self.pmem)?;
        let p1 = p2.next_table(address.p2_index(), &self.pmem)?;

        p1.next_table_address(address.p1_index())
    }

    /// Returns whether a given `VirtAddr` is mapped into the address space
    fn is_mapped(&self, address: VirtAddr) -> bool {
        self.get_page_pa(address).is_some()
    }

    /// Reads data from the virtual address space
    pub fn read(&self, addr: u64, output: &mut [u8]) {
        // Compute the range of pages between VA and VA + read_size
        let start = VirtAddr::new(addr);
        let end = VirtAddr::new(addr + output.len() as u64);
        let pages = VirtRange::new(start, end);

        let mut index = 0;
        let mut page_off = addr & (PAGE_SIZE as u64 - 1);

        // Loop through pages to read
        for page in pages {
            // Get physical page for given VA
            let pa = self.get_page_pa(page).expect("Trying to read from unmapped page");

            let remaining_bytes = (output.len() - index) as u64;
            // TODO page.address() ? Sure ?
            let page_bytes = (page.address() + PAGE_SIZE as u64) - page_off;
            let bytes_to_copy = min(remaining_bytes, page_bytes);

            // Partial read into the slice
            self.pmem.read(
                pa + page_off as usize,
                &mut output[index..index + bytes_to_copy as usize],
            );

            // Update cursor
            page_off = 0;
            index += bytes_to_copy as usize;
        }
    }

    /// Writes data to the virtual address space
    pub fn write(&mut self, addr: u64, input: &[u8]) {
        // Compute the range of pages between VA and VA + read_size
        let start = VirtAddr::new(addr);
        let end = VirtAddr::new(addr + input.len() as u64);
        let pages = VirtRange::new(start, end);

        let mut index = 0;
        let mut page_off = addr & (PAGE_SIZE as u64 - 1);

        // Loop through pages to read
        for page in pages {
            // Get physical page for given VA
            let pa = self.get_page_pa(page).expect("Trying to write from unmapped page");

            let remaining_bytes = (input.len() - index) as u64;
            // TODO page.address() ? Sure ?
            let page_bytes = (page.address() + PAGE_SIZE as u64) - page_off;
            let bytes_to_copy = min(remaining_bytes, page_bytes);

            // Partial write from the slice
            self.pmem.write(
                pa + page_off as usize,
                &input[index..index + bytes_to_copy as usize],
            );

            // Update cursor
            page_off = 0;
            index += bytes_to_copy as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{VMMemory, PAGE_SIZE};
    use paging::VirtAddr;

    #[test]
    fn test_alloc_single() {
        let mut vm = VMMemory::new(512 * PAGE_SIZE).expect("Could not create VmMemory");

        vm.mmap(0x1337000, PAGE_SIZE);
    }

    #[test]
    fn test_alloc_multiple() {
        let mut vm = VMMemory::new(512 * PAGE_SIZE).expect("Could not create VmMemory");

        vm.mmap(0x1337000, PAGE_SIZE * 1);
        vm.mmap(0x1000, PAGE_SIZE * 1);
    }

    #[test]
    fn test_write_simple() {
        let mut vm = VMMemory::new(512 * PAGE_SIZE).expect("Could not allocate Vm memory");

        vm.mmap(0x1337000, PAGE_SIZE);

        let magic: [u8; 4] = [0x41, 0x42, 0x43, 0x44];
        let mut magic_result: [u8; 4] = [0; 4];

        vm.write(0x1337444, &magic);
        vm.read(0x1337444, &mut magic_result);

        assert_eq!(magic, magic_result, "Read after write failed");
    }

    #[test]
    fn test_write_cross_page() {
        let mut vm = VMMemory::new(512 * PAGE_SIZE).expect("Could not allocate Vm memory");
        vm.mmap(0x1337000, PAGE_SIZE * 2);

        let magic: [u8; 4] = [0x41, 0x42, 0x43, 0x44];
        let mut magic_result: [u8; 4] = [0; 4];

        vm.write(0x1337ffd, &magic);
        vm.read(0x1337ffd, &mut magic_result);

        assert_eq!(magic, magic_result, "Read after write failed");
    }

    #[test]
    fn test_write_huge() {
        let mut vm = VMMemory::new(6 * PAGE_SIZE).expect("Could not allocate Vm memory");
        vm.mmap(0x1338000, PAGE_SIZE);
        vm.mmap(0x1337000, PAGE_SIZE);

        let magic: [u8; 2*PAGE_SIZE] = [0x42; 2 * PAGE_SIZE];
        let mut magic_result: [u8; 2*PAGE_SIZE] = [0u8; 2 * PAGE_SIZE];

        vm.write(0x1337000, &magic);
        vm.read(0x1337000, &mut magic_result);

        assert_eq!(magic, magic_result, "Read after write failed");
    }
}
