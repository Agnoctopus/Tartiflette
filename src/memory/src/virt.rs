use super::{
    paging::{FrameAllocator, PagePermissions, PageTable, VirtAddr, VirtRange},
    phys::PhysicalMemory,
    MemoryError, Result, PAGE_SIZE,
};
use std::cmp::min;

/// Virtual machine memory manager
pub struct VirtualMemory {
    /// Physical memory of the VM
    pub pmem: PhysicalMemory,
    /// Current page_directory
    page_directory: usize,
}

impl VirtualMemory {
    /// Create a new `VirtualMemory instance`
    pub fn new(memory_size: usize) -> Result<Self> {
        assert!(
            memory_size >= PAGE_SIZE,
            "Memory size must be at least a page"
        );

        // Create the physical memory manager
        let mut pmem = PhysicalMemory::new(memory_size)?;

        // Setup the page directory
        let page = pmem
            .allocate_frame()
            .expect("Could not allocate page directory");
        pmem.write(page, &[0; PAGE_SIZE])?;

        Ok(VirtualMemory {
            pmem: pmem,
            page_directory: page,
        })
    }

    /// Map a page to a frame
    fn map_page(&mut self, addr: VirtAddr, perms: PagePermissions) -> Result<()> {
        let p4 = PageTable::from_addr(self.pmem.translate(self.page_directory));
        let p3 = p4.next_table_create(addr.p4_index(), &mut self.pmem, perms);
        let p2 = p3.next_table_create(addr.p3_index(), &mut self.pmem, perms);
        let p1 = p2.next_table_create(addr.p2_index(), &mut self.pmem, perms);

        if !p1.entries[addr.p1_index()].unused() {
            return Err(MemoryError::AddressAlreadyMapped(addr.address()));
        }

        let frame = self.pmem.allocate_frame().ok_or(MemoryError::OutOfMemory)?;

        // Set p1 entry
        p1.entries[addr.p1_index()].set_address(frame as u64);
        p1.entries[addr.p1_index()].set_present(true);

        p1.entries[addr.p1_index()].set_writable(perms.writable());
        p1.entries[addr.p1_index()].set_executable(perms.executable());

        Ok(())
    }

    /// Map virtual memory area
    pub fn mmap(&mut self, addr: u64, size: usize, perms: PagePermissions) -> Result<()> {
        // Compute pages range
        let start = VirtAddr::new(addr);
        assert!(start.aligned(), "Page address must be aligned");

        let end = VirtAddr::new(start.address() + size as u64);
        let pages = VirtRange::new(start, end);

        // Loop through pages to map
        for page in pages {
            self.map_page(page, perms)?;
        }

        Ok(())
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
    pub fn is_mapped(&self, address: VirtAddr) -> bool {
        self.get_page_pa(address).is_some()
    }

    /// Reads data from the virtual address space
    pub fn read(&self, addr: u64, output: &mut [u8]) -> Result<()> {
        // Compute the range of pages between VA and VA + read_size
        let start = VirtAddr::new(addr);
        let end = VirtAddr::new(addr + output.len() as u64);
        let pages = VirtRange::new(start, end);

        let mut index = 0;
        let mut page_off = addr & (PAGE_SIZE as u64 - 1);

        // Loop through pages to read
        for page in pages {
            // Get physical page for given VA
            let pa = self
                .get_page_pa(page)
                .ok_or(MemoryError::AddressUnmapped(page.address()))?;

            let remaining_bytes = (output.len() - index) as u64;
            let page_bytes = PAGE_SIZE as u64 - page_off;
            let bytes_to_copy = min(remaining_bytes, page_bytes);

            // Partial read into the slice
            self.pmem.read(
                pa + page_off as usize,
                &mut output[index..index + bytes_to_copy as usize],
            )?;

            // Update cursor
            page_off = 0;
            index += bytes_to_copy as usize;
        }

        Ok(())
    }

    /// Writes data to the virtual address space
    pub fn write(&mut self, addr: u64, input: &[u8]) -> Result<()> {
        // Compute the range of pages between VA and VA + read_size
        let start = VirtAddr::new(addr);
        let end = VirtAddr::new(addr + input.len() as u64);
        let pages = VirtRange::new(start, end);

        let mut index = 0;
        let mut page_off = addr & (PAGE_SIZE as u64 - 1);

        // Loop through pages to read
        for page in pages {
            // Get physical page for given VA
            let pa = self
                .get_page_pa(page)
                .ok_or(MemoryError::AddressUnmapped(page.address()))?;

            let remaining_bytes = (input.len() - index) as u64;
            let page_bytes = PAGE_SIZE as u64 - page_off;
            let bytes_to_copy = min(remaining_bytes, page_bytes);

            // Partial write from the slice
            self.pmem.write(
                pa + page_off as usize,
                &input[index..index + bytes_to_copy as usize],
            )?;

            // Update cursor
            page_off = 0;
            index += bytes_to_copy as usize;
        }

        Ok(())
    }

    pub fn page_directory(&self) -> usize {
        self.page_directory
    }

    /// Returns a copy of the VAS
    pub fn clone(&self) -> Result<Self> {
        let pmem = self.pmem.clone()?;

        Ok(VirtualMemory {
            pmem: pmem,
            page_directory: self.page_directory,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{PagePermissions, Result};
    use super::{VirtualMemory, PAGE_SIZE};

    #[test]
    fn test_alloc_single() -> Result<()> {
        let mut vm = VirtualMemory::new(512 * PAGE_SIZE)?;
        let perms = PagePermissions::READ | PagePermissions::WRITE;

        vm.mmap(0x1337000, PAGE_SIZE, perms)?;

        Ok(())
    }

    #[test]
    fn test_alloc_multiple() -> Result<()> {
        let mut vm = VirtualMemory::new(512 * PAGE_SIZE)?;
        let perms = PagePermissions::READ | PagePermissions::WRITE;

        vm.mmap(0x1337000, PAGE_SIZE * 1, perms)?;
        vm.mmap(0x1000, PAGE_SIZE * 1, perms)?;

        Ok(())
    }

    #[test]
    fn test_write_simple() -> Result<()> {
        let mut vm = VirtualMemory::new(512 * PAGE_SIZE)?;
        let perms = PagePermissions::READ | PagePermissions::WRITE;

        vm.mmap(0x1337000, PAGE_SIZE, perms)?;

        let magic: [u8; 4] = [0x41, 0x42, 0x43, 0x44];
        let mut magic_result: [u8; 4] = [0; 4];

        vm.write(0x1337444, &magic)?;
        vm.read(0x1337444, &mut magic_result)?;

        assert_eq!(magic, magic_result, "Read after write failed");

        Ok(())
    }

    #[test]
    fn test_write_cross_page() -> Result<()> {
        let mut vm = VirtualMemory::new(512 * PAGE_SIZE)?;
        let perms = PagePermissions::READ | PagePermissions::WRITE;

        vm.mmap(0x1337000, PAGE_SIZE * 2, perms)?;

        let magic: [u8; 4] = [0x41, 0x42, 0x43, 0x44];
        let mut magic_result: [u8; 4] = [0; 4];

        vm.write(0x1337ffd, &magic)?;
        vm.read(0x1337ffd, &mut magic_result)?;

        assert_eq!(magic, magic_result, "Read after write failed");

        Ok(())
    }

    #[test]
    fn test_write_huge() -> Result<()> {
        let mut vm = VirtualMemory::new(6 * PAGE_SIZE).expect("Could not allocate Vm memory");
        let perms = PagePermissions::READ | PagePermissions::WRITE;

        vm.mmap(0x1338000, PAGE_SIZE, perms)?;
        vm.mmap(0x1337000, PAGE_SIZE, perms)?;

        let magic: [u8; 2 * PAGE_SIZE] = [0x42; 2 * PAGE_SIZE];
        let mut magic_result: [u8; 2 * PAGE_SIZE] = [0u8; 2 * PAGE_SIZE];

        vm.write(0x1337000, &magic)?;
        vm.read(0x1337000, &mut magic_result)?;

        assert_eq!(magic, magic_result, "Read after write failed");

        Ok(())
    }
}
