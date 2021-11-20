//! Virtual Memory Subsystem

use super::paging::{
    FrameAllocator, PagePermissions, PageTable, PageTableEntry, VirtAddr, VirtRange,
};
use super::phys::PhysicalMemory;
use super::{MemoryError, Result, PAGE_SIZE};

use std::cmp::min;

/// Virtual machine memory manager
#[derive(Debug)]
pub struct VirtualMemory {
    /// Physical memory of the VM
    pub(crate) pmem: PhysicalMemory,
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
        let frame = pmem
            .allocate_frame()
            .expect("Could not allocate page directory");
        pmem.write(frame, &[0; PAGE_SIZE])?;

        Ok(VirtualMemory {
            pmem: pmem,
            page_directory: frame,
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

        // Get a frame to map page to
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

    /// Writes a passed value to memory
    #[inline]
    pub fn write_val<T>(&mut self, address: u64, val: T) -> Result<()> {
        let slice = unsafe {
            std::slice::from_raw_parts(&val as *const T as *const u8, core::mem::size_of::<T>())
        };

        self.write(address, slice)
    }

    /// Reads a given value from memory
    #[inline]
    pub fn read_val<T>(&self, address: u64) -> Result<T> {
        // TODO: Find a better way of doing this
        let mut bytes: Vec<u8> = vec![0; core::mem::size_of::<T>()];
        self.read(address, bytes.as_mut_slice())?;

        let result = bytes.as_ptr() as *const T;

        Ok(unsafe { result.read() })
    }

    /// Returns the page directory virtual address
    #[inline]
    pub fn page_directory(&self) -> usize {
        self.page_directory
    }

    /// Returns the host starting address for guest memory
    #[inline]
    pub fn host_address(&self) -> u64 {
        self.pmem.host_address() as u64
    }

    /// Returns the host allocated size for guest memory
    #[inline]
    pub fn host_memory_size(&self) -> usize {
        self.pmem.size()
    }

    /// Returns an iterator over all mappings
    #[inline]
    pub fn mappings(&self) -> impl Iterator<Item = Mapping> + '_ {
        PageIterator::new(&self).map(|(addr, page)| Mapping {
            address: addr,
            size: PAGE_SIZE,
            dirty: page.dirty(),
        })
    }

    /// Returns a raw mutable Iterator over present PageTableEntries
    #[inline]
    pub fn raw_pages_mut(&mut self) -> impl Iterator<Item = (u64, &mut PageTableEntry)> + '_ {
        PageIteratorMut::new(self)
    }
}

/// Memory mapping inside the VirtualMemory
#[derive(Debug, Copy, Clone)]
pub struct Mapping {
    /// Address of the mapping
    pub address: u64,
    /// Size of the page (here hardcoded to 4k)
    pub size: usize,
    /// Is mapping dirty
    pub dirty: bool,
}

/// Iterator over all page table entries inside VirtualMemory (immutable)
struct PageIterator<'a> {
    l4_index: usize,
    l3_index: usize,
    l2_index: usize,
    l1_index: usize,
    memory: &'a VirtualMemory,
}

impl<'a> PageIterator<'a> {
    pub fn new(mem: &VirtualMemory) -> PageIterator {
        PageIterator {
            l4_index: 0,
            l3_index: 0,
            l2_index: 0,
            l1_index: 0,
            memory: mem,
        }
    }
}

impl<'a> Iterator for PageIterator<'a> {
    type Item = (u64, &'a PageTableEntry);

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: Please find a cleaner way of doing this
        let p4 = PageTable::from_addr(self.memory.pmem.translate(self.memory.page_directory));

        for l4 in self.l4_index..512 {
            if let Some(p3) = p4.next_table(l4, &self.memory.pmem) {
                for l3 in self.l3_index..512 {
                    if let Some(p2) = p3.next_table(l3, &self.memory.pmem) {
                        for l2 in self.l2_index..512 {
                            if let Some(p1) = p2.next_table(l2, &self.memory.pmem) {
                                for l1 in self.l1_index..512 {
                                    self.l1_index += 1;

                                    if p1.entries[l1].present() {
                                        let vaddr = VirtAddr::forge(l4, l3, l2, l1, 0);
                                        return Some((vaddr.address(), &p1.entries[l1]));
                                    }
                                }
                            }
                            self.l1_index = 0;
                            self.l2_index += 1;
                        }
                    }
                    self.l2_index = 0;
                    self.l3_index += 1;
                }
            }
            self.l3_index = 0;
            self.l4_index += 1;
        }

        None
    }
}

/// Mutable version
struct PageIteratorMut<'a> {
    l4_index: usize,
    l3_index: usize,
    l2_index: usize,
    l1_index: usize,
    memory: &'a mut VirtualMemory,
}

impl<'a> PageIteratorMut<'a> {
    pub fn new(mem: &mut VirtualMemory) -> PageIteratorMut {
        PageIteratorMut {
            l4_index: 0,
            l3_index: 0,
            l2_index: 0,
            l1_index: 0,
            memory: mem,
        }
    }
}

impl<'a> Iterator for PageIteratorMut<'a> {
    type Item = (u64, &'a mut PageTableEntry);

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: Please find a cleaner way of doing this
        let p4 = PageTable::from_addr(self.memory.pmem.translate(self.memory.page_directory));

        for l4 in self.l4_index..512 {
            if let Some(p3) = p4.next_table(l4, &self.memory.pmem) {
                for l3 in self.l3_index..512 {
                    if let Some(p2) = p3.next_table(l3, &self.memory.pmem) {
                        for l2 in self.l2_index..512 {
                            if let Some(p1) = p2.next_table(l2, &self.memory.pmem) {
                                for l1 in self.l1_index..512 {
                                    self.l1_index += 1;

                                    if p1.entries[l1].present() {
                                        let vaddr = VirtAddr::forge(l4, l3, l2, l1, 0);
                                        return Some((vaddr.address(), &mut p1.entries[l1]));
                                    }
                                }
                            }
                            self.l1_index = 0;
                            self.l2_index += 1;
                        }
                    }
                    self.l2_index = 0;
                    self.l3_index += 1;
                }
            }
            self.l3_index = 0;
            self.l4_index += 1;
        }

        None
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
