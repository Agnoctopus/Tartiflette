//! Virtual Memory Subsystem

use super::paging::{FrameAllocator, PagePermissions, PageTable, VirtAddr, VirtRange};
use super::phys::PhysicalMemory;
use super::{MemoryError, Result, PAGE_SIZE};

use std::cmp::min;

/// Virtual machine memory manager
#[derive(Debug)]
pub struct VirtualMemory {
    /// Physical memory of the VM
    pmem: PhysicalMemory,
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

        // Get a frame to map page to
        let frame = self.pmem.allocate_frame().ok_or(MemoryError::OutOfMemory)?;
        println!("address: {:x} to frame: {:x}", addr.address(), frame);

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
    #[inline]
    pub fn is_mapped(&self, address: VirtAddr) -> bool {
        self.get_page_pa(address).is_some()
    }

    /// Returns the physical address of a page if it exists
    #[inline]
    fn pa(&self, addr: u64) -> Option<u64> {
        self.get_page_pa(VirtAddr::new(addr)).map(|x| x as u64)
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
    pub fn write_val<T>(&mut self, address: u64, val: T) -> Result<()> {
        let slice = unsafe {
            std::slice::from_raw_parts(&val as *const T as *const u8, core::mem::size_of::<T>())
        };

        self.write(address, slice)
    }

    /// Reads a given value from memory
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

    /// Returns a copy of the `VirtualMemory`
    pub fn clone(&self) -> Result<Self> {
        let pmem = self.pmem.clone()?;

        Ok(VirtualMemory {
            pmem: pmem,
            page_directory: self.page_directory,
        })
    }

    /// Returns the host starting address for guest memory
    pub fn host_address(&self) -> u64 {
        self.pmem.host_address() as u64
    }

    /// Returns the host allocated size for guest memory
    pub fn host_memory_size(&self) -> usize {
        self.pmem.size()
    }

    /// Returns an iterator over all mappings
    pub fn mappings(&self) -> impl Iterator<Item=Mapping> + '_ {
        MappingIterator::new(&self)
    }
}

#[derive(Debug, Copy, Clone)]
/// Memory mapping inside the VirtualMemory
pub struct Mapping {
    /// Address of the mapping
    pub address: u64,
    /// Size of the page (here hardcoded to 4k)
    pub size: usize,
    /// Is mapping dirty
    pub dirty: bool
}

/// Iterator over all mappings inside VirtualMemory
struct MappingIterator<'a> {
    l4_index: usize,
    l3_index: usize,
    l2_index: usize,
    l1_index: usize,
    memory: &'a VirtualMemory
}

impl<'a> MappingIterator<'a> {
    pub fn new(mem: &VirtualMemory) -> MappingIterator {
        MappingIterator {
            l4_index: 0,
            l3_index: 0,
            l2_index: 0,
            l1_index: 0,
            memory: mem
        }
    }
}

impl<'a> Iterator for MappingIterator<'a> {
    type Item = Mapping;

    fn next(&mut self) -> Option<Mapping> {
        // TODO: Fix this ugly function somehow
        let root = PageTable::from_addr(self.memory.pmem.translate(self.memory.page_directory));

        for l4 in self.l4_index..512 {
            let p3 = root.next_table(l4, &self.memory.pmem);

            if p3.is_none() {
                continue
            }

            let p3t = p3.unwrap();

            for l3 in self.l3_index..512 {
                let p2 = p3t.next_table(l3, &self.memory.pmem);

                if p2.is_none() {
                    continue
                }

                let p2t = p2.unwrap();

                for l2 in self.l2_index..512 {
                    let p1 = p2t.next_table(l2, &self.memory.pmem);

                    if p1.is_none() {
                        continue
                    }

                    let p1t = p1.unwrap();

                    for l1 in self.l1_index..512 {
                        if p1t.entries[l1].present() {
                            // Skip to next entry otherwise we will infinitely loop
                            self.l1_index += 1;

                            let vaddr = VirtAddr::forge(l4, l3, l2, l1, 0);

                            return Some(Mapping {
                                address: vaddr.address(),
                                size: PAGE_SIZE,
                                dirty: p1t.entries[l1].dirty()
                            });
                        }

                        self.l1_index += 1;
                    }

                    self.l1_index = 0;
                    self.l2_index += 1;
                }

                self.l2_index = 0;
                self.l3_index += 1;
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
