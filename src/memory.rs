use libc::mmap;
use paging::{self, FrameAllocator, PageTable, PageTableEntry, VirtAddr, VirtRange};

pub(crate) struct VmPhysmem {
    raw_data: *mut u8,
    size: usize,
    top: usize,
}

impl VmPhysmem {
    pub fn new(memory_size: usize) -> Option<VmPhysmem> {
        let size = (memory_size + 0xfff) & !0xfff;
        let buffer = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            ) as *mut u8
        };

        if buffer.is_null() {
            return None;
        }

        Some(VmPhysmem {
            raw_data: buffer,
            size: size,
            top: 0,
        })
    }

    pub fn read(&self, pa: usize, output: &mut [u8]) {
        assert!(pa < self.size && pa + output.len() <= self.size);

        let pdata =
            unsafe { std::slice::from_raw_parts(self.raw_data.offset(pa as isize), output.len()) };

        output.copy_from_slice(pdata);
    }

    pub fn write(&mut self, pa: usize, input: &[u8]) {
        assert!(pa < self.size && pa + input.len() <= self.size);

        let mut pdata = unsafe {
            std::slice::from_raw_parts_mut(self.raw_data.offset(pa as isize), input.len())
        };

        pdata.copy_from_slice(input);
    }
}

impl FrameAllocator for VmPhysmem {
    fn allocate_frame(&mut self) -> Option<usize> {
        if self.top >= self.size {
            None
        } else {
            let result = self.top;
            self.top += PAGE_SIZE;
            Some(result + self.raw_data as usize)
        }
    }

    fn deallocate_frame(&mut self, frame_address: usize) {}
}

pub struct VmMemory {
    pmem: VmPhysmem,
    page_directory: usize,
}

const PAGE_SIZE: usize = 0x1000;

impl VmMemory {
    pub fn new(memory_size: usize) -> Option<VmMemory> {
        assert!(
            memory_size >= PAGE_SIZE,
            "Memory size must be at least a page"
        );
        let mut pmem = VmPhysmem::new(memory_size).expect("Could not allocate physical memory");
        let pg = pmem
            .allocate_frame()
            .expect(("Could not allocate page directory"));

        Some(VmMemory {
            pmem: pmem,
            page_directory: pg,
        })
    }

    fn map_page(&mut self, addr: VirtAddr) {
        let p4 = PageTable::from_addr(self.pmem.raw_data as usize);
        let p3 = p4.next_table_create(addr.p4_index(), &mut self.pmem);
        let p2 = p3.next_table_create(addr.p3_index(), &mut self.pmem);
        let p1 = p2.next_table_create(addr.p2_index(), &mut self.pmem);

        assert!(p1.entries[addr.p1_index()].unused());

        let frame_offset = self.pmem.allocate_frame().expect("Could not allocate page")
            - (self.pmem.raw_data as usize);

        p1.entries[addr.p1_index()].set_writable(true);
        p1.entries[addr.p1_index()].set_address(frame_offset as u64);
        p1.entries[addr.p1_index()].set_present(true);
    }

    pub fn mmap(&mut self, addr: VirtAddr, size: usize) {
        assert!(addr.aligned(), "Page address must be aligned");
        let mut start = addr;
        let mut end = VirtAddr::new(start.address() + size as u64);
        let pages = VirtRange::new(start, end);

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
    use super::{VmMemory, PAGE_SIZE};
    use paging::VirtAddr;

    #[test]
    fn test_alloc_single() {
        let mut vm = VmMemory::new(512 * PAGE_SIZE).expect("Could not create VmMemory");

        vm.mmap(VirtAddr::new(0x1337000), PAGE_SIZE);
    }

    #[test]
    fn test_alloc_multiple() {
        let mut vm = VmMemory::new(512 * PAGE_SIZE).expect("Could not create VmMemory");

        vm.mmap(VirtAddr::new(0x1337000), PAGE_SIZE * 1);
        vm.mmap(VirtAddr::new(0x1000), PAGE_SIZE * 1);
    }
}
