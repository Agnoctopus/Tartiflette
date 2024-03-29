//! Paging management system

#![warn(missing_docs)]

use crate::bits::BitField;
use core::ops::Range;

/// Page size
pub const PAGE_SIZE: usize = 0x1000;

/// Trait implemented by frames allocator
pub trait FrameAllocator {
    /// Allocate a frame
    fn allocate_frame(&mut self) -> Option<usize>;
    /// Deallocate a frame
    fn deallocate_frame(&mut self, frame_address: usize);
    /// Translate a frame address to its virtual address
    fn translate(&self, frame_address: usize) -> usize;
}

/// Page permissions
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PagePermissions(usize);

impl PagePermissions {
    /// The page is readable
    pub const READ: PagePermissions = PagePermissions(1 << 0);
    /// The page is writable
    pub const WRITE: PagePermissions = PagePermissions(1 << 1);
    /// The page is executable
    pub const EXECUTE: PagePermissions = PagePermissions(1 << 2);

    // Readble bit field
    const READ_BIT: usize = 0;
    // Writable bit field
    const WRITE_BIT: usize = 1;
    // Executable bit field
    const EXECUTE_BIT: usize = 2;

    /// Creates a new PagePermissions object
    pub fn new(flags: usize) -> PagePermissions {
        PagePermissions(flags)
    }

    /// Gets the read permission status
    #[inline]
    pub fn readable(&self) -> bool {
        self.0.is_bit_set(Self::READ_BIT)
    }

    /// Sets the read permission status
    #[inline]
    pub fn set_readable(&mut self, readable: bool) {
        self.0.set_bit(Self::READ_BIT, readable)
    }

    /// Gets the write permission status
    #[inline]
    pub fn writable(&self) -> bool {
        self.0.is_bit_set(Self::WRITE_BIT)
    }

    /// Sets the write permission status
    #[inline]
    pub fn set_writable(&mut self, writable: bool) {
        self.0.set_bit(Self::WRITE_BIT, writable)
    }

    /// Gets the execute permission status
    #[inline]
    pub fn executable(&self) -> bool {
        self.0.is_bit_set(Self::EXECUTE_BIT)
    }

    /// Sets the execute permission status
    #[inline]
    pub fn set_executable(&mut self, executable: bool) {
        self.0.set_bit(Self::EXECUTE_BIT, executable)
    }
}

impl core::ops::BitOr<PagePermissions> for PagePermissions {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: PagePermissions) -> Self::Output {
        Self::new(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign<PagePermissions> for PagePermissions {
    #[inline]
    fn bitor_assign(&mut self, rhs: PagePermissions) {
        *self = *self | rhs;
    }
}

/// Page Table
#[repr(align(4096))]
#[derive(Debug)]
pub struct PageTable {
    /// Page Table entries
    pub entries: [PageTableEntry; Self::NB_ENTRIES],
}

impl PageTable {
    /// Number of entries in a page table
    pub const NB_ENTRIES: usize = 512;

    /// Get the `PageTable` from an address, typically cr3 for the
    /// 4-level active page table.
    #[inline]
    pub fn from_addr(addr: usize) -> &'static mut Self {
        // Address should be page aligned
        assert!(addr & 0xFFF == 0);

        unsafe { &mut *(addr as *mut PageTable) }
    }

    /// Get the next level `PageTable` address
    #[inline]
    pub fn next_table_address(&self, entry_index: usize) -> Option<usize> {
        let entry = self.entries[entry_index];
        match entry.unused() || entry.huge_page() {
            true => None,
            false => Some(entry.address() as usize),
        }
    }

    /// Get the next level `PageTable`
    #[inline]
    pub fn next_table<A: FrameAllocator>(
        &self,
        entry_index: usize,
        allocator: &A,
    ) -> Option<&mut PageTable> {
        let table_address = self.next_table_address(entry_index);
        match table_address {
            Some(address) => Some(PageTable::from_addr(allocator.translate(address))),
            None => None,
        }
    }

    /// Get the next level `PageTable` or create it
    #[inline]
    pub fn next_table_create<A: FrameAllocator>(
        &mut self,
        entry_index: usize,
        allocator: &mut A,
        perms: PagePermissions,
    ) -> &mut PageTable {
        if self.next_table(entry_index, allocator).is_none() {
            assert!(!self.entries[entry_index].huge_page());

            let frame_address = allocator.allocate_frame().expect("Out of memory");
            self.entries[entry_index].set_address(frame_address as u64);
            self.entries[entry_index].set_present(true);

            self.entries[entry_index].set_writable(perms.writable());
            self.entries[entry_index].set_executable(perms.executable());

            let table = self.next_table(entry_index, allocator).unwrap();
            table.wipe();
            table
        } else {
            // Merge directory permissions with page permissions
            if perms.writable() && !self.entries[entry_index].writable() {
                self.entries[entry_index].set_writable(true);
            }

            if perms.executable() && !self.entries[entry_index].executable() {
                self.entries[entry_index].set_executable(true);
            }

            self.next_table(entry_index, allocator).unwrap()
        }
    }

    /// Wipe a `PageTable`
    #[inline]
    pub fn wipe(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.set_unused();
        }
    }
}

/// Page Table entry
#[repr(C)]
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// The page is present
    const PRESENT_BIT: usize = 0;
    /// The underlying memory is writable
    const WRITABLE_BIT: usize = 1;
    /// The underlying memory is user accessible
    const USER_ACCESSIBLE_BIT: usize = 2;
    /// The underlying memory is write cached
    const WRITE_CACHING_BIT: usize = 3;
    /// The underlying memory is cached
    const CACHE_DISABLE_BIT: usize = 4;
    /// The underlying memory was accessed
    const ACCESSED_BIT: usize = 5;
    /// The underlying memory was dirtied
    const DIRTY_BIT: usize = 6;
    /// The entry point to physical huge frame
    const HUGE_PAGE_BIT: usize = 7;
    /// The entry is global
    const GLOBAL_BIT: usize = 8;
    /// Address where entry point to
    const ADDRESS_BITS: Range<usize> = 12..52;
    /// The underlying is executable
    const EXECUTION_DISABLE_BIT: usize = 63;

    /// Whether or not The entry is unused
    #[inline]
    pub fn unused(&self) -> bool {
        self.0 == 0
    }

    /// Set the entry as unused
    #[inline]
    pub fn set_unused(&mut self) {
        self.0 = 0;
    }

    /// Whether or not the page is currently in memory
    #[inline]
    pub fn present(&self) -> bool {
        self.0.is_bit_set(Self::PRESENT_BIT)
    }

    /// Set whether or not the page is currently in memory
    #[inline]
    pub fn set_present(&mut self, present: bool) {
        self.0.set_bit(Self::PRESENT_BIT, present);
    }

    /// Whether or not a write is possible to this page
    #[inline]
    pub fn writable(&self) -> bool {
        self.0.is_bit_set(Self::WRITABLE_BIT)
    }

    /// Set whether or not a write is possible to this page
    #[inline]
    pub fn set_writable(&mut self, writable: bool) {
        self.0.set_bit(Self::WRITABLE_BIT, writable);
    }

    /// Whether or not the page is accessible by a user
    #[inline]
    pub fn user_accessible(&self) -> bool {
        self.0.is_bit_set(Self::USER_ACCESSIBLE_BIT)
    }

    /// Whether or not the write go directly to memory on this page
    #[inline]
    pub fn write_caching(&self) -> bool {
        self.0.is_bit_set(Self::WRITE_CACHING_BIT)
    }

    /// Set whether or not the write go directly to memory on this page
    #[inline]
    pub fn set_write_caching(&mut self, write_caching: bool) {
        self.0.set_bit(Self::WRITE_CACHING_BIT, write_caching);
    }

    /// Whether or not the cache is enable for this page
    #[inline]
    pub fn caching(&self) -> bool {
        !self.0.is_bit_set(Self::CACHE_DISABLE_BIT)
    }

    /// Set Whether or not the cache is enable for this page
    #[inline]
    pub fn set_caching(&mut self, caching: bool) {
        self.0.set_bit(Self::CACHE_DISABLE_BIT, !caching)
    }

    /// Whether or not the page was accessed by the CPU
    #[inline]
    pub fn accessed(&self) -> bool {
        self.0.is_bit_set(Self::ACCESSED_BIT)
    }

    /// Whether or not the page was write by the CPU
    #[inline]
    pub fn dirty(&self) -> bool {
        self.0.is_bit_set(Self::DIRTY_BIT)
    }

    /// Sets whether the page is dirty or not
    #[inline]
    pub fn set_dirty(&mut self, status: bool) {
        self.0.set_bit(Self::DIRTY_BIT, status);
    }

    /// Whether or not the page is huge
    #[inline]
    pub fn huge_page(&self) -> bool {
        self.0.is_bit_set(Self::HUGE_PAGE_BIT)
    }

    /// Whether or not the page is global (flush or not from caches on
    /// address space switch)
    #[inline]
    pub fn global(&self) -> bool {
        self.0.is_bit_set(Self::GLOBAL_BIT)
    }

    /// Returns the page aligned 52bit physical address of the frame or
    /// the next page table
    #[inline]
    pub fn address(&self) -> u64 {
        self.0.get_bits(Self::ADDRESS_BITS) << 12
    }

    /// Set the page aligned 52bit physical address of the frame or
    /// the next page table
    #[inline]
    pub fn set_address(&mut self, address: u64) {
        self.0.set_bits(Self::ADDRESS_BITS, address >> 12);
    }

    /// Whether or not the executing code on this page is allowed
    #[inline]
    pub fn executable(&self) -> bool {
        !self.0.is_bit_set(Self::EXECUTION_DISABLE_BIT)
    }

    /// Set whether or not the executing code on this page is allowed
    #[inline]
    pub fn set_executable(&mut self, executable: bool) {
        self.0.set_bit(Self::EXECUTION_DISABLE_BIT, !executable)
    }
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("Present", &self.present())
            .field("Writable", &self.writable())
            .field("User accessible", &self.user_accessible())
            .field("Write cache enable", &self.write_caching())
            .field("Cache enable", &self.caching())
            .field("Accessed", &self.accessed())
            .field("Dirtied", &self.dirty())
            .field("Huge page", &self.huge_page())
            .field("Global", &self.global())
            .field("Physical address", &self.address())
            .field("Executable", &self.executable())
            .finish()
    }
}

/// X86_64 virtual address
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct VirtAddr(u64);

/// X86_64 virtual address range
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtRange {
    /// Start virtual address of the range
    start: VirtAddr,
    /// End virtual address of the range
    end: VirtAddr,
}

impl VirtRange {
    /// Return a new instance of `VirtRange`
    pub fn new(start: VirtAddr, end: VirtAddr) -> Self {
        Self {
            start: start,
            end: end,
        }
    }
}

impl Iterator for VirtRange {
    type Item = VirtAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let mut tmp = self.start;
            tmp.align();
            let next_page = tmp.address() + PAGE_SIZE as u64;
            self.start = VirtAddr::new(next_page);

            Some(tmp)
        } else {
            None
        }
    }
}

impl VirtAddr {
    const CANONICAL_BITS: Range<usize> = 48..64;
    const SIGN_EXTENDED_BIT: usize = 47;

    const P4_INDEX_BITS: Range<usize> = 39..48;
    const P3_INDEX_BITS: Range<usize> = 30..39;
    const P2_INDEX_BITS: Range<usize> = 21..30;
    const P1_INDEX_BITS: Range<usize> = 12..21;

    const P1_OFFSET_BITS: Range<usize> = 0..12;

    /// Create a new `VirtAddr` instance, panic on not possible
    /// virtual address.
    #[inline]
    pub fn new(address: u64) -> Self {
        let canonical = address.get_bits(Self::CANONICAL_BITS);

        if address.is_bit_set(Self::SIGN_EXTENDED_BIT) {
            if canonical == 0 {
                return VirtAddr(Self::canonicalize(address));
            }
            assert!(canonical == 0xFFFF);
        } else {
            assert!(canonical == 0);
        }
        VirtAddr(address)
    }

    /// Canonicalize an address by sign extended it in 48 bit address
    #[inline]
    pub fn canonicalize(address: u64) -> u64 {
        ((address << 16) as i64 >> 16) as u64
    }

    /// Forge a level-1 page table `VirtAddr`
    #[inline]
    pub fn forge(
        p4_index: usize,
        p3_index: usize,
        p2_index: usize,
        p1_index: usize,
        p1_offset: usize,
    ) -> Self {
        let mut virt_addr: usize = 0;

        // Build the virtual address
        virt_addr.set_bits(Self::P4_INDEX_BITS, p4_index);
        virt_addr.set_bits(Self::P3_INDEX_BITS, p3_index);
        virt_addr.set_bits(Self::P2_INDEX_BITS, p2_index);
        virt_addr.set_bits(Self::P1_INDEX_BITS, p1_index);
        virt_addr.set_bits(Self::P1_OFFSET_BITS, p1_offset);

        Self::new(virt_addr as u64)
    }

    /// Return the raw virtual address
    #[inline]
    pub fn address(&self) -> u64 {
        self.0
    }

    /// Return whether or not the address is page aligned
    #[inline]
    pub fn aligned(&self) -> bool {
        self.0 & 0xFFF == 0
    }

    /// Page aligned the address
    #[inline]
    pub fn align(&mut self) {
        self.0 &= !0xFFF;
    }

    /// Get the index of the associated entry in the 4-level page table
    #[inline]
    pub fn p4_index(&self) -> usize {
        self.0.get_bits(Self::P4_INDEX_BITS) as usize
    }

    /// Get the index of the associated entry in the 3-level page table
    #[inline]
    pub fn p3_index(&self) -> usize {
        self.0.get_bits(Self::P3_INDEX_BITS) as usize
    }

    /// Get the index of the associated entry in the 2-level page table
    #[inline]
    pub fn p2_index(&self) -> usize {
        self.0.get_bits(Self::P2_INDEX_BITS) as usize
    }

    /// Get the index of the associated entry in the 1-level page table
    #[inline]
    pub fn p1_index(&self) -> usize {
        self.0.get_bits(Self::P1_INDEX_BITS) as usize
    }
}
