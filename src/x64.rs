#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct IdtEntry {
    /// First part of the handler base address
    base_00_15: u16,
    /// Segment selector to use
    segment_selector: u16,
    /// Entry flags (present, DPL, type, IST)
    flags: u16,
    /// Second part of the handle base address
    base_16_31: u16,
    /// Last part of the handle base address
    base_32_64: u32,
    /// Reserved
    reserved: u32,
}

impl IdtEntry {
    /// Create a new `Idt64Entry` instance
    pub fn new() -> Self {
        IdtEntry {
            base_00_15: 0,
            base_16_31: 0,
            base_32_64: 0,
            segment_selector: 0,
            flags: 0,
            reserved: 0,
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum PrivilegeLevel {
    Ring0 = 0,
    Ring3 = 3,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IdtEntryType {
    Interrupt = 0b1110,
    Trap = 0b1111,
}

pub struct IdtEntryBuilder {
    base: u64,
    segment_selector: u16,
    ist: u8,
    dpl: PrivilegeLevel,
    gate_type: IdtEntryType,
}

impl IdtEntryBuilder {
    pub fn new() -> Self {
        IdtEntryBuilder {
            base: 0,
            segment_selector: 0,
            ist: 0,
            dpl: PrivilegeLevel::Ring0,
            gate_type: IdtEntryType::Interrupt,
        }
    }

    /// Sets the linear address of the interrupt handling code.
    #[inline]
    pub fn base(&mut self, base: u64) -> &mut Self {
        self.base = base;
        self
    }

    /// Sets the index of the stack to be used when handling the interrupt.
    /// Must be between 1 and 7 if enabled, 0 if disabled.
    #[inline]
    pub fn ist(&mut self, ist: u8) -> &mut Self {
        assert!(ist <= 7, "IST mut be in the range 0-7, got {}", ist);
        self.ist = ist;
        self
    }

    /// Sets the descriptor privilege level.
    #[inline]
    pub fn dpl(&mut self, dpl: PrivilegeLevel) -> &mut Self {
        assert!(
            dpl as u8 <= 3,
            "DPL must be in range 0-3, got {}",
            dpl as u8
        );
        self.dpl = dpl;
        self
    }

    /// Sets the segment selector index.
    #[inline]
    pub fn segment_selector(&mut self, index: u16, rpl: PrivilegeLevel) -> &mut Self {
        assert!(index < 8192, "Index must be below 8192 (got {})", index);
        self.segment_selector = index << 3 | rpl as u16;
        self
    }

    #[inline]
    pub fn gate_type(&mut self, gate_type: IdtEntryType) -> &mut Self {
        self.gate_type = gate_type;
        self
    }

    #[inline]
    pub fn collect(&self) -> IdtEntry {
        let mut flags: u16 = 1 << 15; // Present
        flags |= (self.dpl as u16) << 13; // Dpl
        flags |= (self.gate_type as u16) << 8; // Gate Type
        flags |= self.ist as u16;

        IdtEntry {
            base_00_15: self.base as u16,
            base_16_31: (self.base >> 16) as u16,
            base_32_64: (self.base >> 32) as u32,

            segment_selector: self.segment_selector,
            flags: flags,
            reserved: 0,
        }
    }
}

/// Interupt Stack Table
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Ist {
    /// Linear addresses of stack addresses
    entries: [u64; 8],
}

impl Ist {
    /// Creates a new Ist
    pub fn new() -> Self {
        Ist { entries: [0; 8] }
    }

    /// Returns the address contained in the Ist at the given index
    pub fn get(&self, index: usize) -> u64 {
        assert!(index > 7, "Index must be between 0 and 7 (got {})", index);
        self.entries[index]
    }

    /// Sets the Ist entry at the given index.
    pub fn set(&mut self, index: usize, address: u64) {
        assert!(
            index == 0 || index > 7,
            "Index must be between 1 and 7 (got {})",
            index
        );

        self.entries[index] = address;
    }
}
