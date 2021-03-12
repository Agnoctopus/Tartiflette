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
pub enum Dpl {
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
    dpl: Dpl,
    gate_type: IdtEntryType,
}

impl IdtEntryBuilder {
    pub fn new() -> Self {
        IdtEntryBuilder {
            base: 0,
            segment_selector: 0,
            ist: 0,
            dpl: Dpl::Ring0,
            gate_type: IdtEntryType::Interrupt,
        }
    }

    #[inline]
    pub fn base(&mut self, base: u64) -> &mut Self {
        self.base = base;
        self
    }

    #[inline]
    pub fn ist(&mut self, ist: u8) -> &mut Self {
        assert!(ist <= 7, "IST mut be in the range 0-7, got {}", ist);
        self.ist = ist;
        self
    }

    #[inline]
    pub fn dpl(&mut self, dpl: Dpl) -> &mut Self {
        assert!(
            dpl as u8 <= 3,
            "DPL must be in range 0-3, got {}",
            dpl as u8
        );
        self.dpl = dpl;
        self
    }

    #[inline]
    pub fn segment_selector(&mut self, segment: u16) -> &mut Self {
        self.segment_selector = segment;
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
