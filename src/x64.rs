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
/// Define a table of 7 known good stack pointers that can be used for
/// handling interrupts.
#[repr(C, packed)]
#[derive(Default)]
pub struct InterruptStackTable {
    istx: [u64; 7],
}
/// The TSS in all of its glory
#[repr(C, packed)]
#[derive(Default)]
pub struct Tss {
    /// Reserved
    _reserved_1: u32,
    /// RSPx
    rspx: [u64; 3],
    /// Reserved
    _reserved_2: u64,
    /// Interrupt stack table
    ist: InterruptStackTable,
    /// Reserved
    _reserved_3: u64,
    /// Reserved
    _reserved_4: u16,
    /// IOPB offset
    iopb_offset: u16,
}

impl Tss {
    pub fn new() -> Self {
        Tss::default()
    }

    pub fn set_ist(&mut self, index: usize, address: u64) {
        assert!(
            index <= 7,
            "Ist index must be between 1 and 7 (got {})",
            index
        );

        const IST_START_INDEX: usize = 9;
        //let ist_entry_index = IST_START_INDEX + (index * 2);

        self.ist.istx[index] = address as u64; // Address low
        //self.ist.istx[ist_entry_index + 1] = (address >> 32) as u32; // Address high
    }
}

/// TSS GDT entry
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct TssEntry {
    segment_limit: u16,
    base_00_15: u16,
    packed_0: u16,
    packed_1: u16,
    base_63_32: u32,
    reserved: u32,
}

impl TssEntry {
    /// Creates a new TSS entry.
    pub fn new(base: u64, dpl: PrivilegeLevel) -> TssEntry {
        let limit: usize = core::mem::size_of::<Tss>() - 1;

        let mut packed_0: u16 = 1 << 15; // present
        packed_0 |= (dpl as u16) << 13; // dpl
        packed_0 |= 11 << 8; // Type 11: TSS Busy
        packed_0 |= ((base >> 16) & 0xff) as u16; // base 23:16

        let mut packed_1: u16 = ((limit >> 16) & 0b111) as u16; // limit 19:16
        packed_1 |= ((base >> 24) & 0xff) as u16; // base 31:24, G = 0, AVL = 0

        TssEntry {
            segment_limit: limit as u16,
            base_00_15: base as u16,
            packed_0: packed_0,
            packed_1: packed_1,
            base_63_32: (base >> 32) as u32,
            reserved: 0,
        }
    }
}
