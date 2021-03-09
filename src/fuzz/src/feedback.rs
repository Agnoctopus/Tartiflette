/// Feedback subsystem

/// Feedback method
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FeedBackMethod(u32);

impl FeedBackMethod {
    pub const NONE: FeedBackMethod = FeedBackMethod(0);
    pub const INSTRUCTION_COUNTING: FeedBackMethod = FeedBackMethod(1);
    pub const BRANCH_COUNTING: FeedBackMethod = FeedBackMethod(2);
    pub const BRANCH_TRACE_STORE: FeedBackMethod = FeedBackMethod(4);
    pub const PT: FeedBackMethod = FeedBackMethod(8);
    pub const SOFT: FeedBackMethod = FeedBackMethod(16);

    const INSTRUCTION_COUNTING_BIT: usize = 1;
    const BRANCH_COUNTING_BIT: usize = 2;
    const BRANCH_TRACE_STORE_BIT: usize = 3;
    const PT_BIT: usize = 4;
    const SOFT_BIT: usize = 5;
}

impl From<u32> for FeedBackMethod {
    #[inline]
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl core::ops::BitOr<FeedBackMethod> for FeedBackMethod {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: FeedBackMethod) -> Self::Output {
        Self::from(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign<FeedBackMethod> for FeedBackMethod {
    #[inline]
    fn bitor_assign(&mut self, rhs: FeedBackMethod) {
        *self = *self | rhs;
    }
}

/// Entry for `CmpFeedBack`
#[derive(Debug)]
pub struct CmpFeedBacKEntry {
    pub val: [u8; 32],
    pub len: usize,
}

/// Cmp feed back
#[derive(Debug)]
pub struct CmpFeedBack {
    /// Entries
    pub entries: Vec<CmpFeedBacKEntry>,
}

impl CmpFeedBack {
    /// Create a new `CmpFeedBack` instance
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct FeedBack {
    pub cmp_feedback_map: CmpFeedBack,
}

impl FeedBack {
    /// Create a new `FeedBack` instance
    pub fn new() -> Self {
        Self {
            cmp_feedback_map: CmpFeedBack::new(),
        }
    }
}
