//! Dico muation subsystem

use std::path::Path;

/// Dictionary entry
#[derive(Debug)]
pub struct DicoEntry {
    pub data: [u8; 256],
    pub len: usize,
}

/// Dictionary
#[derive(Debug)]
pub struct Dico {
    /// Entries
    pub entries: Vec<DicoEntry>,
}

impl Dico {
    // Create a new instance of empty of `Dico`
    #[inline]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    // Create a new instance of `Dico` from a dictionary file
    pub fn new_from<P: AsRef<Path>>(p: P) -> Self {
        todo!()
    }
}
