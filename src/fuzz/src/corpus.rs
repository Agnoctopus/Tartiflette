//! Corpus tools

use std::cmp;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use crate::app::App;

/// Manage `FuzzInput`
#[derive(Debug)]
pub struct Corpus {
    /// `FuzzInput` ordered according to their coverage performance
    inputs: Vec<FuzzInput>,
    /// Filename index for input search frmo filename
    filenames: BTreeMap<String, FuzzCov>,
}

impl Corpus {
    /// Create a new `Corpus` instance
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            filenames: BTreeMap::new(),
        }
    }

    /// Add a fuzz `input` to the `Corpus`
    pub fn add_file(&mut self, input: FuzzInput) {
        // Make sure, while inserting the input, that it isn't already present
        assert!(self
            .filenames
            .insert(input.filename.clone(), input.cov)
            .is_none());

        // Compute the index to place the input
        let index = match self
            .inputs
            .binary_search_by(|other| other.cov.cmp(&input.cov))
        {
            Ok(index) => index,
            Err(index) => index,
        };

        // Insert the input at the computed index
        self.inputs.insert(index, input);
    }

    /// Returns whether or not a `FuzzInput` is present based on its filename
    #[inline]
    pub fn contains(&self, filename: &str) -> bool {
        self.filenames.contains_key(filename)
    }

    /// Returns an iterator through the `FuzzInput` from the `FuzzInput` that has a specific `filename`.
    /// If no `FuzzInput` is found from the given `filename`, panic
    pub fn iter_from(&self, filename: &str) -> std::slice::Iter<FuzzInput> {
        // Get the indexed coverage from the filename
        let cov = self.filenames.get(filename);
        if cov.is_none() {
            panic!("Failed to find the input named {}.", filename);
        }
        let cov = cov.unwrap();

        // Compute the index of the input
        let index = match self.inputs.binary_search_by(|other| other.cov.cmp(cov)) {
            Ok(index) => index,
            Err(index) => unreachable!(),
        };

        // Inputs can have the same coverages, thus continue iterating to find
        // the correct poisition
        println!("filename: {}, index: {}", filename, index);
        for input in &self.inputs {
            println!("{:?}", input.filename);

        }

        let position = index
            + self.inputs[index..]
                .iter()
                .position(|file| file.filename == filename)
                .unwrap();

        // Returns an iterator through the remaining inputs slice
        self.inputs[position..].iter()
    }

    /// Return an iterator through all `FuzzInput` from the begining
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<FuzzInput> {
        self.inputs.iter()
    }
}

/// Coverage that mesure performance of a `FuzzInput` during a `FuzzCase`
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct FuzzCov([usize; 4]);

impl FuzzCov {
    /// Compute the local maximum with an `other`
    #[inline]
    pub fn compute_local_max(&self, other: &Self) -> Self {
        let mut cov = Self::default();

        cov.0[0] = cmp::max(self.0[0], other.0[0]);
        cov.0[1] = cmp::max(self.0[1], other.0[1]);
        cov.0[2] = cmp::max(self.0[2], other.0[2]);
        cov.0[3] = cmp::max(self.0[3], other.0[3]);

        cov
    }

    /// Returns a mutable reference to the inner cov bytes
    #[inline]
    pub fn bytes(&mut self) -> &mut [usize; 4] {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct FuzzInput {
    /// Filename
    pub filename: String,

    pub data: Vec<u8>,

    pub cov: FuzzCov,
    pub idx: usize,
    pub refs: u32,

    pub exec_usec: usize,
}

impl Default for FuzzInput {
    fn default() -> Self {
        Self {
            filename: String::from(""),

            data: Vec::new(),

            cov: FuzzCov::default(),
            idx: 0,
            refs: 0,
            exec_usec: 0,
        }
    }
}

impl FuzzInput {
    /// Create a new `FuzzInput` instance
    pub fn new(app: &App) -> Self {
        Self {
            data: Vec::with_capacity(app.config.app_config.max_input_size),
            ..Default::default()
        }
    }

    /// Generate a filename based on the contained data
    #[inline]
    pub fn generate_filename(&self) -> String {
        format!("{:x}.{:x}.cov", md5::compute(&self.data), self.data.len())
    }

    pub fn fork(&self, exec_usec: usize, app: &App) -> Self {
        Self {
            filename: self.generate_filename(),
            data: self.data.clone(),
            cov: self.cov,
            idx: app.metrics.fuzz_input_count.fetch_add(1, Ordering::Relaxed),
            refs: 0,
            exec_usec: exec_usec,
        }
    }
}
