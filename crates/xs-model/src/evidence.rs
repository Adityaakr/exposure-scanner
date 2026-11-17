//! The evidence set.

use alloc::collections::BTreeMap;
use alloc::collections::btree_map;
use alloc::string::{String, ToString};
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::canon::CanonError;
use crate::record::{Record, RecordError, RecordId};

/// Records keyed by content hash.
///
/// It is a set, so the order records arrive in cannot reach the output: equal
/// records collapse into one, and iteration is always in id order. Parallel
/// collectors can therefore merge their results in whatever order they finish
/// (design report, section 6.4 rule 2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BTreeMap<RecordId, Record>")]
pub struct EvidenceSet(BTreeMap<RecordId, Record>);

/// Why a record cannot enter the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    /// The record breaks an invariant of the format.
    Invalid(RecordError),
    /// The record has no canonical form.
    Canon(CanonError),
    /// A record read from a file is stored under an id that is not the hash
    /// of its content. The file was edited or damaged.
    IdMismatch {
        /// The id the file claims.
        claimed: String,
        /// The id the content hashes to.
        actual: String,
    },
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => write!(f, "invalid record: {error}"),
            Self::Canon(error) => write!(f, "record has no canonical form: {error}"),
            Self::IdMismatch { claimed, actual } => {
                write!(f, "record stored as {claimed} hashes to {actual}")
            }
        }
    }
}

impl core::error::Error for EvidenceError {}

impl From<RecordError> for EvidenceError {
    fn from(error: RecordError) -> Self {
        Self::Invalid(error)
    }
}

impl From<CanonError> for EvidenceError {
    fn from(error: CanonError) -> Self {
        Self::Canon(error)
    }
}

impl EvidenceSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a record and returns its id. Adding a record that is already
    /// present changes nothing.
    ///
    /// # Errors
    ///
    /// Fails if the record breaks an invariant of the format.
    pub fn insert(&mut self, record: Record) -> Result<RecordId, EvidenceError> {
        record.validate()?;
        let id = record.id()?;
        self.0.entry(id).or_insert(record);
        Ok(id)
    }

    /// Adds every record of `other`.
    pub fn merge(&mut self, other: Self) {
        for (id, record) in other.0 {
            self.0.entry(id).or_insert(record);
        }
    }

    /// The record with this id, if present.
    #[must_use]
    pub fn get(&self, id: &RecordId) -> Option<&Record> {
        self.0.get(id)
    }

    /// Removes a record. Used by tests that check a report cannot cite
    /// evidence it does not carry.
    pub fn remove(&mut self, id: &RecordId) -> Option<Record> {
        self.0.remove(id)
    }

    /// Records in id order.
    pub fn iter(&self) -> btree_map::Iter<'_, RecordId, Record> {
        self.0.iter()
    }

    /// Number of distinct records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a EvidenceSet {
    type Item = (&'a RecordId, &'a Record);
    type IntoIter = btree_map::Iter<'a, RecordId, Record>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Reading a set back from a file re-checks every record and every id, so
/// evidence that was edited after the scan is refused rather than trusted.
impl TryFrom<BTreeMap<RecordId, Record>> for EvidenceSet {
    type Error = EvidenceError;

    fn try_from(stored: BTreeMap<RecordId, Record>) -> Result<Self, Self::Error> {
        for (claimed, record) in &stored {
            record.validate()?;
            let actual = record.id()?;
            if actual != *claimed {
                return Err(EvidenceError::IdMismatch {
                    claimed: claimed.to_string(),
                    actual: actual.to_string(),
                });
            }
        }
        Ok(Self(stored))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use proptest::prelude::*;

    use super::*;
    use crate::canon;
    use crate::record::tests::bitwarden;

    /// Distinct, valid records derived from the spike record.
    fn records(count: u32) -> Vec<Record> {
        (1..=count)
            .map(|n| {
                let mut record = bitwarden();
                if let Record::Edge(edge) = &mut record {
                    edge.proof.count = n;
                }
                record
            })
            .collect()
    }

    #[test]
    fn duplicates_collapse() {
        let mut set = EvidenceSet::new();
        let first = set.insert(bitwarden()).unwrap();
        let second = set.insert(bitwarden()).unwrap();
        assert_eq!(first, second);
        assert_eq!(set.len(), 1);
        assert_eq!(set.get(&first), Some(&bitwarden()));
    }

    #[test]
    fn invalid_records_are_refused() {
        let mut record = bitwarden();
        if let Record::Edge(edge) = &mut record {
            edge.proof.count = 0;
        }
        let mut set = EvidenceSet::new();
        assert_eq!(set.insert(record), Err(EvidenceError::Invalid(RecordError::ZeroCount)));
        assert!(set.is_empty());
    }

    #[test]
    fn a_stored_set_with_a_wrong_id_is_refused() {
        let mut set = EvidenceSet::new();
        set.insert(bitwarden()).unwrap();
        let honest = canon::to_string(&set).unwrap();
        assert_eq!(serde_json::from_str::<EvidenceSet>(&honest).unwrap(), set);

        // Change the evidence but keep the id it was stored under.
        let forged = honest.replace("\"count\":2", "\"count\":9");
        assert_ne!(forged, honest);
        let error = serde_json::from_str::<EvidenceSet>(&forged).unwrap_err();
        assert!(error.to_string().contains("hashes to"), "{error}");
    }

    proptest! {
        /// Design report, task 2: shuffled insertion gives the same set, and
        /// with it the same bytes.
        #[test]
        fn insertion_order_cannot_matter(
            order in Just(records(12)).prop_shuffle(),
            repeats in prop::collection::vec(0usize..12, 0..6),
        ) {
            let mut reference = EvidenceSet::new();
            for record in records(12) {
                reference.insert(record).unwrap();
            }

            let mut shuffled = EvidenceSet::new();
            for record in &order {
                shuffled.insert(record.clone()).unwrap();
            }
            // Inserting some records again must not change anything either.
            for index in repeats {
                shuffled.insert(order[index].clone()).unwrap();
            }

            prop_assert_eq!(&shuffled, &reference);
            prop_assert_eq!(canon::to_vec(&shuffled).unwrap(), canon::to_vec(&reference).unwrap());
        }

        /// Merging partial sets, as parallel workers do, equals inserting
        /// everything into one set.
        #[test]
        fn merging_partitions_equals_one_set(
            order in Just(records(12)).prop_shuffle(),
            split in 0usize..=12,
        ) {
            let mut reference = EvidenceSet::new();
            let mut left = EvidenceSet::new();
            let mut right = EvidenceSet::new();
            for (index, record) in order.into_iter().enumerate() {
                reference.insert(record.clone()).unwrap();
                if index < split { &mut left } else { &mut right }.insert(record).unwrap();
            }
            let mut merged = right.clone();
            merged.merge(left.clone());
            left.merge(right);
            prop_assert_eq!(&merged, &reference);
            prop_assert_eq!(&left, &reference);
        }
    }
}
