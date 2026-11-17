//! Bounded parsers for the file formats the scanner reads.
//!
//! Every input here is hostile: app bundles, archives and property lists are
//! built by whoever ships the app. So every parser in this crate
//!
//! * takes a byte slice and touches nothing else: no file, no socket, no
//!   clock, no environment (the lint lists in `clippy.toml` ban those APIs);
//! * is written in safe Rust (`unsafe` is forbidden workspace-wide) and never
//!   indexes or does arithmetic that could panic;
//! * stops at a **deterministic budget** of bytes, items or depth and says so,
//!   rather than at a time limit, so the same file always parses the same way
//!   (design report, section 3, issue C3).
#![cfg_attr(not(test), deny(clippy::indexing_slicing, clippy::arithmetic_side_effects))]

pub mod android_manifest;
pub mod asar;
pub mod codesign;
pub mod dex;
pub mod host;
pub mod info_plist;
mod le;
pub mod macho;
#[cfg(any(test, feature = "testkit"))]
pub mod macho_build;
pub mod privacy_manifest;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod zip;

use std::fmt;

/// Why a parser gave up on an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// The input exceeds a deterministic budget. The caller reports this as
    /// `over_budget` coverage and carries on.
    OverBudget(Budget),
    /// The input is not a well-formed instance of the format.
    Malformed,
}

/// The budget an input exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Budget {
    /// Total size in bytes.
    Bytes,
    /// Number of values.
    Items,
    /// Nesting depth.
    Depth,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverBudget(Budget::Bytes) => f.write_str("input is larger than its byte budget"),
            Self::OverBudget(Budget::Items) => {
                f.write_str("input holds more values than its budget")
            }
            Self::OverBudget(Budget::Depth) => f.write_str("input nests deeper than its budget"),
            Self::Malformed => f.write_str("input is malformed"),
        }
    }
}

impl std::error::Error for FormatError {}

/// Why a reader gave up on an input whose format comes in variants.
///
/// A zip archive may be split over several disks or use the 64-bit
/// extension, an entry may be encrypted, a DEX file may be of a later
/// version. Such an input is not damaged, so calling it malformed would be
/// wrong: the caller reports it as `unsupported_format` coverage instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The input is over a budget or not well formed.
    Format(FormatError),
    /// The input is a variant of the format this build has no reader for.
    Unsupported,
}

impl From<FormatError> for ReadError {
    fn from(error: FormatError) -> Self {
        Self::Format(error)
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(error) => error.fmt(f),
            Self::Unsupported => {
                f.write_str("input is a variant of its format that this build cannot read")
            }
        }
    }
}

impl std::error::Error for ReadError {}
