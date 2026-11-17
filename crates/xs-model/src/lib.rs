//! Data model of the exposure scanner.
//!
//! This crate defines the contracts every other crate agrees on:
//!
//! * the versioned **evidence record** ([`record`]) and the set that holds
//!   records keyed by content hash ([`evidence`]);
//! * the **claim** derived from evidence ([`claim`]);
//! * the fixed list of **permissions** an access edge from an app can point
//!   at ([`access`]), and of what a browser extension may be allowed to
//!   reach ([`permission`]);
//! * the compiled **rule pack** ([`pack`]), and the advice it carries on
//!   what a person can do about a finding ([`fix`]);
//! * the **report** document that carries claims together with the evidence
//!   they cite ([`report`]);
//! * the **canonical JSON** encoding (RFC 8785) that record ids, claim ids and
//!   every emitted file are built on ([`canon`]).
//!
//! The crate is `no_std` on purpose. Code here cannot read a clock, the
//! environment or a file, and it has no `HashMap`, so no randomly seeded
//! iteration order can leak into output. That is what makes a report a pure
//! function of its evidence, rule pack and scan scope.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod access;
pub mod canon;
pub mod claim;
pub mod digest;
pub mod evidence;
pub mod fix;
pub mod matcher;
pub mod pack;
pub mod path;
pub mod permission;
pub mod record;
pub mod report;
pub mod text;

mod serde_str;

pub use claim::{Claim, ClaimId, ClaimKey, Confidence, Party, Vendor, VendorBasis};
pub use digest::{Sha256Digest, Sha256Stream, SubjectDigest};
pub use evidence::EvidenceSet;
pub use matcher::{Boundary, MatcherKind};
pub use pack::Pack;
pub use path::RelPath;
pub use permission::Permission;
pub use record::{Record, RecordId};
pub use report::{Headline, Report};
