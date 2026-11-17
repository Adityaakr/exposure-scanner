//! The match engine: matchers compiled from a rule pack, the hits they
//! collect, and the decision about what those hits are evidence of.
//!
//! A rule token is a literal plus a boundary. How it is looked for depends
//! on what there is to look in (design report, section 5.1):
//!
//! * **A parsed table** (framework folder names, class names, zip entry
//!   names) gives complete values. Each value goes to
//!   [`Matchers::match_value`]: `exact` and `prefix` tokens are table
//!   lookups, the other boundaries are searched for inside the value. A
//!   table is a small haystack, gives exact rather than substring matches,
//!   and yields a proof a reader can verify with standard tools.
//! * **Free-form bytes** (script text, the data of a binary) are searched
//!   one window at a time through [`Matchers::content`], which returns a
//!   [`ContentMatcher`]. That trait is the seam between the file reader and
//!   the search engine, so the engine can change without touching a
//!   collector.
//!
//! Both record into a [`HitAcc`]. [`Matchers::judge`] then decides which
//! hits are evidence and which are only mentions.
//!
//! The five controls against false positives (section 5.2) and where each
//! one lives:
//!
//! | Control | Where |
//! |---|---|
//! | 1. Scope: content matchers do not run on runtime files | [`applies`], enforced by `content`, `match_value` and `judge` |
//! | 2. Boundaries: `word` and `host` anchors | the search itself |
//! | 3. Token lints | the pack compiler in `xs-rules`, before a pack is signed |
//! | 4. Breadth guard: a file naming 8 companies is a list | `judge` |
//! | 5. Distinct-token minimum per rule and matcher kind | `judge` |
//!
//! The crate is `no_std`: matching is a pure function of bytes and the pack.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod boundary;
mod content;
mod hits;
mod judge;
mod matchers;
mod table;
#[cfg(test)]
mod testkit;

pub use content::{ContentEngine, ContentMatcher, NoContent};
pub use hits::{HitAcc, PatternId};
pub use judge::{BREADTH_LIMIT, Finding, Held, Mention, Verdict};
pub use matchers::{BuildError, Matchers, TokenRef, applies};
