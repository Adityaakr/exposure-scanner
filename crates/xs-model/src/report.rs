//! The report document.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::claim::Claim;
use crate::evidence::EvidenceSet;
use crate::pack::PackRef;

/// The schema tag of a report file. Serializes as `"exposure-report/1"` and
/// refuses to read anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReportSchema;

impl ReportSchema {
    /// The tag as it appears in a file.
    pub const TAG: &'static str = "exposure-report/1";
}

impl Serialize for ReportSchema {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(Self::TAG)
    }
}

impl<'de> Deserialize<'de> for ReportSchema {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tag = String::deserialize(deserializer)?;
        if tag == Self::TAG {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format_args!(
                "unsupported report schema `{tag}`; this build reads `{}`",
                Self::TAG
            )))
        }
    }
}

/// Everything a report says, together with everything it rests on.
///
/// The claims and the evidence travel in one document so that every finding
/// can show the raw record behind it, and so that the report can be rendered
/// again later from the evidence alone.
///
/// The document holds no timestamp, no host name and no path outside an
/// artifact: the same evidence and the same rule pack give the same bytes on
/// any machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// The schema of this document.
    pub schema: ReportSchema,
    /// The scanner that produced it.
    pub scanner: Scanner,
    /// The rule-pack layers that were in use.
    pub packs: Vec<PackRef>,
    /// The claims, in a fixed order.
    pub claims: Vec<Claim>,
    /// The evidence the claims cite, keyed by record id.
    pub evidence: EvidenceSet,
}

/// The program that produced a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scanner {
    /// The program's name.
    pub name: String,
    /// The program's version.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_tag_is_checked() {
        assert_eq!(serde_json::to_string(&ReportSchema).unwrap(), "\"exposure-report/1\"");
        assert!(serde_json::from_str::<ReportSchema>("\"exposure-report/1\"").is_ok());
        assert!(serde_json::from_str::<ReportSchema>("\"exposure-report/2\"").is_err());
        assert!(serde_json::from_str::<ReportSchema>("1").is_err());
    }
}
