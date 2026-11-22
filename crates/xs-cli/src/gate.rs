//! `--fail-on`: the findings a release gate stops on.
//!
//! A scan, a saved report or a diff is checked against each condition once
//! its reports are written. Of a diff, the findings that newly meet a
//! condition are checked: those the new report adds, and those that meet it
//! there but did not in the old report. A condition that a finding meets
//! makes the command exit with [`EXIT_MATCHED`](crate::EXIT_MATCHED), which a
//! CI job can stop a release on; what was written is written either way.

use std::collections::BTreeSet;

use xs_model::claim::Party;
use xs_model::record::{EdgeType, Grade};
use xs_model::{Claim, Pack, access, permission};

use crate::args::FailOn;

/// A condition, checked against the rule pack the findings are read with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Condition {
    /// As the user wrote it, for the summary.
    pub(crate) written: String,
    test: Test,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Test {
    Headline,
    Category(String),
    /// The id of a company at the top of its ownership chain: the one a
    /// finding names.
    Company(String),
}

/// Checks each condition against `pack`, so a misspelt category or company
/// is an error rather than a gate that never closes.
pub(crate) fn conditions(fail_on: &[FailOn], pack: &Pack) -> Result<Vec<Condition>, String> {
    fail_on
        .iter()
        .map(|condition| {
            let written = condition.to_string();
            let test = match condition {
                FailOn::Headline => Test::Headline,
                FailOn::Category(id) => {
                    let known = pack.category(id).is_some()
                        || access::category(id).is_some()
                        || id == permission::CATEGORY;
                    if !known {
                        return Err(format!(
                            "--fail-on {written}: the rule pack has no category `{id}`; \
                             `exposure rules show` lists them"
                        ));
                    }
                    Test::Category(id.clone())
                }
                FailOn::Company(id) => match pack.company_of(id) {
                    // A finding names the company at the top of the chain,
                    // so a subsidiary stands for its parent.
                    Some(company) => Test::Company(company.id.clone()),
                    None => {
                        return Err(format!(
                            "--fail-on {written}: the rule pack has no company `{id}`; \
                             `exposure rules show` lists them"
                        ));
                    }
                },
            };
            Ok(Condition { written, test })
        })
        .collect()
}

impl Condition {
    /// Whether `claim` meets the condition.
    pub(crate) fn meets(&self, claim: &Claim) -> bool {
        match &self.test {
            // What adds to one of the three counts: a company is counted
            // from `contains` up, an app for a third-party channel.
            Test::Headline => {
                claim.headline
                    && claim.edge == EdgeType::Channel
                    && claim.company.is_some()
                    && (claim.grade >= Grade::Contains || claim.party == Party::Third)
            }
            Test::Category(id) => claim.category == *id,
            Test::Company(id) => claim.company.as_deref() == Some(id.as_str()),
        }
    }
}

/// What one condition found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Met<'a> {
    pub(crate) condition: String,
    pub(crate) findings: usize,
    /// The findings that met it, each with the same finding in the earlier
    /// report, if one is compared.
    pub(crate) matched: Vec<(&'a Claim, Option<&'a Claim>)>,
    /// Apps, by platform and app id: two builds of one app are one app.
    pub(crate) apps: usize,
}

/// Each condition with how many of `claims` newly meet it, in the order
/// given. A claim comes with the same finding in an earlier report, if one
/// is compared: a finding that met the condition there is not counted.
pub(crate) fn check<'a>(
    conditions: &[Condition],
    claims: impl Iterator<Item = (&'a Claim, Option<&'a Claim>)> + Clone,
) -> Vec<Met<'a>> {
    conditions
        .iter()
        .map(|condition| {
            let matched: Vec<_> = claims
                .clone()
                .filter(|(claim, was)| {
                    condition.meets(claim) && !was.is_some_and(|was| condition.meets(was))
                })
                .collect();
            let apps: BTreeSet<_> = matched
                .iter()
                .map(|(claim, _)| (claim.subject.platform, &claim.subject.id))
                .collect();
            Met {
                condition: condition.written.clone(),
                findings: matched.len(),
                apps: apps.len(),
                matched,
            }
        })
        .collect()
}

/// Says of a finding that met a condition which one it is and why it is
/// new: of a diff, which names the apps it compares.
pub(crate) type Describe<'d> = &'d dyn Fn(&Claim, Option<&Claim>) -> String;

/// The lines the summary on standard error gives the gate, and whether any
/// condition was met. It names the conditions the user gave and, of a scan
/// or a report, no app. Of a diff, whose findings are the new ones,
/// `describe` names each finding that met a condition, in a fixed order.
pub(crate) fn summary(met: &[Met<'_>], describe: Option<Describe<'_>>) -> (String, bool) {
    let kind = if describe.is_some() { "new " } else { "" };
    let mut out = String::new();
    let mut any = false;
    for one in met {
        any |= one.findings > 0;
        let result = if one.findings == 0 {
            String::from("not met")
        } else {
            let findings = if one.findings == 1 { "finding" } else { "findings" };
            let apps = if one.apps == 1 { "app" } else { "apps" };
            format!("met by {} {kind}{findings} in {} {apps}", one.findings, one.apps)
        };
        out.push_str(&format!("exposure: fail-on {}: {result}\n", one.condition));
        if let Some(describe) = describe {
            let mut lines: Vec<String> =
                one.matched.iter().map(|&(claim, was)| describe(claim, was)).collect();
            lines.sort();
            for line in lines {
                out.push_str(&format!("exposure: fail-on {}:   {line}\n", one.condition));
            }
        }
    }
    if any {
        out.push_str("exposure: fail-on: a condition was met, so the exit status is 3\n");
    }
    (out, any)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_counts_findings_and_apps() {
        let met = [
            Met { condition: "headline".into(), findings: 0, apps: 0, matched: vec![] },
            Met { condition: "company:google".into(), findings: 5, apps: 1, matched: vec![] },
        ];
        let (text, any) = summary(&met, None);
        assert!(any);
        assert_eq!(
            text,
            "exposure: fail-on headline: not met\n\
             exposure: fail-on company:google: met by 5 findings in 1 app\n\
             exposure: fail-on: a condition was met, so the exit status is 3\n"
        );
        let describe = |_: &Claim, _: Option<&Claim>| String::new();
        let (text, any) = summary(&met[..1], Some(&describe));
        assert!(!any);
        assert_eq!(text, "exposure: fail-on headline: not met\n");
        let one = [Met { condition: "headline".into(), findings: 1, apps: 1, matched: vec![] }];
        assert!(
            summary(&one, Some(&describe))
                .0
                .starts_with("exposure: fail-on headline: met by 1 new finding in 1 app\n")
        );
    }
}
