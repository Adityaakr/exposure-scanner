//! What a scan could not look at as a whole, said where a reader looks
//! first (security review, M7).
//!
//! A browser whose profile folder macOS will not let the scan list, or a
//! package the system would not let it read, is a coverage record like any
//! other. In the table of what was set aside it is one row among many, and
//! a reader who uses that browser would take the report as covering its
//! extensions. So each such thing is also named at the top of the page, in
//! the summary a scan prints, and taken out of the line that says where the
//! scan looked.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use xs_model::EvidenceSet;
use xs_model::record::{Browser, CoverageReason, Platform, Record, SubjectKind};

/// What macOS asks of a person for the scan to read a folder it protects.
const FULL_DISK_ACCESS: &str = "allow your terminal app under System Settings > Privacy & \
                                Security > Full Disk Access, scan again, then turn it off";

/// One thing the scan could not look at at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotChecked {
    /// What kind of thing was not checked.
    pub kind: SubjectKind,
    /// The browser whose extensions were not checked, if it is one.
    pub browser: Option<Browser>,
    /// What was not checked, such as `Google Chrome's extensions`, or the
    /// name of a package that could not be read.
    pub what: String,
    /// Why, in one sentence.
    pub why: &'static str,
    /// What a person can do to have it checked, in one sentence, when there
    /// is something.
    pub step: Option<String>,
}

impl NotChecked {
    /// The whole of it after `Not checked: `, in plain words.
    #[must_use]
    pub fn sentence(&self) -> String {
        let mut out = format!("{}. {}", self.what, self.why);
        if let Some(step) = &self.step {
            out.push(' ');
            out.push_str(step);
        }
        out
    }
}

/// The subjects of `evidence` the scan could not look at at all: those with
/// a coverage record about the whole of them, for want of a privilege or
/// because the read was refused, and no artifact record of files read, which
/// a subject the scan did read has. A browser some of whose extensions were read says
/// so. In the order of the subjects.
#[must_use]
pub fn not_checked(evidence: &EvidenceSet) -> Vec<NotChecked> {
    let mut refused: BTreeMap<(SubjectKind, Platform, &str), CoverageReason> = BTreeMap::new();
    let mut read: BTreeSet<Browser> = BTreeSet::new();
    let mut artifacts: BTreeSet<(SubjectKind, Platform, &str)> = BTreeSet::new();
    for (_, record) in evidence.iter() {
        match record {
            Record::Coverage(note)
                if note.location.is_none()
                    && matches!(
                        note.reason,
                        CoverageReason::NoPrivilege | CoverageReason::Unreadable
                    ) =>
            {
                let subject = &note.subject;
                let key = (subject.kind, subject.platform, subject.id.as_str());
                let reason = refused.entry(key).or_insert(note.reason);
                // Of two reasons, the one a person can do something about.
                if note.reason == CoverageReason::NoPrivilege {
                    *reason = CoverageReason::NoPrivilege;
                }
            }
            Record::Artifact(artifact) => {
                let subject = &artifact.subject;
                if artifact.facts.files_scanned > 0 {
                    artifacts.insert((subject.kind, subject.platform, subject.id.as_str()));
                }
                if let Some(browser) = artifact.facts.browser {
                    read.insert(browser);
                }
            }
            _ => {}
        }
    }
    refused
        .into_iter()
        .filter(|(key, _)| !artifacts.contains(key))
        .map(|((kind, _, id), reason)| {
            let privilege = reason == CoverageReason::NoPrivilege;
            match (kind, Browser::from_id(id)) {
                (SubjectKind::Browser, Some(browser)) => NotChecked {
                    kind,
                    browser: Some(browser),
                    what: if read.contains(&browser) {
                        format!("some of {}'s extensions", browser.name())
                    } else {
                        format!("{}'s extensions", browser.name())
                    },
                    why: if privilege {
                        "macOS did not let the scan read its profile folder."
                    } else {
                        "Its profile folder could not be read."
                    },
                    step: privilege.then(|| format!("To include them, {FULL_DISK_ACCESS}.")),
                },
                (SubjectKind::Extension, _) => NotChecked {
                    kind,
                    browser: None,
                    what: format!("the extension {id}"),
                    why: if privilege {
                        "macOS did not let the scan read it."
                    } else {
                        "Its files are missing or could not be read."
                    },
                    step: privilege.then(|| format!("To include it, {FULL_DISK_ACCESS}.")),
                },
                _ => NotChecked {
                    kind,
                    browser: None,
                    what: String::from(id),
                    why: if privilege {
                        "macOS did not let the scan read it."
                    } else {
                        "The system refused the read, or the file changed while it was read."
                    },
                    step: privilege.then(|| format!("To include it, {FULL_DISK_ACCESS}.")),
                },
            }
        })
        .collect()
}

/// The browsers none of whose extensions the scan could look at, so that
/// where the scan looked does not name them.
#[must_use]
pub fn unread_browsers(unchecked: &[NotChecked]) -> Vec<Browser> {
    unchecked
        .iter()
        .filter(|item| !item.what.starts_with("some of "))
        .filter_map(|item| item.browser)
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use xs_model::record::{
        ArtifactRecord, Collector, CoverageRecord, CoverageStatus, Facts, Subject, V1,
    };
    use xs_model::{Sha256Digest, SubjectDigest};

    use super::*;

    fn unlisted(browser: Browser, reason: CoverageReason) -> Record {
        Record::Coverage(CoverageRecord {
            v: V1,
            collector: Collector::BrowserExtension,
            subject: Subject {
                kind: SubjectKind::Browser,
                platform: browser.platform(),
                id: browser.as_str().to_string(),
                version: None,
                digest: SubjectDigest::Unread,
            },
            status: CoverageStatus::Skipped,
            reason,
            location: None,
            bytes: None,
            count: 1,
        })
    }

    fn extension_in(browser: Browser) -> Record {
        Record::Artifact(ArtifactRecord {
            v: V1,
            collector: Collector::BrowserExtension,
            subject: Subject {
                kind: SubjectKind::Extension,
                platform: browser.platform(),
                id: "abcdefghijklmnopabcdefghijklmnop".into(),
                version: Some("1.0".into()),
                digest: SubjectDigest::Bundle(Sha256Digest::of(b"x")),
            },
            facts: Facts { browser: Some(browser), ..Facts::default() },
        })
    }

    fn set(records: impl IntoIterator<Item = Record>) -> EvidenceSet {
        let mut set = EvidenceSet::new();
        for record in records {
            set.insert(record).unwrap();
        }
        set
    }

    #[test]
    fn a_browser_macos_will_not_let_the_scan_read_is_named_with_the_way_to_include_it() {
        let found = not_checked(&set([unlisted(Browser::Chrome, CoverageReason::NoPrivilege)]));
        assert_eq!(
            found.iter().map(NotChecked::sentence).collect::<Vec<_>>(),
            vec![
                "Google Chrome's extensions. macOS did not let the scan read its profile \
                 folder. To include them, allow your terminal app under System Settings > \
                 Privacy & Security > Full Disk Access, scan again, then turn it off."
            ]
        );
        assert_eq!(unread_browsers(&found), [Browser::Chrome]);
    }

    #[test]
    fn a_browser_read_in_part_is_said_to_be_and_stays_in_the_scope() {
        let found = not_checked(&set([
            unlisted(Browser::Brave, CoverageReason::Unreadable),
            extension_in(Browser::Brave),
        ]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].what, "some of Brave's extensions");
        assert_eq!(found[0].why, "Its profile folder could not be read.");
        assert_eq!(found[0].step, None);
        assert_eq!(unread_browsers(&found), []);
    }

    fn subject(kind: SubjectKind, platform: Platform, id: &str, digest: SubjectDigest) -> Subject {
        Subject { kind, platform, id: id.to_string(), version: None, digest }
    }

    fn refused(subject: Subject, collector: Collector) -> Record {
        Record::Coverage(CoverageRecord {
            v: V1,
            collector,
            subject,
            status: CoverageStatus::Skipped,
            reason: CoverageReason::Unreadable,
            location: None,
            bytes: None,
            count: 1,
        })
    }

    #[test]
    fn an_app_that_was_read_is_not_named_for_a_name_it_could_not_store() {
        let app = subject(
            SubjectKind::App,
            Platform::Macos,
            "com.example.App",
            SubjectDigest::Bundle(Sha256Digest::of(b"app")),
        );
        let found = not_checked(&set([
            Record::Artifact(ArtifactRecord {
                v: V1,
                collector: Collector::MacosBundle,
                subject: app.clone(),
                facts: Facts {
                    name: Some("Example".into()),
                    files_scanned: 41,
                    ..Facts::default()
                },
            }),
            refused(app, Collector::MacosBundle),
        ]));
        assert_eq!(found, []);
    }

    #[test]
    fn an_app_whose_top_folder_could_not_be_listed_is_named() {
        let app = subject(
            SubjectKind::App,
            Platform::Macos,
            "Locked.app",
            SubjectDigest::Bundle(Sha256Digest::of(b"")),
        );
        let found = not_checked(&set([
            Record::Artifact(ArtifactRecord {
                v: V1,
                collector: Collector::MacosBundle,
                subject: app.clone(),
                facts: Facts::default(),
            }),
            refused(app, Collector::MacosBundle),
        ]));
        assert_eq!(
            found.iter().map(NotChecked::sentence).collect::<Vec<_>>(),
            vec!["Locked.app. The system refused the read, or the file changed while it was read."]
        );
        assert_eq!(found[0].kind, SubjectKind::App);
    }

    #[test]
    fn an_extension_none_of_which_was_read_is_named_as_an_extension() {
        let id = "abcdefghijklmnopabcdefghijklmnop";
        let unread = subject(SubjectKind::Extension, Platform::Chromium, id, SubjectDigest::Unread);
        let found = not_checked(&set([refused(unread, Collector::BrowserExtension)]));
        assert_eq!(
            found.iter().map(NotChecked::sentence).collect::<Vec<_>>(),
            vec![
                "the extension abcdefghijklmnopabcdefghijklmnop. Its files are missing or \
                 could not be read."
            ]
        );
        assert_eq!(found[0].kind, SubjectKind::Extension);
    }

    #[test]
    fn a_scan_that_read_everything_names_nothing() {
        assert_eq!(not_checked(&set([extension_in(Browser::Chrome)])), []);
        assert_eq!(not_checked(&EvidenceSet::new()), []);
    }
}
