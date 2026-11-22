//! The resolver: who publishes an app, and whether the company behind a
//! claim is that vendor.
//!
//! **Vendor.** Reversing an app id proves nothing about ownership, so the
//! signature is asked first and the app id second (design report, section 3,
//! M5):
//!
//! | The Team ID the signature names | The app id | The vendor |
//! |---|---|---|
//! | listed under a company | anything | that company, by `team_id` |
//! | none, or not listed | of a macOS app, listed under a company that lists no Team ID | that company, by `app_id` |
//! | none, or not listed | of a macOS app, listed under a company that lists Team IDs | none: the app only claims the company |
//! | — | of an Android package, listed under a company | none: the app only claims the company |
//! | none, or not listed | not listed, and it spells a registrable domain | nobody the pack lists; the domain is kept |
//! | none, or not listed | not listed, and it spells no domain | none |
//!
//! Two records of one build that name Team IDs of different owners also give
//! no vendor.
//!
//! An app id is a name the app gives itself, and any developer can give an
//! app any name (security review, M2). It is believed only where the pack
//! has nothing to check it against: on macOS, for a company that lists no
//! Team ID. A company that
//! lists Team IDs signs its apps, so an app that has its app id and not one
//! of its Team IDs is not believed to be its. Android packages carry a
//! signing certificate this version does not read, so an Android app id is
//! never believed: an app called `com.google.x` could be anyone's. Such an
//! app [`claims`] the company, and every claim about it carries the note
//! [`claim::NOTE_CLAIMED_VENDOR`](xs_model::claim::NOTE_CLAIMED_VENDOR)
//! with the company's id, so that the report can say so.
//!
//! **Party.** Only companies that own an SDK can be first party to one, so
//! the pack only has to list those companies (design report, section 3, A6):
//!
//! | The claim | The vendor | Party |
//! |---|---|---|
//! | names a company | that company | first |
//! | names a company | another listed company | third |
//! | names a company | nobody the pack lists | third |
//! | names a company | none | unknown |
//! | a host nobody is named for | its app id spells the host's registrable domain | first |
//! | names no company | anything else | unknown |
//!
//! `first` is therefore only said when a listed identifier names the company,
//! or when a host that belongs to no listed company sits under the app's own
//! domain. An app id is never matched against a company's domains.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use xs_model::claim::{Party, Vendor, VendorBasis};
use xs_model::pack::{Entity, Pack};
use xs_model::record::{ObjectKind, ObjectRef, Platform, RecordId, Subject};
use xs_model::text;

/// The Team IDs the artifact records of one build name, each with the ids of
/// the records that name it.
pub(crate) type Signers<'a> = BTreeMap<&'a str, Vec<RecordId>>;

/// The registrable domain of `host`: the public suffix and one label more,
/// by the Public Suffix List compiled into this build. `None` for a name
/// under no suffix the list knows, such as an IP address or `localhost`.
pub(crate) fn registrable(host: &str) -> Option<&str> {
    let domain = psl::domain(host.as_bytes())?;
    if !domain.suffix().is_known() {
        return None;
    }
    core::str::from_utf8(domain.as_bytes()).ok()
}

/// The registrable domain an app id spells when its labels are read
/// backwards: `com.ranchero.NetNewsWire-Evergreen` gives `ranchero.com`.
/// `None` for an app id that is not a reversed host name.
pub(crate) fn app_domain(app_id: &str) -> Option<String> {
    let lowercase = app_id.to_ascii_lowercase();
    let mut labels: Vec<&str> = lowercase.split('.').collect();
    labels.reverse();
    let host = labels.join(".");
    if !text::is_host(&host) {
        return None;
    }
    registrable(&host).map(ToString::to_string)
}

/// The id of the company at the top of `entity`'s ownership chain.
fn top(pack: &Pack, entity: &Entity) -> Option<String> {
    pack.company_of(&entity.id).map(|company| company.id.clone())
}

/// The id of the company that operates `host`, if the pack lists one.
pub(crate) fn host_company(pack: &Pack, host: &str) -> Option<String> {
    pack.entity_by_host(host).and_then(|entity| top(pack, entity))
}

/// Who publishes the build `subject`, whose artifact records name the Team
/// IDs in `signers`. See the module documentation for the rules.
pub(crate) fn vendor(
    subject: &Subject,
    signers: Option<&Signers<'_>>,
    pack: &Pack,
) -> Option<Vendor> {
    let domain = app_domain(&subject.id);
    let signers = signers.filter(|signers| !signers.is_empty());

    if let Some(signers) = signers {
        let owners: BTreeSet<Option<String>> = signers
            .keys()
            .map(|team| pack.entity_by_team_id(team).and_then(|entity| top(pack, entity)))
            .collect();
        if owners.len() > 1 {
            return None;
        }
        if let Some(company) = owners.into_iter().flatten().next() {
            let mut evidence: Vec<RecordId> = signers.values().flatten().copied().collect();
            evidence.sort_unstable();
            evidence.dedup();
            return Some(Vendor {
                company: Some(company),
                by: Some(VendorBasis::TeamId),
                domain,
                evidence,
            });
        }
    }

    if let Some(company) = app_id_company(subject, pack) {
        // The app says it is this company's. That is believed only where the
        // platform gives nothing to check it against; otherwise nothing else
        // is known about who made it.
        if !believes_app_id(subject.platform, &company, pack) {
            return None;
        }
        return Some(Vendor {
            company: Some(company),
            by: Some(VendorBasis::AppId),
            domain,
            evidence: Vec::new(),
        });
    }

    domain.map(|domain| Vendor {
        company: None,
        by: None,
        domain: Some(domain),
        evidence: Vec::new(),
    })
}

/// The company the app id of `subject` is listed under, if any.
fn app_id_company(subject: &Subject, pack: &Pack) -> Option<String> {
    pack.entity_by_app_id(&subject.id).and_then(|entity| top(pack, entity))
}

/// Whether an app id listed under `company` is enough to name the vendor on
/// `platform`, when no Team ID of a listed company does.
fn believes_app_id(platform: Platform, company: &str, pack: &Pack) -> bool {
    match platform {
        // A company that lists Team IDs signs its apps with one of them.
        Platform::Macos => !pack.lists_team_ids(company),
        // The signing certificate of an Android package is not read, and an
        // extension's id is no reversed domain: nothing ties the name to the
        // company.
        Platform::Android | Platform::Chromium | Platform::Firefox => false,
    }
}

/// The company the build `subject` names itself after while [`vendor`]
/// names nobody: its app id is listed under the company, and nothing the
/// scan read confirms that the app is the company's. `None` when the app id
/// names no listed company, or when a vendor is named, by the app id or by
/// a signature.
pub(crate) fn claims(
    subject: &Subject,
    signers: Option<&Signers<'_>>,
    pack: &Pack,
) -> Option<String> {
    let company = app_id_company(subject, pack)?;
    let named = vendor(subject, signers, pack).is_some_and(|vendor| vendor.company.is_some());
    (!named).then_some(company)
}

/// Whether `company`, the company behind `object`, is the app's vendor. See
/// the module documentation for the rules.
pub(crate) fn party(company: Option<&str>, object: &ObjectRef, vendor: Option<&Vendor>) -> Party {
    let Some(vendor) = vendor else { return Party::Unknown };
    match (company, vendor.company.as_deref()) {
        (Some(company), Some(own)) if company == own => Party::First,
        (Some(_), _) => Party::Third,
        (None, _) => {
            let own_domain = object.kind == ObjectKind::Host
                && vendor.domain.is_some()
                && registrable(&object.id) == vendor.domain.as_deref();
            if own_domain { Party::First } else { Party::Unknown }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_app_id_read_backwards_spells_a_registrable_domain() {
        let domain = |app_id| app_domain(app_id);
        assert_eq!(domain("com.ranchero.NetNewsWire-Evergreen").as_deref(), Some("ranchero.com"));
        assert_eq!(domain("org.p0deje.Maccy").as_deref(), Some("p0deje.org"));
        assert_eq!(domain("com.x8bit.bitwarden").as_deref(), Some("x8bit.com"));
        assert_eq!(domain("com.example").as_deref(), Some("example.com"));
        // A suffix of two labels.
        assert_eq!(domain("uk.co.example.app").as_deref(), Some("example.co.uk"));
        // A suffix a company runs for its users: each of them is an owner.
        assert_eq!(domain("io.github.alice.tool").as_deref(), Some("alice.github.io"));
    }

    #[test]
    fn an_app_id_that_is_no_reversed_host_name_spells_none() {
        for app_id in [
            "",
            "Maccy",
            "com",
            "io.github",
            "notatld.example.app",
            "com..example",
            "com.ex ample.app",
            "com.b\u{fc}cher.app",
        ] {
            assert_eq!(app_domain(app_id), None, "{app_id}");
        }
    }

    #[test]
    fn a_host_is_cut_down_to_its_registrable_domain() {
        assert_eq!(registrable("ranchero.com"), Some("ranchero.com"));
        assert_eq!(registrable("updates.cdn.ranchero.com"), Some("ranchero.com"));
        assert_eq!(registrable("www.example.co.uk"), Some("example.co.uk"));
        assert_eq!(registrable("raw.githubusercontent.com"), Some("raw.githubusercontent.com"));
        for no_domain in ["com", "co.uk", "localhost", "10.0.0.1", "printer.lan", ""] {
            assert_eq!(registrable(no_domain), None, "{no_domain}");
        }
    }
}
