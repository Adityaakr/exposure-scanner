//! The checklist in plain words, one short entry per thing to do, for a
//! terminal.
//!
//! It is the checklist of the HTML report, in the same order and with the
//! same priorities, so the two never disagree. Each entry is cut down to
//! what fits on a few lines: what it is about, in which apps, and the first
//! step. The report has every step and the evidence behind it.
//!
//! The values come out of scanned apps. An app's name could hold escape
//! sequences that a terminal acts on, so every value is passed through
//! [`plain`] before it goes into an entry.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use xs_model::access;
use xs_model::claim::Party;
use xs_model::permission::Permission;
use xs_model::record::Browser;

use super::{
    Entry, InApp, Place, Priority, android_place, block_hosts, checklist, extensions_page,
    firewall, in_app,
};
use crate::html::view::{App, Finding, Found, View};
use crate::html::words::{list_words, plural};
use crate::{Todo, TodoPriority};

/// How many app names an entry lists before it says how many more there are.
const NAMED_APPS: usize = 3;
/// How many hosts a block step lists before it says how many more the
/// report lists.
const NAMED_HOSTS: usize = 3;

/// The checklist, in the order a reader should act on it.
pub(crate) fn todos(pack: &xs_model::pack::Pack, view: &View<'_>) -> Vec<Todo> {
    checklist(view)
        .into_iter()
        .filter_map(|(priority, _, entry)| {
            let priority = match priority {
                Priority::High => TodoPriority::High,
                Priority::Medium => TodoPriority::Medium,
                Priority::Low => TodoPriority::Low,
            };
            let (title, about, step) = match entry {
                Entry::Channel(found) => channel(pack, view, found),
                Entry::Extension(app, findings) => extension(view.apps.get(app)?, &findings),
                Entry::Pane(pane, apps) => self::pane(view, pane, &apps),
                Entry::Android(app, findings) => android(view.apps.get(app)?, &findings),
            };
            Some(Todo { priority, title: plain(&title), about: plain(&about), step: plain(&step) })
        })
        .collect()
}

/// Names of apps, the first few of them, and how many more there are.
fn app_names<'a>(apps: impl Iterator<Item = &'a str>) -> String {
    let names: Vec<&str> = apps.collect();
    if names.len() <= NAMED_APPS + 1 {
        return list_words(&names);
    }
    let shown = names.get(..NAMED_APPS).unwrap_or(&names).join(", ");
    format!("{shown} and {} more", names.len() - NAMED_APPS)
}

fn channel(
    pack: &xs_model::pack::Pack,
    view: &View<'_>,
    found: &Found<'_>,
) -> (String, String, String) {
    let apps: Vec<(&App<'_>, &xs_model::Claim)> = found
        .apps
        .iter()
        .filter(|(_, found_in)| found_in.claim.party != Party::First)
        .filter_map(|(&index, found_in)| Some((view.apps.get(index)?, found_in.claim)))
        .collect();
    let mut about = String::from(found.category.name);
    if let Some(company) = found.company {
        about.push_str(", by ");
        about.push_str(&company.name);
    }
    about.push_str(", in ");
    about.push_str(&plural(apps.len() as u64, "app", "apps"));
    about.push_str(": ");
    about.push_str(&app_names(apps.iter().map(|(app, _)| app.title())));

    // The first step the report gives: the app's own setting, then a block
    // list, then removing the app.
    for &(app, claim) in &apps {
        if let InApp::Settings(_, settings) = in_app(pack, app, &claim.category)
            && let Some(setting) = settings.first()
        {
            let mut step = format!("In {}, turn it off: {}", app.title(), setting.steps);
            if !step.ends_with('.') {
                step.push('.');
            }
            return (String::from(found.name), about, step);
        }
    }
    for &(app, claim) in &apps {
        if let Some(hosts) = block_hosts(pack, claim, found.category.headline)
            && !hosts.is_empty()
        {
            let named = if hosts.len() <= NAMED_HOSTS + 1 {
                list_words(&hosts)
            } else {
                let shown = hosts.get(..NAMED_HOSTS).unwrap_or(&hosts).join(", ");
                format!("{shown} and {} more hosts the report lists", hosts.len() - NAMED_HOSTS)
            };
            let step = format!("Block {named} with {}.", firewall(app.subject.platform));
            return (String::from(found.name), about, step);
        }
    }
    let step =
        String::from("No setting to turn it off is on record. Remove the apps you can do without.");
    (String::from(found.name), about, step)
}

fn extension(app: &App<'_>, findings: &[&Finding<'_>]) -> (String, String, String) {
    let permissions: Vec<Permission> = findings
        .iter()
        .filter_map(|finding| Permission::from_id(&finding.claim.object.id))
        .collect();
    let allows: Vec<&str> = permissions.iter().map(|permission| permission.allows()).collect();
    let about = match app.browser {
        Some(browser) => {
            format!("Browser extension in {}. It may {}.", browser.name(), list_words(&allows))
        }
        None => format!("Browser extension. It may {}.", list_words(&allows)),
    };
    let browser = app.browser.map_or("your browser", Browser::name);
    let page = extensions_page(app.browser, app.subject.platform);
    let sites =
        permissions.iter().any(|&p| matches!(p, Permission::AllSites | Permission::BroadSites));
    let step = if sites {
        format!("Limit the sites it can read, or remove it: open {page} in {browser}.")
    } else {
        format!("Remove it if you do not use it: open {page} in {browser}.")
    };
    (String::from(app.title()), about, step)
}

fn pane(
    view: &View<'_>,
    pane: &str,
    apps: &[(usize, Vec<&Finding<'_>>)],
) -> (String, String, String) {
    let mut names: Vec<&str> = Vec::new();
    for finding in apps.iter().flat_map(|(_, findings)| findings.iter()) {
        if let Some(permission) = access::permission(&finding.claim.object.id)
            && !names.contains(&permission.name)
        {
            names.push(permission.name);
        }
    }
    let about = format!(
        "{}. {}: {}",
        list_words(&names),
        plural(apps.len() as u64, "app may ask", "apps may ask"),
        app_names(apps.iter().filter_map(|(index, _)| view.apps.get(*index)).map(App::title)),
    );
    let step = format!(
        "Open System Settings > Privacy & Security > {pane} and turn off the apps that do not \
         need it."
    );
    (String::from(pane), about, step)
}

fn android(app: &App<'_>, findings: &[&Finding<'_>]) -> (String, String, String) {
    let names: Vec<&str> =
        findings.iter().map(|finding| finding.claim.object.name.as_str()).collect();
    let about = format!("Android app. It may ask for {}.", list_words(&names));
    let on_page = findings
        .iter()
        .any(|finding| android_place(&finding.claim.object.id) == Place::AppPermissions);
    let step = if on_page {
        format!(
            "Open Settings > Apps > {} > Permissions and set what it does not need to Don't allow.",
            app.title()
        )
    } else {
        let path =
            findings.iter().find_map(|finding| match android_place(&finding.claim.object.id) {
                Place::Path(path) => Some(path),
                _ => None,
            });
        match path {
            Some(path) => format!("Open {path} and turn off {}.", app.title()),
            None => String::from("See the report for where to turn it off."),
        }
    };
    (String::from(app.title()), about, step)
}

/// `text` with every character a terminal could act on replaced: control
/// characters, which start escape sequences, and the marks that reverse the
/// direction of what follows.
pub(crate) fn plain(text: &str) -> String {
    text.chars()
        .map(|c| {
            let invisible = matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
            if c.is_control() || invisible { '\u{FFFD}' } else { c }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_cannot_reach_the_terminal_as_an_escape() {
        assert_eq!(plain("Evil\u{1b}[2J\u{7}App"), "Evil\u{FFFD}[2J\u{FFFD}App");
        assert_eq!(plain("a\u{202E}b\nc\td"), "a\u{FFFD}b\u{FFFD}c\u{FFFD}d");
        assert_eq!(plain("Café — ok"), "Café — ok");
    }

    #[test]
    fn long_lists_of_apps_are_cut() {
        let names = ["A", "B", "C", "D", "E", "F"];
        assert_eq!(app_names(names.iter().copied()), "A, B, C and 3 more");
        assert_eq!(app_names(names[..4].iter().copied()), "A, B, C and D");
        assert_eq!(app_names(names[..1].iter().copied()), "A");
    }
}
