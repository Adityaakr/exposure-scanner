//! What a person can do about what the report found.
//!
//! The report changes nothing on the device (project spec, "Fixes"): it
//! tells a person what they can do, where, and what it will and will not
//! achieve. That advice comes in two shapes, written from the same pieces
//! so the two always agree:
//!
//! * **under each finding**, the steps for that finding;
//! * **a checklist** near the top of the page, one entry per thing to do,
//!   with what exposes the most first.
//!
//! What holds for every app of a platform is fixed here, next to the fixed
//! lists of permissions it is about: where macOS and Android let a person
//! turn a permission off, and how a browser lets a person narrow or remove
//! an extension. What holds for one app or one SDK, such as an app's own
//! setting for usage data or the hosts an SDK sends to, is data the rule
//! pack carries ([`xs_model::fix`]).
//!
//! The advice keeps to the report's wording rule. It says what a setting is
//! documented to do, never that it stops a given SDK, which no scan of files
//! can show; it says an app "may" use a permission it asks for; and where
//! nothing can be done, or nothing is known, it says so.

pub(crate) mod text;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Reverse;

use xs_model::Claim;
use xs_model::access;
use xs_model::claim::Party;
use xs_model::fix::{AppFix, NoSetting, Setting};
use xs_model::matcher::Boundary;
use xs_model::pack::Pack;
use xs_model::permission::{self, Permission};
use xs_model::record::{Browser, EdgeType, ObjectKind, Platform, SubjectKind, declared};

use super::view::{App, Finding, Found, View};
use super::words::{list_words, plural};
use crate::markup::{Markup, Value};

/// How much an entry of the checklist exposes, which is the order the
/// checklist lists them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Priority {
    /// Code of a company in a category the headline counts, such as
    /// analytics or advertising, in an app it does not publish; and a
    /// browser extension that may read the pages a person visits or what
    /// they do in the browser.
    High,
    /// What an app may reach of the person and their surroundings: the
    /// camera, the microphone, the screen, location and personal data. And
    /// a domain an app itself declares it tracks through.
    Medium,
    /// The rest that a person can act on: other services of a company in an
    /// app, such as crash reporting, and access to files, nearby devices or
    /// other apps.
    Low,
}

impl Priority {
    const fn name(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }

    const fn class(self) -> &'static str {
        match self {
            Self::High => "prio p-high",
            Self::Medium => "prio p-medium",
            Self::Low => "prio p-low",
        }
    }
}

/// Where a person turns a permission off, or why there is nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Place {
    /// A pane under System Settings > Privacy & Security on macOS, by the
    /// name macOS gives it.
    Privacy(&'static str),
    /// Another place in the settings, written from the top.
    Path(&'static str),
    /// The app's own page of permissions on Android.
    AppPermissions,
    /// Nowhere: why not, as a sentence.
    Nowhere(&'static str),
}

/// What is said of a permission no place is known for.
const NO_PLACE_KNOWN: &str = "No place in the settings is known to this report where this can \
be turned off for one app.";

/// What is said of a permission the app holds by its signature alone.
const SIGNED_GRANT: &str = "The app's signature grants this. macOS has no switch for it: only \
removing the app takes it back.";

/// Where macOS lets a person turn off a permission an app asks for. The
/// names are those of System Settings on macOS 15 and later.
pub(crate) const fn macos_place(permission: &str) -> Place {
    match permission.as_bytes() {
        b"camera" => Place::Privacy("Camera"),
        b"microphone" => Place::Privacy("Microphone"),
        b"screen" | b"system-audio" => Place::Privacy("Screen & System Audio Recording"),
        b"speech-recognition" => Place::Privacy("Speech Recognition"),
        b"location" | b"location-background" => Place::Privacy("Location Services"),
        b"contacts" => Place::Privacy("Contacts"),
        b"calendars" | b"calendars-add" => Place::Privacy("Calendars"),
        b"reminders" => Place::Privacy("Reminders"),
        b"photos" | b"photos-add" => Place::Privacy("Photos"),
        b"media-library" => Place::Privacy("Media & Apple Music"),
        b"homekit" => Place::Privacy("Home"),
        b"bluetooth" => Place::Privacy("Bluetooth"),
        b"local-network" => Place::Privacy("Local Network"),
        b"automation" => Place::Privacy("Automation"),
        b"all-files" => Place::Privacy("Full Disk Access"),
        b"desktop-folder" | b"documents-folder" | b"downloads-folder" | b"network-volumes"
        | b"removable-volumes" => Place::Privacy("Files & Folders"),
        b"network-server" => Place::Path("System Settings > Network > Firewall > Options"),
        b"network-client" => Place::Nowhere(
            "macOS has no switch for an app's outgoing connections. An outbound firewall, such \
             as LuLu or Little Snitch, can block them.",
        ),
        b"user-selected-files" => Place::Nowhere(
            "The app can open only the files you choose in an Open or Save window. There is \
             nothing to turn off.",
        ),
        b"sandbox-exception-files" | b"movies-folder" | b"music-folder" | b"pictures-folder" => {
            Place::Nowhere(SIGNED_GRANT)
        }
        b"biometrics" => Place::Nowhere(
            "The app can ask Touch ID to confirm that it is you, and learns only whether it was. \
             It never receives a fingerprint, and there is no switch per app.",
        ),
        b"usb" => Place::Nowhere("macOS has no switch per app for USB devices."),
        _ => Place::Nowhere(NO_PLACE_KNOWN),
    }
}

/// Where Android lets a person turn off a permission an app asks for.
/// Phone makers rename menus, so the words are those of Android itself.
pub(crate) const fn android_place(permission: &str) -> Place {
    match permission.as_bytes() {
        b"all-files" => Place::Path("Settings > Apps > Special app access > All files access"),
        b"app-usage" => Place::Path("Settings > Apps > Special app access > Usage access"),
        b"network-client" => Place::Nowhere(
            "Android grants internet access when the app is installed, and has no switch for \
             it. A firewall app can block it.",
        ),
        b"installed-apps" | b"nfc" | b"advertising-id" => Place::Nowhere(
            "Android grants this when the app is installed, and has no switch for it per app.",
        ),
        b"biometrics" => Place::Nowhere(
            "The app can ask the fingerprint or face reader to confirm that it is you, and \
             learns only whether it was. It never receives a fingerprint.",
        ),
        b"screen" => Place::Nowhere(
            "Android asks you each time the app starts to record or share the screen.",
        ),
        _ => Place::AppPermissions,
    }
}

/// Where a permission of an app on `platform` is turned off.
const fn place(platform: Platform, permission: &str) -> Place {
    match platform {
        Platform::Android => android_place(permission),
        _ => macos_place(permission),
    }
}

/// What a person should know about a pane besides its name.
const fn pane_note(pane: &str) -> &'static str {
    match pane.as_bytes() {
        b"Files & Folders" => {
            "An app that is not in the list was not allowed through this pane: an app in the \
             App Sandbox may hold a folder by its signature, which has no switch."
        }
        b"Automation" => {
            "Each app is listed with the apps it may control; turn off any pair you do not use."
        }
        b"Location Services" => "Location Services also has a switch for all apps at once.",
        _ => "An app that is not in the list has not been allowed yet: macOS asks before it is.",
    }
}

/// The permissions of a browser extension that give it a wide view of
/// what a person does in the browser.
const fn is_wide(permission: Permission) -> bool {
    matches!(
        permission,
        Permission::AllSites
            | Permission::BroadSites
            | Permission::History
            | Permission::Cookies
            | Permission::WebRequest
            | Permission::WebNavigation
            | Permission::ClipboardRead
            | Permission::Debugger
            | Permission::Proxy
            | Permission::NativeMessaging
    )
}

/// The page of a browser that lists its extensions, as its address bar
/// takes it.
const fn extensions_page(browser: Option<Browser>, platform: Platform) -> &'static str {
    match (browser, platform) {
        (Some(Browser::Brave), _) => "brave://extensions",
        (Some(Browser::Edge), _) => "edge://extensions",
        (Some(Browser::Vivaldi), _) => "vivaldi://extensions",
        (Some(Browser::Firefox), _) | (None, Platform::Firefox) => "about:addons",
        _ => "chrome://extensions",
    }
}

/// The access category a permission of an app counts under, and what that
/// makes its priority.
fn access_priority(permission: &str) -> Priority {
    match access::permission(permission).map(|permission| permission.category) {
        Some("capture" | "location" | "personal_data" | "communications" | "tracking") => {
            Priority::Medium
        }
        _ => Priority::Low,
    }
}

/// What the app's publisher documents about turning off a service of one
/// category, for one app.
pub(crate) enum InApp<'a> {
    /// Settings that cover the category, in the order the publisher's steps
    /// are listed.
    Settings(&'a AppFix, Vec<&'a Setting>),
    /// The publisher documents that no setting covers it.
    None(&'a NoSetting),
    /// The rule pack holds nothing about it.
    Unknown,
}

pub(crate) fn in_app<'a>(pack: &'a Pack, app: &App<'_>, category: &str) -> InApp<'a> {
    let Some(fix) = pack.app_fix(app.subject.platform, &app.subject.id) else {
        return InApp::Unknown;
    };
    let covers = |list: &[String]| list.iter().any(|covered| covered == category);
    let settings: Vec<&Setting> =
        fix.settings.iter().filter(|setting| covers(&setting.covers)).collect();
    if !settings.is_empty() {
        return InApp::Settings(fix, settings);
    }
    match fix.no_setting.iter().find(|none| covers(&none.covers)) {
        Some(none) => InApp::None(none),
        None => InApp::Unknown,
    }
}

/// The hosts a firewall would block to cut off what a finding is about,
/// when blocking is advice the report gives: for a third-party SDK in a
/// category the headline counts, the hosts its rule names and those the
/// rule pack adds; for a domain an app's privacy manifest declares for
/// tracking, that domain, even when no company is named for it, since the
/// app itself says it tracks through it. `None` when blocking is not advice
/// for it at all: a crash reporter or an update feed is not blocked on the
/// report's word, and nor is anything of the app's own publisher (project
/// spec, "Fixes").
///
/// `counted` is whether the claim's category is one the headline counts.
pub(crate) fn block_hosts<'a>(
    pack: &'a Pack,
    claim: &'a Claim,
    counted: bool,
) -> Option<Vec<&'a str>> {
    if claim.edge != EdgeType::Channel || claim.party == Party::First {
        return None;
    }
    match claim.object.kind {
        ObjectKind::Sdk if counted && claim.party == Party::Third => {
            let mut hosts: Vec<&str> = Vec::new();
            if let Some(rule) = pack.rule(&claim.object.id) {
                hosts.extend(
                    rule.matchers
                        .values()
                        .flatten()
                        .filter(|token| token.at == Boundary::Host)
                        .map(|token| token.lit.as_str()),
                );
            }
            if let Some(fix) = pack.sdk_fix(&claim.object.id) {
                hosts.extend(fix.block.iter().map(String::as_str));
            }
            hosts.sort_unstable();
            hosts.dedup();
            Some(hosts)
        }
        ObjectKind::Host if is_tracking_domain(&claim.category) => {
            Some(alloc::vec![claim.object.id.as_str()])
        }
        _ => None,
    }
}

fn is_tracking_domain(category: &str) -> bool {
    declared::category(declared::TRACKING_DOMAIN) == Some(category)
}

/// What blocking hosts may cost and cannot reach, after the list of hosts.
const BLOCK_COST: &str = ". Blocking can stop features that rely on the service, and does not \
                          reach what the app sends through its own servers.";

/// What blocking a declared tracking domain may cost when who runs it is
/// not established.
const UNKNOWN_HOST: &str = " This domain may be a server of the app's own publisher: blocking it \
                            can break features of the app.";

fn is_update_feed(category: &str) -> bool {
    declared::category(declared::UPDATE_FEED) == Some(category)
}

/// The firewall a person on `platform` could use, in a phrase after "with".
const fn firewall(platform: Platform) -> &'static str {
    match platform {
        Platform::Android => "a firewall app that works without root, such as NetGuard",
        _ => "an outbound firewall such as LuLu (free) or Little Snitch",
    }
}

/// Writes the steps for one finding, as the items of a list.
pub(crate) fn finding_steps(
    page: &mut Markup,
    pack: &Pack,
    view: &View<'_>,
    finding: &Finding<'_>,
) {
    let claim = finding.claim;
    let Some(app) = view.app_of(&claim.subject) else { return };
    match (claim.edge, claim.object.kind) {
        (EdgeType::Access, ObjectKind::Permission)
            if app.subject.kind == SubjectKind::Extension =>
        {
            extension_steps(page, app, &[finding]);
        }
        (EdgeType::Access, _) | (_, ObjectKind::Permission) => access_step(page, app, finding),
        (EdgeType::Channel, _) => channel_steps(page, pack, app, finding),
    }
}

/// The steps for a channel: the app's own setting, a block list, another
/// app, removing the app.
fn channel_steps(page: &mut Markup, pack: &Pack, app: &App<'_>, finding: &Finding<'_>) {
    let claim = finding.claim;
    if is_update_feed(&claim.category) {
        step(page, |page| {
            page.raw(
                "Nothing to do: this is where the app fetches its own updates. Blocking it would \
                 stop updates, which often fix security problems.",
            );
        });
        return;
    }
    let Some(company) = finding.company else {
        if claim.object.kind == ObjectKind::Sdk {
            step(page, |page| {
                page.raw(
                    "Nothing to do: a component is a library with no service of its own behind it.",
                );
            });
            return;
        }
        if !is_tracking_domain(&claim.category) {
            step(page, |page| {
                page.raw("Nothing to do on this report's word: no company is named for this host.");
            });
            return;
        }
        block_step(page, pack, app, finding);
        uninstall_step(page, app);
        return;
    };
    if claim.party == Party::First {
        step(page, |page| {
            page.text(&company.name);
            page.raw(" publishes this app, so this is a service of the app's own publisher.");
        });
        if let InApp::Settings(fix, settings) = in_app(pack, app, &claim.category) {
            setting_steps(page, fix, &settings, finding.category.name);
        }
        return;
    }
    match in_app(pack, app, &claim.category) {
        InApp::Settings(fix, settings) => {
            setting_steps(page, fix, &settings, finding.category.name)
        }
        InApp::None(none) => step(page, |page| page.text(&none.says)),
        InApp::Unknown => step(page, |page| {
            page.raw("No setting of this app that turns it off is on record.");
        }),
    }
    block_step(page, pack, app, finding);
    if let Some(fix) = pack.app_fix(app.subject.platform, &app.subject.id) {
        for alternative in &fix.alternatives {
            step(page, |page| {
                page.raw("Or use ");
                page.text(&alternative.name);
                page.raw(" (");
                page.element("code", &[], &alternative.website);
                page.raw("): ");
                page.text(&alternative.about);
                page.raw(".");
            });
        }
    }
    uninstall_step(page, app);
}

/// The app's own settings for a category, each as a step.
fn setting_steps(page: &mut Markup, fix: &AppFix, settings: &[&Setting], category: &str) {
    for setting in settings {
        step(page, |page| {
            page.raw("Turn it off in ");
            page.text(&fix.name);
            page.raw(": ");
            page.text(&setting.steps);
            if !setting.steps.ends_with('.') {
                page.raw(".");
            }
            page.raw(" Its publisher documents this setting for ");
            page.text(&category.to_lowercase());
            page.raw("; a scan of the app's files cannot show that it stops this SDK.");
            if let Some(note) = &setting.note {
                page.raw(" ");
                page.text(note);
            }
        });
    }
}

/// The block list for a finding, when blocking is advice for it.
fn block_step(page: &mut Markup, pack: &Pack, app: &App<'_>, finding: &Finding<'_>) {
    let claim = finding.claim;
    match block_hosts(pack, claim, finding.category.headline) {
        Some(hosts) if !hosts.is_empty() => step(page, |page| {
            page.raw("Block ");
            page.raw(if hosts.len() == 1 { "this host" } else { "these hosts" });
            page.raw(" for ");
            page.text(app.title());
            page.raw(" with ");
            page.raw(firewall(app.subject.platform));
            page.raw(": ");
            for (at, host) in hosts.iter().enumerate() {
                if at > 0 {
                    page.raw(", ");
                }
                page.element("code", &[], host);
            }
            page.raw(BLOCK_COST);
            if claim.party == Party::Unknown {
                page.raw(UNKNOWN_HOST);
            }
        }),
        Some(_) => step(page, |page| {
            page.raw("The rule pack names no host for ");
            page.text(&claim.object.name);
            page.raw(", so no block list can be given.");
        }),
        None if claim.party == Party::Unknown && finding.category.headline => step(page, |page| {
            page.raw(
                "No block list is suggested: who publishes this app is not established, and \
                 blocking an app's own servers breaks it.",
            );
        }),
        None => {}
    }
}

fn uninstall_step(page: &mut Markup, app: &App<'_>) {
    step(page, |page| {
        page.raw("Or remove ");
        page.text(app.title());
        page.raw(" if you can do without it.");
    });
}

/// Where to turn off one permission of an app.
fn access_step(page: &mut Markup, app: &App<'_>, finding: &Finding<'_>) {
    let id = &finding.claim.object.id;
    step(page, |page| match place(app.subject.platform, id) {
        Place::Privacy(pane) => {
            page.raw("Open ");
            privacy_path(page, pane);
            page.raw(" and turn off ");
            page.text(app.title());
            page.raw(" if it does not need this. ");
            page.raw(pane_note(pane));
        }
        Place::Path(path) => {
            page.raw("Open ");
            page.element("strong", &[], path);
            page.raw(" and turn off ");
            page.text(app.title());
            page.raw(".");
        }
        Place::AppPermissions => {
            page.raw("Open ");
            android_app_path(page, app);
            page.raw(" and set ");
            page.text(&finding.claim.object.name);
            page.raw(" to Don't allow. Phone makers can name these menus differently.");
        }
        Place::Nowhere(why) => page.raw(why),
    });
}

fn privacy_path(page: &mut Markup, pane: &str) {
    page.open("strong", &[]);
    page.text("System Settings > Privacy & Security > ");
    page.text(pane);
    page.close();
}

fn android_app_path(page: &mut Markup, app: &App<'_>) {
    page.open("strong", &[]);
    page.text("Settings > Apps > ");
    page.text(app.title());
    page.text(" > Permissions");
    page.close();
}

/// What a person can do about the permissions of one browser extension.
fn extension_steps(page: &mut Markup, app: &App<'_>, findings: &[&Finding<'_>]) {
    let permissions: Vec<Permission> = findings
        .iter()
        .filter_map(|finding| Permission::from_id(&finding.claim.object.id))
        .collect();
    let sites =
        permissions.iter().any(|&p| matches!(p, Permission::AllSites | Permission::BroadSites));
    let others =
        permissions.iter().any(|&p| !matches!(p, Permission::AllSites | Permission::BroadSites));
    let page_name = extensions_page(app.browser, app.subject.platform);
    let firefox = page_name == "about:addons";
    let browser = app.browser.map_or("the browser", Browser::name);
    if sites {
        step(page, |page| {
            page.raw("Limit the sites it can read: open ");
            page.element("code", &[], page_name);
            page.raw(" in ");
            page.raw(browser);
            if firefox {
                page.raw(
                    ", choose the extension, then its Permissions tab, and turn off access to \
                     your data for all websites. Firefox has this switch for extensions built \
                     to the current format; for an older one, removing it is the way.",
                );
            } else {
                page.raw(
                    ", choose Details under the extension, and under Site access choose On click \
                     or On specific sites. It then reads a site only when you allow it.",
                );
            }
        });
    }
    if others {
        step(page, |page| {
            if firefox {
                page.raw(
                    "A permission it asks for as optional can be turned off in the same \
                     Permissions tab. The others stay as long as the extension is installed.",
                );
            } else {
                page.raw(if sites {
                    "The browser has no switch for its other permissions: they stay as long as \
                     the extension is installed."
                } else {
                    "The browser has no switch for these permissions: they stay as long as the \
                     extension is installed."
                });
            }
        });
    }
    step(page, |page| {
        page.raw("Or remove it: open ");
        page.element("code", &[], page_name);
        page.raw(" in ");
        page.raw(browser);
        page.raw(if firefox {
            ", open the menu of the extension and choose Remove."
        } else {
            " and choose Remove under the extension."
        });
    });
    if let Some(browser) = app.browser.filter(|&browser| !names_its_extensions_page(browser)) {
        step(page, |page| {
            page.raw("If ");
            page.raw(browser.name());
            page.raw(" does not open ");
            page.element("code", &[], page_name);
            page.raw(", its own menu lists the extensions it has installed.");
        });
    }
}

/// Whether the browser's own help names the page [`extensions_page`] gives
/// for it. Arc and Dia are built on Chromium, whose page that is, but their
/// help does not name it.
const fn names_its_extensions_page(browser: Browser) -> bool {
    !matches!(browser, Browser::Arc | Browser::Dia)
}

fn step(page: &mut Markup, body: impl FnOnce(&mut Markup)) {
    page.open("li", &[]);
    body(page);
    page.close();
    page.raw("\n");
}

/// One entry of the checklist.
enum Entry<'v, 'a> {
    /// A service of a company, or a declared tracking domain, with the apps
    /// it is in.
    Channel(&'v Found<'a>),
    /// A browser extension and what it may be allowed.
    Extension(usize, Vec<&'v Finding<'a>>),
    /// A pane of System Settings, with the apps that may ask for what it
    /// controls.
    Pane(&'static str, Vec<(usize, Vec<&'v Finding<'a>>)>),
    /// An Android app and the permissions a person can turn off.
    Android(usize, Vec<&'v Finding<'a>>),
}

impl Entry<'_, '_> {
    /// Where an entry of one priority sorts: channels first, then
    /// extensions, then what apps may access.
    const fn rank(&self) -> u8 {
        match self {
            Self::Channel(_) => 0,
            Self::Extension(..) => 1,
            Self::Pane(..) => 2,
            Self::Android(..) => 3,
        }
    }

    fn reach(&self) -> usize {
        match self {
            Self::Channel(found) => found.apps.len(),
            Self::Pane(_, apps) => apps.len(),
            Self::Extension(..) | Self::Android(..) => 1,
        }
    }
}

/// The checklist: every entry with its priority, in the order a reader
/// should act on them.
fn checklist<'v, 'a>(view: &'v View<'a>) -> Vec<(Priority, String, Entry<'v, 'a>)> {
    let mut entries: Vec<(Priority, String, Entry<'v, 'a>)> = Vec::new();
    for found in &view.found {
        if found.edge != EdgeType::Channel
            || (found.company.is_none() && !is_tracking_domain(category_id(found)))
        {
            continue;
        }
        let outside = found.apps.values().any(|app| app.claim.party != Party::First);
        if !outside || is_update_feed(category_id(found)) {
            continue;
        }
        let priority = if found.category.headline {
            Priority::High
        } else if is_tracking_domain(category_id(found)) {
            Priority::Medium
        } else {
            Priority::Low
        };
        entries.push((priority, found.name.to_lowercase(), Entry::Channel(found)));
    }

    let mut panes: BTreeMap<&'static str, BTreeMap<usize, Vec<&'v Finding<'a>>>> = BTreeMap::new();
    let mut pane_priority: BTreeMap<&'static str, Priority> = BTreeMap::new();
    for group in &view.access {
        let Some(app) = view.apps.get(group.app) else { continue };
        match (app.subject.kind, app.subject.platform) {
            (SubjectKind::Extension, _) => {
                let wide = group.findings.iter().any(|finding| {
                    Permission::from_id(&finding.claim.object.id).is_some_and(is_wide)
                        && !finding.claim.notes.iter().any(|note| note == permission::NOTE_OPTIONAL)
                });
                let priority = if wide { Priority::High } else { Priority::Medium };
                let findings = group.findings.iter().collect();
                entries.push((
                    priority,
                    app.title().to_lowercase(),
                    Entry::Extension(group.app, findings),
                ));
            }
            (_, Platform::Android) => {
                let findings: Vec<&Finding<'a>> = group
                    .findings
                    .iter()
                    .filter(|finding| {
                        !matches!(android_place(&finding.claim.object.id), Place::Nowhere(_))
                    })
                    .collect();
                let Some(priority) =
                    findings.iter().map(|finding| access_priority(&finding.claim.object.id)).min()
                else {
                    continue;
                };
                entries.push((
                    priority,
                    app.title().to_lowercase(),
                    Entry::Android(group.app, findings),
                ));
            }
            _ => {
                for finding in &group.findings {
                    let id = &finding.claim.object.id;
                    let Place::Privacy(pane) = macos_place(id) else { continue };
                    panes.entry(pane).or_default().entry(group.app).or_default().push(finding);
                    let priority = pane_priority.entry(pane).or_insert(Priority::Low);
                    *priority = (*priority).min(access_priority(id));
                }
            }
        }
    }
    for (pane, apps) in panes {
        let priority = pane_priority.get(pane).copied().unwrap_or(Priority::Low);
        entries.push((
            priority,
            pane.to_lowercase(),
            Entry::Pane(pane, apps.into_iter().collect()),
        ));
    }
    entries.sort_by(|a, b| {
        (a.0, a.2.rank(), Reverse(a.2.reach()), &a.1).cmp(&(
            b.0,
            b.2.rank(),
            Reverse(b.2.reach()),
            &b.1,
        ))
    });
    entries
}

/// The category id the claims of a thing found were derived under.
fn category_id<'a>(found: &Found<'a>) -> &'a str {
    found.apps.values().next().map_or("", |app| app.claim.category.as_str())
}

/// Writes the checklist section.
pub(crate) fn actions(page: &mut Markup, pack: &Pack, view: &View<'_>) {
    page.raw(
        "<p>What you can do about what was found, with what exposes the most first. Nothing \
         here is done for you: the scanner changes nothing on this device. Each entry links to \
         the findings it is about, which show the evidence.</p>\n\
         <ul class=\"priorities\">\n\
         <li><span class=\"prio p-high\">High</span> Code of a company that does advertising, \
         analytics, attribution, profiling or session replay, in an app that company does not \
         publish; and a browser extension that may read the pages you visit or what you do in \
         the browser.</li>\n\
         <li><span class=\"prio p-medium\">Medium</span> What apps may reach of you and your \
         surroundings: camera, microphone, screen, location and personal data; and a domain an \
         app declares for tracking.</li>\n\
         <li><span class=\"prio p-low\">Low</span> Other services of a company in an app, such \
         as crash reporting, and access to files, nearby devices and other apps.</li>\n\
         </ul>\n",
    );
    let entries = checklist(view);
    if entries.is_empty() {
        page.raw(
            "<p class=\"none\">Nothing here calls for action: no finding is a service of another \
             company than the app's publisher, and no app or extension asks for a permission \
             that can be turned off.</p>\n",
        );
        return;
    }
    page.raw("<ul class=\"checklist\">\n");
    for (priority, _, entry) in &entries {
        page.open_class("li", "todo");
        page.raw("\n");
        match entry {
            Entry::Channel(found) => channel_entry(page, pack, view, *priority, found),
            Entry::Extension(app, findings) => {
                extension_entry(page, view, *priority, *app, findings)
            }
            Entry::Pane(pane, apps) => pane_entry(page, view, *priority, pane, apps),
            Entry::Android(app, findings) => android_entry(page, view, *priority, *app, findings),
        }
        page.close();
        page.raw("\n");
    }
    page.raw("</ul>\n");
    page.raw(
        "<p class=\"note\">The steps name menus as the publishers and the operating systems \
         name them. A setting can move between versions of an app, and what a setting covers is \
         what its publisher documents: a scan of files cannot show what an app sends once it is \
         turned off. Block lists name only hosts of advertising, analytics, attribution, \
         profiling and session replay, and domains an app declares for tracking: blocking a \
         crash reporter or an app's own servers breaks more than it protects.</p>\n",
    );
}

fn entry_head(page: &mut Markup, priority: Priority, title: &str, tag: Option<&str>) {
    page.open_class("p", "todo-head");
    page.classed("span", priority.class(), priority.name());
    page.raw(" ");
    page.element("strong", &[], title);
    if let Some(tag) = tag {
        page.raw(" ");
        page.classed("span", "tag", tag);
    }
    page.close();
    page.raw("\n");
}

/// A link to a finding, named by its app.
fn app_link(page: &mut Markup, app: &App<'_>, claim: &Claim) {
    page.element("a", &[("href", Value::Link("f-", claim.id.digest()))], app.title());
}

fn channel_entry(
    page: &mut Markup,
    pack: &Pack,
    view: &View<'_>,
    priority: Priority,
    found: &Found<'_>,
) {
    entry_head(page, priority, found.name, Some(found.category.name));
    page.open_class("p", "meta");
    if let Some(company) = found.company {
        page.text(&company.name);
        page.raw(" · ");
    }
    page.text(&plural(found.apps.len() as u64, "app", "apps"));
    page.close();
    page.raw("\n<ul class=\"steps\">\n");
    let mut silent: Vec<(&App<'_>, &Claim)> = Vec::new();
    let mut blockable: Vec<(&App<'_>, &Claim)> = Vec::new();
    for (&index, found_in) in &found.apps {
        let Some(app) = view.apps.get(index) else { continue };
        let claim = found_in.claim;
        if claim.party == Party::First {
            continue;
        }
        match in_app(pack, app, &claim.category) {
            InApp::Settings(fix, settings) => {
                for setting in settings {
                    step(page, |page| {
                        page.raw("In ");
                        app_link(page, app, claim);
                        page.raw(", turn it off: ");
                        page.text(&setting.steps);
                        if !setting.steps.ends_with('.') {
                            page.raw(".");
                        }
                        page.raw(" ");
                        page.text(&fix.name);
                        page.raw(" documents this setting for ");
                        page.text(&found.category.name.to_lowercase());
                        page.raw(".");
                        if let Some(note) = &setting.note {
                            page.raw(" ");
                            page.text(note);
                        }
                    });
                }
            }
            InApp::None(none) => step(page, |page| {
                page.raw("In ");
                app_link(page, app, claim);
                page.raw(": ");
                page.text(&none.says);
            }),
            InApp::Unknown => silent.push((app, claim)),
        }
        if matches!(block_hosts(pack, claim, found.category.headline), Some(hosts) if !hosts.is_empty())
        {
            blockable.push((app, claim));
        }
    }
    if !silent.is_empty() {
        step(page, |page| {
            page.raw("No setting that turns it off is on record for ");
            for (at, (app, claim)) in silent.iter().enumerate() {
                if at > 0 {
                    page.raw(", ");
                }
                app_link(page, app, claim);
            }
            page.raw(".");
        });
    }
    let mut firewalls: Vec<&'static str> = Vec::new();
    for (app, _) in &blockable {
        let tool = firewall(app.subject.platform);
        if !firewalls.contains(&tool) {
            firewalls.push(tool);
        }
    }
    for tool in firewalls {
        let group: Vec<_> =
            blockable.iter().filter(|(app, _)| firewall(app.subject.platform) == tool).collect();
        let Some(&&(_, claim)) = group.first() else { continue };
        let hosts = block_hosts(pack, claim, found.category.headline).unwrap_or_default();
        step(page, |page| {
            page.raw("Block ");
            page.raw(if hosts.len() == 1 { "this host" } else { "these hosts" });
            page.raw(" for ");
            for (at, (app, claim)) in group.iter().enumerate() {
                if at > 0 {
                    page.raw(", ");
                }
                app_link(page, app, claim);
            }
            page.raw(" with ");
            page.raw(tool);
            page.raw(": ");
            for (at, host) in hosts.iter().enumerate() {
                if at > 0 {
                    page.raw(", ");
                }
                page.element("code", &[], host);
            }
            page.raw(BLOCK_COST);
            if group.iter().any(|(_, claim)| claim.party == Party::Unknown) {
                page.raw(UNKNOWN_HOST);
            }
        });
    }
    let third = found.apps.values().any(|app| app.claim.party == Party::Third);
    if blockable.is_empty() && third && found.category.headline && found.kind == ObjectKind::Sdk {
        step(page, |page| {
            page.raw("The rule pack names no host for ");
            page.text(found.name);
            page.raw(", so no block list can be given.");
        });
    }
    step(page, |page| page.raw("Or remove the apps you can do without."));
    page.raw("</ul>\n");
}

fn extension_entry(
    page: &mut Markup,
    view: &View<'_>,
    priority: Priority,
    index: usize,
    findings: &[&Finding<'_>],
) {
    let Some(app) = view.apps.get(index) else { return };
    entry_head(page, priority, app.title(), Some("Browser extension"));
    page.open_class("p", "meta");
    if let Some(browser) = app.browser {
        page.raw("In ");
        page.raw(browser.name());
        page.raw(" · ");
    }
    page.raw("It may ");
    let mut said: Vec<&str> = Vec::new();
    for finding in findings {
        if let Some(permission) = Permission::from_id(&finding.claim.object.id) {
            said.push(permission.allows());
        }
    }
    page.text(&list_words(&said));
    page.raw(".");
    page.close();
    page.raw("\n<ul class=\"steps\">\n");
    extension_steps(page, app, findings);
    if let Some(first) = findings.first() {
        step(page, |page| {
            page.element(
                "a",
                &[("href", Value::Link("f-", first.claim.id.digest()))],
                "The findings",
            );
            page.raw(" show the manifest keys it asks in.");
        });
    }
    page.raw("</ul>\n");
}

fn pane_entry(
    page: &mut Markup,
    view: &View<'_>,
    priority: Priority,
    pane: &str,
    apps: &[(usize, Vec<&Finding<'_>>)],
) {
    let names: Vec<&str> = apps
        .iter()
        .flat_map(|(_, findings)| findings.iter())
        .filter_map(|finding| access::permission(&finding.claim.object.id).map(|p| p.name))
        .fold(Vec::new(), |mut names, name| {
            if !names.contains(&name) {
                names.push(name);
            }
            names
        });
    entry_head(page, priority, pane, None);
    page.open_class("p", "meta");
    page.text(&list_words(&names));
    page.raw(" · ");
    page.text(&plural(apps.len() as u64, "app may ask", "apps may ask"));
    page.close();
    page.raw("\n<ul class=\"steps\">\n");
    step(page, |page| {
        page.raw("Open ");
        privacy_path(page, pane);
        page.raw(" and turn off the apps that do not need it: ");
        for (at, (index, findings)) in apps.iter().enumerate() {
            let (Some(app), Some(finding)) = (view.apps.get(*index), findings.first()) else {
                continue;
            };
            if at > 0 {
                page.raw(", ");
            }
            app_link(page, app, finding.claim);
        }
        page.raw(". ");
        page.raw(pane_note(pane));
    });
    page.raw("</ul>\n");
}

fn android_entry(
    page: &mut Markup,
    view: &View<'_>,
    priority: Priority,
    index: usize,
    findings: &[&Finding<'_>],
) {
    let Some(app) = view.apps.get(index) else { return };
    entry_head(page, priority, app.title(), Some("Android app"));
    page.raw("<ul class=\"steps\">\n");
    let mut on_page: Vec<&Finding<'_>> = Vec::new();
    for finding in findings {
        match android_place(&finding.claim.object.id) {
            Place::AppPermissions => on_page.push(finding),
            Place::Path(path) => step(page, |page| {
                page.raw("Open ");
                page.element("strong", &[], path);
                page.raw(" and turn off ");
                app_link(page, app, finding.claim);
                page.raw(".");
            }),
            Place::Privacy(_) | Place::Nowhere(_) => {}
        }
    }
    if !on_page.is_empty() {
        step(page, |page| {
            page.raw("Open ");
            android_app_path(page, app);
            page.raw(" and set what it does not need to Don't allow: ");
            for (at, finding) in on_page.iter().enumerate() {
                if at > 0 {
                    page.raw(", ");
                }
                page.element(
                    "a",
                    &[("href", Value::Link("f-", finding.claim.id.digest()))],
                    &finding.claim.object.name,
                );
            }
            page.raw(". Phone makers can name these menus differently.");
        });
    }
    page.raw("</ul>\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every permission an app can ask for has an answer on each platform,
    /// and a pane is only ever named for a permission macOS lists in one.
    #[test]
    fn every_permission_has_a_place() {
        for permission in access::PERMISSIONS {
            for platform in [Platform::Macos, Platform::Android] {
                match place(platform, permission.id) {
                    Place::Privacy(pane) => {
                        assert!(!pane.is_empty() && platform == Platform::Macos)
                    }
                    Place::Path(path) => {
                        assert!(path.starts_with("System Settings") || path.starts_with("Settings"))
                    }
                    Place::AppPermissions => assert_eq!(platform, Platform::Android),
                    Place::Nowhere(why) => assert!(why.ends_with('.')),
                }
            }
        }
    }

    #[test]
    fn the_capture_permissions_are_reviewed_before_files() {
        assert!(access_priority("camera") < access_priority("downloads-folder"));
        assert_eq!(access_priority("location"), Priority::Medium);
        assert_eq!(access_priority("bluetooth"), Priority::Low);
        assert_eq!(access_priority("no-such-permission"), Priority::Low);
    }

    #[test]
    fn each_browser_has_its_extensions_page() {
        assert_eq!(extensions_page(Some(Browser::Brave), Platform::Chromium), "brave://extensions");
        assert_eq!(extensions_page(Some(Browser::Firefox), Platform::Firefox), "about:addons");
        assert_eq!(extensions_page(None, Platform::Firefox), "about:addons");
        assert_eq!(extensions_page(None, Platform::Chromium), "chrome://extensions");
        assert_eq!(extensions_page(Some(Browser::Arc), Platform::Chromium), "chrome://extensions");
    }
}
