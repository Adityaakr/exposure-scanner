//! What each command does.

use std::fs;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use xs_match::Matchers;
use xs_model::record::Record;
use xs_model::report::{ScanScope, Scanner};
use xs_model::{EvidenceSet, Headline, Pack, Report};
use xs_render::{ReportMeta, Todo};
use xs_rules::{SignedLayer, TRUSTED_KEYS};

use crate::args;

/// The rule pack compiled into the binary, with its signature. It is checked
/// against the built-in keys on every start, exactly like a pack from a file,
/// so a build whose embedded rules were altered refuses to run.
const BUILT_IN_PACK: &[u8] = include_bytes!("../../../rules/dist/core.pack.json");
const BUILT_IN_SIGNATURE: &str = include_str!("../../../rules/dist/core.pack.json.minisig");

/// A FILE that stands for standard output.
const STDOUT: &str = "-";

/// How many entries of the checklist a scan prints. The report has them all.
const PRINTED_TODOS: usize = 5;

/// Largest saved report `exposure report` reads.
const MAX_REPORT_BYTES: u64 = 1 << 30;

/// Errors are messages for the user's terminal.
type Result<T> = std::result::Result<T, String>;

fn built_in_pack() -> Result<Pack> {
    xs_rules::load_pack(
        &[SignedLayer { bytes: BUILT_IN_PACK, signature: BUILT_IN_SIGNATURE }],
        TRUSTED_KEYS,
    )
    .map_err(|error| format!("the built-in rule pack was refused: {error}"))
}

fn this_scanner() -> Scanner {
    Scanner { name: String::from("exposure"), version: String::from(env!("CARGO_PKG_VERSION")) }
}

/// Writes text to standard output.
pub(crate) fn print(text: &str) -> Result<()> {
    std::io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .map_err(|error| format!("cannot write output: {error}"))
}

/// Writes a report to `path`, readable by its owner only, or to standard
/// output when no path is given. A `path` that is not a regular file, such
/// as `/dev/null`, is written to and otherwise left as it is.
fn deliver(report: &str, path: Option<&Path>) -> Result<()> {
    let Some(path) = path.filter(|path| *path != Path::new(STDOUT)) else { return print(report) };
    let fail = |error| format!("cannot write {}: {error}", path.display());
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(fail)?;
    #[cfg(unix)]
    {
        // `mode` only applies to a new file; tighten one that existed.
        use std::os::unix::fs::PermissionsExt as _;
        if file.metadata().map_err(fail)?.is_file() {
            file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(fail)?;
        }
    }
    file.write_all(report.as_bytes()).map_err(fail)
}

/// Where a command writes its reports.
#[derive(Clone, Copy)]
struct Outputs<'a> {
    /// The file for the report a person reads, if one was asked for.
    html: Option<&'a Path>,
    /// The file for the JSON report, if one was asked for.
    json: Option<&'a Path>,
    /// Whether the checklist is wanted in plain words, for the terminal.
    checklist: bool,
}

/// A rendered report, and what the terminal summary says about it.
struct Rendered {
    /// The JSON document.
    json: String,
    /// The HTML document, when one was asked for.
    html: Option<String>,
    /// How many claims it holds.
    claims: usize,
    /// Its headline counts.
    headline: Headline,
    /// The checklist in plain words, when it was asked for.
    todos: Vec<Todo>,
}

/// Derives claims from `evidence` and renders the reports `outputs` asks
/// for. Both documents are rendered from the same claims.
///
/// `scope` is where the scan looked. Both documents carry it, so the page
/// rendered from a saved JSON report is the page of the scan.
fn render(
    evidence: &EvidenceSet,
    pack: &Pack,
    scanner: Scanner,
    scope: Option<ScanScope>,
    outputs: Outputs<'_>,
) -> Result<Rendered> {
    let claims = xs_derive::derive(evidence, pack).map_err(|error| error.to_string())?;
    let meta = ReportMeta { scanner, packs: pack.refs(), scope };
    let json = xs_render::json(&claims, evidence, &meta).map_err(|error| error.to_string())?;
    let html = match outputs.html {
        Some(_) => Some(
            xs_render::html(&claims, evidence, &meta, pack).map_err(|error| error.to_string())?,
        ),
        None => None,
    };
    let todos = if outputs.checklist {
        xs_render::checklist(&claims, evidence, &meta, pack).map_err(|error| error.to_string())?
    } else {
        Vec::new()
    };
    Ok(Rendered { json, html, claims: claims.len(), headline: Headline::of(&claims), todos })
}

/// Writes the reports where `outputs` says. The JSON report goes to
/// standard output only when no file at all was asked for: someone who asks
/// for the report to read does not want the other one on the terminal.
///
/// Nothing is written unless every report was rendered, so a refused report
/// leaves no half of itself behind.
fn deliver_all(report: &Rendered, outputs: Outputs<'_>) -> Result<()> {
    if let (Some(html), Some(path)) = (&report.html, outputs.html) {
        deliver(html, Some(path))?;
    }
    match (outputs.json, outputs.html) {
        (Some(path), _) => deliver(&report.json, Some(path)),
        (None, None) => deliver(&report.json, None),
        (None, Some(_)) => Ok(()),
    }
}

fn plural(count: u64, noun: &str) -> String {
    match (count, noun.strip_suffix('y')) {
        (1, _) => format!("1 {noun}"),
        (_, Some(stem)) => format!("{count} {stem}ies"),
        (_, None) => format!("{count} {noun}s"),
    }
}

/// `exposure scan`
pub(crate) fn scan(args: &args::Scan) -> Result<()> {
    let pack = built_in_pack()?;
    let matchers = Matchers::build(&pack).map_err(|error| error.to_string())?;
    let cache_dir = match &args.cache {
        args::Cache::Default => xs_collect::cache::default_dir(),
        args::Cache::Off => None,
    };
    // With no file named, the report for reading goes to the default place.
    // Where that is is settled before the scan, so a scan is not run in vain.
    let default_page = match (&args.html, &args.json) {
        (None, None) => Some(default_report()?),
        _ => None,
    };
    let options = xs_collect::ScanOptions { threads: args.threads, cache: cache_dir.as_deref() };
    let outcome =
        xs_collect::scan(&args.paths, &matchers, options).map_err(|error| error.to_string())?;
    if let Some(page) = &default_page {
        make_private_folder(page)?;
    }
    let outputs = Outputs {
        html: args.html.as_deref().or(default_page.as_deref()),
        json: args.json.as_deref(),
        checklist: default_page.is_some(),
    };
    let report = render(&outcome.evidence, &pack, this_scanner(), Some(outcome.scope), outputs)?;
    deliver_all(&report, outputs)?;

    let gaps =
        outcome.evidence.iter().filter(|(_, record)| matches!(record, Record::Coverage(_))).count();
    let stats = outcome.stats;
    // A summary for the terminal. It names no app, no company and no path
    // the user gave.
    let headline = report.headline;
    let mut scanned = plural(stats.artifacts, "app");
    if stats.extensions > 0 {
        scanned = format!("{scanned} and {}", plural(stats.extensions, "browser extension"));
    }
    let _ = writeln!(
        std::io::stderr(),
        "exposure: scanned {scanned} ({}, {}): {}, {}\n\
         exposure: headline: {} at contacts or above, {} at contains, {} with a third-party channel\n\
         exposure: scope: {}",
        plural(stats.files, "file"),
        plural(stats.bytes, "byte"),
        plural(report.claims as u64, "claim"),
        plural(gaps as u64, "coverage note"),
        plural(headline.companies_contacts.into(), "company"),
        plural(headline.companies_contains.into(), "company"),
        plural(headline.apps_third_party.into(), "app"),
        outcome.scope,
    );
    // What the cache did. It names no folder unless the folder is at fault.
    let cache = match (&args.cache, &cache_dir, &outcome.cache_failure) {
        (args::Cache::Off, ..) => None,
        (_, None, _) => Some(String::from("not used: there is no home folder to keep it in")),
        (_, Some(_), Some(xs_collect::CacheError::Root)) => {
            Some(String::from("not used when run as root"))
        }
        (_, Some(_), Some(error)) => Some(format!("not used: {error}")),
        (_, Some(_), None) => Some(format!(
            "{} unchanged since an earlier scan and not read again, {} read",
            plural(stats.reused, "app"),
            plural(stats.artifacts.saturating_sub(stats.reused), "app"),
        )),
    };
    if let Some(cache) = cache {
        let _ = writeln!(std::io::stderr(), "exposure: cache: {cache}");
    }

    if let Some(page) = default_page {
        // A browser is only started for a person at a terminal: never for
        // a script, a pipe or a test.
        let opened = args.open && std::io::stdout().is_terminal() && open_in_browser(&page);
        print(&summary(&report, &scanned, &page, opened))?;
    }
    Ok(())
}

/// How far the lines of a checklist entry are indented.
const INDENT: &str = "       ";
/// The width the summary is wrapped to.
const WIDTH: usize = 80;

/// `text` as lines no wider than [`WIDTH`] where it can be, each indented
/// by `indent`. A word longer than a line, such as a host name, is kept
/// whole.
fn wrap(text: &str, indent: &str) -> String {
    let mut out = String::new();
    let mut line = String::from(indent);
    for word in text.split_whitespace() {
        let filled = line.len() > indent.len();
        if filled && line.chars().count() + 1 + word.chars().count() > WIDTH {
            out.push_str(&line);
            out.push('\n');
            line = String::from(indent);
        } else if filled {
            line.push(' ');
        }
        line.push_str(word);
    }
    out.push_str(&line);
    out.push('\n');
    out
}

/// Where `exposure scan` writes the report when no file is named:
/// `report.html` in the user's data folder, in a folder of its own that
/// only the user can read. That is `~/Library/Application Support` on
/// macOS. Elsewhere it is the folder `XDG_DATA_HOME` names, or
/// `~/.local/share` without one, as the XDG base directory specification
/// has it.
fn default_report() -> Result<PathBuf> {
    let home = std::env::home_dir().filter(|home| home.is_absolute());
    let data = if cfg!(target_os = "macos") {
        home.map(|home| home.join("Library/Application Support"))
    } else {
        xdg_data_home().or_else(|| home.map(|home| home.join(".local/share")))
    };
    let folder = data
        .ok_or("there is no home folder to keep the report in; name a file with --html FILE")?
        .join("exposure");
    Ok(folder.join("report.html"))
}

/// Makes the folder `page` goes in, readable by its owner only.
fn make_private_folder(page: &Path) -> Result<()> {
    let Some(folder) = page.parent() else { return Ok(()) };
    let fail = |error: std::io::Error| format!("cannot make {}: {error}", folder.display());
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        builder.mode(0o700);
        builder.create(folder).map_err(fail)?;
        // `mode` only applies to a new folder; tighten one that existed.
        fs::set_permissions(folder, fs::Permissions::from_mode(0o700)).map_err(fail)
    }
    #[cfg(not(unix))]
    builder.create(folder).map_err(fail)
}

/// The folder `XDG_DATA_HOME` names. The specification has a value that is
/// not an absolute path ignored.
#[expect(
    clippy::disallowed_methods,
    reason = "where the report is written is not in the report: its bytes do not depend on it"
)]
fn xdg_data_home() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|path| path.is_absolute())
}

/// Opens the report in the default browser, and says whether that worked.
///
/// This is the one process the scanner starts, and only after the scan is
/// over: macOS's own opener, called by its absolute path and never looked
/// up through `PATH`, given the report the scan just wrote. Nothing that was
/// scanned is ever run.
#[cfg(target_os = "macos")]
#[expect(
    clippy::disallowed_types,
    reason = "the report is handed to the system's opener once the scan is over; nothing scanned is run"
)]
fn open_in_browser(page: &Path) -> bool {
    std::process::Command::new("/usr/bin/open")
        .arg(page)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Elsewhere no process is started, and the summary prints the path. On
/// Linux the standard library's process spawning imports `socketpair`,
/// `sendmsg` and `recvmsg`, which the binary must not import at all.
#[cfg(not(target_os = "macos"))]
fn open_in_browser(_page: &Path) -> bool {
    false
}

/// What a scan that wrote its report to the default place tells the person
/// who ran it: where the report is, what the headline says, and the first
/// entries of the checklist.
fn summary(report: &Rendered, scanned: &str, page: &Path, opened: bool) -> String {
    let mut out = String::new();
    let path = page.display().to_string();
    out.push_str(&format!("\nYour report: {path}\n"));
    if opened {
        out.push_str("It is open in your browser.\n");
    } else if cfg!(target_os = "macos") {
        out.push_str(&format!("Open it with: open '{}'\n", path.replace('\'', "'\\''")));
    } else {
        out.push_str("Open it in your browser.\n");
    }

    let headline = report.headline;
    out.push_str(&format!("\nScanned {scanned}.\n"));
    if headline.companies_contacts > 0 {
        out.push_str(&format!(
            "  {} with a recorded connection\n",
            plural(headline.companies_contacts.into(), "company")
        ));
    }
    out.push_str(&format!(
        "  {} whose code the scanned apps ship, in advertising, analytics and the like\n\
         \x20 {} with code or an endpoint of a company other than their publisher\n",
        plural(headline.companies_contains.into(), "company"),
        plural(headline.apps_third_party.into(), "app"),
    ));

    let todos = &report.todos;
    if todos.is_empty() {
        out.push_str(
            "\nNothing calls for action: no finding is a service of another company than the \
             app's publisher, and no app or extension asks for a permission that can be turned \
             off.\n",
        );
    } else {
        let shown = todos.len().min(PRINTED_TODOS);
        out.push_str(&format!("\nWhat you can do first ({shown} of {}):\n", todos.len()));
        for (at, todo) in todos.iter().take(PRINTED_TODOS).enumerate() {
            out.push_str(&format!("\n{:>3}. [{}] {}\n", at + 1, todo.priority.name(), todo.title));
            out.push_str(&wrap(&todo.about, INDENT));
            out.push_str(&wrap(&todo.step, INDENT));
        }
        if todos.len() > shown {
            let more = todos.len() - shown;
            let entries = if more == 1 { "entry" } else { "entries" };
            out.push_str(&format!("\n{more} more {entries} in the report.\n"));
        }
    }
    out.push('\n');
    out.push_str(&wrap(
        "The report has every step and the evidence behind each finding. It lists apps you use, \
         so keep it private.",
        "",
    ));
    out
}

/// `exposure report`: the pure half of the pipeline, run on saved evidence.
pub(crate) fn report(args: &args::Report) -> Result<()> {
    let fail =
        |error: &dyn std::fmt::Display| format!("cannot read {}: {error}", args.file.display());
    let size = fs::metadata(&args.file).map_err(|error| fail(&error))?.len();
    if size > MAX_REPORT_BYTES {
        return Err(fail(&"the file is larger than 1 GiB"));
    }
    let bytes = fs::read(&args.file).map_err(|error| fail(&error))?;
    // Parsing re-checks every record and every record id, so evidence that
    // was edited after the scan is refused here.
    let saved: Report = serde_json::from_slice(&bytes).map_err(|error| fail(&error))?;
    let pack = built_in_pack()?;
    // The evidence was gathered by the scanner the file names; keep that.
    let outputs =
        Outputs { html: args.html.as_deref(), json: args.json.as_deref(), checklist: false };
    let report = render(&saved.evidence, &pack, saved.scanner, saved.scope, outputs)?;
    deliver_all(&report, outputs)
}

/// `exposure rules show`
pub(crate) fn rules_show() -> Result<()> {
    let pack = built_in_pack()?;
    let mut out = String::new();
    for loaded in pack.layers() {
        let layer = &loaded.layer;
        out.push_str(&format!(
            "layer {} version {} ({}), sha256 {}\n",
            layer.layer, layer.version, layer.license, loaded.sha256
        ));
    }
    out.push_str(&format!("{}\n\n", plural(pack.rule_count() as u64, "rule")));
    for rule in pack.rules() {
        let owner = rule.entity.as_deref().and_then(|entity| pack.company_of(entity));
        let owner = owner.map_or("component, no company", |company| company.name.as_str());
        out.push_str(&format!("{:<28} {:<32} {:<16} {owner}\n", rule.id, rule.name, rule.category));
    }
    print(&out)
}

/// `exposure rules verify`: checks a pack file offline against the built-in
/// keys.
pub(crate) fn rules_verify(args: &args::RulesVerify) -> Result<()> {
    let bytes = fs::read(&args.pack)
        .map_err(|error| format!("cannot read {}: {error}", args.pack.display()))?;
    let signature = fs::read_to_string(&args.signature)
        .map_err(|error| format!("cannot read {}: {error}", args.signature.display()))?;
    let key = xs_rules::verify_signature(&bytes, &signature, TRUSTED_KEYS)
        .map_err(|error| error.to_string())?;
    let pack =
        xs_rules::load_pack(&[SignedLayer { bytes: &bytes, signature: &signature }], TRUSTED_KEYS)
            .map_err(|error| error.to_string())?;
    let mut out = String::new();
    for layer in pack.refs() {
        out.push_str(&format!(
            "ok: layer {} version {}, sha256 {}, {}, signed by {key}\n",
            layer.layer,
            layer.version,
            layer.sha256,
            plural(pack.rule_count() as u64, "rule")
        ));
    }
    print(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_lines_are_wrapped_and_long_words_kept_whole() {
        let text = "Block app.posthog.com, eu.i.posthog.com, i.posthog.com and us.i.posthog.com \
                    with an outbound firewall such as LuLu (free) or Little Snitch.";
        let wrapped = wrap(text, INDENT);
        assert!(wrapped.lines().all(|line| line.starts_with(INDENT) && line.len() <= WIDTH));
        assert_eq!(wrapped.split_whitespace().collect::<Vec<_>>().join(" "), text);
        let long = "x".repeat(100);
        assert_eq!(wrap(&long, "  "), format!("  {long}\n"));
    }
}
