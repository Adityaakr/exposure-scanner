//! What each command does.

use std::fs;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use xs_match::Matchers;
use xs_model::record::{Record, SubjectKind};
use xs_model::report::{ScanScope, Scanner};
use xs_model::{EvidenceSet, Headline, Pack, Report};
use xs_render::{ReportMeta, Todo};
use xs_rules::{SignedLayer, TRUSTED_KEYS};

use crate::{args, diff, gate};

/// The rule pack compiled into the binary, with its signature. It is checked
/// against the built-in keys on every start, exactly like a pack from a file,
/// so a build whose embedded rules were altered refuses to run.
const BUILT_IN_PACK: &[u8] = include_bytes!("../../../rules/dist/core.pack.json");
const BUILT_IN_SIGNATURE: &str = include_str!("../../../rules/dist/core.pack.json.minisig");

/// A FILE that stands for standard output.
const STDOUT: &str = "-";

/// Largest saved report `exposure report` reads.
const MAX_REPORT_BYTES: u64 = 1 << 30;

/// Errors are messages for the user's terminal.
type Result<T> = std::result::Result<T, String>;

/// What a command that can stop a release says: whether a `--fail-on`
/// condition was met. A command given none always leaves the gate open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// No condition was met.
    Open,
    /// A condition was met: the exit status is
    /// [`EXIT_MATCHED`](crate::EXIT_MATCHED).
    Closed,
}

/// Checks `claims` against `conditions`, says on standard error what each
/// condition met, and returns the gate. `describe`, of a diff, names each
/// finding that met a condition, for the summary.
fn close_on<'a>(
    conditions: &[gate::Condition],
    claims: impl Iterator<Item = (&'a xs_model::Claim, Option<&'a xs_model::Claim>)> + Clone,
    describe: Option<gate::Describe<'_>>,
) -> Gate {
    if conditions.is_empty() {
        return Gate::Open;
    }
    let (summary, met) = gate::summary(&gate::check(conditions, claims), describe);
    let _ = std::io::stderr().write_all(summary.as_bytes());
    if met { Gate::Closed } else { Gate::Open }
}

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
/// output when no path is given.
///
/// A report is never written through a link (security review S4). In a
/// folder others can write to, such as `/tmp`, anyone can leave a symbolic
/// link or a hard link at the name the report is about to take, so that
/// writing the report truncates whatever file of the user's it leads to.
/// So:
///
/// - A `path` that is a symbolic link to a file, a folder, nothing or what
///   cannot be looked at is refused. A link to a device or a stream, such
///   as `/dev/stdout` or the `/dev/fd/N` of a shell's process
///   substitution, is written to as that device is, below.
/// - A report is written to a new file next to `path`, created for this
///   write alone and readable by its owner only, and then renamed to
///   `path`. A rename replaces the name and never follows it: what was at
///   `path`, link or file, is replaced, not written into. It also means a
///   scan that stops half way leaves the old report, not half of a new one.
/// - A `path` that is not a regular file, such as `/dev/null`, is written
///   to and otherwise left as it is: it is opened without being truncated or
///   created, and only if what was opened is of the kind that was looked at
///   and not a regular file, so a name re-pointed at a file meanwhile is
///   refused. The kind, not the device and inode, is compared: the system
///   may report what was opened under other numbers than the name it was
///   opened by. macOS does for `/dev/fd/N`, which there is a node of its
///   own and not a link, while what is opened through it is the pipe.
fn deliver(report: &str, path: Option<&Path>) -> Result<()> {
    let Some(path) = path.filter(|path| *path != Path::new(STDOUT)) else { return print(report) };
    let fail = |error| format!("cannot write {}: {error}", path.display());
    match fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_symlink() => match fs::metadata(path) {
            Ok(target) if !target.is_file() && !target.is_dir() => {
                write_into(path, report, |opened| same_kind(&target, opened)).map_err(fail)
            }
            _ => Err(format!(
                "cannot write {}: it is a symbolic link that does not lead to a device or \
                 stream, and a report is never written through such a link; use {STDOUT} for \
                 standard output, or choose another file",
                path.display()
            )),
        },
        Ok(found) if !found.is_file() && !found.is_dir() => {
            write_into(path, report, |opened| same_kind(&found, opened)).map_err(fail)
        }
        _ => replace(path, report.as_bytes()).map_err(fail),
    }
}

/// Writes `report` into what `path` leads to, opened without being created
/// or truncated, if what was opened is still what was looked at.
fn write_into(
    path: &Path,
    report: &str,
    looked_at: impl FnOnce(&fs::Metadata) -> bool,
) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    if !looked_at(&file.metadata()?) {
        return Err(std::io::Error::other("it was replaced while being opened"));
    }
    file.write_all(report.as_bytes())
}

/// Whether what was opened is of the kind that was looked at, and is not a
/// regular file.
fn same_kind(looked_at: &fs::Metadata, opened: &fs::Metadata) -> bool {
    looked_at.file_type() == opened.file_type() && !opened.is_file()
}

/// Writes `bytes` to a new file in the folder of `path`, readable by its
/// owner only, and renames it to `path`.
fn replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().ok_or_else(|| std::io::Error::other("it names no file"))?;
    let folder = path.parent().filter(|folder| !folder.as_os_str().is_empty());
    let folder = folder.unwrap_or_else(|| Path::new("."));
    let (temporary, mut file) = new_file_beside(folder, name)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let renamed = written.and_then(|()| fs::rename(&temporary, path));
    if renamed.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    renamed
}

/// A file of a name no other file has, in `folder`, made for this write:
/// `.<name>.<process>.<n>.part`, readable by its owner only.
fn new_file_beside(folder: &Path, name: &std::ffi::OsStr) -> std::io::Result<(PathBuf, fs::File)> {
    let mut attempt: u32 = 0;
    loop {
        let mut temporary = std::ffi::OsString::from(".");
        temporary.push(name);
        temporary.push(format!(".{}.{attempt}.part", std::process::id()));
        let temporary = folder.join(temporary);
        let mut options = fs::OpenOptions::new();
        // `create_new` refuses a name that is taken, a link included.
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => {
                #[cfg(unix)]
                {
                    // `mode` is narrowed by the umask, never widened; this
                    // is the file's mode whatever the umask was.
                    use std::os::unix::fs::PermissionsExt as _;
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }
                return Ok((temporary, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < 100 => {
                attempt = attempt.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
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
    /// The claims, for `--fail-on`.
    findings: Vec<xs_model::Claim>,
    /// The checklist in plain words, when it was asked for.
    todos: Vec<Todo>,
    /// What the scan could not look at at all.
    unchecked: Vec<xs_render::NotChecked>,
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
    Ok(Rendered {
        json,
        html,
        claims: claims.len(),
        headline: Headline::of(&claims),
        todos,
        findings: claims,
        unchecked: xs_render::not_checked(evidence),
    })
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
pub(crate) fn scan(args: &args::Scan) -> Result<Gate> {
    let pack = built_in_pack()?;
    // A condition is checked against the pack before anything is read.
    let conditions = gate::conditions(&args.fail_on, &pack)?;
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
        outcome.scope.words(&xs_render::unread_browsers(&report.unchecked)),
    );
    for line in not_checked_lines(&report.unchecked) {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
    if let Some(beside) = beside_the_headline(&report) {
        let _ = writeln!(std::io::stderr(), "exposure: beside the headline: {beside}");
    }
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
    Ok(close_on(&conditions, report.findings.iter().map(|claim| (claim, None)), None))
}

/// The lines of the terminal summary on standard error about what the scan
/// could not look at at all, so that it is not read as clean (security
/// review, M7). A browser is named; an extension or an app is not, and is
/// counted, since these lines name no extension or app.
fn not_checked_lines(unchecked: &[xs_render::NotChecked]) -> Vec<String> {
    let mut lines: Vec<String> = unchecked
        .iter()
        .filter(|item| item.browser.is_some())
        .map(|item| format!("exposure: not checked: {}", item.sentence()))
        .collect();
    for (extension, noun) in [(true, "extension"), (false, "app")] {
        let count = unchecked
            .iter()
            .filter(|item| item.browser.is_none())
            .filter(|item| (item.kind == SubjectKind::Extension) == extension)
            .count() as u64;
        if count > 0 {
            lines.push(format!(
                "exposure: not checked: {} that could not be read; the report names them",
                plural(count, noun),
            ));
        }
    }
    lines
}

/// What Android apps ship beside the headline, in a few words, or nothing
/// when they ship nothing it leaves out. It names no app and no company.
fn beside_the_headline(report: &Rendered) -> Option<String> {
    let uncounted = xs_model::Uncounted::android(&report.findings);
    (uncounted.sdks() > 0).then(|| {
        format!(
            "{} of {} in the Android apps, in categories the headline does not count",
            plural(uncounted.sdks().into(), "SDK"),
            plural(uncounted.companies().into(), "company"),
        )
    })
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
/// who ran it: where the report is, what needs attention first, as the
/// report's summary has it ([`xs_render::first_todos`]), and what the
/// headline says.
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
    out.push_str(&format!("\nScanned {scanned}.\n"));
    for item in &report.unchecked {
        out.push('\n');
        out.push_str(&wrap(&format!("Not checked: {}", item.sentence()), ""));
    }

    let todos = &report.todos;
    let first = xs_render::first_todos(todos);
    let total = todos.len();
    match first.first() {
        None => {
            out.push('\n');
            out.push_str(&wrap(
                "Nothing calls for action: no finding is a service of another company than the \
                 app's publisher, and no app or extension asks for a permission that can be \
                 turned off.",
                "",
            ));
        }
        Some(top) if top.priority.needs_attention() => out.push_str(&format!(
            "\nWhat needs your attention first ({} of {total} {}):\n",
            first.len(),
            if total == 1 { "thing you can do" } else { "things you can do" },
        )),
        Some(_) => out.push_str(&format!(
            "\nNothing needs your attention first. Things you can do, all of low priority ({} of \
             {total}):\n",
            first.len(),
        )),
    }
    for (at, todo) in first.iter().enumerate() {
        out.push_str(&format!("\n{:>3}. [{}] {}\n", at + 1, todo.priority.name(), todo.title));
        out.push_str(&wrap(&todo.about, INDENT));
        out.push_str(&wrap(&todo.step, INDENT));
    }
    if total > first.len() {
        let more = total - first.len();
        let entries = if more == 1 { "entry" } else { "entries" };
        out.push_str(&format!("\n{more} more {entries} in the report, under What you can do.\n"));
    }

    let headline = report.headline;
    out.push_str("\nThe headline counts:\n");
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
    if let Some(beside) = beside_the_headline(report) {
        out.push_str(&wrap(&format!("and beside these: {beside}"), "  "));
    }
    out.push('\n');
    out.push_str(&wrap(
        "The report has every step and the evidence behind each finding. It lists apps you use, \
         so keep it private.",
        "",
    ));
    out
}

/// Reads a JSON report an earlier scan wrote.
fn read_saved(path: &Path) -> Result<Report> {
    let fail = |error: &dyn std::fmt::Display| format!("cannot read {}: {error}", path.display());
    let size = fs::metadata(path).map_err(|error| fail(&error))?.len();
    if size > MAX_REPORT_BYTES {
        return Err(fail(&"the file is larger than 1 GiB"));
    }
    let bytes = fs::read(path).map_err(|error| fail(&error))?;
    // Parsing re-checks every record and every record id, so evidence that
    // was edited after the scan is refused here.
    serde_json::from_slice(&bytes).map_err(|error| fail(&error))
}

/// `exposure report`: the pure half of the pipeline, run on saved evidence.
pub(crate) fn report(args: &args::Report) -> Result<Gate> {
    let pack = built_in_pack()?;
    let conditions = gate::conditions(&args.fail_on, &pack)?;
    let saved = read_saved(&args.file)?;
    // The evidence was gathered by the scanner the file names; keep that.
    let outputs =
        Outputs { html: args.html.as_deref(), json: args.json.as_deref(), checklist: false };
    let report = render(&saved.evidence, &pack, saved.scanner, saved.scope, outputs)?;
    deliver_all(&report, outputs)?;
    Ok(close_on(&conditions, report.findings.iter().map(|claim| (claim, None)), None))
}

/// `exposure diff`: what the findings of NEW add to and take from those of
/// OLD. The comparison goes to standard output, and to `--json FILE` as a
/// document as well; with `--json -` the document is all that standard
/// output gets.
pub(crate) fn diff(args: &args::Diff) -> Result<Gate> {
    let pack = built_in_pack()?;
    let conditions = gate::conditions(&args.fail_on, &pack)?;
    let old = read_saved(&args.old)?;
    let new = read_saved(&args.new)?;
    let diff = diff::compare(&old, &new);
    let to_stdout = args.json.as_deref() == Some(Path::new(STDOUT));
    if let Some(path) = &args.json {
        let mut document = serde_json::to_string_pretty(&diff)
            .map_err(|error| format!("cannot write the comparison: {error}"))?;
        document.push('\n');
        deliver(&document, Some(path))?;
    }
    if !to_stdout {
        print(&diff::text(&diff, &pack))?;
    }
    if !diff.same_rules {
        let _ = writeln!(
            std::io::stderr(),
            "exposure: the two reports were made with different rule packs, so a difference \
             may come from the rules rather than from the apps"
        );
    }
    let describe =
        |claim: &xs_model::Claim, was: Option<&xs_model::Claim>| diff.describe(&pack, claim, was);
    Ok(close_on(&conditions, diff.pairs(), Some(&describe)))
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

    // The ids `--fail-on` takes.
    out.push_str("\ncategories, for --fail-on category:ID (* counts in the headline)\n\n");
    for category in pack.layers().iter().flat_map(|loaded| &loaded.layer.categories) {
        let counted = if category.headline { " *" } else { "" };
        out.push_str(&format!("{:<28} {}{counted}\n", category.id, category.name));
    }
    for category in xs_model::access::CATEGORIES {
        out.push_str(&format!("{:<28} {} (what an app may access)\n", category.id, category.name));
    }
    let extension = xs_model::permission::CATEGORY;
    out.push_str(&format!("{extension:<28} {}\n", xs_model::permission::CATEGORY_NAME));
    out.push_str("\ncompanies, for --fail-on company:ID\n\n");
    let mut companies: Vec<_> = pack
        .layers()
        .iter()
        .flat_map(|loaded| &loaded.layer.entities)
        .filter(|entity| entity.parent.is_none())
        .collect();
    companies.sort_by(|a, b| a.id.cmp(&b.id));
    for company in companies {
        out.push_str(&format!("{:<28} {}\n", company.id, company.name));
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

    /// Security review M7: a browser whose profile folder the system will
    /// not let the scan list is named at the top of the page, in the summary
    /// printed on standard output and on standard error, with what lets the
    /// scan read it; and where the scan looked no longer names it. A scan
    /// with no such record names nothing.
    #[test]
    fn a_browser_the_scan_could_not_read_is_named_where_the_reader_looks() {
        use std::os::unix::fs::PermissionsExt as _;

        let support = tempfile::tempdir().unwrap();
        let chrome = support.path().join("Google/Chrome");
        fs::create_dir_all(chrome.join("Default/Extensions")).unwrap();
        fs::set_permissions(&chrome, fs::Permissions::from_mode(0o000)).unwrap();
        let found = xs_collect::browser::installed(support.path());
        fs::set_permissions(&chrome, fs::Permissions::from_mode(0o700)).unwrap();
        if found.unlisted.is_empty() {
            // Run with privileges that ignore the folder's mode.
            return;
        }
        let pack = built_in_pack().unwrap();
        let page = std::path::Path::new("/nowhere/report.html");
        let outputs = Outputs { html: Some(page), json: None, checklist: true };
        let rendered = |evidence: &EvidenceSet| {
            render(evidence, &pack, this_scanner(), Some(ScanScope::Installed), outputs).unwrap()
        };

        let mut evidence = EvidenceSet::new();
        for (&(browser, reason), &count) in &found.unlisted {
            evidence.insert(xs_collect::browser::unlisted(browser, reason, count)).unwrap();
        }
        let report = rendered(&evidence);
        let said = "Google Chrome's extensions. macOS did not let the scan read its profile \
                    folder. To include them, allow your terminal app under System Settings > \
                    Privacy & Security > Full Disk Access, scan again, then turn it off.";
        let html = report.html.as_deref().unwrap();
        let escaped = said.replace('&', "&amp;").replace('>', "&gt;").replace('\'', "&#39;");
        assert!(html.contains(&format!("<strong>Not checked:</strong> {escaped}")), "{html}");
        let terminal = summary(&report, "0 apps", page, false);
        let flat = terminal.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains(&format!("Not checked: {said}")), "{terminal}");
        assert_eq!(
            not_checked_lines(&report.unchecked),
            [format!("exposure: not checked: {said}")]
        );
        let scope = ScanScope::Installed.words(&xs_render::unread_browsers(&report.unchecked));
        assert!(scope.contains("not the extensions of Google Chrome, which could not be read"));
        assert!(!scope.contains("profiles of Arc, Brave, Google Chrome"), "{scope}");
        assert!(
            html.contains("not the extensions of Google Chrome, which could not be read"),
            "{html}"
        );

        // A scan that read everything says nothing of the kind.
        let report = rendered(&EvidenceSet::new());
        assert!(!report.html.as_deref().unwrap().contains("Not checked"));
        assert!(!summary(&report, "0 apps", page, false).contains("Not checked"));
        assert!(not_checked_lines(&report.unchecked).is_empty());
    }

    #[test]
    fn extensions_and_apps_not_checked_are_counted_apart() {
        let item = |kind| xs_render::NotChecked {
            kind,
            browser: None,
            what: String::from("x"),
            why: "y",
            step: None,
        };
        let unchecked =
            [item(SubjectKind::Extension), item(SubjectKind::Extension), item(SubjectKind::App)];
        assert_eq!(
            not_checked_lines(&unchecked),
            [
                "exposure: not checked: 2 extensions that could not be read; the report names them",
                "exposure: not checked: 1 app that could not be read; the report names them",
            ]
        );
    }

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
