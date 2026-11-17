//! What each command does.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use xs_match::Matchers;
use xs_model::record::Record;
use xs_model::report::Scanner;
use xs_model::{EvidenceSet, Pack, Report};
use xs_render::ReportMeta;
use xs_rules::{SignedLayer, TRUSTED_KEYS};

use crate::args;

/// The rule pack compiled into the binary, with its signature. It is checked
/// against the built-in keys on every start, exactly like a pack from a file,
/// so a build whose embedded rules were altered refuses to run.
const BUILT_IN_PACK: &[u8] = include_bytes!("../../../rules/dist/core.pack.json");
const BUILT_IN_SIGNATURE: &str = include_str!("../../../rules/dist/core.pack.json.minisig");

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
    let Some(path) = path else { return print(report) };
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

/// Derives claims from `evidence` and renders the JSON report.
fn render(evidence: &EvidenceSet, pack: &Pack, scanner: Scanner) -> Result<(String, usize)> {
    let claims = xs_derive::derive(evidence, pack).map_err(|error| error.to_string())?;
    let meta = ReportMeta { scanner, packs: pack.refs() };
    let text = xs_render::json(&claims, evidence, &meta).map_err(|error| error.to_string())?;
    Ok((text, claims.len()))
}

fn plural(count: u64, noun: &str) -> String {
    if count == 1 { format!("1 {noun}") } else { format!("{count} {noun}s") }
}

/// `exposure scan`
pub(crate) fn scan(args: &args::Scan) -> Result<()> {
    let pack = built_in_pack()?;
    let matchers = Matchers::build(&pack);
    let options = xs_collect::ScanOptions { threads: args.threads };
    let outcome =
        xs_collect::scan(&args.paths, &matchers, options).map_err(|error| error.to_string())?;
    let (report, claims) = render(&outcome.evidence, &pack, this_scanner())?;
    deliver(&report, args.json.as_deref())?;

    let gaps =
        outcome.evidence.iter().filter(|(_, record)| matches!(record, Record::Coverage(_))).count();
    let stats = outcome.stats;
    // A summary for the terminal. It names no app and no path.
    let _ = writeln!(
        std::io::stderr(),
        "exposure: scanned {} ({}, {}): {}, {}",
        plural(stats.artifacts, "app"),
        plural(stats.files, "file"),
        plural(stats.bytes, "byte"),
        plural(claims as u64, "claim"),
        plural(gaps as u64, "coverage note"),
    );
    Ok(())
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
    let (text, _) = render(&saved.evidence, &pack, saved.scanner)?;
    deliver(&text, args.json.as_deref())
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
