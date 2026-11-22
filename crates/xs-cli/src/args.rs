//! The command line.

use std::ffi::OsString;
use std::path::PathBuf;

use lexopt::prelude::*;

/// Shown by `--help` and after a usage error.
pub(crate) const USAGE: &str = "\
usage:
  exposure scan [PATH...] [--html FILE] [--json FILE] [--no-open] [--threads N] [--no-cache]
                [--fail-on CONDITION]...
  exposure report FILE [--html FILE] [--json FILE] [--fail-on CONDITION]...
  exposure diff OLD NEW [--json FILE] [--fail-on CONDITION]...
  exposure rules show
  exposure rules verify PACK --sig SIGNATURE
  exposure --help | --version

Start with `exposure scan`. It reads the apps installed on this Mac and the
browser extensions in your profiles, writes the report to a private folder,
prints what needs your attention first and opens the report in your
browser.

commands:
  scan     Read the apps at each PATH (a macOS .app bundle, an Android .apk
           or .aab file, or a folder that holds any of them) and report
           which SDKs they ship. A PATH may also be a browser extension (a Firefox .xpi
           file, or a Chromium <id>/<version> folder) or a folder of them:
           the report says what each asks the browser for. Without a PATH,
           on macOS: the apps installed in /Applications and in your own
           Applications folder, but not Apple's own apps in
           /System/Applications, and the extensions installed in your
           profiles of the Chromium-family browsers and Firefox. Of an
           extension only its manifest is read, never your history, cookies
           or pages. A PATH replaces those folders: when any PATH is given,
           only what the PATHs name is scanned. An app, an extension or a
           browser that cannot be read is reported as such and does not stop
           the scan. Nothing scanned is changed or executed, and nothing is
           sent anywhere.
           With neither --html nor --json, the report for reading is written
           to report.html in a folder only you can read: ~/Library/
           Application Support/exposure on macOS, and ~/.local/share/exposure
           (or under XDG_DATA_HOME) elsewhere. Its path and what needs your
           attention first, the entries of its checklist \"What you can do\"
           of high and medium priority, are printed, and when the scan runs
           in a terminal the report is opened in your browser.
           Each scan replaces the report of the one before.
           An app that has not changed since an earlier scan is not read
           again: what was found in it is kept in a private cache, in
           ~/Library/Caches/exposure on macOS and in ~/.cache/exposure (or
           under XDG_CACHE_HOME) elsewhere. The report is the same with the
           cache and without it, and the folder can be deleted at any time.
           A scan run as root does not use it.
  report   Derive the report again from the evidence saved in FILE, a JSON
           report of an earlier scan.
  diff     Compare two JSON reports, OLD and NEW, such as the scans of two
           builds of one app: which findings NEW adds, which it no longer
           has, and which changed grade, app by app. An app is followed
           across builds by its platform and app id. The comparison is
           printed; --json FILE writes it for programs as well.
  rules    Show the built-in rule pack, or verify a signed pack file.

options:
  --html FILE   Write the report for reading to FILE: one HTML file that
                runs no script and loads nothing, grouped by company, with
                the evidence behind every finding and a checklist of what
                you can do about it, which the scanner does not do for you.
  --json FILE   Write the JSON report to FILE: the findings and every
                evidence record, for programs and for `exposure report`.
                A FILE of - is standard output. For `report`, with neither
                option the JSON report goes to standard output.
                A report lists the apps a person uses, so a report file is
                created readable by its owner only.
  --no-open     Do not open the report in the browser.
  --threads N   Worker threads for scan. Default: one per core. The report
                does not depend on it.
  --no-cache    Read every app again, and neither use nor keep the cache.
  --fail-on CONDITION
                Exit with status 3 when a finding meets CONDITION, after the
                reports are written. For `diff`, only the findings that
                newly meet it are checked: those NEW adds, and those that
                meet it in NEW but did not in OLD, and each one is named.
                CONDITION is one of:
                  headline      a finding that counts in the headline
                  category:ID   a finding in the category ID, such as
                                category:analytics or category:camera
                  company:ID    a finding that names the company ID, such
                                as company:google
                `exposure rules show` lists the categories and companies.
                The option can be given more than once; any match fails.

exit status:
  0  done, and no --fail-on CONDITION was met
  1  an error, such as a file that cannot be read or written
  2  a command line that is not understood
  3  done, and a --fail-on CONDITION was met
";

/// What the user asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Help,
    Version,
    Scan(Scan),
    Report(Report),
    Diff(Diff),
    RulesShow,
    RulesVerify(RulesVerify),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Scan {
    /// What to scan. Empty means the apps installed on this machine.
    pub(crate) paths: Vec<PathBuf>,
    pub(crate) html: Option<PathBuf>,
    pub(crate) json: Option<PathBuf>,
    pub(crate) threads: usize,
    pub(crate) cache: Cache,
    /// Whether the report may be opened in the browser. It is only when
    /// it goes to the default place and the scan runs in a terminal.
    pub(crate) open: bool,
    /// When the scan exits with [`EXIT_MATCHED`](crate::EXIT_MATCHED).
    pub(crate) fail_on: Vec<FailOn>,
}

/// A condition of `--fail-on`: findings that, when a report has one, make
/// the command exit with a status of its own, so that a script or a CI job
/// can stop a release on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FailOn {
    /// A finding that counts in the headline.
    Headline,
    /// A finding in this category, by id.
    Category(String),
    /// A finding that names this company, by id.
    Company(String),
}

impl FailOn {
    /// Reads `headline`, `category:ID` or `company:ID`.
    fn parse(text: &str) -> Result<Self, String> {
        let refused =
            || format!("--fail-on takes `headline`, `category:ID` or `company:ID`, not `{text}`");
        if text == "headline" {
            return Ok(Self::Headline);
        }
        let (kind, id) = text.split_once(':').ok_or_else(refused)?;
        if id.is_empty() || id.contains(char::is_whitespace) {
            return Err(refused());
        }
        match kind {
            "category" => Ok(Self::Category(id.to_owned())),
            "company" => Ok(Self::Company(id.to_owned())),
            _ => Err(refused()),
        }
    }
}

impl std::fmt::Display for FailOn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Headline => f.write_str("headline"),
            Self::Category(id) => write!(f, "category:{id}"),
            Self::Company(id) => write!(f, "company:{id}"),
        }
    }
}

/// Where a scan keeps the results it can use again.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum Cache {
    /// In the user's cache folder.
    #[default]
    Default,
    /// Nowhere (`--no-cache`): every app is read and nothing is kept.
    Off,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) file: PathBuf,
    pub(crate) html: Option<PathBuf>,
    pub(crate) json: Option<PathBuf>,
    pub(crate) fail_on: Vec<FailOn>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Diff {
    pub(crate) old: PathBuf,
    pub(crate) new: PathBuf,
    pub(crate) json: Option<PathBuf>,
    pub(crate) fail_on: Vec<FailOn>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RulesVerify {
    pub(crate) pack: PathBuf,
    pub(crate) signature: PathBuf,
}

/// Parses a command line. The error is a message for the user.
pub(crate) fn parse(mut parser: lexopt::Parser) -> Result<Command, String> {
    let mut words: Vec<OsString> = Vec::new();
    let mut html: Option<PathBuf> = None;
    let mut json: Option<PathBuf> = None;
    let mut threads: Option<usize> = None;
    let mut signature: Option<PathBuf> = None;
    let mut no_cache = false;
    let mut no_open = false;
    let mut fail_on: Vec<FailOn> = Vec::new();

    while let Some(arg) = parser.next().map_err(|error| error.to_string())? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Short('V') | Long("version") => return Ok(Command::Version),
            Long("html") => html = Some(value(&mut parser, "--html")?.into()),
            Long("json") => json = Some(value(&mut parser, "--json")?.into()),
            Long("sig") => signature = Some(value(&mut parser, "--sig")?.into()),
            Long("no-cache") => no_cache = true,
            Long("no-open") => no_open = true,
            Long("fail-on") => {
                let text = value(&mut parser, "--fail-on")?;
                let text = text.to_str().ok_or("--fail-on takes text")?;
                let condition = FailOn::parse(text)?;
                if !fail_on.contains(&condition) {
                    fail_on.push(condition);
                }
            }
            Long("threads") => {
                let text = value(&mut parser, "--threads")?;
                let count = text.to_str().and_then(|text| text.parse::<usize>().ok());
                match count {
                    Some(count) if (1..=1024).contains(&count) => threads = Some(count),
                    _ => return Err(String::from("--threads takes a whole number from 1 to 1024")),
                }
            }
            Value(word) => words.push(word),
            other => return Err(other.unexpected().to_string()),
        }
    }

    if html.as_deref() == Some(std::path::Path::new("-"))
        && json.as_deref() == Some(std::path::Path::new("-"))
    {
        return Err(String::from("--html and --json cannot both go to standard output"));
    }

    let mut words = words.into_iter();
    let command = words.next().ok_or("no command given")?;
    let rest: Vec<PathBuf> = words.map(PathBuf::from).collect();
    let reject = |option: &str, present: bool, command: &str| {
        if present { Err(format!("{option} does not apply to `{command}`")) } else { Ok(()) }
    };

    match command.to_str() {
        Some("scan") => {
            reject("--sig", signature.is_some(), "scan")?;
            let cache = if no_cache { Cache::Off } else { Cache::Default };
            Ok(Command::Scan(Scan {
                paths: rest,
                html,
                json,
                threads: threads.unwrap_or(0),
                cache,
                open: !no_open,
                fail_on,
            }))
        }
        Some("report") => {
            reject("--sig", signature.is_some(), "report")?;
            reject("--threads", threads.is_some(), "report")?;
            reject("--no-cache", no_cache, "report")?;
            reject("--no-open", no_open, "report")?;
            match <[PathBuf; 1]>::try_from(rest) {
                Ok([file]) => Ok(Command::Report(Report { file, html, json, fail_on })),
                Err(_) => Err(String::from("report takes exactly one FILE")),
            }
        }
        Some("diff") => {
            reject("--sig", signature.is_some(), "diff")?;
            reject("--html", html.is_some(), "diff")?;
            reject("--threads", threads.is_some(), "diff")?;
            reject("--no-cache", no_cache, "diff")?;
            reject("--no-open", no_open, "diff")?;
            match <[PathBuf; 2]>::try_from(rest) {
                Ok([old, new]) => Ok(Command::Diff(Diff { old, new, json, fail_on })),
                Err(_) => Err(String::from("diff takes exactly two FILEs, OLD and NEW")),
            }
        }
        Some("rules") => {
            reject("--fail-on", !fail_on.is_empty(), "rules")?;
            reject("--html", html.is_some(), "rules")?;
            reject("--json", json.is_some(), "rules")?;
            reject("--threads", threads.is_some(), "rules")?;
            reject("--no-cache", no_cache, "rules")?;
            reject("--no-open", no_open, "rules")?;
            let mut rest = rest.into_iter();
            let action = rest.next();
            let pack = rest.next();
            if rest.next().is_some() {
                return Err(String::from("too many arguments for `rules`"));
            }
            match (action.as_deref().and_then(|action| action.to_str()), pack, signature) {
                (Some("show"), None, None) => Ok(Command::RulesShow),
                (Some("verify"), Some(pack), Some(signature)) => {
                    Ok(Command::RulesVerify(RulesVerify { pack, signature }))
                }
                (Some("verify"), _, _) => {
                    Err(String::from("rules verify takes PACK and --sig SIGNATURE"))
                }
                _ => Err(String::from("rules takes `show` or `verify`")),
            }
        }
        _ => Err(format!("unknown command `{}`", command.to_string_lossy())),
    }
}

fn value(parser: &mut lexopt::Parser, option: &str) -> Result<OsString, String> {
    parser.value().map_err(|_| format!("{option} needs a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_words(words: &[&str]) -> Result<Command, String> {
        parse(lexopt::Parser::from_args(words.iter().copied()))
    }

    #[test]
    fn scan_takes_paths_and_options_in_any_order() {
        let expected = Command::Scan(Scan {
            paths: vec!["/Applications".into(), "My App.app".into()],
            html: None,
            json: Some("out.json".into()),
            threads: 4,
            cache: Cache::Default,
            open: true,
            fail_on: vec![],
        });
        assert_eq!(
            parse_words(&[
                "scan",
                "/Applications",
                "My App.app",
                "--json",
                "out.json",
                "--threads",
                "4"
            ]),
            Ok(expected)
        );
        assert_eq!(
            parse_words(&["--threads=4", "scan", "--json=out.json", "/Applications", "My App.app"]),
            parse_words(&[
                "scan",
                "/Applications",
                "My App.app",
                "--json",
                "out.json",
                "--threads",
                "4"
            ])
        );
        assert_eq!(
            parse_words(&["scan", "x.app"]),
            Ok(Command::Scan(Scan {
                paths: vec!["x.app".into()],
                html: None,
                json: None,
                threads: 0,
                cache: Cache::Default,
                open: true,
                fail_on: vec![]
            }))
        );
    }

    #[test]
    fn a_report_for_reading_can_be_asked_for_with_or_without_the_json_one() {
        assert_eq!(
            parse_words(&["scan", "x.app", "--html", "report.html"]),
            Ok(Command::Scan(Scan {
                paths: vec!["x.app".into()],
                html: Some("report.html".into()),
                json: None,
                threads: 0,
                cache: Cache::Default,
                open: true,
                fail_on: vec![]
            }))
        );
        assert_eq!(
            parse_words(&["report", "--json=again.json", "saved.json", "--html=report.html"]),
            Ok(Command::Report(Report {
                file: "saved.json".into(),
                html: Some("report.html".into()),
                json: Some("again.json".into()),
                fail_on: vec![]
            }))
        );
    }

    /// The cache is on unless it is turned off, and always sits in the
    /// user's cache folder: no option puts it anywhere else.
    #[test]
    fn scan_takes_the_cache_options() {
        let cache = |words: &[&str]| match parse_words(words) {
            Ok(Command::Scan(scan)) => scan.cache,
            other => panic!("{words:?} gave {other:?}"),
        };
        assert_eq!(cache(&["scan", "x.app"]), Cache::Default);
        assert_eq!(cache(&["scan", "--no-cache", "x.app"]), Cache::Off);
        assert_eq!(cache(&["--no-cache", "scan"]), Cache::Off);
        let open = |words: &[&str]| match parse_words(words) {
            Ok(Command::Scan(scan)) => scan.open,
            other => panic!("{words:?} gave {other:?}"),
        };
        assert!(open(&["scan"]));
        assert!(!open(&["scan", "--no-open"]));
        for words in [&["scan", "x.app", "--cache-dir", "kept"][..], &["--cache-dir=kept", "scan"]]
        {
            assert!(parse_words(words).is_err(), "{words:?} should be refused");
        }
    }

    #[test]
    fn scan_without_a_path_is_a_scan_of_the_installed_apps() {
        assert_eq!(
            parse_words(&["scan"]),
            Ok(Command::Scan(Scan {
                paths: vec![],
                html: None,
                json: None,
                threads: 0,
                cache: Cache::Default,
                open: true,
                fail_on: vec![]
            }))
        );
        assert_eq!(
            parse_words(&["scan", "--threads", "2", "--json", "out.json"]),
            Ok(Command::Scan(Scan {
                paths: vec![],
                html: None,
                json: Some("out.json".into()),
                threads: 2,
                cache: Cache::Default,
                open: true,
                fail_on: vec![]
            }))
        );
    }

    #[test]
    fn a_path_that_looks_like_an_option_can_follow_a_double_dash() {
        assert_eq!(
            parse_words(&["scan", "--", "--odd.app"]),
            Ok(Command::Scan(Scan {
                paths: vec!["--odd.app".into()],
                html: None,
                json: None,
                threads: 0,
                cache: Cache::Default,
                open: true,
                fail_on: vec![]
            }))
        );
    }

    #[test]
    fn the_other_commands_parse() {
        assert_eq!(
            parse_words(&["report", "saved.json"]),
            Ok(Command::Report(Report {
                file: "saved.json".into(),
                html: None,
                json: None,
                fail_on: vec![]
            }))
        );
        assert_eq!(parse_words(&["rules", "show"]), Ok(Command::RulesShow));
        assert_eq!(
            parse_words(&["rules", "verify", "p.json", "--sig", "p.json.minisig"]),
            Ok(Command::RulesVerify(RulesVerify {
                pack: "p.json".into(),
                signature: "p.json.minisig".into()
            }))
        );
        assert_eq!(parse_words(&["--help"]), Ok(Command::Help));
        assert_eq!(parse_words(&["scan", "-h"]), Ok(Command::Help));
        assert_eq!(parse_words(&["-V"]), Ok(Command::Version));
    }

    #[test]
    fn fail_on_takes_conditions_once_each_and_diff_takes_two_reports() {
        let fail_on = |words: &[&str]| match parse_words(words) {
            Ok(Command::Scan(scan)) => scan.fail_on,
            Ok(Command::Report(report)) => report.fail_on,
            Ok(Command::Diff(diff)) => diff.fail_on,
            other => panic!("{words:?} gave {other:?}"),
        };
        assert_eq!(fail_on(&["scan"]), vec![]);
        assert_eq!(
            fail_on(&[
                "scan",
                "--fail-on",
                "headline",
                "--fail-on=company:google",
                "--fail-on",
                "category:analytics",
                "--fail-on",
                "headline",
            ]),
            vec![
                FailOn::Headline,
                FailOn::Company("google".into()),
                FailOn::Category("analytics".into())
            ]
        );
        assert_eq!(
            fail_on(&["report", "saved.json", "--fail-on", "company:x:y"]),
            vec![FailOn::Company("x:y".into())]
        );
        assert_eq!(
            parse_words(&["diff", "old.json", "new.json", "--json", "-", "--fail-on", "headline"]),
            Ok(Command::Diff(Diff {
                old: "old.json".into(),
                new: "new.json".into(),
                json: Some("-".into()),
                fail_on: vec![FailOn::Headline],
            }))
        );
        for condition in ["headline", "category:analytics", "company:google"] {
            assert_eq!(FailOn::parse(condition).unwrap().to_string(), condition);
        }
    }

    #[test]
    fn mistakes_are_usage_errors() {
        for words in [
            &[][..],
            &["scan", "x.app", "--threads", "0"],
            &["scan", "x.app", "--threads", "many"],
            &["scan", "x.app", "--threads"],
            &["scan", "x.app", "--cache"],
            &["report", "a.json", "--no-cache"],
            &["rules", "show", "--no-cache"],
            &["report", "a.json", "--no-open"],
            &["rules", "show", "--no-open"],
            &["scan", "--html", "-", "--json", "-"],
            &["scan", "x.app", "--sig", "s"],
            &["scan", "x.app", "--html"],
            &["report"],
            &["report", "a.json", "b.json"],
            &["report", "a.json", "--threads", "2"],
            &["rules"],
            &["rules", "install", "p.json"],
            &["rules", "verify", "p.json"],
            &["rules", "show", "extra"],
            &["rules", "show", "--json", "x"],
            &["rules", "show", "--html", "x"],
            &["update"],
            &["diff", "a"],
            &["diff", "a", "b", "c"],
            &["diff", "a", "b", "--html", "x.html"],
            &["diff", "a", "b", "--no-open"],
            &["scan", "--fail-on"],
            &["scan", "--fail-on", "everything"],
            &["scan", "--fail-on", "company:"],
            &["scan", "--fail-on", "vendor:google"],
            &["scan", "--fail-on", "category:a b"],
            &["rules", "show", "--fail-on", "headline"],
        ] {
            assert!(parse_words(words).is_err(), "{words:?} should be refused");
        }
    }
}
