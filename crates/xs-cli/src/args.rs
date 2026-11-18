//! The command line.

use std::ffi::OsString;
use std::path::PathBuf;

use lexopt::prelude::*;

/// Shown by `--help` and after a usage error.
pub(crate) const USAGE: &str = "\
usage:
  exposure scan [PATH...] [--html FILE] [--json FILE] [--no-open] [--threads N] [--no-cache]
  exposure report FILE [--html FILE] [--json FILE]
  exposure rules show
  exposure rules verify PACK --sig SIGNATURE
  exposure --help | --version

Start with `exposure scan`. It reads the apps installed on this Mac and the
browser extensions in your profiles, writes the report to a private folder,
prints what to do first and opens the report in your browser.

commands:
  scan     Read the apps at each PATH (a macOS .app bundle, an Android .apk
           file, or a folder that holds either) and report which SDKs they
           ship. A PATH may also be a browser extension (a Firefox .xpi
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
           (or under XDG_DATA_HOME) elsewhere. Its path and the first entries
           of its checklist, \"What you can do\", are printed, and when the
           scan runs in a terminal the report is opened in your browser.
           Each scan replaces the report of the one before.
           An app that has not changed since an earlier scan is not read
           again: what was found in it is kept in a private cache, in
           ~/Library/Caches/exposure on macOS and in ~/.cache/exposure (or
           under XDG_CACHE_HOME) elsewhere. The report is the same with the
           cache and without it, and the folder can be deleted at any time.
           A scan run as root does not use it.
  report   Derive the report again from the evidence saved in FILE, a JSON
           report of an earlier scan.
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
";

/// What the user asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    Help,
    Version,
    Scan(Scan),
    Report(Report),
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

    while let Some(arg) = parser.next().map_err(|error| error.to_string())? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Short('V') | Long("version") => return Ok(Command::Version),
            Long("html") => html = Some(value(&mut parser, "--html")?.into()),
            Long("json") => json = Some(value(&mut parser, "--json")?.into()),
            Long("sig") => signature = Some(value(&mut parser, "--sig")?.into()),
            Long("no-cache") => no_cache = true,
            Long("no-open") => no_open = true,
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
            }))
        }
        Some("report") => {
            reject("--sig", signature.is_some(), "report")?;
            reject("--threads", threads.is_some(), "report")?;
            reject("--no-cache", no_cache, "report")?;
            reject("--no-open", no_open, "report")?;
            match <[PathBuf; 1]>::try_from(rest) {
                Ok([file]) => Ok(Command::Report(Report { file, html, json })),
                Err(_) => Err(String::from("report takes exactly one FILE")),
            }
        }
        Some("rules") => {
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
                open: true
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
                open: true
            }))
        );
        assert_eq!(
            parse_words(&["report", "--json=again.json", "saved.json", "--html=report.html"]),
            Ok(Command::Report(Report {
                file: "saved.json".into(),
                html: Some("report.html".into()),
                json: Some("again.json".into())
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
                open: true
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
                open: true
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
                open: true
            }))
        );
    }

    #[test]
    fn the_other_commands_parse() {
        assert_eq!(
            parse_words(&["report", "saved.json"]),
            Ok(Command::Report(Report { file: "saved.json".into(), html: None, json: None }))
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
            &["diff", "a", "b"],
        ] {
            assert!(parse_words(words).is_err(), "{words:?} should be refused");
        }
    }
}
