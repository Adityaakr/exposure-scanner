//! The command line.

use std::ffi::OsString;
use std::path::PathBuf;

use lexopt::prelude::*;

/// Shown by `--help` and after a usage error.
pub(crate) const USAGE: &str = "\
usage:
  exposure scan [PATH...] [--json FILE] [--threads N]
                [--no-cache | --cache-dir DIR]
  exposure report FILE [--json FILE]
  exposure rules show
  exposure rules verify PACK --sig SIGNATURE
  exposure --help | --version

commands:
  scan     Read the apps at each PATH (a macOS .app bundle, an Android .apk
           file, or a folder that holds either) and report which SDKs they
           ship. Without a PATH, on macOS: the apps installed in /Applications
           and in your own Applications folder, but not Apple's own apps in
           /System/Applications. A PATH replaces those folders: when any
           PATH is given, only what the PATHs name is scanned. An app that
           cannot be read is reported as such and does not stop the scan.
           No app is changed, nothing is executed and nothing is sent
           anywhere.
           An app that has not changed since an earlier scan is not read
           again: what was found in it is kept in a private cache, in
           ~/Library/Caches/exposure on macOS and in ~/.cache/exposure (or
           under XDG_CACHE_HOME) elsewhere. The report is the same with the
           cache and without it, and the folder can be deleted at any time.
  report   Derive the report again from the evidence saved in FILE.
  rules    Show the built-in rule pack, or verify a signed pack file.

options:
  --json FILE   Write the JSON report to FILE (owner-readable only) instead
                of standard output.
  --threads N   Worker threads for scan. Default: one per core. The report
                does not depend on it.
  --no-cache    Read every app again, and neither use nor keep the cache.
  --cache-dir DIR
                Keep the cache in DIR, which is created if it is not there,
                instead of the folder named above.
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
    pub(crate) json: Option<PathBuf>,
    pub(crate) threads: usize,
    pub(crate) cache: Cache,
}

/// Where a scan keeps the results it can use again.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum Cache {
    /// In the user's cache folder.
    #[default]
    Default,
    /// In this folder (`--cache-dir`).
    Dir(PathBuf),
    /// Nowhere (`--no-cache`): every app is read and nothing is kept.
    Off,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) file: PathBuf,
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
    let mut json: Option<PathBuf> = None;
    let mut threads: Option<usize> = None;
    let mut signature: Option<PathBuf> = None;
    let mut no_cache = false;
    let mut cache_dir: Option<PathBuf> = None;

    while let Some(arg) = parser.next().map_err(|error| error.to_string())? {
        match arg {
            Short('h') | Long("help") => return Ok(Command::Help),
            Short('V') | Long("version") => return Ok(Command::Version),
            Long("json") => json = Some(value(&mut parser, "--json")?.into()),
            Long("sig") => signature = Some(value(&mut parser, "--sig")?.into()),
            Long("no-cache") => no_cache = true,
            Long("cache-dir") => cache_dir = Some(value(&mut parser, "--cache-dir")?.into()),
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

    let mut words = words.into_iter();
    let command = words.next().ok_or("no command given")?;
    let rest: Vec<PathBuf> = words.map(PathBuf::from).collect();
    let reject = |option: &str, present: bool, command: &str| {
        if present { Err(format!("{option} does not apply to `{command}`")) } else { Ok(()) }
    };

    match command.to_str() {
        Some("scan") => {
            reject("--sig", signature.is_some(), "scan")?;
            let cache = match (no_cache, cache_dir) {
                (true, Some(_)) => {
                    return Err(String::from("--no-cache and --cache-dir do not go together"));
                }
                (true, None) => Cache::Off,
                (false, Some(dir)) => Cache::Dir(dir),
                (false, None) => Cache::Default,
            };
            Ok(Command::Scan(Scan { paths: rest, json, threads: threads.unwrap_or(0), cache }))
        }
        Some("report") => {
            reject("--sig", signature.is_some(), "report")?;
            reject("--threads", threads.is_some(), "report")?;
            reject("--no-cache", no_cache, "report")?;
            reject("--cache-dir", cache_dir.is_some(), "report")?;
            match <[PathBuf; 1]>::try_from(rest) {
                Ok([file]) => Ok(Command::Report(Report { file, json })),
                Err(_) => Err(String::from("report takes exactly one FILE")),
            }
        }
        Some("rules") => {
            reject("--json", json.is_some(), "rules")?;
            reject("--threads", threads.is_some(), "rules")?;
            reject("--no-cache", no_cache, "rules")?;
            reject("--cache-dir", cache_dir.is_some(), "rules")?;
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
            json: Some("out.json".into()),
            threads: 4,
            cache: Cache::Default,
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
                json: None,
                threads: 0,
                cache: Cache::Default
            }))
        );
    }

    /// The cache is on unless it is turned off, and sits in the user's
    /// cache folder unless another is named.
    #[test]
    fn scan_takes_the_cache_options() {
        let cache = |words: &[&str]| match parse_words(words) {
            Ok(Command::Scan(scan)) => scan.cache,
            other => panic!("{words:?} gave {other:?}"),
        };
        assert_eq!(cache(&["scan", "x.app"]), Cache::Default);
        assert_eq!(cache(&["scan", "--no-cache", "x.app"]), Cache::Off);
        assert_eq!(cache(&["scan", "x.app", "--cache-dir", "kept"]), Cache::Dir("kept".into()));
        assert_eq!(cache(&["--cache-dir=kept", "scan"]), Cache::Dir("kept".into()));
    }

    #[test]
    fn scan_without_a_path_is_a_scan_of_the_installed_apps() {
        assert_eq!(
            parse_words(&["scan"]),
            Ok(Command::Scan(Scan {
                paths: vec![],
                json: None,
                threads: 0,
                cache: Cache::Default
            }))
        );
        assert_eq!(
            parse_words(&["scan", "--threads", "2", "--json", "out.json"]),
            Ok(Command::Scan(Scan {
                paths: vec![],
                json: Some("out.json".into()),
                threads: 2,
                cache: Cache::Default
            }))
        );
    }

    #[test]
    fn a_path_that_looks_like_an_option_can_follow_a_double_dash() {
        assert_eq!(
            parse_words(&["scan", "--", "--odd.app"]),
            Ok(Command::Scan(Scan {
                paths: vec!["--odd.app".into()],
                json: None,
                threads: 0,
                cache: Cache::Default
            }))
        );
    }

    #[test]
    fn the_other_commands_parse() {
        assert_eq!(
            parse_words(&["report", "saved.json"]),
            Ok(Command::Report(Report { file: "saved.json".into(), json: None }))
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
            &["scan", "x.app", "--no-cache", "--cache-dir", "kept"],
            &["scan", "x.app", "--cache-dir"],
            &["scan", "x.app", "--cache"],
            &["report", "a.json", "--no-cache"],
            &["report", "a.json", "--cache-dir", "kept"],
            &["rules", "show", "--no-cache"],
            &["scan", "x.app", "--sig", "s"],
            &["report"],
            &["report", "a.json", "b.json"],
            &["report", "a.json", "--threads", "2"],
            &["rules"],
            &["rules", "install", "p.json"],
            &["rules", "verify", "p.json"],
            &["rules", "show", "extra"],
            &["rules", "show", "--json", "x"],
            &["update"],
            &["diff", "a", "b"],
        ] {
            assert!(parse_words(words).is_err(), "{words:?} should be refused");
        }
    }
}
