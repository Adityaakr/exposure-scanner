//! Helpers shared by the integration tests of the binary.

/// The JSON report on standard output, unless the arguments name a file
/// for a report: a scan given neither writes its report for reading to the
/// user's own folder instead.
pub(crate) fn report_options(rest: &[&str]) -> &'static [&'static str] {
    let named = rest.iter().take_while(|arg| **arg != "--").any(|arg| {
        ["--json", "--html"].iter().any(|option| {
            arg.strip_prefix(option).is_some_and(|tail| tail.is_empty() || tail.starts_with('='))
        })
    });
    if named { &[] } else { &["--json", "-"] }
}
