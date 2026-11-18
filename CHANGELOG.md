# Changelog

All notable changes to `exposure` are listed here. The project follows
[Semantic Versioning](https://semver.org); while the version is 0.x, a minor
version can change commands, the report format or the evidence format.

## 0.1.0 (2026-11-18)

The first release: milestone 1, "static truth". Source only; there are no
prebuilt binaries. Install with
`cargo install --git https://github.com/Adityaakr/exposure-scanner --locked --tag v0.1.0 exposure`.

### What it does

- **`exposure scan`, with nothing else, scans this Mac**: the apps in
  `/Applications` and `~/Applications` and the extensions in the profiles of
  Chromium-family browsers and Firefox. It writes the report to a private
  folder, prints the headline and the first entries of what to do, and opens
  the report in the browser (`--no-open` skips that). `--html FILE` and
  `--json FILE` (`-` for standard output) name the files instead.
- **Collectors for three kinds of app**, all read without running anything:
  macOS bundles (frameworks, Mach-O load commands, Objective-C class names and
  strings, code-signature Team ID and entitlements, privacy manifests, update
  feeds), Electron apps (asar archives and loose scripts, with the scope of
  every hit: the app's own code, a dependency, the browser engine) and Android
  packages (DEX classes and strings, the binary manifest, zip entries, within
  an inflate budget). Browser extensions are read from their manifests only.
- **What each app may access**: usage descriptions, entitlements and Android
  permissions, on a ladder of their own (`requested` now), never joined to
  the channels to companies.
- **A signed rule pack of 48 rules** for analytics, advertising, attribution,
  session-replay, profiling, crash-reporting, telemetry, customer-messaging,
  push, payments and component SDKs, each token
  citing the SDK's code or documentation, with an own company map. The
  scanner refuses a pack whose signature does not verify against the key
  built into it.
- **The report**: one HTML page that loads nothing and runs no script,
  grouped by company, with a grade, a confidence and the raw evidence record
  behind every finding; the three headline counts, and no score; what the
  scan covered and set aside; the limits of any scan of a device; and a
  prioritised "What you can do" checklist, with the app's own setting where
  its publisher documents one, hosts to block, the System Settings pane of
  each permission, and how to narrow or remove an extension. The JSON report
  carries the claims and the complete evidence set, and `exposure report`
  renders it again.
- **A results cache**, private and deletable, off with `--no-cache`: a scan
  reads only the apps that changed, and the report is the same bytes with it
  and without it.

### What is checked

- The properties of the specification, in CI: canary recall (every token
  of every rule planted and found: 231 of 231), a negative-control corpus
  of 30 real apps pinned by hash with no channel to another company (a
  subset on every change, all nightly), byte-identical reports across input
  order, threads and cache state, no socket opened (dependency bans, symbol
  audit, network namespace, `strace`, macOS sandbox), and honesty (a report
  that cites a missing record is refused).
- Speed: the absolute speed gates (cold scan under 60 s, warm scan under
  5 s, scaling at 8 threads) are verified on the reference laptop with
  `cargo xtask bench --strict`, not in CI. CI runs the benchmark on the
  fixtures for its memory (under 200 MB) and determinism gates.
- Fuzzing of every parser of hostile files, 60 s per target in CI.
- Reproducible builds: two clean builds of one commit give the same binary
  (`cargo xtask repro`, nightly on macOS and Linux).

### Documents

- [Threat model](docs/threat-model.md), [dispute process](docs/disputes.md)
  with an issue form for publishers and users, and the data licence notices
  in [`NOTICE`](NOTICE): code under Apache-2.0, the project's own rules and
  company map under CC BY 4.0, and a reserved place for converted Exodus
  Privacy signatures under ODbL 1.0.

### Known limits

- macOS on Apple silicon is the only platform where installed apps are found
  automatically. Android packages, and browser extensions, are scanned by
  path on any OS.
- A scan of files sees what an app ships and declares, not what it sends:
  only grades `declares` and `contains` are reported.
- The Exodus Privacy layer and the differential test against Exodus reports
  are not in this release; they are follow-ups.
- CI does not enforce the absolute speed gates; they are checked on the
  reference laptop before a release.
- The cache does not yet remove the entries of apps that were deleted; the
  folder can be deleted at any time.
