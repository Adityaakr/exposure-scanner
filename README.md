# exposure-scanner

**A local scanner that shows which companies have a channel to your data,
through which apps, with the evidence for every finding.**

[![ci](https://github.com/Adityaakr/exposure-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Adityaakr/exposure-scanner/actions/workflows/ci.yml)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

> [!IMPORTANT]
> **This project is under active development.** Milestone 1 is complete and
> released as v0.1.0, from source only (see the [changelog](CHANGELOG.md)):
> Homebrew builds it for you with one command.
> Commands, the report format and its output may still change between
> versions. Suggestions, bug reports and contributions are welcome: open an
> [issue](https://github.com/Adityaakr/exposure-scanner/issues) or read
> [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## Contents

- [What it is](#what-it-is)
- [What it finds](#what-it-finds)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Release gates and comparing builds](#release-gates-and-comparing-builds)
- [Reading the report](#reading-the-report)
- [Privacy guarantees](#privacy-guarantees)
- [What a device-side scan cannot see](#what-a-device-side-scan-cannot-see)
- [Platforms and roadmap](#platforms-and-roadmap)
- [Architecture](#architecture)
- [Rule packs](#rule-packs)
- [Testing and the six properties](#testing-and-the-six-properties)
- [Releases and verifying a build](#releases-and-verifying-a-build)
- [Licences and data sources](#licences-and-data-sources)
- [Contributing](#contributing)
- [Acknowledgements](#acknowledgements)

## What it is

Apps ship code from analytics, advertising, attribution and session-replay
companies. Each of those SDKs is a channel from the app to a company you may
never have heard of, and nothing on your computer lists them.

`exposure` is a command-line tool that reads the apps already on your disk,
recognises third-party SDKs by literal markers they cannot avoid leaving,
maps each one to the company that owns it, and writes a report in which every
statement links to a record you can check by hand.

- **Evidence, not guesses.** Each finding carries a grade that says how
  strong its evidence is, and cites the raw records it rests on: the marker,
  the file, the table, how often.
- **Local and inert.** A scan reads files. It executes nothing it scans,
  changes no app, and contains no network code at all. All it writes is the
  report and a private cache, so that the next scan reads only the apps that
  changed.
- **Reproducible.** The same apps and the same rule pack give the same
  report, byte for byte, on any machine and with any number of threads.

## What it finds

| Finding | Example | Where it comes from |
|---|---|---|
| **SDKs and the companies behind them**, per app | PostHog (analytics), in Logseq, owned by PostHog | Framework folders, linked libraries, Objective-C class names and binary literals on macOS; npm packages and bundled script literals in Electron apps; manifest entries, DEX classes and strings in Android packages |
| **Hosts an app declares** | An update feed on `ranchero.com`, first party to NetNewsWire | `SUFeedURL` in `Info.plist`; tracking domains in privacy manifests |
| **What each app may access** | Camera, microphone, location, contacts, files, other apps | Usage descriptions and entitlements on macOS; `uses-permission` on Android |
| **Browser extensions with powerful permissions** | May read and change data on every website you visit; may read your browsing history | `manifest.json` of every extension in your Chrome, Edge, Brave, Arc, Dia, Vivaldi, Chromium and Firefox profiles |

The built-in rule pack recognises 48 SDKs across analytics, advertising,
attribution, profiling, session replay, crash reporting and customer
messaging ([full list](docs/scanning.md#the-built-in-rule-pack)).

A scan of two of the repository's test fixtures, a synthetic Electron app and
a synthetic Android package:

```console
$ exposure scan tests/fixtures/macos/ElectronSkeleton.app tests/fixtures/android/Skeleton.apk --json report.json
exposure: scanned 2 apps (6 files, 6777 bytes): 4 claims, 0 coverage notes
exposure: headline: 0 companies at contacts or above, 1 company at contains, 2 apps with a third-party channel
exposure: scope: the paths given and nothing else; the installed-app folders were not searched
exposure: cache: 0 apps unchanged since an earlier scan and not read again, 2 apps read
```

Each of the four claims in `report.json` reads like this one, and each id
under `evidence` is a record in the same file:

```json
{
  "type": "channel",
  "subject": {"kind": "app", "platform": "android", "id": "org.example.exposure.skeleton", "version": "1.0.0"},
  "object": {"kind": "sdk", "id": "sdk/posthog", "name": "PostHog"},
  "company": "posthog", "category": "analytics", "headline": true, "party": "third",
  "grade": "contains", "confidence": "high", "witnesses": 2,
  "evidence": ["sha256:1792…3db6", "sha256:631f…5b91"]
}
```

PostHog is analytics, so it counts in the headline. Sentry, found in both
apps too, is crash reporting: it is in the report and not in the counts.

## How it works

```mermaid
flowchart LR
    A["Apps on disk<br/>.app bundles, Electron apps,<br/>.apk and .aab files, browser extensions"] --> COL
    subgraph COL["Collectors (read only)"]
        direction TB
        M["macOS: Mach-O, Info.plist,<br/>code signature, privacy manifests"]
        EL["Electron: asar archive,<br/>npm packages, scripts"]
        AN["Android: zip, DEX, manifest,<br/>resource table (APK and bundle)"]
        BX["Browser extensions:<br/>manifest.json"]
    end
    RP[("Signed rule pack<br/>48 SDK rules, company map")] --> MT
    COL --> MT["Matchers<br/>literal tokens with boundaries"]
    MT --> EV[("Evidence set<br/>records keyed by SHA-256")]
    COL -- "permissions, declared hosts" --> EV
    CA[("Results cache<br/>private, deletable")] -. "unchanged apps<br/>are not read again" .-> EV
    EV --> RS["Resolver<br/>company, vendor, party, grade"]
    RP --> RS
    RS --> CL[("Claims")]
    CL --> REP["Report<br/>HTML and JSON"]
```

1. **Collect.** Collectors find the apps, read every file once in bounded
   windows, hash it, and parse the parts that name code: binary headers,
   class tables, manifests, archives. Each parser takes a byte slice and stops
   at fixed budgets. An app that has not changed since the last scan is not
   read again: its records come from a private results cache.
2. **Match.** Matchers compiled from the rule pack look for literal tokens,
   each with a boundary rule, and record every hit as an evidence record.
   Controls such as scope labels, a breadth guard and distinct-token minimums
   keep coincidental hits out.
3. **Resolve.** Pure functions turn evidence into claims: which company
   operates the SDK, who publishes the app, whether the channel is first or
   third party, and the highest grade the evidence supports.
4. **Report.** The claims and every record they cite are written as an HTML
   page grouped by company, a JSON document, or both. The page holds no
   script and loads nothing, so it stays inert whatever an app's names
   contain.

Everything before the evidence set touches the file system; everything after
it is a pure function. That split is enforced by the crate layout (see
[Architecture](#architecture)).

## Install

**With Homebrew**, on macOS (Apple silicon is the first supported platform)
or Linux:

```console
$ brew tap Adityaakr/exposure-scanner https://github.com/Adityaakr/exposure-scanner
$ brew install adityaakr/exposure-scanner/exposure
```

The repository is its own tap: the formula is
[`Formula/exposure.rb`](Formula/exposure.rb). It builds `exposure` from the
source on `main` with `cargo install --locked`, so the build takes a minute
or two; Homebrew brings the Rust compiler for it. On a Mac, Homebrew builds
from source only with up-to-date Command Line Tools
(`xcode-select --install`, or Software Update).

- The full name, `adityaakr/exposure-scanner/exposure`, is what Homebrew 7
  asks for: it trusts the tap on that install. `brew install exposure` works
  once the tap is trusted, with `brew trust adityaakr/exposure-scanner`, and
  on older versions of Homebrew without that step.
- `brew upgrade` does not see new commits on `main`, since the formula's
  version only changes with a release. `brew reinstall exposure` builds the
  latest.

**With cargo**, from source:

1. On a Mac, install Apple's command-line tools, which hold the linker and
   `git`:

   ```console
   $ xcode-select --install
   ```

2. Install Rust 1.97 or later with [rustup](https://rustup.rs):

   ```console
   $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   $ source "$HOME/.cargo/env"
   ```

   If Rust is already installed, `rustup update stable` brings it up to date.

3. Install `exposure`:

   ```console
   $ cargo install --git https://github.com/Adityaakr/exposure-scanner --locked exposure
   ```

   `--locked` builds with the exact dependency versions the project tests.
   The build takes a minute or two, and puts `exposure` in `~/.cargo/bin`.
   To install the release tag rather than the latest commit, add
   `--tag v0.1.0`.

To build from a clone instead, `cargo build --release --package exposure`
gives `target/release/exposure`; the clone's
[`rust-toolchain.toml`](rust-toolchain.toml) pins the exact toolchain.

## Quick start

```console
$ exposure scan
```

That is all. On macOS it reads the apps in `/Applications` and
`~/Applications` and the extensions in your browser profiles, writes the
report to `~/Library/Application Support/exposure/report.html`, opens it in
your browser, and prints what needs your attention first. The output looks
like this (the apps and counts here are made up):

```text
Your report: /Users/you/Library/Application Support/exposure/report.html
It is open in your browser.

Scanned 16 apps and 4 browser extensions.

What needs your attention first (5 of 14 things you can do):

  1. [High] PostHog
       Analytics by PostHog Inc., in Logseq and Example.
       In Logseq, turn it off: Settings > Advanced, then turn off Send usage
       data and diagnostics to Logseq.
  ...

9 more entries in the report, under What you can do.

The headline counts:
  3 companies whose code the scanned apps ship, in advertising, analytics and the like
  7 apps with code or an endpoint of a company other than their publisher
```

Nothing is sent anywhere, and nothing on your Mac is changed: the report says
what you can do, and you decide. A
[sample HTML report](tests/fixtures/report/Fixtures.report.html) built from
the repository's test fixtures is committed.

## Usage

```
exposure scan [PATH...] [--html FILE] [--json FILE] [--no-open] [--threads N] [--no-cache]
              [--fail-on CONDITION]...              scan apps, extensions, or folders of them
exposure report FILE [--html FILE] [--json FILE] [--fail-on CONDITION]...
                                                    derive the report again from saved evidence
exposure diff OLD NEW [--json FILE] [--fail-on CONDITION]...
                                                    compare two JSON reports, app by app
exposure rules show                                 list the built-in rule pack, its categories
                                                    and its companies
exposure rules verify PACK --sig SIGNATURE          check a signed pack file offline
exposure --help | --version
```

| Option | Effect |
|---|---|
| `PATH` | A macOS `.app` bundle, an Android `.apk` file or app bundle (`.aab`), a browser extension (a Firefox `.xpi` file, or a Chromium `<id>/<version>` folder), or a folder, searched for all of them (never inside a bundle). When any `PATH` is given, only the `PATH`s are scanned. |
| `--html FILE` | Write the report for reading: one self-contained page, grouped by company. |
| `--json FILE` | Write the report a program reads, which `exposure report` can render again. A `FILE` of `-` is standard output. Report files are created readable by their owner only, because the list of apps a person uses is sensitive in itself. |
| `--no-open` | Do not open the report in the browser. |
| `--threads N` | Worker threads. Default: one per core. The report does not depend on it. |
| `--no-cache` | Read every app again, and neither use nor keep the results cache. |
| `--fail-on CONDITION` | Exit with status 3 when a finding meets `CONDITION`, after the reports are written: `headline` (a finding that counts in the headline), `category:ID` (such as `category:analytics`) or `company:ID` (such as `company:google`). `exposure rules show` lists the ids. Can be given more than once; any match fails. For `diff`, only the findings that newly meet it are checked: those `NEW` adds, and those that meet it in `NEW` but did not in `OLD`, such as a finding of the app's own vendor that moves from `declares` to `contains`. The summary on standard error names each such finding, its app and company, and why it is new: added, a grade change, now third-party, now counted in the headline, a new category or another company, so a finding the comparison does not list is still named. |

| Exit status | Means |
|---|---|
| 0 | Done, and no `--fail-on` condition was met |
| 1 | An error, such as a file that cannot be read or written, or a `--fail-on` id the rule pack does not have |
| 2 | A command line that is not understood |
| 3 | Done, and a `--fail-on` condition was met |

**With neither `--html` nor `--json`,** a scan writes the HTML report to
`report.html` in a folder only you can read (`~/Library/Application
Support/exposure` on macOS; `$XDG_DATA_HOME/exposure`, else
`~/.local/share/exposure`, elsewhere), replacing the one before. It prints the
report's path, the headline counts and the first five entries of the "What
you can do" checklist, and when it runs in a terminal it opens the report in
your default browser. For scripts, `--json -` puts the JSON report on
standard output instead, as `exposure report` does by default.

The summary on standard error ends with a scope line that says where the scan
looked; it names no app and no path. Apple's own apps in
`/System/Applications` are not scanned unless you name that folder.

**Browser extensions.** Only each extension's `manifest.json` (and, when its
name refers to one, its message catalogue) is read: never your history,
cookies, bookmarks, saved logins or pages. Each powerful permission becomes
an access claim such as "may read and change data on every website you
visit", which names no company and is not counted in the headline.

**The results cache.** A scan keeps what it found in each app, one file per
app, readable by its owner only, in `~/Library/Caches/exposure` on macOS (or
`$XDG_CACHE_HOME/exposure`, else `~/.cache/exposure`). An app whose files
look exactly as they did, scanned by the same build with the same rule pack,
is not read again: a scan of 16 installed apps drops from 1.4 s to 0.10 s.
The report is the same with the cache and without it, byte for byte. The
folder can be deleted at any time, and a scan run as root does not use it.

A path that does not exist is refused before anything is read. After that, an
app that cannot be read never stops the scan: it is reported as a coverage
note (`skipped`, `unreadable`, `over_budget`, ...), never as "nothing found".

**Android.** An app is shown under the name its label points at, read from
the package's resource table, rather than its package id. App bundles
(`.aab`), the form uploaded to Google Play, are scanned like the APKs they
stand for.

Details: [What a scan reads](docs/scanning.md).

## Release gates and comparing builds

`exposure diff OLD NEW` compares two JSON reports, such as the scans of two
builds of one app. An app is followed from one report to the other by its
platform and app id, and each finding by its claim `key`, so the comparison
says what a build adds, what it no longer has, and what changed grade. The
F-Droid and Google Play builds of Bitwarden 2026.9.1:

```console
$ exposure scan bitwarden-fdroid.apk --json fdroid.json
$ exposure scan bitwarden-play.apk --json play.json
$ exposure diff fdroid.json play.json --fail-on company:google
Bitwarden (Android, com.x8bit.bitwarden), 2026.9.1
  + Firebase Cloud Messaging (Push messaging, Google LLC): contains
  + Firebase Crashlytics (Crash reporting, Google LLC): contains
  + Firebase Installations (Installation identifiers, Google LLC): contains
  + Google DataTransport (Telemetry transport, Google LLC): contains
  + Google Play Billing Library (Payments, Google LLC): contains

5 findings added, 0 findings removed, 0 findings changed grade, in 1 of 1 app.
exposure: fail-on company:google: met by 5 new findings in 1 app
exposure: fail-on company:google:   Firebase Cloud Messaging (Push messaging, Google LLC) in Bitwarden (Android, com.x8bit.bitwarden): added
exposure: fail-on company:google:   Firebase Crashlytics (Crash reporting, Google LLC) in Bitwarden (Android, com.x8bit.bitwarden): added
exposure: fail-on company:google:   Firebase Installations (Installation identifiers, Google LLC) in Bitwarden (Android, com.x8bit.bitwarden): added
exposure: fail-on company:google:   Google DataTransport (Telemetry transport, Google LLC) in Bitwarden (Android, com.x8bit.bitwarden): added
exposure: fail-on company:google:   Google Play Billing Library (Payments, Google LLC) in Bitwarden (Android, com.x8bit.bitwarden): added
exposure: fail-on: a condition was met, so the exit status is 3
```

`--json FILE` writes the comparison as a document as well
(`exposure-diff/1`); with `--json -` it is all that goes to standard output.
When the two reports were made with different rule packs, the summary says
that a difference may come from the rules rather than from the apps.

`--fail-on` makes any scan a release gate: a CI job that scans the build it
is about to ship fails when the build ships what the condition names.

```console
$ exposure scan app-release.aab --json report.json --fail-on headline --fail-on company:meta
```

## Reading the report

Every finding is a **claim** with a **grade**. A claim takes the highest grade
its evidence supports, and new evidence can raise a grade but never lower it.

| Grade | In words | Means | Status |
|---|---|---|---|
| `declares` | declares | The app's own files name the endpoint, such as an update feed or a tracking domain in a privacy manifest | Reported now |
| `contains` | ships | The app ships the SDK's code: a class, package, framework or endpoint literal | Reported now |
| `contacts` | contacted | The OS or a capture recorded a connection | Milestone 2 |
| `confirmed` | confirmed | The receiver lists the sender, or a payload was inspected | Milestone 4 |

What an app may access has its own ladder: `requested` (the app asks for it;
reported now), `granted` and `used` (later milestones). The two ladders are
never joined: "ships an analytics SDK" and "may access the camera" never
become "sends pictures to an analytics company".

> [!NOTE]
> `contains` proves presence, not use. An app can ship code it never calls,
> or code of a service that has been retired. Only `contacts` shows a live
> flow.

**The headline is three counts, and there is no score:** companies at
`contacts` or above, companies at `contains`, and apps with at least one
third-party channel.

| Counted | Not counted |
|---|---|
| Claims that name a company, in five categories: advertising, analytics, attribution, profiling, session replay | Crash reporting, push delivery, payments and billing, customer messaging, update feeds, declared tracking domains no rule names, components (libraries with no company, such as updaters), unmapped hosts, and every access claim |

Each claim says whether it counts in its `headline` field, so the numbers can
be recounted from the claims. A host under no domain the rule pack lists is
**unmapped**: it is shown as itself, nobody is named as its owner, and it is
counted nowhere.

The HTML report opens with **What needs your attention**: the few entries of
its **What you can do** checklist that matter most, each in one sentence with
its first step. The whole checklist follows, and every finding has its steps
too: an app's own opt-out where its publisher documents one;
hosts to block with an outbound firewall such as LuLu or Little Snitch, given
only for the counted categories and declared tracking domains; the
**System Settings > Privacy & Security** pane, or the Android
**Settings > Apps** page, of each permission; and how to narrow or remove a
browser extension. The scanner applies none of it. What holds for one app or
one SDK is data in `rules/core/fixes.toml` (see
[`rules/README.md`](rules/README.md#fixes)).

Details: [Reading the report](docs/report.md), including how the company, the
app's vendor and first or third party are decided.

## Privacy guarantees

A tool that reads the list of apps you use has to be safer than the apps it
reports on. These are enforced by mechanism and checked in CI, not left to
discipline.

| Guarantee | How it is enforced |
|---|---|
| **Local only.** Nothing leaves the machine. | There is no network code. `cargo deny` bans every crate that can open a socket; CI checks that the binary imports no socket function and runs a scan in a network namespace with no interfaces, under `strace`, and under a macOS sandbox that denies the network. |
| **Read only.** A scan changes no app and executes nothing. | Collectors only open files for reading. Symbolic links inside an app are never followed. Nothing is extracted to disk. Of a browser profile, only the extensions are opened: their manifests, and Firefox add-on archives. The one process `exposure` starts is macOS's opener for the report it has just written, after the scan, in a terminal, unless `--no-open`; elsewhere it starts none. |
| **Deterministic.** Same evidence, rule pack and scope, same bytes. | Derivation and rendering live in `no_std` crates that cannot read a clock, a file or the environment. Records hold paths inside an app, never paths of your machine. The HTML report holds no date, no device name and no path you gave. |
| **Minimal storage.** | Only two things are written: the report (the file you name, or `report.html` in a private folder), and the results cache. Both are readable by their owner only, in folders only the owner can open. The cache holds the same records the report shows, no paths and no file lists; it can be deleted at any time and is off with `--no-cache`. |
| **Rules are data.** | A rule is a literal and a boundary from a fixed list: no regular expressions, no scripts. The scanner only loads a pack whose signature verifies against a key built into the binary. |

## What a device-side scan cannot see

A report is only as complete as what a device can show. It cannot see:

- **What happens on servers.** What a company forwards to others from its own
  servers never touches the device.
- **What is inside encrypted traffic.** TLS hides the payload; the current
  build observes no traffic at all.
- **First-party proxying.** An app that sends data to a tracker through its
  own domain looks like a first-party host.
- **SDKs without a rule.** Only what the rule pack has a rule for is
  recognised. A clean report does not mean an app is clean.
- **Use.** Shipping code is not running it.
- **What you granted.** Which permissions you allowed in System Settings
  lives in the system's permission store, outside the app's files.

## Platforms and roadmap

| Platform | Status |
|---|---|
| macOS on Apple silicon | First supported platform. Installed apps are found automatically. Tested in CI on merges and nightly. |
| Linux | The CI platform for the portable core: every check runs there on every change. Scans the paths you name. |
| Android packages (`.apk`) and app bundles (`.aab`) | Scanned by path on any OS. |
| Browser extensions | Chromium-family browsers and Firefox: found automatically in your profiles on macOS, scanned by path elsewhere. |
| Phones, iOS exports, browser history | Milestone 2. |
| Windows | Not planned yet. |

| Milestone | Ships | Status |
|---|---|---|
| **1. Static truth** | Rust core, evidence format, rule pack, collectors for macOS bundles, Electron apps and Android packages, resolver, HTML report | **Done: v0.1.0** |
| 2. Phone and browser | iOS report import, Android phones over adb, browser join, browser extension audit, OS permission stores | Started: the browser extension audit is done |
| 3. Fix and diff | Fix recipes with an undo log, snapshots, a diff between scans | Started: `exposure diff` between two reports is done |
| 4. Confirmed | Platform data-archive adapters, lab capture | Planned |
| 5. Public index | Scans of popular apps published per artifact hash; a signature contribution workflow | Planned |

Milestone 1 in detail:

| Part | Status |
|---|---|
| Workspace, guardrails, CI on Linux and macOS | Done |
| Evidence format v1: canonical JSON, record ids, evidence set | Done |
| Rule pack: source format, compiler and lints, signature check, signed built-in pack of 48 rules | Done |
| Match engine: literal search with boundaries, exact and prefix tables, false-positive controls | Done |
| Collectors: macOS bundles, Electron apps, Android packages | Done |
| Browser extension collector (ahead of milestone 2) | Done |
| What each app may access (`requested`) | Done |
| Resolver: companies, vendors, first or third party, headline counts | Done |
| Scan scheduler: app discovery, one largest-first queue, per-app failure handling | Done |
| HTML report grouped by company, with every record, coverage and limits | Done |
| Local results cache and warm scan | Done; removing entries of deleted apps automatically is a follow-up |
| Gates: canary recall, negative-control corpus, speed gates on the reference laptop (CI runs the benchmark on fixtures for memory and determinism) | Done |
| One-command scan: report to a private folder, opened in the browser, checklist in the terminal | Done |
| Release preparation: threat model, dispute process, reproducible-build check, v0.1.0 | Done |
| Exodus layer and the differential test against Exodus reports | Follow-up |

## Architecture

One Cargo workspace. Only `xs-collect` opens files; the crates that derive
and render are `no_std`, so they cannot reach a file, a clock or a socket.

```mermaid
flowchart TD
    cli["exposure (crates/xs-cli)<br/>the binary"]
    collect["xs-collect<br/>discovery, reading, scheduling, cache"]
    rules["xs-rules<br/>pack loader, signature check"]
    derive["xs-derive<br/>claims, grades, companies"]
    render["xs-render<br/>JSON and HTML report"]
    match["xs-match<br/>matchers, false-positive controls"]
    formats["xs-formats<br/>bounded parsers"]
    model["xs-model<br/>evidence and claim types"]
    cli --> collect & rules & derive & render & match
    collect --> formats & match
    derive --> model
    render --> model
    rules --> model
    match --> model
    collect --> model
```

| Crate | Role | Can use |
|---|---|---|
| `xs-model` | Evidence, claim and pack types; canonical JSON; record ids | `no_std` |
| `xs-formats` | Parsers over byte slices: Mach-O, code signature, property lists, asar, zip, DEX, binary Android XML, extension manifests | std, without file, network, clock or environment APIs |
| `xs-match` | Matchers compiled from a pack; controls against false positives | `no_std` |
| `xs-rules` | Pack loader and signature check; the source compiler behind a tooling-only feature | std, without file access |
| `xs-derive` | Evidence and pack in, claims out | `no_std` |
| `xs-render` | Claims and evidence in, the JSON and HTML report out | `no_std` |
| `xs-collect` | Discovery, scheduling, reading and the results cache; the only crate that opens files | std |
| `exposure` | The command-line binary | std |
| `xtask` | Developer tooling; never shipped | anything |

A scan of 16 installed apps and 8 browser extensions (11,669 files, 6.8 GB)
takes 1.4 s on 8 threads of an Apple M5, with a peak of 40 MB of memory, and
0.11 s when the cache finds that no app has changed.

Details: [Architecture](docs/architecture.md): the pipeline, file reading,
scheduling, benchmarks, and how each property is enforced.

## Rule packs

A rule is data: lists of literal tokens per kind of witness, tied to one
company and one category. Every token cites a source that shows the literal
in the SDK's own code or its vendor's documentation.

```mermaid
flowchart LR
    S["rules/core/*.toml<br/>(edit these)"] -- "cargo xtask pack compile<br/>lints" --> P["rules/dist/core.pack.json<br/>(canonical JSON)"]
    P -- "cargo xtask pack sign<br/>maintainer key" --> G["core.pack.json.minisig"]
    P --> B["built into the exposure binary,<br/>signature checked on load"]
    G --> B
```

To add or change a rule, follow
[Adding or changing a rule](CONTRIBUTING.md#adding-or-changing-a-rule). The
rule format, the boundaries, the lints and advice on choosing tokens are
in [`rules/README.md`](rules/README.md).

## Testing and the six properties

"It works" is defined by six properties from the project's specification.
Each has an automated test. All run in CI except the absolute speed gates
(cold scan under 60 s, warm scan under 5 s, scaling), which are verified on
the reference laptop with `cargo xtask bench --strict`; CI runs the
benchmark on the fixtures for its memory and determinism gates.

| Property | Pass condition | Test | Runs |
|---|---|---|---|
| **Finds what is there** | At least 95% recall of planted SDK markers | `canary`: every token of every rule of the built-in pack is planted the way the SDK leaves it (framework folders, Objective-C classes and strings in Mach-O files, privacy manifests, DEX classes and strings, manifest components and files in APKs, npm packages and script literals in asar archives), one synthetic app per rule and kind of witness, and scanned through the real collectors: 231 of 231 plants found for the 48 rules. Real apps pinned by hash give their expected findings | Every change |
| **Does not cry wolf** | No channel to another company than the app's publisher, at any grade, in a negative control | `negative_corpus`: 30 real apps pinned by hash, 15 for Android and 15 for macOS, including hard negatives: a browser that embeds Chromium (Cromite), two ad blockers (RethinkDNS, personalDNSfilter), Electron apps (VSCodium, Bitwarden desktop), an app whose bundled data names dozens of SDKs (TrackerControl), and one whose bundled documentation holds an analytics snippet (Bitwarden desktop). An app's own update feed is allowed even when another company, such as GitHub, hosts it | A subset of 8 on every change; all 30 nightly |
| **Deterministic** | Same evidence and rule pack give a byte-identical report | Input order (sorted, reversed, shuffled), thread count, install location and cache state (off, empty, full, damaged); committed fixture reports reproduce on Linux and macOS | Every change |
| **Private** | No socket opened during a scan | Dependency bans, symbol audit, network namespace, `strace`, macOS sandbox, each with a control that must be caught | Every change |
| **Fast** | Cold scan under 60 s, warm scan under 5 s, memory under 200 MB, 3x at 8 threads | `cargo xtask bench --strict` on the apps installed on the reference laptop (an Apple M5): 16 apps and 8 extensions, 6.8 GB, read in 1.44 s with an empty results cache and in 0.11 s with nothing changed, 40 MB at most, 4.25x at 8 threads, one report across 17 runs (measured 2026-11-18 with the page cache warm: dropping it needs `sudo`). CI runs the benchmark on the fixtures for its memory and determinism gates | Memory and determinism every change; timing gates on the reference laptop before a release |
| **Honest** | Every finding shows its grade and the raw record behind it | A report that cites a missing record fails to render; the HTML page is read back to find every claim's grade, confidence and records | Every change |

Parsers also run under property tests with arbitrary and damaged input. The
zip, DEX, Android manifest, Android resource table, app bundle and extension
manifest parsers and the Android collector run under libFuzzer for 60 s per
target in CI.

```console
$ cargo test --workspace --all-features
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo deny check               # dependency bans, licences, advisories
$ cargo xtask pack check         # rule sources, compiled pack and signature agree
$ cargo xtask guardrails         # deliberate violations must fail the build
$ cargo xtask no-network         # a scan opens no socket
$ cargo xtask bench --strict     # speed, memory and determinism gates on the installed apps
$ cargo xtask repro              # two clean builds of HEAD give the same binary
$ fuzz/run.sh 60                 # every fuzz target for 60 s (nightly, cargo-fuzz)
```

Tests that scan real apps need them in a local cache folder and pass with a
notice without it; see [`tests/fixtures/README.md`](tests/fixtures/README.md).
`cargo xtask fixtures negatives --dir DIR --all` fetches the negative corpus.

## Releases and verifying a build

Releases are tagged commits of source; [CHANGELOG.md](CHANGELOG.md) lists
what each one changed. There are no prebuilt binaries: a scanner that reads
the list of your apps is more credible built from source you can read. The
Homebrew formula builds from source as well.

Two clean builds of one commit give the same binary, byte for byte.
`cargo xtask repro [REV]` checks it: it exports the commit twice, to two
folders at different paths, builds each in release mode with its own target
folder, and compares the two `exposure` binaries. CI runs it nightly on macOS
and Linux. A build on another machine gives the same bytes with the same
toolchain (the one [`rust-toolchain.toml`](rust-toolchain.toml) pins), target
and cargo home folder. Homebrew builds with its own Rust, not the pinned one,
so its binary is not byte for byte the one `cargo xtask repro` checks.

The [threat model](docs/threat-model.md) says what the scanner protects,
against whom, and where the protection ends. If a report names your app or
your company and you believe a finding is wrong, use the
[dispute form](https://github.com/Adityaakr/exposure-scanner/issues/new?template=dispute.yml);
[docs/disputes.md](docs/disputes.md) says how a dispute is settled.

## Licences and data sources

| What | Licence |
|---|---|
| Code | [Apache-2.0](LICENSE) |
| The project's own rules and company map (`rules/core/`, `rules/dist/`) | [CC BY 4.0](LICENSES/CC-BY-4.0.txt) |
| Signatures converted from Exodus Privacy (`rules/exodus/`, not yet populated) | [ODbL 1.0](LICENSES/ODbL-1.0.txt), kept in a separate file and never merged with other layers |
| The Public Suffix List compiled into the binary | [MPL 2.0](https://mozilla.org/MPL/2.0/) |

Every rule and every company entry is written from the vendor's own source
code, documentation and company pages, and cites them. Entries are not copied
from DuckDuckGo Tracker Radar, Ghostery TrackerDB, Disconnect, the IAB Europe
vendor list or F-Droid's `suss.json`, whose licences do not allow it. See
[`NOTICE`](NOTICE).

## Contributing

Contributions of every size are welcome: a rule for an SDK the pack does not
know, a false positive on a real app, a parser bug, or a clearer sentence in
the docs. Read [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and
submit a change, and open an
[issue](https://github.com/Adityaakr/exposure-scanner/issues) to discuss
anything larger first.

## Acknowledgements

- [Exodus Privacy](https://reports.exodus-privacy.eu.org/), whose tracker
  reports showed what static analysis of Android apps can establish, and
  whose caveat this project shares: a signature found in an app is not proof
  that the tracker is active.
- The [Public Suffix List](https://publicsuffix.org/), used to cut host names
  down to their registrable domain.
- The Rust crates this project is built on, among them
  [`aho-corasick`](https://crates.io/crates/aho-corasick),
  [`miniz_oxide`](https://crates.io/crates/miniz_oxide),
  [`plist`](https://crates.io/crates/plist),
  [`psl`](https://crates.io/crates/psl),
  [`minisign-verify`](https://crates.io/crates/minisign-verify),
  [`rayon`](https://crates.io/crates/rayon) and
  [`serde`](https://crates.io/crates/serde).
- The open-source apps used as test fixtures, among them Bitwarden, Logseq,
  NetNewsWire, Maccy, AltTab and NewPipe.
