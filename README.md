# exposure-scanner

A local command-line scanner that answers one question with proof: which
companies have a channel to your data, through which apps.

`exposure` reads files that are already on your disk, recognises third-party
SDKs by literal markers, maps each one to the company behind it, and writes a
report in which every statement links to a record you can re-check by hand.
It never observes behaviour, changes nothing, executes nothing and sends
nothing anywhere.

## Status

Milestone 1 ("static truth") is in progress. This repository currently holds
the foundation and the macOS, Electron and Android collectors:

| Part | State |
|---|---|
| Evidence format v1, canonical JSON, record ids, evidence set | Done |
| Rule pack: source format, compiler and lints, signature check, built-in signed pack, 12 seed rules | Done |
| `exposure scan` on a macOS app bundle, through derivation, to a JSON report | Done |
| Match engine: literal search with boundary rules, exact and prefix tables, and the controls against false positives | Done |
| macOS collector: Mach-O load commands, Objective-C class names, data and embedded-script sections, Team ID, privacy manifests, update feed | Done (below) |
| Electron apps: npm packages listed in an asar archive or in the `Contents/Resources/app` folder, literals in the app's scripts, scope labels, breadth guard | Done |
| `exposure scan` on an Android package (`.apk`) | Done, with four witnesses: manifest components, classes defined in the DEX files, DEX string constants, and entry names |
| Company and party resolution, HTML report, cache | Not yet (build plan tasks 9 to 14) |
| Finding `.apk` files inside a folder that is scanned | Not yet: it comes with the scan scheduler (build plan task 9), which decides what one found package that cannot be read does to the rest of the scan |

What a scan of a macOS bundle reads, and what each part is a witness of:

| Where | Witness | Finds |
|---|---|---|
| Folder names under `Contents/Frameworks` | `apple_framework` | An SDK shipped as a framework |
| Load commands of every Mach-O file | `macho_dylib` | A linked library, wherever it is installed |
| The `__objc_classname` section | `macho_objc_class` | An SDK linked statically into a binary: the Objective-C runtime needs these names, so stripping does not remove them |
| Bytes outside the sections of instructions | `macho_token` | Literals of a statically linked SDK. Not searched in a browser engine or another runtime |
| Embedded-script sections such as `__BUN,__bun` | `content_literal` | SDK literals in the script of an app compiled into its runtime |
| `NSPrivacyTrackingDomains` of every `PrivacyInfo.xcprivacy` | `privacy_manifest` | Tracking domains the app or a library declares, each shown as a host |
| `SUFeedURL` of `Contents/Info.plist` | `update_feed` | The host the app fetches its updates from |
| Code signature of the main executable | (a fact, not a witness) | The Apple Team ID the signature names. It is read, not verified |

A declared address is cut down to its host; no URL is stored. A host is shown
as itself and names no company yet: mapping hosts and vendors to companies is
build plan task 10. An encrypted binary, such as an iOS app installed on a
Mac, is reported as a coverage note and its ciphertext is not searched.

An Electron app is a macOS bundle too, so all of the above applies to it.
Its scripts are read as well: an SDK is found when it is installed as an npm
package, or bundled into the app's own code.

So today a scan covers macOS bundles, Electron apps among them, and Android
packages. A scan of an Android package looks for the Android SDKs the seed
pack has rules for, and for nothing else. A clean report from this build
does not mean an app is clean.

Measured on the three Electron apps this part is tested against: Logseq
2.0.2 reports Sentry and PostHog, both from `js/main.js` inside its archive
and neither among the 280 npm packages the archive lists. Bitwarden desktop
2026.10.4 and Obsidian 1.15.1 report nothing.

## Use

Requires the Rust toolchain pinned in `rust-toolchain.toml` (rustup installs
it on first use).

```console
$ cargo build --release --package exposure
$ target/release/exposure scan tests/fixtures/macos/Skeleton.app --json report.json
exposure: scanned 1 app (3 files, 676 bytes): 1 claim, 0 coverage notes
```

To install the binary instead of running it from the build folder:

```console
$ cargo install --git https://github.com/Adityaakr/exposure-scanner --locked exposure
```

```
exposure scan PATH... [--json FILE] [--threads N]   scan .app bundles, folders of them, or .apk files
exposure report FILE [--json FILE]                  derive the report again from saved evidence
exposure rules show                                 list the built-in rule pack
exposure rules verify PACK --sig SIGNATURE          check a signed pack file offline
```

Without `--json` the report goes to standard output. A report file is
created readable by its owner only, because the list of apps a person uses is
sensitive in itself.

### What a finding looks like

```json
{
  "type": "channel",
  "subject": {"kind": "app", "platform": "macos", "id": "org.example.exposure.skeleton",
              "version": "1.0.0", "digest": "bd1:e387…4353"},
  "object": {"kind": "sdk", "id": "sdk/sentry", "name": "Sentry"},
  "company": "sentry", "category": "crash_reporting", "party": "unknown",
  "grade": "contains", "rungs": ["contains"],
  "confidence": "high", "witnesses": 1,
  "evidence": ["sha256:078a…5c96"]
}
```

`grade` says how strong the evidence is. `contains` means the app ships the
SDK's code. It proves presence, not use: only an observed connection would
show a live flow. The tool states graded facts and never says more than its
evidence supports. Each id under `evidence` is a record in the same file that
names the rule token, where it was found and how often.

### Android packages

```console
$ target/release/exposure scan tests/fixtures/android/Skeleton.apk --json report.json
exposure: scanned 1 app (1 file, 1818 bytes): 2 claims, 0 coverage notes
```

An `.apk` file is read once, from start to end, for its SHA-256, which is its
identity. On the way the manifest and the DEX files are copied out and
parsed in memory, one at a time, so evidence only comes from bytes the hash
covers. Nothing is extracted to disk and nothing is executed. Four tables
are matched, each an independent witness:

| Witness | Table | Still there when |
|---|---|---|
| `manifest_component` | Component and `meta-data` names in `AndroidManifest.xml` | The code is fully obfuscated |
| `android_class_prefix` | Classes the `classes*.dex` files define, not merely refer to | Entry classes keep their names |
| `dex_string` | String constants of the `classes*.dex` files | The code is fully obfuscated |
| `apk_file` | Names of the archive's entries | The code is fully obfuscated |

A record names the table and the file a hit is in, so it can be checked with
`unzip -l`, `aapt2 dump xmltree` or `dexdump`. A hit in the string table
carries the rule's token and never the string, which could be a URL.

Limits, each reported in the output where it bites: only the DEX files
Android loads from a package are read (`classes.dex`, `classes2.dex`, ...);
an entry over 256 MiB, or past 1 GiB in total, is set aside with its size;
archives with the 64-bit zip extension and DEX container files (version 041)
are reported as unsupported. The seed pack has no `apk_file` tokens yet, and
split packages are scanned one file at a time. A package is scanned when
its path is given: a folder is searched for app bundles only, not for `.apk`
files. A package that cannot be read
to its end, or that changes while it is read, fails the scan: without the
hash of one version of the file there is no subject to report on.

## The six properties

The scanner reads app lists, so it has to be safer than the apps it reports
on. Each property below is enforced by a mechanism and checked in CI, rather
than left to discipline.

| Property | How it is enforced | Checked by |
|---|---|---|
| **Private.** A scan opens no socket. | No crate that can open one is allowed into the dependency graph. The lint lists ban the socket, process, clock and environment APIs. | `cargo deny check`; `cargo xtask no-network`: the binary imports no socket function, and the scan runs in a network namespace with no interfaces, under `strace`, and under a macOS sandbox that denies the network. Each check is paired with a control program that must be caught. |
| **Deterministic.** Same evidence and rule pack, same bytes. | Derivation and rendering live in `no_std` crates that cannot read a clock, a file or the environment and have no randomly seeded map. Records hold paths inside the artifact only. Evidence is a set keyed by content hash. | One report across input orders, thread counts and install locations; the committed fixture report must be reproduced byte for byte on Linux and macOS. |
| **Honest.** Every finding shows its grade and the raw record behind it. | The renderer refuses a claim that cites a record the report does not carry. | A test deletes a cited record and expects the render to fail. |
| **Hostile inputs.** A malicious app cannot crash or mislead the scanner. | Parsers take a byte slice, are written in safe Rust (`unsafe` is forbidden), and stop at budgets of bytes, items and depth. No file over 2 GiB is read for evidence; a binary or archive that large is reported with its size instead. Of a Mach-O file only the headers and at most 1 MiB of load commands per architecture are held in memory, whatever its size. Symbolic links are never followed. The file table of an asar archive is not trusted: an entry that overlaps another or reaches past the end of the archive is counted as a gap and not read, and a header in a shape no archive writer produces is refused whole. Text from files is cut and cleaned before it is stored. | Property tests feed the parsers arbitrary and damaged input. The zip, DEX and manifest parsers and the Android collector also run under libFuzzer, 60 s each (`fuzz/run.sh`). |
| **Rules are data.** A rule pack cannot run code. | A rule is a literal plus one boundary from a fixed list. The scanner only loads a compiled pack whose signature verifies against a key built into the binary; it contains no parser for rule sources. | A tampered pack is refused; the pack compiler's lints are tested. |
| **Finds what is there / does not cry wolf.** | Several independent witnesses per SDK, with controls against coincidental hits (below). | Each control has its own tests, and a property test checks that cutting a file into windows never changes what is found. The canary and the negative corpus arrive with the collectors. |

The controls against coincidental hits, each one there because of a failure
seen on real apps:

| Control | What it does |
|---|---|
| Scope | Every file is app code, a dependency, a runtime or a resource. Free-form bytes of a runtime, such as an embedded browser engine, are not searched: it holds the names of ad hosts as data. In an Electron app only script files (`.js`, `.cjs`, `.mjs`) are searched, and what sits under a `node_modules` folder is a dependency. Pages, source maps and data files are not searched anywhere: a link in a page names a company without the app talking to it, and libraries ship demo pages and documentation. |
| Boundaries | A token found in free-form bytes must sit on a word or hostname boundary. `i.posthog.com` hits in `us.i.posthog.com` and not in `xi.posthog.com` or `i.posthog.com.evil.example`. |
| Token lints | The pack compiler refuses short content tokens and bare brand domains before a pack is signed. |
| Breadth guard | A file that names eight or more companies is a list, such as an ad blocker's filter list. Its hits are mentions and never findings. The guard counts companies over content-matcher hits only and holds back content-matcher hits only. Table-matcher hits, such as framework names, class tables and manifest entries, say what a file is made of and stay edges. This includes the `dex_string` hits of an Android app whose string table names eight or more companies: they are mentions, and the app's edges come from its class table and manifest. |
| Distinct-token minimum | A rule can demand that several different tokens hit before a kind of witness counts. |

`cargo xtask guardrails` proves the first two rows of the properties table
from the other side. It
breaks each rule on purpose in a copy of the workspace (uses `std::fs` in a
pure crate, opens a socket, adds an HTTP client as a dependency) and requires
the build to fail for the right reason.

## Layout

One Cargo workspace. A crate may depend only on crates above it in this list.

| Crate | Role | May use |
|---|---|---|
| `xs-model` | Evidence, claim and pack types; canonical JSON; ids | `no_std` |
| `xs-formats` | Bounded parsers over byte slices | std without file, network, clock or environment APIs |
| `xs-match` | Matchers compiled from a pack; hit collection; the controls against false positives | `no_std` |
| `xs-rules` | Pack loader and signature check; source compiler behind a tooling-only feature | std without file access |
| `xs-derive` | Evidence and pack in, claims out | `no_std` |
| `xs-render` | Claims and evidence in, report out | `no_std` |
| `xs-collect` | Discovery and reading. The only crate that opens files | std |
| `exposure` (in `crates/xs-cli`) | The `exposure` binary | std |
| `xtask` | Developer tooling. Never shipped | anything |

`fuzz/` holds the fuzz targets. It is a workspace of its own, because it
needs a nightly toolchain and the libFuzzer runtime.

```
discover ─▶ collect ─▶ evidence ─▶ derive ─▶ claims ─▶ render ─▶ report
(stat)     (read, hash,  set       (pure)              (pure)
            match)
```

Everything left of the evidence set touches the file system. Everything right
of it is a pure function.

Files are read once, in bounded 1 MiB windows, with the same bytes feeding
the hash and the matcher; one task per file, largest first. On an Apple M5
that scans 5.7 GB of installed app binaries in 1.7 s using 28 MB of memory.
A Mach-O file says where to look in it, so its headers and load commands are
picked out of the windows as they go by; the file is still read exactly once.

## Development

```console
$ cargo test --workspace --all-features    # everything, including the determinism tests
$ EXPOSURE_FIXTURE_CACHE=<dir> cargo test -p exposure --test electron   # also the real apps, see tests/fixtures/README.md
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo deny check                          # needs cargo-deny
$ cargo xtask pack check                    # rule sources, compiled pack and signature agree
$ cargo xtask guardrails                    # the guardrails refuse deliberate violations
$ cargo xtask no-network                    # a scan opens no socket
$ fuzz/run.sh 60                            # every fuzz target for 60 s; see fuzz/README.md
```

Some tests scan real apps, which are never stored here; without a cache
folder the tests say so and pass. The Android packages are pinned by hash in
`tests/fixtures/real-apps.txt`; `tests/fixtures/README.md` pins the rest.

```console
$ cargo xtask fixtures fetch --dir ~/.cache/exposure-fixtures
$ EXPOSURE_FIXTURE_CACHE=~/.cache/exposure-fixtures cargo test -p exposure --test android_real_apps
```

Rule changes are described in [`rules/README.md`](rules/README.md).

## Licence

Code: Apache-2.0 ([`LICENSE`](LICENSE)). The project's own rules and company
table: CC BY 4.0. Converted Exodus Privacy signatures, when added: ODbL 1.0,
in a separate layer. See [`NOTICE`](NOTICE) and [`LICENSES/`](LICENSES).
