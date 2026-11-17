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
the foundation and a walking skeleton:

| Part | State |
|---|---|
| Evidence format v1, canonical JSON, record ids, evidence set | Done |
| Rule pack: source format, compiler and lints, signature check, built-in signed pack, 12 seed rules | Done |
| `exposure scan` on a macOS app bundle, through derivation, to a JSON report | Done, with one witness: framework folder names |
| Content matching, Mach-O internals, Electron and Android collectors, company and party resolution, HTML report, cache | Not yet (build plan tasks 5 to 14) |

So today a scan finds an SDK only when it ships as a framework folder under
`Contents/Frameworks`. An SDK that is linked statically or bundled into a
script is not found yet. A clean report from this build does not mean an app
is clean.

## Use

Requires the Rust toolchain pinned in `rust-toolchain.toml` (rustup installs
it on first use).

```console
$ cargo build --release --package exposure
$ target/release/exposure scan tests/fixtures/macos/Skeleton.app --json report.json
exposure: scanned 1 app (3 files, 628 bytes): 1 claim, 0 coverage notes
```

To install the binary instead of running it from the build folder:

```console
$ cargo install --git https://github.com/Adityaakr/exposure-scanner --locked exposure
```

```
exposure scan PATH... [--json FILE] [--threads N]   scan .app bundles, or folders of them
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
              "version": "1.0.0", "digest": "bd1:1333…0461"},
  "object": {"kind": "sdk", "id": "sdk/sentry", "name": "Sentry"},
  "company": "sentry", "category": "crash_reporting", "party": "unknown",
  "grade": "contains", "rungs": ["contains"],
  "confidence": "high", "witnesses": 1,
  "evidence": ["sha256:faa8…4e08"]
}
```

`grade` says how strong the evidence is. `contains` means the app ships the
SDK's code. It proves presence, not use: only an observed connection would
show a live flow. The tool states graded facts and never says more than its
evidence supports. Each id under `evidence` is a record in the same file that
names the rule token, where it was found and how often.

## The six properties

The scanner reads app lists, so it has to be safer than the apps it reports
on. Each property below is enforced by a mechanism and checked in CI, rather
than left to discipline.

| Property | How it is enforced | Checked by |
|---|---|---|
| **Private.** A scan opens no socket. | No crate that can open one is allowed into the dependency graph. The lint lists ban the socket, process, clock and environment APIs. | `cargo deny check`; `cargo xtask no-network`: the binary imports no socket function, and the scan runs in a network namespace with no interfaces, under `strace`, and under a macOS sandbox that denies the network. Each check is paired with a control program that must be caught. |
| **Deterministic.** Same evidence and rule pack, same bytes. | Derivation and rendering live in `no_std` crates that cannot read a clock, a file or the environment and have no randomly seeded map. Records hold paths inside the artifact only. Evidence is a set keyed by content hash. | One report across input orders, thread counts and install locations; the committed fixture report must be reproduced byte for byte on Linux and macOS. |
| **Honest.** Every finding shows its grade and the raw record behind it. | The renderer refuses a claim that cites a record the report does not carry. | A test deletes a cited record and expects the render to fail. |
| **Hostile inputs.** A malicious app cannot crash or mislead the scanner. | Parsers take a byte slice, are written in safe Rust (`unsafe` is forbidden), and stop at budgets of bytes, items and depth. No file over 2 GiB is read for evidence; a binary that large is reported with its size instead. Symbolic links are never followed. Text from files is cut and cleaned before it is stored. | Property tests feed the parsers arbitrary and damaged input. |
| **Rules are data.** A rule pack cannot run code. | A rule is a literal plus one boundary from a fixed list. The scanner only loads a compiled pack whose signature verifies against a key built into the binary; it contains no parser for rule sources. | A tampered pack is refused; the pack compiler's lints are tested. |
| **Finds what is there / does not cry wolf.** | Several independent witnesses per SDK, with controls against coincidental hits. | Mostly later tasks: the canary and the negative corpus arrive with the collectors. |

`cargo xtask guardrails` proves the first two rows from the other side. It
breaks each rule on purpose in a copy of the workspace (uses `std::fs` in a
pure crate, opens a socket, adds an HTTP client as a dependency) and requires
the build to fail for the right reason.

## Layout

One Cargo workspace. A crate may depend only on crates above it in this list.

| Crate | Role | May use |
|---|---|---|
| `xs-model` | Evidence, claim and pack types; canonical JSON; ids | `no_std` |
| `xs-formats` | Bounded parsers over byte slices | std without file, network, clock or environment APIs |
| `xs-match` | Matchers compiled from a pack; hit collection | `no_std` |
| `xs-rules` | Pack loader and signature check; source compiler behind a tooling-only feature | std without file access |
| `xs-derive` | Evidence and pack in, claims out | `no_std` |
| `xs-render` | Claims and evidence in, report out | `no_std` |
| `xs-collect` | Discovery and reading. The only crate that opens files | std |
| `exposure` (in `crates/xs-cli`) | The `exposure` binary | std |
| `xtask` | Developer tooling. Never shipped | anything |

```
discover ─▶ collect ─▶ evidence ─▶ derive ─▶ claims ─▶ render ─▶ report
(stat)     (read, hash,  set       (pure)              (pure)
            match)
```

Everything left of the evidence set touches the file system. Everything right
of it is a pure function.

Files are read once, in bounded 1 MiB windows, with the same bytes feeding
the hash and the matcher; one task per file, largest first. On an Apple M5
that scans 5.7 GB of installed app binaries in 1.7 s using 24 MB of memory.

## Development

```console
$ cargo test --workspace --all-features    # everything, including the determinism tests
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo deny check                          # needs cargo-deny
$ cargo xtask pack check                    # rule sources, compiled pack and signature agree
$ cargo xtask guardrails                    # the guardrails refuse deliberate violations
$ cargo xtask no-network                    # a scan opens no socket
```

Rule changes are described in [`rules/README.md`](rules/README.md).

## Licence

Code: Apache-2.0 ([`LICENSE`](LICENSE)). The project's own rules and company
table: CC BY 4.0. Converted Exodus Privacy signatures, when added: ODbL 1.0,
in a separate layer. See [`NOTICE`](NOTICE) and [`LICENSES/`](LICENSES).
