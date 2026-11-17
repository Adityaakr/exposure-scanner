# Contributing to exposure-scanner

Thank you for your interest. The project is under active development, so
suggestions about its direction are as welcome as code. This page explains
how to propose a change and what a change has to meet to be merged.

- [Ways to contribute](#ways-to-contribute)
- [Ground rules](#ground-rules)
- [Development setup](#development-setup)
- [Checks before a pull request](#checks-before-a-pull-request)
- [Adding or changing a rule](#adding-or-changing-a-rule)
- [Reporting a wrong finding](#reporting-a-wrong-finding)
- [Pull requests](#pull-requests)
- [Security issues](#security-issues)
- [Licensing of contributions](#licensing-of-contributions)

## Ways to contribute

- **Report a wrong finding.** A false positive, or an SDK an app ships that
  the scanner misses. These are the most useful reports (see
  [below](#reporting-a-wrong-finding)).
- **Add a rule** for an SDK the built-in pack does not know.
- **Fix a bug** or improve a parser, a collector or the report.
- **Improve the documentation.** If a sentence confused you, it will confuse
  others.
- **Discuss the design.** Open an issue before starting anything large, such
  as a new collector or a change to the evidence format, so the approach can
  be agreed before you spend time on it.

## Ground rules

The scanner reads the list of apps a person uses, so it holds itself to
rules that most projects do not need. A change that breaks one of them is not
merged, however useful it is otherwise. Most are enforced by CI.

| Rule | What it means for a change |
|---|---|
| **No network** | No dependency that can open a socket, directly or through its own dependencies. `cargo deny check` and `cargo xtask no-network` fail otherwise. |
| **Deterministic** | No clock, no environment variables, no randomly seeded maps (`HashMap`, `HashSet`) anywhere a report is built. Lints ban them. Records hold paths inside an app only. |
| **Pure core** | `xs-model`, `xs-match`, `xs-derive` and `xs-render` are `no_std` and build for `wasm32v1-none`. Only `xs-collect` opens files. |
| **Hostile inputs** | Parsers take a byte slice, use no `unsafe` (it is forbidden), and stop at fixed budgets of bytes, items and depth. Symbolic links inside an app are never followed. |
| **Rules are data** | A rule is a literal plus one boundary from a fixed list. No regular expressions, no scripts. |
| **Graded facts** | Wording states what the evidence shows and no more: "ships", "may access", never "spies" or "sends your data". |

## Development setup

You need the Rust toolchain pinned in `rust-toolchain.toml`; `rustup`
installs it on first use. macOS on Apple silicon and Linux are the
development platforms.

```console
$ git clone https://github.com/Adityaakr/exposure-scanner.git
$ cd exposure-scanner
$ cargo build --workspace
$ cargo test --workspace --all-features
```

Optional tools, for the checks CI runs:

| Tool | For | Where the pinned version is |
|---|---|---|
| `cargo-deny` | `cargo deny check` | `.github/workflows/ci.yml` |
| `strace` (Linux) | `cargo xtask no-network` | system package |
| nightly toolchain and `cargo-fuzz` | `fuzz/run.sh` | [`fuzz/README.md`](fuzz/README.md) |

Some tests scan real apps. They are pinned by hash and never stored in the
repository; without a local copy those tests print a notice and pass. To run
them:

```console
$ cargo xtask fixtures fetch --dir ~/.cache/exposure-fixtures
$ EXPOSURE_FIXTURE_CACHE=~/.cache/exposure-fixtures cargo test -p exposure --test android_real_apps
```

[`tests/fixtures/README.md`](tests/fixtures/README.md) lists every pinned app
and how to get it.

## Checks before a pull request

CI runs these on Linux for every pull request. Running them locally first
saves a round trip.

```console
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo test --workspace --all-features
$ cargo build --target wasm32v1-none -p xs-model -p xs-match -p xs-derive -p xs-render
$ cargo deny check
$ cargo xtask pack check
$ cargo xtask guardrails
$ cargo xtask no-network
```

If a change alters a report, the committed fixture reports under
`tests/fixtures/` must change with it. Regenerate them with
`EXPOSURE_BLESS=1 cargo test -p exposure` and review the diff: every changed
byte should be one you expected.

## Adding or changing a rule

Rules live in [`rules/core/`](rules/core/); [`rules/README.md`](rules/README.md)
describes the format, the boundaries and the compiler's lints in full.

1. Add or edit one file under `rules/core/sdk/`, and the company in
   `rules/core/entities.toml` if it is new.
2. Take every token from the SDK's own source code or the vendor's
   documentation, and cite that page as an `https://` source.
3. Do not copy entries from DuckDuckGo Tracker Radar, Ghostery TrackerDB,
   Disconnect, the IAB Europe vendor list or F-Droid's `suss.json`. Their
   licences do not allow it.
4. Run `cargo xtask pack compile`, which applies the lints, and
   `cargo test -p exposure --test rule_pack`, which checks that every token
   finds its own rule and no other.
5. Open a pull request with the sources and, where you can, the name,
   version and SHA-256 of a public build of an app that ships the SDK.

The compiled pack is signed with a key only the maintainer holds, so the
maintainer signs it and refreshes the fixture reports before merging. You do
not need to sign anything.

## Reporting a wrong finding

Open an issue with:

- the app's name, version and platform, and where it can be downloaded;
- the SHA-256 of the `.apk` file, or of the bundle's main executable;
- the claim you believe is wrong, and the evidence records it cites, copied
  from the JSON report.

Please do not attach a full report. It lists every app on your machine, which
is personal information; copy only the claim and its records.

## Pull requests

- Keep a pull request to one change, with tests that fail without it.
- Write commit titles as `type(scope): summary`, where `scope` is a crate or
  area, as in `feat(xs-collect): add the Android package collector` or
  `fix(rules): narrow the Branch endpoint token`.
- Update the documentation in the same pull request when behaviour changes:
  [`README.md`](README.md), the pages under [`docs/`](docs/), and
  [`rules/README.md`](rules/README.md) for rule format changes.
- Explain in the description what changed and why, and how you checked it.

A maintainer reviews every pull request. CI must pass before merging.

## Security issues

If you find a way to make the scanner open a connection, execute code from an
app, write outside the report it was asked for, or crash on a crafted file,
do not describe it in a public issue. Open an issue that says only that you
have a security report, and the maintainer will arrange a private channel.

## Licensing of contributions

By contributing you agree that your contribution is licensed under the
licence of the part of the repository it changes:

- code under [Apache-2.0](LICENSE);
- rules and company data under `rules/core/` and `rules/dist/` under
  [CC BY 4.0](LICENSES/CC-BY-4.0.txt);
- anything under `rules/exodus/` under [ODbL 1.0](LICENSES/ODbL-1.0.txt).
