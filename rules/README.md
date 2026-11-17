# Rule pack

A rule is data: lists of literal tokens per matcher kind, tied to one company
and one category. There is no regular expression and no script, so a rule
pack cannot run code or stall the scanner.

```
rules/core/*.toml ──compile──▶ rules/dist/core.pack.json ──sign──▶ core.pack.json.minisig
  (edit these)                   (canonical JSON, committed)         (committed)
```

| Path | What | Licence |
|---|---|---|
| `core/pack.toml` | Layer name, version, the fixed list of categories | CC BY 4.0 |
| `core/entities.toml` | Companies, each with a source | CC BY 4.0 |
| `core/sdk/*.toml` | One rule per SDK | CC BY 4.0 |
| `dist/core.pack.json` | The compiled `core` layer | CC BY 4.0 |
| `dist/core.pack.json.minisig` | Its detached minisign signature | — |
| `keys/exposure-pack-1.pub` | The public key the scanner trusts | — |
| `exodus/` | Reserved for the converted Exodus Privacy signatures | ODbL 1.0 |

Layers are licensed separately and are only ever combined in memory on the
user's machine. No merged table is distributed. The licence texts are in
`../LICENSES/`.

## Changing a rule

1. Edit a file under `core/`. Every token needs a `sources` URL that shows
   the literal in the SDK's own source or the vendor's documentation.
2. `cargo xtask pack compile` runs the lints and writes `dist/core.pack.json`.
3. `cargo xtask pack sign --key ~/.exposure/keys/exposure-pack-1.key` writes
   the signature. Only the holder of the secret key can do this step.
4. `EXPOSURE_BLESS=1 cargo test -p exposure` refreshes the committed fixture
   report, which names the pack's hash.
5. Commit the sources, both files in `dist/` and the fixture report together.
   CI runs `cargo xtask pack check`, which fails if the three disagree.

Raise `version` in `core/pack.toml` whenever the compiled bytes change.

## What the compiler refuses

These lints exist because of failures seen on real apps (design report,
section 5.2).

- A content token (`content_literal`, `dex_string`, `macho_token`) under
  eight bytes. Short literals hit by coincidence. Only `dex_string` allows
  the `exact` boundary, and a `dex_string` token that uses it may be
  shorter.
- A content token that is a bare registrable domain, such as
  `doubleclick.net` or `googleapis.com`. Embedded browser engines contain
  such names, so they would tie every app that embeds one to that company.
  Name a specific endpoint instead.
- A content token without a stated boundary.
- A token claimed by two rules for the same matcher.
- A rule or an entity without an `https://` source.
- A rule that neither names an `entity` nor sets `component = true`.

A rule may pin real artifacts in `[[fixture]]` tables (`sha256`, `url`,
`expect`). The table is parsed and checked today, and a rule without one is
accepted; pinning a fixture becomes a requirement when the fixture corpus
lands (build plan, task 13).

## Where the data may come from

Endpoints, class names and package names are facts; take them from the SDK's
source and the vendor's documentation and cite the page. Do not copy entries
from DuckDuckGo Tracker Radar, Ghostery TrackerDB, Disconnect, the IAB Europe
vendor list or F-Droid's `suss.json`: their licences do not allow it.

## The signing key

The scanner accepts a pack only if a key compiled into it signed the exact
bytes. The secret half of `exposure-pack-1` is not in this repository and
must never be. `cargo xtask key generate --dir <dir>` creates a new pair and
refuses a directory inside the repository.
