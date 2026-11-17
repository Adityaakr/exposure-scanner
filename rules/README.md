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
   reports, which name the pack's hash.
5. Commit the sources, both files in `dist/` and the fixture reports together.
   CI runs `cargo xtask pack check`, which fails if the three disagree.

Raise `version` in `core/pack.toml` whenever the compiled bytes change.

## Boundaries

A token is a literal plus one boundary, which says how the literal must sit
in its surroundings to count. Matching looks at bytes and is case-sensitive.
The start and the end of a value or a file count as boundaries.

| Boundary | The token hits when |
|---|---|
| `exact` | the value equals the literal |
| `prefix` | the value starts with the literal |
| `word` | the byte before and the byte after are not an ASCII letter, digit or underscore. `sentry.javascript.` hits in `"sentry.javascript."` and in `sentry.javascript.${name}`, and not in `sentry.javascript.browser` |
| `host` | the literal is a whole hostname or the parent of one. The byte before is a dot or not a hostname byte (ASCII letter, digit, hyphen, underscore); after it the name ends, so no hostname byte follows, and no dot that a hostname byte follows. `i.posthog.com` hits in `us.i.posthog.com` and `i.posthog.com.`, and not in `xi.posthog.com` or `i.posthog.com.evil.example` |
| `none` | the literal occurs anywhere |

`exact` and `prefix` are about a whole value, such as a class name or a
folder name. The other three are searched for inside a value or in the bytes
of a file. Write a `host` token so that it starts and ends with a letter or a
digit: one that starts or ends with a dot cannot sit on a hostname boundary.

`min_distinct = { macho_token = 2 }` in a `[match]` table says that at least
two different `macho_token` tokens of the rule must hit in one file before
any of them counts.

## What the macOS matchers are given

A token is matched against values the collector takes from a bundle. Write
the token as that value is stored:

| Matcher | The value | Example token |
|---|---|---|
| `apple_framework` | The name of a folder directly under `Contents/Frameworks` | `Sentry.framework` |
| `macho_dylib` | One path component of the install name of a library a Mach-O file links. A token therefore names the framework folder or the library file, not where it is installed: `Sentry.framework` hits `@rpath/Sentry.framework/Versions/A/Sentry`. The proof shows the whole install name when it is relative to the bundle (`@rpath/`, `@executable_path/`, `@loader_path/`), and otherwise only the part from the matched component on, so no path of the machine that built the binary is stored | `Sentry.framework` |
| `macho_objc_class` | One name of the `__objc_classname` section: an Objective-C class, category or protocol the file defines. Swift classes are not listed there under their plain names | `MSACAppCenter` |
| `macho_token` | Searched for in the bytes of a Mach-O file outside its sections of instructions and outside an encrypted part. Not searched for in a runtime, such as a browser engine | `{ lit = "…", at = "host" }` |
| `content_literal` | Besides script files: searched for in a section that holds script text, such as `__BUN,__bun` | `{ lit = "sentry.javascript.", at = "word" }` |
| `privacy_manifest` | A host listed under `NSPrivacyTrackingDomains` in a `PrivacyInfo.xcprivacy` file, in lowercase, without scheme, port or trailing dot | `{ lit = "i.posthog.com", at = "host" }` |

A `privacy_manifest` hit is a declaration: it is graded `declares`, not
`contains`. An entry written as an address rather than a bare domain is not
matched; it is reported as not understood.

Every declared host is also reported as itself, with or without a rule: a
tracking domain under the category `tracking_domain`, and the host of the
update feed (`SUFeedURL` in `Contents/Info.plist`) under `update_feed`. Those
two categories are for declared hosts; a rule does not use them. The update
feed is reported only that way: `update_feed` is the kind of that proof, not a
matcher a rule may list, and the compiler refuses a rule that does.

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
