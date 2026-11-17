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
| `core/entities.toml` | Companies, each with its sources and the identifiers of its own apps and hosts | CC BY 4.0 |
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

## Companies

`core/entities.toml` holds one entry per company. It is the project's own
map: every entry is written from the company's own pages and cites them.

| Field | What |
|---|---|
| `id`, `name`, `website` | The id rules refer to, the legal name, the company's site |
| `parent` | The id of the company that owns this one. A claim names the company at the top of the chain |
| `team_ids` | Apple Team IDs the company signs its apps with |
| `app_ids` | App ids of the company's apps, in lowercase. An entry covers the app ids below it: `com.example` covers `com.example.Mail` and not `com.examples` |
| `domains` | Domains the company operates. An entry covers the hosts below it, and the longest entry wins |
| `sources` | `https://` pages that show the facts above: the legal entity, and each identifier or owner the first page does not show |

The three lists of identifiers are what makes a channel first party. Who
publishes an app is decided by its Team ID first and its app id second; whose
a host is, by its domain. An identifier names one entity, so the compiler
refuses one that is listed twice. Only companies that own an SDK can be
first party to one, so only those companies need identifiers.

- List a Team ID only from a page of the company that states it.
- An app id entry is the company's own domain read backwards, or an app id
  the company documents. Do not list a name that unrelated developers use,
  such as `com.github`: an app id is only looked up in this list, never
  matched against `domains`.
- A domain that holds what a company's users publish, such as `github.io`,
  is listed for the company that operates the hosts.
- A host under no listed domain is reported as unmapped. That is the right
  answer for a host nobody has sourced: do not add a domain to make a report
  look complete.

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
two categories are for declared hosts; a rule does not use them. Neither
counts in a report's headline: a declared tracking domain counts through the
rule that names it, under that rule's category. The claim names the company
`entities.toml` lists the host's domain for, and no company otherwise. The update
feed is reported only that way: `update_feed` is the kind of that proof, not a
matcher a rule may list, and the compiler refuses a rule that does.

## What the Android matchers look at

Each matcher is given the values of one table of an `.apk` file, and a
token is compared with one value at a time.

| Matcher | A value is | Write a token as |
|---|---|---|
| `manifest_component` | The `android:name` of an `activity`, `activity-alias`, `service`, `receiver` or `provider` directly inside `<application>`, as a fully qualified class name; or the `android:name` of a `meta-data` entry, as written | `io.sentry.android.core.SentryInitProvider`, or the `meta-data` key `com.google.firebase.components:<Registrar class>` |
| `android_class_prefix` | The name of a class that a `classes*.dex` file defines, with dots: `com.example.Outer$Inner`. A class the app only refers to is not a value | A package with its trailing dot: `io.sentry.` |
| `dex_string` | One string constant of a `classes*.dex` file | An endpoint host with the `host` boundary |
| `apk_file` | The full name of one entry of the archive | The whole name, one token for each place it can be: `billing.properties`, `lib/arm64-v8a/libsentry.so` |

## Choosing tokens

A token has to be something only the SDK puts in an app. These are the
mistakes made while the pack was written, each found on a real app.

- **A Swift class** is listed in `__objc_classname` under its mangled name:
  `_TtC`, the length of the module name, the module name, then the class,
  as in `_TtC7PostHog12BundleFinder`. A `prefix` token `_TtC7PostHog` finds
  every class of the module. Use it only when the module name is the
  vendor's own: Dia names a module of its own `TelemetryClient`, the name of
  an older TelemetryDeck module, and `Segment` is a word any app may use.
  The same holds for a framework folder name.
- **An endpoint that is a bare registrable domain** is refused by the
  compiler. Write it with the path of the API below it and the `word`
  boundary, as Statsig's rule does with `featureassets.org/v1`.
- **The hosts of an ad network** are data in apps that block or skip ads:
  NewPipe, which shows no ads, holds `googleads.g.doubleclick.net` among its
  DEX strings. Prefer the table witnesses (manifest entries, classes, file
  names), and ask for two different endpoint strings with `min_distinct`.
- **A name an app writes into its own code for the SDK** is not a token.
  Apps label their pages with `data-dd-action-name` for Datadog's SDK
  whether or not they ship it; the SDK's own name for itself,
  `browser-rum-sdk`, is the token.
- **A short storage key** proves little alone. Countly's rule asks for both
  of its keys in one file.

The table test in `crates/xs-cli/tests/rule_pack.rs` hands every token to the
engine in the shape its matcher reads and requires it to find its own rule
and no other; the look-alikes above are kept there as tests.

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
- An entity's domain that is a suffix registries operate, such as `co.uk`,
  or that is under no public suffix at all. An app id entry that, read
  backwards, is not at least a registrable domain: `uk.co` would cover every
  app of every company under `co.uk`.
- A Team ID that is not ten uppercase letters and digits, and any Team ID,
  app id or domain that is listed twice.
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
