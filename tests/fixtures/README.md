# Test fixtures

Nothing here is a real program. Real artifacts are never stored in this
repository; the ones tests need are described under "Real apps" below.

## `macos/Skeleton.app`

A synthetic macOS application bundle, the fixture of the walking skeleton
(build plan, task 4): scanning it must yield exactly one claim, Sentry, from
the folder name `Contents/Frameworks/Sentry.framework`.

The two "binaries" are the 32-byte header of a 64-bit Mach-O file that has no
load commands, followed by a line of text. That is a well-formed file to the
collector, which classifies it, reads its (empty) load commands and hashes
it. The framework uses the symbolic links Xcode creates, so the fixture also
exercises the rule that links are never followed.

Mach-O files with content, such as class names, linked libraries, a code
signature or an encrypted part, are not stored either: tests build them in
memory with `xs_formats::macho_build`.

`macos/Skeleton.report.json` is the report a scan of it must reproduce byte
for byte.

## `macos/ElectronSkeleton.app`

A synthetic Electron app, the fixture of the Electron collector (build plan,
task 7). Its `Contents/Resources/app.asar` was written by the real packer,
not by this code base, so that the reader is tested against what the tool
actually produces:

```console
$ npx @electron/asar@4.3.2 pack app app.asar --unpack "*.node"
```

The archive holds:

| Path in the archive | What it is there for |
|---|---|
| `main.js` | The app's own script, with the two literals a bundler leaves of the Sentry and PostHog browser SDKs. Both must be found, as `app_code` |
| `main.js.map` | A source map that names both SDKs. Not searched |
| `renderer/index.html`, `renderer/app.js` | The app's own page and script, with nothing in them. The script is searched, the page is not |
| `node_modules/@sentry/electron/` | An installed package: found by name in the file table, and by the literal in its script, as `dependency` |
| `node_modules/lunr/index.html` | The demo page of a library, with a PostHog host in it. Not searched: only scripts are |
| `node_modules/keytar/build/Release/keytar.node` | Listed as unpacked; the file is in `app.asar.unpacked` beside the archive |

Scanning it must yield two claims: Sentry with two kinds of witness, and
PostHog with one. `macos/ElectronSkeleton.report.json` is the report a scan
must reproduce byte for byte.

## `android/Skeleton.apk`

A synthetic Android package, 1.8 kB, and the fixture of the Android
collector (build plan, task 8). Scanning it must yield exactly two claims, Sentry and PostHog, each from two kinds of
witness: `android/Skeleton.report.json` is the report, byte for byte. The
package holds decoys that must find nothing: the server-side PostHog SDK, a
host name that continues past a rule's token, an ad host no rule names, and
a resource that mentions Crashlytics. Its DEX files define classes and hold
strings and no code. The file is written by `fixture()` in
`crates/xs-cli/tests/android.rs`, and a test fails if the two disagree;
`EXPOSURE_BLESS=1 cargo test -p exposure` regenerates it and the committed
reports.

## `browser/`

Synthetic browser extensions, the fixture of the extension collector. Each
manifest is written to show one rule of the collector:

| Path | What it is there for |
|---|---|
| `Extensions/abcdefghijklmnopabcdefghijklmnop/2.1.0_0/` | A Chromium extension as a profile stores it. Its manifest has a comment, a name that is a reference into `_locales/en/messages.json`, `<all_urls>` under `host_permissions`, `tabs` and `cookies`, an optional `clipboardRead`, and a script for every `https` and `http` page. `background.js` and `content.js` hold a URL and are never read |
| `Extensions/ponmlkjihgfedcbaponmlkjihgfedcba/1.0_0/` | A Chromium extension that asks for nothing broad: named sites, interface names that are not on the list, and a style sheet for every page. It has an `artifact` record and no claim |
| `addon@example.org.xpi` | A Firefox add-on with a version 2 manifest: site patterns among its `permissions`, its publisher under `developer`, and an optional pattern for every `.com` site that is not reported next to the `<all_urls>` it holds. The file is written by `addon()` in `crates/xs-cli/tests/browser.rs`, and a test fails if the two disagree |

Scanning `Extensions` and the add-on must yield nine claims, every one an
`access` claim at `requested` that names no company:
`browser/Extensions.report.json` is the report, byte for byte.
`EXPOSURE_BLESS=1 cargo test -p exposure` regenerates the add-on and the
report.

## Real apps

Real apps are pinned here by URL and SHA-256 and read from a cache folder
outside the repository, named by `EXPOSURE_FIXTURE_CACHE`. The apps are only
read; nothing in the cache is ever executed. Fetching the whole fixture
corpus in CI is build plan task 13.

### Electron apps

The Electron collector is measured on three real apps (project spec, spike
results). The tests in `crates/xs-cli/tests/electron.rs` that need them are
skipped when the variable is not set, and fail when it is set and an app is
missing.

| App | Download | SHA-256 of the download | Place in the cache |
|---|---|---|---|
| Logseq 2.0.2, macOS arm64 | `https://github.com/logseq/logseq/releases/download/2.0.2/Logseq-darwin-arm64-2.0.2.zip` | `ffd6e086ba6f68a4748f80eaa8b38244a9cf78b05c076343d75e0230fe9440b4` | `logseq-2.0.2/Logseq.app` |
| Bitwarden desktop 2026.10.4, macOS universal | `https://github.com/bitwarden/clients/releases/download/desktop-v2026.10.4/Bitwarden-2026.10.4-universal-mac.zip` | `61ebef7a7cb75ed4e8facbe185ea23f94cc17f8d850177099a693b1578112d0a` | `bitwarden-desktop-2026.10.4/Bitwarden.app` |
| Obsidian 1.15.1, macOS | `https://github.com/obsidianmd/obsidian-releases/releases/download/v1.15.1/Obsidian-1.15.1.dmg` | `e05c7e3e2262b14c965bb246dcb74a30fc9098bd669e42957c4d9f788d04fdf4` | `obsidian-1.15.1/Obsidian.app` |

Check each download against its hash, then unpack it: `ditto -x -k` for a
zip, and for the disk image attach it read-only and copy the app out. The
scanner only reads the apps; nothing in them is run.

| App | Must report | Why |
|---|---|---|
| Logseq | Sentry and PostHog, both from `js/main.js` in `app.asar`, as `app_code` | Its `package.json` lists `@sentry/react` and `posthog-js`; both are bundled, and neither is among the 280 packages the archive lists |
| Bitwarden desktop | Nothing | No analytics package among its packages. The archive does hold an analytics snippet, in `node_modules/lunr/index.html`, the demo page of a search library |
| Obsidian | Nothing | Negative control. It ships two archives, `app.asar` and `obsidian.asar` |

### macOS apps

`crates/xs-cli/tests/real_apps.rs` checks the macOS collector against three
of the apps in the spec's spike table. It runs only when
`EXPOSURE_FIXTURE_CACHE` names the cache folder, and passes without doing
anything otherwise. The test checks both hashes below before it scans.

| Folder in the cache | Archive | SHA-256 of the archive |
|---|---|---|
| `alttab-11.10.2/` | <https://github.com/lwouis/alt-tab-macos/releases/download/v11.10.2/AltTab-11.10.2.zip> | `5a2a821a83be1092df0f63d2403359ef2f7d52ad39cec36d930e4c7554cc045b` |
| `netnewswire-7.2.1/` | <https://github.com/Ranchero-Software/NetNewsWire/releases/download/mac-7.2.1/NetNewsWire7.2.1.zip> | `9459896e516ac6c34685b38111dc456a3d1a4e49c964e40bc8f8af8fdc3b17db` |
| `maccy-2.8.0/` | <https://github.com/p0deje/Maccy/releases/download/2.8.0/Maccy.app.zip> | `e684e1ce0c60d7cffd3a2b182dc37bd7e88c29967a64a431a2c71be65b1d27e0` |

Each folder holds the archive as downloaded and, in `app/`, the bundle
unpacked from it:

```console
$ cache=~/Library/Caches/exposure-fixtures
$ mkdir -p "$cache/alttab-11.10.2" && cd "$cache/alttab-11.10.2"
$ curl --fail --location --remote-name https://github.com/lwouis/alt-tab-macos/releases/download/v11.10.2/AltTab-11.10.2.zip
$ shasum -a 256 AltTab-11.10.2.zip          # compare with the table
$ unzip -q AltTab-11.10.2.zip -d app        # gives app/AltTab.app
$ EXPOSURE_FIXTURE_CACHE="$cache" cargo test --package exposure --test real_apps
```

### Android packages

The Android collector is measured on real packages too. `real-apps.txt` pins
them by SHA-256 and download address. `cargo xtask fixtures fetch --dir DIR`
downloads them into a folder outside the repository and refuses a file
whose hash is not the pinned one, and tests that scan them run when
`EXPOSURE_FIXTURE_CACHE` names that folder. CI does both, for
`crates/xs-cli/tests/android_real_apps.rs` alone: the macOS apps above are
not fetched there.
