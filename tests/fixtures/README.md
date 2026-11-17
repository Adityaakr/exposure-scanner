# Test fixtures

Nothing here is a real program. Real artifacts are never stored in this
repository; the ones tests need are described under "Real apps" below.

## `macos/Skeleton.app`

A synthetic macOS application bundle, the fixture of the walking skeleton
(build plan, task 4): scanning it must yield exactly one claim, Sentry, from
the folder name `Contents/Frameworks/Sentry.framework`.

The two "binaries" are a Mach-O magic number followed by a line of text,
which is all the collector needs to classify and hash them. The framework
uses the symbolic links Xcode creates, so the fixture also exercises the rule
that links are never followed.

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
| `renderer/index.html`, `renderer/app.js` | The app's own page and script, with nothing in them |
| `node_modules/@sentry/electron/` | An installed package: found by name in the file table, and by the literal in its script, as `dependency` |
| `node_modules/lunr/index.html` | The demo page of a library, with a PostHog host in it. Not searched: dependencies count for scripts only |
| `node_modules/keytar/build/Release/keytar.node` | Listed as unpacked; the file is in `app.asar.unpacked` beside the archive |

Scanning it must yield two claims: Sentry with two kinds of witness, and
PostHog with one. `macos/ElectronSkeleton.report.json` is the report a scan
must reproduce byte for byte.

## Real apps

The Electron collector is measured on three real apps (project spec, spike
results). They are pinned here by URL and SHA-256 and read from a folder
outside the repository, named by `EXPOSURE_FIXTURE_CACHE`. The tests in
`crates/xs-cli/tests/electron.rs` that need them are skipped when that
variable is not set, and fail when it is set and an app is missing.

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
