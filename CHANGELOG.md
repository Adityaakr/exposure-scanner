# Changelog

All notable changes to `exposure` are listed here. The project follows
[Semantic Versioning](https://semver.org); while the version is 0.x, a minor
version can change commands, the report format or the evidence format.

## 0.2.0 (2026-11-22)

Source only, as before; there are no prebuilt binaries. Install with
Homebrew, or with
`cargo install --git https://github.com/Adityaakr/exposure-scanner --locked --tag v0.2.0 exposure`.

### Added

- **Homebrew**: `brew tap Adityaakr/exposure-scanner https://github.com/Adityaakr/exposure-scanner`
  and `brew install adityaakr/exposure-scanner/exposure`. The repository is
  its own tap (`Formula/exposure.rb`), and the formula builds the latest
  release tag from source with `cargo install --locked`; `brew install
  --HEAD` builds `main`.
- **`--fail-on CONDITION`** for `scan` and `report`: exit status 3 when a
  finding counts in the headline (`headline`), is in a category
  (`category:analytics`) or names a company (`company:google`), after the
  reports are written. A condition the rule pack does not know is refused
  before anything is read. `exposure rules show` now lists the category and
  company ids.
- **`exposure diff OLD NEW`**: which findings a report adds, no longer has, or
  has at another grade, app by app, following an app by its platform and app
  id and a finding by its claim key. `--json FILE` writes the comparison as an
  `exposure-diff/1` document, and `--fail-on` checks the findings that newly
  meet a condition: those added, and those that meet it in NEW but did not in
  OLD.
- **Android app bundles (`.aab`)**: scanned like the APKs they stand for,
  with their protocol buffer manifest and resource table and the code of
  every module. The layout comes from the archive's directory, never from the
  file name.
- **Android app names**: the label an app's manifest points at is looked up
  in the resource table (`resources.arsc`, or `resources.pb` in a bundle), in
  its default configuration, so the report shows "Bitwarden" rather than
  `com.x8bit.bitwarden`.
- **Beside the headline, for Android**: the SDKs of companies in categories
  the headline does not count, such as the five Google SDKs of Bitwarden's
  Play build, in the terminal summary and the HTML report, so a scan whose
  counts are zero does not read as "nothing found".
- Fuzz targets for the resource table and the app bundle readers, and for
  the readers a macOS app reaches first: Mach-O, code signatures, property
  lists and asar archives.
- **A hostile-folder memory gate** in `cargo xtask bench`, on a folder of
  crafted packages that inflate to gigabytes, and a second one on the same
  packages with DEX files of zeros, which hold nothing to read: under 150 MB
  at one thread per core.
- **`cargo xtask difftest`**: builds a base commit (by default
  `origin/main`) and the working tree, scans the committed fixtures, a corpus
  it writes from the rule pack's own tokens (bundles with files on both sides
  of every read size, damaged and hostile packages) and any path given with
  both, and fails unless every report of the new build is the base build's,
  byte for byte: without the cache, on one thread, and with the cache empty
  and full. CI runs it on every change against the commit the change goes
  onto, with the pinned real apps and the negative-control apps, and on
  macOS. A change meant to change what is reported passes `--expect-changes`.

### Changed

- **The HTML report leads with what needs your attention**: how much was
  found, then the first entries of "What you can do" of high and medium
  priority, each in one sentence with its first step and a link to every
  step. The first step is one you can take: an app's own setting, then a
  block list, and only then what a publisher says cannot be done. The
  headline counts and the list of everything found are under it, opened on
  demand, as are the facts, steps and records of each finding, the
  lower-priority entries of the checklist, long block lists, the glossary and
  the coverage tables. They are `details` elements: no script, the content
  is in the file whether open or not, and printing opens them in browsers
  that support the `::details-content` pseudo-element (current Chrome, Edge,
  Safari and Firefox); an older browser prints them closed. No link leads
  into one that is closed. "What you can do" stands out as a panel of its
  own. The terminal summary of `exposure scan` prints the same entries
  before the headline counts. The JSON report is unchanged.
- **Electron's default usage descriptions rank low** in the "What you can do"
  checklist. A System Settings entry that rests only on "This app needs access
  to the camera" and Electron's other default wording is `Low`, and an entry
  that rests on it in part says how many of its apps state only that.
- The README no longer says the repository is private.
- **The attention entries say when a finding rests on text alone**: "Found as
  text in the app's code (one kind of evidence), not as a name read from a
  table the app declares", on the page and in the terminal, naming the apps it
  holds for when it does not hold for all of them. An advertising or analytics
  entry that rests only on text inside a library the app ships, in every app,
  ranks `Medium` instead of `High`.
- **Clearer coverage notes**: a main executable `Info.plist` names that is not
  there as a file is `missing`, no longer `unsupported_format`, and V8
  bytecode files are `compiled_script`, counted in files, with what not
  searching them means.
- **Android packages are read the way Android reads them**: the "encrypted"
  flag is ignored, and the manifest and resource table are read as stored
  under any compression method but DEFLATE, so a package that hides its
  manifest or code that way is no longer reported as `unidentified.apk`.
- **Memory is bounded by the scan's threads**, not by the packages it reads:
  a folder of small crafted packages that inflate to gigabytes no longer
  takes a scan's memory to gigabytes on macOS. See
  [the architecture](docs/architecture.md#performance).
- **A report is never written through a link**: a report file named by a
  symbolic link that does not lead to a device or stream, such as
  `/dev/stdout`, is refused, and a report is written beside its name and
  renamed into place, so a scan that stops leaves no half of a report. See
  [the threat model](docs/threat-model.md).
- Rule pack version 8.
- **Faster scans, with the same reports**, measured on an Apple M5 against
  the build before, on the same day and apps. The 16 installed apps and 8
  extensions (6.85 GB): 7.32 s on one thread against 9.04 s, 1.63 s on eight
  against 1.96 s, and 1.63 s for the first scan against 2.10 s. Electron
  apps, whose scripts are searched, gain most: three of them in 0.41 s
  against 0.70 s. The search is built as a DFA instead of a contiguous NFA,
  so it costs less than half as much. Files are started truly largest
  first. Small files are read on at most four threads at once on macOS,
  where more threads make them slower: a folder of 102,161 files, all but
  80 of them small, reads in 1.1 s on four threads against 2.2 to 2.5 s on
  ten, which spend several times the system time. They are read beside the
  large files rather than after them. A script costs one read call fewer,
  and a file one size query fewer. See
  [the architecture](docs/architecture.md#scheduling).
- **Less memory for Android packages**: a DEX file whose header alone
  decides what it holds, such as one of zeros made to inflate to 255 MiB,
  is checked to the end of its stream in a window of memory instead of
  inflated whole (24 such packages: 22 MB at ten threads against 1,091 MB),
  and a resource table that comes after its manifest is not kept for the
  app's name: 30 real packages take 228 MB at ten threads against 264 MB,
  and 27 MB at one against 35 MB.

### Fixed

- **Google Mobile Ads (AdMob) was reported for apps that only use Firebase
  Analytics.** The rule matched the whole `com.google.android.gms.ads.`
  package, which also holds `play-services-ads-identifier`, the advertising-ID
  library Firebase Analytics and many attribution SDKs depend on. It now names
  classes of the ads SDK itself (`AdRequest`, `AdView`, `MobileAds`,
  `admanager.`, `com.google.android.gms.internal.ads.`), besides its manifest
  entries and property files.
- **An app could hide its trackers by naming itself after a company.** An app
  id is now believed only for a macOS app and a company that lists no Team
  ID: an Android package called `com.google.*`, or a Mac app with Google's or
  Microsoft's app id and without their Team ID, has no known publisher. Its
  findings carry the note `claims-vendor:<company>`, the report says the app
  only claims the company, and its channels still count in the headline and
  in what needs attention.
- **Removing a browser extension now comes with a warning**: every "remove
  it" step adds that removing an extension deletes what it keeps in the
  browser, so for a wallet or a password manager the recovery phrase or an
  export comes first.
- **A browser the scan could not read is said where you look**: "Not checked:
  Google Chrome's extensions", with the Full Disk Access step and a note to
  turn it off again, at the top of the page, in the summary `exposure scan`
  prints and on standard error. Where the scan looked no longer names a
  browser none of whose extensions could be read.
- **App names keep their letters**: a left-to-right or right-to-left mark in a
  name, as WhatsApp's starts with, is dropped instead of shown as U+FFFD. The
  controls that can reorder text still are.

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
