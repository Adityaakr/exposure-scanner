# exposure-scanner

A local command-line scanner that answers one question with proof: which
companies have a channel to your data, through which apps.

`exposure` reads files that are already on your disk, recognises third-party
SDKs by literal markers, maps each one to the company behind it, and writes a
report in which every statement links to a record you can re-check by hand.
It never observes behaviour, changes no app, executes nothing and sends
nothing anywhere. All it writes is the report, and a private cache of what
it found, so that the next scan reads only the apps that changed.

## Status

Milestone 1 ("static truth") is in progress. This repository currently holds
the foundation, the macOS, Electron, Android and browser extension
collectors, the resolver, the scan scheduler and the results cache:

| Part | State |
|---|---|
| Evidence format v1, canonical JSON, record ids, evidence set | Done |
| Rule pack: source format, compiler and lints, signature check, built-in signed pack, 48 rules (below) | Done |
| `exposure scan` on a macOS app bundle, through derivation, to a JSON report | Done |
| Match engine: literal search with boundary rules, exact and prefix tables, and the controls against false positives | Done |
| macOS collector: Mach-O load commands, Objective-C class names, data and embedded-script sections, Team ID, privacy manifests, update feed | Done (below) |
| Electron apps: npm packages listed in an asar archive or in the `Contents/Resources/app` folder, literals in the app's scripts, scope labels, breadth guard | Done |
| `exposure scan` on an Android package (`.apk`) | Done, with four witnesses: manifest components, classes defined in the DEX files, DEX string constants, and entry names |
| Resolver: the company behind an SDK or a host, the app's vendor by Team ID then app id, first or third party, headline counts | Done (below) |
| Scan scheduler: finding the installed apps, and bundles and packages in a folder; one queue of files for the whole scan, largest first; an app that cannot be read is reported and does not stop the scan | Done (below) |
| What each app may access: usage descriptions and entitlements of a macOS bundle, `uses-permission` of an Android manifest, as access claims graded `requested` | Done (below) |
| Results cache: an app that has not changed since an earlier scan is not read again; private, deletable, off with `--no-cache`; the report is the same with it and without | Done (below) |
| Automatic eviction of removed apps from the results cache | Not yet (follow-up); until then, delete the cache folder |
| Browser extensions: the extensions in your profiles of Chromium-family browsers and Firefox, and what each manifest asks the browser for | Done (below) |
| HTML report | Not yet (build plan tasks 11, 13 and 14) |

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
| Code signature of the main executable | (a fact, not a witness) | The Apple Team ID the signature names, and whether the app asks for the App Sandbox. Both are read, not verified |
| `*UsageDescription` keys of `Contents/Info.plist` | `usage_description` | A permission the app asks for, with the purpose it states (an access edge, below) |
| Entitlements in the code signature of the main executable | `entitlement` | A permission the app asks for (an access edge, below) |

A declared address is cut down to its host; no URL is stored. A host is shown
as itself, under the company the rule pack lists its domain for, or as
unmapped (below). An encrypted binary, such as an iOS app installed on a
Mac, is reported as a coverage note and its ciphertext is not searched.

An Electron app is a macOS bundle too, so all of the above applies to it.
Its scripts are read as well: an SDK is found when it is installed as an npm
package, or bundled into the app's own code.

So today a scan covers macOS bundles, Electron apps among them, Android
packages and browser extensions. It looks for the SDKs the built-in pack has
rules for, and for nothing else. A clean report from this build does not mean
an app is clean.

### What the built-in pack recognises

| Category | SDKs |
|---|---|
| Analytics | Google Analytics (Firebase), Mixpanel, Amplitude, Twilio Segment, PostHog, Heap, Datadog RUM, New Relic, Microsoft App Center Analytics, Countly, TelemetryDeck, Aptabase, Statsig, Facebook SDK (app events) |
| Advertising | Google Mobile Ads (AdMob), Meta Audience Network, AppLovin MAX, Unity Ads, Unity LevelPlay (ironSource) |
| Attribution | AppsFlyer, Adjust, Branch, Kochava, Singular |
| Profiling | Braze, Customer.io |
| Session replay | LogRocket, Fullstory, Hotjar, Smartlook, UXCam |
| Crash reporting | Sentry, Bugsnag, Firebase Crashlytics, Rollbar, Raygun, App Center Crashes |
| Customer messaging | Intercom, OneSignal |
| Other, not counted | Firebase Cloud Messaging, Firebase Installations, Google DataTransport, Google Play Billing, App Center |
| Components (no company) | Sparkle, Squirrel, electron-updater, PLCrashReporter |

Each rule looks for an SDK in every place it can leave a mark, as far as the
SDK exists for that platform: its Android manifest entries, classes and
endpoint strings; its npm package and the literals that survive bundling;
its framework folder, Objective-C or Swift class names and endpoint strings
in a Mac binary; the tracking domains its privacy manifest declares. Every
token is taken from the SDK as its vendor publishes it, and the source is
cited in the rule (`rules/core/sdk/`).

Measured on the three Electron apps the collector is tested against: Logseq
2.0.2 reports Sentry and PostHog, both from `js/main.js` inside its archive
and neither among the 280 npm packages the archive lists. Bitwarden desktop
2026.10.4 and Obsidian 1.15.1 name no company. What they report is the
updaters they ship, which are components: Squirrel, which is part of
Electron on macOS and so in every Electron app, and in Bitwarden also
electron-updater.

### Whose it is, and what counts

Every SDK and every host resolves to one company or to none, and every app
to one vendor or to none. A channel is first party when the two are the
same.

| Question | How it is answered |
|---|---|
| Who is behind an SDK? | The rule names the entity that operates it; the claim names the company at the top of that entity's ownership chain. A library with no network side of its own, such as an updater, is a component and names no company. |
| Who is behind a host? | The company whose listed domain the host is under. A host under no listed domain is **unmapped**: it is shown as itself, nobody is named as its owner, and it is counted nowhere. There is no generic table of host owners. |
| Who publishes the app? | First the Apple Team ID its code signature names, then its app id, each looked up among the identifiers the rule pack lists per company. Reversing an app id proves nothing about ownership, so an app id is not believed against a signature: an app that calls itself `com.microsoft.x` and is signed by a team the pack does not list for Microsoft has no known vendor. |
| First or third party? | `first` when a listed identifier says the app is the company's own, or when a host that belongs to no listed company is under the domain the app id spells (`ranchero.com` for `com.ranchero.NetNewsWire-Evergreen`). `third` when the app belongs to another listed company or to nobody the pack lists. `unknown` otherwise: no company is named, or nothing identifies the vendor. |

Only companies that own an SDK can be first party to one, so the pack lists
identifiers for those companies and no others. Each claim carries a `vendor`
block that says what the party rests on, and a vendor known by its signature
cites the record that holds the Team ID.

The headline is three counts, and there is no score:

| Count | What is counted |
|---|---|
| `companies_contacts` | Companies with a channel at `contacts` or above. Always 0 for now: nothing in this build observes a connection. |
| `companies_contains` | Companies whose strongest channel is `contains`. |
| `apps_third_party` | Apps with at least one third-party channel. |

Only claims in the categories advertising, analytics, attribution, profiling
and session replay are counted, and only when they name a company. Hosting is
not receiving: crash reporting, push delivery, payments, an update feed and a
declared tracking domain that no rule names are in the report and in none of
the three numbers. Customer messaging (Intercom, OneSignal) is in
the report under its company and is not counted either: the five counted
categories are a fixed list (design report, section 3, A7). Braze and
Customer.io track what the user does and so are counted, under profiling.
Each claim says whether it counts, in `headline`, so the numbers can be
recounted from the claims.

Measured on the real apps the macOS collector is tested against:
NetNewsWire 7.2.1's update feed, on `ranchero.com`, is first party. Maccy
2.8.0's, on `raw.githubusercontent.com`, is GitHub's and so Microsoft's: a
third party, and not counted. App Center in AltTab 11.10.2 is a third party
to it, in categories that are not counted. PostHog in Logseq 2.0.2 is
analytics, and is counted: one company at `contains`, one app with a
third-party channel.

## Use

Requires the Rust toolchain pinned in `rust-toolchain.toml` (rustup installs
it on first use).

```console
$ cargo build --release --package exposure
$ target/release/exposure scan tests/fixtures/macos/Skeleton.app --json report.json
exposure: scanned 1 app (3 files, 676 bytes): 1 claim, 0 coverage notes
exposure: headline: 0 companies at contacts or above, 0 companies at contains, 0 apps with a third-party channel
exposure: scope: the paths given and nothing else; the installed-app folders were not searched
exposure: cache: 0 apps unchanged since an earlier scan and not read again, 1 app read
```

To install the binary instead of running it from the build folder:

```console
$ cargo install --git https://github.com/Adityaakr/exposure-scanner --locked exposure
```

```
exposure scan [PATH...] [--json FILE] [--threads N]   scan .app bundles, .apk files, extensions, or folders of them
              [--no-cache]                            without the cache
exposure report FILE [--json FILE]                    derive the report again from saved evidence
exposure rules show                                   list the built-in rule pack
exposure rules verify PACK --sig SIGNATURE            check a signed pack file offline
```

Without `--json` the report goes to standard output. A report file is
created readable by its owner only, because the list of apps a person uses is
sensitive in itself.

### What is scanned

A `PATH` is a macOS `.app` bundle, an Android `.apk` file, a browser
extension (a Firefox `.xpi` file, or a Chromium `<id>/<version>` folder that
holds a `manifest.json`), or a folder. A folder is searched for all of them,
in itself and in its sub-folders, never inside a bundle. An app reached two
ways, such as directly and through a symbolic link, is scanned once.

Without a `PATH`, on macOS, the installed apps are scanned: those in
`/Applications` and in your own `~/Applications`. So are the extensions in
your own profiles of the browsers below ("Browser extensions"). On another
system there is no folder this build knows to look in, and a scan without a
`PATH` says so.

A `PATH` replaces the installed-app folders, it is not added to them: when
any `PATH` is given, only what the `PATH`s name is scanned.

Apple's own apps on the sealed system volume, in `/System/Applications`, are
a documented omission: name that folder to scan it. Every scan without a
`PATH` states the omission in its scope line, the last line of the summary on
standard error. It is not a coverage record, which differs from the design
report (section 4.8), which asked for one: a coverage record needs an app as
its subject, and a folder is not one. The scope line is fixed text. It is
not part of the JSON report, and it never holds a path you gave.

```console
$ target/release/exposure scan --json report.json
exposure: scanned 16 apps and 8 browser extensions (11669 files, 6813657279 bytes): 136 claims, 4 coverage notes
exposure: headline: 0 companies at contacts or above, 0 companies at contains, 0 apps with a third-party channel
exposure: scope: the apps installed in /Applications and ~/Applications; /System/Applications (Apple's own apps on the sealed system volume) was not searched: name the folder to scan it; the extensions installed in your profiles of Arc, Brave, Google Chrome, Chromium, Dia, Microsoft Edge, Firefox and Vivaldi
exposure: cache: 16 apps unchanged since an earlier scan and not read again, 0 apps read
```

A path that does not exist, or that is not something to scan, is a mistake
in the command and is refused before anything is read. After that, nothing
one app does can cost the scan the others. What could not be read is in the
report as a coverage note, never passed off as "nothing found":

| What cannot be read | What the report says |
|---|---|
| A file inside a bundle, or a bundle's folder | `skipped`, `unreadable`, under that bundle, with the place inside it |
| An `.apk` file: no permission, a read error, or the file changes while it is read | `skipped`, `unreadable`, under the name of the file |
| A browser whose profile folder the system will not let the scan list (macOS protects some apps' data this way) | `skipped`, `no_privilege`, under the browser, such as `chrome`, with how many folders |
| A browser extension whose `manifest.json` is missing, is a link, or cannot be read; an add-on archive over 64 MiB | `skipped`, `unreadable` or `over_budget`, under the extension's id |
| A `manifest.json` that is not JSON, or a message catalogue the name points at that is missing | `unrecognized`, `parse_error`, or `skipped`, `unreadable`, under the extension, with the place inside it |

An `.apk` file is identified by its hash. One that was not read to its end
as one file has none, so its coverage note carries the digest `unread` and
the file's name, and no other record can be about it.

### The cache

Reading is nearly all of a scan's time, and between two scans nearly no app
changes. So a scan keeps what it found in each app, and the next scan reads
only the apps whose files look different. On the laptop measured below, a
scan of the 16 installed apps takes 1.4 s when it reads them and 0.10 s when
none has changed. Browser extensions are not kept: a manifest is a few
kilobytes, so every scan reads them again.

**The report is the same with the cache and without it, byte for byte.** A
kept result is used only if all of this still holds:

| What | How it is told |
|---|---|
| The app is in the state it was read in | Every folder of a bundle is listed, which reads no content. The names and kinds of all entries must be the same, and for every regular file its size, its modification time, its change time and its inode. An `.apk` file answers for itself the same way. |
| It is the same app in the same place | An entry is kept under the hash of the app's path. |
| It is the same program | The SHA-256 of the `exposure` binary itself. A version number is not enough: two builds of one version can read an app differently. |
| It is the same rules | The hash of every layer of the rule pack. |

Anything else is a miss, and a miss is an ordinary read. The last line of
the summary says how many apps were read and how many were not.

**What is kept, and where.** One file per app, readable by its owner only,
in a folder created for its owner only:

| System | Folder |
|---|---|
| macOS | `~/Library/Caches/exposure` |
| elsewhere | `$XDG_CACHE_HOME/exposure`, or `~/.cache/exposure` without that variable |

A file holds the records about one app, the same records the report shows,
and two hashes: of the four things above, and of the file's own content. It
holds no path and no list of the app's files.

No scan removes anything from the cache. The entry of an app you removed
stays until you delete the folder; it is never used again, since no app is
in the state it was made from, and no report depends on it. Deleting the
folder is safe at any time: the next scan reads everything and fills it
again. Removing the entries of removed apps automatically is a follow-up.

`--no-cache` reads every app, uses nothing that is kept and keeps nothing.
A scan run as root, with `sudo` for example, uses no cache either and
creates nothing in one, so that it leaves no file in your cache folder that
you cannot replace; the summary says `cache: not used when run as root`. A
cache folder that belongs to another user is not used. A cache that cannot
be used, such as a folder that cannot be written, is said in the summary and
the scan runs without it.

**What is not kept, and not trusted:**

- A result for an app with a file that was written or changed within a few
  seconds before the scan. A change made in the same tick of the clock as
  the listing could leave such a file looking as it was listed, so the app
  is read again next time. This is the one place the scanner goes by a time:
  that of the file system the cache is on, compared with the times of the
  app's files. No report depends on it.
- A result with a part the file system refused. The refusal may be gone the
  next time, with no file looking different.
- A file in the cache that is damaged or was edited: its content hash, the
  hash of what it is valid for, and every record's own id are checked, and
  what fails is passed over. The app is read and the file replaced.
- A file in the cache that belongs to another user, or that another user
  may write.

The checks are against damage and against other users. They are not against
you: whoever can write your files can write the cache, as they can write the
report. And one thing the listing cannot show: if the right to read an app
is taken away without any of its files changing, a scan with the cache still
reports what the app held when it was read.

The cache amends the spec's trust rule 5, "store the minimum: by default
only the report file is kept": the warm-scan target cannot be met without
kept results (design report, section 10.4). Two things differ from the
design report's section 4.7. It asked for the list of an app's files to be
kept, with their sizes, times, inodes and hashes; the cache keeps one hash
of that list, which is all a comparison needs. And it asked for results to
be valid for a scanner version; they are valid for one build.

### What a finding looks like

```json
{
  "type": "channel",
  "subject": {"kind": "app", "platform": "macos", "id": "org.example.exposure.skeleton",
              "version": "1.0.0", "digest": "bd1:e387…4353"},
  "object": {"kind": "sdk", "id": "sdk/sentry", "name": "Sentry"},
  "company": "sentry", "category": "crash_reporting", "headline": false,
  "party": "third", "vendor": {"domain": "example.org"},
  "grade": "contains", "rungs": ["contains"],
  "confidence": "high", "witnesses": 1,
  "evidence": ["sha256:078a…5c96"]
}
```

`grade` says how strong the evidence is. `contains` means the app ships the
SDK's code. It proves presence, not use: only an observed connection would
show a live flow. The tool states graded facts and never says more than its
evidence supports. Each id under `evidence` is a record in the same file that
names the rule token, where it was found and how often. `vendor` says what
`party` rests on: here the pack lists nobody as the publisher of the app, and
all that is known is the domain its app id spells.

### What an app may access

Besides what an app ships, a scan says what it may access: the camera, the
microphone, the screen's sound, location, contacts, files and folders, the
network, other apps. An app asks for these in its own files, and each place
it asks is a witness of its own:

| Where | Witness | Example key |
|---|---|---|
| `Contents/Info.plist` of a macOS bundle | `usage_description` | `NSCameraUsageDescription`, with the sentence macOS shows when it asks |
| Entitlements of the main executable's code signature | `entitlement` | `com.apple.security.device.camera` |
| `uses-permission` in an Android manifest | `android_permission` | `android.permission.CAMERA` |

Each becomes an access claim, apart from every channel:

```json
{
  "type": "access",
  "object": {"kind": "permission", "id": "camera", "name": "Camera"},
  "category": "capture", "company": null, "headline": false, "party": "unknown",
  "grade": "requested", "rungs": ["requested"], "confidence": "high", "witnesses": 2,
  "evidence": ["sha256:…", "sha256:…"]
}
```

`requested` is the bottom rung of the access ladder and means "may access":
the app asks for it. It does not mean the user allowed it, and it does not
mean the app ever did it. The cited records carry the key, the file it is
in, and for a usage description the purpose the app states, cut to 160
bytes. A claim about access names no company and counts in no headline
number. That an app may access the camera and ships an analytics SDK does
not say the SDK receives pictures, and the report never joins the two.

Which keys mean which permission is a fixed list in `xs-model`
(`access.rs`), with its own categories: camera, microphone and screen;
location; personal data; calls and messages; files and folders; network;
nearby devices; control of other apps and the system; tracking identifiers;
authentication. An Android permission that reaches nothing of the user's,
such as `WAKE_LOCK`, is not listed and is no finding. A usage description
under a key the list does not know is a coverage note (`unrecognized`,
`unrecognized_record`), not silence. An entitlement that holds a list, such
as a sandbox exception for paths on your disk, is recorded with the number
of its entries and never the entries. An Android permission the manifest
limits with `android:maxSdkVersion` keeps that level as `max_sdk` in its
record. When every witness of a claim stops at a level, the claim's `notes`
say which devices it is limited to, such as "only on Android 9 and older
(API level 28)".

Only the main executable speaks for the app; a helper's entitlements are the
helper's. Its signature also says whether the app runs in the App Sandbox,
recorded as `sandbox` in the app's facts. Outside the sandbox no
entitlement limits which of your files the app can read or whether it can
use the network, so the absence of those permissions says nothing about such
an app. A main executable whose signature could not be read leaves a
coverage note and `sandbox` unknown.

Not seen: what macOS grants in System Settings without the app declaring
it, such as Accessibility, Screen Recording and Full Disk Access, and which
permissions you actually allowed. Both live in the system's permission
store, outside the app's files, which macOS 27 closes to other apps
(design report, C10). A scan of files says what an app may ask for, not what
it was given.

On the Mac this was built on, the 16 installed apps gave 102 access claims:
14 of them may access the camera and the microphone, 7 may control other
apps, 5 are sandboxed. Each claim matched what `plutil` and
`codesign -d --entitlements -` show for the same app.

### Android packages

```console
$ target/release/exposure scan tests/fixtures/android/Skeleton.apk --json report.json
exposure: scanned 1 app (1 file, 1818 bytes): 2 claims, 0 coverage notes
exposure: headline: 0 companies at contacts or above, 1 company at contains, 1 app with a third-party channel
exposure: scope: the paths given and nothing else; the installed-app folders were not searched
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

The manifest's `uses-permission` elements are read too, for what the app may
access (above).

A record names the table and the file a hit is in, so it can be checked with
`unzip -l`, `aapt2 dump xmltree` or `dexdump`. A hit in the string table
carries the rule's token and never the string, which could be a URL.

Limits, each reported in the output where it bites: only the DEX files
Android loads from a package are read (`classes.dex`, `classes2.dex`, ...);
an entry over 256 MiB, or past 1 GiB in total, is set aside with its size;
archives with the 64-bit zip extension and DEX container files (version 041)
are reported as unsupported. Split packages are scanned one file at a time. A package that cannot be
read to its end, or that changes while it is read, has no hash to report
its content under: it is reported as skipped (see "What is scanned").

### Browser extensions

An extension sits inside every page you open, and it may only do what its
`manifest.json` asks the browser for: the browser grants nothing that is not
listed there. So that file is what is read, and nothing else:

| Browser | Where its extensions are | What is read |
|---|---|---|
| Arc, Brave, Google Chrome, Chromium, Dia, Microsoft Edge, Vivaldi | `~/Library/Application Support/<browser>/<profile>/Extensions/<id>/<version>/`, every profile | `manifest.json`, and `_locales/<default_locale>/messages.json` when the name is a reference into it |
| Firefox | `~/Library/Application Support/Firefox/Profiles/<profile>/extensions/<id>.xpi` | The archive, for its hash, and the same two entries inside it |

Your history, cookies, bookmarks, saved logins, preferences and pages are
never opened. Folders are listed to find the extensions; a link is never
followed. No special privilege is needed: a browser whose folders macOS will
not let the scan list (it protects some apps' data unless the terminal has
been given access) is reported as skipped, and the scan carries on.

Each powerful thing a manifest asks for becomes an `access` claim at the
grade `requested`, about the extension, to a permission from a fixed list
that is part of the scanner, not of the rule pack:

| Permission | The extension may |
|---|---|
| `extension/all-sites` | read and change data on every website you visit |
| `extension/broad-sites` | read and change data on a broad set of websites: every site under one domain ending, or part of every site |
| `extension/history` | read and change your browsing history |
| `extension/tabs` | see the address and title of every tab you have open |
| `extension/web-navigation` | see the address of each page as you open it |
| `extension/web-request` | watch the network requests of the sites it can reach |
| `extension/cookies` | read and change the cookies of the sites it can reach |
| `extension/clipboard-read`, `extension/clipboard-write` | read what you copy; replace what is on your clipboard |
| `extension/downloads` | start downloads and see what you have downloaded |
| `extension/native-messaging` | exchange messages with a program installed on this computer |
| `extension/management` | see, switch on and switch off your other extensions |
| `extension/debugger` | attach the browser's debugger to a page, which can read and change everything in it |
| `extension/proxy` | route the browser's traffic through a proxy it chooses |

"Every website" is said only of a pattern that covers every page of every
site: `<all_urls>`, or a wildcard host with the path `/*` over `https` or
both schemes. A wildcard pattern that covers less (only `http`, part of each
site, a script that `include_globs` narrows, or every site under a suffix such
as `*.com`) is a broad set; a pattern that names sites is not reported. A
script the browser puts into pages counts only if it runs code: style sheets
alone cannot read a page. What an extension lists under an `optional_` key
it holds only once it asks while it runs and you agree, so such a claim
carries the note `optional`. Whether the browser holds a permission now is
not read.

The words are what the browser allows, not what an extension does: "may
read and change data on every website you visit". A permission names no
company and counts in no headline number, and its claim's category is
`extension_permission`. Each claim cites records that name the manifest
key, how many of its entries ask for the permission, and the least of them,
so it can be checked by opening `manifest.json`.

An extension is a subject of the kind `extension` on the platform `chromium`
or `firefox`. Its id is the browser's: the folder name for the Chromium
family, the file name for Firefox. Its digest covers the files that were
read (`bd1` for a folder, `sha256` for an add-on), so the same extension is
the same subject in every browser and on every machine. Its `artifact`
record holds its name, the publisher and the host of the home page its
manifest declares, and which browser it was found in.

```console
$ target/release/exposure scan tests/fixtures/browser/Extensions tests/fixtures/browser/addon@example.org.xpi
exposure: scanned 0 apps and 3 browser extensions (4 files, 1436 bytes): 9 claims, 0 coverage notes
```

`tests/fixtures/browser/Extensions.report.json` is that report in full: two
Chromium extensions, one of which asks for nothing broad and so has no
claim, and one Firefox add-on.

## The six properties

The scanner reads app lists, so it has to be safer than the apps it reports
on. Each property below is enforced by a mechanism and checked in CI, rather
than left to discipline.

| Property | How it is enforced | Checked by |
|---|---|---|
| **Private.** A scan opens no socket. | No crate that can open one is allowed into the dependency graph. The lint lists ban the socket, process, clock and environment APIs. | `cargo deny check`; `cargo xtask no-network`: the binary imports no socket function, and the scan runs in a network namespace with no interfaces, under `strace`, and under a macOS sandbox that denies the network, each time without the cache, with an empty one and with a full one. Each check is paired with a control program that must be caught. |
| **Deterministic.** Same evidence and rule pack, same bytes. | Derivation and rendering live in `no_std` crates that cannot read a clock, a file or the environment and have no randomly seeded map. Records hold paths inside the artifact only. Evidence is a set keyed by content hash. | One report across input orders, thread counts, install locations and cache states (off, empty, full, damaged); the committed fixture report must be reproduced byte for byte on Linux and macOS. |
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
| `xs-derive` | Evidence and pack in, claims out: grades, companies, vendors, parties | `no_std` |
| `xs-render` | Claims and evidence in, report out | `no_std` |
| `xs-collect` | Discovery, reading and the results cache, one module per collector. The only crate that opens files | std |
| `exposure` (in `crates/xs-cli`) | The `exposure` binary | std |
| `xtask` | Developer tooling. Never shipped | anything |

`fuzz/` holds the fuzz targets. It is a workspace of its own, because it
needs a nightly toolchain and the libFuzzer runtime.

```
discover ─▶ collect ─▶ evidence ─▶ derive ─▶ claims ─▶ render ─▶ report
(stat)     (read, hash,  set       (pure)              (pure)
   ▲        match)
   └─ cache ─┘   an app that looks as it did when it was read is not read again
```

Everything left of the evidence set touches the file system. Everything right
of it is a pure function.

Files are read once, in bounded 1 MiB windows, with the same bytes feeding
the hash and the matcher. A Mach-O file says where to look in it, so its
headers and load commands are picked out of the windows as they go by; the
file is still read exactly once.

The scan has one queue. Every bundle is listed first, which only looks at
names, sizes and times. An app that the cache holds in the state listed is
done with there. Then every file to read, of every other bundle and
package, is one task in one list, largest first. A few files hold most of the bytes
(on the laptop below, half of them sit in 12 files), so the order matters:
they start at once on separate threads, and no thread is left reading a
large file alone at the end. Which thread reads what, and in which order,
cannot reach the report.

Measured with `cargo xtask bench` on an Apple M5 (10 cores) over the 16
installed apps, 11,658 files and 6.8 GB read, page cache warm:

| Threads | Time | Speed-up | Peak memory |
|---|---|---|---|
| 1 | 5.96 s | 1.00x | 20 MB |
| 2 | 2.23 s | 2.66x | 25 MB |
| 4 | 1.37 s | 4.32x | 30 MB |
| 8 | 0.91 s | 6.48x | 39 MB |

Those runs keep no cache. With one, and nothing changed since the scan that
filled it, the same scan takes 0.10 s at 8 MB: all 16 apps are found
unchanged and none is read.

All 17 runs gave the same report, byte for byte: 13 without the cache, one
that fills it and three that find it full. The benchmark fails below 3x at
8 threads, at 200 MB of memory, or if the scan with nothing changed takes
5 s. With Rayon's default splitting in place of one task per file it
measures 1.19x and fails. A cold disk was not measured.

Memory does not grow with the bytes read. It grows with the number of files
listed: a bundle of 300,000 small files took 84 MB. And it grows with the
largest entry of a package that is read whole to be parsed, a DEX file or a
manifest: up to the 256 MiB budget, stored and inflated, per worker thread.
DEX files of real apps are a few megabytes.

## Development

```console
$ cargo test --workspace --all-features    # everything, including the determinism tests
$ EXPOSURE_FIXTURE_CACHE=<dir> cargo test -p exposure --test electron   # also the real apps, see tests/fixtures/README.md
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo deny check                          # needs cargo-deny
$ cargo xtask pack check                    # rule sources, compiled pack and signature agree
$ cargo xtask guardrails                    # the guardrails refuse deliberate violations
$ cargo xtask no-network                    # a scan opens no socket
$ cargo xtask bench --strict                # scaling, memory and warm-scan gates on the installed apps (macOS)
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
in a separate layer. The Public Suffix List compiled into the binary: MPL 2.0.
See [`NOTICE`](NOTICE) and [`LICENSES/`](LICENSES).
