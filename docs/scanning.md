# What a scan reads

This page lists, per platform, which files a scan opens, what each part is
evidence of, and what happens when something cannot be read. For how the
findings are graded and counted, see [Reading the report](report.md).

- [Choosing what to scan](#choosing-what-to-scan)
- [macOS app bundles](#macos-app-bundles)
- [Electron apps](#electron-apps)
- [Android packages](#android-packages)
- [Browser extensions](#browser-extensions)
- [What an app may access](#what-an-app-may-access)
- [What could not be read](#what-could-not-be-read)
- [The results cache](#the-results-cache)
- [The built-in rule pack](#the-built-in-rule-pack)
- [Measured on real apps](#measured-on-real-apps)

## Choosing what to scan

A `PATH` is a macOS `.app` bundle, an Android `.apk` file, a browser
extension (a Firefox `.xpi` file, or a Chromium `<id>/<version>` folder that
holds a `manifest.json`), or a folder. A folder is searched for all of them,
in itself and in its sub-folders, never inside a bundle. An app reached two
ways, such as directly and through a symbolic link, is scanned once.

Without a `PATH`, on macOS, the installed apps are scanned: those in
`/Applications` and in your own `~/Applications`. So are the extensions in
your own profiles of the browsers listed under
[Browser extensions](#browser-extensions). On another system there is no
folder this build knows to look in, and a scan without a `PATH` says so.

A `PATH` replaces the installed-app folders, it is not added to them: when
any `PATH` is given, only what the `PATH`s name is scanned.

Apple's own apps on the sealed system volume, in `/System/Applications`, are
a documented omission: name that folder to scan it. Every scan without a
`PATH` states the omission in its scope line, the last line of the summary on
standard error. It is not a coverage record, which differs from the design
report (section 4.8), which asked for one: a coverage record needs an app as
its subject, and a folder is not one. The scope line is fixed text, and it
never holds a path you gave. The JSON report records which of the two scopes
the scan had, in its `scope` field, outside the evidence records. The HTML
report states the scope too, at the top of its coverage section.

```console
$ exposure scan --json report.json
exposure: scanned 16 apps and 8 browser extensions (11669 files, 6813657279 bytes): 136 claims, 4 coverage notes
exposure: headline: 0 companies at contacts or above, 0 companies at contains, 0 apps with a third-party channel
exposure: scope: the apps installed in /Applications and ~/Applications; /System/Applications (Apple's own apps on the sealed system volume) was not searched: name the folder to scan it; the extensions installed in your profiles of Arc, Brave, Google Chrome, Chromium, Dia, Microsoft Edge, Firefox and Vivaldi
exposure: cache: 16 apps unchanged since an earlier scan and not read again, 0 apps read
```

A path that does not exist, or that is not something to scan, is a mistake
in the command and is refused before anything is read. After that, nothing
one app does can cost the scan the others (see
[What could not be read](#what-could-not-be-read)).

## macOS app bundles

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
| `*UsageDescription` keys of `Contents/Info.plist` | `usage_description` | A permission the app asks for, with the purpose it states ([access](#what-an-app-may-access)) |
| Entitlements in the code signature of the main executable | `entitlement` | A permission the app asks for ([access](#what-an-app-may-access)) |

A declared address is cut down to its host; no URL is stored. A host is shown
as itself, under the company the rule pack lists its domain for, or as
unmapped. An encrypted binary, such as an iOS app installed on a Mac, is
reported as a coverage note and its ciphertext is not searched.

## Electron apps

An Electron app is a macOS bundle too, so everything above applies to it.
Its scripts are read as well: an SDK is found when it is installed as an npm
package listed in an asar archive or in the `Contents/Resources/app` folder,
or when it is bundled into the app's own code.

Only script files (`.js`, `.cjs`, `.mjs`) are searched, and what sits under a
`node_modules` folder is labelled a dependency. Pages, source maps and data
files are not searched: a link in a page names a company without the app
talking to it, and libraries ship demo pages and documentation.

The file table of an asar archive is not trusted: an entry that overlaps
another or reaches past the end of the archive is counted as a gap and not
read, and a header in a shape no archive writer produces is refused whole.

## Android packages

```console
$ exposure scan tests/fixtures/android/Skeleton.apk --json report.json
exposure: scanned 1 app (1 file, 1818 bytes): 2 claims, 0 coverage notes
exposure: headline: 0 companies at contacts or above, 1 company at contains, 1 app with a third-party channel
exposure: scope: the paths given and nothing else; the installed-app folders were not searched
exposure: cache: 0 apps unchanged since an earlier scan and not read again, 1 app read
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

The manifest's `uses-permission` elements are read too, for
[what the app may access](#what-an-app-may-access).

A record names the table and the file a hit is in, so it can be checked with
`unzip -l`, `aapt2 dump xmltree` or `dexdump`. A hit in the string table
carries the rule's token and never the string, which could be a URL.

Limits, each reported in the output where it applies:

- Only the DEX files Android loads from a package are read (`classes.dex`,
  `classes2.dex`, ...).
- An entry over 256 MiB, or past 1 GiB in total, is set aside with its size.
- Archives with the 64-bit zip extension and DEX container files (version
  041) are reported as unsupported.
- Split packages are scanned one file at a time.
- A package that cannot be read to its end, or that changes while it is
  read, has no hash to report its content under: it is reported as skipped.

## Browser extensions

An extension sits inside every page you open, and it may only do what its
`manifest.json` asks the browser for: the browser grants nothing that is not
listed there. So that file is what is read, and nothing else:

| Browser | Where its extensions are | What is read |
|---|---|---|
| Arc, Brave, Google Chrome, Chromium, Dia, Microsoft Edge, Vivaldi | `~/Library/Application Support/<browser>/<profile>/Extensions/<id>/<version>/`, every profile, the highest version of each extension | `manifest.json`, and `_locales/<default_locale>/messages.json` when the name is a reference into it |
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
| `extension/broad-sites` | read and change data on a broad set of websites: every site under one domain ending, every site over plain http or on one port, or some pages of every site |
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
site: `<all_urls>`, or a wildcard host on any port over `https` or both
schemes. The browser grants a site whole whatever path a permission's pattern
gives, so `https://*/` under `host_permissions` (or, in a version 2 manifest,
`permissions`) is every website; a script's `matches` must have the path `/*`.
A browser takes sites under `host_permissions` and `optional_host_permissions`
only from manifest version 3, and under `permissions` and
`optional_permissions` only before it, so what the other pair lists is not
reported; a manifest that states no version counts as version 2.
A wildcard pattern that covers less (only `http`, one port, part of each site
for a script, a script that `include_globs` narrows, or every site under a
suffix such as `*.com`) is a broad set; a pattern that names sites is not
reported. A script the browser puts into pages counts only if it runs code:
style sheets alone cannot read a page. What an extension lists under an
`optional_` key it holds only once it asks while it runs and you agree, so
such a claim carries the note `optional`. Whether the browser holds a
permission now is not read.

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
$ exposure scan tests/fixtures/browser/Extensions tests/fixtures/browser/addon@example.org.xpi
exposure: scanned 0 apps and 3 browser extensions (4 files, 1436 bytes): 9 claims, 0 coverage notes
exposure: headline: 0 companies at contacts or above, 0 companies at contains, 0 apps with a third-party channel
exposure: scope: the paths given and nothing else; the installed-app folders were not searched
exposure: cache: 0 apps unchanged since an earlier scan and not read again, 0 apps read
```

`tests/fixtures/browser/Extensions.report.json` is that report in full: two
Chromium extensions, one of which asks for nothing broad and so has no
claim, and one Firefox add-on.

## What an app may access

Besides what an app ships, a scan says what it may access: the camera, the
microphone, the screen's sound, location, contacts, files and folders, the
network, other apps. An app asks for these in its own files, and each place
it asks is a witness of its own:

| Where | Witness | Example key |
|---|---|---|
| `Contents/Info.plist` of a macOS bundle | `usage_description` | `NSCameraUsageDescription`, with the sentence macOS shows when it asks |
| Entitlements of the main executable's code signature | `entitlement` | `com.apple.security.device.camera` |
| `uses-permission` in an Android manifest | `android_permission` | `android.permission.CAMERA` |

Each becomes an access claim, separate from every channel, graded
`requested` (see [the access ladder](report.md#grades)).

Which keys mean which permission is a fixed list in `xs-model`
(`access.rs`), with its own categories: camera, microphone and screen;
location; personal data; calls and messages; files and folders; network;
nearby devices; control of other apps and the system; tracking identifiers;
authentication.

- An Android permission that reaches nothing of the user's, such as
  `WAKE_LOCK`, is not listed and is no finding.
- A usage description under a key the list does not know is a coverage note
  (`unrecognized`, `unrecognized_record`), not silence.
- An entitlement that holds a list, such as a sandbox exception for paths on
  your disk, is recorded with the number of its entries and never the
  entries.
- An Android permission the manifest limits with `android:maxSdkVersion`
  keeps that level as `max_sdk` in its record. When every witness of a claim
  stops at a level, the claim's `notes` say which devices it is limited to,
  such as "only on Android 9 and older (API level 28)".

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

## What could not be read

What could not be read is in the report as a coverage note, never passed off
as "nothing found":

| What cannot be read | What the report says |
|---|---|
| A file inside a bundle, or a bundle's folder | `skipped`, `unreadable`, under that bundle, with the place inside it |
| An `.apk` file: no permission, a read error, or the file changes while it is read | `skipped`, `unreadable`, under the name of the file |
| A file over 2 GiB; a zip entry over 256 MiB, or past 1 GiB inflated in one package | `skipped`, `over_budget`, with its size |
| A browser whose profile folder the system will not let the scan list (macOS protects some apps' data this way) | `skipped`, `no_privilege`, under the browser, such as `chrome`, with how many folders |
| A browser extension whose `manifest.json` is missing, is a link, or cannot be read; an add-on archive over 64 MiB | `skipped`, `unreadable` or `over_budget`, under the extension's id |
| A `manifest.json` that is not JSON, or a message catalogue the name points at that is missing | `unrecognized`, `parse_error`, or `skipped`, `unreadable`, under the extension, with the place inside it |
| Older version folders of a Chromium extension that an update left behind, next to the highest version, which is the one scanned | `skipped`, `superseded_version`, under the extension, with how many folders |
| An encrypted Mach-O binary | `skipped`, `encrypted_binary`; the ciphertext is not searched |
| A zip64 archive or a DEX container file | `skipped`, `unsupported_format` |
| A damaged file, or a usage description under a key this build does not know | `unrecognized`, `parse_error` or `unrecognized_record` |

An `.apk` file is identified by its hash. One that was not read to its end
as one file has none, so its coverage note carries the digest `unread` and
the file's name, and no other record can be about it.

## The results cache

Reading is nearly all of a scan's time, and between two scans nearly no app
changes. So a scan keeps what it found in each app, and the next scan reads
only the apps whose files look different. On the laptop measured in
[Architecture](architecture.md#performance), a scan of the 16 installed apps
takes 1.4 s when it reads them and 0.10 s when none has changed. Browser
extensions are not kept: a manifest is a few kilobytes, so every scan reads
them again.

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

## The built-in rule pack

The signed pack in `rules/dist/` holds 48 rules. A scan looks for these SDKs
and for nothing else, so a clean report does not mean an app is clean.

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
cited in the rule (`rules/core/sdk/`). `exposure rules show` lists the pack.

## Measured on real apps

The collectors are tested against real apps that are pinned by hash and never
stored in this repository (`tests/fixtures/README.md`,
`tests/fixtures/real-apps.txt`).

- **Electron.** Logseq 2.0.2 reports Sentry and PostHog, both from
  `js/main.js` inside its archive and neither among the 280 npm packages the
  archive lists. Bitwarden desktop 2026.10.4 and Obsidian 1.15.1 name no
  company. What they report is the updaters they ship, which are components:
  Squirrel, which is part of Electron on macOS and so in every Electron app,
  and in Bitwarden also electron-updater.
- **macOS.** NetNewsWire 7.2.1's update feed, on `ranchero.com`, is first
  party. Maccy 2.8.0's, on `raw.githubusercontent.com`, is GitHub's and so
  Microsoft's: a third party, and not counted. App Center in AltTab 11.10.2
  is a third party to it, in categories that are not counted.
- **Android.** Bitwarden 2026.9.1's Play build reports five Google SDKs
  (Crashlytics, Installations, Cloud Messaging, DataTransport and Play
  Billing), each from two or three independent witnesses. Its F-Droid build
  and NewPipe 0.29.3 report no SDK.
- **Access.** On the Mac this was built on, the 16 installed apps gave 102
  access claims: 14 of them may access the camera and the microphone, 7 may
  control other apps, 5 are sandboxed. Each claim matched what `plutil` and
  `codesign -d --entitlements -` show for the same app.
