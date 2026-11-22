# Reading the report

A scan writes a JSON report, an HTML report, or both. The JSON report holds
the **evidence**, every record the scan collected, each keyed by the SHA-256
of its canonical text, and the **claims** derived from that evidence. The
HTML report is the same content laid out for reading, grouped by company. Every claim cites the records it rests
on, so any statement in a report can be checked by hand against the app.

- [Claims](#claims)
- [Grades](#grades)
- [Whose it is](#whose-it-is)
- [The headline](#the-headline)
- [What is not counted](#what-is-not-counted)
- [Access claims](#access-claims)
- [The HTML report](#the-html-report)
- [What you can do](#what-you-can-do)

## Claims

There are two kinds of claim:

| Type | Says | Example |
|---|---|---|
| `channel` | A company has a channel to an app's data: the app ships the company's SDK, or names one of its hosts | Sentry in an app, graded `contains` |
| `access` | An app or a browser extension may access something | The camera, or every website you visit, graded `requested` |

A channel claim:

```json
{
  "type": "channel",
  "subject": {"kind": "app", "platform": "android", "id": "org.example.exposure.skeleton",
              "version": "1.0.0", "digest": "sha256:7cde…3c"},
  "object": {"kind": "sdk", "id": "sdk/posthog", "name": "PostHog"},
  "company": "posthog", "category": "analytics", "headline": true,
  "party": "third", "vendor": {"domain": "example.org"},
  "grade": "contains", "rungs": ["contains"],
  "confidence": "high", "witnesses": 2,
  "evidence": ["sha256:1792…db6", "sha256:631f…5b91"]
}
```

| Field | Meaning |
|---|---|
| `subject` | The app, identified by its platform, id, version and a digest of its content |
| `object` | The SDK or host the channel goes through |
| `company` | The company at the top of the ownership chain of the SDK's operator, or `null` |
| `category` | One of the fixed categories of the rule pack |
| `headline` | Whether the claim counts in the headline numbers |
| `party` | `first`, `third` or `unknown` (see [Whose it is](#whose-it-is)) |
| `vendor` | Who publishes the app and what `party` rests on: the company the pack lists it under and by which identifier (Team ID or app id), and the domain the app id spells |
| `grade` | The highest rung the evidence reaches; `rungs` lists every rung that has evidence |
| `confidence` | The highest confidence any single witness earns: `high` for a name read from a parsed table, `medium` for a literal in app code or a binary, `low` for a literal inside a dependency or resource |
| `witnesses` | How many distinct kinds of evidence (matchers) agree |
| `evidence` | The ids of the records the claim rests on, each present in the same file |
| `notes` | Remarks carried over from the rule, such as `retired:2025-03-31` |

## Grades

Each kind of claim has its own ladder. A claim takes the highest grade its
evidence supports, and new evidence can raise a grade but never lower it.

| Ladder | Grade | In words | Means | Evidence | Available |
|---|---|---|---|---|---|
| Channel | `declares` | declares | The app's own files name the endpoint | An update feed URL, a tracking domain in a privacy manifest | Now |
| Channel | `contains` | ships | The app ships the SDK's code | A class, package, framework or endpoint literal | Now |
| Channel | `contacts` | contacted | The OS or a capture recorded a connection | An iOS app privacy report, a capture log | Milestone 2 |
| Channel | `confirmed` | confirmed | The receiver lists the sender, or a payload was inspected | A platform data archive, a lab capture | Milestone 4 |
| Access | `requested` | may access | The app asks for the permission | A manifest entry, a usage description, an entitlement | Now |
| Access | `granted` | granted | The user allowed it | The OS permission store | Milestone 2 |
| Access | `used` | used | The OS logged an access | An iOS report | Milestone 2 |

**`contains` proves presence, not use.** An app can ship the code of a
service it never starts, or of a service that has been retired: AltTab still
ships Microsoft App Center code, which Microsoft retired in 2025. Only
`contacts` shows a live flow, and nothing in the current build observes a
connection.

The two ladders are never joined into a stronger statement. A report can say
that a company has a channel through an app and that the app may access
location. It does not say that the company receives location.

## Whose it is

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
identifiers for those companies and no others. A vendor known by its
signature cites the record that holds the Team ID.

## The headline

The headline is three counts. There is no score.

| Count | What is counted |
|---|---|
| `companies_contacts` | Companies with a channel at `contacts` or above. Always 0 in the current build: nothing observes a connection yet. |
| `companies_contains` | Companies whose strongest channel is `contains`. |
| `apps_third_party` | Apps with at least one third-party channel in a counted category. |

Only claims in five categories are counted, and only when they name a
company: **advertising, analytics, attribution, profiling and session
replay**. Each claim says whether it counts in its `headline` field, so the
numbers can be recounted from the claims.

**Beside the headline, for Android.** On Android most of what ships is a
large company's infrastructure, which the counts leave out: the Play build
of Bitwarden ships five Google SDKs, none in a counted category, so its
counts are zero. So that such a scan does not read as "nothing found", the
terminal summary and the HTML report add one more line when the Android apps
ship SDKs of a company outside the counted categories: "5 SDKs of 1 company
in the Android apps, in categories the headline does not count". The HTML
report names the companies and the SDKs. It is a tally of the claims like
the three counts, is not stored in the JSON report, and is no score.

## What is not counted

Hosting is not receiving. These are in the report, under their company where
there is one, and in none of the three numbers:

- crash reporting, push delivery, payments and billing;
- an update feed, and a declared tracking domain that no rule names;
- customer messaging, such as Intercom and OneSignal (the five counted
  categories are a fixed list; Braze and Customer.io track what the user does
  and so are counted, under profiling);
- components, which name no company;
- unmapped hosts;
- every access claim.

Measured on real apps: PostHog in Logseq 2.0.2 is analytics and is counted,
giving one company at `contains` and one app with a third-party channel.
Maccy's update feed on `raw.githubusercontent.com` belongs to Microsoft
through GitHub, is third party, and is not counted.

## Access claims

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
mean the app ever did it. The cited records carry the key, the file it is in,
and for a usage description the purpose the app states, cut to 160 bytes.

A claim about access names no company and counts in no headline number. That
an app may access the camera and ships an analytics SDK does not say the SDK
receives pictures, and the report never joins the two. See
[What an app may access](scanning.md#what-an-app-may-access) and
[Browser extensions](scanning.md#browser-extensions) for where the keys come
from.

## The HTML report

```console
$ exposure scan /Applications --html report.html --json report.json
$ exposure report report.json --html again.html   # the same page, from the saved evidence
```

`--html FILE` writes the report for reading and `--json FILE` the one a
program reads; both can be asked for at once. With neither, `exposure scan`
writes the page to `report.html` in a folder only you can read
(`~/Library/Application Support/exposure` on macOS), opens it in your
browser when it runs in a terminal, and prints what needs your attention
first: the entries of [What you can do](#what-you-can-do) of high and medium
priority, as the page's summary lists them. The HTML report is one file
that opens in any browser, also on a phone, and has a layout for print. A
sample, the page for the fixtures of this repository, is
[`tests/fixtures/report/Fixtures.report.html`](../tests/fixtures/report/Fixtures.report.html).
It leads with what needs your attention and keeps the detail one click
away: what is opened on demand is in a `details` element, which the browser
opens and closes with no script. Its content is in the file whether it is
open or not, printing opens it in browsers that support the
`::details-content` pseudo-element (current Chrome, Edge, Safari and Firefox;
an older browser prints it closed), and no link on the page leads into one
that is closed. It holds:

| Part | What it says |
|---|---|
| What needs your attention | One sentence with how much was found. Then the first entries of [What you can do](#what-you-can-do) of high and medium priority, at most five, each in one sentence with its first step and a link to the entry with every step; with none of them, the first low-priority entries, said to be low priority. The terminal summary of `exposure scan` prints the same entries. Under it, opened on demand: the three headline counts, whose line states the three numbers, said to count the counted categories only; when findings exist and all three counts are zero, the page says why; beside them, for Android, the SDKs of companies outside the counted categories; and the totals. Then everything that was found, each thing once (an SDK or a declared host, under its company or under none) with its category, its grade as a fact with a count (`ships in 10 of 16 apps`), the apps as links to their findings, and whether it is counted. No score. |
| What you can do | A checklist with what exposes the most first, one entry per service with the apps it is in, per System Settings pane with the apps that may ask for it, per extension and per Android app. Each entry links to the findings it is about. Entries of low priority are under one line that names them, opened on demand, unless there is nothing else. A block list of more than four hosts names how many there are and lists them under the step, opened on demand. See [What you can do](#what-you-can-do). |
| How to read it | What each grade shows and does not show, in one word each: declares, ships, contacted, confirmed; and, when the scan found what an app may access, the access grades too (may access). Opened on demand. |
| Findings by company | Companies with a counted finding first, then the others by name. Under each, the apps, and for each finding its grade; opened on demand, its confidence, how many kinds of evidence agree, whether the company is the app's publisher, what you can do about it, and each record it rests on in words: the marker, the file, the table, an example, a count. Components and unmapped hosts come after the companies, under no company. Findings about what an app may access have a part of their own, by app. A company with no counted finding is tagged as outside the counted categories, as visibly as a counted one. |
| Coverage | Where the scan looked, and where it deliberately did not. Every app that was read, with what was read of it, also the apps with no finding. Then everything that was skipped or not understood, and why. Both tables are opened on demand, from a line with their count. |
| Limits | What no scan of a device can see: what is inside encrypted traffic, what companies pass on between their own servers, and what an app sends through its own domain. And that presence is not use, and that only what has a rule is recognised. |
| Evidence records | Every record of the scan as it is stored. A finding links to its records, and the SHA-256 of a record's text is its id. |

App names, versions, class names and paths are chosen by whoever built the
app, so the page is built to stay inert whatever they hold:

| Guard | How it is enforced |
|---|---|
| Every value is escaped | The writer takes markup only as text that is part of the program. Any other string can enter as character data alone, escaped. An attribute value is fixed text, or an anchor made of a hash; no string from a file can be one. |
| No script | The page holds none, and its content security policy, `default-src 'none'`, allows none. |
| Nothing is loaded | No image, no font, no link that leaves the page. The one stylesheet is in the page, and the policy admits it by its hash, so an inline style or a second stylesheet would not apply. |
| The same bytes | No date, no device name, no path outside an app, and no path you gave. The same evidence, rule pack and scope give the same file. |

Where a scan looked is not evidence about any app, so no record holds it.
The JSON report carries it beside the evidence, in its `scope` field, as
`installed` or `given`. So the page `exposure report` renders from a saved
report is the page of the scan, byte for byte, with the same statement of
where the scan looked. A JSON report saved before the field existed is
still read; its page says that the scope is not on record.

A test scans a bundle and a package whose app names, ids, versions and class
names are markup, reads the page back with a reader stricter than a browser,
and requires the same elements as the page of two harmless apps.

## What you can do

The HTML report has a **What you can do** checklist near the top, and the
same steps under every finding. It is advice: the scanner changes nothing.
Within an entry, and under a finding, the steps that do something come
first: an app's own setting where its publisher documents one, then the
hosts to block, and only then what a publisher says cannot be done, and
that nothing is on record. The summary at the top of the page gives the
first of them for each entry that needs attention.
The checklist lists what exposes the most first:

| Priority | What it covers |
|---|---|
| **High** | Code of a company in a counted category (advertising, analytics, attribution, profiling, session replay) in an app it does not publish; and a browser extension that may read the pages you visit or what you do in the browser, unless that access is only optional. |
| **Medium** | What an app may reach of you and your surroundings: the camera, the microphone, the screen, location, personal data and communications. A domain an app itself declares it tracks through. Any other browser extension. |
| **Low** | The rest you can act on: other services of a company in an app, such as crash reporting, and access to files, nearby devices or other apps. |

Within a priority, services come first, then extensions, System Settings
panes and Android apps. An update feed and a service of the app's own
publisher get no entry.

A permission an app asks for only in Electron's own wording ("This app needs
access to the camera", and the like for the microphone, Bluetooth and audio
capture, which Electron writes into every app built with it) is no purpose
of the app's. It raises a System Settings pane no higher than **Low**, and
an entry that rests on it in part says how many of its apps state only
Electron's wording. The finding itself is reported as any other.

For a service of another company in an app, the page gives the app's own
setting where its publisher documents one, says so plainly where the
publisher documents that there is none, and says the setting is not on
record otherwise; it never claims a setting stops a given SDK, which no scan
of files can show. Hosts to block, with an outbound firewall such as LuLu or
Little Snitch on macOS, are given only for the counted categories and for
domains an app declares for tracking, never for a crash reporter or an app's
own publisher, since blocking those breaks more than it protects. For a
permission it names the pane of **System Settings > Privacy & Security** on
macOS, or **Settings > Apps > the app > Permissions** on Android, and says
when the platform has no switch at all. For an extension it names the
browser's own extensions page, how to narrow its site access to *On click*,
and how to remove it. What holds for one app or one SDK is data in the rule
pack, `rules/core/fixes.toml`, with a source for every entry (see
[`rules/README.md`](../rules/README.md#fixes)).
