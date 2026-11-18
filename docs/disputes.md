# Disputing a finding

A report names apps, SDKs and companies. When a finding is wrong, it should
be easy to show, and quick to correct. This page says how a dispute is made,
how it is settled, and what changes when it is upheld. Use the
[dispute form](https://github.com/Adityaakr/exposure-scanner/issues/new?template=dispute.yml).

## What a finding says, and what it does not

A finding at grade `contains` says that a file of one build of the app holds
a token that the rule pack ties to an SDK: a class name, a package, a
framework, an endpoint. It does not say that the code runs, that data was
sent, or what anyone intends; the report says so on every page (see
[Reading the report](report.md)). A dispute is about what the files hold, so
it is settled by the files.

## What to send

The form asks for:

- the app, its version and platform, and a public address of that exact
  build, with its SHA-256: a finding is about a build, not about an app's
  name;
- the claim, copied from the JSON report, and every evidence record it
  cites. A record names the file inside the app, the rule, the token and
  where it matched, so anyone can look at the same bytes;
- what is wrong, and how it can be checked.

Copy only the one claim and its records. A whole report lists every app on
the machine it was made on.

## How it is settled

1. **The build is fetched and scanned again** from the address given, and
   the hash is checked. If the records do not reproduce, the dispute is
   upheld at once: the scanner should never report what it cannot show.
2. **Each record is checked against the build.** The file it names is
   opened, and the matched bytes are read in context.
3. **The rule is checked against its sources.** Every token cites the SDK's
   code or its vendor's documentation ([`rules/README.md`](../rules/README.md)).
4. **The outcome is written in the issue**, with what was checked.

A dispute is upheld when the token matched something that is not the SDK
(for example an address in bundled documentation), when the code belongs to
another SDK or company, when the company or the app's publisher is wrong, or
when the category is wrong. It is not upheld because the code is unused,
disabled by default, or behind a consent dialog: `contains` reports presence,
and the report already says that presence is not use.

## What changes when it is upheld

- **The rule is fixed**, not the report: a token is narrowed, a boundary
  tightened, a witness kind given a `min_distinct`, or a company entry
  corrected. The change cites the dispute.
- **The build joins the test corpus** when it is public: as a negative
  control if it ships no other company's code
  ([`tests/fixtures/negative-apps.txt`](../tests/fixtures/negative-apps.txt)),
  or as a real-app fixture with its expected findings otherwise. CI then
  keeps the mistake from coming back.
- **A new rule pack is signed and released**, and the changelog names the
  correction.

Nothing is removed from the pack on request alone, and no app is listed as
an exception: the same rule applies to every app.

## For publishers

If your app ships an SDK you have removed in a later version, the later
build will not have the finding; nothing needs to be disputed. If you want
the steps under "What you can do" to name your app's own setting for a
service (a switch for usage data, say), open a pull request against
[`rules/core/fixes.toml`](../rules/core/fixes.toml) with a link to your
documentation, or say so in a dispute.
