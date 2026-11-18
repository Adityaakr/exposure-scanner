# Threat model

`exposure` reads every app a person has installed and writes down which
companies have a channel into them. That list is personal, and the files it
reads are written by the very companies it reports on. So the scanner has to
be safer than the apps it looks at, and this page says against what, how, and
where the protection ends.

[Architecture](architecture.md#how-each-property-is-enforced) lists each
mechanism and the test that checks it; this page is the reasoning behind
them.

## What is protected

| Asset | Why it matters |
|---|---|
| **The list of apps and extensions on the machine** | It tells what a person reads, uses, believes and is treated for. It is the most sensitive thing the scanner holds, and every report is made of it. |
| **The machine itself** | A scanner runs as the user, over files of unknown origin. It must not become a way to run their code, damage files or leak them. |
| **The truth of the report** | A person acts on it: removes apps, blocks hosts, files complaints. A report that is wrong, or that can be made wrong, does harm in both directions. |
| **The rule pack** | It decides what is found. Whoever controls it controls the report. |

## Who could attack, and how

| Adversary | What they control | What they would want |
|---|---|---|
| **A hostile app** | Every byte of its own files: names, archives, binaries, property lists, manifests | Crash or stall the scan; run code; hide its SDKs; make the report name someone else; smuggle markup or terminal escapes into what the person reads |
| **A network observer** | Nothing on the machine | Learn which apps are installed by watching the scanner talk |
| **Another local user** | Their own files, and folders the user leaves writable | Read the user's report or cache; plant a cache entry that changes the report |
| **Whoever edits the rule pack in transit** | A pack file, or the repository a build comes from | Hide an SDK, or name a company that is not there |
| **The build chain** | A dependency, a compromised crate | Put network or execution code into the binary |
| **A reader of a shared report** | A report file passed on, or a terminal log | Learn the person's apps |

The person running the scanner is trusted: they can write anything into their
own report, cache and files, and nothing here tries to stop them.

## Mitigations

### Nothing leaves the machine

- No crate that can open a socket is in the dependency graph; `cargo deny`
  refuses one if it is added, and `cargo xtask guardrails` proves it does.
- The lint lists ban the socket, process, clock and environment APIs in the
  scanner's crates.
- CI checks the built binary: it imports no socket function, and a scan run
  in a network namespace with no interfaces, under `strace`, and under a
  macOS sandbox that denies the network prints the same report as one run
  without them. A control program that does open a socket must be caught by
  each check, or the check proves nothing.
- The HTML report loads nothing. Its content security policy is
  `default-src 'none'`, its one stylesheet is admitted by hash, and it holds
  no script, image, font or outside link. Opening it makes no request.

### A hostile app cannot take over the scan

- **Nothing is executed.** Collectors open files for reading. Symbolic links
  inside an app are never followed, and nothing is unpacked to disk: archives
  are read in memory, within budgets.
- **Parsers are bounded.** Every parser takes a byte slice, is safe Rust
  (`unsafe` is forbidden in the workspace), and stops at budgets of bytes,
  items and depth: a zip directory of at most 64 MiB, an entry that inflates
  to at most its budget and its declared size, at most 1 MiB of Mach-O load
  commands per architecture, no file over 2 GiB read for evidence. Limits are
  counts, never times, so a scan cannot be made to give a different answer by
  being slowed down.
- **Failures stay local.** An app that cannot be read is reported as a
  coverage note, and the scan goes on. A damaged file is never "nothing
  found".
- **Inputs are fuzzed.** The zip, DEX, Android manifest and extension
  manifest parsers and the Android collector run under libFuzzer with the
  address sanitizer in CI, and every parser runs under property tests with
  arbitrary and damaged input.

### What an app writes cannot reach the reader as code

- In the HTML report every value is escaped and placed as character data,
  never as an attribute; a test renders class names and app names full of
  markup and checks they stay inert.
- In the terminal, the checklist a scan prints names apps as they name
  themselves. Every value is cleaned first: control characters, which start
  escape sequences, and the marks that reverse text direction are replaced,
  so an app named to clear the screen or forge a line does neither.

### The report says only what the evidence shows

- A finding cites the records it rests on, and the renderers refuse a report
  in which a cited record is missing. The HTML report carries every record,
  so each finding can be checked against the bytes it came from.
- Grades only go up with evidence. `contains` says the code is present, and
  the report says on every page that presence is not use.
- An app cannot make the report blame a company the rule pack does not tie
  to its tokens, and a token only counts on its boundary: a host inside a
  longer host, or an identifier inside a longer one, does not hit. Several
  witnesses per SDK, `min_distinct` for weak kinds of witness, and the scope
  of each hit (the app's own code, a dependency, a browser engine) keep
  coincidences out. A canary test plants every rule's tokens and requires
  them found; a corpus of real apps that ship no other company's code
  requires nothing found.
- The same evidence and rules give the same bytes: no clock, no randomly
  seeded order, no path of the machine in the report.

### The rule pack cannot be swapped

- The scanner loads only a compiled pack whose minisign signature verifies
  against a key built into the binary; the pack built into the binary is
  checked the same way on every start. The signing key never enters the
  repository.
- A rule is data: a literal and one boundary from a fixed list. There are no
  regular expressions and no scripts, so a pack cannot run code or stall the
  matcher.

### What is written is the user's alone

- A scan writes the report it is asked for, or `report.html` in a folder of
  the user's (`~/Library/Application Support/exposure` on macOS), and the
  results cache (`~/Library/Caches/exposure`). Report files are created
  readable by their owner only, and the two folders are made, or tightened,
  so that only the owner can open them.
- The cache holds the records a report shows and two hashes per app: no
  path, no file list. An entry is used only if it is a regular file of the
  user who runs the scan that nobody else may write, and only when its own
  hash, the app's state, the program's hash and the rule pack all match. A
  damaged or foreign entry is a miss, and a miss is an ordinary read: the
  report is byte for byte the same with the cache, without it, and with a
  damaged one. A scan run as root keeps no cache. `--no-cache` turns it off.
- The summary on standard error names no app and no path. The checklist a
  scan prints when it writes the report to the default place does name apps:
  it is for the person at the terminal, and is printed only then.

### The one process the scanner starts

After a scan that wrote its report to the default place, and only when it
runs in a terminal, `exposure` hands the report to the system's opener
(`/usr/bin/open` on macOS, `xdg-open` elsewhere) so it shows in the browser.
That is the only process it ever starts: the path is the report it just
wrote, nothing that was scanned is ever run, and `--no-open` turns it off.
The ban on starting processes still holds everywhere else, and the
guardrails check that it bites.

### The build can be checked

- Dependencies are pinned by `Cargo.lock` and installed with `--locked`;
  `cargo deny` checks licences and advisories as well as bans.
- Two clean builds of one commit give the same binary, byte for byte
  (`cargo xtask repro`, run nightly on macOS and Linux), so a binary can be
  compared against one built from the published source.

## What is not protected

- **The user's own account.** Anything running as the user can read the
  report and the cache, as it can read the user's mail. Delete the report
  folder and the cache when they are no longer needed; both are safe to
  remove at any time.
- **A report someone passes on.** It lists apps the person uses. The page
  says so at its top; share a single finding (the dispute form asks for one
  claim and its records) rather than a whole report.
- **What a device cannot show.** What is sent, what servers share with each
  other, and data proxied through an app's own domain are out of reach of any
  scan of files; the report states these limits on every page.
- **An SDK without a rule, or one hidden well.** Heavily obfuscated code, an
  encrypted binary or JavaScript compiled to bytecode can keep an SDK from
  being recognised; what was set aside is listed under coverage. A clean
  report does not show an app is clean.
- **A compromised toolchain or maintainer key.** Reproducible builds let
  others check a binary against the source; they do not check the source.
  If the pack signing key is lost or leaked, a new key is made and the
  public key in the repository replaced, which needs a new build.
