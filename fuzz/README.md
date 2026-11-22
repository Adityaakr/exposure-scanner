# Fuzz targets

The parsers in `xs-formats` read files built by whoever ships an app, so
each one that the Android collector uses has a libFuzzer target here, and
the collector has one for the whole path from bytes to records. So do the
reader of browser extension manifests and the readers a macOS app reaches
first: Mach-O, code signatures, property lists and asar archives. The macOS
collector as a whole has none yet: it reads files from disk, and has no
entry point for bytes in memory.

| Target | What it drives | What it asserts beyond "does not crash" |
|---|---|---|
| `zip` | End record, central directory, local headers, inflate | The directory lies inside the file; nothing inflates past the budget or past its declared size |
| `dex` | Header, string table, type table, class definitions | Neither walk hands out more string bytes than the file holds |
| `android_manifest` | Chunks, string pool in both encodings, resource map, attributes | Text taken from the string pool stays within its budget |
| `android_resources` | The lookup of a string in `resources.arsc`: chunks, type chunks in every entry layout, plain and compact entries, chains of references | The text it gives stays within its budget |
| `android_proto` | An app bundle's protocol buffers: the manifest and the lookup of a string in `resources.pb` | Text taken from either stays within its budget |
| `apk` | The Android collector on a package (an APK or an app bundle) in memory, with the signed built-in rule pack | The scan succeeds; every record is valid, has an id, and carries the hash of the input; there is exactly one artifact record |
| `extension_manifest` | Comment blanking, the lenient manifest reader, message catalogues, site patterns | What a manifest keeps stays within its entry budget, and a kept locale is one safe path component |
| `macho` | The Mach-O walker over load commands, sections and universal slices, fed in pieces whose size is the input's first byte, and the reader of names in string tables | The spans of an image are in order, apart and inside the image; no name is over its budget |
| `codesign` | The code signature reader, fed in pieces whose size is the input's first byte, and the entitlements reader | A Team ID and the list of entitlements stay within their budgets |
| `plist` | `Info.plist` and privacy manifests, XML or binary | A privacy manifest keeps no more domains than its budget |
| `asar` | An Electron archive's prefix and JSON header, and the path of every entry | A header lists no more entries than its budget |

## Running

```console
$ cargo install cargo-fuzz --version 0.13.2 --locked
$ fuzz/run.sh 60        # every target for 60 s
```

`run.sh` seeds each target from the committed fixture package and app
bundle (`tests/fixtures/android/Skeleton.apk` and `Skeleton.aab`) and their
parts, the manifest
target from the committed extensions (`tests/fixtures/browser/`), and the
macOS targets from the binaries, property lists and asar archive of the
committed app bundles (`tests/fixtures/macos/`), and keeps what
libFuzzer finds in `fuzz/corpus/`, which is not committed. A crash leaves
its input in `fuzz/artifacts/<target>/`; `cargo fuzz run <target> <file>`
from this folder replays it.

The targets need a nightly compiler for the sanitizer. It is pinned in
`rust-toolchain.toml` in this folder and rustup selects it for commands run
from here; the scanner itself builds with the stable toolchain pinned at the
repository root. This package is a workspace of its own, so neither the
nightly toolchain nor the libFuzzer runtime can reach the scanner's lock
file or its dependency checks.

CI runs `fuzz/run.sh 60` on every change.
