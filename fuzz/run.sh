#!/bin/sh
# Runs every fuzz target for a number of seconds (60 unless given), starting
# from the committed fixture package and app bundle and their parts, from the
# manifests of the committed fixture extensions, and from the binaries,
# property lists and asar archive of the committed fixture app bundles. The
# resource table of an APK has no committed seed: its target starts from
# nothing.
#
#   fuzz/run.sh [SECONDS]
#
# Needs cargo-fuzz and the nightly toolchain pinned in rust-toolchain.toml
# next to this script; see README.md.
set -eu

seconds="${1:-60}"
cd "$(dirname "$0")"

fixture=../tests/fixtures/android/Skeleton.apk
seeds=target/seeds
rm -rf "$seeds"
bundle=../tests/fixtures/android/Skeleton.aab
mkdir -p "$seeds/zip" "$seeds/apk" "$seeds/dex" "$seeds/android_manifest" \
    "$seeds/extension_manifest" "$seeds/android_resources" "$seeds/android_proto" \
    "$seeds/macho" "$seeds/codesign" "$seeds/plist" "$seeds/asar"
cp "$fixture" "$seeds/zip/"
cp "$fixture" "$seeds/apk/"
cp "$bundle" "$seeds/apk/"
unzip -q -j "$bundle" base/manifest/AndroidManifest.xml base/resources.pb -d "$seeds/android_proto"
unzip -q "$fixture" 'classes*.dex' -d "$seeds/dex"
unzip -q "$fixture" AndroidManifest.xml -d "$seeds/android_manifest"
extensions=../tests/fixtures/browser/Extensions
n=0
for file in "$extensions"/*/*/manifest.json "$extensions"/*/*/_locales/*/messages.json; do
    n=$((n + 1))
    cp "$file" "$seeds/extension_manifest/$n.json"
done

# The macOS readers. The Mach-O and signature targets take the size of the
# pieces they are fed in as their first byte: each binary is a seed twice,
# read in one piece of 255 bytes at a time and one byte at a time.
bundles=../tests/fixtures/macos
n=0
find "$bundles" -type f -path '*/Contents/*' ! -name '*.plist' ! -name '*.asar' ! -name '*.json' |
    while IFS= read -r file; do
        n=$((n + 1))
        for step in 377 001; do
            { printf "\\$step"; cat "$file"; } > "$seeds/macho/$n-$step"
            cp "$seeds/macho/$n-$step" "$seeds/codesign/$n-$step"
        done
    done
n=0
find "$bundles" -type f \( -name '*.plist' -o -name '*.xcprivacy' \) | while IFS= read -r file; do
    n=$((n + 1))
    cp "$file" "$seeds/plist/$n.plist"
done
n=0
find "$bundles" -type f -name '*.asar' | while IFS= read -r file; do
    n=$((n + 1))
    cp "$file" "$seeds/asar/$n.asar"
done

# Build for the compiler's own host. cargo-fuzz defaults to the triple it was
# built for, and its prebuilt Linux binary is a musl one: that target is not
# installed and cannot carry the address sanitizer.
host="$(rustc -vV | sed -n 's/^host: //p')"

for target in zip dex android_manifest android_resources android_proto apk extension_manifest \
    macho codesign plist asar; do
    mkdir -p "corpus/$target"
    echo "== $target: $seconds s"
    cargo fuzz run --target "$host" "$target" "corpus/$target" "$seeds/$target" -- \
        -max_total_time="$seconds" -print_final_stats=1
done
