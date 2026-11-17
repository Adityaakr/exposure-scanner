#!/bin/sh
# Runs every fuzz target for a number of seconds (60 unless given), starting
# from the committed fixture package and its parts.
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
mkdir -p "$seeds/zip" "$seeds/apk" "$seeds/dex" "$seeds/android_manifest"
cp "$fixture" "$seeds/zip/"
cp "$fixture" "$seeds/apk/"
unzip -q "$fixture" 'classes*.dex' -d "$seeds/dex"
unzip -q "$fixture" AndroidManifest.xml -d "$seeds/android_manifest"

for target in zip dex android_manifest apk; do
    mkdir -p "corpus/$target"
    echo "== $target: $seconds s"
    cargo fuzz run "$target" "corpus/$target" "$seeds/$target" -- \
        -max_total_time="$seconds" -print_final_stats=1
done
