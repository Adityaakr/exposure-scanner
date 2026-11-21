#!/bin/sh
# Builds the website into a folder ready to publish.
#
#   site/build.sh OUT        copy the site to OUT and write OUT/sample/ afresh
#   site/build.sh --sample   write site/sample/ afresh, in place
#
# The sample report is not written by hand: this script builds `exposure`
# from this checkout and scans the synthetic apps in tests/fixtures with it,
# so the report on the site is what the code it was built from writes. A
# scan of the same fixtures with the same rule pack gives the same bytes, so
# a committed sample that differs from a fresh one is out of date.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
site="$root/site"

usage() {
  echo "usage: site/build.sh OUT | --sample" >&2
  exit 2
}
[ $# -eq 1 ] || usage

case "$1" in
  --sample) out="$site" ;;
  -*) usage ;;
  *)
    mkdir -p -- "$1"
    out=$(CDPATH= cd -- "$1" && pwd)
    case "$out" in
      "$site" | "$site"/*) echo "site/build.sh: OUT must be outside site/" >&2; exit 2 ;;
    esac
    # Everything the site serves; the tooling beside it stays behind.
    for entry in "$site"/*; do
      case "${entry##*/}" in
        build.sh | check.py | README.md) ;;
        *) cp -R -- "$entry" "$out/" ;;
      esac
    done
    ;;
esac

cargo build --release --locked --quiet --package exposure --manifest-path "$root/Cargo.toml"
exposure="$root/target/release/exposure"

fixtures="$root/tests/fixtures"
mkdir -p -- "$out/sample"
rm -f -- "$out/sample/report.html" "$out/sample/report.json"
"$exposure" scan --no-open --no-cache \
  --html "$out/sample/report.html" --json "$out/sample/report.json" \
  "$fixtures/macos/Skeleton.app" \
  "$fixtures/macos/ElectronSkeleton.app" \
  "$fixtures/android/Skeleton.apk" \
  "$fixtures/browser/Extensions" \
  "$fixtures/browser/addon@example.org.xpi"
# The scanner writes reports readable by their owner only; these are public.
chmod 0644 "$out/sample/report.html" "$out/sample/report.json"
