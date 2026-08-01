#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
deps_root=${1:-"$repo_root/build/_deps"}

if [[ -z "$deps_root" || "$deps_root" == "/" || "$deps_root" == "." || "$deps_root" == ".." ]]; then
  printf 'unsafe dependency directory: %s\n' "$deps_root" >&2
  exit 1
fi

for command in curl flock sha256sum tar python3 find; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 1
  }
done

zydis_url="https://codeload.github.com/zyantific/zydis/tar.gz/refs/tags/v4.1.1"
zydis_sha256="45c6d4d499a1cc80780f7834747c637509777c01dca1e98c5e7c0bfaccdb1514"
zycore_url="https://codeload.github.com/zyantific/zycore-c/tar.gz/0b2432ced0884fd152b471d97ecf0258ff4d859f"
zycore_sha256="698e4623e661db312eb9da327519f53f0a9dd7fbbfacf02159687bca62369467"

mkdir -p -- "$(dirname -- "$deps_root")"
exec 9>"${deps_root}.lock"
flock 9

if [[ -f "$deps_root/.ready" ]] &&
   grep -qF "$zydis_sha256" "$deps_root/.ready" &&
   grep -qF "$zycore_sha256" "$deps_root/.ready"; then
  exit 0
fi

stage=$(mktemp -d "$(dirname -- "$deps_root")/.vaporhook-deps.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT

fetch_and_extract() {
  local name=$1
  local url=$2
  local expected=$3
  local archive="$stage/$name.tar.gz"
  local unpack="$stage/$name-unpack"

  curl --fail --location --silent --show-error --retry 3 --output "$archive" "$url"
  printf '%s  %s\n' "$expected" "$archive" | sha256sum --check --status
  mkdir -p -- "$unpack"
  tar -xzf "$archive" --strip-components=1 --directory "$unpack"
}

fetch_and_extract zydis "$zydis_url" "$zydis_sha256"
fetch_and_extract zycore "$zycore_url" "$zycore_sha256"

mkdir -p -- "$stage/zydis-unpack/dependencies/zycore"
find "$stage/zycore-unpack" -mindepth 1 -maxdepth 1 -exec mv -- {} "$stage/zydis-unpack/dependencies/zycore/" \;
(
  cd -- "$stage/zydis-unpack"
  python3 assets/amalgamate.py >/dev/null
)

test -f "$stage/zydis-unpack/amalgamated-dist/Zydis.h"
test -f "$stage/zydis-unpack/amalgamated-dist/Zydis.c"

{
  printf 'zydis v4.1.1 %s\n' "$zydis_sha256"
  printf 'zycore 0b2432ced0884fd152b471d97ecf0258ff4d859f %s\n' "$zycore_sha256"
} > "$stage/zydis-unpack/.ready"

old="${deps_root}.old.$$"
if [[ -e "$deps_root" ]]; then
  mv -- "$deps_root" "$old"
fi
mv -- "$stage/zydis-unpack" "$deps_root"
rm -rf -- "$old"
