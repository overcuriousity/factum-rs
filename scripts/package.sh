#!/usr/bin/env bash
# Packages a built binary as a release archive: <name>-<target>.tar.gz (or .zip for Windows) in <out-dir>.
#
#   scripts/package.sh <target> <path-to-binary> <name: factum|factum-cli> <out-dir>
set -euo pipefail

target=$1 binary=$2 name=$3 out=$4
root=$(cd "$(dirname "$0")/.." && pwd)
version=$(grep -m1 '^version' "$root/Cargo.toml" | cut -d'"' -f2)
stage=$(mktemp -d)
dir="$stage/$name-$version-$target"
mkdir -p "$dir/licenses" "$dir/share" "$out"

exe=factum
[[ $target == *windows* ]] && exe=factum.exe
cp "$binary" "$dir/$exe"
cp "$root/README.md" "$root/LICENSE" "$root/CHANGELOG.md" "$root/.env.example" "$dir/"
cp "$root/install.sh" "$root/install.ps1" "$dir/"
cp "$root"/assets/fonts/OFL-*.txt "$root/assets/fonts/LICENSE-Phosphor.txt" "$dir/licenses/"
[[ -f $root/THIRD-PARTY-LICENSES.md ]] && cp "$root/THIRD-PARTY-LICENSES.md" "$dir/licenses/"
cp "$root/assets/icon.png" "$dir/share/factum.png"
cp "$root/packaging/factum.desktop" "$dir/share/factum.desktop"

out=$(cd "$out" && pwd)
if [[ $target == *windows* ]]; then
    archive="$out/$name-$target.zip"
    if command -v 7z >/dev/null 2>&1; then
        # 7z on Windows runners is a native program: it needs a Windows path
        native=$archive
        command -v cygpath >/dev/null 2>&1 && native=$(cygpath -w "$archive")
        (cd "$stage" && 7z a -tzip -bso0 "$native" "$(basename "$dir")")
    else
        (cd "$stage" && zip -qr "$archive" "$(basename "$dir")")
    fi
else
    archive="$out/$name-$target.tar.gz"
    tar -C "$stage" -czf "$archive" "$(basename "$dir")"
fi
rm -rf "$stage"
echo "$archive"
