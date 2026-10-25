#!/usr/bin/env bash
# Run on a machine WITH internet access: downloads everything needed to install factum on air-gapped machines
# into one folder (and a .tar of it), and verifies the checksums before you carry it across.
#
#   scripts/airgap-download.sh [--version v2.0.0] [--target <target> ...] [--source] [--out DIR]
#
# Without --target, the archives for all platforms are downloaded. --source adds the vendored source archive
# (build from source offline, see docs/AIRGAP.md).
set -euo pipefail

repo=${FACTUM_REPO:-overcuriousity/factum-rs}
version=latest
out=""
source=0
targets=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --version) version=$2; shift 2 ;;
        --target) targets+=("$2"); shift 2 ;;
        --source) source=1; shift ;;
        --out) out=$2; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 1 ;;
    esac
done

if [[ $version == latest ]]; then
    version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | grep -m1 '"tag_name"' | cut -d'"' -f4)
fi
base="https://github.com/$repo/releases/download/$version"
out=${out:-factum-$version-airgap}
mkdir -p "$out"
cd "$out"

curl -fsSLO "$base/SHA256SUMS"
curl -fsSLO "$base/SHA256SUMS.asc" 2>/dev/null || echo "note: this release has no signed SHA256SUMS.asc"
curl -fsSLO "$base/install.sh"
curl -fsSLO "$base/install.ps1"
if [[ ${#targets[@]} -eq 0 ]]; then
    mapfile -t assets < <(cut -d' ' -f3 SHA256SUMS | grep -E '^factum(-cli)?-[a-z0-9_]+-.*\.(tar\.gz|zip)$' | grep -v vendored-source)
else
    assets=()
    for target in "${targets[@]}"; do
        assets+=("$(cut -d' ' -f3 SHA256SUMS | grep -E "^factum(-cli)?-$target\.(tar\.gz|zip)$")")
    done
fi
[[ $source == 1 ]] && assets+=("factum-${version#v}-vendored-source.tar.gz")
for asset in "${assets[@]}"; do
    echo "downloading $asset"
    curl -fsSLO "$base/$asset"
done
# only the files that were downloaded
grep -F -f <(printf '  %s\n' "${assets[@]}" install.sh install.ps1) SHA256SUMS | sha256sum -c -
cd ..
tar -cf "$out.tar" "$out"
echo "Ready: $out/ and $out.tar — carry it to the air-gapped machine and follow docs/AIRGAP.md."
