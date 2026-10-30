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
have_asc=1
curl -fsSLO "$base/SHA256SUMS.asc" 2>/dev/null || { have_asc=0; echo "warning: this release has no signed SHA256SUMS.asc; only integrity, not authenticity, can be checked"; }
# a bad signature stops here; no gpg or no release key in the keyring only warns (no key is ever fetched)
if [[ $have_asc == 1 ]]; then
    if ! command -v gpg >/dev/null 2>&1; then
        echo "warning: gpg is not installed; SHA256SUMS.asc was not checked, only integrity, not authenticity"
    else
        status=$(gpg --batch --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null || true)
        if grep -q '^\[GNUPG:\] \(BADSIG\|EXPSIG\|EXPKEYSIG\|REVKEYSIG\) ' <<<"$status"; then
            echo "error: the signature on SHA256SUMS is bad, expired or from a revoked key" >&2; exit 1
        elif grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status"; then
            echo "signature on SHA256SUMS is good; make sure that key is the release key you trust"
        elif grep -q '^\[GNUPG:\] \(NO_PUBKEY\|ERRSIG\) ' <<<"$status"; then
            echo "warning: the release key is not in your keyring; only integrity, not authenticity, was checked"
        else
            echo "error: SHA256SUMS.asc could not be checked with gpg" >&2; exit 1
        fi
    fi
fi
curl -fsSLO "$base/install.sh"
curl -fsSLO "$base/install.ps1"
if [[ ${#targets[@]} -eq 0 ]]; then
    mapfile -t assets < <(cut -d' ' -f3 SHA256SUMS | grep -E '^factum(-cli)?-[a-z0-9_]+-.*\.(tar\.gz|zip)$' | grep -v vendored-source || true)
    [[ ${#assets[@]} -gt 0 ]] || { echo "error: SHA256SUMS lists no release archives" >&2; exit 1; }
else
    assets=()
    for target in "${targets[@]}"; do
        mapfile -t found < <(cut -d' ' -f3 SHA256SUMS | grep -E "^factum(-cli)?-$target\.(tar\.gz|zip)$" || true)
        [[ ${#found[@]} -gt 0 ]] || { echo "error: no archive for target '$target' in SHA256SUMS" >&2; exit 1; }
        assets+=("${found[@]}")
    done
fi
[[ $source == 1 ]] && assets+=("factum-${version#v}-vendored-source.tar.gz")
for asset in "${assets[@]}"; do
    echo "downloading $asset"
    curl -fsSLO "$base/$asset"
done
# every downloaded file must be listed in SHA256SUMS and match; a file that is not listed is an error
: > downloaded.sums
for f in "${assets[@]}" install.sh install.ps1; do
    line=$(awk -v f="$f" '$2 == f || $2 == "*" f' SHA256SUMS | head -n 1)
    [[ -n $line ]] || { echo "error: $f is not listed in SHA256SUMS" >&2; exit 1; }
    printf '%s\n' "$line" >> downloaded.sums
done
sha256sum -c downloaded.sums
rm -f downloaded.sums
cd ..
tar -cf "$out.tar" "$out"
echo "Ready: $out/ and $out.tar — carry it to the air-gapped machine and follow docs/AIRGAP.md."
