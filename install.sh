#!/bin/sh
# factum installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/factum-rs/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/factum-rs/main/install.sh | sh -s -- --version v2.1.3
#
# Air-gapped: copy a release archive and SHA256SUMS to the machine, then
#   sh install.sh --archive factum-x86_64-unknown-linux-gnu.tar.gz
#
# Options:
#   --version TAG     install this release (default: the latest)
#   --dir DIR         install the binary here (default: ~/.local/bin, or /usr/local/bin as root)
#   --archive FILE    install from a downloaded archive instead of downloading (checked against the
#                     SHA256SUMS file next to it)
#   --cli             the command-line-only build (static, no GUI; Linux x86_64)
#   --no-desktop      do not add the GUI to the application menu (Linux)
#   --skip-verify     do not check the SHA-256 checksum (not recommended)
#   --uninstall       remove the binary and the menu entry; the database and seal files are kept
#
# Environment: FACTUM_REPO (default overcuriousity/factum-rs), FACTUM_INSTALL_DIR (like --dir).
set -eu

REPO="${FACTUM_REPO:-overcuriousity/factum-rs}"
VERSION=latest
DIR="${FACTUM_INSTALL_DIR:-}"
ARCHIVE=""
CLI=0
DESKTOP=1
VERIFY=1
UNINSTALL=0

say() { printf '%s\n' "factum-install: $*"; }
usage() {
    cat <<'USAGE'
usage: install.sh [--version TAG] [--dir DIR] [--archive FILE] [--cli] [--no-desktop] [--skip-verify] [--uninstall]
  --version TAG   install this release (default: the latest)
  --dir DIR       install the binary here (default: ~/.local/bin, or /usr/local/bin as root)
  --archive FILE  offline: install from a release archive, checked against the SHA256SUMS next to it
  --cli           the command-line-only build (static, no GUI; Linux x86_64)
  --no-desktop    do not add the GUI to the application menu (Linux)
  --skip-verify   do not check the SHA-256 checksum (not recommended)
  --uninstall     remove the binary and the menu entry; database and seal files are kept
USAGE
}
die() { printf '%s\n' "factum-install: error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a tag}"; shift 2 ;;
        --dir) DIR="${2:?--dir needs a folder}"; shift 2 ;;
        --archive) ARCHIVE="${2:?--archive needs a file}"; shift 2 ;;
        --cli) CLI=1; shift ;;
        --no-desktop) DESKTOP=0; shift ;;
        --skip-verify) VERIFY=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

if [ -z "$DIR" ]; then
    if [ "$(id -u)" = 0 ]; then DIR=/usr/local/bin; else DIR="$HOME/.local/bin"; fi
fi
if [ "$(id -u)" = 0 ]; then
    SHARE=/usr/local/share
else
    SHARE="${XDG_DATA_HOME:-$HOME/.local/share}"
fi

if [ "$UNINSTALL" = 1 ]; then
    rm -f "$DIR/factum" "$SHARE/applications/factum.desktop" "$SHARE/icons/hicolor/256x256/apps/factum.png"
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$SHARE/applications" >/dev/null 2>&1 || true
    say "removed $DIR/factum and the menu entry. Your database and seal files were not touched."
    exit 0
fi

# --- which build fits this machine
os=$(uname -s)
arch=$(uname -m)
case "$arch" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) die "unsupported CPU architecture $arch; build from source (see docs/AIRGAP.md)" ;;
esac
name=factum
case "$os" in
    Linux)
        # musl systems (Alpine) cannot run the glibc build; the static CLI build runs everywhere
        if ldd --version 2>&1 | grep -qi musl; then
            [ "$CLI" = 1 ] || say "musl libc detected: installing the command-line build (no GUI)"
            CLI=1
        fi
        if [ "$CLI" = 1 ]; then
            [ "$arch" = x86_64 ] || die "the command-line-only build is available for x86_64; build from source"
            name=factum-cli
            target=x86_64-unknown-linux-musl
            DESKTOP=0
        else
            target="$arch-unknown-linux-gnu"
        fi
        ;;
    Darwin)
        target="$arch-apple-darwin"
        DESKTOP=0
        ;;
    *) die "unsupported system $os; on Windows use install.ps1" ;;
esac
asset="$name-$target.tar.gz"

# --- tools
fetch() { # url file
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only "$1" -O "$2"
    else
        die "neither curl nor wget is installed"
    fi
}
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die "neither sha256sum nor shasum is installed (use --skip-verify at your own risk)"
    fi
}

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t factum)
trap 'rm -rf "$tmp"' EXIT INT TERM

if [ -n "$ARCHIVE" ]; then
    [ -f "$ARCHIVE" ] || die "$ARCHIVE does not exist"
    asset=$(basename "$ARCHIVE")
    sums="$(dirname "$ARCHIVE")/SHA256SUMS"
    cp "$ARCHIVE" "$tmp/$asset"
    if [ "$VERIFY" = 1 ]; then
        [ -f "$sums" ] || die "SHA256SUMS not found next to $ARCHIVE; copy it from the release too (or use --skip-verify)"
        cp "$sums" "$tmp/SHA256SUMS"
    fi
else
    if [ "$VERSION" = latest ]; then
        base="https://github.com/$REPO/releases/latest/download"
    else
        base="https://github.com/$REPO/releases/download/$VERSION"
    fi
    say "downloading $asset ($VERSION)"
    fetch "$base/$asset" "$tmp/$asset" || die "download of $base/$asset failed"
    if [ "$VERIFY" = 1 ]; then
        fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download of SHA256SUMS failed"
    fi
fi

if [ "$VERIFY" = 1 ]; then
    expected=$(grep "  $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
    [ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
    actual=$(sha256 "$tmp/$asset")
    [ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"
    say "checksum OK ($actual)"
fi

tar -xzf "$tmp/$asset" -C "$tmp"
src=$(find "$tmp" -mindepth 2 -maxdepth 2 -type f -name factum | head -n 1)
[ -n "$src" ] || die "the archive contains no factum binary"
mkdir -p "$DIR"
install -m 755 "$src" "$DIR/factum" 2>/dev/null || { cp "$src" "$DIR/factum" && chmod 755 "$DIR/factum"; }
say "installed $DIR/factum ($("$DIR/factum" --version 2>/dev/null || echo "version unknown"))"

if [ "$DESKTOP" = 1 ]; then
    share_src=$(dirname "$src")/share
    mkdir -p "$SHARE/applications" "$SHARE/icons/hicolor/256x256/apps"
    cp "$share_src/factum.png" "$SHARE/icons/hicolor/256x256/apps/factum.png"
    # Exec needs an absolute path: a launcher does not see ~/.local/bin on every desktop
    sed "s|^Exec=factum --gui|Exec=$DIR/factum --gui|" "$share_src/factum.desktop" > "$SHARE/applications/factum.desktop"
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$SHARE/applications" >/dev/null 2>&1 || true
    say "added Factum Notes to the application menu"
fi

case ":$PATH:" in
    *":$DIR:"*) ;;
    *) say "note: $DIR is not on your PATH; add it, e.g.: echo 'export PATH=\"$DIR:\$PATH\"' >> ~/.profile" ;;
esac
command -v gpg >/dev/null 2>&1 || say "note: gpg is not installed; notes can be written, but nothing is signed until it is"
say "done. Start the GUI with 'factum --gui', or see 'factum --help'."
