#!/bin/sh
# Writes assets/fonts/Phosphor-Regular-subset.ttf with only the icons src/gui/icons.rs uses.
# Phosphor.ttf: src/regular/Phosphor.ttf of the @phosphor-icons/web npm package. Needs fonttools (pyftsubset).
set -eu
[ $# -eq 1 ] || { echo "usage: $0 path/to/Phosphor.ttf" >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
unicodes=$(grep -o '\\u{[0-9a-f]*}' "$root/src/gui/icons.rs" | tr -d '\\u{}' | sed 's/^/U+/' | paste -sd, -)
pyftsubset "$1" --unicodes="$unicodes" --no-hinting --desubroutinize --layout-features='' \
    --output-file="$root/assets/fonts/Phosphor-Regular-subset.ttf"
echo "assets/fonts/Phosphor-Regular-subset.ttf: $(echo "$unicodes" | tr ',' '\n' | wc -l) icons"
