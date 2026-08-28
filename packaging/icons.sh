#!/bin/sh
# Re-render the PNG icons from the SVG. Run after changing the SVG.
#
# The PNGs are committed rather than generated at build time because Flathub
# builds offline and its AppStream step needs an icon it can read without an
# SVG loader, which the freedesktop SDK does not have.
set -eu
cd "$(dirname "$0")/../crates/rpgp-gui/desktop"
for size in 64 128 256; do
    rsvg-convert -w "$size" -h "$size" app.rpgp.rpgp.svg -o "app.rpgp.rpgp-$size.png"
done

# Windows wants one .ico carrying every size it might ask for: 16 for the title
# bar, 32 for the taskbar, 48 for Explorer's medium view, 256 for the large one.
# Committed for the same reason the PNGs are — the Windows runner has no SVG
# loader, and adding one to get an icon would be a poor trade.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
rsvg-convert -w 256 -h 256 app.rpgp.rpgp.svg -o "$tmp/icon.png"
python3 -c "
from PIL import Image
Image.open('$tmp/icon.png').convert('RGBA').save(
    'app.rpgp.rpgp.ico', format='ICO',
    sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
"

echo "rendered 64, 128 and 256 px icons and app.rpgp.rpgp.ico from app.rpgp.rpgp.svg"
