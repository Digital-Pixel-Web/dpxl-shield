#!/usr/bin/env bash
#
# Builds the production zip for DPXL Shield.
#
# Replaces the manual build steps: installs production dependencies, trims the
# Dompdf font bundle, drops dev-only files, and zips the plugin folder into the
# parent directory ("ShieldWP - Digital Pixel").
#
# The working tree is left untouched — everything happens in a staging copy —
# so this is safe to run at any time, and a later `composer install` cannot
# silently undo the trim the way editing vendor/ by hand would.
#
# Usage:  tools/build-zip.sh [--force]
#
#   --force  overwrite an existing zip for this version. Without it the build
#            refuses, so a already-released artifact is never clobbered by a
#            run that forgot to bump DPXL_SHIELD_VERSION.
set -euo pipefail

FORCE=0
if [[ "${1:-}" == "--force" ]]; then
    FORCE=1
fi

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT_DIR="$(dirname "$PLUGIN_DIR")"
PLUGIN_SLUG="$(basename "$PLUGIN_DIR")"

VERSION="$(grep -m1 -E '^\s*\*\s*Version:' "$PLUGIN_DIR/dpxl-shield.php" | sed -E 's/.*Version:[[:space:]]*//' | tr -d '[:space:]')"

if [[ -z "$VERSION" ]]; then
    echo "error: could not read Version from dpxl-shield.php" >&2
    exit 1
fi

ZIP_PATH="$PARENT_DIR/$PLUGIN_SLUG-$VERSION.zip"

if [[ -e "$ZIP_PATH" && "$FORCE" -eq 0 ]]; then
    echo "error: $ZIP_PATH already exists." >&2
    echo "       Bump the version in dpxl-shield.php, or re-run with --force to overwrite." >&2
    exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

DEST="$STAGE/$PLUGIN_SLUG"

echo "==> Building $PLUGIN_SLUG $VERSION"

# ── 0. Gate: the source must stay within the PHP 7.4 floor ───────────────────
# The dev machine runs PHP 8.x, so nothing else would catch a stray match() or
# promoted property before it shipped to a 7.4 host and fataled there.
echo "==> Checking PHP 7.4 compatibility"
php "$PLUGIN_DIR/tools/check-php74.php" \
    "$PLUGIN_DIR/src" \
    "$PLUGIN_DIR/dpxl-shield.php" \
    "$PLUGIN_DIR/dpxl-shield-waf.php" \
    "$PLUGIN_DIR/uninstall.php"

# ── 1. Copy the plugin into staging, excluding everything dev-only ──────────
# vendor/ is deliberately excluded here and rebuilt below with --no-dev, so a
# dev vendor tree can never leak into a release.
#
# Every directory pattern is ANCHORED with a leading slash, so it matches only
# at the plugin root. An unanchored 'tools/' also matches src/Admin/Views/tools/
# — which silently stripped all five Tools tab views out of the 1.4.0 build.
rsync -a \
    --exclude '/.git/' \
    --exclude '/.github/' \
    --exclude '/.*/' \
    --exclude '/tests/' \
    --exclude '/tools/' \
    --exclude '/docs/' \
    --exclude '/vendor/' \
    --exclude '/node_modules/' \
    --exclude '/.gitignore' \
    --exclude '/phpunit.xml' \
    --exclude '/.phpunit.cache/' \
    --exclude '/.phpunit.result.cache' \
    --exclude '/data/*.mmdb' \
    --exclude '/data/blocked-ips.php' \
    --exclude '/data/early-config.php' \
    --exclude '*.zip' \
    --exclude '.DS_Store' \
    "$PLUGIN_DIR/" "$DEST/"

# ── 2. Production dependencies ───────────────────────────────────────────────
# composer.lock is copied into staging on purpose: `install` then reproduces the
# exact versions that were tested, instead of resolving fresh at build time. The
# lock is dropped from the zip afterwards; composer.json stays, because the
# WordPress.org review (and Plugin Check) expect it next to a vendor/ folder.
echo "==> composer install (--no-dev)"
composer install \
    --working-dir="$DEST" \
    --no-dev \
    --optimize-autoloader \
    --classmap-authoritative \
    --no-interaction \
    --quiet

rm -f "$DEST/composer.lock"

# ── 3. Trim the Dompdf font bundle ───────────────────────────────────────────
# The PDF report renders with 'DejaVu Sans', sans-serif (src/Alerts/PdfReport.php).
# DejaVu Serif and DejaVu Sans Mono are never referenced: the generic serif and
# monospace families resolve to the built-in AFM core fonts (Times / Courier),
# which are a few KB each. Verified by rendering the report's font stack with
# and without them — byte-identical output.
#
# The manifest entries are removed alongside the files, so nothing can resolve
# to a font that is no longer on disk.
FONT_DIR="$DEST/vendor/dompdf/dompdf/lib/fonts"

if [[ -d "$FONT_DIR" ]]; then
    before="$(du -sk "$FONT_DIR" | cut -f1)"

    rm -f "$FONT_DIR"/DejaVuSerif* "$FONT_DIR"/DejaVuSansMono*

    php -r '
        $path = $argv[1];
        $fonts = json_decode(file_get_contents($path), true);
        if (!is_array($fonts)) { fwrite(STDERR, "error: unreadable font manifest\n"); exit(1); }
        unset($fonts["dejavu serif"], $fonts["dejavu sans mono"]);
        file_put_contents($path, json_encode($fonts, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    ' "$FONT_DIR/installed-fonts.dist.json"

    after="$(du -sk "$FONT_DIR" | cut -f1)"
    echo "==> Fonts trimmed: $((before / 1024)) MB -> $((after / 1024)) MB"
fi

# ── 4. Verify the staged tree before zipping ─────────────────────────────────
# An over-broad rsync exclude once stripped every Tools tab view out of a build
# and the zip still looked healthy from the outside. Nothing ships now unless
# each PHP file the plugin loads at runtime is actually present.
echo "==> Verifying staged tree"

missing=0

# Every admin view must survive — these are require'd by path, so a missing one
# is not a fatal error, just a silently broken tab.
while IFS= read -r view; do
    relative="${view#"$PLUGIN_DIR/"}"

    if [[ ! -f "$DEST/$relative" ]]; then
        echo "  MISSING: $relative" >&2
        missing=$((missing + 1))
    fi
done < <(find "$PLUGIN_DIR/src/Admin/Views" -name '*.php')

# Spot-check the rest of the runtime surface.
for required in \
    dpxl-shield.php \
    dpxl-shield-waf.php \
    uninstall.php \
    readme.txt \
    vendor/symfony/polyfill-php80/bootstrap.php \
    src/Bootstrap/Loader.php \
    vendor/autoload.php \
    assets/js/admin.js \
    assets/css/admin.css \
    rules/waf-rules.json
do
    if [[ ! -e "$DEST/$required" ]]; then
        echo "  MISSING: $required" >&2
        missing=$((missing + 1))
    fi
done

# And the dev-only trees must NOT be there.
for forbidden in tests tools composer.lock phpunit.xml .git; do
    if [[ -e "$DEST/$forbidden" ]]; then
        echo "  LEAKED: $forbidden" >&2
        missing=$((missing + 1))
    fi
done

if [[ "$missing" -gt 0 ]]; then
    echo "error: $missing problem(s) in the staged tree — not packaging." >&2
    exit 1
fi

src_count="$(find "$PLUGIN_DIR/src" -name '*.php' | wc -l | tr -d ' ')"
dst_count="$(find "$DEST/src" -name '*.php' | wc -l | tr -d ' ')"

if [[ "$src_count" != "$dst_count" ]]; then
    echo "error: src/ has $src_count PHP files but the build staged $dst_count." >&2
    exit 1
fi

echo "==> OK: $dst_count PHP files under src/, all views present"

# ── 5. Zip ───────────────────────────────────────────────────────────────────
rm -f "$ZIP_PATH"
( cd "$STAGE" && zip -rq "$ZIP_PATH" "$PLUGIN_SLUG" -x '*.DS_Store' )

echo "==> $ZIP_PATH ($(du -h "$ZIP_PATH" | cut -f1))"
