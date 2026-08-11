#!/usr/bin/env bash
#
# Builds a distributable ZIP of the WP-Agent plugin.
#
# Usage: ./build.sh [version]
#   - version: optional; if omitted it is read from wp-agent.php.
#
# Output: dist/wp-agent-<version>.zip (a folder named "wp-agent/" inside).
#
set -euo pipefail

cd "$(dirname "$0")"

PLUGIN="wp-agent"
MAIN="${PLUGIN}.php"

if [[ ! -f "${MAIN}" ]]; then
	echo "ERROR: ${MAIN} not found. Run this script from the plugin root." >&2
	exit 1
fi

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
	VERSION="$(sed -n 's/^ \* Version:[[:space:]]*\([0-9][0-9.]*\).*/\1/p' "${MAIN}" | head -n1)"
fi
if [[ -z "${VERSION}" ]]; then
	VERSION="$(sed -n "s/^define( 'WPA_VERSION', '\([0-9][0-9.]*\)' );.*/\1/p" "${MAIN}" | head -n1)"
fi
if [[ -z "${VERSION}" ]]; then
	echo "ERROR: could not determine plugin version." >&2
	exit 1
fi

echo "Building ${PLUGIN} ${VERSION}..."

rm -rf dist
mkdir -p dist

# Staging dir that mirrors the plugin slug, so WordPress picks it up as-is.
STAGE="dist/${PLUGIN}"
mkdir -p "${STAGE}"

# Copy the plugin, excluding repo/build artifacts.
cp -r "${MAIN}" README.md uninstall.php includes assets "${STAGE}/"
rm -rf "${STAGE}/includes/.DS_Store" "${STAGE}/assets/.DS_Store"

ZIP="dist/${PLUGIN}-${VERSION}.zip"
( cd dist && zip -rq "${PLUGIN}-${VERSION}.zip" "${PLUGIN}" )

echo "Done: ${ZIP}"
