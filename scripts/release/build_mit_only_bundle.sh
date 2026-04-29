#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUTPUT_DIR="${1:-dist/release}"
VERSION_TAG="${2:-$(git rev-parse --short HEAD)}"
BUNDLE_NAME="cmsoc-mit-${VERSION_TAG}"
BUNDLE_DIR="${OUTPUT_DIR}/${BUNDLE_NAME}"
ARCHIVE_PATH="${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"

echo "[INFO] Root: $ROOT_DIR"
echo "[INFO] Output dir: $OUTPUT_DIR"
echo "[INFO] Bundle: $BUNDLE_NAME"

rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"
mkdir -p "$OUTPUT_DIR"

# Copy repository content while excluding EE-licensed directories and local git metadata.
rsync -a \
  --exclude ".git" \
  --exclude ".github" \
  --exclude ".venv" \
  --exclude "venv" \
  --exclude "web/node_modules" \
  --exclude "backend/.pytest_cache" \
  --exclude "**/__pycache__" \
  --exclude ".next" \
  --exclude "dist" \
  --exclude "tmp" \
  --exclude "backend/ee" \
  --exclude "web/src/app/ee" \
  --exclude "web/src/ee" \
  ./ "$BUNDLE_DIR"/

# Add a lightweight manifest to make release scope explicit.
cat > "${BUNDLE_DIR}/MIT_RELEASE_SCOPE.txt" <<'EOF'
This package is built as a MIT-only distribution of the repository.

Excluded from this bundle:
- backend/ee
- web/src/app/ee
- web/src/ee

Refer to LICENSE in the root of this bundle for mixed-license definitions.
This artifact intentionally contains only non-EE paths.
EOF

tar -czf "$ARCHIVE_PATH" -C "$OUTPUT_DIR" "$BUNDLE_NAME"

echo "[PASS] MIT-only bundle created: $ARCHIVE_PATH"
