#!/bin/bash
# Zovark Update Bundle Builder
# Packages Docker images + migrations + templates → signed .zvk file
# Usage: ./build_bundle.sh 2.1.0 [--include-models]
set -euo pipefail

VERSION="${1:?Usage: $0 VERSION [--include-models]}"
INCLUDE_MODELS=false
[ "${2:-}" = "--include-models" ] && INCLUDE_MODELS=true

BUNDLE_DIR="bundles/v${VERSION}"
BUNDLE_FILE="zovark-update-v${VERSION}.zvk"
KEY_FILE="agent/keys/zovark_signing_key.pem"

echo "═══════════════════════════════════════"
echo "  ZOVARK BUNDLE BUILDER v${VERSION}"
echo "═══════════════════════════════════════"

mkdir -p "$BUNDLE_DIR"

# 1. Manifest
EXPIRES=$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "2026-07-01T00:00:00Z")

cat > "$BUNDLE_DIR/manifest.json" <<EOF
{
  "version": "$VERSION",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "builder": "$(whoami)@$(hostname)",
  "expires_at": "$EXPIRES",
  "components": {
    "api": "zovark-api:$VERSION",
    "worker": "zovark-worker:$VERSION",
    "dashboard": "zovark-dashboard:$VERSION"
  },
  "include_models": $INCLUDE_MODELS
}
EOF
echo "[1/6] Manifest created"

# 2. Docker images
echo "[2/6] Exporting Docker images..."
docker save zovark-api:latest | gzip > "$BUNDLE_DIR/api.tar.gz"
docker save zovark-worker:latest | gzip > "$BUNDLE_DIR/worker.tar.gz"
docker save zovark-dashboard:latest | gzip > "$BUNDLE_DIR/dashboard.tar.gz"
echo "  Images exported ($(du -sh "$BUNDLE_DIR"/*.tar.gz | awk '{sum+=$1}END{print sum}' 2>/dev/null || echo '?'))"

# 3. Migrations
echo "[3/6] Copying migrations..."
cp migrations/*.sql "$BUNDLE_DIR/" 2>/dev/null || echo "  No new migrations"

# 4. Templates (anonymized community templates)
echo "[4/6] Templates..."
mkdir -p "$BUNDLE_DIR/templates"
# Future: export anonymized templates from DB

# 5. Package
echo "[5/6] Packaging .zvk bundle..."
tar czf "$BUNDLE_FILE" -C "$BUNDLE_DIR" .
echo "  Bundle: $BUNDLE_FILE ($(du -h "$BUNDLE_FILE" | cut -f1))"

# 6. Sign
echo "[6/6] Signing..."
if [ -f "$KEY_FILE" ]; then
  HASH=$(sha256sum "$BUNDLE_FILE" | awk '{print $1}')
  echo -n "$HASH" | openssl pkeyutl -sign -inkey "$KEY_FILE" -rawin -out "${BUNDLE_FILE}.sig" 2>/dev/null
  echo "  Signed: ${BUNDLE_FILE}.sig"
  echo "  Hash: $HASH"
else
  echo "  WARNING: No signing key at $KEY_FILE — bundle unsigned"
  echo "  Generate: openssl genpkey -algorithm ED25519 -out $KEY_FILE"
fi

echo ""
echo "═══════════════════════════════════════"
echo "  Bundle: $BUNDLE_FILE"
echo "  Size: $(du -h "$BUNDLE_FILE" | cut -f1)"
[ -f "${BUNDLE_FILE}.sig" ] && echo "  Signature: ${BUNDLE_FILE}.sig"
echo "═══════════════════════════════════════"

# Cleanup
rm -rf "$BUNDLE_DIR"
