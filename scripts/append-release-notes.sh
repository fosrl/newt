#!/usr/bin/env bash
set -euo pipefail

: "${TAG:?}"
: "${GHCR_REF:?}"
: "${DIGEST:?}"

NOTES_FILE="$(mktemp)"

existing_body="$(gh release view "${TAG}" --json body --jq '.body')"
cat > "${NOTES_FILE}" <<EOF
${existing_body}

## Container Images
- GHCR: \`${GHCR_REF}\`
- Docker Hub: \`${DH_REF:-N/A}\`
**Digest:** \`${DIGEST}\`
EOF

gh release edit "${TAG}" --draft --notes-file "${NOTES_FILE}"

rm -f "${NOTES_FILE}"
