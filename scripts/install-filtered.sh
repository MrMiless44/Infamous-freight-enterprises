#!/usr/bin/env bash
set -euo pipefail

# Install only API, Web, and Shared to avoid mobile native postinstall issues
echo "Using pnpm version: $(pnpm -v || true)"

pnpm install --filter @infamous-freight/shared --filter infamous-freight-api --filter infamous-freight-web

echo "Install complete for shared, api, and web."