#!/usr/bin/env bash
set -euo pipefail

# Start dev servers for API + Web + Shared only
pnpm -r --parallel dev --filter infamous-freight-api --filter infamous-freight-web --filter @infamous-freight/shared
