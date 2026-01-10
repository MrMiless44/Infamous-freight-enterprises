#!/usr/bin/env bash
set -euo pipefail

# Deploy performance indexes for the API database
# Usage: DATABASE_URL="postgres://..." ./scripts/deploy-indexes.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SQL_FILE="${ROOT_DIR}/src/apps/api/prisma/migrations/20260110_add_performance_indexes.sql"

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL is required" >&2
  exit 1
fi

if [[ ! -f "$SQL_FILE" ]]; then
  echo "Migration file not found: $SQL_FILE" >&2
  exit 1
fi

echo "Applying performance indexes from ${SQL_FILE}" >&2
psql "$DATABASE_URL" -f "$SQL_FILE"

echo "Index deployment complete." >&2
