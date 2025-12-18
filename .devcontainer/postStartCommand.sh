#!/usr/bin/env bash
set -euo pipefail

# Ensure Codex CLI is available in the devcontainer (optional, fail open)
if command -v npm >/dev/null 2>&1; then
  if ! command -v codex >/dev/null 2>&1; then
    echo "Codex CLI not found. Installing @openai/codex globally..."
    npm install -g @openai/codex 2>/dev/null || true
  fi
  codex --version 2>/dev/null || true
else
  echo "ℹ npm not available; skipping Codex CLI install"
fi
