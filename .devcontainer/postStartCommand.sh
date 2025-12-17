#!/usr/bin/env bash
set -euo pipefail

# Ensure Codex CLI is available in the devcontainer
if ! command -v codex >/dev/null 2>&1; then
  echo "Codex CLI not found. Installing @openai/codex globally..."
  if command -v sudo >/dev/null 2>&1; then
    sudo -n npm install -g @openai/codex || npm install -g @openai/codex
  else
    npm install -g @openai/codex
  fi
fi

# Print version for verification, do not fail the container startup if it errors
codex --version || true
