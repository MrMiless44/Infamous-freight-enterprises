#!/usr/bin/env bash
# Check for npm/yarn lockfiles that should not be committed
# This project uses pnpm only - package-lock.json and yarn.lock are not allowed

set -euo pipefail

echo "🔍 Checking for disallowed lockfiles..."

# Check for package-lock.json files
if [ -f "package-lock.json" ]; then
  echo "❌ Error: package-lock.json found in repository root"
  echo "   This project uses pnpm. Please remove it and run: pnpm install"
  exit 1
fi

# Check for any tracked package-lock.json files
if git ls-files '**/package-lock.json' | grep -q .; then
  echo "❌ Error: package-lock.json files found in repository:"
  git ls-files '**/package-lock.json'
  echo "   This project uses pnpm. Please remove them and run: pnpm install"
  exit 1
fi

# Check for yarn.lock files
if [ -f "yarn.lock" ]; then
  echo "❌ Error: yarn.lock found in repository root"
  echo "   This project uses pnpm. Please remove it and run: pnpm install"
  exit 1
fi

# Check for any tracked yarn.lock files
if git ls-files '**/yarn.lock' | grep -q .; then
  echo "❌ Error: yarn.lock files found in repository:"
  git ls-files '**/yarn.lock'
  echo "   This project uses pnpm. Please remove them and run: pnpm install"
  exit 1
fi

# Check for npm-shrinkwrap.json
if [ -f "npm-shrinkwrap.json" ]; then
  echo "❌ Error: npm-shrinkwrap.json found in repository root"
  echo "   This project uses pnpm. Please remove it."
  exit 1
fi

# Check for any tracked npm-shrinkwrap.json files
if git ls-files '**/npm-shrinkwrap.json' | grep -q .; then
  echo "❌ Error: npm-shrinkwrap.json files found in repository"
  echo "   This project uses pnpm. Please remove them."
  exit 1
fi

# Verify pnpm-lock.yaml exists
if [ ! -f "pnpm-lock.yaml" ]; then
  echo "⚠️  Warning: pnpm-lock.yaml not found"
  echo "   Run: pnpm install"
  exit 1
fi

echo "✅ Lockfile check passed - only pnpm-lock.yaml present"
exit 0
