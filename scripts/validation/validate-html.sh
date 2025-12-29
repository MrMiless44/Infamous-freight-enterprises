#!/usr/bin/env bash
set -euo pipefail

# HTML validation script using HTML Tidy
# Validates top-level HTML files in the repository

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

echo "🔍 Searching for top-level HTML files..."

# Find top-level HTML files (maxdepth 1) with same exclusions as CI workflow
mapfile -t HTML_FILES < <(find . -maxdepth 1 -type f -name "*.html" \
  -not -path "*/node_modules/*" \
  -not -path "*/dist/*" \
  -not -path "*/build/*" \
  -not -path "*/.git/*" 2>/dev/null || true)

if [ ${#HTML_FILES[@]} -eq 0 ]; then
  echo "✅ No top-level HTML files found; nothing to validate."
  exit 0
fi

echo "📄 Found ${#HTML_FILES[@]} HTML file(s) to validate:"
for f in "${HTML_FILES[@]}"; do
  echo "  - $f"
done

# Check if tidy is installed
if ! command -v tidy &> /dev/null; then
  echo "❌ Error: HTML Tidy is not installed."
  echo "   Install it with: sudo apt-get install tidy (Debian/Ubuntu)"
  echo "                    brew install tidy-html5 (macOS)"
  exit 1
fi

echo ""
echo "🔧 Running HTML Tidy validation..."
echo ""

# Function to validate a single HTML file
validate_html_file() {
  local file=$1
  local config_flag=""
  
  if [ -f ".tidyrc" ]; then
    config_flag="-config .tidyrc"
  fi
  
  if tidy -e -q -utf8 $config_flag "$file" 2>&1; then
    return 0
  else
    return 1
  fi
}

ERR=0
for f in "${HTML_FILES[@]}"; do
  echo "Validating: $f"
  if validate_html_file "$f"; then
    echo "  ✅ Valid"
  else
    ERR=1
    echo "  ❌ Validation failed"
  fi
  echo ""
done

if [ $ERR -ne 0 ]; then
  echo "❌ One or more HTML files failed validation."
  exit 1
fi

echo "✅ All HTML files passed validation!"
exit 0
