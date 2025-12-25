#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

run_html_validation() {
  mapfile -t html_files < <(find "$ROOT_DIR/src" "$ROOT_DIR/tests" -type f -name "*.html" 2>/dev/null || true)
  if [ ${#html_files[@]} -eq 0 ]; then
    echo "No HTML files found; skipping HTML validation."
    return
  fi

  echo "Running HTML validation on ${#html_files[@]} file(s)..."
  pnpm exec html-validate --config "$ROOT_DIR/configs/validation/html-validate.config.js" "${html_files[@]}"
}

run_css_validation() {
  mapfile -t css_files < <(find "$ROOT_DIR/src" "$ROOT_DIR/tests" -type f -name "*.css" 2>/dev/null || true)
  if [ ${#css_files[@]} -eq 0 ]; then
    echo "No CSS files found; skipping CSS validation."
    return
  fi

  echo "Running CSS validation on ${#css_files[@]} file(s)..."
  pnpm exec stylelint "{src,tests}/**/*.css" --config "$ROOT_DIR/configs/validation/stylelint.config.cjs" --ignore-path "$ROOT_DIR/configs/validation/.stylelintignore"
}

run_js_validation() {
  echo "Running JavaScript/TypeScript linting..."
  pnpm exec eslint -c "$ROOT_DIR/configs/linting/eslint.config.js" "src/**/*.{js,jsx,ts,tsx}" "tests/**/*.{js,jsx,ts,tsx}"
}

run_html_validation
run_css_validation
run_js_validation
