# HTML Quality CI Workflow

## Overview

The HTML Quality workflow (`.github/workflows/html-quality.yml`) ensures HTML files in the repository meet quality standards through automated validation using HTML Tidy.

## Workflow Triggers

- **Pull Requests**: Validates HTML changes in PRs (excluding `archive/**`)
- **Push to main**: Runs on main branch commits (excluding `archive/**`)
- **Concurrency**: Cancels in-progress runs for the same ref

## Jobs

### html-validation

A single job that performs HTML validation with the following steps:

#### 1. Show Repository Tree (Debugging)

Displays the directory structure and lists top-level HTML files for debugging purposes.

```yaml
- name: Show repo tree (for debugging)
  run: |
    echo "Repository root:"
    ls -la
    echo "Top-level HTML files:"
    ls -la *.html || true
```

**Purpose**: Helps diagnose issues related to file discovery and directory structure.

#### 2. Install HTML Tidy

Installs HTML Tidy (libtidy) version 5.6.0 for HTML validation.

```yaml
- name: Install html tidy (libtidy)
  env:
    DEBIAN_FRONTEND: noninteractive
  run: |
    sudo apt-get update -y
    sudo apt-get install -y tidy
    tidy -v || true
```

**Tool**: [HTML Tidy](http://www.html-tidy.org/) - A command-line tool for checking and cleaning HTML.

#### 3. Validate HTML Files

Recursively finds and validates all HTML files using the `.tidyrc` configuration.

**File Discovery**:

- Searches up to 4 levels deep from the repository root
- Excludes: `node_modules/`, `dist/`, `build/`, `.git/`
- Note: `archive/` is excluded at the workflow trigger level via `paths-ignore`

**Validation**:

- Uses `.tidyrc` configuration for consistent validation rules
- Logs all validation results to `ci-logs/tidy.log`
- Fails the workflow if any HTML file fails validation

#### 4. Upload Logs on Failure

If validation fails, uploads CI logs as artifacts for debugging.

## Configuration

### .tidyrc

HTML Tidy validation rules are defined in `.tidyrc`:

```ini
# HTML Version
doctype: html5

# Character Encoding
input-encoding: utf8
output-encoding: utf8
char-encoding: utf8

# Error Reporting
show-errors: 6
show-warnings: yes

# Treatment of Errors
drop-empty-elements: no
drop-empty-paras: no
```

See [.tidyrc](../.tidyrc) for complete configuration.

## Usage

### Local Testing

You can test HTML validation locally by installing tidy:

```bash
# Install tidy
sudo apt-get install -y tidy

# Validate a single file
tidy -e -q -utf8 -config .tidyrc path/to/file.html

# Validate all HTML files (excluding common directories)
find . -maxdepth 4 -type f -name "*.html" \
  -not -path "*/node_modules/*" \
  -not -path "*/dist/*" \
  -not -path "*/build/*" \
  -not -path "*/.git/*" \
  -exec tidy -e -q -utf8 -config .tidyrc {} \;
```

### Adding New HTML Files

When adding new HTML files:

1. Ensure they are valid HTML5
2. Test locally with tidy before committing
3. The CI workflow will automatically validate them on PR

### Handling Validation Errors

If the workflow fails:

1. Check the workflow run logs in GitHub Actions
2. Download the `ci-logs` artifact for detailed error messages
3. Fix validation errors in your HTML files
4. Push the fixes - the workflow will re-run automatically

## Troubleshooting

### No HTML Files Found

If the workflow reports "No HTML files found":

- Verify HTML files exist in the repository (not just in archive/)
- Check file extensions are `.html` (case-sensitive)
- Ensure files are not in excluded directories

### Validation Errors

Common HTML Tidy errors:

- Missing DOCTYPE declaration
- Unclosed tags
- Invalid nesting
- Character encoding issues

Refer to [HTML Tidy documentation](http://api.html-tidy.org/tidy/quickref_5.6.0.html) for error codes and fixes.

## Workflow Status

[![HTML Quality](https://github.com/MrMiless44/Infamous-freight-enterprises/actions/workflows/html-quality.yml/badge.svg)](https://github.com/MrMiless44/Infamous-freight-enterprises/actions/workflows/html-quality.yml)

## Related Documentation

- [GitHub Actions Workflows](../.github/workflows/)
- [Quality Enforcement Summary](./QUALITY_ENFORCEMENT_SUMMARY.md)
- [Testing Strategy](./TESTING_STRATEGY.md)
