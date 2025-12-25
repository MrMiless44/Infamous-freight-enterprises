# Code Validation Guide

This document describes the validation tools and processes used in the Infamous Freight Enterprise project.

## Overview

The project uses multiple validation tools to ensure code quality, security, and standards compliance:

1. **HTML Validation** - Validates HTML markup
2. **CSS Validation** - Validates CSS stylesheets
3. **JavaScript/TypeScript Linting** - ESLint for code quality
4. **Type Checking** - TypeScript compiler for type safety
5. **Security Scanning** - CodeQL for security vulnerabilities

## HTML Validation

### Tool: HTML Tidy

HTML files are validated using [HTML Tidy](http://www.html-tidy.org/), which checks for:
- Proper HTML structure
- Valid element nesting
- Attribute correctness
- Accessibility issues

### Configuration

HTML validation runs automatically in CI for all `.html` files.

### Manual Validation

```bash
# Install tidy (Ubuntu/Debian)
sudo apt-get install tidy

# Validate a single HTML file
tidy -q -e -utf8 path/to/file.html

# Validate all HTML files
find . -name "*.html" -not -path "*/node_modules/*" -exec tidy -q -e -utf8 {} \;
```

### Common Issues

- **Missing closing tags**: Ensure all HTML elements are properly closed
- **Invalid nesting**: Follow HTML5 nesting rules
- **Missing required attributes**: Include required attributes (e.g., `alt` for images)

## CSS Validation

### Tool: Stylelint

CSS and style files are validated using [Stylelint](https://stylelint.io/), which checks for:
- Syntax errors
- Best practices
- Consistent formatting
- Browser compatibility issues

### Configuration

Stylelint configuration is defined in `configs/linting/.stylelintrc.json`.

### Manual Validation

```bash
# Install stylelint (if not already installed)
pnpm add -D stylelint stylelint-config-standard

# Validate CSS files
npx stylelint "**/*.css"

# Auto-fix issues
npx stylelint "**/*.css" --fix
```

### Rules

The project follows the [stylelint-config-standard](https://github.com/stylelint/stylelint-config-standard) configuration with custom overrides.

## JavaScript/TypeScript Linting

### Tool: ESLint

JavaScript and TypeScript files are validated using [ESLint](https://eslint.org/).

### Configuration

ESLint configuration is in `configs/linting/eslint.config.js` (flat config format).

### Workspace-Specific Configs

- **API** (`api/`): CommonJS rules, Node.js globals
- **Web** (`web/`): ESM rules, React/JSX support
- **Mobile** (`mobile/`): React Native rules, Expo support
- **Shared** (`packages/shared/`): TypeScript strict mode

### Manual Linting

```bash
# Lint all workspaces
pnpm lint

# Lint specific workspace
pnpm --filter api lint
pnpm --filter web lint

# Auto-fix issues
pnpm lint --fix
```

### Common Rules

- `no-console`: Warn for console statements (except `console.warn` and `console.error`)
- `no-unused-vars`: Error for unused variables (ignores vars starting with `_`)
- `no-undef`: Error for undefined variables
- TypeScript-specific rules for type safety

## Type Checking

### Tool: TypeScript Compiler

TypeScript files are type-checked using `tsc`.

### Manual Type Checking

```bash
# Type check all TypeScript workspaces
pnpm --filter api typecheck
pnpm --filter web typecheck
pnpm --filter mobile typecheck
pnpm --filter @infamous-freight/shared typecheck
```

### Configuration

Each workspace has its own `tsconfig.json`:
- **API**: `api/tsconfig.json`
- **Web**: `web/tsconfig.json`
- **Mobile**: `mobile/tsconfig.json`
- **Shared**: `packages/shared/tsconfig.json`

## Security Scanning

### Tool: CodeQL

GitHub CodeQL scans for security vulnerabilities automatically on every push and pull request.

### What It Scans

- SQL injection vulnerabilities
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- Insecure dependencies
- Cryptographic issues

### Viewing Results

Security scan results are available in:
- GitHub Actions workflow runs
- Security tab in the GitHub repository

### Manual Security Scan

CodeQL scans run automatically in CI. To run manually:

1. Go to the Actions tab in GitHub
2. Select the "CodeQL" workflow
3. Click "Run workflow"

## Pre-commit Validation

### Tool: Husky + lint-staged

Pre-commit hooks run automatically before each commit using [Husky](https://typicode.github.io/husky/).

### What Runs on Pre-commit

1. ESLint on staged JavaScript/TypeScript files
2. Prettier formatting on all staged files
3. Type checking on TypeScript files

### Configuration

- **Husky**: `.husky/` directory
- **lint-staged**: `configs/linting/.lintstagedrc`

### Skipping Pre-commit Hooks

```bash
# Skip hooks (not recommended)
git commit --no-verify
```

## Continuous Integration

All validation checks run automatically in CI on:
- Every push to `main` branch
- Every pull request

### CI Workflow

The main CI workflow (`.github/workflows/ci.yml`) runs:

1. **HTML Validation** - Validate all HTML files with tidy
2. **Install Dependencies** - Install pnpm packages
3. **Linting** - Run ESLint on all workspaces
4. **Type Checking** - Run TypeScript compiler
5. **Tests** - Run unit and integration tests
6. **Build** - Build all workspaces
7. **CSS Validation** - Run Stylelint on CSS files

### Workflow Badges

CI status is shown in the README:
- [![CI](https://github.com/MrMiless44/Infamous-freight-enterprises/actions/workflows/ci.yml/badge.svg)](https://github.com/MrMiless44/Infamous-freight-enterprises/actions/workflows/ci.yml)

## Validation in Development

### VS Code Integration

Install recommended extensions (defined in `.vscode/extensions.json`):
- ESLint
- Prettier
- Stylelint
- Code Spell Checker

### Auto-fix on Save

Configure VS Code settings (`.vscode/settings.json`):

```json
{
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true,
    "source.fixAll.stylelint": true
  }
}
```

## Troubleshooting

### ESLint Errors Not Auto-fixing

1. Check ESLint output for errors
2. Some errors require manual fixes
3. Ensure you're using the correct config

### TypeScript Type Errors

1. Rebuild shared package: `pnpm --filter @infamous-freight/shared build`
2. Regenerate Prisma client: `cd api && pnpm prisma:generate`
3. Clear cache: `pnpm store prune`

### Stylelint Not Running

1. Install Stylelint: `pnpm add -D stylelint stylelint-config-standard`
2. Ensure config file exists: `configs/linting/.stylelintrc.json`
3. Check file patterns in CI workflow

### Pre-commit Hooks Not Running

1. Reinstall Husky: `pnpm install`
2. Check `.husky/` directory exists
3. Verify Git hooks are installed: `ls -la .git/hooks/`

## Best Practices

1. **Run validation locally** before pushing code
2. **Fix validation errors** immediately to prevent build failures
3. **Use auto-fix** features when available (`--fix` flag)
4. **Keep dependencies updated** to get latest rules and fixes
5. **Document exceptions** when disabling rules (use `eslint-disable` comments with explanations)

## Adding New Validation Rules

### For ESLint

1. Edit `configs/linting/eslint.config.js`
2. Add rules to the appropriate section
3. Test locally: `pnpm lint`
4. Document the rule and rationale

### For Stylelint

1. Edit `configs/linting/.stylelintrc.json`
2. Add rules to the `rules` section
3. Test locally: `npx stylelint "**/*.css"`
4. Document the rule and rationale

### For HTML Validation

1. Update tidy options in `.github/workflows/ci.yml`
2. Test locally with tidy
3. Document any custom settings

## Resources

- [ESLint Documentation](https://eslint.org/docs/)
- [Stylelint Documentation](https://stylelint.io/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [HTML Tidy Documentation](http://www.html-tidy.org/documentation/)
- [CodeQL Documentation](https://codeql.github.com/docs/)
