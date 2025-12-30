# CI Workflow Documentation

## Overview

The CI (Continuous Integration) workflow is designed to validate code quality, run tests, and build all packages in the Infamous Freight Enterprises monorepo. It runs automatically on every push to `main` and for all pull requests.

## Workflow Configuration

**File:** `.github/workflows/ci.yml`

### Trigger Events

- **Push to `main` branch**: Validates production-bound code
- **Pull Requests**: Validates changes before merging
- **Path Exclusions**: Skips runs for documentation changes (`docs/**`, `*.md`) and archived code (`archive/**`)

### Concurrency Control

The workflow uses concurrency groups to prevent multiple CI runs for the same branch:
```yaml
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
```
This ensures efficient resource usage by canceling outdated workflow runs.

## Jobs

### 1. Main CI Job (`ci`)

**Matrix Strategy:** Runs against Node.js versions 18 and 20 (LTS versions)

#### Steps:

1. **Checkout Repository** (`actions/checkout@v4`)
   - Fetches full git history for better caching
   - Uses read-only permissions (least privilege)

2. **Setup pnpm** (`pnpm/action-setup@v2`)
   - Version: `8.15.9` (pinned for consistency)
   - Ensures consistent package manager behavior across all CI runs

3. **Setup Node.js** (`actions/setup-node@v3`)
   - Matrix versions: 18, 20
   - Automatically caches pnpm store for faster subsequent runs

4. **Guard: Verify pnpm-only workspace**
   - Validates that no `package-lock.json` files exist
   - Ensures monorepo uses pnpm exclusively
   - Prevents accidental usage of npm

5. **Install Dependencies**
   - Command: `pnpm install --frozen-lockfile`
   - `--frozen-lockfile`: Ensures lockfile isn't modified (CI safety)
   - `HUSKY=0`: Disables git hooks in CI environment

6. **Lint Workspace**
   - Command: `pnpm lint`
   - Validates code style and quality across all packages
   - Enforces consistent coding standards

7. **Type-check Workspace**
   - Command: `pnpm typecheck`
   - Runs TypeScript compiler in check mode (`--noEmit`)
   - Validates type safety across the entire monorepo

8. **Run Tests**
   - Command: `pnpm test --ci`
   - `--ci`: Optimizes test execution for CI environment
   - Environment variables:
     - `NODE_ENV=test`: Ensures test configuration is used
     - `CI=true`: Signals to test frameworks they're running in CI

9. **Build Shared Package**
   - Command: `pnpm --filter @infamous-freight/shared build`
   - Builds shared TypeScript utilities and types
   - **Must run before building dependent packages**

10. **Build API**
    - Command: `pnpm --filter infamous-freight-api build`
    - Compiles TypeScript backend services

11. **Build Web**
    - Command: `pnpm --filter infamous-freight-web build`
    - Builds Next.js web application

12. **Build Mobile**
    - Command: `pnpm --filter infamous-freight-mobile build`
    - No-op in CI (Expo build handled separately)

### 2. Expo Validation Job (`expo-validation`)

**Conditional:** Only runs if `EXPO_TOKEN` secret is configured

This job validates the React Native/Expo mobile application:

#### Steps:

1. **Checkout Repository**
2. **Setup pnpm** (version 8.15.9)
3. **Setup Node.js** (version 20 only)
4. **Install Dependencies** (with frozen lockfile)
5. **Setup Expo** (`expo/expo-github-action@v8`)
   - Uses `EXPO_TOKEN` from GitHub Secrets
   - Required for Expo CLI authentication
6. **Validate Expo Configuration**
   - Runs `expo-cli doctor` to check project health
7. **Type-check Mobile App**
   - Validates TypeScript in mobile codebase

## Security & Hardening

### Permissions (Least Privilege)

```yaml
permissions:
  contents: read
```

- Workflow has **read-only** access to repository contents
- Cannot write, create releases, or modify settings
- Follows principle of least privilege

### Secret Handling

- `EXPO_TOKEN`: Securely fetched from GitHub Secrets
- Never exposed in logs or workflow files
- Only used when explicitly configured

### Idempotency

- `--frozen-lockfile`: Prevents lockfile modifications
- Consistent dependency versions across all runs
- Reproducible builds

### ESM Support

- All packages use `"type": "module"` in package.json
- TypeScript compiled with ESM output
- Node.js ESM module resolution

## Environment Variables

The workflow uses these environment variables:

- `HUSKY=0`: Disables git hooks in CI
- `NODE_ENV=test`: Sets Node environment for tests
- `CI=true`: Standard CI indicator flag

## Matrix Testing

The workflow tests against **two Node.js LTS versions**:

| Version | Status | Notes |
|---------|--------|-------|
| Node 18 | LTS    | Minimum supported version |
| Node 20 | LTS    | Current LTS version |

This ensures compatibility across the supported Node.js version range.

## Workflow Optimization

### Caching Strategy

- pnpm store cached by `actions/setup-node@v3`
- Cache key based on `pnpm-lock.yaml` hash
- Significantly reduces dependency installation time

### Fail-Fast Disabled

```yaml
strategy:
  fail-fast: false
```

- All Node versions tested even if one fails
- Provides complete compatibility picture
- Better for debugging version-specific issues

### Concurrency Control

- Cancels in-progress runs when new commits pushed
- Saves CI minutes and provides faster feedback
- One run per branch at a time

## Usage

### Required Setup

1. **Repository Secrets** (if using Expo):
   - `EXPO_TOKEN`: Your Expo authentication token

2. **Branch Protection** (recommended):
   - Require CI to pass before merging
   - Enforce status checks for both Node versions

### Local Development

Before pushing, run these commands locally:

```bash
# Install dependencies
pnpm install --frozen-lockfile

# Run linting
pnpm lint

# Run type checking
pnpm typecheck

# Run tests
pnpm test

# Build all packages
pnpm build
```

### Troubleshooting

#### CI Fails on Node 18 but not Node 20

- Check for Node version-specific dependencies
- Review usage of newer Node.js APIs
- Ensure polyfills for older Node versions

#### Tests Fail in CI but Pass Locally

- Verify `NODE_ENV=test` locally
- Check for timing issues (use `--ci` flag)
- Review environment-specific configurations

#### Build Fails After Dependencies Update

- Ensure `pnpm-lock.yaml` is committed
- Run `pnpm install --frozen-lockfile` locally first
- Check for breaking changes in dependencies

## Maintenance

### Updating Node Versions

To change tested Node versions, edit the matrix:

```yaml
strategy:
  matrix:
    node-version: [18, 20, 22]  # Add Node 22 when it becomes LTS
```

### Updating pnpm Version

Update the pinned version:

```yaml
- name: Setup pnpm
  uses: pnpm/action-setup@v2
  with:
    version: 8.15.9  # Update this version
```

### Adding New Packages

New workspace packages are automatically included in:
- `pnpm lint`
- `pnpm typecheck`
- `pnpm test`

Ensure they have these scripts in their `package.json`:
```json
{
  "scripts": {
    "lint": "...",
    "typecheck": "tsc --noEmit",
    "test": "jest"
  }
}
```

## Best Practices

1. **Always use `--frozen-lockfile`** in CI to prevent dependency drift
2. **Pin action versions** (e.g., `@v4`, not `@latest`) for stability
3. **Use matrix testing** for Node version compatibility
4. **Keep secrets secure** - never log or expose them
5. **Apply least privilege** - use minimal required permissions
6. **Enable concurrency control** to save resources
7. **Ignore non-code paths** to skip unnecessary runs

## Related Workflows

- `ci-cd.yml`: Full CI/CD pipeline with deployment
- `e2e.yml`: End-to-end testing with Playwright
- `codeql.yml`: Security scanning and code analysis

## Support

For issues with the CI workflow:

1. Check workflow run logs in GitHub Actions tab
2. Review failed step output
3. Compare with successful runs
4. Check for environment-specific issues
5. Open an issue with the CI workflow label
