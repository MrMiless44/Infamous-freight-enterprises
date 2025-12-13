# Branch Protection Rules Setup

This guide enables branch protection to enforce code quality standards on the `main` branch.

## Steps to Enable Branch Protection

### 1. Navigate to Repository Settings

- Go to: **https://github.com/MrMiless44/Infamous-freight-enterprises/settings/branches**
- Or: Repository → Settings → Branches (left sidebar)

### 2. Add Branch Protection Rule

Click **"Add rule"** and configure:

#### Branch name pattern

```
main
```

#### Protect matching branches

✅ **Require a pull request before merging**

- ✅ Require approvals: **1** (minimum reviewers)
- ✅ Require review from code owners (if CODEOWNERS file exists)
- ✅ Dismiss stale pull request approvals when new commits are pushed

✅ **Require status checks to pass before merging**

- Require branches to be up to date before merging: **YES**
- Select required status checks:
  - `lint-build` (linting and builds)
  - `test-coverage` (unit tests)
  - `security-audit` (npm audit)
  - `smoke-tests` (API health checks)

✅ **Require code scanning to pass**

- ✅ Require code scanning results to pass (if enabled)

✅ **Additional settings**

- ✅ Restrict who can push to matching branches (Optional - admin only)
- ✅ Allow force pushes: **DISABLED** (prevent destructive force pushes)
- ✅ Allow deletions: **DISABLED** (prevent branch deletion)

### 3. Save the Rule

Click **"Create"** to enable protection on the `main` branch.

---

## What This Enforces

| Check             | Description                     | Status      |
| ----------------- | ------------------------------- | ----------- |
| **PR Review**     | At least 1 approval required    | ✅ Required |
| **CI/CD Checks**  | All GitHub Actions must pass    | ✅ Required |
| **Up-to-date**    | PR must be rebased before merge | ✅ Required |
| **Force Push**    | Prevents overwriting history    | ✅ Blocked  |
| **Branch Delete** | Prevents accidental deletion    | ✅ Blocked  |

---

## Husky Pre-commit Hooks (Already Enabled)

Local validation before commits:

**✅ Pre-commit Hook** (`.husky/pre-commit`)

- Runs ESLint on staged files
- Formats code with Prettier
- Prevents commits with linting errors

**✅ Commit-msg Hook** (`.husky/commit-msg`)

- Enforces Conventional Commits format
- Example: `feat(api): add user authentication`
- Prevents vague commit messages

---

## Commit Message Format

To ensure consistency, follow Conventional Commits:

```
type(scope): subject

body (optional)

footer (optional)
```

**Types:**

- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `style` - Code style (formatting, semicolons, etc.)
- `refactor` - Code refactoring
- `perf` - Performance improvement
- `test` - Test additions/modifications
- `chore` - Build, dependencies, tooling
- `ci` - CI/CD configuration
- `revert` - Revert previous commit

**Examples:**

```bash
git commit -m "feat(auth): add JWT token validation"
git commit -m "fix(web): resolve button click handler"
git commit -m "docs: update API endpoint documentation"
git commit -m "refactor(api): simplify error handling middleware"
git commit -m "test: add unit tests for user service"
```

---

## Testing Locally

Before pushing, ensure:

```bash
# Run linting (runs automatically on commit)
npm run lint

# Run tests
npm test

# Run security audit
npm audit

# Verify commit message format (runs automatically)
git commit -m "feat(scope): description"
```

---

## Troubleshooting

### Pre-commit hook failing

**Linting errors:**

```bash
cd api && npm run lint -- --fix
cd web && npm run lint -- --fix
```

**Test failures:**

```bash
npm test -- --watch
```

### Commit message rejected

Ensure format matches Conventional Commits:

```bash
# ❌ Bad
git commit -m "fixed bug"
git commit -m "update code"

# ✅ Good
git commit -m "fix(api): resolve database connection error"
git commit -m "refactor(web): simplify form validation"
```

### Bypassing hooks (Not Recommended)

Only for emergency situations:

```bash
git commit --no-verify -m "your message"
```

**⚠️ Warning:** This skips quality checks and should only be used for urgent fixes.

---

## Benefits

- 🔒 **Code Quality**: Enforces linting and testing
- 🎯 **Consistency**: Standardized commit messages
- 🛡️ **Security**: Requires security audits to pass
- 📝 **Traceability**: Clear commit history
- 👥 **Collaboration**: Code review ensures knowledge sharing
- 🚀 **Automation**: CI/CD must pass before merge
