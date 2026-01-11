# 🔒 CodeQL Security Analysis 100% - Complete Guide

**Document Version**: 1.0  
**Date**: January 11, 2026  
**Status**: ✅ Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Quick Start](#quick-start)
4. [Running Scans](#running-scans)
5. [Interpreting Results](#interpreting-results)
6. [Custom Queries](#custom-queries)
7. [Integration](#integration)
8. [Performance Optimization](#performance-optimization)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

---

## Overview

### What is CodeQL?

CodeQL is GitHub's **semantic code analysis engine** that finds vulnerabilities in your code before deployment.

**Key Features:**
- 🔍 Detects 150+ security and quality issues
- ⚡ Runs automatically on every push/PR
- 📊 Generates detailed SARIF reports
- 🔗 Integrates with GitHub Security Dashboard
- 🛠️ Supports custom query development

### Security Coverage (100%)

```
LAYER 1: CodeQL Analysis
├─ Security queries (50+)
├─ Quality queries (100+)
└─ Custom rules

LAYER 2: Dependency Scanning
├─ npm audit
├─ License compliance
└─ Outdated detection

LAYER 3: Supply Chain
├─ SBOM (CycloneDX)
├─ Secret detection
└─ Build integrity

LAYER 4: Code Quality
├─ ESLint
├─ TypeScript checks
└─ Complexity metrics

LAYER 5: Security Config
├─ Headers audit
├─ CORS review
└─ Rate limiting

LAYER 6: Performance
├─ Bundle size
├─ Load time
└─ Lighthouse metrics

LAYER 7: Reporting
├─ GitHub Dashboard
├─ SARIF export
└─ Notifications
```

---

## Architecture

### Workflow Components

**File**: [.github/workflows/codeql.yml](.github/workflows/codeql.yml)

```yaml
┌─────────────────────────────────────────┐
│     EVENT TRIGGERS                      │
│  (push, pull_request, schedule)         │
└────────────────┬────────────────────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
    ▼            ▼            ▼
┌───────────┐ ┌─────────┐ ┌──────────┐
│ CodeQL    │ │Depend.  │ │Supply    │
│Analysis   │ │Scanning │ │Chain     │
└─────┬─────┘ └────┬────┘ └────┬─────┘
      │            │           │
      └────────┬───┴─────┬─────┘
               │         │
               ▼         ▼
            Results   Artifacts
               │         │
      ┌────────┴───┬─────┘
      │            │
      ▼            ▼
   SARIF        Report
   Upload       Summary
```

### Job Flow

| Job | Purpose | Duration | Runs On |
|-----|---------|----------|---------|
| `analyze` | Core CodeQL analysis | 5-10 min | Every push/PR |
| `dependency-scan` | npm audit + outdated check | 2-5 min | Every push |
| `supply-chain-security` | SBOM + secrets | 3-7 min | Every push |
| `code-quality` | Linting + type checks | 3-5 min | Every push |
| `security-audit` | Config review | 1-2 min | Every push |
| `results` | Report aggregation | <1 min | Always |
| `notify` | Alerts + emails | <1 min | On failure |

### Configuration Files

```
.github/
├─ workflows/
│  └─ codeql.yml ..................... Main workflow
└─ codeql/
   └─ codeql-config.yml .............. Query configuration
```

---

## Quick Start

### View Security Alerts

```bash
# 1. Open GitHub Repository
https://github.com/MrMiless44/Infamous-freight-enterprises

# 2. Navigate to Security Tab
Security → Code scanning alerts

# 3. Filter by severity
- Critical (red)
- High (orange)
- Medium (yellow)
- Low (blue)
```

### Run Local Analysis

```bash
# Install CodeQL CLI
# https://codeql.github.com/docs/codeql-cli/

# Clone CodeQL queries
git clone https://github.com/github/codeql.git
cd codeql

# Create database
codeql database create /tmp/infamous-db \
  --language=javascript \
  --source-root=/home/vscode/deploy-site

# Run analysis
codeql database analyze /tmp/infamous-db \
  javascript-security-and-quality.qls \
  --format=sarif-latest \
  --output=results.sarif

# View results
cat results.sarif | jq
```

### GitHub Actions Integration

CodeQL runs automatically on:
- ✅ Every push to `main` or `develop`
- ✅ Every pull request
- ✅ Daily schedule (3 AM UTC)
- ✅ Weekly schedule (Sundays)

**Check status:**
```
Repository → Actions → CodeQL Security Analysis
```

---

## Running Scans

### Automated Scans (GitHub Actions)

**Trigger:** Push to main or develop
**Time:** ~15-20 minutes
**Output:** Security alerts + artifacts

**View workflow run:**
```
Actions → CodeQL Security Analysis 100% → Latest run
```

### Manual Workflow Dispatch

```bash
# Trigger via GitHub CLI
gh workflow run codeql.yml

# Or via web UI
Actions → CodeQL Security Analysis 100% → Run workflow
```

### Local Analysis (Advanced)

```bash
# 1. Install CodeQL
npm install -g codeql

# 2. Create database
codeql database create \
  ./codeql-db \
  --language=javascript \
  --source-root=.

# 3. Run queries
codeql database analyze \
  ./codeql-db \
  javascript-security-and-quality.qls \
  --format=csv \
  --output=results.csv

# 4. View results
cat results.csv
```

---

## Interpreting Results

### Security Alert Example

```json
{
  "rule": {
    "id": "js/sql-injection",
    "name": "SQL Injection",
    "severity": "error"
  },
  "message": {
    "text": "Database query depends on user input"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "api/src/routes/shipments.js"
        },
        "region": {
          "startLine": 42,
          "startColumn": 10,
          "endLine": 42,
          "endColumn": 25
        }
      }
    }
  ]
}
```

### Severity Levels

```
🔴 ERROR (Critical)
├─ Remote code execution
├─ SQL injection
├─ Authentication bypass
└─ Data exposure
→ Action: Fix immediately

🟠 WARNING (High)
├─ XSS vulnerability
├─ CSRF token missing
├─ Weak crypto
└─ Input validation missing
→ Action: Fix before merge

🟡 NOTE (Medium)
├─ Deprecated function
├─ Performance issue
├─ Code smell
└─ Best practice violation
→ Action: Review and prioritize

🔵 RECOMMENDATION (Low)
├─ Code improvement
├─ Documentation
├─ Test coverage
└─ Refactoring
→ Action: Consider in next sprint
```

### Analysis Report Format

**GitHub Dashboard:**
```
Security → Code scanning alerts

Filters:
- State: Open / Closed / Dismissed
- Severity: Critical / High / Medium / Low
- Branch: main / develop / all
- Status: Resolved / Unresolved
- Last seen: Today / This week / This month
```

**SARIF Format:**
```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "CodeQL" } },
      "results": [ ... ]
    }
  ]
}
```

---

## Custom Queries

### Creating Custom Security Query

**File**: `.github/codeql/custom-queries/my-security.ql`

```ql
/**
 * @name Dangerous Math Expression
 * @description Detects potential division by zero
 * @kind problem
 * @severity warning
 * @id js/dangerous-math
 */

import javascript

from BinaryExpr e
where e.getOperator() = "/"
  and e.getRightOperand().(NumberLiteral).getValue() = "0"
select e, "Potential division by zero"
```

### Deploying Custom Query

```bash
# 1. Add query to repository
cp my-security.ql .github/codeql/custom-queries/

# 2. Update configuration
# Edit .github/codeql/codeql-config.yml

queries:
  - uses: security-and-quality
  - uses: ./codeql/custom-queries/my-security.ql

# 3. Push changes
git add .github/codeql/
git commit -m "feat: add custom security query"
git push origin main

# 4. Workflow will pick up changes automatically
```

### Query Debugging

```bash
# Test query locally
codeql query run \
  ./codeql/custom-queries/my-security.ql \
  --database=/tmp/infamous-db

# Compare results
codeql query run \
  ./codeql/custom-queries/my-security.ql \
  --database=/tmp/infamous-db \
  --output=before.csv

# Modify query...

codeql query run \
  ./codeql/custom-queries/my-security.ql \
  --database=/tmp/infamous-db \
  --output=after.csv

diff before.csv after.csv
```

---

## Integration

### GitHub Security Dashboard

**Features:**
- 📊 Real-time vulnerability dashboard
- 🔔 Email notifications for new alerts
- 🔗 Link code locations to pull requests
- 📈 Trend analysis and reports

**Setup:**
1. Go to `Settings → Security & analysis`
2. Enable `Code scanning → CodeQL analysis`
3. Configure notifications
4. Set branch protection rules

### Pull Request Integration

**Automatic:**
- ✅ Runs on every PR
- ✅ Comments with results
- ✅ Blocks merge on critical issues
- ✅ Shows inline code annotations

**Configuration:**
```yaml
# .github/workflows/codeql.yml

# Comment on PR with results
- name: Comment on PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v6
  with:
    script: |
      # Adds security results comment
```

### Slack Integration

```yaml
# Send notifications to Slack
- name: Notify Slack
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
    payload: |
      {
        "text": "🔒 CodeQL Analysis Complete",
        "blocks": [{
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "Review: ${{ github.server_url }}/${{ github.repository }}/security/code-scanning"
          }
        }]
      }
```

### Email Notifications

**GitHub Built-in:**
- Settings → Notifications → Enable security alerts
- CodeQL results sent to registered email

**Custom Email:**
```yaml
- name: Send email
  uses: dawidd6/action-send-mail@v3
  with:
    server_address: smtp.gmail.com
    to: security@infamous-freight.com
    subject: "CodeQL Alert: Critical issue found"
    body: "Review at: ${{ github.server_url }}/..."
```

---

## Performance Optimization

### Scan Time Optimization

**Current**: ~15-20 minutes per scan

**Optimization techniques:**

```bash
# 1. Parallel execution
strategy:
  matrix:
    language: ["javascript", "typescript"]
  max-parallel: 4

# 2. Incremental analysis
- Use: database caching
- Scope: Only changed files

# 3. Query filtering
- Run: only security queries
- Skip: optional quality queries
```

### Cache Strategy

```yaml
- name: Cache CodeQL database
  uses: actions/cache@v3
  with:
    path: codeql-db
    key: codeql-db-${{ github.ref }}-${{ github.sha }}
    restore-keys: |
      codeql-db-${{ github.ref }}-
      codeql-db-main-
```

### Resource Limits

```yaml
# Reduce memory usage
env:
  CODEQL_THREADS: 4
  CODEQL_MEMORY: 8g

# Timeout configuration
timeout-minutes: 360  # 6 hours max
```

---

## Troubleshooting

### Common Issues

#### Issue: CodeQL workflow times out

**Solution:**
```yaml
# Increase timeout
timeout-minutes: 360  # was 60

# Or reduce scope
# Add path filters to skip unnecessary scans
on:
  push:
    paths:
      - "**.ts"
      - "**.js"
      - ".github/workflows/codeql.yml"
```

#### Issue: "No database found"

**Solution:**
```bash
# Rebuild database
codeql database create ./codeql-db \
  --language=javascript \
  --source-root=.

# Verify
ls -la ./codeql-db/
```

#### Issue: Out of memory

**Solution:**
```yaml
# Reduce workers
env:
  CODEQL_THREADS: 2  # was 4

# Or increase runner memory
runs-on: ubuntu-latest-x2
```

#### Issue: False positives

**Solution:**
```yaml
# Dismiss irrelevant alerts
# In GitHub UI: Security → Code scanning alerts → Dismiss

# Or suppress in code
// lgtm [SECURITY] - Reviewed and safe
const result = dangerousFunction();
```

### Debugging

**Enable debug logging:**
```yaml
- name: Debug CodeQL
  env:
    ACTIONS_STEP_DEBUG: true
  run: codeql database analyze ./codeql-db javascript-security-and-quality.qls
```

**Inspect artifacts:**
```bash
# Download SARIF file
ls -la security-artifacts/

# View SARIF content
cat codeql-complete-report/codeql-results-javascript-typescript.sarif | jq .
```

---

## Best Practices

### Pre-Commit

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "🔒 Running security scan..."
pnpm audit --audit-level=moderate

if [ $? -ne 0 ]; then
  echo "❌ Security vulnerabilities found"
  exit 1
fi

echo "✅ Security check passed"
```

### Branch Protection

**Require passing CodeQL checks:**

1. Go to `Settings → Branches`
2. Select default branch
3. Add rule: `require: CodeQL Security Analysis`
4. Status checks required: `Code scanning / CodeQL`

### Code Review

**Security checklist:**
- [ ] No hardcoded secrets
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention
- [ ] XSS protection
- [ ] CSRF tokens present
- [ ] Error handling secure
- [ ] Rate limiting applied
- [ ] Logs don't expose sensitive data
- [ ] Dependencies updated
- [ ] CodeQL alerts resolved

### Release Process

```bash
# 1. Run CodeQL locally
codeql database analyze ...

# 2. Verify no high/critical issues
# 3. Get security team approval
# 4. Tag release
git tag -s v1.0.0 -m "Release v1.0.0"

# 5. Push tag
git push origin v1.0.0

# 6. Create release notes
# 7. Document security fixes
```

---

## Maintenance

### Regular Reviews

| Frequency | Task | Owner |
|-----------|------|-------|
| Daily | Review new alerts | Security team |
| Weekly | Triage issues | Dev lead |
| Monthly | Update queries | Security architect |
| Quarterly | Audit configuration | Security review |

### Updates

```bash
# Update CodeQL actions
github/codeql-action: v3  # Check latest version

# Update CodeQL CLI
npm update -g codeql

# Update query database
cd codeql && git pull origin main
```

---

## Resources

### Official Documentation
- [GitHub CodeQL](https://codeql.github.com/)
- [CodeQL Query Language](https://codeql.github.com/docs/ql-language-reference/)
- [GitHub Actions Security](https://docs.github.com/en/actions/security)

### Security Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE Top 25](https://cwe.mitre.org/top25/)

### Community
- [CodeQL GitHub](https://github.com/github/codeql)
- [CodeQL Queries](https://github.com/github/codeql-js)
- [Security Advisories](https://github.com/advisories)

---

**Document Status**: ✅ Complete  
**Last Updated**: January 11, 2026  
**Next Review**: April 11, 2026  
**Maintained By**: Security Team
