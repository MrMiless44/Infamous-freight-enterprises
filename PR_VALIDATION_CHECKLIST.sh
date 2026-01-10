#!/bin/bash
# PR Validation Checklist - Run before creating PR

set -e

echo "🔍 PR READINESS VALIDATION"
echo "=========================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

check_pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
    ((PASS++))
}

check_fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    ((FAIL++))
}

check_warn() {
    echo -e "${YELLOW}⚠️  WARN${NC}: $1"
}

# 1. Check branch is up to date
echo "📡 Checking remote sync..."
git fetch origin main --quiet 2>/dev/null || true
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "0")
if [ "$BEHIND" -eq 0 ]; then
    check_pass "Branch is up to date with origin/main"
else
    check_warn "Branch is $BEHIND commits behind main (consider rebasing)"
fi
echo ""

# 2. Check working tree is clean
echo "📁 Checking working tree..."
if [ -z "$(git status --porcelain)" ]; then
    check_pass "Working tree is clean"
else
    check_fail "Uncommitted changes detected"
    git status --short
fi
echo ""

# 3. Check critical workflow files exist
echo "🔄 Checking workflow files..."
WORKFLOWS=("ci.yml" "ci-cd.yml" "deploy-fly.yml" "deploy-vercel.yml" "lighthouse-accessibility.yml" "monorepo-health.yml")
for workflow in "${WORKFLOWS[@]}"; do
    if [ -f ".github/workflows/$workflow" ]; then
        check_pass "Workflow exists: $workflow"
    else
        check_fail "Missing workflow: $workflow"
    fi
done
echo ""

# 4. Check package.json scripts
echo "📦 Checking package.json scripts..."
SCRIPTS=("dev" "build" "test" "lint" "typecheck" "check:types")
for script in "${SCRIPTS[@]}"; do
    if grep -q "\"$script\":" package.json; then
        check_pass "Script exists: $script"
    else
        check_fail "Missing script: $script"
    fi
done
echo ""

# 5. Check workspace typecheck scripts
echo "🔍 Checking workspace typecheck scripts..."
WORKSPACES=("src/apps/web" "src/apps/mobile" "src/packages/shared")
for workspace in "${WORKSPACES[@]}"; do
    if [ -f "$workspace/package.json" ]; then
        if grep -q "\"typecheck\":" "$workspace/package.json"; then
            check_pass "Typecheck script in $workspace"
        else
            check_fail "Missing typecheck in $workspace"
        fi
    fi
done
echo ""

# 6. Check documentation files
echo "📚 Checking documentation..."
DOCS=("docs/DATADOG_SETUP.md" "docs/SECURITY_ROTATION.md" "docs/DISASTER_RECOVERY.md" ".github/agent-instructions.md")
for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        check_pass "Documentation exists: $(basename $doc)"
    else
        check_warn "Missing documentation: $doc"
    fi
done
echo ""

# 7. Check test files
echo "🧪 Checking test coverage..."
TEST_FILES=("src/apps/api/src/__tests__/rate-limiter.integration.test.ts" "tests/e2e/critical-flows.spec.ts")
for test in "${TEST_FILES[@]}"; do
    if [ -f "$test" ]; then
        check_pass "Test file exists: $(basename $test)"
    else
        check_warn "Missing test: $test"
    fi
done
echo ""

# 8. Check setup script
echo "🛠️  Checking setup scripts..."
if [ -f "scripts/setup-local.sh" ] && [ -x "scripts/setup-local.sh" ]; then
    check_pass "Local setup script exists and is executable"
else
    check_warn "Setup script missing or not executable"
fi
echo ""

# 9. Check commit message
echo "💬 Checking commit message..."
COMMIT_MSG=$(git log -1 --pretty=%B)
if echo "$COMMIT_MSG" | grep -qE "^(feat|fix|docs|chore|refactor|test|ci):"; then
    check_pass "Commit follows conventional commits format"
else
    check_warn "Commit message doesn't follow conventional commits"
fi
echo ""

# 10. Check branch is pushed
echo "🚀 Checking remote push status..."
LOCAL_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse origin/$(git branch --show-current) 2>/dev/null || echo "none")
if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
    check_pass "Branch is pushed to remote"
else
    check_fail "Local commits not pushed to remote"
fi
echo ""

# Summary
echo "=========================="
echo "📊 VALIDATION SUMMARY"
echo "=========================="
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL CRITICAL CHECKS PASSED!${NC}"
    echo ""
    echo "✅ Ready to create PR at:"
    echo "   https://github.com/MrMiless44/Infamous-freight-enterprises/compare/main...$(git branch --show-current)?expand=1"
    echo ""
    exit 0
else
    echo -e "${RED}❌ $FAIL CRITICAL CHECKS FAILED${NC}"
    echo ""
    echo "Fix the issues above before creating PR"
    exit 1
fi
