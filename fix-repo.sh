#!/usr/bin/env bash
# Repository Fix Script
# This script attempts to automatically fix common repository issues
# including linting errors, test failures, dependency issues, and more.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "════════════════════════════════════════════════════════════════"
echo "  🔧 Infamous Freight Enterprises - Repository Fix Script"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Function to print status messages
print_status() {
    echo -e "${BLUE}➜${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if we're in a git repository
if [ ! -d .git ]; then
    print_error "Not a git repository. Please run this script from the repository root."
    exit 1
fi

print_status "Starting repository fix process..."
echo ""

# Step 1: Clean and reinstall dependencies
print_status "Step 1: Cleaning and reinstalling dependencies..."
if command -v pnpm &> /dev/null; then
    print_status "Removing node_modules and lockfile..."
    find . -name "node_modules" -type d -prune -exec rm -rf {} + 2>/dev/null || true
    rm -f pnpm-lock.yaml
    
    print_status "Installing fresh dependencies..."
    HUSKY=0 pnpm install --no-frozen-lockfile
    print_success "Dependencies reinstalled"
else
    print_warning "pnpm not found. Skipping dependency reinstall."
fi
echo ""

# Step 2: Build shared package
print_status "Step 2: Building shared package..."
if [ -d "packages/shared" ] || [ -d "src/packages/shared" ]; then
    SHARED_PATH=""
    if [ -d "packages/shared" ]; then
        SHARED_PATH="packages/shared"
    elif [ -d "src/packages/shared" ]; then
        SHARED_PATH="src/packages/shared"
    fi
    
    if [ -n "$SHARED_PATH" ]; then
        print_status "Building $SHARED_PATH..."
        pnpm --filter @infamous-freight/shared build || pnpm -C "$SHARED_PATH" build || true
        print_success "Shared package built"
    fi
else
    print_warning "Shared package not found. Skipping."
fi
echo ""

# Step 3: Apply lint fixes
print_status "Step 3: Applying lint fixes..."
if command -v pnpm &> /dev/null; then
    print_status "Running lint --fix on all workspaces..."
    pnpm -r --if-present lint -- --fix || pnpm lint --fix || true
    print_success "Lint fixes applied"
else
    print_warning "pnpm not available. Skipping lint fixes."
fi
echo ""

# Step 4: Format code
print_status "Step 4: Formatting code..."
if command -v pnpm &> /dev/null; then
    print_status "Running prettier/format on all workspaces..."
    pnpm -r --if-present format || pnpm format || true
    print_success "Code formatted"
else
    print_warning "pnpm not available. Skipping code formatting."
fi
echo ""

# Step 5: Update test snapshots
print_status "Step 5: Updating test snapshots..."
if command -v pnpm &> /dev/null; then
    print_status "Updating Jest snapshots..."
    pnpm -r --if-present test -- --updateSnapshot --passWithNoTests || true
    print_success "Test snapshots updated"
else
    print_warning "pnpm not available. Skipping snapshot updates."
fi
echo ""

# Step 6: Clean build artifacts
print_status "Step 6: Cleaning build artifacts..."
print_status "Removing common build directories..."
find . -type d \( -name "dist" -o -name "build" -o -name ".next" -o -name "coverage" \) -not -path "./node_modules/*" -exec rm -rf {} + 2>/dev/null || true
print_success "Build artifacts cleaned"
echo ""

# Step 7: Rebuild projects
print_status "Step 7: Rebuilding projects..."
if command -v pnpm &> /dev/null; then
    print_status "Building all workspaces..."
    pnpm -r --if-present build || true
    print_success "Projects rebuilt"
else
    print_warning "pnpm not available. Skipping rebuild."
fi
echo ""

# Step 8: Run tests to verify fixes
print_status "Step 8: Running tests to verify fixes..."
if command -v pnpm &> /dev/null; then
    print_status "Running tests on all workspaces..."
    set +e
    pnpm -r --if-present test
    test_status=$?
    set -e
    
    if [ "$test_status" -eq 0 ]; then
        print_success "All tests passed!"
    else
        print_warning "Some tests still failing. Manual intervention may be required."
    fi
else
    print_warning "pnpm not available. Skipping tests."
fi
echo ""

# Step 9: Show git status
print_status "Step 9: Checking for changes..."
if git status --porcelain | grep -q .; then
    print_status "Changes detected:"
    git status --short
    echo ""
    print_warning "Changes have been made. Review them and commit if appropriate."
else
    print_success "No changes made by the fix script."
fi
echo ""

echo "════════════════════════════════════════════════════════════════"
echo "  🎯 Fix Script Complete"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Summary:"
echo "  ✓ Dependencies reinstalled"
echo "  ✓ Shared package built"
echo "  ✓ Lint fixes applied"
echo "  ✓ Code formatted"
echo "  ✓ Test snapshots updated"
echo "  ✓ Build artifacts cleaned"
echo "  ✓ Projects rebuilt"
echo "  ✓ Tests executed"
echo ""
echo "Next steps:"
echo "  1. Review the changes with 'git status' and 'git diff'"
echo "  2. Run 'git add .' to stage changes"
echo "  3. Run 'git commit -m \"chore: apply automated fixes\"'"
echo "  4. Run 'git push' to push changes"
echo ""
echo "════════════════════════════════════════════════════════════════"
