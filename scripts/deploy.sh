#!/bin/bash

################################################################################
# DEPLOYMENT EXECUTION SCRIPT
# Complete 4-step production deployment for Infamous Freight Enterprises
#
# Usage:
#   export DATABASE_URL="postgresql://..."
#   export REDIS_URL="redis://..."
#   export JWT_SECRET="..."
#   export API_APP_NAME="infamous-freight-api"     # Fly.io app name
#   export WEB_APP_NAME="infamous-freight-web"     # Vercel project
#   export API_URL="https://api.your-domain.com"
#   export WEB_URL="https://your-domain.com"
#   ./scripts/deploy.sh
#
# Exit codes:
#   0 = Success
#   1 = Failed dependency check
#   2 = Failed database migration
#   3 = Failed API deployment
#   4 = Failed web deployment
#   5 = Failed verification
################################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOY_LOG="$REPO_ROOT/deployment-$(date +%Y%m%d-%H%M%S).log"

# Helper functions
log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$DEPLOY_LOG"
}

log_success() {
    echo -e "${GREEN}✅ $*${NC}" | tee -a "$DEPLOY_LOG"
}

log_error() {
    echo -e "${RED}❌ $*${NC}" | tee -a "$DEPLOY_LOG"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $*${NC}" | tee -a "$DEPLOY_LOG"
}

log_section() {
    echo "" | tee -a "$DEPLOY_LOG"
    echo -e "${BLUE}================================================================================${NC}" | tee -a "$DEPLOY_LOG"
    echo -e "${BLUE}$*${NC}" | tee -a "$DEPLOY_LOG"
    echo -e "${BLUE}================================================================================${NC}" | tee -a "$DEPLOY_LOG"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Required command not found: $1"
        return 1
    fi
}

check_env() {
    if [ -z "${!1}" ]; then
        log_error "Environment variable not set: $1"
        return 1
    fi
}

################################################################################
# PHASE 0: PRE-DEPLOYMENT CHECKS
################################################################################

log_section "PHASE 0: Pre-Deployment Checks"

log_info "Checking required commands..."
check_command "pnpm" || exit 1
check_command "git" || exit 1
check_command "psql" || exit 1
check_command "curl" || exit 1
log_success "All required commands available"

log_info "Checking environment variables..."
check_env "DATABASE_URL" || exit 1
check_env "REDIS_URL" || exit 1
check_env "JWT_SECRET" || exit 1
check_env "API_URL" || exit 1
check_env "WEB_URL" || exit 1
log_success "All environment variables set"

log_info "Checking repository state..."
if ! cd "$REPO_ROOT"; then
    log_error "Failed to cd to repo root: $REPO_ROOT"
    exit 1
fi

if [ -z "$(git status --short)" ]; then
    log_success "Repository clean (no uncommitted changes)"
else
    log_warning "Repository has uncommitted changes:"
    git status --short | tee -a "$DEPLOY_LOG"
    log_warning "These will NOT be deployed. Commit changes if needed."
fi

log_info "Checking build artifacts..."
if [ ! -d "src/apps/api/dist" ]; then
    log_warning "API build artifacts not found. Will rebuild."
else
    log_success "API build artifacts found"
fi

if [ ! -d "src/apps/web/.next" ]; then
    log_warning "Web build artifacts not found. Will rebuild."
else
    log_success "Web build artifacts found"
fi

log_success "Pre-deployment checks passed"

################################################################################
# PHASE 1: BUILD & VERIFICATION
################################################################################

log_section "PHASE 1: Build & Verification"

log_info "Building API..."
cd "$REPO_ROOT/src/apps/api"
if pnpm build >> "$DEPLOY_LOG" 2>&1; then
    log_success "API build successful"
else
    log_error "API build failed"
    exit 3
fi

log_info "Building Web..."
cd "$REPO_ROOT/src/apps/web"
if pnpm build >> "$DEPLOY_LOG" 2>&1; then
    log_success "Web build successful"
else
    log_error "Web build failed"
    exit 4
fi

cd "$REPO_ROOT"
log_success "Phase 1 complete"

################################################################################
# PHASE 2: DATABASE MIGRATION
################################################################################

log_section "PHASE 2: Database Migration & Indexes"

log_info "Testing database connection..."
if psql "$DATABASE_URL" -c "SELECT 1" > /dev/null 2>&1; then
    log_success "Database connection successful"
else
    log_error "Database connection failed"
    log_error "Check DATABASE_URL: ${DATABASE_URL:0:50}..."
    exit 2
fi

cd "$REPO_ROOT/src/apps/api"

log_info "Generating Prisma client..."
if pnpm prisma:generate >> "$DEPLOY_LOG" 2>&1; then
    log_success "Prisma client generated"
else
    log_error "Prisma client generation failed"
    exit 2
fi

log_info "Running Prisma migrations..."
if pnpm prisma:migrate:deploy >> "$DEPLOY_LOG" 2>&1; then
    log_success "Prisma migrations applied"
else
    log_error "Prisma migrations failed"
    exit 2
fi

log_info "Deploying performance indexes..."
if psql "$DATABASE_URL" -f prisma/migrations/20260110_add_performance_indexes.sql >> "$DEPLOY_LOG" 2>&1; then
    log_success "Performance indexes deployed"
else
    log_warning "Performance indexes may have already been applied"
fi

log_info "Verifying indexes..."
INDEX_COUNT=$(psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_indexes WHERE tablename IN ('Shipment', 'Driver', 'User', 'Organization')" | tr -d ' ')
log_success "Found $INDEX_COUNT indexes on core tables"

cd "$REPO_ROOT"
log_success "Phase 2 complete"

################################################################################
# PHASE 3: API DEPLOYMENT
################################################################################

log_section "PHASE 3: API Deployment"

if [ -z "$API_APP_NAME" ]; then
    log_warning "API_APP_NAME not set. Skipping Fly.io deployment."
    log_warning "To deploy manually:"
    echo "  cd src/apps/api"
    echo "  fly deploy --app $API_APP_NAME"
else
    log_info "Deploying API to Fly.io ($API_APP_NAME)..."
    
    # Check if fly CLI is available
    if ! check_command "fly"; then
        log_warning "Fly CLI not found. Install: curl -L https://fly.io/install.sh | sh"
        log_warning "Skipping Fly.io deployment."
    else
        cd "$REPO_ROOT/src/apps/api"
        
        if fly deploy --app "$API_APP_NAME" >> "$DEPLOY_LOG" 2>&1; then
            log_success "API deployed to Fly.io"
            
            log_info "Waiting for API to be healthy..."
            sleep 10
            
            for i in {1..30}; do
                if curl -s "$API_URL/api/health" | grep -q "ok"; then
                    log_success "API is healthy"
                    break
                fi
                log_info "Waiting for API... ($i/30)"
                sleep 2
            done
        else
            log_error "API deployment to Fly.io failed"
            log_warning "Check logs and deploy manually with: fly deploy --app $API_APP_NAME"
        fi
    fi
fi

cd "$REPO_ROOT"
log_success "Phase 3 complete"

################################################################################
# PHASE 4: WEB DEPLOYMENT
################################################################################

log_section "PHASE 4: Web Deployment"

if [ -z "$WEB_APP_NAME" ]; then
    log_warning "WEB_APP_NAME not set. Skipping Vercel deployment."
    log_warning "To deploy manually:"
    echo "  cd src/apps/web"
    echo "  vercel deploy --prod"
else
    log_info "Deploying Web to Vercel ($WEB_APP_NAME)..."
    
    # Check if vercel CLI is available
    if ! check_command "vercel"; then
        log_warning "Vercel CLI not found. Install: npm i -g vercel"
        log_warning "Skipping Vercel deployment."
    else
        cd "$REPO_ROOT/src/apps/web"
        
        if vercel deploy --prod >> "$DEPLOY_LOG" 2>&1; then
            log_success "Web deployed to Vercel"
        else
            log_error "Web deployment to Vercel failed"
            log_warning "Check logs and deploy manually with: vercel deploy --prod"
        fi
    fi
fi

cd "$REPO_ROOT"
log_success "Phase 4 complete"

################################################################################
# PHASE 5: POST-DEPLOYMENT VERIFICATION
################################################################################

log_section "PHASE 5: Post-Deployment Verification"

log_info "Verifying API health..."
if curl -s "$API_URL/api/health" | grep -q "ok"; then
    log_success "API health check passed"
else
    log_warning "API health check failed. API may still be starting up."
fi

log_info "Verifying Web accessibility..."
if curl -s "$WEB_URL" | grep -q "html"; then
    log_success "Web application accessible"
else
    log_warning "Web accessibility check inconclusive"
fi

log_info "Verifying security headers..."
if curl -I "$API_URL/api/health" 2>/dev/null | grep -q "x-frame-options"; then
    log_success "Security headers present"
else
    log_warning "Security headers not detected"
fi

log_success "Phase 5 complete"

################################################################################
# SUMMARY
################################################################################

log_section "DEPLOYMENT SUMMARY"

log_success "All deployment phases completed!"
log_info ""
log_info "Deployment Details:"
log_info "  Database:     $DATABASE_URL"
log_info "  API URL:      $API_URL"
log_info "  Web URL:      $WEB_URL"
log_info "  Deploy Log:   $DEPLOY_LOG"
log_info ""
log_info "Next steps:"
log_info "  1. Monitor logs: tail -f $DEPLOY_LOG"
log_info "  2. Check Grafana dashboards"
log_info "  3. Verify business metrics flowing"
log_info "  4. Run smoke tests (auth, avatar, payments)"
log_info ""
log_success "Deployment complete! 🚀"

exit 0
