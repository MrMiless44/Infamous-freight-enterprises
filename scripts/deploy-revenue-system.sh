#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════════
# MASTER REVENUE SYSTEM DEPLOYMENT SCRIPT
# Executes all 6 phases automatically (where possible)
# ═══════════════════════════════════════════════════════════════════════════════

set -e

echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                   💰 REVENUE SYSTEM MASTER DEPLOYMENT 💰                     ║"
echo "║                                                                               ║"
echo "║                        Complete 6-Phase Execution                            ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Check if running in CI/CD
if [ -n "$CI" ]; then
  echo "Running in CI/CD mode"
  INTERACTIVE=false
else
  INTERACTIVE=true
fi

# Phase status tracking
PHASE1_DONE=false
PHASE2_DONE=false
PHASE3_DONE=false
PHASE4_DONE=false
PHASE5_DONE=false
PHASE6_DONE=false

# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTION START
# ═══════════════════════════════════════════════════════════════════════════════

echo "Starting revenue system deployment..."
echo "This will execute all 6 phases of the deployment process."
echo ""

read -p "Are you ready to begin? (yes/no): " START

if [ "$START" != "yes" ]; then
  echo "Deployment cancelled."
  exit 0
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: PAYMENT INFRASTRUCTURE SETUP
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 1: PAYMENT INFRASTRUCTURE SETUP${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase1-setup-accounts.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase1-setup-accounts.sh"
  PHASE1_DONE=true
  echo -e "${GREEN}✓ Phase 1 Complete${NC}"
else
  echo -e "${RED}✗ Phase 1 script not found${NC}"
  exit 1
fi

echo ""
read -p "Press ENTER to continue to Phase 2... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: ENVIRONMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 2: ENVIRONMENT CONFIGURATION${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase2-configure-environment.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase2-configure-environment.sh"
  PHASE2_DONE=true
  echo -e "${GREEN}✓ Phase 2 Complete${NC}"
else
  echo -e "${RED}✗ Phase 2 script not found${NC}"
  exit 1
fi

echo ""
read -p "Press ENTER to continue to Phase 3... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: FRONTEND DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 3: FRONTEND DEPLOYMENT & TESTING${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase3-deploy-frontend.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase3-deploy-frontend.sh"
  PHASE3_DONE=true
  echo -e "${GREEN}✓ Phase 3 Complete${NC}"
else
  echo -e "${RED}✗ Phase 3 script not found${NC}"
  exit 1
fi

echo ""
read -p "Press ENTER to continue to Phase 4... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: PAYMENT VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 4: PAYMENT FLOW VERIFICATION${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase4-verify-payments.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase4-verify-payments.sh"
  PHASE4_DONE=true
  echo -e "${GREEN}✓ Phase 4 Complete${NC}"
else
  echo -e "${RED}✗ Phase 4 script not found${NC}"
  exit 1
fi

echo ""
read -p "Press ENTER to continue to Phase 5... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: PRODUCTION LAUNCH
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 5: PRODUCTION LAUNCH${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

echo -e "${YELLOW}⚠️  WARNING: Phase 5 will enable LIVE payments!${NC}"
read -p "Continue to production launch? (yes/no): " LAUNCH

if [ "$LAUNCH" = "yes" ]; then
  if [ -f "$SCRIPT_DIR/revenue-deployment/phase5-production-launch.sh" ]; then
    bash "$SCRIPT_DIR/revenue-deployment/phase5-production-launch.sh"
    PHASE5_DONE=true
    echo -e "${GREEN}✓ Phase 5 Complete${NC}"
  else
    echo -e "${RED}✗ Phase 5 script not found${NC}"
    exit 1
  fi
else
  echo -e "${YELLOW}⚠ Skipping Phase 5. Run manually when ready.${NC}"
fi

echo ""
read -p "Press ENTER to continue to Phase 6... "
echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: MONITORING & DOCUMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}PHASE 6: MONITORING & DOCUMENTATION${NC}"
echo "═══════════════════════════════════════════════════════════════════════════════"

if [ -f "$SCRIPT_DIR/revenue-deployment/phase6-monitoring.sh" ]; then
  bash "$SCRIPT_DIR/revenue-deployment/phase6-monitoring.sh"
  PHASE6_DONE=true
  echo -e "${GREEN}✓ Phase 6 Complete${NC}"
else
  echo -e "${RED}✗ Phase 6 script not found${NC}"
  exit 1
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT COMPLETE
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
echo "║                    🎉 ALL PHASES COMPLETE! 🎉                                ║"
echo "║                                                                               ║"
echo "║                  YOUR REVENUE SYSTEM IS LIVE!                                ║"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo ""

echo "DEPLOYMENT SUMMARY:"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "Phase 1: Payment Infrastructure     [$( [ "$PHASE1_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 2: Environment Configuration  [$( [ "$PHASE2_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 3: Frontend Deployment        [$( [ "$PHASE3_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 4: Payment Verification       [$( [ "$PHASE4_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 5: Production Launch          [$( [ "$PHASE5_DONE" = true ] && echo "✓" || echo "✗" )]"
echo "Phase 6: Monitoring & Documentation [$( [ "$PHASE6_DONE" = true ] && echo "✓" || echo "✗" )]"
echo ""

echo "📚 DOCUMENTATION CREATED:"
echo "• REVENUE_DASHBOARD_GUIDE.md"
echo "• REVENUE_OPERATIONS_RUNBOOK.md"
echo "• REVENUE_SUCCESS_METRICS.md"
echo "• monitoring/revenue-alerts.yml"
echo ""

echo "🚀 NEXT STEPS:"
echo "1. Monitor Stripe dashboard for first payments"
echo "2. Track MRR growth daily"
echo "3. Review email delivery rates"
echo "4. Watch for alerts"
echo "5. Celebrate first $1k MRR! 🎊"
echo ""

echo "💰 START MAKING MONEY! 💰"
echo ""
