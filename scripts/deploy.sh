#!/bin/bash
# Automated deployment script for Vercel (Web) and Fly.io (API)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Infamous Freight - Deployment Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check prerequisites
command -v vercel >/dev/null 2>&1 || {
  echo -e "${RED}Error: Vercel CLI not found. Install it with: npm i -g vercel${NC}"
  exit 1
}

command -v flyctl >/dev/null 2>&1 || {
  echo -e "${RED}Error: Fly CLI not found. Install it from: https://fly.io/docs/hands-on/install-flyctl/${NC}"
  exit 1
}

# Parse arguments
ENVIRONMENT="${1:-production}"
SKIP_WEB="${2:-false}"
SKIP_API="${3:-false}"

echo -e "${YELLOW}Deployment Environment: $ENVIRONMENT${NC}"
echo ""

# Deploy Web to Vercel
if [ "$SKIP_WEB" != "true" ]; then
  echo -e "${GREEN}Step 1: Deploying Web to Vercel...${NC}"
  cd web
  
  if [ "$ENVIRONMENT" == "production" ]; then
    vercel --prod
  else
    vercel
  fi
  
  cd ..
  echo -e "${GREEN}✓ Web deployed successfully${NC}"
  echo ""
else
  echo -e "${YELLOW}Skipping Web deployment${NC}"
fi

# Deploy API to Fly.io
if [ "$SKIP_API" != "true" ]; then
  echo -e "${GREEN}Step 2: Deploying API to Fly.io...${NC}"
  cd api
  
  # Check if fly.toml exists
  if [ ! -f "fly.toml" ]; then
    echo -e "${YELLOW}No fly.toml found. Creating new app...${NC}"
    flyctl launch --no-deploy
  fi
  
  # Deploy
  flyctl deploy
  
  cd ..
  echo -e "${GREEN}✓ API deployed successfully${NC}"
  echo ""
else
  echo -e "${YELLOW}Skipping API deployment${NC}"
fi

# Database migrations
echo -e "${GREEN}Step 3: Running database migrations...${NC}"
cd api
pnpm prisma:migrate || echo -e "${YELLOW}Migration skipped or failed${NC}"
cd ..

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Next steps:"
echo -e "1. Verify web deployment at your Vercel URL"
echo -e "2. Verify API deployment at your Fly.io URL"
echo -e "3. Update NEXT_PUBLIC_API_URL in Vercel environment variables"
echo -e "4. Test the application"
echo ""
