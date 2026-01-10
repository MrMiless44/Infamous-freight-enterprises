#!/bin/bash
# Local Development Setup Script
# Initializes all dependencies and local databases for Infamous Freight

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log() {
  echo -e "${BLUE}→${NC} $1"
}

success() {
  echo -e "${GREEN}✓${NC} $1"
}

warn() {
  echo -e "${YELLOW}⚠${NC} $1"
}

error() {
  echo -e "${RED}✗${NC} $1"
  exit 1
}

# Check prerequisites
log "Checking prerequisites..."

# Check Node.js
if ! command -v node &> /dev/null; then
  error "Node.js not found. Install from https://nodejs.org/"
fi
success "Node.js $(node --version)"

# Check pnpm
if ! command -v pnpm &> /dev/null; then
  error "pnpm not found. Install with: npm install -g pnpm@8.15.9"
fi
success "pnpm $(pnpm --version)"

# Check Docker
if ! command -v docker &> /dev/null; then
  error "Docker not found. Install from https://docker.com/"
fi
success "Docker $(docker --version)"

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
  error "Docker Compose not found. Install from https://docs.docker.com/compose/"
fi
success "Docker Compose $(docker-compose --version)"

# Create .env files
log "Setting up environment files..."

if [ ! -f .env.local ]; then
  log "Creating .env.local from .env.example..."
  cp .env.example .env.local
  
  # Set development defaults
  sed -i 's/NODE_ENV=.*/NODE_ENV=development/' .env.local
  sed -i 's/API_PORT=.*/API_PORT=4000/' .env.local
  sed -i 's/WEB_PORT=.*/WEB_PORT=3000/' .env.local
  
  success "Created .env.local"
else
  success ".env.local already exists"
fi

# API environment
if [ ! -f src/apps/api/.env.local ]; then
  log "Creating src/apps/api/.env.local..."
  cat > src/apps/api/.env.local << 'EOF'
NODE_ENV=development
API_PORT=4000
DATABASE_URL=postgresql://infamous:infamouspass@localhost:5432/infamous_freight
LOG_LEVEL=debug
JWT_SECRET=dev-secret-$(openssl rand -hex 16)
CORS_ORIGINS=http://localhost:3000,http://localhost:19006
AI_PROVIDER=synthetic
VOICE_MAX_FILE_SIZE_MB=10
EOF
  success "Created src/apps/api/.env.local"
fi

# Web environment
if [ ! -f src/apps/web/.env.local ]; then
  log "Creating src/apps/web/.env.local..."
  cat > src/apps/web/.env.local << 'EOF'
WEB_PORT=3000
NEXT_PUBLIC_API_BASE_URL=http://localhost:4000
NEXT_PUBLIC_ENV=development
EOF
  success "Created src/apps/web/.env.local"
fi

# Start Docker services
log "Starting Docker services..."

if docker-compose ps | grep -q "postgres"; then
  warn "PostgreSQL already running"
else
  log "Starting PostgreSQL..."
  docker-compose up -d postgres
  sleep 3
  success "PostgreSQL started"
fi

if docker-compose ps | grep -q "redis"; then
  warn "Redis already running"
else
  log "Starting Redis..."
  docker-compose up -d redis
  sleep 2
  success "Redis started"
fi

# Install dependencies
log "Installing dependencies..."
pnpm install --frozen-lockfile
success "Dependencies installed"

# Database setup
log "Setting up database..."

cd src/apps/api

if ! pnpm exec prisma db push --skip-generate &> /dev/null; then
  log "Running initial migration..."
  pnpm exec prisma db push
fi

success "Database schema synchronized"

# Generate Prisma client
log "Generating Prisma client..."
pnpm exec prisma generate
success "Prisma client generated"

# Seed database (optional)
if [ -f prisma/seed.ts ]; then
  log "Seeding database..."
  pnpm exec prisma db seed
  success "Database seeded"
fi

# Database verification
log "Verifying database..."
TABLES=$(pnpm exec prisma db execute --stdin << 'SQL'
SELECT COUNT(*) FROM information_schema.tables 
WHERE table_schema = 'public';
SQL
)

if [ -n "$TABLES" ]; then
  success "Database verified"
else
  error "Database verification failed"
fi

cd ../..

# Build shared library
log "Building shared library..."
pnpm --filter @infamous-freight/shared build
success "Shared library built"

# Type checking
log "Running type check..."
pnpm check:types
success "Type check passed"

# Setup git hooks
log "Setting up git hooks..."
pnpm husky install
success "Git hooks installed"

# Port check
log "Checking for port conflicts..."

check_port() {
  local PORT=$1
  local NAME=$2
  if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    warn "Port $PORT ($NAME) already in use"
    echo "Kill with: lsof -ti:$PORT | xargs kill -9"
  fi
}

check_port 3000 "Web"
check_port 4000 "API"
check_port 5432 "PostgreSQL"
check_port 6379 "Redis"

# Summary
cat << 'EOF'

╔════════════════════════════════════════════════════════════════╗
║        ✅ Development Environment Setup Complete!              ║
╚════════════════════════════════════════════════════════════════╝

📁 Project Structure:
  src/apps/api/          - Express.js backend
  src/apps/web/          - Next.js frontend
  src/apps/mobile/       - React Native app
  src/packages/shared/   - TypeScript shared library

🚀 Start Development:
  pnpm dev               - Start all services
  pnpm api:dev           - Start API only
  pnpm web:dev           - Start Web only

📊 View Database:
  pnpm prisma:studio    - Open Prisma Studio

✅ Run Tests:
  pnpm test              - All tests
  pnpm test:api          - API tests only
  pnpm test:watch        - Watch mode

🔧 Environment Files:
  .env.local             - Root configuration
  src/apps/api/.env.local     - API configuration
  src/apps/web/.env.local     - Web configuration

📖 Documentation:
  cat README.md          - Project overview
  cat .github/agent-instructions.md  - AI agent guidance

🐳 Docker Containers:
  docker-compose ps      - View running services
  docker-compose logs    - View service logs
  docker-compose down    - Stop services

⚠️  Troubleshooting:
  Port conflicts: lsof -ti:PORT | xargs kill -9
  DB issues: pnpm prisma:migrate:reset
  Clean install: rm -rf node_modules pnpm-lock.yaml && pnpm install

👤 First Run Tips:
  1. Create test user: API runs at http://localhost:4000
  2. Login to http://localhost:3000 with test credentials
  3. Check browser console for API calls
  4. Monitor API logs: pnpm logs:api

🆘 Need Help?
  - Check docs/: Documentation guides
  - Review .github/copilot-instructions.md: Architecture notes
  - Run: pnpm check:types (verify all types)

EOF

success "Setup complete! Run 'pnpm dev' to start development"
