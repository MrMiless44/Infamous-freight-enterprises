# Development Setup Guide

## 📋 Prerequisites

- **Node.js:** 18+ (recommended 20.x)
- **pnpm:** 8.15.9+
- **Docker:** 20.10+ (for local database/Redis)
- **PostgreSQL:** 14+ (if running without Docker)
- **Redis:** 7+ (optional, for caching)
- **Git:** 2.30+

## 🚀 Quick Start (5 minutes)

### 1. Clone Repository

```bash
git clone https://github.com/MrMiless44/Infamous-freight-enterprises.git
cd Infamous-freight-enterprises
```

### 2. Install Dependencies

```bash
pnpm install
```

### 3. Set Up Environment

```bash
# Copy example env file
cp .env.example .env.local

# Edit with your values
nano .env.local
```

**Required Environment Variables:**

```bash
# Database
DATABASE_URL="postgresql://user:password@localhost:5432/infamous_dev"

# Redis (optional)
REDIS_URL="redis://localhost:6379"

# JWT
JWT_SECRET="your-secret-key-min-32-chars"
JWT_REFRESH_SECRET="your-refresh-secret-min-32-chars"

# API
API_PORT=4000
API_BASE_URL="http://localhost:4000"

# Web
WEB_PORT=3000

# Email (optional)
EMAIL_SERVICE_ENABLED=false
EMAIL_HOST="smtp.gmail.com"
EMAIL_PORT=587
EMAIL_USER="your-email@gmail.com"
EMAIL_PASS="your-app-password"

# AI Provider (optional)
AI_PROVIDER="synthetic"  # or "openai" / "anthropic"
OPENAI_API_KEY=""
ANTHROPIC_API_KEY=""
```

### 4. Start Services

```bash
# Start all services (API, Web, Database, Redis)
pnpm dev

# Or start individually
pnpm api:dev      # API on port 4000
pnpm web:dev      # Web on port 3000
```

### 5. Verify Setup

```bash
# API health check
curl http://localhost:4000/api/health

# Open web app
open http://localhost:3000
```

---

## 🗄️ Database Setup

### Option 1: Docker Compose (Recommended)

```bash
# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Run migrations
cd src/apps/api
pnpm prisma migrate deploy

# Seed database (optional)
pnpm prisma db seed
```

### Option 2: Local PostgreSQL

```bash
# Create database
createdb infamous_dev

# Set DATABASE_URL in .env.local
DATABASE_URL="postgresql://user:password@localhost:5432/infamous_dev"

# Run migrations
cd src/apps/api
pnpm prisma migrate deploy
```

### Option 3: Database Studio (GUI)

```bash
# Open Prisma Studio to browse data
cd src/apps/api
pnpm prisma studio
# Opens http://localhost:5555
```

---

## 🧪 Testing

### Run All Tests

```bash
pnpm test
```

### Run Specific Test Suite

```bash
# API tests
pnpm --filter infamous-freight-api test

# Web tests
pnpm --filter infamous-freight-web test

# Security tests
pnpm --filter infamous-freight-api test security/sql-injection
```

### Test Coverage

```bash
# Generate coverage report
pnpm test -- --coverage

# View HTML report
open api/coverage/lcov-report/index.html
```

### Watch Mode (Auto-rerun on changes)

```bash
pnpm test -- --watch
```

---

## 🏗️ Project Structure

```
├── src/apps/
│   ├── api/                    # Express.js backend (CommonJS)
│   │   ├── src/
│   │   │   ├── routes/        # API endpoints
│   │   │   ├── middleware/    # Express middleware
│   │   │   ├── services/      # Business logic
│   │   │   ├── config/        # Configuration
│   │   │   ├── __tests__/     # Test files
│   │   │   └── server.ts      # Server entry
│   │   ├── prisma/            # Database schema
│   │   └── package.json
│   │
│   ├── web/                    # Next.js frontend (TypeScript)
│   │   ├── pages/             # Route pages
│   │   ├── components/        # React components
│   │   ├── public/            # Static assets
│   │   └── package.json
│   │
│   └── mobile/                 # React Native/Expo
│       └── package.json
│
├── packages/
│   └── shared/                 # Shared types & utilities
│       ├── src/
│       │   ├── types.ts       # Shared TypeScript types
│       │   ├── constants.ts   # Shared constants
│       │   └── utils.ts       # Shared utilities
│       └── package.json
│
├── docs/                       # Documentation
│   ├── architecture/          # Architecture Decision Records
│   ├── operations/            # Runbooks & guides
│   └── README.md
│
├── monitoring/                 # Monitoring configuration
│   ├── grafana/              # Grafana dashboards
│   ├── prometheus/           # Prometheus config
│   └── alertmanager/         # Alert rules
│
└── docker-compose.yml        # Local development stack
```

---

## 📝 Common Development Tasks

### Add New API Endpoint

```bash
# 1. Create route file
touch src/apps/api/src/routes/my-feature.ts

# 2. Add middleware and handlers
# See existing routes for pattern

# 3. Register in server.ts
import { myFeature } from "./routes/my-feature";
app.use("/api/my-feature", myFeature);

# 4. Update shared types if needed
vim packages/shared/src/types.ts

# 5. Test endpoint
curl http://localhost:4000/api/my-feature
```

### Update Database Schema

```bash
# 1. Edit schema
vim src/apps/api/prisma/schema.prisma

# 2. Create migration
cd src/apps/api
pnpm prisma migrate dev --name describe_change

# 3. Generate client
pnpm prisma generate

# 4. Rebuild
pnpm build
```

### Add New React Component

```bash
# 1. Create component
touch src/apps/web/components/MyComponent.tsx

# 2. Write component with TypeScript
# Import types from @infamous-freight/shared

# 3. Use in page
import MyComponent from '@/components/MyComponent';

# 4. Test
pnpm web:dev
open http://localhost:3000
```

### Update Shared Package

```bash
# 1. Edit code
vim packages/shared/src/types.ts

# 2. Rebuild shared
pnpm --filter @infamous-freight/shared build

# 3. Restart services
# Changes auto-detected in development
```

---

## 🔧 Development Tools

### Code Formatting

```bash
# Format all code
pnpm format

# Format specific file
pnpm format src/apps/api/src/server.ts
```

### Linting

```bash
# Lint all code
pnpm lint

# Fix linting errors
pnpm lint -- --fix
```

### Type Checking

```bash
# Check TypeScript types
pnpm check:types

# Watch mode
pnpm check:types -- --watch
```

### Build

```bash
# Build all packages
pnpm build

# Build specific package
pnpm --filter infamous-freight-api build
```

---

## 🐛 Debugging

### VS Code Debugging

**Launch Configuration (.vscode/launch.json):**

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "node",
      "request": "launch",
      "name": "Debug API",
      "program": "${workspaceFolder}/src/apps/api/dist/server.js",
      "cwd": "${workspaceFolder}/src/apps/api",
      "runtimeArgs": ["--nolazy"],
      "port": 9229,
      "protocol": "inspector"
    }
  ]
}
```

### API Debugging

```bash
# Start API with debugger
node --inspect src/apps/api/dist/server.js

# Open Chrome DevTools: chrome://inspect
# Click on Node process to debug
```

### Database Debugging

```bash
# View all queries
psql $DATABASE_URL -c "SET log_min_duration_statement = 0;"

# View slow queries (>100ms)
psql $DATABASE_URL -c "SET log_min_duration_statement = 100;"
```

---

## 📚 Learning Resources

### Architecture

- [README.md](../README.md) - Project overview
- [Architecture Docs](../docs/architecture/) - ADRs and design decisions
- [API Documentation](http://localhost:3001/api/docs) - OpenAPI/Swagger

### Code Examples

- API Routes: `src/apps/api/src/routes/`
- Middleware: `src/apps/api/src/middleware/`
- React Components: `src/apps/web/components/`
- Shared Types: `packages/shared/src/types.ts`

### External Resources

- [Express.js Docs](https://expressjs.com/)
- [Next.js Docs](https://nextjs.org/docs)
- [Prisma Docs](https://www.prisma.io/docs/)
- [TypeScript Docs](https://www.typescriptlang.org/docs/)

---

## 🐛 Troubleshooting

### Issue: Database connection failed

```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# If not, start it
docker-compose up -d postgres

# Check connection string
echo $DATABASE_URL
```

### Issue: Port already in use

```bash
# Find process using port 4000
lsof -i :4000

# Kill it
kill -9 <PID>

# Or use different port
API_PORT=4001 pnpm api:dev
```

### Issue: TypeScript errors after changes

```bash
# Rebuild shared package
pnpm --filter @infamous-freight/shared build

# Restart services
pnpm dev
```

### Issue: Tests failing

```bash
# Clear test cache
pnpm test -- --clearCache

# Run with verbose output
pnpm test -- --verbose
```

---

## 📞 Getting Help

1. **Check Documentation:** `docs/` folder
2. **Review Tests:** See `__tests__/` folders for examples
3. **Check Slack:** #engineering channel
4. **Create Issue:** GitHub Issues with detailed reproduction steps

---

## ✅ Verification Checklist

After setup, verify everything works:

- [ ] `pnpm install` completes without errors
- [ ] `pnpm build` produces no TypeScript errors
- [ ] `pnpm test` passes all tests
- [ ] `pnpm api:dev` starts API on port 4000
- [ ] `pnpm web:dev` starts Web on port 3000
- [ ] Database migrations applied (`pnpm prisma migrate deploy`)
- [ ] `curl http://localhost:4000/api/health` returns 200
- [ ] `open http://localhost:3000` loads website
- [ ] Can log in with test account
- [ ] API documentation at `http://localhost:4000/api/docs`

---

**Last Updated:** 2026-01-10  
**Maintainer:** Platform Engineering Team  
**Questions?** Slack #engineering or email: engineering@infamous-freight.com
