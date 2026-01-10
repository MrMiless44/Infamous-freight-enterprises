# Autonomous Agent Instructions - Infamous Freight Enterprises

Comprehensive instructions for all agent types working on this monorepo.

---

## 🤖 1. AUTONOMOUS CODING AGENT INSTRUCTIONS

### Mission

Autonomously implement features, fixes, and refactorings across the monorepo while maintaining code quality, security, type safety, and performance.

### Core Principles

1. **Correctness First**: Verify changes compile, types check, and tests pass before marking complete
2. **Type Safety**: All TypeScript code fully typed; no `any` unless documented with `// @ts-ignore` with reason
3. **Testing**: New features include unit tests; aim for >75% coverage (API threshold)
4. **Shared Contract**: Import types/constants from `@infamous-freight/shared` exclusively
5. **Security**: Never hardcode secrets; validate inputs; enforce auth scopes; use rate limiters
6. **Documentation**: Update comments, JSDoc, READMEs when changing APIs or patterns

### Pre-Implementation Checklist

- [ ] Read the issue/PR description fully
- [ ] Identify affected services (API, Web, Mobile, Shared, E2E)
- [ ] Check existing implementations for patterns
- [ ] Verify type definitions exist in `@infamous-freight/shared`
- [ ] Confirm database schema supports change (if data-related)
- [ ] Identify required rate limiters, auth scopes, validation rules

### Implementation Workflow

#### Phase 1: Setup & Discovery

```bash
# 1. Understand the change scope
- Read issue/PR description, acceptance criteria, acceptance tests
- Identify all files that need changes
- List breaking changes, if any

# 2. Verify shared types exist or need creation
pnpm --filter @infamous-freight/shared list
# If types missing, add to packages/shared/src/types.ts

# 3. Run baseline tests
pnpm test
pnpm check:types
```

#### Phase 2: Implement Core Logic

**API (Express.js + CommonJS)**:

1. Update Prisma schema (if data model change)
   ```bash
   cd api
   pnpm prisma:migrate:dev --name <descriptive_name>
   pnpm prisma:generate
   ```
2. Create/update service layer (`api/src/services/`)
3. Create/update route handler (`api/src/routes/`)
   - Apply middleware in order: limiters → auth → scope → auditLog → validators → handler → error
4. Add/update unit tests (`api/src/**/__tests__/`)

**Web (Next.js + TypeScript ESM)**:

1. Create/update components (`web/components/`)
2. Create/update pages/routes (`web/pages/`)
3. Update API calls to match backend
4. Add tests (`web/__tests__/`)
5. Verify type imports from shared

**Mobile (React Native/Expo)**:

1. Update screens/components
2. Verify API calls
3. Test on simulator

#### Phase 3: Shared Library Update (if needed)

```bash
# 1. Update types/constants
# - packages/shared/src/types.ts
# - packages/shared/src/constants.ts
# - packages/shared/src/utils.ts
# - packages/shared/src/env.ts

# 2. Build and propagate
pnpm --filter @infamous-freight/shared build

# 3. Update API/Web imports
# Verify: grep -r "from '@infamous-freight/shared'" api/ web/
```

#### Phase 4: Testing & Validation

```bash
# Type checking
pnpm check:types

# Unit tests (API coverage threshold ~75–84%)
pnpm --filter api test

# Web tests
pnpm --filter web test

# Lint & format
pnpm lint
pnpm format

# E2E tests (if UI changes)
cd e2e
pnpm test
```

#### Phase 5: PR & Submission

- Create branch: `feature/feature-name`, `fix/issue-name`, `chore/task-name`
- Push with descriptive commit messages
- Open PR with:
  - Linked issue(s)
  - Summary of changes
  - Testing performed
  - Screenshots (if UI)
  - Migration notes (if DB change)

### Code Quality Standards

#### API Route Template

```javascript
// api/src/routes/example.js
const express = require("express");
const {
  limiters,
  authenticate,
  requireScope,
  auditLog,
} = require("../middleware/security");
const {
  validateString,
  handleValidationErrors,
} = require("../middleware/validation");
const { logger } = require("../middleware/logger");
const { HTTP_STATUS, ApiResponse } = require("@infamous-freight/shared");
const { exampleService } = require("../services/exampleService");

const router = express.Router();

/**
 * POST /api/example/action
 * @param {string} field - Required field
 * @returns {ApiResponse<ExampleData>}
 */
router.post(
  "/action",
  limiters.general,
  authenticate,
  requireScope("example:action"),
  auditLog,
  [validateString("field"), handleValidationErrors],
  async (req, res, next) => {
    try {
      const result = await exampleService.doAction(req.body);
      logger.info("Action completed", {
        userId: req.user.sub,
        resultId: result.id,
      });
      res
        .status(HTTP_STATUS.CREATED)
        .json(new ApiResponse({ success: true, data: result }));
    } catch (err) {
      next(err);
    }
  },
);

module.exports = router;
```

#### Web Component Template (TypeScript)

```typescript
// web/components/ExampleComponent.tsx
import { ApiResponse, ExampleData, EXAMPLE_STATUSES } from "@infamous-freight/shared";
import { useState, useEffect } from "react";

interface ExampleComponentProps {
  id: string;
}

export default function ExampleComponent({ id }: ExampleComponentProps) {
  const [data, setData] = useState<ExampleData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      try {
        const res = await apiClient.get<ExampleData>(`/example/${id}`);
        setData(res.data);
      } catch (err) {
        logger.error("Failed to fetch example", { id, error: err.message });
      } finally {
        setLoading(false);
      }
    };
    fetch();
  }, [id]);

  if (loading) return <div>Loading...</div>;
  if (!data) return <div>Not found</div>;

  return (
    <div>
      <h2>{data.name}</h2>
      <p>Status: {data.status}</p>
    </div>
  );
}
```

### Common Patterns

**Error Handling**:

```javascript
// ✅ GOOD: Delegate to error handler
router.post("/action", async (req, res, next) => {
  try {
    const result = await service.action(req.body);
    res.json(new ApiResponse({ success: true, data: result }));
  } catch (err) {
    next(err); // Global errorHandler catches this
  }
});

// ❌ BAD: Manual error handling
router.post("/action", async (req, res) => {
  try {
    const result = await service.action(req.body);
    res.json({ success: true, data: result });
  } catch (err) {
    res.status(500).json({ error: err.message }); // No logging, no Sentry
  }
});
```

**Type Imports**:

```typescript
// ✅ GOOD: Import from shared
import {
  ApiResponse,
  Shipment,
  SHIPMENT_STATUSES,
} from "@infamous-freight/shared";

// ❌ BAD: Redefine types
interface Shipment {
  id: string;
  status: "pending" | "in-transit" | "delivered";
}
```

**Database Queries**:

```javascript
// ✅ GOOD: Fetch related data with include
const shipment = await prisma.shipment.findUnique({
  where: { id },
  include: { driver: true, route: true },
});

// ❌ BAD: N+1 queries
const shipment = await prisma.shipment.findUnique({ where: { id } });
const driver = await prisma.driver.findUnique({
  where: { id: shipment.driverId },
});
```

### Debugging & Troubleshooting

**Type Errors**:

```bash
pnpm check:types
# Fix imports in shared package; rebuild: pnpm --filter @infamous-freight/shared build
```

**API Tests Failing**:

```bash
cd api
pnpm test --no-coverage  # Run without coverage
pnpm test -- --testNamePattern="specific test"  # Run single test
```

**Port Conflicts**:

```bash
lsof -ti:3001 | xargs kill -9  # Kill API
lsof -ti:3000 | xargs kill -9  # Kill Web
```

**Prisma Issues**:

```bash
cd api
pnpm prisma:studio  # Visual DB browser
pnpm prisma:migrate:status  # Check migration state
pnpm prisma:migrate:reset --force  # DANGER: Reset dev DB
```

---

## 👥 2. ROLE-BASED AGENT INSTRUCTIONS

### 🔌 Backend Agent

**Scope**: API, Prisma, services, middleware, database

**Must Know**:

- Express.js middleware stack order
- Prisma ORM patterns (include, select, relations)
- JWT scope-based auth enforcement
- Rate limiting configuration per endpoint
- Error handling via errorHandler.js
- Structured logging with Winston

**Primary Files**:

- Routes: `api/src/routes/*.js`
- Services: `api/src/services/*.js`
- Middleware: `api/src/middleware/*.js`
- Schema: `api/prisma/schema.prisma`
- Tests: `api/src/**/__tests__/*.test.js`

**Checklist**:

- [ ] Route has correct middleware order
- [ ] Auth scope enforced with `requireScope()`
- [ ] Input validated with `validateString()`, etc.
- [ ] Database query uses `include` (no N+1)
- [ ] Error delegated to `next(err)`
- [ ] Logging includes userId, requestId
- [ ] Tests cover happy path + errors
- [ ] Rate limit appropriate for endpoint

---

### 🎨 Frontend Agent

**Scope**: Web (Next.js), components, pages, styling, SSR, client state

**Must Know**:

- Next.js 14 app structure, SSR patterns
- TypeScript strict mode
- Component composition best practices
- Client state management (React hooks, context)
- API integration patterns with ApiResponse
- Code splitting and lazy loading
- Vercel Analytics & Datadog RUM integration

**Primary Files**:

- Pages: `web/pages/*.tsx`
- Components: `web/components/**/*.tsx`
- Layouts: `web/components/layout/`
- Styling: `web/styles/`
- Utils: `web/lib/`
- Tests: `web/__tests__/*.test.tsx`

**Checklist**:

- [ ] Component fully typed (no `any`)
- [ ] Props interface defined
- [ ] SSR-safe (no window global in render)
- [ ] Error boundaries for critical sections
- [ ] Loading states handled
- [ ] Types imported from `@infamous-freight/shared`
- [ ] API calls wrapped in try-catch with logging
- [ ] Responsive design verified
- [ ] Accessibility (a11y) checked
- [ ] Tests cover user interactions

---

### 📱 Mobile Agent

**Scope**: React Native/Expo app, screens, navigation, device APIs

**Must Know**:

- Expo SDK capabilities
- React Navigation patterns
- Safe area handling
- Native module integration
- Device permissions
- Offline support

**Primary Files**:

- Screens: `mobile/src/screens/`
- Navigation: `mobile/src/navigation/`
- Components: `mobile/src/components/`
- Services: `mobile/src/services/`

**Checklist**:

- [ ] Works on both iOS & Android simulators
- [ ] Handles safe areas correctly
- [ ] Permissions requested properly
- [ ] API calls use same auth as Web
- [ ] Offline fallback implemented
- [ ] Performance optimized (no re-renders)
- [ ] Tests cover navigation flow

---

### 🔧 DevOps Agent

**Scope**: Docker, CI/CD, deployment, monitoring, infrastructure

**Must Know**:

- Docker Compose local dev setup
- GitHub Actions workflows
- Environment variables & secrets
- Database migrations in production
- Health checks & monitoring
- Fly.io deployment (current prod)
- Vercel deployment (Web)

**Primary Files**:

- Docker: `docker-compose.yml`, `docker-compose.prod.yml`, `Dockerfile.fly`
- CI/CD: `.github/workflows/*.yml`
- Config: `.env.example`, `fly.toml`
- Monitoring: Sentry integration

**Checklist**:

- [ ] Docker builds locally without errors
- [ ] All env vars documented in `.env.example`
- [ ] Health check passes after startup
- [ ] Migrations run automatically on deployment
- [ ] Secrets not exposed in logs
- [ ] Monitoring alerts configured
- [ ] Rollback procedure documented
- [ ] Load testing passed (if applicable)

---

### 🧪 QA Agent

**Scope**: Testing strategy, test automation, bug validation, performance

**Must Know**:

- Jest (API) & Vitest (Web) configuration
- Playwright for E2E testing
- Test coverage thresholds (API: ~75–84%)
- Bug reproduction steps
- Regression testing

**Primary Files**:

- API Tests: `api/src/**/__tests__/*.test.js`
- Web Tests: `web/__tests__/*.test.tsx`
- E2E Tests: `e2e/tests/*.spec.ts`
- Config: `jest.config.js`, `vitest.config.ts`

**Checklist**:

- [ ] Unit tests cover happy path + errors
- [ ] Integration tests validate API endpoints
- [ ] E2E tests validate user workflows
- [ ] Coverage report generated
- [ ] No flaky tests
- [ ] Tests run in CI/CD successfully

---

## 🎯 3. TASK-SPECIFIC AGENT INSTRUCTIONS

### Task: Feature Implementation

1. **Discovery**: Understand requirements, acceptance criteria, affected services
2. **Design**: DB schema, API endpoints, Web components
3. **Implement**: Shared types → API → Web → Mobile → Tests → E2E
4. **Review**: Type check, lint, tests, coverage
5. **Deploy**: Migrations, feature flags, monitoring

### Task: Bug Fix

1. **Reproduce**: Write failing test that demonstrates bug
2. **Diagnose**: Trace code path, identify root cause
3. **Fix**: Minimal change to fix root cause
4. **Verify**: Ensure test passes, no regressions
5. **Document**: Comment explaining why fix was needed

### Task: Performance Optimization

1. **Profile**: Identify bottleneck (API latency, DB queries, bundle size, Web Vitals)
2. **Benchmark**: Record baseline metric
3. **Optimize**:
   - API: Use Prisma `include`, add caching, optimize queries
   - Web: Code splitting, lazy loading, bundle analysis
   - DB: Indexes, query optimization
4. **Measure**: Confirm improvement (target: >10% faster)
5. **Monitor**: Add metric to dashboard

### Task: Security Audit

1. **Scope**: Identify auth, data validation, secret handling
2. **Review**: Check for hardcoded secrets, SQL injection, XSS, CSRF
3. **Fix**: Add validation, rate limiting, scope checks
4. **Test**: Write security-focused tests
5. **Document**: Update security guidelines

### Task: Database Migration

1. **Plan**: Design schema change, backwards compatibility
2. **Implement**: Write Prisma migration
3. **Test**: Verify migration on staging
4. **Deploy**: Run migration in production with monitoring
5. **Rollback**: Document rollback procedure

### Task: Dependency Update

1. **Identify**: New major/minor/patch version available
2. **Review**: Changelog for breaking changes
3. **Update**: Run `pnpm update package@version`
4. **Test**: Full test suite, type check
5. **Deploy**: Merge and deploy

---

## 📚 4. ENHANCED PROJECT INSTRUCTIONS

### Project Context

- **Monorepo**: 5 workspaces (api, web, mobile, shared, e2e)
- **Package Manager**: pnpm 8.15.9 with workspaces
- **Type System**: TypeScript in web/mobile/shared; CommonJS in api
- **Data**: PostgreSQL with Prisma ORM
- **Auth**: JWT with scope-based access control
- **Monitoring**: Sentry (errors), Winston (logging), Datadog RUM (Web)
- **Deployment**: Fly.io (API), Vercel (Web)

### Directory Structure

```
Infamous-freight-enterprises/
├── api/                          # Express.js backend
│   ├── src/
│   │   ├── routes/              # API endpoints
│   │   ├── services/            # Business logic
│   │   ├── middleware/          # Auth, validation, error handling
│   │   └── __tests__/           # Jest unit tests
│   ├── prisma/
│   │   ├── schema.prisma        # Data model
│   │   └── migrations/          # DB migrations
│   └── package.json
├── web/                          # Next.js 14 frontend
│   ├── pages/                   # App routes
│   ├── components/              # React components
│   ├── lib/                     # Utilities, API client
│   ├── __tests__/               # Vitest unit tests
│   └── package.json
├── mobile/                       # React Native/Expo
│   ├── src/
│   │   ├── screens/
│   │   ├── components/
│   │   └── navigation/
│   └── package.json
├── packages/
│   └── shared/                  # TypeScript shared library
│       ├── src/
│       │   ├── types.ts         # Domain types
│       │   ├── constants.ts     # Shared constants
│       │   ├── utils.ts         # Utilities
│       │   └── env.ts           # Env schemas
│       ├── dist/                # Build output
│       └── package.json
├── e2e/                         # Playwright tests
│   ├── tests/                   # Test specs
│   └── package.json
├── .github/
│   ├── workflows/               # CI/CD pipelines
│   └── copilot-instructions.md  # Copilot guidance
├── docker-compose.yml           # Local dev setup
├── docker-compose.prod.yml      # Production setup
└── package.json                 # Root workspace config
```

### Environment Variables

```bash
# API (.env)
API_PORT=4000                    # API server port
DATABASE_URL=...                 # PostgreSQL connection string
JWT_SECRET=...                   # JWT signing key
CORS_ORIGINS=...                 # CORS allowed origins
LOG_LEVEL=info                   # Winston log level
AI_PROVIDER=synthetic|openai|anthropic
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
VOICE_MAX_FILE_SIZE_MB=10
SENTRY_DSN=...
STRIPE_SECRET_KEY=...
PAYPAL_CLIENT_ID=...

# Web (.env.local)
WEB_PORT=3000
API_BASE_URL=http://localhost:4000
NEXT_PUBLIC_ENV=development|production
NEXT_PUBLIC_DD_APP_ID=...       # Datadog RUM
NEXT_PUBLIC_DD_CLIENT_TOKEN=...
NEXT_PUBLIC_DD_SITE=...
```

### Critical Commands

```bash
# Development
pnpm dev                           # All services
pnpm api:dev                       # API only
pnpm web:dev                       # Web only

# Testing
pnpm test                          # All tests
pnpm --filter api test             # API tests only
pnpm --filter api test --coverage  # With coverage

# Build & Deploy
pnpm build                         # All packages
pnpm --filter web build
pnpm --filter api build           # If applicable

# Database
cd api
pnpm prisma:migrate:dev --name "description"
pnpm prisma:studio                # Visual DB browser
pnpm prisma:generate              # Regenerate Prisma client

# Shared Library
pnpm --filter @infamous-freight/shared build  # Always rebuild after type changes

# Code Quality
pnpm lint                          # ESLint
pnpm format                        # Prettier
pnpm check:types                   # TypeScript
```

### API Authentication & Authorization

**Scope-Based Access Control**:

```javascript
// Each route declares required scope(s)
router.post("/ai/command", requireScope("ai:command"), handler);
router.post("/voice/ingest", requireScope("voice:ingest"), handler);
router.post("/billing/checkout", requireScope("billing:checkout"), handler);

// Scopes granted via JWT claims or API key permissions
```

**Rate Limiters** (preset in `security.js`):

- `limiters.general`: 100 requests / 15 min
- `limiters.auth`: 5 requests / 15 min (login, register)
- `limiters.ai`: 20 requests / 1 min (expensive operations)
- `limiters.billing`: 30 requests / 15 min

### Shared Type System

**All domain types live in `packages/shared/src/types.ts`**:

```typescript
export interface Shipment {
  id: string;
  status: (typeof SHIPMENT_STATUSES)[number];
  origin: string;
  destination: string;
  driverId?: string;
  driver?: Driver;
  createdAt: Date;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export const SHIPMENT_STATUSES = [
  "pending",
  "in-transit",
  "delivered",
  "failed",
] as const;

export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  NOT_FOUND: 404,
  INTERNAL_ERROR: 500,
} as const;
```

**Import everywhere**:

```javascript
// ✅ Correct
const { ApiResponse, Shipment, SHIPMENT_STATUSES } = require("@infamous-freight/shared");

// ❌ Never define locally
interface Shipment { /* ... */ }
```

---

## 🎪 5. MULTI-AGENT ORCHESTRATION INSTRUCTIONS

### Agent Coordination

#### Phase 1: Planning (Orchestrator Agent)

1. **Parse request**: Break down into atomic tasks
2. **Assign specialists**: Backend, Frontend, Mobile, QA, DevOps
3. **Set dependencies**: Identify sequential vs. parallel work
4. **Communicate**: Each agent knows start/end states

#### Phase 2: Parallel Execution

**Parallel Work Streams** (can execute simultaneously):

```
Backend Agent: API routes, services, DB schema
    ↓
Web Agent: Components, pages, API integration (depends on Backend types)
    ↓
Mobile Agent: Screens, navigation (depends on Backend API)
    ↓
QA Agent: Unit tests, E2E tests (depends on implementations)
```

**Sequential Dependencies**:

- Shared types must be defined & built before API implementation
- API routes must be implemented before Web/Mobile integrations
- All changes must pass tests before QA approval

#### Phase 3: Integration & Testing

1. **Type Check**: `pnpm check:types` (all agents verify)
2. **Unit Tests**: Each agent runs their test suite
3. **Integration Tests**: QA agent validates end-to-end
4. **Performance Check**: DevOps agent profiles if applicable
5. **Security Audit**: Backend agent reviews auth/validation

#### Phase 4: Deployment

1. **Build Artifacts**: `pnpm build`
2. **Run Migrations**: DevOps agent applies DB changes
3. **Deploy API**: Fly.io deployment
4. **Deploy Web**: Vercel deployment
5. **Monitor**: Sentry, Datadog, health checks

### Agent Communication Protocol

**When Agent A Blocks Agent B**:

1. Agent A: "Type definitions for `Shipment` are ready in shared package"
2. Agent B: Rebuilds shared, imports types, proceeds
3. Agent B: "Web integration complete; E2E tests ready"
4. QA Agent: Runs E2E tests, confirms functionality

**Conflict Resolution**:

- **Type conflicts**: Always use shared types, never redefine
- **API changes**: Broadcast to Web/Mobile agents immediately
- **DB schema**: Coordinate with all agents before migration
- **Breaking changes**: Feature flag or versioning required

### Multi-Agent Command Examples

```bash
# Agent 1: Backend — Implement API & migrations
cd api
pnpm prisma:migrate:dev --name "add-shipment-tracking"
# Updates Prisma client, generates types

# Agent 2: Shared — Build library (triggered by Agent 1 request)
pnpm --filter @infamous-freight/shared build
# Exports updated types to dist/

# Agent 3: Web — Integrate with new API
pnpm --filter web dev
# Imports types from shared, builds components

# Agent 4: Mobile — Mirror Web integration
pnpm --filter mobile dev
# Same types, parallel implementation

# Agent 5: QA — Run tests
pnpm test
pnpm --filter e2e test
# Validates all integrations

# Agent 6: DevOps — Prepare deployment
docker-compose -f docker-compose.prod.yml build
# All agents' changes included in Docker images
```

### Escalation Protocol

**If Agent Encounters Blocker**:

1. **Identify**: Type missing, API undefined, circular dependency
2. **Notify**: Escalate to Orchestrator with clear description
3. **Wait**: Orchestrator redirects to blocking agent
4. **Resume**: Blocking agent unblocks; waiting agent continues

### Success Criteria for Multi-Agent Tasks

✅ All agents complete their work
✅ Type system fully typed, no `any`
✅ Tests pass: unit, integration, E2E
✅ `pnpm lint` and `pnpm format` clean
✅ `pnpm check:types` passes
✅ `pnpm build` succeeds for all packages
✅ Docker build successful
✅ Monitoring alerts configured
✅ PR description mentions all agents' work
✅ Code review approved by relevant specialists

---

## 📋 UNIVERSAL AGENT RULES

### Always Enforce

1. **Shared Types**: Import from `@infamous-freight/shared`, never redefine
2. **Type Safety**: No `any`; full TypeScript strict mode
3. **Error Handling**: Delegate to `next(err)` in API; use try-catch in Web/Mobile
4. **Testing**: New code = new tests; maintain coverage thresholds
5. **Security**: Validate inputs, enforce auth scopes, use rate limiters
6. **Logging**: Structured logs with context (userId, requestId, timestamps)
7. **Migrations**: DB changes via Prisma migrations, never manual SQL
8. **Code Quality**: Lint + format on commit; type-check before push
9. **Documentation**: Comments for complex logic; JSDoc for public APIs
10. **Performance**: Profile before optimizing; benchmark improvements

### Never Do

- ❌ Hardcode secrets or API keys
- ❌ Skip error handling (`async/await` without try-catch)
- ❌ Redefine types locally
- ❌ Mix auth patterns (always JWT + scopes)
- ❌ Leave console.log in production code
- ❌ Modify Prisma schema without migration
- ❌ Commit to main directly (use PRs)
- ❌ Skip tests for "small" changes
- ❌ Use `any` type (or document why)
- ❌ Make breaking API changes without versioning/flags

### When in Doubt

1. Check `copilot-instructions.md` for project context
2. Look for existing implementations (patterns, not copy-paste)
3. Ask Orchestrator or run `pnpm check:types` + `pnpm test`
4. Verify with other agents before integrating
5. Document assumptions in PR description

---

## 🚀 Quick Start for Each Agent

### Backend Agent

```bash
pnpm dev  # Start all services
cd api
pnpm test --watch  # Watch for changes
# Edit: api/src/routes/, api/src/services/, api/prisma/schema.prisma
```

### Frontend Agent

```bash
pnpm dev  # Start all services
# Edit: web/pages/, web/components/
pnpm lint  # Check formatting
```

### Mobile Agent

```bash
cd mobile
pnpm start  # Start Expo
# Edit: mobile/src/screens/, mobile/src/components/
```

### QA Agent

```bash
pnpm test  # All tests
cd e2e
pnpm test --headed  # See tests run
```

### DevOps Agent

```bash
docker-compose -f docker-compose.prod.yml build  # Test build
# Edit: docker-compose.yml, .github/workflows/, fly.toml
```

---

**Last Updated**: January 2, 2026
**Project**: Infamous Freight Enterprises
**Maintained By**: Development Team
