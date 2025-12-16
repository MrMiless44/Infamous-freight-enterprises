# GitHub Copilot Instructions for Infamous Freight Enterprises

## 🏗️ Architecture Overview

**Monorepo Structure** (pnpm workspaces @ 7.5.1):
- `api/` - Express.js backend (port 4000 default, configurable via `API_PORT`), **CommonJS** via `require()`
- `web/` - Next.js 14 frontend (port 3000), **TypeScript/ESM** via `import`
- `mobile/` - React Native/Expo app (TypeScript)
- `packages/shared/` - TypeScript package with shared types, constants, utilities (`@infamous-freight/shared`)
- `e2e/` - Playwright end-to-end tests

**Data Flow**: API ↔ PostgreSQL (Prisma ORM) | Web/Mobile ↔ API (REST + scope-based auth)

**Critical**: Shared package exports domain types, constants, and utils that **MUST be imported from `@infamous-freight/shared`** everywhere — never redefine. The shared package must be **built before API startup** when types change: `pnpm --filter @infamous-freight/shared build`

## 🔌 Service Communication Patterns

### API Architecture (Express.js + CommonJS)
**Routes** (`api/src/routes/`): 
- `health.js` - Liveness/readiness probes
- `ai.commands.js` - AI inference with scope-based auth + rate limiting
- `voice.js` - Audio ingest & text commands, Multer file upload
- `billing.js` - Stripe/PayPal integration
- `shipments.js`, `users.js` - CRUD with Prisma

**Middleware Stack** (`api/src/middleware/`):
- **security.js** - JWT auth, `authenticate()` + `requireScope()`, per-endpoint rate limiters
  - Exports: `limiters` (general, auth, billing, ai), `authenticate`, `requireScope`, `auditLog`
  - Rate limits: general 100/15min, auth 5/15min, ai 20/1min, billing 30/15min
  - Maintains set of allowed JWT scopes per route
  
- **validation.js** - `validateString()` + `handleValidationErrors()` via express-validator
  - Reusable validators: `validateEmail()`, `validatePhone()`, `validateUUID()`
  - Always pair with `handleValidationErrors` to catch and format violations
  
- **errorHandler.js** - Global error catch-all, converts errors to HTTP status codes
  - Catches all errors from route handlers via `next(error)`
  - Custom errors with `.status` property → converted to HTTP response
  - Integrates with Sentry for error tracking
  
- **logger.js** - Winston HTTP logger, Sentry integration
  - Exports: `logger` (structured logging), `httpLogger` (middleware for HTTP requests)
  - Used in: error reporting, request tracing, AI service calls
  
- **securityHeaders.js** - Helmet CSP, HSTS, clickjacking prevention
  - Applied early in server startup
  - Configurable CSP directives for API/external resource restrictions

**Key Pattern**: All route handlers follow strict order:
```javascript
router.METHOD(
  "/path",
  limiters.specific,           // 1. Rate limiting first
  authenticate,                // 2. JWT verification
  requireScope("scope:name"),  // 3. Permission check
  auditLog,                    // 4. Audit trail
  [validators...],             // 5. Input validation
  handleValidationErrors,      // 6. Validation error handler
  async (req, res, next) => {  // 7. Route handler
    try {
      const result = await business logic;
      res.json(new ApiResponse({ success: true, data: result }));
    } catch (err) {
      next(err);  // → Global errorHandler
    }
  }
);
```
**Critical**: Never break this order. Middleware at top protects handlers below it.

**Database**: Prisma ORM in `api/prisma/schema.prisma` with models: User, Driver, Shipment, AiEvent

### Web Frontend (Next.js + TypeScript)
**Pages** (`web/pages/`): `_app.tsx`, `index.tsx` (home), `dashboard.tsx`, `billing.tsx`
- API calls to `http://localhost:4000` (dev) via `fetch()` or custom hooks
- Always check `ApiResponse<T>.success` before using `.data`
- Uses Vercel Analytics for production monitoring

**Shared Package Build**: Must run before API startup if types changed. Exports:
- `types.ts` - Domain interfaces (User, Shipment, ApiResponse, PaginatedResponse, etc.)
- `constants.ts` - HTTP_STATUS, SHIPMENT_STATUSES, USER_ROLES, pagination defaults
- `utils.ts` - Reusable functions (formatDate, formatCurrency, etc.)
- `env.ts` - Environment validation helpers

## 🛠️ Critical Workflows

### Pre-Task Checklist
1. Check if changes touch `packages/shared/` — if so, rebuild immediately: `pnpm --filter @infamous-freight/shared build`
2. Verify imports: API uses `require()` (CommonJS), Web/Mobile use `import` (ESM)
3. Database schema change? Create + apply migration: `cd api && pnpm prisma:migrate:dev --name your_change`
4. After any merge, run `pnpm install` to sync dependencies

### Common Development Commands
```bash
pnpm dev                                          # Start all services (API + Web)
pnpm api:dev                                      # API only
pnpm web:dev                                      # Web only
pnpm test                                         # Run all tests
pnpm lint && pnpm format                          # Code quality
pnpm --filter @infamous-freight/shared build    # Rebuild shared (critical!)
pnpm check:types                                  # TypeScript check (web + shared)
```

### Prisma Database Workflow
When modifying `api/prisma/schema.prisma`:
```bash
cd api
# 1. Edit schema.prisma
# 2. Create and apply migration
pnpm prisma:migrate:dev --name descriptive_change_name

# 3. Verify changes with GUI
pnpm prisma:studio

# 4. Regenerate Prisma client if needed
pnpm prisma:generate

# 5. Seed test data (optional)
pnpm prisma:seed
```

**Example**: Adding a field to Shipment
```prisma
// api/prisma/schema.prisma
model Shipment {
  id                String   @id @default(cuid())
  trackingNumber    String   @unique
  priority          String   @default("standard")  // NEW
  createdAt         DateTime @default(now())
  updatedAt         DateTime @updatedAt
}
```
Then: `pnpm prisma:migrate:dev --name add_priority_to_shipment`

## 📋 Code Conventions

### API (CommonJS + Express)
**Routes** (`api/src/routes/*.js`): Return wrapped `ApiResponse<T>` objects
- Middleware order matters: `limiters → authenticate → requireScope → auditLog → validate → handler`
- Always use `next(error)` to delegate to global errorHandler
- Scope-based auth: `requireScope("ai:command")` checks JWT claims

**Services** (`api/src/services/`): Business logic and external integrations
- Example: `aiSyntheticClient.js` handles OpenAI/Anthropic/synthetic fallback with retry logic
- Use `withRetry()` wrapper for flaky external API calls
- Convert upstream errors to HTTP errors: `toHttpError(err, "User message", httpStatus)`

**Error Handling Pattern**:
```javascript
// api/src/routes/example.js
const { ApiResponse, HTTP_STATUS } = require("@infamous-freight/shared");

router.post("/action", authenticate, requireScope("scope:name"), async (req, res, next) => {
  try {
    const result = await someService.doAction(req.body);
    res.status(HTTP_STATUS.OK).json(new ApiResponse({ success: true, data: result }));
  } catch (err) {
    // Let global errorHandler convert to proper status + response
    next(err);
  }
});
```

### Web (TypeScript + Next.js)
**Pages** (`web/pages/`): API route handlers and server-side rendering
**Components** (`web/components/`): Reusable React components with TypeScript

**API Call Pattern**:
```typescript
// web/pages/example.tsx
import { ApiResponse, Shipment } from "@infamous-freight/shared";

export async function getServerSideProps() {
  const response = await fetch(`http://localhost:4000/api/shipments/1`);
  const result: ApiResponse<Shipment> = await response.json();
  
  if (!result.success || !result.data) {
    return { notFound: true };
  }
  return { props: { shipment: result.data } };
}
```

**Component Pattern**:
```typescript
// web/components/ShipmentCard.tsx
import { Shipment, SHIPMENT_STATUSES } from "@infamous-freight/shared";

export function ShipmentCard({ shipment }: { shipment: Shipment }) {
  const isDelivered = shipment.status === SHIPMENT_STATUSES.DELIVERED;
  return <div className={isDelivered ? "done" : "pending"}>{shipment.trackingNumber}</div>;
}
```

### Shared Package (TypeScript)
**Location**: `packages/shared/src/`

**Exports**:
- **types.ts**: Domain interfaces (`User`, `Shipment`, `ApiResponse<T>`)
  - Always define API contracts here, not in route files
  - Types consumed by both API (for validation) and Web (for type safety)
  - Changes here require shared rebuild before dependent services run

- **constants.ts**: Enums and defaults (`HTTP_STATUS`, `SHIPMENT_STATUSES`, `USER_ROLES`)
  - Single source of truth for magic strings (avoid hardcoding "DELIVERED", "PENDING" in multiple files)
  - Update here, not scattered across codebase

- **utils.ts**: Pure functions (`formatDate()`, `formatCurrency()`)
  - Reusable business logic without side effects
  - Example: date formatting, currency conversion, address parsing

- **env.ts**: Environment validation helpers (Zod schemas)
  - Validates env vars at startup
  - Type-safe environment config

**Build Workflow**:
```bash
cd packages/shared
pnpm build        # Compiles TypeScript → dist/ (generated, NOT committed)
pnpm dev          # Watch mode for development
```

**Critical**: After any type/constant changes:
1. Rebuild shared: `pnpm --filter @infamous-freight/shared build`
2. Restart dependent services: `pnpm dev` or `pnpm api:dev`
3. If Web doesn't pick up changes, restart: `pnpm web:dev`

**Import Pattern**:
```javascript
// API (CommonJS) - Uses require()
const { User, SHIPMENT_STATUSES, HTTP_STATUS, ApiResponse } = require("@infamous-freight/shared");

// Web (ESM) - Uses import
import { User, SHIPMENT_STATUSES, HTTP_STATUS, ApiResponse } from "@infamous-freight/shared";

// Mobile (ESM) - Same as web
import { User, formatDate } from "@infamous-freight/shared";
```

**Key Principle**: Never redefine types in individual services. If you need a type, add it to shared first, rebuild, then import everywhere.

### ESLint Flat Config (ESM-based)

Project uses **ESLint v9+ flat config** (`eslint.config.js`) with ESM format:

```javascript
// Root and service-level eslint.config.js
import js from "@eslint/js";
import prettier from "eslint-config-prettier";

export default [
  {
    ignores: ["node_modules/**", "dist/**", ".next/**", "coverage/**"],
  },
  {
    files: ["**/*.{js,jsx,mjs,cjs}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
    },
    rules: {
      // Project-specific rules
    }
  },
  prettier, // Always last to override formatting rules
];
```

**Key Differences from Legacy Config**:
- No `.eslintrc.json` — uses `eslint.config.js` (ESM export)
- Flat array of config objects, not nested extends/overrides
- `ignores` at top level replaces `.eslintignore`
- `languageOptions` replaces `env` and `parserOptions`
- API uses CommonJS (`require()`) but ESLint config is still ESM

**Per-service configs**: Each workspace (api/, web/, packages/shared/) has its own `eslint.config.js` that can extend root config or customize rules.

### Input Validation Patterns
**Location**: `api/src/middleware/validation.js` exports reusable validators

```javascript
// Using express-validator with custom middleware
const { validateString, validateEmail, handleValidationErrors } = require("../middleware/validation");

router.post("/users", 
  [
    validateEmail(),              // Built-in email validator
    validateString("name", { min: 2, max: 100 }),  // Custom string validator
    body("phone").optional().isMobilePhone(),  // Optional phone validation
    handleValidationErrors         // Catches + converts to 400 with error array
  ],
  async (req, res, next) => {
    // If validation fails, handleValidationErrors delegates to global errorHandler
    const { email, name, phone } = req.body;
    // ... process validated data
  }
);
```

**Key Pattern**: Always place validators BEFORE handler, then use `handleValidationErrors` to catch issues. Validation errors automatically return 400 with structured error array.

### Commit Messages
Use **Conventional Commits**: `type(scope): description`
- `feat(api)`: New API endpoint or feature
- `fix(web)`: Bug fix in frontend
- `docs`: Documentation
- `refactor`: Code restructuring
- `test`: Test additions
- `chore`: Dependencies, tooling

Example: `feat(api): add shipment status webhook endpoint`

**Pre-commit Automation**: Husky hooks enforce formatting automatically
- `.husky/pre-commit` runs `lint-staged` before every commit
- `.lintstagedrc` applies Prettier to staged files matching `*.{js,jsx,ts,tsx,json,md}`
- No need to manually run `pnpm format` if using git commits normally

## 🔗 Integration Points & External Dependencies

### External APIs
- **OpenAI/Anthropic**: AI inference via `api/src/services/aiSyntheticClient.js`
  - Mode selected by `AI_PROVIDER` env var: "openai" | "anthropic" | "synthetic"
  - Uses `withRetry()` for resilience; synthetic fallback if both API keys missing
  - Route: `POST /api/ai/command` with auth + rate limiting (20/min)
  
- **Stripe/PayPal**: Payment processing via `api/src/routes/billing.js`
  - Routes handle subscription creation, webhook verification
  - Rate limited to 30 requests/15min
  
- **OpenAI Whisper**: Voice transcription in `api/src/routes/voice.js`
  - File upload via Multer (10MB default, configurable via `VOICE_MAX_FILE_SIZE_MB`)
  - Scope: `voice:ingest`, `voice:command`

### Database
- **Prisma ORM**: `api/prisma/schema.prisma` defines all models
- **PostgreSQL**: Connection via `DATABASE_URL` env var
- **Migrations**: Auto-generated in `api/prisma/migrations/` by `prisma:migrate:dev`

### Security & Monitoring
- **JWT**: Header-based auth via `authenticate()` middleware, claims in `req.user`
- **Scope-based RBAC**: `requireScope("scope:name")` validates JWT claims
- **Rate Limiting**: Per-endpoint via `express-rate-limit`
  - General: 100/15min | Auth: 5/15min | AI: 20/1min | Billing: 30/15min
- **Sentry**: Error tracking initialized in `api/src/server.js`, errors attached via `attachErrorHandler()`
- **CORS**: Whitelist in `CORS_ORIGINS` env var (default: `http://localhost:3000`)
- **Security Headers**: Helmet CSP, HSTS, X-Frame-Options via `securityHeaders.js`

### Common Feature Implementation Pattern

When adding a new feature (e.g., "Add shipment notes"):

1. **Update Shared Types** (`packages/shared/src/types.ts`)
   ```typescript
   export interface Shipment {
     id: string;
     notes?: string;  // NEW FIELD
     // ... other fields
   }
   ```

2. **Rebuild Shared**
   ```bash
   pnpm --filter @infamous-freight/shared build
   ```

3. **Update Database Schema** (`api/prisma/schema.prisma`)
   ```prisma
   model Shipment {
     notes    String?  // NEW FIELD
   }
   ```

4. **Create Migration**
   ```bash
   cd api && pnpm prisma:migrate:dev --name add_notes_to_shipment
   ```

5. **Add API Endpoint** (`api/src/routes/shipments.js`)
   ```javascript
   const { ApiResponse, HTTP_STATUS } = require("@infamous-freight/shared");
   
   router.patch("/:id/notes", async (req, res) => {
     const { notes } = req.body;
     const shipment = await prisma.shipment.update({
       where: { id: req.params.id },
       data: { notes }
     });
     res.json(new ApiResponse({ success: true, data: shipment }));
   });
   ```

6. **Add Web Component** (`web/components/ShipmentNotes.tsx`)
   ```typescript
   import { Shipment } from "@infamous-freight/shared";
   
   export function ShipmentNotes({ shipment }: { shipment: Shipment }) {
     return <div>{shipment.notes}</div>;
   }
   ```

7. **Test Everything**
   ```bash
   pnpm test
   pnpm lint:fix && pnpm format
   ```

## ⚙️ Troubleshooting & Edge Cases

### Module Resolution

**Module not found `@infamous-freight/shared`:**
```bash
pnpm --filter @infamous-freight/shared build
pnpm install
```
- Verify `packages/shared/dist/` exists
- Check both API and Web can resolve via `node -e "require('@infamous-freight/shared')"`

**Type errors after modifying shared package:**
- Rebuild: `pnpm --filter @infamous-freight/shared build`
- Restart: `pnpm dev`
- Clear TSC cache: `rm -rf packages/shared/dist && pnpm --filter shared build`

### Database Issues

**Prisma client out of sync:**
```bash
cd api && pnpm prisma:generate
```

**Migration conflicts** (e.g., after rebase):
```bash
cd api
# Option 1: Reset (development only)
pnpm prisma:migrate:dev --name reset_after_conflict

# Option 2: Verify current state
pnpm prisma:studio  # GUI shows actual DB state
```

**PostgreSQL connection refused:**
- Check `DATABASE_URL` env var format: `postgresql://user:pass@host:port/db`
- Verify PostgreSQL running: `psql -c "SELECT 1"`
- Docker: `docker compose up postgres` before API

### Authentication & CORS

**CORS rejected errors:**
```
Error: "CORS Rejected - Origin is not allowed"
```
- Check `CORS_ORIGINS` env var matches your frontend URL (case-sensitive, includes protocol)
- Example: `http://localhost:3000,https://app.example.com`
- Default: `http://localhost:3000` (dev only)

**Invalid token / 401 Unauthorized:**
- Verify JWT in Authorization header: `Authorization: Bearer <token>`
- Check `JWT_SECRET` matches between token generation and API verification
- Token expired? JWT defaults to 1 hour expiry (check `security.js` for payload structure)

**Missing scopes / 403 Forbidden:**
- Token has correct JWT `scopes` claim? Use test token generator from test files
- Endpoint requires `requireScope("scope:name")` — verify token includes this scope

### Port & Process Issues

**Port conflicts (4000 API, 3000 Web):**
```bash
# Kill existing processes
lsof -ti:4000 | xargs kill -9  # API
lsof -ti:3000 | xargs kill -9  # Web
lsof -ti:5432 | xargs kill -9  # PostgreSQL
```

Or override in `.env.local`:
```bash
API_PORT=4001
WEB_PORT=3001
```

**"Address already in use"** in Docker:
```bash
docker compose down    # Stop all containers
docker system prune    # Remove orphaned volumes
```

### Testing Failures

**Tests timeout or hang:**
- Check if database is running: `psql -c "SELECT 1"`
- Increase Jest timeout: `jest.setTimeout(10000)` in test file
- API tests need `JWT_SECRET` set: `process.env.JWT_SECRET = "test-secret"`

**Mocked service not being called:**
- Jest mock must be declared BEFORE importing module: `jest.mock("../service")` at top
- Clear mock between tests: `jest.clearAllMocks()` in `beforeEach`
- Verify service is actually being imported in the route handler

**Coverage thresholds failing:**
- API requires ≥50% coverage (see `api/jest.config.js`)
- Run locally: `pnpm --filter api test:coverage`
- Check HTML report: `api/coverage/index.html`
- Temporarily lower threshold in config for debugging

### Deployment Issues

**Fly.io deployment fails with "build error":**
```bash
flyctl logs -a infamous-freight-api
# Check for:
# - Missing PNPM_HOME or Node.js version incompatibility
# - Database migration failure (run locally first)
# - Missing .env secrets
```

**"Cannot find module @infamous-freight/shared" in production:**
- Shared package must be built BEFORE API container build
- Dockerfile order: Install → Build shared → Build API
- Verify in `api/Dockerfile`: `RUN pnpm --filter @infamous-freight/shared build` comes before `pnpm --filter infamous-freight-api build`

**Vercel web deployment hangs:**
- Ensure `web/next.config.mjs` exports valid config
- Check build logs: `vercel logs`
- API_BASE_URL must be set in Vercel dashboard env vars

## � Security & Authentication Patterns

### Scope-Based Access Control
All protected endpoints use JWT claims with scopes. Implement via middleware chain:

```javascript
// api/src/routes/example.js
router.post(
  "/protected-action",
  limiters.general,        // Rate limiting first
  authenticate,            // Verify JWT token
  requireScope("scope:name"),  // Check claims
  auditLog,               // Log action
  async (req, res, next) => {
    // req.user contains JWT claims (sub, roles, scopes)
  }
);
```

**Available Scopes**: `ai:command`, `voice:ingest`, `voice:command`, `billing:*`, defined in routes

### Error Handling via Global Middleware
Use `next(error)` pattern — never send errors directly:

```javascript
// ✅ CORRECT: Let global errorHandler format the response
try {
  const result = await operation();
  res.json(new ApiResponse({ success: true, data: result }));
} catch (err) {
  next(err);  // Global errorHandler converts to HTTP response
}

// ❌ WRONG: Don't format error responses manually
catch (err) {
  res.status(500).json({ error: err.message });
}
```

The global `errorHandler` middleware (`api/src/middleware/errorHandler.js`) handles:
- Converting custom `.status` properties to HTTP codes
- Attaching to Sentry for monitoring
- Returning standardized `ApiResponse` format

## � Testing & Quality Assurance

### Test Structure
**API Tests** (`api/__tests__/`): Jest + supertest for HTTP testing
- **routes.success.test.js** - Happy path scenarios
- **routes.validation.test.js** - Error handling, input validation, auth failures
- **routes.shipments.test.js** - CRUD operations
- **server.test.js** - Server initialization

**Web Tests** (`web/__tests__/`): Jest + jsdom for component testing

**E2E Tests** (`e2e/tests/`): Playwright for full user workflows

### API Testing Pattern
```javascript
// api/__tests__/routes.success.test.js
const request = require("supertest");
const jwt = require("jsonwebtoken");

const makeToken = (scopes) => 
  jwt.sign({ sub: "test-user", scopes }, process.env.JWT_SECRET);

const authHeader = (token) => `Bearer ${token}`;

test("ai command executes with valid payload", async () => {
  const token = makeToken(["ai:command"]);
  const res = await request(app)
    .post("/api/ai/command")
    .set("Authorization", authHeader(token))
    .send({ command: "optimize", payload: { id: "123" } });

  expect(res.status).toBe(200);
  expect(res.body.ok).toBe(true);
});

test("validation fails when command missing", async () => {
  const token = makeToken(["ai:command"]);
  const res = await request(app)
    .post("/api/ai/command")
    .set("Authorization", authHeader(token))
    .send({});  // Missing required 'command'

  expect(res.status).toBe(400);
  expect(res.body.error).toBe("Validation Error");
});
```

### Test Coverage Requirements
- **API**: Minimum 50% (branches, functions, lines, statements)
- **Web**: Currently 0% baseline (no hard requirements)
- Run: `pnpm test:coverage` → Generates HTML reports in `coverage/` directories
- CI/CD enforces coverage thresholds — coverage decreases will fail PRs (see `jest.config.js`)

### Running Tests
```bash
pnpm test                    # Run all tests (API + Web + E2E)
pnpm test:coverage           # With coverage reports
pnpm --filter api test       # API only
pnpm --filter web test       # Web only
pnpm e2e                     # Playwright E2E tests
```

### Mocking External Services
```javascript
// Mock AI service in tests
jest.mock("../src/services/aiSyntheticClient", () => ({
  sendCommand: jest.fn(),
}));

const { sendCommand } = require("../src/services/aiSyntheticClient");

beforeEach(() => {
  sendCommand.mockReset();
});

test("handles AI response", async () => {
  sendCommand.mockResolvedValueOnce({ provider: "synthetic", text: "result" });
  // ... test AI command route
});
```

**Important**: Tests run with `process.env.JWT_SECRET = "test-secret"` and many env vars deleted to avoid external API calls. Check test file setup before debugging failures.

## �🧠 AI Integration Patterns

### Using the AI Client Service
The `aiSyntheticClient.js` service abstracts OpenAI/Anthropic/synthetic modes:

```javascript
const { sendCommand } = require("../services/aiSyntheticClient");

// Automatically uses mode from AI_PROVIDER env var
const response = await sendCommand("shipment.optimize", {
  shipments: [...],
  constraints: { maxHours: 12 }
});
// Returns: { provider: "openai", text: "Suggested routing..." }
```

**AI Provider Logic**:
- `AI_PROVIDER=openai` → Uses OpenAI API (requires `OPENAI_API_KEY`)
- `AI_PROVIDER=anthropic` → Uses Anthropic Claude (requires `ANTHROPIC_API_KEY`)
- `AI_PROVIDER=synthetic` → Uses local simulation (fallback, no keys needed)

**Retry & Resilience**: 
- Automatic retry on transient errors (5xx, connection issues)
- `withRetry()` wrapper handles exponential backoff
- Circuit breaker for persistent failures
## 🚀 Deployment-Specific Patterns

### Environment Configuration by Platform

**Development** (`.env.local` or `docker-compose.override.yml`):
```bash
NODE_ENV=development
API_PORT=4000          # Internal Express port
WEB_PORT=3000
DATABASE_URL=postgresql://infamous:infamouspass@localhost:5432/infamous_freight
AI_PROVIDER=synthetic  # No API keys needed
JWT_SECRET=dev-secret
CORS_ORIGINS=http://localhost:3000
```

**Fly.io Deployment** (see `fly.toml`):
```toml
app = "infamous-freight-api"
primary_region = "iad"
PORT = 4000            # Fly.io uses 4000, maps to 80/443 public

[services.concurrency]
hard_limit = 50
soft_limit = 35
```

Deploy via:
```bash
flyctl launch              # Initialize
flyctl postgres create     # Database
flyctl secrets set KEY=value  # Environment secrets
flyctl deploy              # Deploy
```

**Vercel Deployment** (Web, see `web/vercel.json`):
```json
{
  "buildCommand": "next build",
  "outputDirectory": ".next"
}
```

Vercel automatically:
- Builds Next.js on push to main
- Sets environment vars from dashboard
- Maps to custom domain

**Docker** (see `docker-compose.yml`, `api/Dockerfile`, `web/Dockerfile`):
- Multi-stage builds for optimized images
- pnpm store caching via BuildKit
- Named volumes for pnpm cache persistence
- Environment overrides via `.env.local`

### Post-Deployment Validation
```bash
# Health check
curl https://your-api.fly.dev/api/health

# AI command test
curl -X POST https://your-api.fly.dev/api/ai/command \
  -H "Content-Type: application/json" \
  -d '{"command": "test", "payload": {}}'

# Verify web loads
curl https://your-web.vercel.app
```

### Environment Secret Management
**Never commit secrets**. Use platform-specific secret stores:
- **Fly.io**: `flyctl secrets set KEY=value`
- **Vercel**: Dashboard → Settings → Environment Variables
- **Local**: Use `.env.local` (ignored by git)

Key secrets to set in all environments:
```
JWT_SECRET           # Generate: openssl rand -base64 32
DATABASE_URL         # PostgreSQL connection string
OPENAI_API_KEY       # If using OpenAI (optional, synthetic fallback)
STRIPE_SECRET_KEY    # If enabling billing
PAYPAL_CLIENT_ID     # If enabling PayPal
CORS_ORIGINS         # Production domain(s)
```

### CI/CD Workflows

The project includes several GitHub Actions workflows (`.github/workflows/`):

- **ci.yml** - Main CI pipeline: security audit, lint, build, tests (unit + integration)
  - Runs on push/PR to `main` and `develop`
  - Uses pnpm caching for faster builds
  - Enforces code coverage thresholds (API ≥50%)
  - Matrix testing across Node versions if needed
  
- **e2e.yml** - Playwright end-to-end tests
  - Runs against deployed preview environments
  - Uses Playwright test runner with browsers
  
- **fly-deploy.yml** - Automated deployment to Fly.io for API
  - Triggered on push to `main` after CI passes
  - Runs database migrations before deployment
  
- **vercel-deploy.yml** - Web frontend deployment to Vercel
  - Automatic preview deployments for PRs
  - Production deployment on merge to `main`
  
- **docker-build.yml** - Container image builds and registry push
  - Multi-arch builds (amd64, arm64) if configured
  
- **container-security.yml** - Trivy vulnerability scanning
  - Scans built images for CVEs
  
- **codeql.yml** - GitHub CodeQL security analysis
  - Static analysis for JavaScript/TypeScript

**Key CI Pattern**: All workflows use consistent Node.js version (v20) and pnpm (v7.5.1) defined in env vars for easy updates.

### Docker Build Optimization

The Dockerfiles use advanced BuildKit features for optimal builds:

```dockerfile
# syntax=docker/dockerfile:1.4  ← Enable BuildKit features

# Leverage BuildKit cache mounts for pnpm
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile

# Multi-stage builds to minimize final image size
FROM base AS dependencies  # Install deps
FROM base AS builder-shared  # Build shared package
FROM base AS final  # Minimal runtime image
```

**Key Docker Patterns**:
- **Named volumes** in `docker-compose.yml`: `pnpm-store`, `node-modules-api`, `node-modules-web`, `nextjs-cache`
- **Build context**: API Dockerfile builds from project root, not `/api`, to access shared package
- **Production builds**: Multi-stage with `--prod=false` for dev deps, then copy only needed artifacts
- **Healthchecks**: Services have healthcheck directives for proper startup ordering
- **.dockerignore**: Excludes `node_modules`, `dist`, `.git` to speed up context copying

**Rebuilding after changes**: If shared package or dependencies change, rebuild containers:
```bash
docker-compose build --no-cache api  # Force rebuild API
docker-compose up -d                  # Restart with new image
```
## �📚 Project Structure Reference

```
├── api/                           # CommonJS Express backend
│   ├── src/routes/                # Route handlers (health, shipments, users, etc.)
│   ├── src/services/              # Business logic
│   ├── src/middleware/            # Security, logging, error handling
│   ├── prisma/schema.prisma       # Database models (User, Driver, Shipment, AiEvent)
│   └── __tests__/                 # Jest tests
├── web/                           # TypeScript Next.js frontend
│   ├── pages/                     # Routes & API handlers
│   ├── components/                # React components
│   └── __tests__/                 # Jest tests
├── packages/shared/               # Shared TypeScript package (MUST build before API runs)
│   ├── src/types.ts              # Domain interfaces (User, Shipment, ApiResponse)
│   ├── src/constants.ts          # HTTP_STATUS, SHIPMENT_STATUSES, USER_ROLES
│   ├── src/utils.ts              # Shared utilities
│   └── dist/                      # Compiled output (auto-generated)
├── e2e/                           # Playwright end-to-end tests
└── .github/workflows/             # CI/CD pipelines
```

## ✅ Before Committing

Pre-commit hooks (Husky + lint-staged) automatically run on `git commit`:
- Prettier formatting on staged files (`*.{js,jsx,ts,tsx,json,md}`)
- No manual formatting needed unless hooks disabled

**Manual verification checklist:**
1. **Shared package changes?** → Run `pnpm --filter @infamous-freight/shared build`
2. **Database schema changes?** → Run `pnpm prisma:migrate:dev` (creates migration)
3. **Code quality:** `pnpm lint:fix && pnpm format`
4. **Tests pass:** `pnpm test`
5. **Types check:** `pnpm check:types` (for TypeScript files)

**Bypass hooks (not recommended):** `git commit --no-verify`

## 📖 Additional Resources

- [README.md](../README.md) - Project overview & architecture
- [QUICK_REFERENCE.md](../QUICK_REFERENCE.md) - Command cheat sheet
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development guidelines
- [DOCUMENTATION_INDEX.md](../DOCUMENTATION_INDEX.md) - All documentation
