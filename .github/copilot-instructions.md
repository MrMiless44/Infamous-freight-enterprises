# Copilot Instructions (Infamous Freight)

Monorepo (pnpm 8.15.9, Node 20.18.1+)

- api/ (Express, CommonJS) – 4000 standalone, 3001 in Docker
- web/ (Next.js 14, TypeScript/ESM) – 3000
- mobile/ (Expo RN)
- packages/shared/ – types, constants, utils as @infamous-freight/shared
- e2e/ – Playwright

Golden Rule (shared)

- Import domain types/constants/utils only from @infamous-freight/shared. Never redefine.
- After editing packages/shared/src/\*, run: pnpm --filter @infamous-freight/shared build, then restart services.

API Request Flow (order is critical)

1. Rate limiter: limiters.general|auth|ai|billing (see api/src/middleware/security.js)
2. Auth: authenticate → sets req.user from JWT
3. Authorization: requireScope("scope:name") (e.g., ai:command, voice:ingest)
4. Audit: auditLog
5. Validation: from api/src/middleware/validation.js
6. handleValidationErrors
7. Handler: always next(err) to api/src/middleware/errorHandler.js

Responses & Errors

- Use ApiResponse and HTTP_STATUS from shared for success payloads.
- Set err.status (400/401/403/404/503) and call next(err); global handler formats JSON (see api/src/middleware/errorHandler.js).

Prisma Patterns

- Schema: api/prisma/schema.prisma → migrate via: cd api && pnpm prisma:migrate:dev --name <desc> → pnpm prisma:generate.
- Avoid N+1: always use include() for relations (e.g., prisma.shipment.findMany({ include: { driver: true } })).

Rate Limits (api/src/middleware/security.js)

- general: 100/15m • auth: 5/15m • ai: 20/min • billing: 30/15m

Security & Headers

- JWT required in production (JWT_SECRET). CORS via CORS_ORIGINS. Helmet/CSP via api/src/middleware/securityHeaders.js. Audit log on by default.

AI/Payments/Voice Integrations

- AI provider via AI_PROVIDER=openai|anthropic|synthetic (default synthetic); client in api/src/services/aiSyntheticClient.js.
- Stripe/PayPal keys optional; billing routes use limiters.billing (api/src/routes/billing.js).
- Voice upload via Multer; VOICE_MAX_FILE_SIZE_MB; scopes: voice:ingest, voice:command (api/src/routes/voice.js).

Dev Workflow

- Install/build: pnpm install; pnpm --filter @infamous-freight/shared build
- Run all: pnpm dev (starts api, web, mobile, e2e)
- Individually: pnpm api:dev • pnpm web:dev • pnpm e2e
- Types/quality: pnpm check:types • pnpm lint && pnpm format • pnpm test • pnpm test:coverage

Testing Assumptions

- API tests assume JWT_SECRET=test-secret and mock Stripe/PayPal/OpenAI. Coverage HTML: api/coverage/.

Key References

- Routes: api/src/routes/ (e.g., ai.commands.js)
- Middleware: api/src/middleware/{security.js,validation.js,errorHandler.js,logger.js,securityHeaders.js}
- Sentry init: api/src/instrument.js
- Shared: packages/shared/src/{types.ts,constants.ts,utils.ts,env.ts}

Ports & Gotchas

- API 4000 (standalone) / 3001 (Docker); Web 3000.
- Rebuild shared after edits; use .include() with Prisma; always next(err) with status.

Scopes & Auth

- Dev auth: if JWT_SECRET is unset, `authenticate` allows requests (useful locally). Set JWT_SECRET to enforce auth.
- Scopes in use: ai:command • voice:ingest|voice:command • billing:write • users:read|users:write • shipments:read|shipments:write.

Env & Web Proxy

- Web proxy reads NEXT_PUBLIC_API_URL or API_BASE_URL (see web/pages/api/proxy/[...path].ts). Prefer NEXT_PUBLIC_API_URL.

Schema vs Shared

- Shared types now align with Prisma: User.role = admin|dispatcher|user; Shipment.reference (not trackingNumber); status = created|in_transit|delivered|cancelled.
- Old docs mention generateTrackingNumber and trackingNumber; use reference = `TRK-${Date.now()}` instead.
- After type/constant updates to shared, rebuild: `pnpm --filter @infamous-freight/shared build && pnpm install && restart services`.

Seed & JWT

- Seed fixtures: api/prisma/seed.js creates baseline users, drivers, shipments.
- Quick token (scoped):

```bash
node -e "const jwt=require('jsonwebtoken');console.log(jwt.sign({sub:'local',scopes:['users:read','shipments:write']}, process.env.JWT_SECRET||'test-secret',{expiresIn:'1h'}))"
```

## Route & SSR Snippets

- Express route (middleware order + shared responses):

```js
// api/src/routes/shipments.js
const express = require("express");
const router = express.Router();
const { authenticate } = require("../middleware/auth");
const { requireScope } = require("../middleware/authz");
const { auditLog } = require("../middleware/logger");
const { validate, shipmentQuerySchema } = require("../middleware/validation");
const { handleValidationErrors } = require("../middleware/validation");
const { HTTP_STATUS, ApiResponse } = require("@infamous-freight/shared");

router.get(
  "/",
  // 1) Rate limiter applied globally in security.js
  authenticate,
  requireScope("shipments:read"),
  auditLog,
  validate(shipmentQuerySchema),
  handleValidationErrors,
  async (req, res, next) => {
    try {
      const { prisma } = req; // set earlier in app context
      const shipments = await prisma.shipment.findMany({
        include: { driver: true },
      });
      res.status(HTTP_STATUS.OK).json(new ApiResponse(shipments));
    } catch (err) {
      err.status = HTTP_STATUS.SERVICE_UNAVAILABLE;
      next(err);
    }
  },
);

module.exports = router;
```

- Next.js (App Router server component fetch via `NEXT_PUBLIC_API_URL`):

```tsx
// web/app/shipments/page.tsx
export default async function ShipmentsPage() {
  const base = process.env.NEXT_PUBLIC_API_URL;
  const res = await fetch(`${base}/shipments`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load shipments");
  const data = await res.json();
  return (
    <main>
      <h1>Shipments</h1>
      <pre>{JSON.stringify(data?.data ?? [], null, 2)}</pre>
    </main>
  );
}
```

- Next.js (Pages `getServerSideProps` via proxy fallback):

```tsx
// web/pages/shipments.tsx
export async function getServerSideProps() {
  const base = process.env.NEXT_PUBLIC_API_URL || process.env.API_BASE_URL;
  const res = await fetch(`${base}/shipments`);
  const json = await res.json();
  return { props: { shipments: json?.data ?? [] } };
}

export default function Shipments({ shipments }) {
  return (
    <main>
      <h1>Shipments</h1>
      <pre>{JSON.stringify(shipments, null, 2)}</pre>
    </main>
  );
}
```

- Notes:
  - Prefer `NEXT_PUBLIC_API_URL` for direct calls; proxy route exists at `web/pages/api/proxy/[...path].ts` for environments requiring relative API access.
  - Always import types/constants from `@infamous-freight/shared`; do not redefine domain entities.
