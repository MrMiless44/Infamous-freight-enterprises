# Copilot Instructions for Infæmous Freight Enterprises

## Project Overview

This is **Infæmous Freight AI**, a next-generation AI-powered logistics platform featuring three core AI systems:
- **GĘŊÏŮ§ Core** - Logistics AI Navigator for route optimization
- **AURUM Dispatch** - Dispatcher Co-pilot for lane monitoring and bidding
- **NOIR Guardian** - Risk and Compliance AI for fraud detection

## Architecture

### Stack
- **Backend API**: Node.js 20 + Express 4.19
- **Frontend Web**: Next.js 14 + React 18 + TypeScript 5.4
- **Database**: PostgreSQL 15 with Prisma ORM 5.11
- **AI Providers**: OpenAI (GPT-4o-mini), Anthropic (Claude-3-Haiku), Synthetic fallback
- **Payments**: Stripe 12.0, PayPal SDK 1.0.3
- **Auth**: JWT with bcryptjs
- **DevOps**: Docker + Docker Compose, Nginx reverse proxy

### Directory Structure
```
/api/                  # Backend Express API
  /src/
    /routes/          # API route handlers
    /services/        # Business logic and external services
    server.js         # Express app entry point
  /prisma/            # Database schema and migrations
  /scripts/           # Utility scripts (validation, migrations)
  
/web/                 # Frontend Next.js app
  /pages/             # Next.js pages and API routes
  /components/        # React components
  /hooks/             # Custom React hooks
  /styles/            # Global styles
  
/nginx/               # Nginx reverse proxy config
/deploy/              # Deployment configs (Fly.io, Vercel, Render)
/.github/workflows/   # CI/CD pipelines
```

## Coding Standards

### General Principles
- **Minimal changes**: Make the smallest possible changes to achieve the goal
- **Consistency**: Match existing code style and patterns in the file you're editing
- **No breaking changes**: Preserve existing functionality unless explicitly required
- **Comments**: Add comments only when necessary to explain complex logic; match existing comment style

### Backend (Node.js/Express)
- Use **CommonJS** (`require`/`module.exports`), not ES modules
- Use `async/await` for asynchronous code
- Always handle errors with proper try-catch blocks
- Return meaningful HTTP status codes (200, 201, 400, 401, 404, 500)
- Log errors to console with descriptive context
- Use environment variables for configuration (access via `process.env`)
- File naming: `kebab-case.js` (e.g., `ai.commands.js`, `aiSim.internal.js`)

Example route structure:
```javascript
const express = require('express');
const router = express.Router();

router.post('/endpoint', async (req, res) => {
  try {
    // Implementation
    res.status(200).json({ success: true, data: result });
  } catch (error) {
    console.error('Error in endpoint:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
```

### Frontend (Next.js/TypeScript)
- Use **TypeScript** with proper type annotations
- Use **ES modules** (`import`/`export`)
- Functional components with React hooks
- Use inline styles (not CSS modules) to match existing patterns
- Component naming: **PascalCase** (e.g., `AvatarGrid.tsx`, `VoicePanel.tsx`)
- File extensions: `.tsx` for components, `.ts` for utilities
- Use `next/link` for navigation
- Fetch API data using the `useApi` hook from `/hooks/useApi.ts`

Example component structure:
```typescript
import React from "react";

interface Props {
  title: string;
  description?: string;
}

export function ComponentName({ title, description }: Props) {
  return (
    <div style={{ padding: "1rem" }}>
      <h2>{title}</h2>
      {description && <p>{description}</p>}
    </div>
  );
}
```

### Database (Prisma)
- Use Prisma Client for all database operations
- Always use `async/await` with Prisma queries
- Use transactions for multi-step operations
- Model naming: **PascalCase** (e.g., `User`, `Driver`, `Shipment`)
- Field naming: **camelCase** (e.g., `createdAt`, `avatarCode`)
- Always include `id`, `createdAt`, and `updatedAt` fields where appropriate

### Environment Variables
- Never commit secrets or API keys
- Use `.env.example` as template
- Validate required env vars with `api/scripts/env.validation.js`
- Access env vars: `process.env.VARIABLE_NAME`
- Next.js public vars: Prefix with `NEXT_PUBLIC_`

## Development Workflow

### Before Making Changes
1. Understand the existing code structure and patterns
2. Check if linting/testing infrastructure exists
3. Run existing tests to establish baseline
4. Make minimal, focused changes

### Local Development
```bash
# Start all services
docker compose up --build

# API development (without Docker)
cd api
npm install
npm run dev

# Web development (without Docker)
cd web
npm install
npm run dev
```

### Testing
```bash
# Lint frontend code
cd web && npm run lint

# Validate API environment
cd api && npm run validate:env

# Health check
cd api && npm run smoke:health
```

### Database Migrations
```bash
# Generate Prisma client
cd api && npm run prisma:generate

# Development migrations
cd api && npx prisma migrate dev

# Production migrations
cd api && npm run prisma:migrate

# View database
cd api && npm run prisma:studio
```

## API Endpoints

### Core Endpoints
- `GET /api/health` - Health check
- `GET /health` - Root health check (no /api prefix)
- `POST /api/ai/command` - Execute AI commands
- `POST /api/voice/ingest` - Voice audio upload
- `POST /api/voice/command` - Text command processing
- `POST /api/billing/stripe/session` - Stripe checkout
- `POST /api/billing/paypal/order` - PayPal order creation
- `POST /internal/ai-sim/event` - Internal AI simulation events

### API Conventions
- All endpoints under `/api` prefix (except root `/health`)
- Use proper HTTP methods (GET, POST, PUT, DELETE)
- Request body: JSON format
- Response format: `{ success: boolean, data?: any, error?: string }`
- Include timestamps in responses when relevant

## AI Integration

### AI Providers
- Default: Synthetic AI (for testing, no external API needed)
- Production: OpenAI or Anthropic (requires API keys)
- Switch provider: Set `AI_PROVIDER` env var to `synthetic`, `openai`, or `anthropic`

### AI Service Patterns
- Use `/api/src/services/aiSyntheticClient.js` as reference for AI client services
- Always handle AI provider errors gracefully
- Provide fallback responses when AI services are unavailable
- Log AI interactions for debugging

## Deployment

### Platforms
- **API**: Fly.io (recommended), Render (alternative)
- **Web**: Vercel (recommended), Render (alternative)
- **Database**: Fly.io Postgres, external managed PostgreSQL

### CI/CD Workflows
- `docker-build.yml` - Build and test on push
- `fly-deploy.yml` - Deploy API to Fly.io on main branch
- `vercel-deploy.yml` - Deploy Web to Vercel on main branch

### Pre-deployment Checklist
1. All environment variables configured in deployment platform
2. Database migrations applied
3. Health check endpoint responding
4. Secrets rotated for production

## Security Considerations

- JWT secret must be strong and unique in production
- Use Helmet.js for security headers (already configured)
- Enable CORS only for trusted origins in production
- Rate limiting available via `rate-limiter-flexible`
- Validate all user input with Zod schemas
- Sanitize database queries via Prisma (SQL injection protection)
- Never log sensitive data (passwords, API keys, tokens)

## Common Tasks

### Adding a New API Route
1. Create route file in `/api/src/routes/`
2. Follow existing route patterns
3. Register route in `/api/src/server.js`
4. Add environment variables to `.env.example` if needed
5. Test with curl or Postman

### Adding a New Frontend Page
1. Create page file in `/web/pages/`
2. Use TypeScript and inline styles
3. Follow existing page structure
4. Use `useApi` hook for data fetching
5. Add navigation link if needed

### Adding a New Database Model
1. Update `/api/prisma/schema.prisma`
2. Run `npx prisma migrate dev --name descriptive-name`
3. Generate Prisma client: `npm run prisma:generate`
4. Use model in API routes via `@prisma/client`

### Updating Dependencies
1. Check for security vulnerabilities: `npm audit`
2. Update specific package: `npm update package-name`
3. Test thoroughly after updates
4. Update both `/api` and `/web` as needed

## Troubleshooting

### Common Issues
- **Database connection fails**: Check `DATABASE_URL` env var, ensure PostgreSQL is running
- **API returns 500**: Check server logs, verify env vars are set
- **Frontend can't reach API**: Verify `NEXT_PUBLIC_API_BASE` points to correct API URL
- **Build fails**: Clear `node_modules` and reinstall dependencies
- **Prisma errors**: Regenerate client with `npx prisma generate`

### Debugging
- Check Docker logs: `docker compose logs -f [service]`
- API logs: Located in console output (Morgan logging)
- Database inspection: `npm run prisma:studio` (in `/api`)

## Additional Notes

- The platform uses special Unicode characters in branding (GĘŊÏŮ§, Infæmous) - preserve these when editing
- API port priority: `API_PORT` env var, then `PORT`, then default 4000
- Web port: Default 3000 (Next.js standard)
- Nginx reverse proxy routes traffic: `/` → web:3000, `/api` → api:4000
- All services run in single container on Render, separate containers on Fly.io/Vercel

## When in Doubt

1. Check existing code for patterns and conventions
2. Refer to `PROJECT_SUMMARY.md` for architecture overview
3. Refer to `DEPLOYMENT_GUIDE.md` for deployment details
4. Consult official documentation:
   - Express: https://expressjs.com
   - Next.js: https://nextjs.org/docs
   - Prisma: https://www.prisma.io/docs
   - TypeScript: https://www.typescriptlang.org/docs
5. Ask clarifying questions before making significant architectural changes
