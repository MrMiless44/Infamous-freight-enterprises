# @infamous-freight/ai-service

A minimal AI microservice (Express + Zod) that proxies AI commands to a configured AI engine.

## Endpoints
- `GET /health` → `{ ok: true }`
- `GET /metrics` → Prometheus exposition using shared metrics registry
- `POST /command` → `{ command, payload?, context{ userId, mode } }`

## Environment
- `PORT` (default: 4001)
- `AI_SYNTHETIC_ENGINE_URL` or `AI_ENGINE_URL` (required)
- `AI_SYNTHETIC_API_KEY` (optional)
- `AI_ENGINE_COMMAND_PATH` (default: `/command`)

## Dev
```bash
pnpm --filter @infamous-freight/shared build
pnpm --filter @infamous-freight/ai-service dev
```

## Build & Run
```bash
pnpm --filter @infamous-freight/ai-service build
pnpm --filter @infamous-freight/ai-service start
```
