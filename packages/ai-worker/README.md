# AI Worker (@infamous-freight/ai-worker)

BullMQ worker that processes AI command jobs from Redis and forwards them to the configured AI engine using the shared client.

## Usage

```bash
# From monorepo root
pnpm --filter @infamous-freight/ai-worker dev
# or build + start
pnpm --filter @infamous-freight/ai-worker build && pnpm --filter @infamous-freight/ai-worker start
```

## Environment

- `REDIS_URL` (or `REDIS_CONNECTION_STRING`): Redis connection string. Default: `redis://localhost:6379`
- `AI_QUEUE_NAME`: Queue name to process. Default: `ai-commands`
- `AI_ENGINE_URL` (or `AI_SYNTHETIC_ENGINE_URL`): Target AI engine base URL
- `AI_ENGINE_API_KEY`: Optional API key for the AI engine
- `ENQUEUE_SAMPLE`: If `true`, enqueues a sample job at startup

## Enqueue Sample Job

```bash
ENQUEUE_SAMPLE=true pnpm --filter @infamous-freight/ai-worker dev
```

This enqueues `{ command: "echo", payload: { text: "Hello from worker" } }`.

## Notes

- Implements graceful shutdown on `SIGINT`/`SIGTERM`.
- Uses shared `sendAICommand` from `@infamous-freight/shared/aiClient`.
