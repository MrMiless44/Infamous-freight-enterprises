# AI v2 + Monitoring Integration Plan

Repository: MrMiless44/Infamous-freight-enterprises (branch: feat/my-feature)

This plan maps the contents of the `infamous-freight-ai-v2` bundle into the current monorepo and outlines step-by-step integration with minimal disruption.

## Source Layout (provided)

```
infamous-freight-ai-v2/
├── services/
│   ├── api-gateway/
│   ├── ai-service/
│   ├── auth-service/
│   ├── shipment-service/
│   └── worker-service/
├── libs/
│   ├── common/
│   ├── prisma/
│   ├── logger/
│   └── types/
├── infra/
│   ├── docker/
│   ├── k8s/
│   ├── terraform/
│   └── monitoring/
│       ├── prometheus.yml
│       ├── docker-compose.monitoring.yml
│       ├── loki-config.yml
│       ├── promtail-config.yml
│       └── grafana-dashboards/
├── .github/workflows/ci.yml
├── docker-compose.yml
├── package.json
├── tsconfig.json
├── .env.example
└── README.md
```

## Target Mapping (monorepo)

- services/api-gateway → consolidate with API gateway logic in [api/src](../api/src) and/or edge routing in [web](../web)
- services/ai-service → merge into [api/src/ai](../api/src/ai) and versioned handlers in [api/src/api/ai.commands.js](../api/src/api/ai.commands.js)
- services/auth-service → optional; current repo uses JWT middleware in [api/src/middleware](../api/src/middleware). Only integrate if token issuance endpoints are required.
- services/shipment-service → reconcile with [api/src/api/shipments.js](../api/src/api/shipments.js)
- services/worker-service → stage under [api/src/worker](../api/src) or [scripts](../scripts) (design TBD)
- libs/types → extend [packages/shared/src/types.ts](../packages/shared/src/types.ts)
- libs/common → migrate utilities into [packages/shared/src/utils.ts](../packages/shared/src/utils.ts) or new modules under `packages/shared/src/`
- libs/logger → unify with [api/src/middleware/logger.js](../api/src/middleware/logger.js); consider promoting a shared logger module
- libs/prisma → compare with existing Prisma schema/migrations in [api/prisma](../api/prisma); plan a safe merge path
- infra/docker → reconcile with root compose files (docker-compose*.yml)
- infra/k8s, infra/terraform → add under [deploy/](../deploy) or [docs/deployment](../docs/deployment) with clear usage notes
- infra/monitoring → add under [monitoring/](../docs) or a new top-level `monitoring/` folder; wire optional compose override

## Integration Phases

1. Staging
   - Place archives into `uploads/` then extract to `.staging/ai_v2` and `.staging/monitoring`.
   - Do not overwrite existing files yet.

2. Diff & Inventory
   - Generate a file+symbol diff to find:
     - Overlapping routes (AI, shipments, auth).
     - Prisma schema differences and migrations.
     - Shared library overlaps (types, logger, utilities).

3. AI v2 Merge
   - Merge `ai-service` request handlers into existing versioned flow:
     - Validate with Zod schemas in [api/src/middleware](../api/src/middleware).
     - Route through version detection in [api/src/middleware/versionDetection.js](../api/src/middleware/versionDetection.js).
     - Keep v1 backward compatibility.

4. Shipments
   - Align `shipment-service` endpoints with [api/src/api/shipments.js](../api/src/api/shipments.js): reuse JWT scopes and validation.

5. Auth
   - If `auth-service` implements token issuance, add `POST /auth/login` behind a feature flag; otherwise keep current JWT-only validation.

6. Workers
   - Stage `worker-service` into `api/src/worker` or `scripts/` with clear start scripts and env configuration.

7. Libraries
   - Migrate shared types/utilities/logger into [packages/shared](../packages/shared) with minimal breaking changes.
   - Document refactors in CHANGELOG.

8. Monitoring Stack
   - Add a separate monitoring compose (Prometheus, Loki, Promtail, Grafana) as an optional stack.
   - Expose API metrics endpoint (e.g., `/metrics`) and logs to Promtail (follow-up PR).

9. CI/CD
   - Extend existing GitHub Actions to build any new packages/images and, if needed, publish monitoring images.

## Commands (after archives are uploaded)

```bash
mkdir -p .staging/ai_v2 .staging/monitoring uploads
unzip -q uploads/infamous_freight_ai_v2.zip -d .staging/ai_v2
unzip -q uploads/infamous_freight_ai_v2_monitoring_stack.zip -d .staging/monitoring

# quick inventory
find .staging/ai_v2 -maxdepth 2 -type d | sort
find .staging/monitoring -maxdepth 2 -type f | sort
```

## Notes & Risks
- Prisma schema divergence requires careful migration planning to avoid data loss.
- Avoid duplicating routing/auth—prefer consolidating to current middleware and versioning approach.
- Monitoring stack should be optional and disabled by default in developer environments.

## Deliverables
- Merged AI v2 handlers with tests and docs
- Optional monitoring compose and setup guide
- Updated shared libraries with types/utilities/logger
- CI adjusted to new components if introduced
