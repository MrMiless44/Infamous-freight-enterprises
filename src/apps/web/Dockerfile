# syntax=docker/dockerfile:1.4
FROM node:22-alpine AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && apk add --no-cache libc6-compat

# Install dependencies for all workspaces
FROM base AS dependencies
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY src/apps/web/package.json ./src/apps/web/
COPY src/packages/shared/package.json ./src/packages/shared/
RUN --mount=type=cache,id=pnpm,target=/pnpm/store HUSKY=0 pnpm install --frozen-lockfile --filter=infamous-freight-web --filter=@infamous-freight/shared

# Build shared package
FROM base AS builder-shared
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=dependencies /app/src/packages ./src/packages
COPY src/packages/shared ./src/packages/shared
RUN pnpm --filter=@infamous-freight/shared build

# Build Next.js application
FROM base AS builder
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Inject database URL during build to satisfy env validation in shared package
ARG DATABASE_URL
ENV DATABASE_URL=${DATABASE_URL}

# Copy workspace configuration
COPY pnpm-workspace.yaml package.json ./

# Copy shared package
COPY --from=builder-shared /app/src/packages/shared/dist ./src/packages/shared/dist
COPY --from=builder-shared /app/src/packages/shared/package.json ./src/packages/shared/

# Copy dependencies and web source
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=dependencies /app/src/apps/web/node_modules ./src/apps/web/node_modules
COPY src/apps/web ./src/apps/web

WORKDIR /app/src/apps/web
RUN pnpm build

# Production stage
FROM base AS final
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Create non-root user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy workspace configuration
COPY pnpm-workspace.yaml package.json ./

# Copy shared package
COPY --from=builder-shared /app/src/packages/shared/dist ./src/packages/shared/dist
COPY --from=builder-shared /app/src/packages/shared/package.json ./src/packages/shared/

# Copy Next.js build artifacts
COPY --from=builder --chown=nextjs:nodejs /app/src/apps/web/public ./src/apps/web/public
COPY --from=builder --chown=nextjs:nodejs /app/src/apps/web/.next/standalone ./src/apps/web/
COPY --from=builder --chown=nextjs:nodejs /app/src/apps/web/.next/static ./src/apps/web/.next/static
COPY --from=builder /app/src/apps/web/package.json ./src/apps/web/

USER nextjs
WORKDIR /app/src/apps/web
EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:3000/api/health || exit 1

CMD ["node", "server.js"]
