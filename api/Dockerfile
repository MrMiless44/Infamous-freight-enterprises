# syntax=docker/dockerfile:1.4
FROM node:22-alpine AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# Install dependencies for all workspaces
FROM base AS dependencies
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY api/package.json ./api/
COPY packages/shared/package.json ./packages/shared/
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile --prod=false

# Build shared package
FROM base AS builder-shared
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=dependencies /app/packages ./packages
COPY packages/shared ./packages/shared
RUN pnpm --filter=@infamous-freight/shared build

# Production stage
FROM base AS final
WORKDIR /app
ENV NODE_ENV=production

# Copy root package.json and workspace config
COPY pnpm-workspace.yaml package.json ./

# Copy shared package build
COPY --from=builder-shared /app/packages/shared/dist ./packages/shared/dist
COPY --from=builder-shared /app/packages/shared/package.json ./packages/shared/

# Copy dependencies and API source
COPY --from=dependencies /app/node_modules ./node_modules
COPY api ./api

WORKDIR /app/api
EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:3001/health || exit 1

CMD ["node", "src/server.js"]
