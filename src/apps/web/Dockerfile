# Production-optimized Dockerfile for Next.js Web App
# Multi-stage build with security hardening and Next.js standalone mode

FROM node:20-alpine AS base

# Install security updates and required tools
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
        libc6-compat \
        dumb-init \
        wget \
        ca-certificates && \
    rm -rf /var/cache/apk/*

# Enable pnpm with specific version
RUN corepack enable && corepack prepare pnpm@8.15.9 --activate
ENV PNPM_HOME=/usr/local/bin
ENV PATH="$PNPM_HOME:$PATH"

# Stage 1: Install dependencies for all workspaces
FROM base AS deps
WORKDIR /app

# Copy workspace configuration
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY src/apps/web/package.json ./src/apps/web/
COPY src/packages/shared/package.json ./src/packages/shared/

# Install dependencies with cache mount
ENV HUSKY=0
RUN --mount=type=cache,id=pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --filter=infamous-freight-web --filter=@infamous-freight/shared

# Stage 2: Build shared package
FROM base AS shared-builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/src/packages ./src/packages
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY src/packages/shared ./src/packages/shared

WORKDIR /app/src/packages/shared
RUN pnpm run build

# Stage 3: Build Next.js application
FROM base AS builder
WORKDIR /app

# Next.js environment variables
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Build-time environment variables (these should be provided at build time)
ARG DATABASE_URL
ARG NEXT_PUBLIC_API_URL
ENV DATABASE_URL=${DATABASE_URL}
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

# Copy workspace configuration
COPY pnpm-workspace.yaml package.json ./

# Copy built shared package
COPY --from=shared-builder /app/src/packages/shared/dist ./src/packages/shared/dist
COPY --from=shared-builder /app/src/packages/shared/package.json ./src/packages/shared/

# Copy dependencies and web source
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/src/apps/web/node_modules ./src/apps/web/node_modules
COPY src/apps/web ./src/apps/web

# Build Next.js app
WORKDIR /app/src/apps/web
RUN pnpm build

# Stage 4: Production runtime
FROM node:20-alpine AS runner
WORKDIR /app

# Install security updates and required tools
RUN apk update && \
    apk upgrade && \
    apk add --no-cache \
        dumb-init \
        wget \
        ca-certificates \
        tini && \
    rm -rf /var/cache/apk/*

# Next.js environment
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Create non-root user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs && \
    mkdir -p /app/.next/cache && \
    chown -R nextjs:nodejs /app

# Copy workspace configuration
COPY --chown=nextjs:nodejs pnpm-workspace.yaml package.json ./

# Copy built shared package
COPY --from=shared-builder --chown=nextjs:nodejs /app/src/packages/shared/dist ./src/packages/shared/dist
COPY --from=shared-builder --chown=nextjs:nodejs /app/src/packages/shared/package.json ./src/packages/shared/

# Copy Next.js build artifacts (standalone mode)
COPY --from=builder --chown=nextjs:nodejs /app/src/apps/web/public ./src/apps/web/public
COPY --from=builder --chown=nextjs:nodejs /app/src/apps/web/.next/standalone ./src/apps/web/
COPY --from=builder --chown=nextjs:nodejs /app/src/apps/web/.next/static ./src/apps/web/.next/static
COPY --from=builder --chown=nextjs:nodejs /app/src/apps/web/package.json ./src/apps/web/

# Switch to non-root user
USER nextjs

WORKDIR /app/src/apps/web

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:3000/api/health || exit 1

# Use dumb-init for proper signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.js"]
