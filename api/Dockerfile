FROM node:20-alpine AS builder

WORKDIR /app

# Install only the API workspace dependencies
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY api/package.json ./api/package.json
RUN corepack enable && pnpm install --filter api... --frozen-lockfile

# Generate the Prisma client for the API
COPY api/prisma ./api/prisma
RUN pnpm --filter api... prisma generate

# Copy the remaining API source and build
COPY api/tsconfig.json ./api/tsconfig.json
COPY api/scripts ./api/scripts
COPY api/src ./api/src
RUN pnpm --filter api... build

FROM node:20-alpine AS runner
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/api/dist ./api/dist
COPY --from=builder /app/api/prisma ./api/prisma
COPY api/package.json ./api/package.json

WORKDIR /app/api
ENV NODE_ENV=production
CMD ["node", "dist/server.js"]
