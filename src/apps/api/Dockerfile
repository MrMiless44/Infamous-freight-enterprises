FROM node:20-alpine AS builder

WORKDIR /app
ENV HUSKY=0

# Install only the API workspace dependencies
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY src/apps/api/package.json ./src/apps/api/package.json
RUN corepack enable && pnpm install --filter infamous-freight-api... --frozen-lockfile

# Copy Prisma schema for the API (client is generated during build via prebuild hook)
COPY src/apps/api/prisma ./src/apps/api/prisma

# Copy the remaining API source and build
COPY src/apps/api/tsconfig.json ./src/apps/api/tsconfig.json
COPY src/apps/api/scripts ./src/apps/api/scripts
COPY src/apps/api/src ./src/apps/api/src
RUN pnpm --filter infamous-freight-api... build

FROM node:20-alpine AS runner
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/src/apps/api/dist ./src/apps/api/dist
COPY --from=builder /app/src/apps/api/prisma ./src/apps/api/prisma
COPY src/apps/api/package.json ./src/apps/api/package.json

WORKDIR /app/src/apps/api
ENV NODE_ENV=production
CMD ["node", "dist/server.js"]
