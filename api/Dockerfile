FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install

COPY prisma ./prisma
RUN pnpm prisma generate

COPY . .
RUN pnpm build

FROM node:20-alpine AS runner
WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma
COPY package.json ./

ENV NODE_ENV=production
CMD ["node", "dist/server.js"]
