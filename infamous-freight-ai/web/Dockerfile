FROM node:20-alpine AS builder

WORKDIR /app
ENV NODE_ENV=development

COPY package*.json ./
RUN npm ci

RUN mkdir -p public
COPY . .

RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/next.config.mjs ./next.config.mjs
COPY --from=builder /app/node_modules ./node_modules

RUN npm prune --omit=dev && addgroup -S nodejs && adduser -S node -G nodejs && chown -R node:node /app
USER node

EXPOSE 3000

CMD ["npm","start"]
