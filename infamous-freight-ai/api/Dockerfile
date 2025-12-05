FROM node:20-alpine AS builder

RUN apk add --no-cache openssl

WORKDIR /app
ENV NODE_ENV=development

COPY package*.json ./
RUN npm ci

COPY prisma ./prisma
RUN npm run prisma:generate

COPY src ./src
COPY scripts ./scripts

RUN npm prune --omit=dev

FROM node:20-alpine AS runner

RUN apk add --no-cache openssl

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/src ./src
COPY --from=builder /app/scripts ./scripts

RUN chown -R node:node /app
USER node

EXPOSE 4000

CMD ["npm","start"]
