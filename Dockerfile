# Multi-stage Dockerfile for Infæmous Freight (Render deployment)
# Builds both API and Web services in a single container with nginx routing

FROM node:20-alpine AS base
RUN apk add --no-cache openssl nginx

# Build API
FROM base AS api-builder
WORKDIR /app/api
COPY api/package*.json ./
RUN npm ci --only=production
COPY api/ ./
RUN npx prisma generate

# Build Web
FROM base AS web-builder
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Production Stage
FROM node:20-alpine AS production
RUN apk add --no-cache openssl nginx supervisor

# Default internal ports
ENV API_PORT=4000
ENV NEXT_PORT=3000

# Copy API
WORKDIR /app/api
COPY --from=api-builder /app/api ./

# Copy Web
WORKDIR /app/web
COPY --from=web-builder /app/web/.next ./.next
COPY --from=web-builder /app/web/node_modules ./node_modules
COPY --from=web-builder /app/web/package*.json ./
COPY --from=web-builder /app/web/public ./public

# Copy nginx config tuned for single-container deployment
COPY nginx/nginx.render.conf /etc/nginx/nginx.conf

# Create supervisor config to run all services
RUN mkdir -p /var/log/supervisor
COPY <<'SUPERVISOR' /etc/supervisord.conf
[supervisord]
nodaemon=true
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid

[program:api]
directory=/app/api
command=node src/server.js
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

environment=API_PORT=4000

[program:web]
directory=/app/web
command=node node_modules/next/dist/bin/next start -p 3000
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

environment=PORT=3000

[program:nginx]
command=nginx -g 'daemon off;'
autostart=true
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
SUPERVISOR

EXPOSE 8080

CMD ["supervisord", "-c", "/etc/supervisord.conf"]
