# syntax=docker/dockerfile:1.4

# ============================================
# Stage 1: Build stage - Install dependencies
# ============================================
FROM node:20-alpine AS builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./
COPY prisma ./prisma

# Install dependencies (production only)
RUN npm ci --only=production --ignore-scripts

# Generate Prisma Client
RUN npx prisma generate

# ============================================
# Stage 2: Production stage - Optimized image
# ============================================
FROM node:20-alpine AS production
WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV API_PORT=4000

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy node_modules from builder
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/prisma ./prisma

# Copy application source
COPY --chown=nodejs:nodejs package*.json ./
COPY --chown=nodejs:nodejs src ./src

# Switch to non-root user
USER nodejs

# Expose API port
EXPOSE 4000

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/api/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})" || exit 1

# Start the server
CMD ["node", "src/server.js"]
