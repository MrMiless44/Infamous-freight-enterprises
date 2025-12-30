# Team Knowledge Transfer Guide

## Overview

This guide provides comprehensive documentation for onboarding new developers and transferring knowledge about the Infamous Freight Enterprises platform architecture, features, and operations.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Key Technologies](#key-technologies)
3. [Development Setup](#development-setup)
4. [API Endpoints](#api-endpoints)
5. [WebSocket Integration](#websocket-integration)
6. [Real-Time Features](#real-time-features)
7. [Monitoring & Observability](#monitoring--observability)
8. [Performance Optimization](#performance-optimization)
9. [Security Practices](#security-practices)
10. [Troubleshooting](#troubleshooting)

## Architecture Overview

### System Design

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Applications                     │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │  Web (Next.js)   │  │ Mobile (Expo RN) │                 │
│  │  TypeScript      │  │  TypeScript      │                 │
│  └──────────┬───────┘  └────────┬─────────┘                 │
│             │                   │                            │
│             └───────────────────┼──────────────────┐        │
│                                 │                  │         │
│                            REST + WebSocket       │         │
│                                 │                  │         │
│             ┌───────────────────▼──────────────────▼───┐    │
│             │     API Server (Express.js)              │    │
│             │     - REST endpoints                      │    │
│             │     - WebSocket (Socket.IO)              │    │
│             │     - Auth (JWT + Scopes)                │    │
│             │     - Rate Limiting                       │    │
│             │     - Monitoring & Metrics               │    │
│             └──────────────────┬──────────────────────┘    │
│                                 │                           │
│                        Prisma ORM                           │
│                                 │                           │
│             ┌───────────────────▼──────────────────────┐   │
│             │     PostgreSQL Database                  │   │
│             │     - Shipments                          │   │
│             │     - Drivers                            │   │
│             │     - Users                              │   │
│             │     - Audit Logs                         │   │
│             └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Monorepo Structure

```
├── src/
│   ├── apps/
│   │   ├── api/              # Express.js API server
│   │   │   ├── src/
│   │   │   │   ├── routes/   # API endpoints
│   │   │   │   ├── services/ # Business logic
│   │   │   │   ├── middleware/
│   │   │   │   └── server.ts # Express app setup
│   │   │   ├── __tests__/    # Jest tests
│   │   │   └── package.json
│   │   ├── web/              # Next.js frontend
│   │   │   ├── pages/        # Next.js pages
│   │   │   ├── components/   # React components
│   │   │   ├── hooks/        # Custom hooks
│   │   │   ├── contexts/     # React contexts
│   │   │   └── package.json
│   │   └── mobile/           # React Native/Expo
│   └── packages/
│       └── shared/           # Shared types & utilities
├── pnpm-workspace.yaml       # pnpm workspace config
└── package.json              # Root package.json
```

## Key Technologies

### Backend

- **Express.js**: REST API framework
- **Socket.IO**: Real-time bidirectional communication
- **Prisma**: TypeScript ORM for database access
- **PostgreSQL**: Relational database
- **Jest**: Testing framework
- **Winston**: Structured logging

### Frontend

- **Next.js 14**: React framework with SSR
- **TypeScript**: Static typing
- **React Hooks**: State management
- **Socket.IO Client**: WebSocket client library
- **TailwindCSS**: Utility-first CSS

### DevOps

- **Docker**: Containerization
- **Docker Compose**: Multi-container orchestration
- **pnpm**: Package manager with workspaces
- **GitHub Actions**: CI/CD

## Development Setup

### Prerequisites

```bash
# Required versions
Node.js: 18+
pnpm: 8.15.9+
PostgreSQL: 14+
Docker: 20.10+
```

### Quick Start

```bash
# 1. Clone repository
git clone <repo-url>
cd Infamous-freight-enterprises

# 2. Install dependencies
pnpm install

# 3. Setup environment
cp .env.example .env
# Edit .env with your config

# 4. Setup database
cd src/apps/api
pnpm prisma migrate dev

# 5. Start dev server
cd ../..
pnpm dev

# Access:
# - Web: http://localhost:3000
# - API: http://localhost:4000
```

### Environment Variables

**Key Variables**:

```env
# API Configuration
API_PORT=4000
API_BASE_URL=http://localhost:4000

# Web Configuration
WEB_PORT=3000
NEXT_PUBLIC_API_URL=http://localhost:4000

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/freight

# Authentication
JWT_SECRET=your-secret-key-here
JWT_EXPIRY=24h

# AI Provider
AI_PROVIDER=synthetic  # openai, anthropic, or synthetic

# WebSocket
WEBSOCKET_ENABLED=true
WEBSOCKET_CORS_ORIGINS=http://localhost:3000

# Monitoring
ENABLE_MONITORING=true
LOG_LEVEL=debug
```

## API Endpoints

### Health & Monitoring

```
GET /api/health                    # Service health status
GET /api/metrics                   # Prometheus metrics
GET /api/metrics/performance       # Performance metrics
GET /api/metrics/cache             # Cache statistics
GET /api/metrics/websocket         # WebSocket metrics
GET /api/metrics/ratelimit         # Rate limit status
GET /api/metrics/alive             # Liveness probe
GET /api/metrics/ready             # Readiness probe
```

### Shipments

```
GET    /api/shipments              # List shipments
GET    /api/shipments/:id          # Get shipment details
POST   /api/shipments              # Create shipment
PUT    /api/shipments/:id          # Update shipment
DELETE /api/shipments/:id          # Delete shipment
GET    /api/shipments/export       # Export shipments
```

### WebSocket Events

```
# Client → Server
socket.emit('subscribe', { event: 'shipment:update' })
socket.emit('unsubscribe', { event: 'shipment:update' })

# Server → Client
socket.on('shipment:update', (data) => { ... })
socket.on('shipment:created', (data) => { ... })
socket.on('connection-error', (error) => { ... })
```

## WebSocket Integration

### Client Setup

```typescript
import { useWebSocket } from '@/hooks/useWebSocket';

function MyComponent() {
  const ws = useWebSocket();

  useEffect(() => {
    // Subscribe to events
    ws.subscribe('shipment:update', (shipment) => {
      console.log('Shipment updated:', shipment);
    });

    // Cleanup on unmount
    return () => ws.unsubscribe('shipment:update');
  }, [ws]);

  return (
    <div>
      Connection Status: {ws.isConnected ? 'Connected' : 'Disconnected'}
    </div>
  );
}
```

### Server Events

```typescript
// Broadcasting updates to all connected clients
io.emit("shipment:update", {
  id: shipment.id,
  status: shipment.status,
  timestamp: new Date(),
});

// Broadcasting to specific room
io.to(`shipment:${shipmentId}`).emit("shipment:update", shipment);

// Broadcasting to user
io.to(`user:${userId}`).emit("notification", message);
```

## Real-Time Features

### Real-time Shipment Updates

Use `RealtimeShipmentList` component for live updates:

```typescript
import RealtimeShipmentList from '@/components/RealtimeShipmentList';

export default function Dashboard() {
  return (
    <RealtimeShipmentList
      initialShipments={shipments}
      onShipmentUpdate={(updated) => {
        console.log('Shipment updated:', updated);
      }}
    />
  );
}
```

### Live Notifications

```typescript
// Subscribe to user notifications
ws.subscribe(`user:${userId}:notification`, (notification) => {
  // Show toast, update badge, etc.
  showNotification(notification.message);
});
```

### Real-time Presence

```typescript
// Track who's online
socket.on("user:online", (user) => {
  console.log(`${user.name} is now online`);
});

socket.on("user:offline", (user) => {
  console.log(`${user.name} went offline`);
});
```

## Monitoring & Observability

### Health Checks

```bash
# Check service health
curl http://localhost:4000/api/health

# Response includes:
# - uptime: Service uptime in seconds
# - status: "ok" or "degraded"
# - database: "connected" or "disconnected"
```

### Metrics Collection

```bash
# Get Prometheus metrics
curl http://localhost:4000/api/metrics

# Get performance metrics
curl http://localhost:4000/api/metrics/performance

# Response includes:
# - Memory usage (heap, RSS)
# - CPU usage
# - Uptime
# - Database connection status
```

### Logs

```bash
# View API logs
docker-compose logs -f api

# View Web logs
docker-compose logs -f web

# Filter logs
docker-compose logs api | grep "error"
```

### Debugging

```bash
# Enable debug logging
DEBUG=* pnpm api:dev

# Check database connection
pnpm prisma:studio

# View raw queries
# Add this to code:
// Enable query logging
prisma.$on('query', (e) => {
  console.log('Query: ' + e.query)
  console.log('Duration: ' + e.duration + 'ms')
})
```

## Performance Optimization

### Database Queries

**Good practices**:

```typescript
// ✅ Use include for relations
const shipments = await prisma.shipment.findMany({
  include: { driver: true },
  take: 100,
});

// ✅ Use select for specific columns
const shipments = await prisma.shipment.findMany({
  select: {
    id: true,
    status: true,
    driver: { select: { name: true } },
  },
});

// ❌ Avoid N+1 queries
const shipments = await prisma.shipment.findMany();
for (const s of shipments) {
  s.driver = await prisma.driver.findUnique({ ... });
}
```

### Caching

```typescript
// Use in-memory cache
const cache = new Map();

async function getShipment(id) {
  const cached = cache.get(id);
  if (cached) return cached;

  const shipment = await prisma.shipment.findUnique({
    where: { id },
  });

  // Cache for 5 minutes
  cache.set(id, shipment);
  setTimeout(() => cache.delete(id), 5 * 60 * 1000);

  return shipment;
}
```

### Frontend Performance

```typescript
// Code splitting with dynamic imports
const RealtimeChart = dynamic(
  () => import('@/components/RealtimeChart'),
  { ssr: false }
);

// Image optimization
import Image from 'next/image';
<Image src={url} width={400} height={300} alt="..." />

// Lazy loading lists
import { useIntersectionObserver } from '@/hooks/useIntersectionObserver';
```

## Security Practices

### Authentication

```typescript
// JWT authentication
const token = localStorage.getItem("auth_token");

// Include in API requests
const res = await fetch("/api/shipments", {
  headers: {
    Authorization: `Bearer ${token}`,
  },
});

// WebSocket authentication
const socket = io("http://localhost:4000", {
  auth: { token },
});
```

### Authorization

```typescript
// Scope-based authorization
// Client must have correct scope for endpoint

const shipments = await fetch("/api/shipments", {
  headers: {
    Authorization: `Bearer ${token}`, // Token must have 'shipment:read' scope
  },
});
```

### Input Validation

```typescript
// Server-side validation
import { body, validationResult } from "express-validator";

app.post(
  "/api/shipments",
  [
    body("origin").notEmpty().trim(),
    body("destination").notEmpty().trim(),
    body("weight").isFloat({ min: 0 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors });
    }
    // Process valid request
  },
);
```

### Rate Limiting

```typescript
// Configured per endpoint
// Default: 100 requests per 15 minutes
// AI endpoints: 20 per minute
// Auth endpoints: 5 per 15 minutes

// Check headers for limit info
const remaining = res.headers["X-RateLimit-Remaining"];
const reset = res.headers["X-RateLimit-Reset"];
```

## Troubleshooting

### Common Issues

**1. WebSocket Connection Fails**

```bash
# Check if WebSocket server is running
curl http://localhost:4000/api/health

# Verify CORS settings in .env
WEBSOCKET_CORS_ORIGINS=http://localhost:3000

# Check browser console for errors
# Enable debug logging
localStorage.debug = '*'
```

**2. Database Connection Errors**

```bash
# Check database URL
echo $DATABASE_URL

# Test connection
pnpm prisma:studio

# Check PostgreSQL is running
docker ps | grep postgres
```

**3. Performance Issues**

```bash
# Check metrics
curl http://localhost:4000/api/metrics/performance

# Monitor memory usage
# If > 90%, restart service

# Check slow queries
# Enable query logging in development
DEBUG=* pnpm api:dev
```

**4. Authentication Failures**

```bash
# Verify JWT secret matches between services
grep JWT_SECRET .env

# Check token expiration
# Decode JWT at https://jwt.io

# Verify token is sent with requests
curl -H "Authorization: Bearer <token>" http://localhost:4000/api/shipments
```

### Getting Help

1. **Check logs**: `docker-compose logs <service>`
2. **Check metrics**: `curl http://localhost:4000/api/metrics/health`
3. **Check documentation**: See [README.md](README.md) and [OPERATIONAL_RUNBOOKS.md](OPERATIONAL_RUNBOOKS.md)
4. **Ask in team chat**: Reference error messages and reproduction steps
5. **Create issue**: Include logs, steps to reproduce, environment info

## Quick Reference

### Common Commands

```bash
# Start development
pnpm dev

# Run tests
pnpm test

# Type checking
pnpm check:types

# Linting
pnpm lint

# Code formatting
pnpm format

# Build for production
pnpm build

# Database migrations
cd src/apps/api
pnpm prisma:migrate:dev --name <description>

# View database GUI
pnpm prisma:studio

# Generate Prisma client
pnpm prisma:generate
```

### Debug Mode

```bash
# Enable debug logging
DEBUG=* pnpm dev

# Debug specific service
DEBUG=api:* pnpm api:dev

# Debug API with Inspector
node --inspect=9229 src/server.js

# Then open in Chrome: chrome://inspect
```

### Performance Profiling

```bash
# CPU profiling
node --prof src/server.js
# Process output: node --prof-process isolate-*.log > profile.txt

# Memory profiling
node --inspect src/server.js
# Use Chrome DevTools Memory tab
```

## Additional Resources

- [README.md](README.md) - Project overview
- [API_REFERENCE.md](API_REFERENCE.md) - Detailed API documentation
- [OPERATIONAL_RUNBOOKS.md](OPERATIONAL_RUNBOOKS.md) - Operations procedures
- [DATABASE_OPTIMIZATION_GUIDE.md](DATABASE_OPTIMIZATION_GUIDE.md) - Database optimization
- [SECURITY.md](SECURITY.md) - Security guidelines
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contributing guidelines

---

**Last Updated**: 2024
**Version**: 1.0
**Maintainers**: Development Team
