# Quick Reference: System Enhancements

## 🎯 At a Glance

**15 enhancements** implemented across API, Web, and infrastructure:
- Real-time tracking (WebSocket)
- Distributed caching (Redis)
- User rate limiting
- Enhanced health checks
- Data export (CSV/PDF/JSON)
- Error boundaries & loading skeletons
- Integration tests & CI/CD
- Deployment automation

## 📦 New Dependencies

```json
{
  "socket.io": "^4.8.1",
  "redis": "^4.7.0",
  "json2csv": "^6.0.0",
  "pdfkit": "^0.15.0",
  "rate-limiter-flexible": "^2.4.2"
}
```

**Install**: `pnpm install`

## 🔌 API Services

### WebSocket Service
```typescript
import { WebSocketService } from '@/services/websocket';

// Emit shipment update
WebSocketService.emitShipmentUpdate({
  shipmentId: 'SHIP-001',
  status: 'in_transit'
});

// Emit driver location
WebSocketService.emitDriverUpdate({
  driverId: 'DRV-001',
  location: { lat: 40.7128, lng: -74.0060 }
});
```

### Cache Service
```typescript
import { CacheService } from '@/services/cache';

// Simple get/set
await CacheService.set('key', value, 3600); // TTL in seconds
const value = await CacheService.get('key');
await CacheService.del('key');

// Atomic get-or-set pattern
const data = await CacheService.getOrSet(
  'expensive-query',
  async () => {
    // Only runs if cache miss
    return await db.query();
  },
  3600
);
```

### Export Service
```typescript
import { ExportService } from '@/services/export';

// CSV
ExportService.sendCSV(res, data, 'export.csv');

// PDF (with streaming)
await ExportService.exportToPDF(res, shipments, 'report.pdf');

// JSON
ExportService.sendJSON(res, data, 'export.json');
```

### Rate Limiting Middleware
```typescript
import { userRateLimit } from '@/middleware/userRateLimit';

// Apply to route
router.get('/api/expensive', userRateLimit('ai'), handler);

// Options: 'general', 'ai', 'billing'
// Limits: 100/15min, 20/1min, 30/15min
```

## 🎨 Web Components

### Error Boundary
```tsx
import { ErrorBoundary } from '@/components/ErrorBoundary';

<ErrorBoundary fallback={(error, reset) => (
  <div>
    <p>Error: {error.message}</p>
    <button onClick={reset}>Retry</button>
  </div>
)}>
  <App />
</ErrorBoundary>
```

### Loading Skeletons
```tsx
import {
  Skeleton,
  SkeletonText,
  SkeletonCard,
  SkeletonTable,
  SkeletonStats,
  SkeletonShipmentList
} from '@/components/Skeleton';

// Quick usage
{isLoading && <SkeletonShipmentList count={5} />}

// Skeleton with options
<Skeleton count={3} height={20} width="100%" />

// Text lines
<SkeletonText count={4} />

// Card layout
<SkeletonCard count={2} />

// Table
<SkeletonTable rows={10} columns={4} />

// Statistics dashboard
<SkeletonStats count={4} />
```

## 🏥 Health Endpoints

```bash
# Basic health check
curl http://localhost:4000/api/health

# Detailed status
curl http://localhost:4000/api/health/detailed

# Kubernetes readiness
curl http://localhost:4000/api/health/ready

# Kubernetes liveness
curl http://localhost:4000/api/health/live
```

## 🔧 Environment Variables

```bash
# Cache (optional)
REDIS_URL=redis://localhost:6379

# WebSocket
WS_CORS_ORIGINS=http://localhost:3000

# Rate Limiting
RATE_LIMIT_GENERAL_MAX=100    # requests per 15 minutes
RATE_LIMIT_AI_MAX=20           # requests per 1 minute
RATE_LIMIT_BILLING_MAX=30      # requests per 15 minutes

# Optional: custom rate limit windows
RATE_LIMIT_WINDOW_MS=900000    # 15 minutes
```

## 🧪 Testing

```bash
# All tests
pnpm test

# API only
pnpm --filter infamous-freight-api test

# With coverage
pnpm --filter infamous-freight-api test -- --coverage

# Watch mode
pnpm --filter infamous-freight-api test -- --watch

# Integration tests only
pnpm --filter infamous-freight-api test -- integration
```

## 🚀 Common Tasks

### Monitor Service Health
```bash
# Check if services are ready
curl http://localhost:4000/api/health/detailed

# Should show database and memory status
```

### Enable WebSocket Real-time
```typescript
// In server.ts - already done!
WebSocketService.initialize(httpServer);

// In route handlers
WebSocketService.emitShipmentUpdate({...});
```

### Add Caching to Query
```typescript
// Before: Always hits database
const shipment = await prisma.shipment.findUnique({...});

// After: Uses cache with 1-hour TTL
const shipment = await CacheService.getOrSet(
  `shipment:${id}`,
  () => prisma.shipment.findUnique({...}),
  3600
);
```

### Export Shipments
```bash
# CSV
curl http://localhost:4000/api/shipments?format=csv > export.csv

# PDF
curl http://localhost:4000/api/shipments?format=pdf > export.pdf

# JSON
curl http://localhost:4000/api/shipments?format=json > export.json
```

### Handle Errors in UI
```tsx
// Wrap component to catch errors
<ErrorBoundary>
  <ShipmentsDashboard />
</ErrorBoundary>

// Show loading state
{isLoading ? <SkeletonShipmentList /> : <ShipmentList {...} />}
```

## 📊 Files Changed/Created

### API (`src/apps/api/src/`)
- ✅ **NEW** `services/websocket.ts` - Real-time WebSocket server
- ✅ **NEW** `services/cache.ts` - Redis caching with fallback
- ✅ **NEW** `services/export.ts` - CSV/PDF/JSON export
- ✅ **NEW** `middleware/userRateLimit.ts` - Per-user rate limiting
- ✅ **ENHANCED** `routes/health.ts` - Detailed health checks
- ✅ **ENHANCED** `server.ts` - WebSocket & cache initialization

### Web (`src/apps/web/`)
- ✅ **NEW** `components/ErrorBoundary.tsx` - Error handling
- ✅ **NEW** `components/Skeleton.tsx` - Loading states

### Tests (`src/apps/api/__tests__/`)
- ✅ **NEW** `integration/realtime-tracking.test.ts` - Integration tests

### Deployment
- ✅ **NEW** `.github/workflows/mobile.yml` - Mobile CI/CD
- ✅ **NEW** `scripts/deploy.sh` - Deployment automation

### Documentation
- ✅ **NEW** `ENHANCEMENTS_COMPLETE.md` - Full feature guide
- ✅ **NEW** `QUICK_REFERENCE_ENHANCEMENTS.md` - This file!
- ✅ **ENHANCED** `SETUP_STATUS.md` - Setup checklist

## 🎓 Learning Path

**New to the enhancements?**

1. **Start**: Read [ENHANCEMENTS_COMPLETE.md](ENHANCEMENTS_COMPLETE.md) overview
2. **Explore**: Check out service files in `src/apps/api/src/services/`
3. **Implement**: Add WebSocket events to a route
4. **Test**: Run integration tests with `pnpm test`
5. **Deploy**: Use `bash scripts/deploy.sh`

## ⚠️ Common Issues

| Issue | Solution |
|-------|----------|
| WebSocket won't connect | Check `server.ts` initializes `WebSocketService` |
| Cache not working | Verify `CacheService.initialize()` called |
| Rate limits too strict | Increase `RATE_LIMIT_*_MAX` env vars |
| Export fails | Ensure `json2csv` and `pdfkit` installed |
| Health check 503 | Database connection may be down |

## 🔗 File Links

- [WebSocket Service](../src/apps/api/src/services/websocket.ts)
- [Cache Service](../src/apps/api/src/services/cache.ts)
- [Export Service](../src/apps/api/src/services/export.ts)
- [User Rate Limit](../src/apps/api/src/middleware/userRateLimit.ts)
- [Health Routes](../src/apps/api/src/routes/health.ts)
- [Error Boundary](../src/apps/web/components/ErrorBoundary.tsx)
- [Skeleton Components](../src/apps/web/components/Skeleton.tsx)
- [Integration Tests](../src/apps/api/__tests__/integration/realtime-tracking.test.ts)

## 📞 Quick Help

**What does each enhancement do?**

1. **WebSocket**: Real-time updates (shipment status, driver location)
2. **Caching**: Faster responses, less database load
3. **Rate Limiting**: Prevent abuse, fair resource allocation
4. **Health Checks**: Monitor system status, Kubernetes support
5. **Export**: Download shipments as CSV/PDF/JSON
6. **Error Boundary**: Catch component errors gracefully
7. **Skeletons**: Show loading states professionally
8. **API Docs**: Swagger/OpenAPI documentation
9. **Tests**: Validate real-time and export features
10. **Mobile CI/CD**: Automate React Native testing/building
11. **Deploy Script**: One-command deployment
12. **Server Updates**: WebSocket HTTP upgrade support
13. **Performance Monitoring**: Track key metrics
14. **Security**: JWT auth for WebSocket, per-user rate limits
15. **Documentation**: Complete developer guides

**Which one should I use first?**

→ Start with **Error Boundary** + **Skeletons** for UI improvements
→ Then add **WebSocket** for real-time features
→ Finally optimize with **Caching**

**How do I troubleshoot?**

1. Check logs: `docker logs [container]` or terminal output
2. Test endpoints: `curl http://localhost:4000/api/health`
3. Review errors in console (browser Dev Tools)
4. Check environment variables in `.env`
5. Run tests: `pnpm test`
