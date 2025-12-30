# Quick Reference - New Features

## 🔌 WebSocket Real-Time Updates

### Client Connection
```javascript
import io from 'socket.io-client';

const socket = io('http://localhost:4000', {
  auth: { token: yourJWTToken }
});

// Subscribe to shipment updates
socket.emit('subscribe:shipment', 'shipment-id-123');

// Listen for updates
socket.on('shipment:update', (data) => {
  console.log('Shipment updated:', data);
});

// Unsubscribe
socket.emit('unsubscribe:shipment', 'shipment-id-123');
```

### Events
- `subscribe:shipment` - Subscribe to shipment updates
- `subscribe:driver` - Subscribe to driver updates
- `subscribe:shipments:all` - Subscribe to all (admin/dispatcher only)
- `driver:location` - Emit driver location (from mobile)
- `shipment:update` - Receive shipment updates
- `driver:update` - Receive driver updates
- `driver:location:update` - Receive driver location
- `notification` - Receive user notifications

## 💾 Redis Caching

```javascript
const cache = require('./services/cache');

// Get cached value
const value = await cache.get('my-key');

// Set with TTL (seconds)
await cache.set('my-key', { data: 'value' }, 300);

// Get or fetch and cache
const data = await cache.getOrSet('my-key', async () => {
  return await fetchFromDatabase();
}, 600);

// Delete cache
await cache.del('my-key');

// Delete pattern
await cache.delPattern('shipments:*');
```

## 📊 Export Data

```bash
# Export to CSV
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:4000/api/shipments/export/csv \
  -o shipments.csv

# Export to PDF
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:4000/api/shipments/export/pdf \
  -o report.pdf

# Export to JSON
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:4000/api/shipments/export/json \
  -o data.json
```

## 🎨 Loading States

```jsx
import { 
  SkeletonShipmentList,
  SkeletonTable,
  SkeletonCard,
  SkeletonStats 
} from '@/components/Skeleton';

// In your component
{isLoading ? <SkeletonShipmentList count={5} /> : <ShipmentList data={data} />}
```

## 🛡️ Error Boundaries

```jsx
import ErrorBoundary from '@/components/ErrorBoundary';

function App() {
  return (
    <ErrorBoundary fallback={(error, reset) => (
      <div>
        <h1>Error: {error.message}</h1>
        <button onClick={reset}>Try Again</button>
      </div>
    )}>
      <YourComponent />
    </ErrorBoundary>
  );
}
```

## 🚦 Rate Limiting

### Apply User-Level Rate Limiting
```javascript
const { userRateLimit } = require('./middleware/userRateLimit');

// Apply to routes
router.post('/api/command',
  authenticate,
  userRateLimit('ai'),  // 'general', 'ai', or 'billing'
  handler
);
```

### Rate Limit Headers
- `X-RateLimit-User-Limit` - Max requests allowed
- `X-RateLimit-User-Remaining` - Requests remaining
- `X-RateLimit-User-Reset` - When limit resets
- `Retry-After` - Seconds to wait (when rate limited)

## 🏥 Health Checks

```bash
# Basic health check
curl http://localhost:4000/api/health

# Detailed check (all services)
curl http://localhost:4000/api/health/detailed

# Kubernetes readiness
curl http://localhost:4000/api/health/ready

# Kubernetes liveness
curl http://localhost:4000/api/health/live
```

## 📚 API Documentation

Visit: `http://localhost:4000/api/docs`

Interactive Swagger UI with:
- All endpoints documented
- Try-it-out functionality
- Request/response examples
- Authentication testing

## 🚀 Deployment

```bash
# Deploy to production (Vercel + Fly.io)
./scripts/deploy.sh production

# Deploy to staging
./scripts/deploy.sh staging

# Deploy only web
./scripts/deploy.sh production false true

# Deploy only API
./scripts/deploy.sh production true false
```

## 🧪 Testing

```bash
# Run all tests
pnpm test

# Run with coverage
pnpm test:coverage

# Run specific test file
cd api && pnpm test realtime-tracking

# Watch mode
cd api && pnpm test:watch
```

## 🔐 Environment Variables

```bash
# Required
DATABASE_URL=postgresql://...
JWT_SECRET=your-secret

# Optional but recommended
REDIS_URL=redis://localhost:6379
SENTRY_DSN=https://...
DD_TRACE_ENABLED=true

# CORS (add your domains)
CORS_ORIGINS=http://localhost:3000,https://yourdomain.com
```

## 📱 Mobile Development

```bash
# Start Expo dev server
cd mobile && pnpm dev

# Build Android
pnpm exec eas build --platform android

# Build iOS
pnpm exec eas build --platform ios

# Publish update
pnpm exec eas update --branch production
```

## 🔍 Debugging

### View Logs
```bash
# API logs
cd api && tail -f logs/app.log

# Docker logs
docker logs infamous-freight-api

# Fly.io logs
flyctl logs
```

### Common Issues

**WebSocket not connecting?**
- Check JWT token is valid
- Verify CORS_ORIGINS includes your domain
- Try polling transport first: `transports: ['polling', 'websocket']`

**Cache not working?**
- System uses memory fallback if Redis unavailable
- Check Redis connection: `redis-cli ping`
- View cache stats: `GET /api/health/detailed`

**Rate limited?**
- Check headers for limits and reset time
- Adjust limits in `api/src/middleware/userRateLimit.js`
- Or disable for development

## 📖 Documentation

- **API Reference**: `/api/docs` (Swagger UI)
- **Full Guide**: `ENHANCEMENTS_COMPLETE.md`
- **Deployment**: `DEPLOY_ACTION.md`
- **Contributing**: `CONTRIBUTING.md`
