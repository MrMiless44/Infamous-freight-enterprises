# Quick Start: Session 3 New Features

## 🎯 What's New in This Session

### 1. WebSocket Real-Time Updates (NEW)

```typescript
// Use the WebSocket hook in any component
import { useWebSocketContext } from '@/contexts/WebSocketContext';

function ShipmentTracker() {
  const ws = useWebSocketContext();

  useEffect(() => {
    // Subscribe to live shipment updates
    ws.subscribe('shipment:update', (shipment) => {
      console.log('Shipment updated:', shipment);
      // Update UI with fresh data
    });

    return () => ws.unsubscribe('shipment:update');
  }, [ws]);

  return <div>Real-time shipment list here</div>;
}
```

### 2. Export Data (NEW)

```typescript
// Use the export modal in your dashboard
import ExportModal from '@/components/ExportModal';

<ExportModal
  shipments={allShipments}
  onExport={(format) => console.log(`Exporting as ${format}`)}
/>
```

### 3. Monitor API Health (NEW)

```bash
# Check service metrics
curl http://localhost:4000/api/metrics

# Get performance stats
curl http://localhost:4000/api/metrics/performance

# Check cache hit rate
curl http://localhost:4000/api/metrics/cache

# Monitor WebSocket connections
curl http://localhost:4000/api/metrics/websocket
```

### 4. Run Load Tests (NEW)

```bash
# Using K6
k6 run scripts/load-test-k6.js

# Using Bash script
./scripts/load-test.sh 60 10  # 60 seconds, 10 concurrent users
```

---

## 📚 Documentation Guide

### For Developers

- Start here: [TEAM_KNOWLEDGE_TRANSFER.md](TEAM_KNOWLEDGE_TRANSFER.md)
- WebSocket examples: [REALTIME_COLLABORATION_GUIDE.md](REALTIME_COLLABORATION_GUIDE.md)
- Caching patterns: [ADVANCED_CACHING_GUIDE.md](ADVANCED_CACHING_GUIDE.md)

### For DevOps/Operations

- Operations guide: [OPERATIONAL_RUNBOOKS.md](OPERATIONAL_RUNBOOKS.md)
- Database tuning: [DATABASE_OPTIMIZATION_GUIDE.md](DATABASE_OPTIMIZATION_GUIDE.md)
- Monitoring setup: See [TEAM_KNOWLEDGE_TRANSFER.md](TEAM_KNOWLEDGE_TRANSFER.md#monitoring--observability)

### For Architects

- Full session summary: [SESSION_3_FINAL_DELIVERY.md](SESSION_3_FINAL_DELIVERY.md)
- Detailed completion: [SESSION_3_RECOMMENDATIONS_COMPLETE.md](SESSION_3_RECOMMENDATIONS_COMPLETE.md)

---

## 🚀 Getting Started

### 1. Setup Development Environment

```bash
# Install dependencies
pnpm install

# Setup environment
cp .env.example .env

# Start dev server
pnpm dev

# Access:
# - Web: http://localhost:3000
# - API: http://localhost:4000
```

### 2. Test WebSocket Connection

```bash
# Open browser console and test
const socket = io('http://localhost:4000', {
  auth: { token: 'your-jwt-token' }
});

socket.on('connect', () => console.log('Connected!'));
socket.emit('user:online', { id: 'user123', name: 'John' });
socket.on('presence:updated', (data) => console.log(data));
```

### 3. Test Monitoring Endpoints

```bash
# Liveness probe
curl -s http://localhost:4000/api/metrics/alive | json_pp

# Readiness check
curl -s http://localhost:4000/api/metrics/ready | json_pp

# Full health status
curl -s http://localhost:4000/api/metrics/health | json_pp

# Performance metrics
curl -s http://localhost:4000/api/metrics/performance | json_pp
```

### 4. Run Tests

```bash
# All tests
pnpm test

# Just the new tests
pnpm test -- extended-features

# With coverage
pnpm test -- --coverage
```

---

## 💡 Key Patterns

### WebSocket Subscription

```typescript
const ws = useWebSocketContext();

// Subscribe
ws.subscribe("event:name", (data) => {
  // Handle event
});

// Unsubscribe
ws.unsubscribe("event:name");

// Emit
ws.emit("event:name", { data: "value" });
```

### Cache Hit Rate

```bash
# Check cache performance
curl http://localhost:4000/api/metrics/cache

# Response includes:
# - hitRate: 0.75 (75% hit rate)
# - size: 125 (items in cache)
# - maxSize: 1000 (cache capacity)
```

### Database Query Optimization

```typescript
// ❌ BAD: N+1 queries
const shipments = await db.shipment.findMany();
for (const s of shipments) {
  s.driver = await db.driver.findUnique({ where: { id: s.driverId } });
}

// ✅ GOOD: Single query with relations
const shipments = await db.shipment.findMany({
  include: { driver: true },
  take: 100,
});
```

---

## 🔍 Troubleshooting

### WebSocket Not Connecting

```bash
# Check service is running
curl http://localhost:4000/api/health

# Verify JWT token
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:4000/api/metrics

# Check browser console for errors
# localStorage.debug = '*' to enable debug logging
```

### Slow API Responses

```bash
# Check performance metrics
curl http://localhost:4000/api/metrics/performance

# Run database query analysis
# Check DATABASE_OPTIMIZATION_GUIDE.md for slow query troubleshooting
```

### High Memory Usage

```bash
# Check memory stats
curl http://localhost:4000/api/metrics/performance

# If > 90%, restart service
docker-compose restart api  # or pnpm dev (restart)
```

---

## 📊 Monitoring Dashboard

### Key Metrics to Watch

| Metric                | Healthy | Warning    | Critical         |
| --------------------- | ------- | ---------- | ---------------- |
| Memory Usage          | <50%    | 50-75%     | >75%             |
| Cache Hit Rate        | >70%    | 50-70%     | <50%             |
| Response Time p95     | <500ms  | 500-1000ms | >1000ms          |
| Error Rate            | <1%     | 1-5%       | >5%              |
| WebSocket Connections | N/A     | Growing    | Stability issues |

### Quick Checks

```bash
# Overall health
curl http://localhost:4000/api/metrics/health | jq .status

# Memory usage
curl http://localhost:4000/api/metrics/performance | jq .memory

# Cache performance
curl http://localhost:4000/api/metrics/cache | jq .hitRate

# WebSocket activity
curl http://localhost:4000/api/metrics/websocket | jq .activeConnections
```

---

## 📝 Common Tasks

### Adding Real-Time Feature

```typescript
// 1. Emit event from server
io.emit("custom:event", { data: "value" });

// 2. Subscribe in component
ws.subscribe("custom:event", (data) => {
  // Update state
});

// 3. Cleanup on unmount
return () => ws.unsubscribe("custom:event");
```

### Exporting Data

```typescript
// Use the ExportModal component
<ExportModal shipments={shipments} onExport={handleExport} />

// Or call export service directly
exportService.exportToCSV(shipments);
exportService.exportToPDF(shipments);
exportService.exportToJSON(shipments);
```

### Optimizing Database Query

```typescript
// Check query performance
const start = Date.now();
const result = await db.shipment.findMany({
  include: { driver: true }, // Use include instead of N+1
  select: { id: true, status: true }, // Only fetch needed fields
  where: { status: "in_transit" }, // Filter early
  take: 100, // Limit results
});
console.log(`Query took ${Date.now() - start}ms`);
```

---

## 🎓 Learning Resources

### By Role

**Frontend Developer**

1. Read: [TEAM_KNOWLEDGE_TRANSFER.md](TEAM_KNOWLEDGE_TRANSFER.md)
2. Study: `src/apps/web/hooks/useWebSocket.ts`
3. Review: `src/apps/web/components/ExportModal.tsx`
4. Practice: Create a real-time component

**Backend Developer**

1. Read: [TEAM_KNOWLEDGE_TRANSFER.md](TEAM_KNOWLEDGE_TRANSFER.md)
2. Study: `src/apps/api/src/routes/monitoring.ts`
3. Review: [DATABASE_OPTIMIZATION_GUIDE.md](DATABASE_OPTIMIZATION_GUIDE.md)
4. Practice: Optimize a slow query

**DevOps/Operations**

1. Read: [OPERATIONAL_RUNBOOKS.md](OPERATIONAL_RUNBOOKS.md)
2. Setup: Monitoring endpoints
3. Configure: Load testing
4. Monitor: Health checks

**Architect/Tech Lead**

1. Review: [SESSION_3_FINAL_DELIVERY.md](SESSION_3_FINAL_DELIVERY.md)
2. Study: [REALTIME_COLLABORATION_GUIDE.md](REALTIME_COLLABORATION_GUIDE.md)
3. Plan: Remaining recommendations (17-20)
4. Evaluate: Performance impact

---

## ✅ Pre-Flight Checklist

Before going to production:

- [ ] All tests passing (`pnpm test`)
- [ ] No console errors in browser
- [ ] WebSocket connecting successfully
- [ ] Monitoring endpoints responding
- [ ] Load test completed successfully
- [ ] Documentation reviewed
- [ ] Performance baselines met
- [ ] Security review completed
- [ ] Code review approved
- [ ] Deployed to staging first

---

## 🆘 Support

### Documentation

1. [TEAM_KNOWLEDGE_TRANSFER.md](TEAM_KNOWLEDGE_TRANSFER.md) - All technical docs
2. [OPERATIONAL_RUNBOOKS.md](OPERATIONAL_RUNBOOKS.md) - Operational procedures
3. [SESSION_3_FINAL_DELIVERY.md](SESSION_3_FINAL_DELIVERY.md) - Session overview

### Getting Help

1. Check relevant documentation above
2. Review code examples in guides
3. Run diagnostic commands (see Troubleshooting)
4. Check git history for similar changes
5. Ask in team chat with error logs

---

## 📞 Quick Links

- API Health: http://localhost:4000/api/health
- Metrics: http://localhost:4000/api/metrics
- Performance: http://localhost:4000/api/metrics/performance
- Cache Stats: http://localhost:4000/api/metrics/cache
- Database GUI: `pnpm prisma:studio`

---

**Ready to start? Head to [TEAM_KNOWLEDGE_TRANSFER.md](TEAM_KNOWLEDGE_TRANSFER.md)** 🚀
