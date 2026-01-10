# Datadog RUM Dashboard Setup Guide

## Overview

This guide configures Datadog Real User Monitoring (RUM) to track Web Vitals, API latency, and error rates.

## Prerequisites

- Datadog account with RUM access
- Datadog API keys configured in `.env`
- Web application deployed to production

## Configuration Steps

### 1. Set Environment Variables

Add these to your `.env.production`:

```bash
NEXT_PUBLIC_DD_APP_ID=your_app_id
NEXT_PUBLIC_DD_CLIENT_TOKEN=your_client_token
NEXT_PUBLIC_DD_SITE=datadoghq.com  # or datadoghq.eu
```

These are automatically used in `web/pages/_app.tsx` via `datadog-browser-rum`.

### 2. Create Custom Dashboard in Datadog

#### Dashboard Name

**Infamous Freight - Web Performance**

#### Add Widgets

##### Widget 1: Web Vitals (LCP, FID, CLS)

```
Query: @view.measures.largest_contentful_paint{*}
- LCP: Largest Contentful Paint (<2.5s is good)
- First Input Delay: <100ms is good
- Cumulative Layout Shift: <0.1 is good
```

##### Widget 2: API Latency (P50, P95, P99)

```
Query: @service_name:infamous-freight-api
- Metrics: duration
- Aggregation: p50, p95, p99
- Group by: endpoint
```

##### Widget 3: Error Rate

```
Query: @status:error
- Metric: count
- Group by: service
- Display: time series
```

##### Widget 4: Request Throughput

```
Query: @http.method:*
- Metric: count
- Aggregation: as_count
- Group by: @http.status_code
```

##### Widget 5: RUM Session Replay Rate

```
Query: @session.replay.key_session:*
- Shows % of sessions with replay enabled
```

### 3. Set Monitors/Alerts

#### Alert 1: High LCP

```
Trigger: @view.measures.largest_contentful_paint > 2500
Severity: Warning
Notification: #alerts Slack channel
```

#### Alert 2: High Error Rate

```
Trigger: error_rate > 5%
Severity: Critical
Notification: #alerts Slack channel + PagerDuty
```

#### Alert 3: API Latency P95 > 1000ms

```
Trigger: duration.p95 > 1000
Severity: Warning
Notification: #infrastructure Slack channel
```

### 4. Enable Real User Monitoring Code

In `web/pages/_app.tsx`:

```typescript
import { datadogRum } from "@datadog/browser-rum";

if (process.env.NEXT_PUBLIC_ENV === "production") {
  datadogRum.init({
    applicationId: process.env.NEXT_PUBLIC_DD_APP_ID!,
    clientToken: process.env.NEXT_PUBLIC_DD_CLIENT_TOKEN!,
    site: process.env.NEXT_PUBLIC_DD_SITE || "datadoghq.com",
    service: "infamous-freight-web",
    env: "production",
    sessionSampleRate: 100, // Collect 100% of sessions
    sessionReplaySampleRate: 10, // Record 10% for replay
    trackUserInteractions: true,
    trackResources: true,
    trackLongTasks: true,
    defaultPrivacyLevel: "mask-user-input",
  });
  datadogRum.startSessionReplayRecording();
}
```

### 5. Monitor API Performance

Add custom metrics in API error handler:

```typescript
// api/src/middleware/errorHandler.ts
import { statsd } from "../lib/datadog";

const errorHandler = (err, req, res, next) => {
  // Send metric to Datadog
  statsd.increment("error.count", 1, {
    error_type: err.constructor.name,
    endpoint: req.path,
    status_code: err.status || 500,
  });

  // Send timing
  statsd.timing("request.duration", Date.now() - req.startTime, {
    endpoint: req.path,
  });

  res.status(err.status || 500).json({ error: err.message });
};
```

### 6. Configure API Instrumentation

For Express.js backend, add APM:

```typescript
// api/src/server.ts
import tracer from "dd-trace";

// Must be called before importing other modules
if (process.env.DD_AGENT_HOST) {
  tracer.init({
    service: "infamous-freight-api",
    env: process.env.NODE_ENV || "development",
    version: "2.0.0",
  });
  tracer.use("express", {
    // Span hooks
  });
}
```

### 7. Log Integration

Send structured logs to Datadog:

```typescript
// Log from API with context
logger.info("Shipment created", {
  shipment_id: shipment.id,
  user_id: req.user.sub,
  duration_ms: Date.now() - req.startTime,
  dd: {
    trace_id: req.traceId,
    span_id: req.spanId,
  },
});
```

## Dashboard Link

Once set up, access your dashboard:

```
https://app.datadoghq.com/dashboard/lists
```

Search for "Infamous Freight - Web Performance"

## Key Metrics to Monitor

| Metric                         | Target | Warning   | Critical |
| ------------------------------ | ------ | --------- | -------- |
| LCP (Largest Contentful Paint) | <2.5s  | 2.5-4s    | >4s      |
| FID (First Input Delay)        | <100ms | 100-300ms | >300ms   |
| CLS (Cumulative Layout Shift)  | <0.1   | 0.1-0.25  | >0.25    |
| API P95 Latency                | <200ms | 200-500ms | >500ms   |
| Error Rate                     | <1%    | 1-5%      | >5%      |
| Database P95 Latency           | <100ms | 100-300ms | >300ms   |

## Troubleshooting

### No Data Appearing

1. Verify environment variables are set: `echo $NEXT_PUBLIC_DD_CLIENT_TOKEN`
2. Check browser console for RUM SDK errors
3. Confirm traffic exists: check Web application logs

### High Latency

1. Check slow query log in database
2. Review API error logs in Sentry
3. Check frontend bundle size with Lighthouse

### Missing Metrics

1. Verify Datadog agent is running on API server
2. Check `dd-trace` initialization runs before routes
3. Confirm `.env` variables are passed to containers

## References

- [Datadog RUM Documentation](https://docs.datadoghq.com/real_user_monitoring/)
- [Next.js Integration](https://docs.datadoghq.com/real_user_monitoring/browser_support/#supported-frameworks)
- [Express.js APM](https://docs.datadoghq.com/tracing/trace_collection/automatic_instrumentation/nodejs/)
- [Datadog Alerts](https://docs.datadoghq.com/monitors/)
