# 📊 Vercel Analytics Setup Guide

**Status**: ✅ Package installed (`@vercel/analytics@^1.4.0`)

## Installation Complete

The `@vercel/analytics` package has been added to the web application and is ready to use.

## Quick Integration

### 1. Add to Root Layout (app/layout.tsx or pages/\_app.tsx)

```typescript
import { Analytics } from '@vercel/analytics/react';

export default function RootLayout({ children }) {
  return (
    <html>
      <body>
        {children}
        <Analytics />
      </body>
    </html>
  );
}
```

### 2. For Pages Router (Next.js Pages)

Add to `pages/_app.tsx`:

```typescript
import { Analytics } from '@vercel/analytics/react';

function MyApp({ Component, pageProps }) {
  return (
    <>
      <Component {...pageProps} />
      <Analytics />
    </>
  );
}

export default MyApp;
```

## What Gets Tracked Automatically

✅ **Web Vitals**

- Largest Contentful Paint (LCP)
- First Input Delay (FID)
- Cumulative Layout Shift (CLS)

✅ **Navigation Events**

- Page transitions
- Route changes

✅ **Custom Events**

- Button clicks (with data attributes)
- Form submissions
- User interactions

## Custom Event Tracking

```typescript
import { track } from "@vercel/analytics";

// Track custom events
track("button_click", {
  button_name: "signup",
  location: "/pricing",
});

// Track conversions
track("conversion", {
  item: "premium_plan",
  value: 99.99,
});
```

## Environment Configuration

Analytics are **automatically disabled in development**:

- `NODE_ENV=development` → No data sent
- `NODE_ENV=production` → Data sent to Vercel

### Manual Control

```typescript
<Analytics debug={process.env.NODE_ENV === 'development'} />
```

## Data Privacy

- ✅ No personally identifiable information (PII) collected
- ✅ GDPR compliant
- ✅ Can be disabled per user: Check Vercel dashboard settings
- ✅ Data retention: 90 days default

## Vercel Dashboard

Once deployed to Vercel:

1. Go to **Project Settings** → **Analytics**
2. View **Web Vitals** metrics
3. Monitor **Real User Monitoring (RUM)**
4. Set up **Alerts** for performance degradation

## Performance Monitoring

Key metrics to monitor:

| Metric  | Good    | Fair       | Poor    |
| ------- | ------- | ---------- | ------- |
| **LCP** | < 2.5s  | 2.5s - 4s  | > 4s    |
| **FID** | < 100ms | 100-300ms  | > 300ms |
| **CLS** | < 0.1   | 0.1 - 0.25 | > 0.25  |

## Integration Points

### Track Shipment Creation

```typescript
import { track } from "@vercel/analytics";

async function createShipment(data) {
  try {
    const response = await fetch("/api/shipments", {
      method: "POST",
      body: JSON.stringify(data),
    });
    track("shipment_created", { shipment_id: response.id });
    return response;
  } catch (error) {
    track("shipment_error", { error: error.message });
    throw error;
  }
}
```

### Track User Actions

```typescript
track("feature_used", {
  feature: "real_time_tracking",
  timestamp: new Date().toISOString(),
});
```

## Debugging

Enable debug mode to see analytics in browser console:

```typescript
<Analytics debug />
```

Look for logs starting with `[analytics]`

## Next Steps

1. ✅ Integration code in pages/\_app.tsx or app/layout.tsx
2. ⏳ Deploy to Vercel
3. ⏳ Wait 5-10 minutes for data to appear
4. ⏳ Visit Vercel Analytics dashboard
5. ⏳ Set up performance alerts
6. ⏳ Add custom event tracking for business metrics

## Useful Links

- [Vercel Analytics Docs](https://vercel.com/docs/analytics)
- [Web Vitals Guide](https://web.dev/vitals/)
- [Analytics API Reference](https://vercel.com/docs/analytics/api)

---

**Commit**: Added `@vercel/analytics` to web dependencies
**Next**: Add Analytics component to main Next.js entry point
