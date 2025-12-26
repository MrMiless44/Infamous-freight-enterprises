/**
 * Web Vitals Monitoring and Reporting
 * Tracks Core Web Vitals and sends to analytics
 */

export const reportWebVitals = (metric) => {
  // Log to console in development
  if (process.env.NODE_ENV === "development") {
    console.warn("📊 Web Vital:", metric);
  }

  // Send to Vercel Analytics
  if (typeof window !== "undefined" && window.gtag) {
    window.gtag("event", metric.name, {
      value: Math.round(metric.value),
      event_category: "Web Vitals",
      event_label: metric.id,
      non_interaction: true,
    });
  }

  // Send to Datadog RUM if available
  if (typeof window !== "undefined" && window.dd_rum) {
    const metricValue = Math.round(metric.value);
    window.dd_rum.addAction(`Web Vital: ${metric.name}`, {
      metric_value: metricValue,
      metric_name: metric.name,
      metric_id: metric.id,
    });
  }

  // Log critical metrics that need attention
  const THRESHOLDS = {
    LCP: 2500, // Largest Contentful Paint
    FID: 100, // First Input Delay
    CLS: 0.1, // Cumulative Layout Shift
    TTFB: 600, // Time to First Byte
    FCP: 1800, // First Contentful Paint
  };

  if (metric.value > (THRESHOLDS[metric.name] || Infinity)) {
    console.warn(`⚠️  ${metric.name} exceeded threshold: ${metric.value}ms`);
  }
};

/**
 * Track which elements cause Cumulative Layout Shift
 */
export const trackCLS = () => {
  if (typeof window === "undefined") return;

  const observer = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      if (!entry.hadRecentInput) {
        console.warn("🔄 Layout Shift:", {
          value: entry.value,
          source: entry.sources?.[0]?.node,
        });
      }
    }
  });

  try {
    observer.observe({ entryTypes: ["layout-shift"] });
  } catch {
    console.warn("PerformanceObserver not supported");
  }
};

/**
 * Monitor Long Tasks that block main thread
 */
export const trackLongTasks = () => {
  if (typeof window === "undefined") return;

  const observer = new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) {
      console.warn("⏱️ Long Task Detected:", {
        duration: entry.duration,
        startTime: entry.startTime,
        name: entry.name,
      });
    }
  });

  try {
    observer.observe({ entryTypes: ["longtask"] });
  } catch {
    // Long Task API not available
  }
};
