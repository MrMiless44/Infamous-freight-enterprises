/**
 * Web Vitals & Real User Monitoring
 * Tracks Core Web Vitals: LCP, FID, CLS
 */

import { useEffect } from "react";

export interface WebVitalMetric {
  metric: "LCP" | "FID" | "CLS" | "TTFB" | "INP";
  value: number;
  rating: "good" | "needs-improvement" | "poor";
  id: string;
  navigationType: string;
  delta: number;
  attribution?: any;
}

/**
 * Send metric to analytics
 */
function sendMetricToAnalytics(metric: WebVitalMetric): void {
  // Send to Datadog RUM or custom analytics endpoint
  if ((window as any).datadog) {
    (window as any).datadog.rum?.addAction("Web Vital", {
      metric: metric.metric,
      value: metric.value,
      rating: metric.rating,
    });
  }

  // Send to custom analytics endpoint
  if (process.env.NEXT_PUBLIC_ENV === "production") {
    const endpoint =
      process.env.NEXT_PUBLIC_ANALYTICS_ENDPOINT || "/api/metrics/web-vitals";
    navigator.sendBeacon(
      endpoint,
      JSON.stringify({
        metric: metric.metric,
        value: metric.value,
        rating: metric.rating,
        timestamp: new Date().toISOString(),
        page: window.location.pathname,
      }),
    );
  }
}

/**
 * Hook to track Web Vitals
 */
export function useWebVitals(): void {
  useEffect(() => {
    // Only run in browsers that support Web Vitals API
    if (!("PerformanceObserver" in window)) {
      return;
    }

    try {
      // Largest Contentful Paint (LCP)
      if ("PerformanceObserver" in window) {
        const lcpObserver = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const lastEntry = entries[entries.length - 1];

          const entryAny: any = lastEntry as any;
          const metric: WebVitalMetric = {
            metric: "LCP",
            value: entryAny.renderTime || entryAny.loadTime || 0,
            rating: entryAny.startTime < 2500 ? "good" : "poor",
            id: `lcp-${lastEntry.startTime}`,
            navigationType: "navigation",
            delta: 0,
          };

          sendMetricToAnalytics(metric);
        });

        lcpObserver.observe({ entryTypes: ["largest-contentful-paint"] });
      }

      // Cumulative Layout Shift (CLS)
      if ("PerformanceObserver" in window) {
        let cls = 0;
        const clsObserver = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (!(entry as any).hadRecentInput) {
              cls += (entry as any).value;

              const metric: WebVitalMetric = {
                metric: "CLS",
                value: cls,
                rating:
                  cls < 0.1
                    ? "good"
                    : cls < 0.25
                      ? "needs-improvement"
                      : "poor",
                id: `cls-${entry.startTime}`,
                navigationType: "navigation",
                delta: (entry as any).value,
              };

              sendMetricToAnalytics(metric);
            }
          }
        });

        clsObserver.observe({ entryTypes: ["layout-shift"] });
      }

      // First Input Delay (FID) / Interaction to Next Paint (INP)
      if ("PerformanceObserver" in window) {
        const fidObserver = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            const metric: WebVitalMetric = {
              metric: (entry as any).interactionId ? "INP" : "FID",
              value: (entry as any).processingDuration || 0,
              rating: (entry as any).processingDuration < 100 ? "good" : "poor",
              id: `fid-${entry.startTime}`,
              navigationType: "navigation",
              delta: (entry as any).processingDuration || 0,
            };

            sendMetricToAnalytics(metric);
          }
        });

        fidObserver.observe({
          entryTypes: ["first-input", "interaction-to-next-paint"],
        });
      }
    } catch (error) {
      console.error("Error initializing Web Vitals tracking:", error);
    }
  }, []);
}

/**
 * Report Web Vitals via web-vitals library (alternative)
 */
export function reportWebVitals(metric: any): void {
  sendMetricToAnalytics({
    metric: metric.name,
    value: metric.value,
    rating: metric.rating || "good",
    id: metric.id,
    navigationType: metric.navigationType,
    delta: metric.delta,
    attribution: metric.attribution,
  });
}

export default useWebVitals;
