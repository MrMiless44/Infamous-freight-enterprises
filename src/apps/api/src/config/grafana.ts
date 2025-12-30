/**
 * Grafana Dashboard Configuration
 * Configures Prometheus data source and dashboard for monitoring
 */

export const grafanaConfig = {
  prometheusDataSource: {
    name: "Prometheus",
    type: "prometheus",
    url: process.env.PROMETHEUS_URL || "http://localhost:9090",
    access: "proxy",
    isDefault: true,
  },

  dashboards: {
    system: {
      title: "System Health Dashboard",
      panels: [
        {
          title: "CPU Usage",
          targets: [{ expr: "rate(process_cpu_seconds_total[1m]) * 100" }],
        },
        {
          title: "Memory Usage",
          targets: [{ expr: "process_resident_memory_bytes / 1024 / 1024" }],
        },
        {
          title: "Uptime",
          targets: [{ expr: "process_uptime_seconds / 3600" }],
        },
      ],
    },

    api: {
      title: "API Performance Dashboard",
      panels: [
        {
          title: "Request Rate (req/s)",
          targets: [{ expr: "rate(http_requests_total[1m])" }],
        },
        {
          title: "Response Time (p95)",
          targets: [
            {
              expr: "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            },
          ],
        },
        {
          title: "Error Rate",
          targets: [{ expr: 'rate(http_requests_total{status=~"5.."}[1m])' }],
        },
        {
          title: "Active Connections",
          targets: [{ expr: "http_requests_in_flight" }],
        },
      ],
    },

    websocket: {
      title: "WebSocket Real-time Dashboard",
      panels: [
        {
          title: "Connected Clients",
          targets: [{ expr: "websocket_connections_active" }],
        },
        {
          title: "Messages per Second",
          targets: [{ expr: "rate(websocket_messages_total[1m])" }],
        },
        {
          title: "Connection Latency (ms)",
          targets: [{ expr: "websocket_connection_latency_ms" }],
        },
      ],
    },

    cache: {
      title: "Cache Performance Dashboard",
      panels: [
        {
          title: "Cache Hit Rate",
          targets: [{ expr: "cache_hit_ratio" }],
        },
        {
          title: "Cache Size (MB)",
          targets: [{ expr: "cache_size_bytes / 1024 / 1024" }],
        },
        {
          title: "Redis Commands/sec",
          targets: [{ expr: "rate(redis_commands_total[1m])" }],
        },
      ],
    },

    alerts: {
      title: "Alerts & Incidents",
      rules: [
        {
          name: "HighErrorRate",
          expr: 'rate(http_requests_total{status=~"5.."}[5m]) > 0.05',
          for: "5m",
          severity: "critical",
        },
        {
          name: "HighLatency",
          expr: "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1",
          for: "5m",
          severity: "warning",
        },
        {
          name: "HighMemoryUsage",
          expr: "process_resident_memory_bytes / 1024 / 1024 > 1024",
          for: "2m",
          severity: "warning",
        },
        {
          name: "WebSocketConnectionDrop",
          expr: "rate(websocket_disconnections_total[1m]) > 10",
          for: "2m",
          severity: "warning",
        },
      ],
    },
  },
};

export const alertingConfig = {
  // Webhook endpoints for alert notifications
  webhooks: [
    {
      name: "slack",
      url: process.env.SLACK_WEBHOOK_URL,
      enabled: !!process.env.SLACK_WEBHOOK_URL,
    },
    {
      name: "pagerduty",
      url: process.env.PAGERDUTY_WEBHOOK_URL,
      enabled: !!process.env.PAGERDUTY_WEBHOOK_URL,
    },
    {
      name: "email",
      url: process.env.EMAIL_ALERT_ENDPOINT,
      enabled: !!process.env.EMAIL_ALERT_ENDPOINT,
    },
  ],

  // Alert routing rules
  routes: {
    critical: {
      channels: ["slack", "pagerduty", "email"],
      throttle: "5m",
    },
    warning: {
      channels: ["slack"],
      throttle: "30m",
    },
    info: {
      channels: ["email"],
      throttle: "1h",
    },
  },
};
