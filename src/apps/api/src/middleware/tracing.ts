/**
 * OpenTelemetry Distributed Tracing
 * Traces requests across API → Database → AI services
 * Helps identify bottlenecks and slow queries
 */

import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { registerInstrumentations } from "@opentelemetry/instrumentation";
import { HttpInstrumentation } from "@opentelemetry/instrumentation-http";
import { ExpressInstrumentation } from "@opentelemetry/instrumentation-express";
import { PrismaInstrumentation } from "@prisma/instrumentation";
import { Resource } from "@opentelemetry/resources";
import { SemanticResourceAttributes } from "@opentelemetry/semantic-conventions";
import { BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import type { Express } from "express";

/**
 * Initialize OpenTelemetry tracing
 */
export function initializeTracing(
  serviceName: string = "infamous-freight-api",
): NodeTracerProvider {
  // Create resource with service information
  const resource = Resource.default().merge(
    new Resource({
      [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
      [SemanticResourceAttributes.SERVICE_VERSION]:
        process.env.npm_package_version || "2.0.0",
      [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]:
        process.env.NODE_ENV || "development",
    }),
  );

  // Create tracer provider
  const provider = new NodeTracerProvider({
    resource,
  });

  // Configure exporter (exports to OTLP-compatible backend)
  const otlpEndpoint =
    process.env.OTEL_EXPORTER_OTLP_ENDPOINT ||
    "http://localhost:4318/v1/traces";

  const exporter = new OTLPTraceExporter({
    url: otlpEndpoint,
    headers: process.env.OTEL_EXPORTER_OTLP_HEADERS
      ? JSON.parse(process.env.OTEL_EXPORTER_OTLP_HEADERS)
      : {},
  });

  // Add span processor
  provider.addSpanProcessor(new BatchSpanProcessor(exporter));

  // Register the provider
  provider.register();

  // Auto-instrument common libraries
  registerInstrumentations({
    instrumentations: [
      new HttpInstrumentation({
        // Don't trace health checks
        ignoreIncomingRequestHook: (req) => {
          return req.url === "/api/health" || req.url === "/metrics";
        },
      }),
      new ExpressInstrumentation({
        // Add custom attributes
        requestHook: (span, request: any) => {
          span.setAttribute("http.user_id", request.user?.sub || "anonymous");
          span.setAttribute("http.user_role", request.user?.role || "none");
        },
      }),
      new PrismaInstrumentation(),
    ],
  });

  console.log(
    `✅ OpenTelemetry tracing initialized (endpoint: ${otlpEndpoint})`,
  );

  return provider;
}

/**
 * Middleware to add custom tracing attributes
 */
export function tracingMiddleware(serviceName: string) {
  return (req: any, res: any, next: any) => {
    // Add custom attributes to current span
    const { trace } = require("@opentelemetry/api");
    const span = trace.getActiveSpan();

    if (span) {
      span.setAttribute("http.route", req.route?.path || req.path);
      span.setAttribute("http.query_params", JSON.stringify(req.query));

      if (req.user) {
        span.setAttribute("user.id", req.user.sub);
        span.setAttribute("user.role", req.user.role);
      }
    }

    next();
  };
}

/**
 * Create custom span for business logic
 */
export function createSpan(name: string, attributes?: Record<string, any>) {
  const { trace } = require("@opentelemetry/api");
  const tracer = trace.getTracer("infamous-freight");

  return tracer.startSpan(name, {
    attributes: attributes || {},
  });
}

/**
 * Shutdown tracing gracefully
 */
export async function shutdownTracing(
  provider: NodeTracerProvider,
): Promise<void> {
  try {
    await provider.shutdown();
    console.log("✅ OpenTelemetry tracing shutdown complete");
  } catch (error) {
    console.error("Error shutting down tracing:", error);
  }
}

export default {
  initializeTracing,
  tracingMiddleware,
  createSpan,
  shutdownTracing,
};
