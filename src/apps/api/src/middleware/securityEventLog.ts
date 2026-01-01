/**
 * Security Event Logging and SIEM Integration
 * Logs security-relevant events for monitoring and compliance
 */

import { Request, Response, NextFunction } from "express";
import winston from "winston";
import * as Sentry from "@sentry/node";

// Initialize security logger
const securityLogger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.metadata(),
  ),
  defaultMeta: { service: "security" },
  transports: [
    // File transport for security events
    new winston.transports.File({
      filename: "logs/security.log",
      level: "info",
    }),
    // Separate error log
    new winston.transports.File({
      filename: "logs/security-errors.log",
      level: "error",
    }),
  ],
});

// Console output in development
if (process.env.NODE_ENV !== "production") {
  securityLogger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    }),
  );
}

/**
 * Event types for security monitoring
 */
export enum SecurityEventType {
  // Authentication events
  AUTH_SUCCESS = "auth.success",
  AUTH_FAILURE = "auth.failure",
  AUTH_TIMEOUT = "auth.timeout",
  INVALID_TOKEN = "auth.invalid_token",
  TOKEN_EXPIRED = "auth.token_expired",

  // Authorization events
  UNAUTHORIZED_ACCESS = "authz.unauthorized",
  INSUFFICIENT_SCOPE = "authz.insufficient_scope",
  PERMISSION_DENIED = "authz.permission_denied",

  // Rate limiting
  RATE_LIMIT_EXCEEDED = "ratelimit.exceeded",
  RATE_LIMIT_RESET = "ratelimit.reset",

  // Data access
  SENSITIVE_DATA_ACCESS = "data.sensitive_access",
  DATA_MODIFICATION = "data.modification",
  DATA_DELETION = "data.deletion",

  // Anomalies
  SUSPICIOUS_ACTIVITY = "anomaly.suspicious",
  ACCOUNT_LOCKOUT = "anomaly.lockout",
  BRUTE_FORCE_ATTEMPT = "anomaly.brute_force",

  // Administrative
  ADMIN_ACTION = "admin.action",
  CONFIG_CHANGE = "admin.config_change",
  PERMISSION_CHANGE = "admin.permission_change",

  // Encryption
  ENCRYPTION_FAILURE = "crypto.failure",
  KEY_ROTATION = "crypto.key_rotation",

  // External
  THIRD_PARTY_ACCESS = "external.access",
  API_KEY_USED = "external.api_key",

  // Compliance
  AUDIT_LOG_CREATED = "compliance.audit_log",
  PII_ACCESSED = "compliance.pii_accessed",
}

/**
 * Log a security event
 */
export function logSecurityEvent(
  eventType: SecurityEventType,
  data: Record<string, any>,
): void {
  const enrichedData = {
    eventType,
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV,
    ...data,
  };

  // Determine log level
  const level = determineLogLevel(eventType);

  securityLogger.log(level, `Security Event: ${eventType}`, enrichedData);

  // Send to SIEM if configured
  if (process.env.SIEM_ENABLED === "true") {
    sendToSIEM(enrichedData);
  }

  // Send critical events to Sentry
  if (level === "error" || level === "warn") {
    Sentry.captureMessage(`Security Event: ${eventType}`, "warning");
  }
}

/**
 * Middleware to log HTTP requests with security context
 */
export function securityEventMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  // Add request start time
  const startTime = Date.now();

  // Capture original send
  const originalSend = res.send;

  // Log on response
  res.send = function (data: any) {
    const duration = Date.now() - startTime;
    const statusCode = res.statusCode;

    // Log security-relevant status codes
    if (statusCode === 401 || statusCode === 403) {
      logSecurityEvent(
        statusCode === 401
          ? SecurityEventType.AUTH_FAILURE
          : SecurityEventType.UNAUTHORIZED_ACCESS,
        {
          method: req.method,
          path: req.path,
          statusCode,
          userId: req.user?.sub,
          ip: req.ip,
          userAgent: req.get("user-agent"),
          duration,
        },
      );
    }

    // Log successful authentication
    if (req.path.includes("/auth") && statusCode === 200) {
      logSecurityEvent(SecurityEventType.AUTH_SUCCESS, {
        method: req.method,
        path: req.path,
        userId: req.user?.sub,
        ip: req.ip,
      });
    }

    // Call original send
    return originalSend.call(this, data);
  };

  next();
}

/**
 * Middleware to log suspicious activity
 */
export function suspiciousActivityDetection(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  // SQL injection patterns
  const sqlPatterns = /(\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b)/i;

  // Check query parameters and body for suspicious patterns
  const checkInput = (input: string): boolean => {
    return sqlPatterns.test(input);
  };

  // Check all inputs
  const allInputs = [
    ...Object.values(req.query || {}),
    ...Object.values(req.body || {}),
  ].map(String);

  for (const input of allInputs) {
    if (checkInput(input)) {
      logSecurityEvent(SecurityEventType.SUSPICIOUS_ACTIVITY, {
        method: req.method,
        path: req.path,
        userId: req.user?.sub,
        ip: req.ip,
        suspiciousPattern: "SQL injection attempt",
      });

      return res.status(400).json({ error: "Invalid input" });
    }
  }

  next();
}

/**
 * Log PII access for compliance (GDPR, CCPA, etc.)
 */
export function logPIIAccess(
  userId: string,
  action: "read" | "update" | "delete",
  dataType: string,
  recordId: string,
): void {
  logSecurityEvent(SecurityEventType.PII_ACCESSED, {
    userId,
    action,
    dataType,
    recordId,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Log administrative actions
 */
export function logAdminAction(
  adminId: string,
  action: string,
  targetUserId: string,
  details: Record<string, any>,
): void {
  logSecurityEvent(SecurityEventType.ADMIN_ACTION, {
    adminId,
    action,
    targetUserId,
    details,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Track failed login attempts and detect brute force
 */
const loginAttempts = new Map<string, { count: number; lastAttempt: number }>();
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_WINDOW = 15 * 60 * 1000; // 15 minutes

export function trackFailedLogin(identifier: string): boolean {
  const now = Date.now();
  const attempt = loginAttempts.get(identifier) || {
    count: 0,
    lastAttempt: now,
  };

  // Reset if outside lockout window
  if (now - attempt.lastAttempt > LOCKOUT_WINDOW) {
    loginAttempts.set(identifier, { count: 1, lastAttempt: now });
    return false;
  }

  attempt.count++;
  attempt.lastAttempt = now;
  loginAttempts.set(identifier, attempt);

  if (attempt.count >= LOCKOUT_THRESHOLD) {
    logSecurityEvent(SecurityEventType.ACCOUNT_LOCKOUT, {
      identifier,
      attemptCount: attempt.count,
    });
    return true; // Account locked
  }

  if (attempt.count > 2) {
    logSecurityEvent(SecurityEventType.BRUTE_FORCE_ATTEMPT, {
      identifier,
      attemptCount: attempt.count,
    });
  }

  return false;
}

/**
 * Reset failed login attempts after successful auth
 */
export function resetFailedLogins(identifier: string): void {
  loginAttempts.delete(identifier);
}

/**
 * Determine appropriate log level based on event type
 */
function determineLogLevel(eventType: SecurityEventType): string {
  const criticalEvents = [
    SecurityEventType.BRUTE_FORCE_ATTEMPT,
    SecurityEventType.ACCOUNT_LOCKOUT,
    SecurityEventType.UNAUTHORIZED_ACCESS,
    SecurityEventType.DATA_DELETION,
    SecurityEventType.CONFIG_CHANGE,
    SecurityEventType.ENCRYPTION_FAILURE,
  ];

  return criticalEvents.includes(eventType) ? "error" : "warn";
}

/**
 * Send event to SIEM (Datadog, Splunk, etc.)
 */
async function sendToSIEM(event: Record<string, any>): Promise<void> {
  try {
    const siemEndpoint = process.env.SIEM_ENDPOINT;
    if (!siemEndpoint) return;

    const response = await fetch(siemEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.SIEM_API_KEY}`,
      },
      body: JSON.stringify(event),
    });

    if (!response.ok) {
      console.error(`SIEM integration failed: ${response.statusText}`);
    }
  } catch (error) {
    console.error("Error sending to SIEM:", error);
  }
}

/**
 * Export logger for direct use
 */
export { securityLogger };

/**
 * Usage example:
 *
 * // In middleware
 * app.use(securityEventMiddleware);
 * app.use(suspiciousActivityDetection);
 *
 * // In auth route
 * try {
 *   const user = await authenticate(credentials);
 *   resetFailedLogins(email);
 *   logSecurityEvent(SecurityEventType.AUTH_SUCCESS, { userId: user.id });
 * } catch (error) {
 *   const isLocked = trackFailedLogin(email);
 *   if (isLocked) {
 *     logSecurityEvent(SecurityEventType.ACCOUNT_LOCKOUT, { email });
 *   }
 * }
 *
 * // For PII access
 * logPIIAccess(req.user.id, 'read', 'shipment', shipmentId);
 */
