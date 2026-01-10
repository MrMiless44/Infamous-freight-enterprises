/**
 * Enhanced Audit Logging Service
 * Tracks all significant actions with detailed context
 */

import { Request } from "express";
import prisma from "../lib/prismaClient";
import { logger } from "../middleware/logger";

export enum AuditEventType {
  // Authentication events
  USER_LOGIN = "user:login",
  USER_LOGOUT = "user:logout",
  USER_REGISTER = "user:register",
  USER_PASSWORD_CHANGE = "user:password_change",
  USER_PASSWORD_RESET = "user:password_reset",
  USER_2FA_ENABLE = "user:2fa_enable",
  USER_2FA_DISABLE = "user:2fa_disable",

  // Shipment events
  SHIPMENT_CREATE = "shipment:create",
  SHIPMENT_UPDATE = "shipment:update",
  SHIPMENT_CANCEL = "shipment:cancel",
  SHIPMENT_COMPLETE = "shipment:complete",
  SHIPMENT_ASSIGN_DRIVER = "shipment:assign_driver",

  // Driver events
  DRIVER_CREATE = "driver:create",
  DRIVER_UPDATE = "driver:update",
  DRIVER_DEACTIVATE = "driver:deactivate",
  DRIVER_ACTIVATE = "driver:activate",

  // Billing events
  PAYMENT_PROCESS = "payment:process",
  PAYMENT_REFUND = "payment:refund",
  INVOICE_CREATE = "invoice:create",
  INVOICE_SEND = "invoice:send",
  SUBSCRIPTION_CREATE = "subscription:create",
  SUBSCRIPTION_CANCEL = "subscription:cancel",

  // Admin events
  ADMIN_USER_MANAGE = "admin:user_manage",
  ADMIN_SYSTEM_CONFIG = "admin:system_config",
  ADMIN_DATA_EXPORT = "admin:data_export",
  ADMIN_DATA_DELETE = "admin:data_delete",

  // Security events
  SECURITY_BREACH = "security:breach",
  SECURITY_SUSPICIOUS_ACTIVITY = "security:suspicious_activity",
  SECURITY_RATE_LIMIT = "security:rate_limit",
  SECURITY_SQL_INJECTION = "security:sql_injection",
  SECURITY_XSS_ATTEMPT = "security:xss_attempt",
}

export interface AuditLogEntry {
  eventType: AuditEventType;
  userId?: string;
  resourceId?: string;
  resourceType?: string;
  action: string;
  details: Record<string, any>;
  ip?: string;
  userAgent?: string;
  status: "success" | "failure";
  errorMessage?: string;
  timestamp: Date;
}

/**
 * Enhanced Audit Logging Service
 */
export class AuditService {
  /**
   * Log an audit event
   */
  async logEvent(entry: AuditLogEntry): Promise<void> {
    try {
      // Log to database
      await prisma.auditLog.create({
        data: {
          eventType: entry.eventType,
          userId: entry.userId,
          resourceId: entry.resourceId,
          resourceType: entry.resourceType,
          action: entry.action,
          details: entry.details,
          ip: entry.ip,
          userAgent: entry.userAgent,
          status: entry.status,
          errorMessage: entry.errorMessage,
          createdAt: entry.timestamp || new Date(),
        },
      });

      // Log to file with sensitive data redacted
      const redactedDetails = this.redactSensitiveData(entry.details);
      logger.info(`Audit: ${entry.eventType}`, {
        userId: entry.userId,
        resourceId: entry.resourceId,
        action: entry.action,
        details: redactedDetails,
        status: entry.status,
        ip: entry.ip,
      });

      // Alert on critical events
      if (this.isCriticalEvent(entry.eventType)) {
        logger.warn(`CRITICAL AUDIT EVENT: ${entry.eventType}`, {
          userId: entry.userId,
          resourceId: entry.resourceId,
          details: redactedDetails,
          ip: entry.ip,
        });
      }
    } catch (err) {
      logger.error("Failed to log audit event", {
        error: (err as Error).message,
        eventType: entry.eventType,
      });
    }
  }

  /**
   * Log authentication event
   */
  async logAuthEvent(
    req: Request,
    eventType: AuditEventType,
    userId: string,
    status: "success" | "failure",
    details: Record<string, any> = {},
  ): Promise<void> {
    await this.logEvent({
      eventType,
      userId,
      action: eventType,
      details: { ...details, method: "password" }, // Hide actual password
      ip: req.ip,
      userAgent: req.get("user-agent"),
      status,
      timestamp: new Date(),
    });
  }

  /**
   * Log data modification event
   */
  async logDataEvent(
    req: Request,
    eventType: AuditEventType,
    resourceId: string,
    resourceType: string,
    before: any,
    after: any,
  ): Promise<void> {
    const changes = this.calculateChanges(before, after);

    await this.logEvent({
      eventType,
      userId: (req.user as any)?.sub,
      resourceId,
      resourceType,
      action: eventType,
      details: {
        changes,
        before: this.redactSensitiveData(before),
        after: this.redactSensitiveData(after),
      },
      ip: req.ip,
      userAgent: req.get("user-agent"),
      status: "success",
      timestamp: new Date(),
    });
  }

  /**
   * Log security event
   */
  async logSecurityEvent(
    req: Request,
    eventType: AuditEventType,
    details: Record<string, any>,
    severity: "low" | "medium" | "high" | "critical" = "medium",
  ): Promise<void> {
    await this.logEvent({
      eventType,
      userId: (req.user as any)?.sub,
      action: eventType,
      details: { ...details, severity },
      ip: req.ip,
      userAgent: req.get("user-agent"),
      status: "failure",
      timestamp: new Date(),
    });
  }

  /**
   * Get audit logs for user
   */
  async getUserAuditLogs(userId: string, limit: number = 50): Promise<any[]> {
    return prisma.auditLog.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
  }

  /**
   * Get audit logs for resource
   */
  async getResourceAuditLogs(
    resourceId: string,
    limit: number = 50,
  ): Promise<any[]> {
    return prisma.auditLog.findMany({
      where: { resourceId },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
  }

  /**
   * Get audit logs by event type
   */
  async getAuditLogsByEventType(
    eventType: AuditEventType,
    limit: number = 50,
  ): Promise<any[]> {
    return prisma.auditLog.findMany({
      where: { eventType },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
  }

  /**
   * Redact sensitive data from audit logs
   */
  private redactSensitiveData(data: any): any {
    if (!data) return data;

    const redacted = JSON.parse(JSON.stringify(data));
    const sensitiveFields = [
      "password",
      "token",
      "secret",
      "apiKey",
      "creditCard",
      "ssn",
      "phone",
    ];

    const redactKeys = (obj: any) => {
      for (const key in obj) {
        if (
          sensitiveFields.some((field) =>
            key.toLowerCase().includes(field.toLowerCase()),
          )
        ) {
          obj[key] = "***REDACTED***";
        } else if (typeof obj[key] === "object" && obj[key] !== null) {
          redactKeys(obj[key]);
        }
      }
    };

    redactKeys(redacted);
    return redacted;
  }

  /**
   * Calculate changes between two objects
   */
  private calculateChanges(before: any, after: any): Record<string, any> {
    const changes: Record<string, any> = {};

    for (const key in after) {
      if (before[key] !== after[key]) {
        changes[key] = { from: before[key], to: after[key] };
      }
    }

    return changes;
  }

  /**
   * Check if event is critical
   */
  private isCriticalEvent(eventType: AuditEventType): boolean {
    const criticalEvents = [
      AuditEventType.SECURITY_BREACH,
      AuditEventType.SECURITY_SQL_INJECTION,
      AuditEventType.ADMIN_DATA_DELETE,
      AuditEventType.USER_PASSWORD_CHANGE,
    ];

    return criticalEvents.includes(eventType);
  }
}

// Export singleton instance
export const auditService = new AuditService();
export default auditService;
