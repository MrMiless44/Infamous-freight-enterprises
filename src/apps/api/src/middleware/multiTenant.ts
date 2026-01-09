/**
 * Multi-Tenant Architecture Middleware
 * Support multiple freight companies on single platform
 * Tenant isolation at database level
 */

import { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import { GraphQLError } from "graphql";
import { prisma } from "../db/prisma";

/**
 * Tenant context
 */
export interface TenantContext {
  tenantId: string;
  tenantName: string;
  plan: "free" | "pro" | "enterprise";
  features: string[];
  limits: {
    maxUsers: number;
    maxShipments: number;
    maxDrivers: number;
    maxStorage: number; // GB
  };
}

/**
 * Tenant-aware Prisma client
 */
export class TenantPrismaClient extends PrismaClient {
  constructor(private tenantId: string) {
    super();

    // Add tenant filter to all queries
    this.$use(async (params, next) => {
      // Add tenantId to all where clauses
      if (params.action === "findUnique" || params.action === "findFirst") {
        params.args.where = { ...params.args.where, tenantId: this.tenantId };
      }

      if (params.action === "findMany") {
        if (params.args.where) {
          params.args.where = { ...params.args.where, tenantId: this.tenantId };
        } else {
          params.args.where = { tenantId: this.tenantId };
        }
      }

      // Add tenantId to all creates
      if (params.action === "create") {
        params.args.data = { ...params.args.data, tenantId: this.tenantId };
      }

      if (params.action === "createMany") {
        params.args.data = params.args.data.map((item: any) => ({
          ...item,
          tenantId: this.tenantId,
        }));
      }

      // Add tenantId filter to updates and deletes
      if (params.action === "update" || params.action === "delete") {
        params.args.where = { ...params.args.where, tenantId: this.tenantId };
      }

      if (params.action === "updateMany" || params.action === "deleteMany") {
        if (params.args.where) {
          params.args.where = { ...params.args.where, tenantId: this.tenantId };
        } else {
          params.args.where = { tenantId: this.tenantId };
        }
      }

      return next(params);
    });
  }
}

/**
 * Tenant cache (in-memory, use Redis in production)
 */
const tenantCache = new Map<string, TenantContext>();

/**
 * Get tenant from subdomain
 */
function getTenantFromHost(host: string): string | null {
  // Example: acme.infamousfreight.com -> acme
  const match = host.match(/^([a-z0-9-]+)\.infamousfreight\.com$/);
  return match ? match[1] : null;
}

/**
 * Get tenant from custom domain
 */
async function getTenantFromCustomDomain(
  host: string,
  prisma: PrismaClient,
): Promise<string | null> {
  const tenant = await prisma.tenant.findUnique({
    where: { customDomain: host },
  });
  return tenant?.id || null;
}

/**
 * Load tenant configuration
 */
async function loadTenantConfig(
  tenantId: string,
  prisma: PrismaClient,
): Promise<TenantContext | null> {
  // Check cache
  if (tenantCache.has(tenantId)) {
    return tenantCache.get(tenantId)!;
  }

  // Load from database
  const tenant = await prisma.tenant.findUnique({
    where: { id: tenantId },
    include: {
      plan: true,
      features: true,
    },
  });

  if (!tenant) return null;

  const context: TenantContext = {
    tenantId: tenant.id,
    tenantName: tenant.name,
    plan: tenant.plan.tier as "free" | "pro" | "enterprise",
    features: tenant.features.map((f) => f.name),
    limits: {
      maxUsers: tenant.plan.maxUsers,
      maxShipments: tenant.plan.maxShipments,
      maxDrivers: tenant.plan.maxDrivers,
      maxStorage: tenant.plan.maxStorage,
    },
  };

  // Cache for 5 minutes
  tenantCache.set(tenantId, context);
  setTimeout(() => tenantCache.delete(tenantId), 5 * 60 * 1000);

  return context;
}

/**
 * Multi-tenant middleware for Express
 */
export function multiTenantMiddleware(prisma: PrismaClient) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const host = req.hostname;

      // Extract tenant ID from subdomain or custom domain
      let tenantId = getTenantFromHost(host);

      if (!tenantId) {
        tenantId = await getTenantFromCustomDomain(host, prisma);
      }

      // Fallback to header (for API calls without domain)
      if (!tenantId) {
        tenantId = req.headers["x-tenant-id"] as string;
      }

      if (!tenantId) {
        return res.status(400).json({
          success: false,
          error: "Tenant not specified",
          hint: "Use subdomain (acme.infamousfreight.com) or X-Tenant-Id header",
        });
      }

      // Load tenant configuration
      const tenantContext = await loadTenantConfig(tenantId, prisma);

      if (!tenantContext) {
        return res.status(404).json({
          success: false,
          error: "Tenant not found",
        });
      }

      // Check if tenant is active
      const tenant = await prisma.tenant.findUnique({
        where: { id: tenantId },
      });

      if (!tenant?.active) {
        return res.status(403).json({
          success: false,
          error: "Tenant account is suspended",
        });
      }

      // Attach tenant context to request
      req.tenant = tenantContext;

      // Create tenant-specific Prisma client
      req.tenantPrisma = new TenantPrismaClient(tenantId);

      next();
    } catch (error) {
      console.error("Multi-tenant middleware error:", error);
      res.status(500).json({
        success: false,
        error: "Tenant resolution failed",
      });
    }
  };
}

/**
 * Feature gate middleware
 */
export function requireFeature(featureName: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.header("x-user-id");
    if (!userId) {
      return res
        .status(401)
        .json({ error: "Missing x-user-id (replace with real auth)" });
    }

    const ent = await prisma.subscriptionEntitlement.findUnique({
      where: { userId },
    });
    if (!ent || ent.status !== "active") {
      return res.status(403).json({ error: "Subscription not active" });
    }

    const features = ent.featuresJson as Record<string, boolean> | null;
    if (!features?.[featureName]) {
      return res
        .status(403)
        .json({ error: `Missing entitlement: ${featureName}` });
    }

    return next();
  };
}

/**
 * Usage limit middleware
 */
export function checkUsageLimit(
  resource: "users" | "shipments" | "drivers" | "storage",
) {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.tenant || !req.tenantPrisma) {
      return res.status(400).json({
        success: false,
        error: "Tenant context not found",
      });
    }

    const prisma = req.tenantPrisma;
    const limits = req.tenant.limits;

    let currentUsage = 0;
    let limit = 0;

    switch (resource) {
      case "users":
        currentUsage = await prisma.user.count();
        limit = limits.maxUsers;
        break;
      case "shipments":
        currentUsage = await prisma.shipment.count();
        limit = limits.maxShipments;
        break;
      case "drivers":
        currentUsage = await prisma.driver.count();
        limit = limits.maxDrivers;
        break;
      case "storage":
        // Calculate total storage usage
        const storage = await prisma.$queryRaw<{ total: bigint }[]>`
          SELECT SUM(size) as total FROM documents WHERE tenantId = ${req.tenant.tenantId}
        `;
        currentUsage = Number(storage[0]?.total || 0) / (1024 * 1024 * 1024); // Convert to GB
        limit = limits.maxStorage;
        break;
    }

    if (currentUsage >= limit) {
      return res.status(403).json({
        success: false,
        error: `${resource} limit reached`,
        currentUsage,
        limit,
        upgrade: true,
        upgradeUrl: "/settings/upgrade",
      });
    }

    next();
  };
}

/**
 * GraphQL context with tenant
 */
export async function createTenantContext({ req }: { req: Request }) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const tenantId = req.headers["x-tenant-id"] as string;

  if (!tenantId) {
    throw new GraphQLError("Tenant ID required", {
      extensions: { code: "TENANT_REQUIRED" },
    });
  }

  const prisma = new PrismaClient();
  const tenantContext = await loadTenantConfig(tenantId, prisma);

  if (!tenantContext) {
    throw new GraphQLError("Tenant not found", {
      extensions: { code: "TENANT_NOT_FOUND" },
    });
  }

  // Create tenant-specific Prisma client
  const tenantPrisma = new TenantPrismaClient(tenantId);

  return {
    tenant: tenantContext,
    prisma: tenantPrisma,
    // ... decode JWT token for user
  };
}

/**
 * Tenant onboarding
 */
export async function createTenant(
  name: string,
  subdomain: string,
  ownerEmail: string,
  plan: "free" | "pro" | "enterprise" = "free",
): Promise<{ tenantId: string; apiKey: string }> {
  const prisma = new PrismaClient();

  // Check subdomain availability
  const existing = await prisma.tenant.findUnique({
    where: { subdomain },
  });

  if (existing) {
    throw new Error("Subdomain already taken");
  }

  // Get plan details
  const planDetails = await prisma.plan.findUnique({
    where: { tier: plan },
  });

  if (!planDetails) {
    throw new Error("Invalid plan");
  }

  // Create tenant
  const tenant = await prisma.tenant.create({
    data: {
      name,
      subdomain,
      planId: planDetails.id,
      active: true,
    },
  });

  // Create owner user
  const owner = await prisma.user.create({
    data: {
      email: ownerEmail,
      role: "admin",
      tenantId: tenant.id,
    },
  });

  // Generate API key
  const apiKey = `ift_${tenant.id}_${Math.random().toString(36).substring(2, 15)}`;

  await prisma.apiKey.create({
    data: {
      key: apiKey,
      tenantId: tenant.id,
      userId: owner.id,
    },
  });

  return {
    tenantId: tenant.id,
    apiKey,
  };
}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      tenant?: TenantContext;
      tenantPrisma?: TenantPrismaClient;
    }
  }
}

export default multiTenantMiddleware;

/**
 * Usage:
 *
 * // In main.ts
 * import multiTenantMiddleware, { requireFeature, checkUsageLimit } from './middleware/multiTenant';
 *
 * app.use(multiTenantMiddleware(prisma));
 *
 * // Feature-gated endpoint
 * app.post('/api/ai/advanced',
 *   requireFeature('ai-advanced'),
 *   async (req, res) => {
 *     // Only available on Pro/Enterprise plans
 *   }
 * );
 *
 * // Usage-limited endpoint
 * app.post('/api/shipments',
 *   checkUsageLimit('shipments'),
 *   async (req, res) => {
 *     // Will reject if shipment limit reached
 *   }
 * );
 *
 * // Access tenant-specific data
 * app.get('/api/shipments', async (req, res) => {
 *   const shipments = await req.tenantPrisma!.shipment.findMany();
 *   // Automatically filtered by tenantId
 *   res.json(shipments);
 * });
 *
 * Database schema additions:
 *
 * model Tenant {
 *   id            String   @id @default(uuid())
 *   name          String
 *   subdomain     String   @unique
 *   customDomain  String?  @unique
 *   planId        String
 *   plan          Plan     @relation(fields: [planId], references: [id])
 *   active        Boolean  @default(true)
 *   createdAt     DateTime @default(now())
 *   users         User[]
 *   shipments     Shipment[]
 * }
 *
 * model Plan {
 *   id            String   @id @default(uuid())
 *   tier          String   @unique // free, pro, enterprise
 *   maxUsers      Int
 *   maxShipments  Int
 *   maxDrivers    Int
 *   maxStorage    Int      // GB
 *   price         Float
 *   tenants       Tenant[]
 * }
 *
 * // Add to existing models:
 * tenantId      String
 * tenant        Tenant   @relation(fields: [tenantId], references: [id])
 *
 * Benefits:
 * - Single codebase for all customers
 * - Data isolation per tenant
 * - Feature gating by plan
 * - Usage limits enforcement
 * - Easy onboarding
 * - Scalable architecture
 */
