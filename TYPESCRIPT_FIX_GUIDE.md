# TypeScript Error Resolution Guide

## Overview

42 TypeScript errors identified in API package after implementing 10 new features.
These are fixable type safety issues that prevent compilation.

---

## Root Causes

### 1. **Missing Prisma Schema Models** (Highest Priority)

The new features reference Prisma models not defined in the schema:

- `Notification` model (notification.service.ts)
- `Message` model (websocket-events.ts)
- `Webhook` model (monitoring)

### 2. **Type Definition Issues**

- Missing `@types/` packages
- Incorrect enum values
- Property access on untyped objects

### 3. **Import/Export Mismatches**

- Prisma using default export (should be named)
- Service classes exported differently

---

## Solution: Update Prisma Schema

**File**: `src/apps/api/prisma/schema.prisma`

### Add Missing Models:

```prisma
// Add these to prisma/schema.prisma

model Notification {
  id            String   @id @default(cuid())
  userId        String
  type          String   // "shipment_update", "payment", "alert"
  title         String
  message       String
  isRead        Boolean  @default(false)

  // Contact methods
  emailTo       String?
  phoneTo       String?

  // Metadata
  metadata      Json?    // Store related shipment/payment IDs

  // Timestamps
  createdAt     DateTime @default(now())
  updatedAt     DateTime @updatedAt

  // Relations
  user          User     @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([userId])
  @@index([isRead, createdAt])
}

model Message {
  id            String   @id @default(cuid())
  senderId      String
  recipientId   String?  // Null for broadcasts

  content       String
  type          String   // "system", "driver_update", "customer_notification"
  isRead        Boolean  @default(false)

  // Metadata
  relatedId     String?  // shipment_id, route_id, etc
  relatedType   String?  // "shipment", "route", etc

  // Timestamps
  createdAt     DateTime @default(now())

  // Relations
  sender        User     @relation("MessagesSent", fields: [senderId], references: [id], onDelete: Cascade)
  recipient     User?    @relation("MessagesReceived", fields: [recipientId], references: [id], onDelete: SetNull)

  @@index([senderId])
  @@index([recipientId])
  @@index([isRead, createdAt])
}

model Webhook {
  id            String   @id @default(cuid())
  organizationId String

  event         String   // "shipment.created", "shipment.updated", "payment.completed"
  url           String
  secret        String   // For HMAC signature verification

  isActive      Boolean  @default(true)
  maxRetries    Int      @default(3)

  // Metadata
  headers       Json?    // Custom headers

  // Timestamps
  createdAt     DateTime @default(now())
  updatedAt     DateTime @updatedAt
  lastTriggered DateTime?

  // Relations
  organization  Organization @relation(fields: [organizationId], references: [id], onDelete: Cascade)

  @@index([organizationId])
  @@index([event])
}

// Add these relations to User model:
// model User {
//   ...existing fields...
//
//   notifications    Notification[]
//   messagesSent     Message[] @relation("MessagesSent")
//   messagesReceived Message[] @relation("MessagesReceived")
// }

// Add to Organization model:
// model Organization {
//   ...existing fields...
//
//   webhooks         Webhook[]
// }
```

### Add Shipment Enhancements:

```prisma
// In existing Shipment model, ensure these fields exist:
model Shipment {
  // ... existing fields ...

  // Add these if missing:
  status        String   // "pending", "in_transit", "delivered"
  eventLog      Json?    // Store location/status updates

  @@index([status])
  @@index([createdAt])
}
```

---

## Step-by-Step Fix Process

### Step 1: Update Prisma Schema

```bash
cd src/apps/api

# Add the models above to prisma/schema.prisma
nano prisma/schema.prisma  # or your editor
```

### Step 2: Create and Apply Migration

```bash
# Create migration
pnpm prisma:migrate:dev --name "add-notification-message-webhook-models"

# This will:
# 1. Generate new types
# 2. Create SQL migration
# 3. Apply to development database
# 4. Generate Prisma Client
```

### Step 3: Update Prisma Exports

**File**: `src/apps/api/src/db/prisma.ts`

```typescript
import { PrismaClient } from "@prisma/client";

export const prisma = new PrismaClient({
  log: ["query", "warn", "error"],
});

// For backwards compatibility if needed:
export default prisma;

// Ensure proper export for services
export type { Notification, Message, Webhook } from "@prisma/client";
```

### Step 4: Fix Service Imports

**Files to Update**:

- `src/services/websocket-events.ts`
- `src/services/notification.service.ts`

```typescript
// Change from:
// import prisma from "../db/prisma";

// To:
import { prisma } from "../db/prisma";
```

### Step 5: Fix Type Issues in Services

**File**: `src/middleware/file-upload-validation.ts`

Already fixed ✅ (Line 134 fixed above)

**File**: `src/routes/health.ts`

Update health status enum values:

```typescript
// Replace status values with valid enum:
// "ok" → "healthy"
// "degraded" → "unhealthy"
// "error" → "unknown"

const healthResponse = {
  uptime: process.uptime(),
  timestamp: new Date().toISOString(),
  status: "healthy" as const, // Valid enum value
  // ... other fields
};
```

### Step 6: Fix Express Types

**File**: `src/server.ts`

```typescript
// Ensure proper import:
import express, { type Server } from "express";

// Or use:
import type { Server } from "http";
import express from "express";
```

### Step 7: Run TypeCheck Again

```bash
# From workspace root
pnpm run typecheck

# Expected output: "No errors found ✓"
```

### Step 8: Verify Build

```bash
# Build API
pnpm run build:api

# Verify artifacts
ls -lah src/apps/api/dist/
```

---

## Verification Checklist

- [ ] Prisma schema updated with 3 new models
- [ ] Migration created and applied
- [ ] Prisma Client regenerated
- [ ] All imports updated (prisma exports)
- [ ] Health status enum values fixed
- [ ] File upload type issues resolved
- [ ] WebSocket service types correct
- [ ] Notification service types correct
- [ ] TypeCheck passes (pnpm run typecheck)
- [ ] Build succeeds (pnpm run build:api)
- [ ] Tests still pass (npm test)

---

## Quick Commands Summary

```bash
# Complete fix process:
cd src/apps/api
nano prisma/schema.prisma  # Add models
pnpm prisma:migrate:dev --name "add-notification-message-webhook-models"
pnpm run typecheck
npm test

# From root:
pnpm run build
git add .
git commit -m "fix: Add missing Prisma models and resolve TypeScript errors"
git push origin main
```

---

## Expected Timeline

- Schema update: 15 minutes
- Migration creation: 5 minutes
- TypeScript fixes: 20 minutes
- Testing and verification: 15 minutes
- **Total: ~55 minutes**

---

## Fallback: TypeScript Skip

If complex schema changes are not feasible:

```bash
# Skip typecheck in build (temporary)
cd src/apps/api
# Edit tsconfig.json: "skipLibCheck": true

# Build without typecheck
pnpm build

# Then fix types incrementally
```

**Not recommended** - These are important type safety checks.

---

## Success Criteria

✅ All 35 tests passing  
✅ TypeCheck: 0 errors  
✅ Build: Successful  
✅ Code: Properly formatted  
✅ Git: Commits pushed

---

**Status**: Ready to implement  
**Owner**: Development team  
**Priority**: P0 - Blocks production build  
**ETA**: ~1 hour to complete
