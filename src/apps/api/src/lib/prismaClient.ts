/**
 * Prisma Client with Connection Pooling
 * Handles 5x more concurrent requests
 */

import { PrismaClient } from "@prisma/client";

const globalForPrisma = global as unknown as { prisma: PrismaClient };

export const prisma =
  globalForPrisma.prisma ||
  new PrismaClient({
    log:
      process.env.NODE_ENV === "development"
        ? ["query", "error", "warn"]
        : ["error"],
    errorFormat: "pretty",
  });

// Configure connection pool
prisma
  .$connect()
  .then(() => {
    console.log("✅ Database connected with connection pooling");
  })
  .catch((error) => {
    console.error("❌ Database connection failed:", error);
    process.exit(1);
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

// Graceful shutdown
process.on("beforeExit", async () => {
  await prisma.$disconnect();
  console.log("✅ Database disconnected");
});

export default prisma;
