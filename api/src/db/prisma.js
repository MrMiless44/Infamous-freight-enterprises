/* istanbul ignore file */
const { PrismaClient } = require("@prisma/client");

let prisma;

if (process.env.NODE_ENV === "test") {
  const createModel = () => ({
    findMany: async () => [],
    findUnique: async () => null,
    create: async (data) => data || {},
    update: async (data) => data || {},
    delete: async () => ({}),
  });

  prisma = {
    user: createModel(),
    shipment: createModel(),
    aiEvent: {
      create: async (data) => data || {},
    },
    $transaction: async (callback) =>
      callback({
        user: createModel(),
        shipment: createModel(),
        aiEvent: {
          create: async (data) => data || {},
        },
      }),
  };
} else {
  const client = new PrismaClient({
    log:
      process.env.NODE_ENV === "development"
        ? ["query", "error", "warn"]
        : ["error"],
    errorFormat: "minimal",
  });

  // Graceful shutdown
  process.on("beforeExit", async () => {
    await client.$disconnect();
  });

  process.on("SIGINT", async () => {
    await client.$disconnect();
    process.exit(0);
  });

  process.on("SIGTERM", async () => {
    await client.$disconnect();
    process.exit(0);
  });

  prisma = client;
}

module.exports = { prisma };
