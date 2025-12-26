const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function main() {
  console.warn("Seeding Infamous Freight database...");

  await prisma.user.upsert({
    where: { email: "admin@infamous.ai" },
    update: {},
    create: {
      email: "admin@infamous.ai",
      name: "System Admin",
      role: "admin",
    },
  });

  await prisma.user.upsert({
    where: { email: "dispatch@infamous.ai" },
    update: {},
    create: {
      email: "dispatch@infamous.ai",
      name: "Primary Dispatcher",
      role: "dispatcher",
    },
  });

  const driver1 = await prisma.driver.create({
    data: {
      name: "Michael Reyes",
      phone: "+1-202-555-0123",
      status: "active",
      avatarCode: "genesis",
    },
  });

  const driver2 = await prisma.driver.create({
    data: {
      name: "Jada Kingsley",
      phone: "+1-202-555-0199",
      status: "active",
      avatarCode: "aurum",
    },
  });

  await prisma.shipment.create({
    data: {
      reference: "NF-1001",
      origin: "Los Angeles, CA",
      destination: "Dallas, TX",
      status: "in_transit",
      driverId: driver1.id,
    },
  });

  await prisma.shipment.create({
    data: {
      reference: "NF-1002",
      origin: "Chicago, IL",
      destination: "Atlanta, GA",
      status: "created",
      driverId: driver2.id,
    },
  });

  await prisma.aiEvent.create({
    data: {
      type: "seed",
      payload: { message: "Seed completed" },
    },
  });

  console.warn("Seed completed.");
}

main()
  .catch((err) => {
    console.error("Seed error", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
