const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
  await prisma.user.upsert({
    where: { email: "owner@infamousfreight.ai" },
    update: {},
    create: {
      email: "owner@infamousfreight.ai",
      name: "Fleet Owner",
      role: "admin",
    },
  });

  const driver = await prisma.driver.upsert({
    where: { id: "drv_seed" },
    update: {},
    create: {
      id: "drv_seed",
      name: "Genesis Driver",
      phone: "+1-312-555-0188",
      status: "active",
      avatarCode: "genesis",
    },
  });

  await prisma.shipment.upsert({
    where: { reference: "IF-EXP-0001" },
    update: {},
    create: {
      reference: "IF-EXP-0001",
      origin: "Chicago, IL",
      destination: "Atlanta, GA",
      status: "en_route",
      driver: { connect: { id: driver.id } },
    },
  });

  await prisma.aiEvent.create({
    data: {
      type: "seed:init",
      payload: {
        message: "Seed data installed",
        ts: new Date().toISOString(),
      },
    },
  });
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
