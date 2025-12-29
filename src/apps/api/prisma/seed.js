const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();

async function main() {
  console.info("🌱 Seeding Infamous Freight database...");

  // Create a default organization
  const org = await prisma.organization.upsert({
    where: { id: "seed-org-1" },
    update: {},
    create: {
      id: "seed-org-1",
      name: "Infamous Freight Enterprises",
    },
  });

  console.info("✅ Organization created:", org.name);

  // Hash password for users
  const passwordHash = await bcrypt.hash("password123", 10);

  // Create admin user
  const admin = await prisma.user.upsert({
    where: { email: "admin@infamous.ai" },
    update: {},
    create: {
      email: "admin@infamous.ai",
      passwordHash,
      role: "admin",
      organizationId: org.id,
    },
  });

  console.info("✅ Admin user created:", admin.email);

  // Create dispatcher user
  const dispatcher = await prisma.user.upsert({
    where: { email: "dispatch@infamous.ai" },
    update: {},
    create: {
      email: "dispatch@infamous.ai",
      passwordHash,
      role: "dispatcher",
      organizationId: org.id,
    },
  });

  console.info("✅ Dispatcher user created:", dispatcher.email);

  // Create driver profile for a sample driver
  const driver1 = await prisma.user.upsert({
    where: { email: "driver1@infamous.ai" },
    update: {},
    create: {
      email: "driver1@infamous.ai",
      passwordHash,
      role: "driver",
      organizationId: org.id,
    },
  });

  await prisma.driverProfile.upsert({
    where: { userId: driver1.id },
    update: {},
    create: {
      userId: driver1.id,
      organizationId: org.id,
      displayName: "Michael Reyes",
      avatarTheme: "genesis",
    },
  });

  console.info("✅ Driver profile created: Michael Reyes");

  // Create a sample invoice
  await prisma.invoice.create({
    data: {
      organizationId: org.id,
      amount: 1250.50,
      vendor: "Fuel Express Inc",
      status: "pending",
    },
  });

  console.info("✅ Sample invoice created");

  // Create a sample AI decision
  await prisma.aiDecision.create({
    data: {
      organizationId: org.id,
      type: "route_optimization",
      confidence: 0.92,
      rationale: "Recommended route based on traffic patterns and fuel efficiency",
    },
  });

  console.info("✅ Sample AI decision created");

  // Create a route session
  const routeSession = await prisma.routeSession.create({
    data: {
      userId: driver1.id,
      organizationId: org.id,
    },
  });

  // Create route events
  await prisma.routeEvent.create({
    data: {
      sessionId: routeSession.id,
      type: "route_start",
      meta: JSON.stringify({ location: "Los Angeles, CA" }),
    },
  });

  console.info("✅ Sample route session and events created");

  console.info("🎉 Seed completed successfully!");
}

main()
  .catch((err) => {
    console.error("❌ Seed error:", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

