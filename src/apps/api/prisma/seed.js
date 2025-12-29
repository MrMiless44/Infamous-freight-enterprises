const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

async function main() {
  console.info("Seeding Infamous Freight database...");

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

  await prisma.driverMemory.create({
    data: {
      driverId: driver1.id,
      preferences: {
        preferredRoutes: ["I-10", "I-40"],
        restStopFrequency: "medium",
        musicPreference: "classic-rock",
      },
      drivingStyle: "efficient",
      riskTolerance: "moderate",
      pastRoutes: [
        { route: "LA to Dallas", frequency: 15, avgTime: "18h" },
        { route: "Dallas to Atlanta", frequency: 8, avgTime: "12h" },
      ],
      earningsPatterns: {
        averageWeekly: 2400,
        peakSeason: "Q4",
        bonusEligible: true,
      },
      communicationTone: "professional",
      learnedConstraints: {
        avoidNightDriving: false,
        maxDailyHours: 11,
        preferredStartTime: "06:00",
      },
    },
  });

  await prisma.driverMemory.create({
    data: {
      driverId: driver2.id,
      preferences: {
        preferredRoutes: ["I-55", "I-75"],
        restStopFrequency: "high",
        musicPreference: "hip-hop",
      },
      drivingStyle: "cautious",
      riskTolerance: "low",
      pastRoutes: [
        { route: "Chicago to Atlanta", frequency: 22, avgTime: "11h" },
        { route: "Atlanta to Miami", frequency: 10, avgTime: "10h" },
      ],
      earningsPatterns: {
        averageWeekly: 2200,
        peakSeason: "Q2",
        bonusEligible: true,
      },
      communicationTone: "friendly",
      learnedConstraints: {
        avoidNightDriving: true,
        maxDailyHours: 10,
        preferredStartTime: "07:00",
      },
    },
  });

  await prisma.aiEvent.create({
    data: {
      type: "seed",
      payload: { message: "Seed completed" },
    },
  });

  console.info("Seed completed.");
}

main()
  .catch((err) => {
    console.error("Seed error", err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
