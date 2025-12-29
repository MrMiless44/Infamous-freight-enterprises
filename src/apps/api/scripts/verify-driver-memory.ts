import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function verifyDriverMemoryModel() {
  console.log("🔍 Verifying DriverMemory model integration...\n");

  try {
    // Check if we can query the model
    console.log("1. Testing model query capability...");
    const memories = await prisma.driverMemory.findMany();
    console.log(`✓ Successfully queried DriverMemory table. Found ${memories.length} records.\n`);

    // Check if we can query with relations
    console.log("2. Testing relations...");
    const memoriesWithDriver = await prisma.driverMemory.findMany({
      include: { driver: true },
    });
    console.log(`✓ Successfully queried with driver relation. Found ${memoriesWithDriver.length} records.\n`);

    // List all drivers
    console.log("3. Checking available drivers...");
    const drivers = await prisma.driver.findMany({
      select: { id: true, name: true, status: true },
    });
    console.log(`✓ Found ${drivers.length} drivers:`);
    drivers.forEach((driver) => {
      console.log(`   - ${driver.name} (${driver.id}) - Status: ${driver.status}`);
    });
    console.log();

    // Check if any driver has memory
    console.log("4. Checking driver-memory relationships...");
    const driversWithMemory = await prisma.driver.findMany({
      include: { driverMemory: true },
    });
    const withMemory = driversWithMemory.filter((d) => d.driverMemory);
    console.log(`✓ ${withMemory.length} out of ${driversWithMemory.length} drivers have memory records.\n`);

    if (withMemory.length > 0) {
      console.log("Sample driver memory:");
      const sample = withMemory[0];
      console.log(`   Driver: ${sample.name}`);
      console.log(`   Memory ID: ${sample.driverMemory?.id}`);
      console.log(
        `   Driving Style: ${sample.driverMemory?.drivingStyle || "Not set"}`
      );
      console.log(
        `   Risk Tolerance: ${sample.driverMemory?.riskTolerance || "Not set"}`
      );
      console.log(
        `   Last Updated: ${sample.driverMemory?.lastUpdated || "Not set"}`
      );
    }

    console.log("\n✅ All verification checks passed!");
    console.log("The DriverMemory model is successfully integrated.");
  } catch (error) {
    console.error("\n❌ Verification failed:");
    console.error(error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

verifyDriverMemoryModel();
