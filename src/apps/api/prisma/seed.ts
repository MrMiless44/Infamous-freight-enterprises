/**
 * Database Seeding Script
 * Populates database with test data for development and testing
 */

import { PrismaClient } from "@prisma/client";
import { faker } from "@faker-js/faker";
import bcrypt from "bcrypt";

const prisma = new PrismaClient();

async function main() {
  console.log("🌱 Starting database seed...");

  // Clear existing data
  await prisma.$executeRawUnsafe(
    `TRUNCATE TABLE "public"."_prisma_migrations" RESTART IDENTITY CASCADE;`,
  );

  // Create Organizations
  const org1 = await prisma.organization.create({
    data: {
      name: "Infamous Freight Enterprises",
      slug: "infamous-freight",
      description: "Leading freight and logistics company",
      website: "https://infamousfreight.com",
    },
  });

  console.log("✅ Organizations created");

  // Create Users
  const adminUser = await prisma.user.create({
    data: {
      email: "admin@infamousfreight.com",
      name: "Admin User",
      password: await bcrypt.hash("admin123", 10),
      role: "ADMIN",
      organizationId: org1.id,
      emailVerified: new Date(),
    },
  });

  const dispatcherUser = await prisma.user.create({
    data: {
      email: "dispatcher@infamousfreight.com",
      name: "Dispatcher User",
      password: await bcrypt.hash("dispatch123", 10),
      role: "DISPATCHER",
      organizationId: org1.id,
      emailVerified: new Date(),
    },
  });

  const drivers = [];
  for (let i = 0; i < 5; i++) {
    const driver = await prisma.user.create({
      data: {
        email: `driver${i + 1}@infamousfreight.com`,
        name: faker.person.fullName(),
        password: await bcrypt.hash("driver123", 10),
        role: "DRIVER",
        organizationId: org1.id,
        emailVerified: new Date(),
      },
    });
    drivers.push(driver);
  }

  console.log("✅ Users created (1 admin, 1 dispatcher, 5 drivers)");

  // Create Customers
  const customers = [];
  for (let i = 0; i < 10; i++) {
    const customer = await prisma.customer.create({
      data: {
        name: faker.company.name(),
        email: faker.internet.email(),
        phone: faker.phone.number(),
        address: faker.location.streetAddress(),
        city: faker.location.city(),
        state: faker.location.state({ abbreviated: true }),
        zipCode: faker.location.zipCode(),
        organizationId: org1.id,
      },
    });
    customers.push(customer);
  }

  console.log("✅ Customers created (10)");

  // Create Driver Profiles
  const driverProfiles = [];
  for (const driver of drivers) {
    const profile = await prisma.driverProfile.create({
      data: {
        userId: driver.id,
        licenseNumber: faker.string.alphaNumeric(10).toUpperCase(),
        licenseExpiry: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        yearsExperience: faker.number.int({ min: 1, max: 30 }),
        status: "ACTIVE",
        currentLatitude: faker.location.latitude(),
        currentLongitude: faker.location.longitude(),
      },
    });
    driverProfiles.push(profile);
  }

  console.log("✅ Driver profiles created (5)");

  // Create Vehicles
  const vehicles = [];
  const vehicleTypes = ["truck", "van", "trailer", "flatbed"];
  for (let i = 0; i < 8; i++) {
    const vehicle = await prisma.vehicle.create({
      data: {
        make: faker.vehicle.manufacturer(),
        model: faker.vehicle.model(),
        year: faker.number.int({ min: 2015, max: 2024 }),
        vin: faker.vehicle.vin(),
        licensePlate: faker.string.alphaNumeric(7).toUpperCase(),
        type: vehicleTypes[i % vehicleTypes.length],
        capacity: faker.number.int({ min: 5000, max: 50000 }),
        fuelType: faker.helpers.arrayElement([
          "diesel",
          "gasoline",
          "electric",
        ]),
        organizationId: org1.id,
        status: "ACTIVE",
      },
    });
    vehicles.push(vehicle);
  }

  console.log("✅ Vehicles created (8)");

  // Create Shipments
  const shipments = [];
  const statuses = [
    "PENDING",
    "ASSIGNED",
    "IN_TRANSIT",
    "DELIVERED",
    "CANCELLED",
  ];
  for (let i = 0; i < 20; i++) {
    const originCity = faker.location.city();
    const destCity = faker.location.city();
    const shipment = await prisma.shipment.create({
      data: {
        trackingNumber: `IF-${faker.string.alphaNumeric(8).toUpperCase()}`,
        customerId: faker.helpers.arrayElement(customers).id,
        driverId:
          faker.helpers.maybe(() => faker.helpers.arrayElement(drivers).id, {
            probability: 0.7,
          }) || undefined,
        vehicleId:
          faker.helpers.maybe(() => faker.helpers.arrayElement(vehicles).id, {
            probability: 0.7,
          }) || undefined,
        originCity,
        originState: faker.location.state({ abbreviated: true }),
        originZip: faker.location.zipCode(),
        destinationCity: destCity,
        destinationState: faker.location.state({ abbreviated: true }),
        destinationZip: faker.location.zipCode(),
        weight: faker.number.int({ min: 100, max: 10000 }),
        dimensions: `${faker.number.int({ min: 50, max: 200 })}x${faker.number.int({ min: 50, max: 200 })}x${faker.number.int({ min: 50, max: 200 })}`,
        contents: faker.commerce.productDescription(),
        status: faker.helpers.arrayElement(statuses),
        pickupDate: faker.date.soon({ days: 7 }),
        estimatedDelivery: faker.date.soon({ days: 14 }),
        actualDelivery: Math.random() > 0.5 ? faker.date.recent() : null,
        rate: faker.number.float({ min: 500, max: 5000, precision: 0.01 }),
        notes: faker.lorem.sentence(),
        organizationId: org1.id,
      },
    });
    shipments.push(shipment);
  }

  console.log("✅ Shipments created (20)");

  // Create Route Events
  for (const shipment of shipments.slice(0, 10)) {
    if (shipment.driverId) {
      await prisma.routeEvent.create({
        data: {
          shipmentId: shipment.id,
          driverId: shipment.driverId,
          eventType: "PICKUP_COMPLETED",
          latitude: faker.location.latitude(),
          longitude: faker.location.longitude(),
          timestamp: new Date(),
          notes: "Shipment picked up",
        },
      });
    }
  }

  console.log("✅ Route events created");

  // Create Invoices
  const invoices = [];
  for (let i = 0; i < 15; i++) {
    const shipment = faker.helpers.arrayElement(shipments);
    const invoice = await prisma.invoice.create({
      data: {
        invoiceNumber: `INV-${faker.string.alphaNumeric(8).toUpperCase()}`,
        customerId: shipment.customerId,
        shipmentId: shipment.id,
        amount: shipment.rate,
        taxAmount: shipment.rate * 0.08,
        totalAmount: shipment.rate * 1.08,
        status: faker.helpers.arrayElement([
          "DRAFT",
          "SENT",
          "PAID",
          "OVERDUE",
        ]),
        dueDate: faker.date.soon({ days: 30 }),
        issuedDate: faker.date.past({ years: 1 }),
        organizationId: org1.id,
      },
    });
    invoices.push(invoice);
  }

  console.log("✅ Invoices created (15)");

  // Create Payments
  for (let i = 0; i < 10; i++) {
    const invoice = faker.helpers.arrayElement(
      invoices.filter((inv) => inv.status !== "DRAFT"),
    );
    await prisma.payment.create({
      data: {
        invoiceId: invoice.id,
        amount: invoice.amount,
        method: faker.helpers.arrayElement([
          "CREDIT_CARD",
          "ACH",
          "CHECK",
          "WIRE",
        ]),
        transactionId: faker.string.alphaNumeric(20).toUpperCase(),
        status: "COMPLETED",
        paidDate: faker.date.recent(),
        organizationId: org1.id,
      },
    });
  }

  console.log("✅ Payments created (10)");

  console.log("✅ Database seed completed successfully!");
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error("❌ Seed error:", e);
    await prisma.$disconnect();
    process.exit(1);
  });
