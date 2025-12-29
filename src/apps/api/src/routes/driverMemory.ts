import { Router } from "express";
import { prisma } from "../db/prisma";
import { requireAuth } from "../middleware/auth";

export const driverMemory = Router();

driverMemory.use(requireAuth);

// GET /api/driver-memory/:driverId - Get driver memory by driver ID
driverMemory.get("/:driverId", async (req, res) => {
  try {
    const { driverId } = req.params;

    const memory = await prisma.driverMemory.findUnique({
      where: { driverId },
      include: {
        driver: {
          select: {
            id: true,
            name: true,
            status: true,
            avatarCode: true,
          },
        },
      },
    });

    if (!memory) {
      return res.status(404).json({ error: "Driver memory not found" });
    }

    res.json(memory);
  } catch (error) {
    console.error("Error fetching driver memory:", error);
    res.status(500).json({ error: "Failed to fetch driver memory" });
  }
});

// GET /api/driver-memory - Get all driver memories
driverMemory.get("/", async (req, res) => {
  try {
    const memories = await prisma.driverMemory.findMany({
      include: {
        driver: {
          select: {
            id: true,
            name: true,
            status: true,
            avatarCode: true,
          },
        },
      },
    });

    res.json(memories);
  } catch (error) {
    console.error("Error fetching driver memories:", error);
    res.status(500).json({ error: "Failed to fetch driver memories" });
  }
});

// POST /api/driver-memory - Create driver memory
driverMemory.post("/", async (req, res) => {
  try {
    const {
      driverId,
      preferences,
      drivingStyle,
      riskTolerance,
      pastRoutes,
      earningsPatterns,
      communicationTone,
      learnedConstraints,
    } = req.body;

    if (!driverId || !preferences) {
      return res
        .status(400)
        .json({ error: "driverId and preferences are required" });
    }

    // Check if driver exists
    const driver = await prisma.driver.findUnique({
      where: { id: driverId },
    });

    if (!driver) {
      return res.status(404).json({ error: "Driver not found" });
    }

    // Check if memory already exists for this driver
    const existingMemory = await prisma.driverMemory.findUnique({
      where: { driverId },
    });

    if (existingMemory) {
      return res
        .status(409)
        .json({ error: "Driver memory already exists for this driver" });
    }

    const memory = await prisma.driverMemory.create({
      data: {
        driverId,
        preferences,
        drivingStyle,
        riskTolerance,
        pastRoutes,
        earningsPatterns,
        communicationTone,
        learnedConstraints,
      },
      include: {
        driver: {
          select: {
            id: true,
            name: true,
            status: true,
            avatarCode: true,
          },
        },
      },
    });

    res.status(201).json(memory);
  } catch (error) {
    console.error("Error creating driver memory:", error);
    res.status(500).json({ error: "Failed to create driver memory" });
  }
});

// PUT /api/driver-memory/:driverId - Update driver memory
driverMemory.put("/:driverId", async (req, res) => {
  try {
    const { driverId } = req.params;
    const {
      preferences,
      drivingStyle,
      riskTolerance,
      pastRoutes,
      earningsPatterns,
      communicationTone,
      learnedConstraints,
    } = req.body;

    // Check if memory exists
    const existingMemory = await prisma.driverMemory.findUnique({
      where: { driverId },
    });

    if (!existingMemory) {
      return res.status(404).json({ error: "Driver memory not found" });
    }

    const memory = await prisma.driverMemory.update({
      where: { driverId },
      data: {
        preferences: preferences ?? existingMemory.preferences,
        drivingStyle: drivingStyle ?? existingMemory.drivingStyle,
        riskTolerance: riskTolerance ?? existingMemory.riskTolerance,
        pastRoutes: pastRoutes ?? existingMemory.pastRoutes,
        earningsPatterns: earningsPatterns ?? existingMemory.earningsPatterns,
        communicationTone:
          communicationTone ?? existingMemory.communicationTone,
        learnedConstraints:
          learnedConstraints ?? existingMemory.learnedConstraints,
      },
      include: {
        driver: {
          select: {
            id: true,
            name: true,
            status: true,
            avatarCode: true,
          },
        },
      },
    });

    res.json(memory);
  } catch (error) {
    console.error("Error updating driver memory:", error);
    res.status(500).json({ error: "Failed to update driver memory" });
  }
});

// DELETE /api/driver-memory/:driverId - Delete driver memory
driverMemory.delete("/:driverId", async (req, res) => {
  try {
    const { driverId } = req.params;

    // Check if memory exists
    const existingMemory = await prisma.driverMemory.findUnique({
      where: { driverId },
    });

    if (!existingMemory) {
      return res.status(404).json({ error: "Driver memory not found" });
    }

    await prisma.driverMemory.delete({
      where: { driverId },
    });

    res.status(204).send();
  } catch (error) {
    console.error("Error deleting driver memory:", error);
    res.status(500).json({ error: "Failed to delete driver memory" });
  }
});
