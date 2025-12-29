import { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import { AppError } from "../middleware/validate";
import * as aiDispatchService from "../services/aiDispatch.service";

const prisma = new PrismaClient();

interface LoadQuery {
  status?: string;
  page?: string;
  limit?: string;
}

export async function getLoads(
  req: Request<object, object, object, LoadQuery>,
  res: Response,
  next: NextFunction,
) {
  try {
    const { status, page = "1", limit = "10" } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const where: { status?: string; organizationId: string } = {
      organizationId: req.user!.organizationId,
    };
    if (status) {
      where.status = status;
    }

    const [loads, total] = await Promise.all([
      prisma.load.findMany({
        where,
        skip: parseInt(skip.toString()),
        take: parseInt(limit),
        include: {
          customer: {
            include: {
              user: {
                select: {
                  firstName: true,
                  lastName: true,
                  email: true,
                },
              },
            },
          },
          driver: {
            include: {
              user: {
                select: {
                  firstName: true,
                  lastName: true,
                  phone: true,
                },
              },
            },
          },
          vehicle: true,
        },
        orderBy: {
          createdAt: "desc",
        },
      }),
      prisma.load.count({ where }),
    ]);

    res.json({
      status: "success",
      data: {
        loads,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / parseInt(limit)),
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function getLoadById(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;

    const load = await prisma.load.findUnique({
      where: { id },
      include: {
        customer: {
          include: {
            user: true,
          },
        },
        driver: {
          include: {
            user: true,
          },
        },
        vehicle: true,
        aiDecisions: {
          orderBy: {
            createdAt: "desc",
          },
        },
      },
    });

    if (!load) {
      throw new AppError("Load not found", 404);
    }

    // Check if user has access to this load
    if (
      load.organizationId !== req.user!.organizationId &&
      req.user!.role !== "ADMIN"
    ) {
      throw new AppError("Unauthorized", 403);
    }

    res.json({
      status: "success",
      data: { load },
    });
  } catch (error) {
    next(error);
  }
}

export async function createLoad(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const {
      customerId,
      pickupAddress,
      pickupLat,
      pickupLng,
      deliveryAddress,
      deliveryLat,
      deliveryLng,
      pickupTime,
      deliveryTime,
      weight,
      rate,
      description,
    } = req.body;

    // Generate unique load number
    const loadNumber = `LOAD-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    const load = await prisma.load.create({
      data: {
        loadNumber,
        organizationId: req.user!.organizationId,
        customerId,
        pickupAddress,
        pickupLat: parseFloat(pickupLat),
        pickupLng: parseFloat(pickupLng),
        deliveryAddress,
        deliveryLat: parseFloat(deliveryLat),
        deliveryLng: parseFloat(deliveryLng),
        pickupTime: new Date(pickupTime),
        deliveryTime: new Date(deliveryTime),
        weight: parseFloat(weight),
        rate: parseFloat(rate),
        description,
        status: "PENDING",
      },
      include: {
        customer: {
          include: {
            user: true,
          },
        },
      },
    });

    console.log(
      `Load created: ${load.loadNumber} by user ${req.user!.id}`,
    );

    res.status(201).json({
      status: "success",
      data: { load },
    });
  } catch (error) {
    next(error);
  }
}

export async function assignLoad(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;
    const { driverId, vehicleId, useAI = true } = req.body;

    const load = await prisma.load.findUnique({
      where: { id },
      include: {
        customer: true,
      },
    });

    if (!load) {
      throw new AppError("Load not found", 404);
    }

    if (load.organizationId !== req.user!.organizationId) {
      throw new AppError("Unauthorized", 403);
    }

    if (load.status !== "PENDING") {
      throw new AppError("Load is not in pending status", 400);
    }

    let assignedDriverId = driverId;
    let assignedVehicleId = vehicleId;
    let aiDecision = null;

    // Use AI for assignment if requested and no specific driver/vehicle provided
    if (useAI && (!driverId || !vehicleId)) {
      const aiRecommendation =
        await aiDispatchService.recommendAssignment(load);

      if (!driverId) {
        assignedDriverId = aiRecommendation.driverId;
      }
      if (!vehicleId) {
        assignedVehicleId = aiRecommendation.vehicleId;
      }

      // Log AI decision
      aiDecision = await prisma.aIDecision.create({
        data: {
          loadId: load.id,
          aiRole: "DISPATCH_OPERATOR",
          decision: "LOAD_ASSIGNMENT",
          reasoning: aiRecommendation.reasoning,
          confidence: aiRecommendation.confidence,
          humanApproved: false,
        },
      });
    }

    // Validate driver and vehicle
    if (assignedDriverId) {
      const driver = await prisma.driver.findUnique({
        where: { id: assignedDriverId },
      });
      if (!driver || !driver.isAvailable) {
        throw new AppError("Driver not available", 400);
      }
    }

    if (assignedVehicleId) {
      const vehicle = await prisma.vehicle.findUnique({
        where: { id: assignedVehicleId },
      });
      if (!vehicle || vehicle.status !== "AVAILABLE") {
        throw new AppError("Vehicle not available", 400);
      }
    }

    // Update load
    const updatedLoad = await prisma.load.update({
      where: { id },
      data: {
        driverId: assignedDriverId,
        vehicleId: assignedVehicleId,
        status: "ASSIGNED",
      },
      include: {
        driver: {
          include: {
            user: true,
          },
        },
        vehicle: true,
        customer: {
          include: {
            user: true,
          },
        },
      },
    });

    console.log(
      `Load ${load.loadNumber} assigned to driver ${assignedDriverId}`,
    );

    res.json({
      status: "success",
      data: {
        load: updatedLoad,
        aiDecision,
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function optimizeRoutes(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { loadIds } = req.body;

    const loads = await prisma.load.findMany({
      where: {
        id: { in: loadIds },
        status: "PENDING",
        organizationId: req.user!.organizationId,
      },
      include: {
        customer: true,
      },
    });

    if (loads.length === 0) {
      throw new AppError("No valid loads found for optimization", 400);
    }

    const optimization = await aiDispatchService.optimizeRoutes(loads);

    // Log AI decision
    if (loads.length > 0) {
      await prisma.aIDecision.create({
        data: {
          loadId: loads[0].id,
          aiRole: "DISPATCH_OPERATOR",
          decision: "ROUTE_OPTIMIZATION",
          reasoning: optimization.reasoning,
          confidence: optimization.confidence,
          humanApproved: false,
        },
      });
    }

    res.json({
      status: "success",
      data: optimization,
    });
  } catch (error) {
    next(error);
  }
}

export default {
  getLoads,
  getLoadById,
  createLoad,
  assignLoad,
  optimizeRoutes,
};
