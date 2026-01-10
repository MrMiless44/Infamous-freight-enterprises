import { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import { AppError } from "../middleware/validate";
import * as aiDispatchService from "../services/aiDispatchService";
import { DriverAvailabilityPredictor } from "../services/driverAvailabilityPredictor";
import { RouteOptimizer } from "../services/routeOptimizer";

declare global {
  // eslint-disable-next-line no-var
  // Using var on the global object to allow reuse across modules
  var prisma: PrismaClient | undefined;
}

const prisma = globalThis.prisma ?? new PrismaClient();

if (!globalThis.prisma) {
  globalThis.prisma = prisma;
}

// Initialize services
const driverPredictor = new DriverAvailabilityPredictor();
const routeOptimizer = new RouteOptimizer();
interface LoadQuery {
  status?: string;
  page?: string;
  limit?: string;
}

/**
 * Get all loads (shipments) for the authenticated organization with optional filtering
 * @param {Request} req - Express request with optional query params (status, page, limit)
 * @param {Response} res - Express response object
 * @param {NextFunction} next - Express error handler
 * @returns {Promise<void>} JSON response with loads array, pagination, and total count
 * @throws {AppError} If database query fails or status filter is invalid
 */
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
        skip,
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

    console.log(`Load created: ${load.loadNumber} by user ${req.user!.id}`);

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
    let mlPrediction: any = null;

    // Use AI for assignment if requested and no specific driver/vehicle provided
    if (useAI && (!driverId || !vehicleId)) {
      // Get all available drivers and rank them by ML prediction
      const availableDrivers = await prisma.driver.findMany({
        where: {
          organizationId: req.user!.organizationId,
          isAvailable: true,
        },
        include: {
          user: {
            select: {
              firstName: true,
              lastName: true,
              email: true,
            },
          },
        },
      });

      if (availableDrivers.length === 0) {
        throw new AppError("No available drivers for assignment", 400);
      }

      // Get ML predictions for all drivers
      const predictions = availableDrivers
        .map((driver) => {
          const prediction = driverPredictor.predict(driver.id, "clear", 50, 0);
          return {
            driver,
            prediction,
            score: prediction.availabilityProbability,
          };
        })
        .sort((a, b) => b.score - a.score);

      mlPrediction = predictions[0];
      if (!driverId) {
        assignedDriverId = predictions[0].driver.id;
      }

      // Original AI recommendation for vehicle
      const aiRecommendation =
        await aiDispatchService.recommendAssignment(load);

      if (!vehicleId) {
        assignedVehicleId = aiRecommendation.vehicleId;
      }

      // Log AI decision with ML insights
      aiDecision = await prisma.aIDecision.create({
        data: {
          loadId: load.id,
          aiRole: "DISPATCH_OPERATOR",
          decision: "LOAD_ASSIGNMENT",
          reasoning: `ML prediction: ${mlPrediction.prediction.recommendation} (${(mlPrediction.prediction.availabilityProbability * 100).toFixed(1)}% confidence). ${aiRecommendation.reasoning}`,
          confidence:
            (mlPrediction.prediction.confidence + aiRecommendation.confidence) /
            2,
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
      `Load ${load.loadNumber} assigned to driver ${assignedDriverId} using ML prediction`,
    );

    res.json({
      status: "success",
      data: {
        load: updatedLoad,
        aiDecision,
        mlPrediction: mlPrediction
          ? {
              driverId: mlPrediction.driver.id,
              driverName: `${mlPrediction.driver.user.firstName} ${mlPrediction.driver.user.lastName}`,
              availabilityScore:
                mlPrediction.prediction.availabilityProbability,
              confidence: mlPrediction.prediction.confidence,
            }
          : null,
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

    // Build waypoints from loads
    const waypoints = loads.map((load) => ({
      lat: load.pickupLat,
      lng: load.pickupLng,
      name: load.pickupAddress,
    }));

    // Add delivery point if single load, otherwise optimize multi-stop
    if (loads.length === 1) {
      waypoints.push({
        lat: loads[0].deliveryLat,
        lng: loads[0].deliveryLng,
        name: loads[0].deliveryAddress,
      });
    }

    // Use route optimizer
    const optimization = routeOptimizer.optimizeMultiStop(waypoints);

    // Store optimization
    await prisma.routeOptimization.create({
      data: {
        waypoints: JSON.stringify(waypoints),
        optimizedPath: JSON.stringify(optimization.waypoints),
        totalDistance: optimization.totalDistance,
        estimatedTime: optimization.estimatedTime,
        efficiency: parseFloat(optimization.efficiency.replace("%", "")),
        fuelEstimate: optimization.fuel,
        costEstimate: optimization.cost,
        metadata: JSON.stringify({
          loadIds,
          timestamp: new Date(),
        }),
      },
    });

    // Log AI decision
    if (loads.length > 0) {
      await prisma.aIDecision.create({
        data: {
          loadId: loads[0].id,
          aiRole: "DISPATCH_OPERATOR",
          decision: "ROUTE_OPTIMIZATION",
          reasoning: `Optimized ${loads.length} load(s) for delivery. Total distance: ${optimization.totalDistance.toFixed(2)} km, Estimated time: ${optimization.estimatedTime} min, Efficiency: ${optimization.efficiency}`,
          confidence: 0.92,
          humanApproved: false,
        },
      });
    }

    res.json({
      status: "success",
      data: {
        loads,
        optimization: {
          totalDistance: optimization.totalDistance,
          estimatedTime: optimization.estimatedTime,
          efficiency: optimization.efficiency,
          fuelEstimate: optimization.fuel,
          costEstimate: optimization.cost,
          waypoints: optimization.waypoints,
        },
      },
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
