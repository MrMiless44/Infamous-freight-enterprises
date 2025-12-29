import { Request, Response, NextFunction } from "express";
import prisma from "../db/prisma";
import { AppError } from "../middleware/validate";
import * as aiFleetService from "../services/aiFleet.service";

interface VehicleQuery {
  status?: string;
}

export async function getVehicles(
  req: Request<object, object, object, VehicleQuery>,
  res: Response,
  next: NextFunction,
) {
  try {
    const { status } = req.query;

    const where: { status?: string; organizationId: string } = {
      organizationId: req.user!.organizationId,
    };
    if (status) {
      where.status = status;
    }

    const vehicles = await prisma.vehicle.findMany({
      where,
      include: {
        maintenanceLogs: {
          orderBy: {
            performedAt: "desc",
          },
          take: 5,
        },
        loads: {
          where: {
            status: { in: ["ASSIGNED", "IN_TRANSIT"] },
          },
        },
      },
    });

    res.json({
      status: "success",
      data: { vehicles },
    });
  } catch (error) {
    next(error);
  }
}

export async function getVehicleById(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;

    const vehicle = await prisma.vehicle.findUnique({
      where: { id },
      include: {
        maintenanceLogs: {
          orderBy: {
            performedAt: "desc",
          },
        },
        loads: {
          orderBy: {
            createdAt: "desc",
          },
          take: 20,
        },
      },
    });

    if (!vehicle) {
      throw new AppError("Vehicle not found", 404);
    }

    // Check if user has access
    if (
      vehicle.organizationId !== req.user!.organizationId &&
      req.user!.role !== "ADMIN"
    ) {
      throw new AppError("Unauthorized", 403);
    }

    res.json({
      status: "success",
      data: { vehicle },
    });
  } catch (error) {
    next(error);
  }
}

export async function logMaintenance(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;
    const { type, description, cost, nextDue } = req.body;

    const vehicle = await prisma.vehicle.findUnique({
      where: { id },
    });

    if (!vehicle) {
      throw new AppError("Vehicle not found", 404);
    }

    // Check if user has access
    if (
      vehicle.organizationId !== req.user!.organizationId &&
      req.user!.role !== "ADMIN"
    ) {
      throw new AppError("Unauthorized", 403);
    }

    const maintenanceLog = await prisma.maintenanceLog.create({
      data: {
        vehicleId: id,
        type,
        description,
        cost: parseFloat(cost),
        nextDue: nextDue ? new Date(nextDue) : null,
      },
    });

    // Update vehicle
    await prisma.vehicle.update({
      where: { id },
      data: {
        lastMaintenance: new Date(),
        nextMaintenance: nextDue ? new Date(nextDue) : null,
        status: "AVAILABLE",
      },
    });

    res.status(201).json({
      status: "success",
      data: { maintenanceLog },
    });
  } catch (error) {
    next(error);
  }
}

export async function predictMaintenance(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;

    const vehicle = await prisma.vehicle.findUnique({
      where: { id },
      include: {
        maintenanceLogs: {
          orderBy: {
            performedAt: "desc",
          },
        },
      },
    });

    if (!vehicle) {
      throw new AppError("Vehicle not found", 404);
    }

    // Check if user has access
    if (
      vehicle.organizationId !== req.user!.organizationId &&
      req.user!.role !== "ADMIN"
    ) {
      throw new AppError("Unauthorized", 403);
    }

    const prediction = await aiFleetService.predictMaintenance(vehicle);

    res.json({
      status: "success",
      data: prediction,
    });
  } catch (error) {
    next(error);
  }
}

export async function getAnalytics(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const vehicles = await prisma.vehicle.findMany({
      where: {
        organizationId: req.user!.organizationId,
      },
      include: {
        maintenanceLogs: true,
        loads: {
          where: {
            status: "DELIVERED",
          },
        },
      },
    });

    const analytics = {
      totalVehicles: vehicles.length,
      availableVehicles: vehicles.filter(
        (v: { status: string }) => v.status === "AVAILABLE",
      ).length,
      inUseVehicles: vehicles.filter(
        (v: { status: string }) => v.status === "IN_USE",
      ).length,
      maintenanceVehicles: vehicles.filter(
        (v: { status: string }) => v.status === "MAINTENANCE",
      ).length,
      totalMileage: vehicles.reduce(
        (sum: number, v: { mileage: number }) => sum + v.mileage,
        0,
      ),
      maintenanceCosts: vehicles.reduce(
        (sum: number, v: { maintenanceLogs: Array<{ cost: number }> }) =>
          sum +
          v.maintenanceLogs.reduce(
            (s: number, log: { cost: number }) => s + log.cost,
            0,
          ),
        0,
      ),
      utilizationRate:
        vehicles.length > 0
          ? (vehicles.filter((v: { status: string }) => v.status === "IN_USE")
              .length /
              vehicles.length) *
            100
          : 0,
    };

    res.json({
      status: "success",
      data: analytics,
    });
  } catch (error) {
    next(error);
  }
}

export default {
  getVehicles,
  getVehicleById,
  logMaintenance,
  predictMaintenance,
  getAnalytics,
};
