import { Request, Response, NextFunction } from "express";
import prisma from "../db/prisma";
import { AppError } from "../middleware/validate";
import * as aiCoachService from "../services/aiCoach.service";
interface DriverQuery {
  isAvailable?: string;
  page?: string;
  limit?: string;
}

export async function getDrivers(
  req: Request<object, object, object, DriverQuery>,
  res: Response,
  next: NextFunction,
) {
  try {
    const { isAvailable, page = "1", limit = "10" } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const where: { isAvailable?: boolean; organizationId: string } = {
      organizationId: req.user!.organizationId,
    };
    if (isAvailable !== undefined) {
      where.isAvailable = isAvailable === "true";
    }

    const drivers = await prisma.driver.findMany({
      where,
      skip: parseInt(skip.toString()),
      take: parseInt(limit),
      include: {
        user: {
          select: {
            firstName: true,
            lastName: true,
            email: true,
            phone: true,
          },
        },
      },
    });

    res.json({
      status: "success",
      data: { drivers },
    });
  } catch (error) {
    next(error);
  }
}

export async function getDriverById(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;

    const driver = await prisma.driver.findUnique({
      where: { id },
      include: {
        user: true,
        loads: {
          where: {
            status: { in: ["ASSIGNED", "IN_TRANSIT"] },
          },
          include: {
            customer: {
              include: {
                user: true,
              },
            },
          },
        },
        aiCoachingSessions: {
          orderBy: {
            createdAt: "desc",
          },
          take: 10,
        },
      },
    });

    if (!driver) {
      throw new AppError("Driver not found", 404);
    }

    // Check if user has access
    if (
      driver.organizationId !== req.user!.organizationId &&
      req.user!.role !== "ADMIN"
    ) {
      throw new AppError("Unauthorized", 403);
    }

    res.json({
      status: "success",
      data: { driver },
    });
  } catch (error) {
    next(error);
  }
}

export async function getAICoaching(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;

    const driver = await prisma.driver.findUnique({
      where: { id },
      include: {
        loads: {
          where: {
            status: "DELIVERED",
          },
          orderBy: {
            deliveryTime: "desc",
          },
          take: 50,
        },
      },
    });

    if (!driver) {
      throw new AppError("Driver not found", 404);
    }

    // Check if user has access
    if (
      driver.organizationId !== req.user!.organizationId &&
      req.user!.role !== "ADMIN"
    ) {
      throw new AppError("Unauthorized", 403);
    }

    // Get AI coaching insights
    const coaching = await aiCoachService.generateCoaching(driver);

    // Save coaching session
    const session = await prisma.aICoachingSession.create({
      data: {
        driverId: driver.id,
        feedback: coaching.feedback,
        metrics: coaching.metrics as never,
        suggestions: coaching.suggestions as never,
      },
    });

    res.json({
      status: "success",
      data: { coaching, session },
    });
  } catch (error) {
    next(error);
  }
}

export async function getPerformance(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;
    const { startDate, endDate } = req.query as {
      startDate?: string;
      endDate?: string;
    };

    const where: {
      driverId: string;
      status: string;
      deliveryTime?: { gte?: Date; lte?: Date };
    } = {
      driverId: id,
      status: "DELIVERED",
    };

    if (startDate || endDate) {
      where.deliveryTime = {};
      if (startDate) where.deliveryTime.gte = new Date(startDate);
      if (endDate) where.deliveryTime.lte = new Date(endDate);
    }

    const loads = await prisma.load.findMany({
      where,
      orderBy: {
        deliveryTime: "desc",
      },
    });

    // Calculate performance metrics
    const metrics = {
      totalLoads: loads.length,
      onTimeDeliveries: loads.filter(
        (l: { deliveryTime: Date | string }) => new Date(l.deliveryTime) <= new Date(l.deliveryTime),
      ).length,
      totalRevenue: loads.reduce((sum: number, l: { rate: number }) => sum + l.rate, 0),
      averageRating:
        loads.length > 0
          ? loads.reduce((sum: number, l: { rating: number | null }) => sum + (l.rating || 0), 0) / loads.length
          : 0,
    };

    res.json({
      status: "success",
      data: { metrics, loads },
    });
  } catch (error) {
    next(error);
  }
}

export async function updateLocation(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;
    const { latitude, longitude } = req.body;

    // Verify driver owns this record or is admin
    const existingDriver = await prisma.driver.findUnique({
      where: { id },
    });

    if (!existingDriver) {
      throw new AppError("Driver not found", 404);
    }

    if (
      req.user!.role !== "ADMIN" &&
      existingDriver.userId !== req.user!.id
    ) {
      throw new AppError("Unauthorized", 403);
    }

    const driver = await prisma.driver.update({
      where: { id },
      data: {
        currentLocation: {
          latitude,
          longitude,
          timestamp: new Date().toISOString(),
        } as never,
      },
    });

    res.json({
      status: "success",
      data: { driver },
    });
  } catch (error) {
    next(error);
  }
}

export default {
  getDrivers,
  getDriverById,
  getAICoaching,
  getPerformance,
  updateLocation,
};
