import { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import { AppError } from "../middleware/validate";
import * as aiCustomerService from "../services/aiCustomer.service";

const prisma = new PrismaClient();

export async function getCustomers(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const customers = await prisma.customer.findMany({
      where: {
        organizationId: req.user!.organizationId,
      },
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
      data: { customers },
    });
  } catch (error) {
    next(error);
  }
}

export async function getCustomerById(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;

    const customer = await prisma.customer.findUnique({
      where: { id },
      include: {
        user: true,
        loads: {
          orderBy: {
            createdAt: "desc",
          },
          take: 50,
        },
      },
    });

    if (!customer) {
      throw new AppError("Customer not found", 404);
    }

    // Check if user has access
    if (
      customer.organizationId !== req.user!.organizationId &&
      req.user!.role !== "ADMIN"
    ) {
      throw new AppError("Unauthorized", 403);
    }

    res.json({
      status: "success",
      data: { customer },
    });
  } catch (error) {
    next(error);
  }
}

export async function getCustomerLoads(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { id } = req.params;
    const { status } = req.query as { status?: string };

    const customer = await prisma.customer.findUnique({
      where: { id },
    });

    if (!customer) {
      throw new AppError("Customer not found", 404);
    }

    // Check if user has access
    if (
      customer.organizationId !== req.user!.organizationId &&
      req.user!.role !== "ADMIN"
    ) {
      throw new AppError("Unauthorized", 403);
    }

    const where: { customerId: string; status?: string } = {
      customerId: id,
    };
    if (status) {
      where.status = status;
    }

    const loads = await prisma.load.findMany({
      where,
      include: {
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
    });

    res.json({
      status: "success",
      data: { loads },
    });
  } catch (error) {
    next(error);
  }
}

export async function getAISupport(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const { question, customerId, context } = req.body;

    if (!question) {
      throw new AppError("Question is required", 400);
    }

    const support = await aiCustomerService.getSupport({
      question,
      customerId,
      context,
    });

    res.json({
      status: "success",
      data: support,
    });
  } catch (error) {
    next(error);
  }
}

export default {
  getCustomers,
  getCustomerById,
  getCustomerLoads,
  getAISupport,
};
