import { Router } from "express";
import { body, param } from "express-validator";
import * as driverController from "../controllers/driver.controller";
import { requireAuth, restrictTo, validate } from "../middleware/validate";

export const driver = Router();

driver.use(requireAuth);

/**
 * @swagger
 * /api/drivers:
 *   get:
 *     summary: Get all drivers
 *     tags: [Drivers]
 *     security:
 *       - bearerAuth: []
 */
driver.get("/", driverController.getDrivers);

/**
 * @swagger
 * /api/drivers/{id}:
 *   get:
 *     summary: Get driver by ID
 *     tags: [Drivers]
 *     security:
 *       - bearerAuth: []
 */
driver.get("/:id", driverController.getDriverById);

/**
 * @swagger
 * /api/drivers/{id}/coaching:
 *   post:
 *     summary: Get AI coaching for driver
 *     tags: [Drivers]
 *     security:
 *       - bearerAuth: []
 */
driver.post(
  "/:id/coaching",
  [param("id").notEmpty().withMessage("Driver ID is required")],
  validate,
  driverController.getAICoaching,
);

/**
 * @swagger
 * /api/drivers/{id}/performance:
 *   get:
 *     summary: Get driver performance metrics
 *     tags: [Drivers]
 *     security:
 *       - bearerAuth: []
 */
driver.get("/:id/performance", driverController.getPerformance);

/**
 * @swagger
 * /api/drivers/{id}/location:
 *   put:
 *     summary: Update driver location
 *     tags: [Drivers]
 *     security:
 *       - bearerAuth: []
 */
driver.put(
  "/:id/location",
  restrictTo("DRIVER", "ADMIN"),
  [
    param("id").notEmpty().withMessage("Driver ID is required"),
    body("latitude")
      .isFloat()
      .withMessage("Latitude must be a valid number"),
    body("longitude")
      .isFloat()
      .withMessage("Longitude must be a valid number"),
  ],
  validate,
  driverController.updateLocation,
);
