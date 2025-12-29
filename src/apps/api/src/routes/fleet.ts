import { Router } from "express";
import { body, param } from "express-validator";
import * as fleetController from "../controllers/fleet.controller";
import { requireAuth, restrictTo, validate } from "../middleware/validate";

export const fleet = Router();

fleet.use(requireAuth);

/**
 * @swagger
 * /api/fleet/vehicles:
 *   get:
 *     summary: Get all vehicles
 *     tags: [Fleet]
 */
fleet.get("/vehicles", fleetController.getVehicles);

/**
 * @swagger
 * /api/fleet/vehicles/{id}:
 *   get:
 *     summary: Get vehicle by ID
 *     tags: [Fleet]
 */
fleet.get("/vehicles/:id", fleetController.getVehicleById);

/**
 * @swagger
 * /api/fleet/vehicles/{id}/maintenance:
 *   post:
 *     summary: Log maintenance for vehicle
 *     tags: [Fleet]
 */
fleet.post(
  "/vehicles/:id/maintenance",
  restrictTo("ADMIN", "DISPATCHER"),
  [
    param("id").notEmpty().withMessage("Vehicle ID is required"),
    body("type").notEmpty().withMessage("Maintenance type is required"),
    body("description")
      .notEmpty()
      .withMessage("Maintenance description is required"),
    body("cost")
      .isFloat({ min: 0 })
      .withMessage("Cost must be a positive number"),
  ],
  validate,
  fleetController.logMaintenance,
);

/**
 * @swagger
 * /api/fleet/vehicles/{id}/predict-maintenance:
 *   get:
 *     summary: Get AI-powered maintenance predictions
 *     tags: [Fleet]
 */
fleet.get(
  "/vehicles/:id/predict-maintenance",
  fleetController.predictMaintenance,
);

/**
 * @swagger
 * /api/fleet/analytics:
 *   get:
 *     summary: Get fleet analytics
 *     tags: [Fleet]
 */
fleet.get("/analytics", fleetController.getAnalytics);
