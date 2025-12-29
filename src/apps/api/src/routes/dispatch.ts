import { Router } from "express";
import { body, param } from "express-validator";
import * as dispatchController from "../controllers/dispatch.controller";
import { requireAuth, restrictTo, validate } from "../middleware/validate";

export const dispatch = Router();

// Protect all routes
dispatch.use(requireAuth);

/**
 * @swagger
 * /api/dispatch/loads:
 *   get:
 *     summary: Get all loads
 *     tags: [Dispatch]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [PENDING, ASSIGNED, IN_TRANSIT, DELIVERED, CANCELLED]
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: List of loads
 */
dispatch.get("/loads", dispatchController.getLoads);

/**
 * @swagger
 * /api/dispatch/loads/{id}:
 *   get:
 *     summary: Get load by ID
 *     tags: [Dispatch]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Load details
 *       404:
 *         description: Load not found
 */
dispatch.get("/loads/:id", dispatchController.getLoadById);

/**
 * @swagger
 * /api/dispatch/loads:
 *   post:
 *     summary: Create new load
 *     tags: [Dispatch]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - customerId
 *               - pickupAddress
 *               - pickupLat
 *               - pickupLng
 *               - deliveryAddress
 *               - deliveryLat
 *               - deliveryLng
 *               - pickupTime
 *               - deliveryTime
 *               - weight
 *               - rate
 *     responses:
 *       201:
 *         description: Load created successfully
 */
dispatch.post(
  "/loads",
  restrictTo("ADMIN", "DISPATCHER"),
  [
    body("customerId").notEmpty().withMessage("Customer ID is required"),
    body("pickupAddress").notEmpty().withMessage("Pickup address is required"),
    body("pickupLat")
      .isFloat()
      .withMessage("Pickup latitude must be a number"),
    body("pickupLng")
      .isFloat()
      .withMessage("Pickup longitude must be a number"),
    body("deliveryAddress")
      .notEmpty()
      .withMessage("Delivery address is required"),
    body("deliveryLat")
      .isFloat()
      .withMessage("Delivery latitude must be a number"),
    body("deliveryLng")
      .isFloat()
      .withMessage("Delivery longitude must be a number"),
    body("pickupTime").isISO8601().withMessage("Invalid pickup time format"),
    body("deliveryTime")
      .isISO8601()
      .withMessage("Invalid delivery time format"),
    body("weight")
      .isFloat({ min: 0 })
      .withMessage("Weight must be a positive number"),
    body("rate")
      .isFloat({ min: 0 })
      .withMessage("Rate must be a positive number"),
  ],
  validate,
  dispatchController.createLoad,
);

/**
 * @swagger
 * /api/dispatch/loads/{id}/assign:
 *   post:
 *     summary: Assign load to driver (with AI assistance)
 *     tags: [Dispatch]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               driverId:
 *                 type: string
 *               vehicleId:
 *                 type: string
 *               useAI:
 *                 type: boolean
 *                 description: Whether to use AI for assignment recommendation
 *     responses:
 *       200:
 *         description: Load assigned successfully
 */
dispatch.post(
  "/loads/:id/assign",
  restrictTo("ADMIN", "DISPATCHER"),
  [
    param("id").notEmpty().withMessage("Load ID is required"),
    body("driverId").optional(),
    body("vehicleId").optional(),
    body("useAI").optional().isBoolean().withMessage("useAI must be a boolean"),
  ],
  validate,
  dispatchController.assignLoad,
);

/**
 * @swagger
 * /api/dispatch/optimize:
 *   post:
 *     summary: Get AI-powered route optimization
 *     tags: [Dispatch]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - loadIds
 *             properties:
 *               loadIds:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Optimization recommendations
 */
dispatch.post(
  "/optimize",
  restrictTo("ADMIN", "DISPATCHER"),
  [body("loadIds").isArray().withMessage("loadIds must be an array")],
  validate,
  dispatchController.optimizeRoutes,
);
