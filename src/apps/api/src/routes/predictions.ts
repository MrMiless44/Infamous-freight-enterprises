import { Router, Request, Response, NextFunction } from "express";
import { body, param } from "express-validator";
import { requireAuth, restrictTo, validate } from "../middleware/validate";
import { DriverAvailabilityPredictor } from "../services/driverAvailabilityPredictor";
import { RouteOptimizer } from "../services/routeOptimizer";
import { GPSTrackingManager } from "../services/gpsTracking";
import { prisma } from "../db/prisma";

export const predictions = Router();

// Initialize services
const driverPredictor = new DriverAvailabilityPredictor();
const routeOptimizer = new RouteOptimizer();
const gpsTracker = new GPSTrackingManager();

// Protect all routes
predictions.use(requireAuth);

/**
 * @swagger
 * /api/predictions/driver-availability:
 *   post:
 *     summary: Predict driver availability with ML model
 *     tags: [Predictions]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - driverId
 *             properties:
 *               driverId:
 *                 type: string
 *               weatherCondition:
 *                 type: string
 *               trafficLevel:
 *                 type: number
 *               recentLoadCount:
 *                 type: number
 *     responses:
 *       200:
 *         description: Availability prediction with confidence scores
 */
predictions.post(
  "/driver-availability",
  restrictTo("ADMIN", "DISPATCHER"),
  [
    body("driverId").notEmpty().withMessage("Driver ID is required"),
    body("weatherCondition").optional().isString(),
    body("trafficLevel").optional().isFloat({ min: 0, max: 100 }),
    body("recentLoadCount").optional().isInt({ min: 0 }),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const {
        driverId,
        weatherCondition = "clear",
        trafficLevel = 50,
        recentLoadCount = 0,
      } = req.body;

      // Get driver data from database
      const driver = await prisma.driver.findUnique({
        where: { id: driverId },
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

      if (!driver) {
        return res.status(404).json({ error: "Driver not found" });
      }

      // Make prediction
      const prediction = driverPredictor.predict(
        driverId,
        weatherCondition,
        trafficLevel,
        recentLoadCount,
      );

      // Store prediction in database
      await prisma.driverPrediction.create({
        data: {
          driverId,
          availabilityScore: prediction.availabilityProbability,
          confidence: prediction.confidence,
          factors: JSON.stringify(prediction.factors),
          recommendation: prediction.recommendation,
          metadata: JSON.stringify({
            weather: weatherCondition,
            traffic: trafficLevel,
            recentLoads: recentLoadCount,
            timestamp: new Date(),
          }),
        },
      });

      res.json({
        success: true,
        data: {
          driverId,
          driverName: `${driver.user.firstName} ${driver.user.lastName}`,
          availabilityProbability: prediction.availabilityProbability,
          confidence: prediction.confidence,
          recommendation: prediction.recommendation,
          estimatedTimeOnline: prediction.estimatedTimeOnline,
          factors: prediction.factors,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * @swagger
 * /api/predictions/driver-recommendations:
 *   post:
 *     summary: Get dispatch recommendations for available drivers
 *     tags: [Predictions]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - loadId
 *             properties:
 *               loadId:
 *                 type: string
 *               topN:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Ranked list of recommended drivers for dispatch
 */
predictions.post(
  "/driver-recommendations",
  restrictTo("ADMIN", "DISPATCHER"),
  [
    body("loadId").notEmpty().withMessage("Load ID is required"),
    body("topN").optional().isInt({ min: 1, max: 20 }),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { loadId, topN = 5 } = req.body;

      // Get load details
      const load = await prisma.load.findUnique({
        where: { id: loadId },
        include: {
          customer: true,
        },
      });

      if (!load) {
        return res.status(404).json({ error: "Load not found" });
      }

      // Get all active drivers in organization
      const drivers = await prisma.driver.findMany({
        where: {
          organizationId: req.user!.organizationId,
          active: true,
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

      // Get predictions for all drivers
      const recommendations = drivers
        .map((driver) => {
          const prediction = driverPredictor.predict(driver.id, "clear", 50, 0);
          return {
            driver: {
              id: driver.id,
              name: `${driver.user.firstName} ${driver.user.lastName}`,
              email: driver.user.email,
            },
            availabilityScore: prediction.availabilityProbability,
            confidence: prediction.confidence,
            recommendation: prediction.recommendation,
            rank: 0, // Will be calculated
          };
        })
        .sort((a, b) => b.availabilityScore - a.availabilityScore)
        .slice(0, topN)
        .map((item, index) => ({
          ...item,
          rank: index + 1,
        }));

      res.json({
        success: true,
        data: {
          loadId,
          recommendations,
          totalMatches: recommendations.length,
          generatedAt: new Date(),
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * @swagger
 * /api/predictions/routes/optimize:
 *   post:
 *     summary: Optimize route for single or multi-stop delivery
 *     tags: [Predictions]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - waypoints
 *             properties:
 *               waypoints:
 *                 type: array
 *                 items:
 *                   type: object
 *               isDeparture:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Optimized route with estimated time and fuel
 */
predictions.post(
  "/routes/optimize",
  restrictTo("ADMIN", "DISPATCHER"),
  [
    body("waypoints")
      .isArray({ min: 2 })
      .withMessage("At least 2 waypoints required"),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { waypoints, isDeparture = true } = req.body;

      // Validate waypoint format
      waypoints.forEach((wp: any, idx: number) => {
        if (!wp.lat || !wp.lng) {
          throw new Error(`Waypoint ${idx} missing latitude or longitude`);
        }
      });

      // Optimize route based on number of waypoints
      let optimizedRoute;
      if (waypoints.length === 2) {
        optimizedRoute = routeOptimizer.optimizeRoute(
          waypoints[0],
          waypoints[1],
        );
      } else {
        optimizedRoute = routeOptimizer.optimizeMultiStop(waypoints);
      }

      // Store optimization result
      await prisma.routeOptimization.create({
        data: {
          waypoints: JSON.stringify(waypoints),
          optimizedPath: JSON.stringify(optimizedRoute.waypoints),
          totalDistance: optimizedRoute.totalDistance,
          estimatedTime: optimizedRoute.estimatedTime,
          efficiency: optimizedRoute.efficiency,
          fuelEstimate: optimizedRoute.fuel,
          costEstimate: optimizedRoute.cost,
          metadata: JSON.stringify({
            isDeparture,
            timestamp: new Date(),
          }),
        },
      });

      res.json({
        success: true,
        data: {
          waypoints: optimizedRoute.waypoints,
          totalDistance: optimizedRoute.totalDistance,
          estimatedTime: optimizedRoute.estimatedTime,
          efficiency: optimizedRoute.efficiency,
          fuelEstimate: optimizedRoute.fuel,
          costEstimate: optimizedRoute.cost,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * @swagger
 * /api/tracking/update-location:
 *   post:
 *     summary: Update driver real-time location
 *     tags: [Tracking]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - driverId
 *               - latitude
 *               - longitude
 *             properties:
 *               driverId:
 *                 type: string
 *               latitude:
 *                 type: number
 *               longitude:
 *                 type: number
 *               speed:
 *                 type: number
 *               heading:
 *                 type: number
 *               accuracy:
 *                 type: number
 *     responses:
 *       200:
 *         description: Location update received and processed
 */
predictions.post(
  "/tracking/update-location",
  [
    body("driverId").notEmpty().withMessage("Driver ID is required"),
    body("latitude")
      .isFloat({ min: -90, max: 90 })
      .withMessage("Valid latitude required"),
    body("longitude")
      .isFloat({ min: -180, max: 180 })
      .withMessage("Valid longitude required"),
    body("speed").optional().isFloat({ min: 0 }),
    body("heading").optional().isFloat({ min: 0, max: 360 }),
    body("accuracy").optional().isFloat({ min: 0 }),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const {
        driverId,
        latitude,
        longitude,
        speed = 0,
        heading = 0,
        accuracy = 10,
      } = req.body;

      // Update driver location
      gpsTracker.updateDriverLocation(
        driverId,
        latitude,
        longitude,
        speed,
        heading,
        accuracy,
      );

      // Store location history
      await prisma.locationHistory.create({
        data: {
          driverId,
          latitude,
          longitude,
          speed,
          heading,
          accuracy,
          timestamp: new Date(),
        },
      });

      // Check geofence events
      const geofences = await prisma.geofence.findMany({
        where: {
          organizationId: req.user!.organizationId,
        },
      });

      const geofenceEvents: any[] = [];
      for (const geofence of geofences) {
        const inGeofence = gpsTracker.isInGeofence(
          { lat: latitude, lng: longitude },
          {
            lat: geofence.latitude,
            lng: geofence.longitude,
            radiusMeters: geofence.radiusMeters,
          },
        );

        if (inGeofence) {
          geofenceEvents.push({
            type: "inside",
            geofence: {
              id: geofence.id,
              name: geofence.name,
              type: geofence.type,
            },
          });
        }
      }

      // Check speed alerts
      const speedAlert =
        speed > 120 ? { exceeded: true, speed, limit: 120 } : null;

      res.json({
        success: true,
        received: true,
        geofenceEvents,
        speedAlert,
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * @swagger
 * /api/tracking/eta:
 *   post:
 *     summary: Calculate ETA to delivery location
 *     tags: [Tracking]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - driverId
 *               - destinationLat
 *               - destinationLng
 *     responses:
 *       200:
 *         description: Estimated time to arrival
 */
predictions.post(
  "/tracking/eta",
  [
    body("driverId").notEmpty().withMessage("Driver ID is required"),
    body("destinationLat")
      .isFloat({ min: -90, max: 90 })
      .withMessage("Valid destination latitude required"),
    body("destinationLng")
      .isFloat({ min: -180, max: 180 })
      .withMessage("Valid destination longitude required"),
  ],
  validate,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { driverId, destinationLat, destinationLng } = req.body;

      // Get current driver location
      const lastLocation = await prisma.locationHistory.findFirst({
        where: { driverId },
        orderBy: { timestamp: "desc" },
      });

      if (!lastLocation) {
        return res
          .status(404)
          .json({ error: "No location history found for driver" });
      }

      // Calculate ETA
      const eta = gpsTracker.calculateETA(
        driverId,
        { lat: destinationLat, lng: destinationLng },
        { lat: lastLocation.latitude, lng: lastLocation.longitude },
      );

      res.json({
        success: true,
        data: {
          driverId,
          destination: {
            lat: destinationLat,
            lng: destinationLng,
          },
          currentLocation: {
            lat: lastLocation.latitude,
            lng: lastLocation.longitude,
          },
          estimatedMinutes: eta.estimatedMinutes,
          estimatedArrival: eta.arrival,
          confidence: eta.confidence,
          trafficFactor: eta.trafficFactor,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

/**
 * @swagger
 * /api/tracking/active-drivers:
 *   get:
 *     summary: Get all active drivers for map display
 *     tags: [Tracking]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of active drivers with current locations
 */
predictions.get(
  "/tracking/active-drivers",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const activeDrivers = gpsTracker.getActiveDrivers();

      // Get driver details
      const drivers = await prisma.driver.findMany({
        where: {
          id: { in: activeDrivers.map((d) => d.driverId) },
        },
        include: {
          user: {
            select: {
              firstName: true,
              lastName: true,
              phone: true,
            },
          },
        },
      });

      const result = activeDrivers
        .map((active) => {
          const driver = drivers.find((d) => d.id === active.driverId);
          if (!driver) return null;
          return {
            id: driver.id,
            name: `${driver.user.firstName} ${driver.user.lastName}`,
            phone: driver.user.phone,
            location: active.location,
            speed: active.speed,
            heading: active.heading,
            lastUpdate: active.lastUpdate,
          };
        })
        .filter(Boolean);

      res.json({
        success: true,
        data: {
          drivers: result,
          total: result.length,
          timestamp: new Date(),
        },
      });
    } catch (error) {
      next(error);
    }
  },
);
