const express = require("express");
const prisma = require("../db/prisma");
const {
  authenticate,
  requireScope,
  auditLog,
} = require("../middleware/security");

const router = express.Router();

// Get all shipments with optional filtering
router.get(
  "/shipments",
  authenticate,
  requireScope("shipments:read"),
  auditLog,
  async (req, res, next) => {
    try {
      const { status, driverId } = req.query;
      const where = {};

      if (status) where.status = status;
      if (driverId) where.driverId = driverId;

      const shipments = await prisma.shipment.findMany({
        where,
        include: {
          driver: {
            select: {
              id: true,
              name: true,
              phone: true,
              status: true,
            },
          },
        },
        orderBy: {
          createdAt: "desc",
        },
      });

      res.json({ ok: true, shipments });
    } catch (err) {
      next(err);
    }
  },
);

// Get shipment by ID
router.get(
  "/shipments/:id",
  authenticate,
  requireScope("shipments:read"),
  auditLog,
  async (req, res, next) => {
    try {
      const shipment = await prisma.shipment.findUnique({
        where: { id: req.params.id },
        include: {
          driver: {
            select: {
              id: true,
              name: true,
              phone: true,
              status: true,
            },
          },
        },
      });

      if (!shipment) {
        return res.status(404).json({ ok: false, error: "Shipment not found" });
      }

      res.json({ ok: true, shipment });
    } catch (err) {
      next(err);
    }
  },
);

// Create shipment with transaction
router.post(
  "/shipments",
  authenticate,
  requireScope("shipments:write"),
  auditLog,
  async (req, res, next) => {
    try {
      const { reference, origin, destination, driverId } = req.body;

      if (!reference || !origin || !destination) {
        return res.status(400).json({
          ok: false,
          error: "Reference, origin, and destination are required",
        });
      }

      // Use transaction to ensure atomic operation
      const result = await prisma.$transaction(
        async (tx) => {
          const shipment = await tx.shipment.create({
            data: {
              reference,
              origin,
              destination,
              driverId: driverId || null,
              status: "created",
            },
            include: {
              driver: {
                select: {
                  id: true,
                  name: true,
                  phone: true,
                  status: true,
                },
              },
            },
          });

          // Log AI event
          await tx.aiEvent.create({
            data: {
              type: "shipment.created",
              payload: {
                shipmentId: shipment.id,
                reference: shipment.reference,
                origin: shipment.origin,
                destination: shipment.destination,
                userId: req.user?.id,
              },
            },
          });

          return shipment;
        },
        {
          timeout: 30000,
        },
      );

      res.status(201).json({ ok: true, shipment: result });
    } catch (err) {
      if (err.code === "P2002") {
        return res
          .status(409)
          .json({ ok: false, error: "Reference already exists" });
      }
      next(err);
    }
  },
);

// Update shipment status with transaction
router.patch(
  "/shipments/:id",
  authenticate,
  requireScope("shipments:write"),
  auditLog,
  async (req, res, next) => {
    try {
      const { status, driverId } = req.body;
      const updates = {};

      if (status !== undefined) updates.status = status;
      if (driverId !== undefined) updates.driverId = driverId;

      const result = await prisma.$transaction(
        async (tx) => {
          const shipment = await tx.shipment.update({
            where: { id: req.params.id },
            data: updates,
            include: {
              driver: {
                select: {
                  id: true,
                  name: true,
                  phone: true,
                  status: true,
                },
              },
            },
          });

          // Log AI event for status change
          if (status) {
            await tx.aiEvent.create({
              data: {
                type: "shipment.status.changed",
                payload: {
                  shipmentId: shipment.id,
                  reference: shipment.reference,
                  newStatus: status,
                  userId: req.user?.id,
                },
              },
            });
          }

          return shipment;
        },
        {
          timeout: 30000,
        },
      );

      res.json({ ok: true, shipment: result });
    } catch (err) {
      if (err.code === "P2025") {
        return res.status(404).json({ ok: false, error: "Shipment not found" });
      }
      next(err);
    }
  },
);

// Delete shipment
router.delete(
  "/shipments/:id",
  authenticate,
  requireScope("shipments:write"),
  auditLog,
  async (req, res, next) => {
    try {
      await prisma.shipment.delete({
        where: { id: req.params.id },
      });

      res.json({ ok: true, message: "Shipment deleted successfully" });
    } catch (err) {
      if (err.code === "P2025") {
        return res.status(404).json({ ok: false, error: "Shipment not found" });
      }
      next(err);
    }
  },
);

module.exports = router;
