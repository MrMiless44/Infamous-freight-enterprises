/**
 * AWS S3 Object Storage Integration
 * Store media files (photos, documents, videos) in S3 instead of database
 * 22x cheaper than database storage, faster retrieval
 */

import AWS from "aws-sdk";
import multer from "multer";
import multerS3 from "multer-s3";
import { Request, Response, Router } from "express";
import { authenticate } from "./security";

const router = Router();

// Configure S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || "us-east-1",
});

/**
 * Multer S3 storage configuration
 */
const uploadToS3 = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.S3_BUCKET_NAME || "infamous-freight-media",
    contentType: multerS3.AUTO_CONTENT_TYPE,
    metadata: (req, file, cb) => {
      cb(null, {
        userId: req.user?.sub,
        uploadTime: new Date().toISOString(),
      });
    },
    key: (req, file, cb) => {
      const userId = req.user?.sub || "anonymous";
      const timestamp = Date.now();
      const fileName = `${timestamp}-${file.originalname}`;

      // Organize by type and user
      const fileType = file.mimetype.split("/")[0]; // 'image', 'document', 'video', etc.
      const path = `${fileType}/${userId}/${fileName}`;

      cb(null, path);
    },
  }),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB max
  },
  fileFilter: (req, file, cb) => {
    // Validate file types
    const allowedMimes = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "application/pdf",
      "video/mp4",
      "audio/mpeg",
    ];

    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${file.mimetype} not allowed`));
    }
  },
});

/**
 * Upload shipment photo
 */
router.post(
  "/shipments/:shipmentId/photo",
  authenticate,
  uploadToS3.single("photo"),
  async (req: Request, res: Response) => {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const fileUrl = (req.file as any).location;
    const fileKey = (req.file as any).key;

    // Store reference in database
    // await prisma.shipment.update({
    //   where: { id: req.params.shipmentId },
    //   data: { photoUrl: fileUrl, photoKey: fileKey }
    // });

    res.json({
      success: true,
      data: {
        url: fileUrl,
        key: fileKey,
        size: req.file.size,
        contentType: req.file.mimetype,
      },
    });
  },
);

/**
 * Upload multiple files
 */
router.post(
  "/shipments/:shipmentId/documents",
  authenticate,
  uploadToS3.array("documents", 10), // Max 10 files
  (req: Request, res: Response) => {
    const files = req.files as Express.Multer.File[];

    if (!files || files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    const uploadedFiles = files.map((file: any) => ({
      url: file.location,
      key: file.key,
      name: file.originalname,
      size: file.size,
      contentType: file.mimetype,
    }));

    res.json({
      success: true,
      data: uploadedFiles,
    });
  },
);

/**
 * Generate presigned URL for temporary access
 * Allows temporary download without exposing S3 directly
 */
router.get(
  "/media/:shipmentId/photo/presigned-url",
  authenticate,
  async (req: Request, res: Response) => {
    const photoKey = req.query.key as string;

    if (!photoKey) {
      return res.status(400).json({ error: "Photo key required" });
    }

    try {
      const presignedUrl = s3.getSignedUrl("getObject", {
        Bucket: process.env.S3_BUCKET_NAME || "infamous-freight-media",
        Key: photoKey,
        Expires: 3600, // 1 hour
      });

      res.json({
        success: true,
        data: {
          url: presignedUrl,
          expiresIn: 3600,
        },
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to generate presigned URL" });
    }
  },
);

/**
 * Delete file from S3
 */
router.delete(
  "/media/:shipmentId/photo",
  authenticate,
  async (req: Request, res: Response) => {
    const photoKey = req.query.key as string;

    if (!photoKey) {
      return res.status(400).json({ error: "Photo key required" });
    }

    try {
      await s3
        .deleteObject({
          Bucket: process.env.S3_BUCKET_NAME || "infamous-freight-media",
          Key: photoKey,
        })
        .promise();

      // Update database to remove reference
      // await prisma.shipment.update({
      //   where: { id: req.params.shipmentId },
      //   data: { photoUrl: null, photoKey: null }
      // });

      res.json({
        success: true,
        message: "File deleted successfully",
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete file" });
    }
  },
);

/**
 * Get S3 bucket statistics
 */
router.get(
  "/admin/storage/stats",
  authenticate,
  async (req: Request, res: Response) => {
    try {
      const bucketName = process.env.S3_BUCKET_NAME || "infamous-freight-media";

      // List all objects in bucket
      const objects = await s3
        .listObjectsV2({
          Bucket: bucketName,
        })
        .promise();

      const totalSize =
        objects.Contents?.reduce((sum, obj) => sum + (obj.Size || 0), 0) || 0;
      const totalObjects = objects.Contents?.length || 0;

      res.json({
        success: true,
        data: {
          bucket: bucketName,
          totalObjects,
          totalSizeGB: (totalSize / 1024 / 1024 / 1024).toFixed(2),
          estimatedCostPerMonth: (
            (totalSize / 1024 / 1024 / 1024) *
            0.023
          ).toFixed(2), // $0.023/GB
        },
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to get storage stats" });
    }
  },
);

export default router;

/**
 * Cost comparison with database storage:
 *
 * Database (PostgreSQL): $0.50/GB/month
 * S3 Standard: $0.023/GB/month
 * S3 Glacier: $0.004/GB/month (for archival)
 *
 * 100GB of photos:
 * - Database: $50/month
 * - S3: $2.30/month
 * - Savings: $47.70/month (95% cheaper!)
 *
 * Setup:
 *
 * 1. Create S3 bucket:
 *    aws s3 mb s3://infamous-freight-media --region us-east-1
 *
 * 2. Enable versioning (optional):
 *    aws s3api put-bucket-versioning \
 *      --bucket infamous-freight-media \
 *      --versioning-configuration Status=Enabled
 *
 * 3. Enable lifecycle policy (archive old files):
 *    {
 *      "Rules": [
 *        {
 *          "Id": "ArchiveOldFiles",
 *          "Status": "Enabled",
 *          "Transitions": [
 *            {
 *              "Days": 30,
 *              "StorageClass": "GLACIER"
 *            }
 *          ]
 *        }
 *      ]
 *    }
 *
 * 4. Environment variables:
 *    AWS_ACCESS_KEY_ID=...
 *    AWS_SECRET_ACCESS_KEY=...
 *    AWS_REGION=us-east-1
 *    S3_BUCKET_NAME=infamous-freight-media
 */
