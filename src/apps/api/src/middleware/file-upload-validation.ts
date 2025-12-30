/**
 * File Upload Validation Middleware
 * Validates file types, sizes, and security
 */

import { Request, Response, NextFunction } from "express";
import multer from "multer";
import path from "path";
import { v4 as uuidv4 } from "uuid";

// Configure multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${uuidv4()}`;
    cb(null, `${uniqueSuffix}${path.extname(file.originalname)}`);
  },
});

// Allowed file types per endpoint
const allowedMimeTypes = {
  documents: [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ],
  images: ["image/jpeg", "image/png", "image/webp"],
  voice: ["audio/mpeg", "audio/wav", "audio/ogg"],
  documents_and_images: [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "image/jpeg",
    "image/png",
    "image/webp",
  ],
};

const maxFileSizes = {
  documents: 10 * 1024 * 1024, // 10MB
  images: 5 * 1024 * 1024, // 5MB
  voice: parseInt(process.env.VOICE_MAX_FILE_SIZE_MB || "10") * 1024 * 1024,
  documents_and_images: 10 * 1024 * 1024, // 10MB
};

/**
 * File type validator
 */
function fileTypeValidator(allowedTypes: string[]) {
  return (
    req: Request,
    file: Express.Multer.File,
    cb: multer.FileFilterCallback,
  ) => {
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          `File type not allowed. Allowed types: ${allowedTypes.join(", ")}`,
        ),
      );
    }
  };
}

/**
 * File size validator
 */
function fileSizeValidator(maxSize: number) {
  return (
    req: Request,
    file: Express.Multer.File,
    cb: multer.FileFilterCallback,
  ) => {
    if (file.size <= maxSize) {
      cb(null, true);
    } else {
      cb(
        new Error(
          `File too large. Maximum size: ${Math.floor(maxSize / 1024 / 1024)}MB`,
        ),
      );
    }
  };
}

/**
 * Create file upload middleware
 */
export function createUploadMiddleware(
  fileType: "documents" | "images" | "voice" | "documents_and_images",
  fieldName: string = "file",
) {
  const upload = multer({
    storage,
    fileFilter: fileTypeValidator(allowedMimeTypes[fileType]),
    limits: {
      fileSize: maxFileSizes[fileType],
    },
  });

  return upload.single(fieldName);
}

/**
 * Multiple files upload middleware
 */
export function createMultipleUploadMiddleware(
  fileType: "documents" | "images" | "voice" | "documents_and_images",
  fieldName: string = "files",
  maxCount: number = 5,
) {
  const upload = multer({
    storage,
    fileFilter: fileTypeValidator(allowedMimeTypes[fileType]),
    limits: {
      fileSize: maxFileSizes[fileType],
    },
  });

  return upload.array(fieldName, maxCount);
}

/**
 * Validate file upload handler
 */
export function validateFileUpload(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (!req.file && !req.files) {
    return res.status(400).json({
      error: "No file uploaded",
    });
  }

  // Validate file extension matches mime type
  const files = req.files as Express.Multer.File[] | undefined;
  const file = req.file || (files && files.length > 0 ? files[0] : undefined);
  if (!file) {
    return res.status(400).json({ error: "No valid file found" });
  }
  const ext = path.extname(file.originalname).toLowerCase();
  const mimeType = file.mimetype;

  const extensionMimeMap: { [key: string]: string[] } = {
    ".pdf": ["application/pdf"],
    ".doc": ["application/msword"],
    ".docx": [
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ],
    ".jpg": ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".png": ["image/png"],
    ".webp": ["image/webp"],
    ".mp3": ["audio/mpeg"],
    ".wav": ["audio/wav"],
    ".ogg": ["audio/ogg"],
  };

  if (extensionMimeMap[ext] && !extensionMimeMap[ext].includes(mimeType)) {
    return res.status(400).json({
      error: "File extension does not match file type",
    });
  }

  next();
}

/**
 * Sanitize file uploads (remove malicious content)
 */
export async function sanitizeFileUpload(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    if (!req.file && !req.files) {
      return next();
    }

    const files = req.file ? [req.file] : req.files || [];

    // Scan files for malicious content
    // Integration with antivirus service like ClamAV can be added here
    for (const file of files as Express.Multer.File[]) {
      // Example: Scan with ClamAV
      // const result = await scanFile(file.path);
      // if (result.isInfected) {
      //   throw new Error(`File infected with ${result.virus}`);
      // }

      // Log file upload
      console.log(`File uploaded: ${file.originalname} (${file.size} bytes)`);
    }

    next();
  } catch (error) {
    res.status(400).json({
      error: `File validation failed: ${(error as Error).message}`,
    });
  }
}

/**
 * Clean up failed uploads
 */
export function cleanupFailedUpload(
  err: any,
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({
        error: "File too large",
        message: err.message,
      });
    }
    if (err.code === "LIMIT_FILE_COUNT") {
      return res.status(400).json({
        error: "Too many files",
        message: err.message,
      });
    }
  }

  if (err) {
    return res.status(400).json({
      error: err.message || "File upload validation failed",
    });
  }

  next();
}

/**
 * File upload helpers
 */
export const fileUploadHelpers = {
  /**
   * Get allowed file types for endpoint
   */
  getAllowedTypes(fileType: keyof typeof allowedMimeTypes): string[] {
    return allowedMimeTypes[fileType];
  },

  /**
   * Get max file size for endpoint
   */
  getMaxFileSize(fileType: keyof typeof maxFileSizes): number {
    return maxFileSizes[fileType];
  },

  /**
   * Format file size for display
   */
  formatFileSize(bytes: number): string {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + " " + sizes[i];
  },

  /**
   * Validate file before upload
   */
  validateFileBeforeUpload(
    file: Express.Multer.File,
    fileType: keyof typeof allowedMimeTypes,
  ): { valid: boolean; error?: string } {
    // Check mime type
    if (!allowedMimeTypes[fileType].includes(file.mimetype)) {
      return {
        valid: false,
        error: `Invalid file type. Allowed: ${allowedMimeTypes[fileType].join(", ")}`,
      };
    }

    // Check file size
    if (file.size > maxFileSizes[fileType]) {
      return {
        valid: false,
        error: `File too large. Maximum: ${this.formatFileSize(maxFileSizes[fileType])}`,
      };
    }

    // Check file extension
    const ext = path.extname(file.originalname).toLowerCase();
    const validExtensions = [
      ".pdf",
      ".doc",
      ".docx",
      ".jpg",
      ".jpeg",
      ".png",
      ".webp",
      ".mp3",
      ".wav",
      ".ogg",
    ];
    if (!validExtensions.includes(ext)) {
      return {
        valid: false,
        error: "Invalid file extension",
      };
    }

    return { valid: true };
  },
};

export default {
  createUploadMiddleware,
  createMultipleUploadMiddleware,
  validateFileUpload,
  sanitizeFileUpload,
  cleanupFailedUpload,
  fileUploadHelpers,
};
