// @ts-nocheck
import { Router } from "express";
import fs from "fs";
import path from "path";
import multer from "multer";
import rateLimit from "express-rate-limit";
import { getAvatarInsights } from "../avatar/assistant";
import { requireAuth } from "../middleware/auth";

export const avatarRouter = Router();

// Ensure storage directory exists
const uploadsDir = path.join(process.cwd(), "uploads", "avatars");
fs.mkdirSync(uploadsDir, { recursive: true });

// Configure Multer storage
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || ".bin";
    const safeExt = [".png", ".jpg", ".jpeg", ".gif", ".webp"].includes(
      ext.toLowerCase(),
    )
      ? ext
      : ".bin";
    cb(null, `${req.user?.id || "anon"}-${Date.now()}${safeExt}`);
  },
});

const fileFilter: multer.Options["fileFilter"] = (_req, file, cb) => {
  const allowed = ["image/png", "image/jpeg", "image/webp", "image/gif"];
  if (!allowed.includes(file.mimetype)) {
    return cb(new Error("Unsupported file type"));
  }
  cb(null, true);
};

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter,
});

const avatarRateLimit = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 60,
});

avatarRouter.use(requireAuth, avatarRateLimit);

avatarRouter.get("/insights", async (req, res) => {
  const insights = await getAvatarInsights(
    req.user!.id,
    req.user!.organizationId,
  );
  res.json(insights);
});

avatarRouter.post("/upload", upload.single("avatar"), (req, res): void => {
  if (!req.file) {
    res.status(400).json({ error: "No file uploaded" });
    return;
  }

  res.status(201).json({
    message: "Avatar uploaded",
    filename: req.file.filename,
    size: req.file.size,
    mimeType: req.file.mimetype,
  });
});

avatarRouter.get("/:userId", (req, res): void => {
  const { userId } = req.params;
  const files = fs
    .readdirSync(uploadsDir)
    .filter((f) => f.startsWith(`${userId}-`));

  if (files.length === 0) {
    res.status(404).json({ error: "Avatar not found" });
    return;
  }

  const filePath = path.join(uploadsDir, files[0]);
  res.sendFile(filePath);
});

avatarRouter.delete("/:userId", (req, res): void => {
  const { userId } = req.params;
  const files = fs
    .readdirSync(uploadsDir)
    .filter((f) => f.startsWith(`${userId}-`));

  if (files.length === 0) {
    res.status(404).json({ error: "Avatar not found" });
    return;
  }

  for (const file of files) {
    try {
      fs.unlinkSync(path.join(uploadsDir, file));
    } catch (err) {
      res.status(500).json({ error: "Failed to delete avatar" });
      return;
    }
  }

  res.status(204).send();
});

export default avatarRouter;
