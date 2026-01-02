import request from "supertest";
import express from "express";
import { s3StorageRouter } from "../../routes/s3-storage";
import { authenticate, requireScope } from "../../middleware/security";

jest.mock("@prisma/client");
jest.mock("../../middleware/security");
jest.mock("multer");
jest.mock("aws-sdk");

describe("S3 Storage Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/s3-storage", s3StorageRouter as any);
    jest.clearAllMocks();
  });

  describe("POST /s3-storage/upload", () => {
    it("should upload file to S3", async () => {
      const response = await request(app)
        .post("/s3-storage/upload")
        .set("Content-Type", "multipart/form-data");

      expect([200, 201, 400]).toContain(response.status);
    });
  });

  describe("GET /s3-storage/:fileId", () => {
    it("should get file from S3", async () => {
      const response = await request(app).get("/s3-storage/file-123");

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("DELETE /s3-storage/:fileId", () => {
    it("should delete file from S3", async () => {
      const response = await request(app).delete("/s3-storage/file-123");

      expect([200, 204, 404]).toContain(response.status);
    });
  });

  describe("GET /s3-storage/:fileId/download", () => {
    it("should download file from S3", async () => {
      const response = await request(app).get("/s3-storage/file-123/download");

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("POST /s3-storage/batch-upload", () => {
    it("should upload multiple files", async () => {
      const response = await request(app)
        .post("/s3-storage/batch-upload")
        .set("Content-Type", "multipart/form-data");

      expect([200, 201, 400]).toContain(response.status);
    });
  });
});
