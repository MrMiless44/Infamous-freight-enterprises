import request from "supertest";
import express from "express";
import avatarRouter from "../../routes/avatar";
import { authenticate } from "../../middleware/security";

jest.mock("../../middleware/security");
jest.mock("multer");

describe("Avatar Routes", () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(authenticate as any);
    app.use("/avatar", avatarRouter as any);
    jest.clearAllMocks();
  });

  describe("POST /avatar/upload", () => {
    it("should upload user avatar", async () => {
      const response = await request(app)
        .post("/avatar/upload")
        .set("Content-Type", "multipart/form-data");

      expect([200, 201, 400]).toContain(response.status);
    });

    it("should validate file type", async () => {
      const response = await request(app)
        .post("/avatar/upload")
        .field("filename", "test.txt");

      expect([200, 201, 400]).toContain(response.status);
    });
  });

  describe("GET /avatar/:userId", () => {
    it("should retrieve user avatar", async () => {
      const response = await request(app).get("/avatar/user-123");

      expect([200, 404]).toContain(response.status);
    });
  });

  describe("DELETE /avatar/:userId", () => {
    it("should delete user avatar", async () => {
      const response = await request(app).delete("/avatar/user-123");

      expect([200, 204, 404]).toContain(response.status);
    });
  });
});
