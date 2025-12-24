const request = require("supertest");
const app = require("../../server");
const { prisma } = require("../../db/prisma");

describe("Health Route", () => {
  beforeEach(() => {
    prisma.$queryRaw.mockReset();
    prisma.$queryRaw.mockResolvedValue([{ ok: 1 }]);
  });

  test("returns ok with database connected", async () => {
    const res = await request(app).get("/api/health");

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.database).toBe("connected");
    expect(res.body).toHaveProperty("timestamp");
    expect(res.body).toHaveProperty("uptime");
    expect(res.body.databaseLatencyMs).toEqual(expect.any(Number));
  });

  test("returns degraded when database check fails", async () => {
    prisma.$queryRaw.mockRejectedValueOnce(new Error("db down"));

    const res = await request(app).get("/api/health");

    expect(res.status).toBe(503);
    expect(res.body.status).toBe("degraded");
    expect(res.body.database).toBe("disconnected");
    expect(res.body.databaseLatencyMs).toBeNull();
  });
});
