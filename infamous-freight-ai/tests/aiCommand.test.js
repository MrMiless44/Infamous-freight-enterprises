const request = require("supertest");
const app = require("../src/server");

describe("AI Command", () => {
    it("rejects unauthorized", async () => {
        const res = await request(app).post("/ai/command").send({ command: "ping" });
        expect(res.statusCode).toBe(401);
    });
});
