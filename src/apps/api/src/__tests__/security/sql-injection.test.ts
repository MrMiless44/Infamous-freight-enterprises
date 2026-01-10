// @ts-nocheck
/**
 * SQL Injection Security Test Suite
 * Tests all critical endpoints for SQL injection vulnerabilities
 */

import request from "supertest";
import app from "../../server";
import prisma from "../../lib/prismaClient";

describe("SQL Injection Security Tests", () => {
  let authToken: string;

  beforeAll(async () => {
    // Get auth token for authenticated endpoints
    const loginRes = await request(app)
      .post("/api/auth/login")
      .send({ email: "test@example.com", password: "testpassword" });
    authToken = loginRes.body.token;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  /**
   * SQL Injection Payloads
   * Based on OWASP testing guide and real-world attack patterns
   */
  const sqlInjectionPayloads = [
    // Classic SQL injection
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'x'='x",
    "admin' --",
    "admin' #",
    "admin'/*",

    // Union-based injection
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT password FROM users--",

    // Boolean-based blind injection
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND '1'='1",
    "' AND '1'='2",

    // Time-based blind injection
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT pg_sleep(5)--",
    "' OR SLEEP(5)--",

    // Stacked queries
    "'; DROP TABLE users--",
    "'; DELETE FROM shipments--",
    "'; UPDATE users SET role='admin'--",

    // Comment-based injection
    "/**/OR/**/1=1",
    "/*!OR*/1=1",
    "#' OR 1=1",

    // Encoding-based injection
    "%27%20OR%201=1--",
    "0x27204F522031=313B2D2D",
    "\\' OR 1=1--",

    // Database-specific payloads
    "' || '1'='1", // PostgreSQL concatenation
    "' || pg_sleep(5)--",
    "'; SELECT version()--",
    "'; SELECT current_user--",

    // Advanced payloads
    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 64--",
    "' AND (SELECT COUNT(*) FROM users) > 0--",
    "'; COPY users TO '/tmp/dump.txt'--",
  ];

  describe("User Authentication Endpoints", () => {
    test.each(sqlInjectionPayloads)(
      "POST /api/auth/login should reject SQL injection: %s",
      async (payload) => {
        const startTime = Date.now();

        const res = await request(app)
          .post("/api/auth/login")
          .send({
            email: payload,
            password: "testpassword",
          })
          .expect((res) => {
            // Should NOT be successful
            expect(res.status).not.toBe(200);

            // Should NOT return database data
            expect(res.body).not.toHaveProperty("users");
            expect(res.body).not.toHaveProperty("password");

            // Response should be fast (not delayed by time-based injection)
            const duration = Date.now() - startTime;
            expect(duration).toBeLessThan(2000);
          });
      },
    );

    test.each(sqlInjectionPayloads)(
      "POST /api/auth/register should reject SQL injection: %s",
      async (payload) => {
        const res = await request(app)
          .post("/api/auth/register")
          .send({
            email: payload,
            password: "testpassword",
            name: "Test User",
          })
          .expect((res) => {
            expect(res.status).not.toBe(200);
            expect(res.body).not.toHaveProperty("users");
          });
      },
    );
  });

  describe("Shipment Endpoints", () => {
    test.each(sqlInjectionPayloads)(
      "GET /api/shipments/:id should reject SQL injection: %s",
      async (payload) => {
        const res = await request(app)
          .get(`/api/shipments/${payload}`)
          .set("Authorization", `Bearer ${authToken}`)
          .expect((res) => {
            expect(res.status).not.toBe(200);
            expect(res.body).not.toHaveProperty("users");
            expect(res.body).not.toHaveProperty("password");
          });
      },
    );

    test.each(sqlInjectionPayloads)(
      "POST /api/shipments should reject SQL injection in body: %s",
      async (payload) => {
        const res = await request(app)
          .post("/api/shipments")
          .set("Authorization", `Bearer ${authToken}`)
          .send({
            origin: payload,
            destination: "Test Destination",
            weight: 100,
          })
          .expect((res) => {
            // Should validate input or return error
            expect([400, 422, 500]).toContain(res.status);
            expect(res.body).not.toHaveProperty("users");
          });
      },
    );

    test.each(sqlInjectionPayloads)(
      "GET /api/shipments?status= should reject SQL injection: %s",
      async (payload) => {
        const res = await request(app)
          .get(`/api/shipments?status=${encodeURIComponent(payload)}`)
          .set("Authorization", `Bearer ${authToken}`)
          .expect((res) => {
            expect(res.body).not.toHaveProperty("users");
            expect(res.body).not.toHaveProperty("password");
          });
      },
    );
  });

  describe("User Management Endpoints", () => {
    test.each(sqlInjectionPayloads)(
      "GET /api/users/:id should reject SQL injection: %s",
      async (payload) => {
        const res = await request(app)
          .get(`/api/users/${payload}`)
          .set("Authorization", `Bearer ${authToken}`)
          .expect((res) => {
            expect(res.status).not.toBe(200);
            expect(res.body).not.toHaveProperty("users");
          });
      },
    );

    test.each(sqlInjectionPayloads)(
      "PUT /api/users/:id should reject SQL injection: %s",
      async (payload) => {
        const res = await request(app)
          .put(`/api/users/${payload}`)
          .set("Authorization", `Bearer ${authToken}`)
          .send({ name: "Updated Name" })
          .expect((res) => {
            expect(res.status).not.toBe(200);
          });
      },
    );

    test.each(sqlInjectionPayloads)(
      "GET /api/users?email= should reject SQL injection: %s",
      async (payload) => {
        const res = await request(app)
          .get(`/api/users?email=${encodeURIComponent(payload)}`)
          .set("Authorization", `Bearer ${authToken}`)
          .expect((res) => {
            expect(res.body).not.toHaveProperty("password");
          });
      },
    );
  });

  describe("Search Endpoints", () => {
    test.each(sqlInjectionPayloads)(
      "GET /api/search?q= should reject SQL injection: %s",
      async (payload) => {
        const res = await request(app)
          .get(`/api/search?q=${encodeURIComponent(payload)}`)
          .set("Authorization", `Bearer ${authToken}`)
          .expect((res) => {
            expect(res.body).not.toHaveProperty("users");
            expect(res.body).not.toHaveProperty("password");
          });
      },
    );
  });

  describe("Billing Endpoints", () => {
    test.each(sqlInjectionPayloads)(
      "GET /api/billing/invoices/:id should reject SQL injection: %s",
      async (payload) => {
        const res = await request(app)
          .get(`/api/billing/invoices/${payload}`)
          .set("Authorization", `Bearer ${authToken}`)
          .expect((res) => {
            expect(res.status).not.toBe(200);
          });
      },
    );
  });

  describe("Time-Based Injection Detection", () => {
    const timingPayloads = [
      "'; SELECT pg_sleep(5)--",
      "' OR pg_sleep(5)--",
      "'; WAITFOR DELAY '00:00:05'--",
    ];

    test.each(timingPayloads)(
      "Should not exhibit timing delays for payload: %s",
      async (payload) => {
        const startTime = Date.now();

        await request(app).post("/api/auth/login").send({
          email: payload,
          password: "testpassword",
        });

        const duration = Date.now() - startTime;

        // Should respond quickly even with sleep injection attempts
        expect(duration).toBeLessThan(2000);
      },
    );
  });

  describe("Parameterized Query Verification", () => {
    test("Should use parameterized queries (Prisma ORM)", async () => {
      // Prisma uses parameterized queries by default
      // This test verifies no raw queries are executed

      const payload = "' OR 1=1--";

      // Mock Prisma to detect raw query usage
      const rawQuerySpy = jest.spyOn(prisma, "$queryRaw");
      const unsafeRawSpy = jest.spyOn(prisma, "$queryRawUnsafe");

      await request(app).post("/api/auth/login").send({
        email: payload,
        password: "testpassword",
      });

      // Should NOT use $queryRawUnsafe (dangerous)
      expect(unsafeRawSpy).not.toHaveBeenCalled();

      // If $queryRaw is used, ensure parameters are properly escaped
      if (rawQuerySpy.mock.calls.length > 0) {
        const calls = rawQuerySpy.mock.calls;
        calls.forEach((call) => {
          // Verify no raw SQL concatenation
          expect(call[0]).not.toContain("' OR");
          expect(call[0]).not.toContain("OR 1=1");
        });
      }

      rawQuerySpy.mockRestore();
      unsafeRawSpy.mockRestore();
    });
  });

  describe("Error Message Leakage", () => {
    test("Should not leak database structure in error messages", async () => {
      const payload = "' UNION SELECT * FROM users--";

      const res = await request(app)
        .get(`/api/shipments/${payload}`)
        .set("Authorization", `Bearer ${authToken}`);

      // Error message should NOT contain:
      const errorMessage = JSON.stringify(res.body).toLowerCase();
      expect(errorMessage).not.toContain("syntax error");
      expect(errorMessage).not.toContain("pg_catalog");
      expect(errorMessage).not.toContain("relation");
      expect(errorMessage).not.toContain("column");
      expect(errorMessage).not.toContain("table");
      expect(errorMessage).not.toContain("prisma");
      expect(errorMessage).not.toContain("postgresql");
    });
  });

  describe("NoSQL Injection (JSON fields)", () => {
    const noSQLPayloads = [
      '{"$gt": ""}',
      '{"$ne": null}',
      '{"$where": "1==1"}',
      '{"$regex": ".*"}',
    ];

    test.each(noSQLPayloads)(
      "Should reject NoSQL injection in JSON fields: %s",
      async (payload) => {
        const res = await request(app)
          .post("/api/shipments")
          .set("Authorization", `Bearer ${authToken}`)
          .send({
            origin: "Test Origin",
            destination: "Test Destination",
            metadata: payload, // JSON field
          })
          .expect((res) => {
            // Should validate or reject
            expect([200, 400, 422]).toContain(res.status);
            if (res.status === 200) {
              // If accepted, verify metadata is properly sanitized
              expect(res.body.data?.metadata).not.toContain("$gt");
              expect(res.body.data?.metadata).not.toContain("$where");
            }
          });
      },
    );
  });
});

/**
 * Manual Testing Instructions
 *
 * Run these tests:
 * ```bash
 * cd src/apps/api
 * pnpm test src/__tests__/security/sql-injection.test.ts
 * ```
 *
 * Expected results:
 * - All tests should PASS
 * - No database errors in logs
 * - No timing delays (< 2s per request)
 * - No sensitive data leaked in responses
 *
 * If any test fails:
 * 1. Review the endpoint code
 * 2. Ensure Prisma ORM is used (not raw SQL)
 * 3. Add input validation middleware
 * 4. Enable sanitization middleware
 * 5. Review error handling (don't leak DB details)
 */
