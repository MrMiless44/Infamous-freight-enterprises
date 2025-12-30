/**
 * Load testing and stress testing utilities
 */

import { describe, it, expect } from "@jest/globals";
import http from "http";

interface LoadTestResult {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  minResponseTime: number;
  maxResponseTime: number;
  requestsPerSecond: number;
  errors: Array<{ message: string; count: number }>;
}

/**
 * Execute a load test against an endpoint
 */
export async function runLoadTest(
  url: string,
  options: {
    concurrentUsers: number;
    requestsPerUser: number;
    method?: string;
    headers?: Record<string, string>;
    body?: any;
  },
): Promise<LoadTestResult> {
  const {
    concurrentUsers,
    requestsPerUser,
    method = "GET",
    headers = {},
    body,
  } = options;

  const startTime = Date.now();
  const responseTimes: number[] = [];
  const errors: Map<string, number> = new Map();
  let successCount = 0;
  let failCount = 0;

  const makeRequest = async (): Promise<void> => {
    const requestStart = Date.now();
    try {
      const response = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
      });

      const responseTime = Date.now() - requestStart;
      responseTimes.push(responseTime);

      if (response.ok) {
        successCount++;
      } else {
        failCount++;
        const errorKey = `HTTP ${response.status}`;
        errors.set(errorKey, (errors.get(errorKey) || 0) + 1);
      }
    } catch (error) {
      failCount++;
      const errorKey = error instanceof Error ? error.message : "Unknown error";
      errors.set(errorKey, (errors.get(errorKey) || 0) + 1);
      responseTimes.push(Date.now() - requestStart);
    }
  };

  // Create concurrent users
  const userPromises: Promise<void>[] = [];
  for (let u = 0; u < concurrentUsers; u++) {
    const userRequests: Promise<void>[] = [];
    for (let r = 0; r < requestsPerUser; r++) {
      userRequests.push(makeRequest());
    }
    userPromises.push(Promise.all(userRequests).then(() => {}));
  }

  await Promise.all(userPromises);

  const totalTime = Date.now() - startTime;
  const totalRequests = concurrentUsers * requestsPerUser;

  return {
    totalRequests,
    successfulRequests: successCount,
    failedRequests: failCount,
    averageResponseTime:
      responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length,
    minResponseTime: Math.min(...responseTimes),
    maxResponseTime: Math.max(...responseTimes),
    requestsPerSecond: totalRequests / (totalTime / 1000),
    errors: Array.from(errors.entries()).map(([message, count]) => ({
      message,
      count,
    })),
  };
}

describe("Load Testing", () => {
  const BASE_URL = process.env.API_BASE_URL || "http://localhost:3001";

  it("should handle moderate load on health endpoint", async () => {
    const result = await runLoadTest(`${BASE_URL}/api/health`, {
      concurrentUsers: 10,
      requestsPerUser: 10,
    });

    expect(result.totalRequests).toBe(100);
    expect(result.successfulRequests).toBeGreaterThan(95);
    expect(result.averageResponseTime).toBeLessThan(500);
    expect(result.requestsPerSecond).toBeGreaterThan(10);
  }, 30000);

  it("should handle stress test on metrics endpoint", async () => {
    const result = await runLoadTest(`${BASE_URL}/api/metrics`, {
      concurrentUsers: 50,
      requestsPerUser: 5,
    });

    expect(result.totalRequests).toBe(250);
    expect(result.failedRequests / result.totalRequests).toBeLessThan(0.05);
    expect(result.averageResponseTime).toBeLessThan(2000);
  }, 60000);

  it("should verify rate limiting works correctly", async () => {
    const result = await runLoadTest(`${BASE_URL}/api/health`, {
      concurrentUsers: 1,
      requestsPerUser: 150,
    });

    expect(result.totalRequests).toBe(150);
    expect(result.errors.some((e) => e.message.includes("429"))).toBe(true);
  }, 30000);
});

/**
 * Run a comprehensive load test suite
 */
export async function runLoadTestSuite(baseUrl: string) {
  console.log("🚀 Starting Load Test Suite...\n");

  const tests = [
    {
      name: "Light Load - Health Check",
      url: `${baseUrl}/api/health`,
      concurrentUsers: 5,
      requestsPerUser: 10,
    },
    {
      name: "Moderate Load - Metrics",
      url: `${baseUrl}/api/metrics`,
      concurrentUsers: 20,
      requestsPerUser: 10,
    },
    {
      name: "Heavy Load - Health Check",
      url: `${baseUrl}/api/health`,
      concurrentUsers: 100,
      requestsPerUser: 5,
    },
  ];

  for (const test of tests) {
    console.log(`\n📊 Running: ${test.name}`);
    console.log(`   Users: ${test.concurrentUsers}`);
    console.log(`   Requests per user: ${test.requestsPerUser}`);

    const result = await runLoadTest(test.url, {
      concurrentUsers: test.concurrentUsers,
      requestsPerUser: test.requestsPerUser,
    });

    console.log(`\n   ✅ Results:`);
    console.log(`      Total: ${result.totalRequests} requests`);
    console.log(`      Success: ${result.successfulRequests}`);
    console.log(`      Failed: ${result.failedRequests}`);
    console.log(
      `      Avg Response: ${Math.round(result.averageResponseTime)}ms`,
    );
    console.log(`      RPS: ${Math.round(result.requestsPerSecond)}`);

    if (result.errors.length > 0) {
      console.log(`\n   ⚠️  Errors:`);
      result.errors.forEach((err) => {
        console.log(`      ${err.message}: ${err.count}`);
      });
    }
  }

  console.log("\n✨ Load Test Suite Complete!");
}
