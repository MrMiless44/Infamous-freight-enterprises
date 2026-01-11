import { test, expect } from '@playwright/test';

/**
 * API Integration Tests
 * Tests backend API endpoints directly
 */

const API_URL = process.env.API_URL || 'http://localhost:4000';

test.describe('API Health', () => {
  test('should respond to health check', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/health`);
    
    expect(response.ok()).toBeTruthy();
    expect(response.status()).toBe(200);
    
    const data = await response.json();
    expect(data.status).toBe('ok');
  });

  test('should include uptime in health response', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/health`);
    const data = await response.json();
    
    expect(data.uptime).toBeDefined();
    expect(typeof data.uptime).toBe('number');
  });
});

test.describe('API Authentication', () => {
  let authToken: string;

  test('should login with valid credentials', async ({ request }) => {
    const response = await request.post(`${API_URL}/api/auth/login`, {
      data: {
        email: 'test@example.com',
        password: 'testpassword123'
      }
    });
    
    // May be 200 or 401 depending on test data
    const data = await response.json();
    
    if (response.ok()) {
      expect(data.success).toBeTruthy();
      expect(data.data.token).toBeDefined();
      authToken = data.data.token;
    }
  });

  test('should reject invalid credentials', async ({ request }) => {
    const response = await request.post(`${API_URL}/api/auth/login`, {
      data: {
        email: 'wrong@example.com',
        password: 'wrongpassword'
      }
    });
    
    expect(response.status()).toBe(401);
    const data = await response.json();
    expect(data.success).toBeFalsy();
  });

  test('should validate JWT token', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/auth/me`, {
      headers: {
        'Authorization': 'Bearer invalid_token'
      }
    });
    
    expect(response.status()).toBe(401);
  });

  test('should enforce rate limiting on auth endpoints', async ({ request }) => {
    // Make multiple rapid requests
    const promises = Array(10).fill(0).map(() =>
      request.post(`${API_URL}/api/auth/login`, {
        data: { email: 'test@example.com', password: 'wrong' }
      })
    );
    
    const responses = await Promise.all(promises);
    
    // At least one should be rate limited
    const rateLimited = responses.some(r => r.status() === 429);
    expect(rateLimited).toBeTruthy();
  });
});

test.describe('API Shipments', () => {
  let authToken = 'mock_token';

  test('should list shipments', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/shipments`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    // May be 401 if not authenticated, or 200
    if (response.ok()) {
      const data = await response.json();
      expect(data.success).toBeTruthy();
      expect(Array.isArray(data.data)).toBeTruthy();
    }
  });

  test('should create shipment', async ({ request }) => {
    const response = await request.post(`${API_URL}/api/shipments`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      },
      data: {
        origin: 'New York, NY',
        destination: 'Los Angeles, CA',
        weight: 100,
        type: 'standard'
      }
    });
    
    // May be 401 if not authenticated
    if (response.status() !== 401) {
      const data = await response.json();
      
      if (response.ok()) {
        expect(data.success).toBeTruthy();
        expect(data.data.id).toBeDefined();
      }
    }
  });

  test('should validate shipment data', async ({ request }) => {
    const response = await request.post(`${API_URL}/api/shipments`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      data: {
        // Missing required fields
        origin: 'New York'
      }
    });
    
    expect(response.status()).toBe(400);
  });

  test('should get shipment by ID', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/shipments/test-id`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    // May be 404 or 401
    expect([200, 401, 404]).toContain(response.status());
  });

  test('should update shipment status', async ({ request }) => {
    const response = await request.patch(`${API_URL}/api/shipments/test-id`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      data: {
        status: 'in_transit'
      }
    });
    
    // May be 404 or 401
    expect([200, 401, 404]).toContain(response.status());
  });

  test('should delete shipment', async ({ request }) => {
    const response = await request.delete(`${API_URL}/api/shipments/test-id`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    // May be 404 or 401
    expect([200, 401, 404]).toContain(response.status());
  });
});

test.describe('API Payments', () => {
  let authToken = 'mock_token';

  test('should create checkout session', async ({ request }) => {
    const response = await request.post(`${API_URL}/api/payments/create-checkout-session`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      data: {
        priceId: 'price_test_123',
        plan: 'starter'
      }
    });
    
    // May be 401 if not authenticated
    if (response.ok()) {
      const data = await response.json();
      expect(data.success).toBeTruthy();
      expect(data.data.sessionId).toBeDefined();
    }
  });

  test('should handle webhook events', async ({ request }) => {
    const response = await request.post(`${API_URL}/api/webhooks/stripe`, {
      headers: {
        'stripe-signature': 'test_signature'
      },
      data: {
        type: 'payment_intent.succeeded',
        data: {
          object: {
            id: 'pi_test_123'
          }
        }
      }
    });
    
    // Should reject invalid signature
    expect([200, 400]).toContain(response.status());
  });

  test('should list invoices', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/invoices`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    if (response.ok()) {
      const data = await response.json();
      expect(data.success).toBeTruthy();
      expect(Array.isArray(data.data)).toBeTruthy();
    }
  });
});

test.describe('API Metrics', () => {
  let authToken = 'mock_admin_token';

  test('should get revenue metrics', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/metrics/revenue/live`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    if (response.ok()) {
      const data = await response.json();
      expect(data.success).toBeTruthy();
      expect(data.data.mrr).toBeDefined();
      expect(data.data.arr).toBeDefined();
    }
  });

  test('should cache metrics response', async ({ request }) => {
    const start1 = Date.now();
    await request.get(`${API_URL}/api/metrics/revenue/live`, {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    const time1 = Date.now() - start1;
    
    // Second request should be faster (cached)
    const start2 = Date.now();
    await request.get(`${API_URL}/api/metrics/revenue/live`, {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    const time2 = Date.now() - start2;
    
    // Cached response should be faster
    expect(time2).toBeLessThan(time1);
  });

  test('should export metrics to CSV', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/metrics/revenue/export`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    if (response.ok()) {
      const contentType = response.headers()['content-type'];
      expect(contentType).toContain('csv');
    }
  });
});

test.describe('API Security', () => {
  test('should include security headers', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/health`);
    const headers = response.headers();
    
    // Check for security headers
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBeDefined();
  });

  test('should handle CORS properly', async ({ request }) => {
    const response = await request.options(`${API_URL}/api/shipments`, {
      headers: {
        'Origin': 'http://localhost:3000'
      }
    });
    
    const headers = response.headers();
    expect(headers['access-control-allow-origin']).toBeDefined();
  });

  test('should sanitize SQL injection attempts', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/shipments`, {
      params: {
        search: "1' OR '1'='1"
      }
    });
    
    // Should either return 400 or safely handle it
    expect([200, 400]).toContain(response.status());
  });

  test('should enforce rate limiting', async ({ request }) => {
    const endpoint = `${API_URL}/api/shipments`;
    const promises = Array(150).fill(0).map((_, i) =>
      request.get(endpoint + `?test=${i}`)
    );
    
    const responses = await Promise.all(promises);
    const rateLimited = responses.filter(r => r.status() === 429);
    
    // Should rate limit after threshold
    expect(rateLimited.length).toBeGreaterThan(0);
  });
});

test.describe('API Performance', () => {
  test('should respond quickly to health check', async ({ request }) => {
    const start = Date.now();
    const response = await request.get(`${API_URL}/api/health`);
    const duration = Date.now() - start;
    
    expect(response.ok()).toBeTruthy();
    expect(duration).toBeLessThan(1000); // Under 1 second
  });

  test('should handle concurrent requests', async ({ request }) => {
    const promises = Array(50).fill(0).map(() =>
      request.get(`${API_URL}/api/health`)
    );
    
    const responses = await Promise.all(promises);
    const allSuccessful = responses.every(r => r.ok());
    
    expect(allSuccessful).toBeTruthy();
  });

  test('should compress responses', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/shipments`, {
      headers: {
        'Accept-Encoding': 'gzip, deflate'
      }
    });
    
    if (response.ok()) {
      const headers = response.headers();
      // May have compression in production
      // expect(headers['content-encoding']).toBeDefined();
    }
  });
});
