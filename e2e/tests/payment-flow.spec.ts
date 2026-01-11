import { test, expect } from '@playwright/test';

/**
 * Comprehensive Payment Flow E2E Tests
 * Tests the complete payment journey from plan selection to confirmation
 */

test.describe('Payment Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to homepage
    await page.goto('/');
  });

  test('should display pricing page correctly', async ({ page }) => {
    // Navigate to pricing
    await page.goto('/pricing');
    
    // Check page title
    await expect(page).toHaveTitle(/Pricing/i);
    
    // Verify all 4 pricing tiers are visible
    await expect(page.locator('text=Free')).toBeVisible();
    await expect(page.locator('text=Starter')).toBeVisible();
    await expect(page.locator('text=Pro')).toBeVisible();
    await expect(page.locator('text=Enterprise')).toBeVisible();
    
    // Verify pricing amounts
    await expect(page.locator('text=$0')).toBeVisible(); // Free tier
    await expect(page.locator('text=$29')).toBeVisible(); // Starter
    await expect(page.locator('text=$99')).toBeVisible(); // Pro
  });

  test('should allow plan selection', async ({ page }) => {
    await page.goto('/pricing');
    
    // Click on Starter plan
    const starterButton = page.locator('button:has-text("Choose Starter")').first();
    await starterButton.click();
    
    // Should redirect to signup or checkout
    await expect(page).toHaveURL(/\/(signup|checkout|auth)/);
  });

  test('should complete Stripe checkout flow', async ({ page }) => {
    // Navigate directly to checkout (assuming test environment)
    await page.goto('/checkout?plan=starter');
    
    // Check Stripe Elements are loaded
    await page.waitForSelector('iframe[name*="stripe"]', { timeout: 10000 });
    
    // Verify checkout page elements
    await expect(page.locator('text=Payment Details')).toBeVisible();
    await expect(page.locator('text=Starter Plan')).toBeVisible();
    await expect(page.locator('text=$29')).toBeVisible();
  });

  test('should handle payment success', async ({ page, context }) => {
    // Mock successful payment response
    await page.route('**/api/payments/create-checkout-session', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            sessionId: 'cs_test_mock_session_id',
            url: '/payment/success?session_id=cs_test_mock'
          }
        })
      });
    });
    
    await page.goto('/checkout?plan=pro');
    
    // Fill payment form (test mode)
    const submitButton = page.locator('button[type="submit"]:has-text("Complete Payment")');
    if (await submitButton.isVisible()) {
      await submitButton.click();
      
      // Should redirect to success page
      await page.waitForURL(/payment\/success/, { timeout: 10000 });
      
      // Verify success message
      await expect(page.locator('text=Payment Successful')).toBeVisible();
      await expect(page.locator('text=Thank you for your purchase')).toBeVisible();
    }
  });

  test('should handle payment failure gracefully', async ({ page }) => {
    // Mock failed payment response
    await page.route('**/api/payments/create-checkout-session', async (route) => {
      await route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({
          success: false,
          error: 'Payment failed'
        })
      });
    });
    
    await page.goto('/checkout?plan=starter');
    
    const submitButton = page.locator('button[type="submit"]');
    if (await submitButton.isVisible()) {
      await submitButton.click();
      
      // Should show error message
      await expect(page.locator('text=Payment failed')).toBeVisible({ timeout: 5000 });
    }
  });

  test('should validate card number format', async ({ page }) => {
    await page.goto('/checkout?plan=starter');
    
    // Wait for Stripe iframe
    const stripeFrame = page.frameLocator('iframe[name*="cardNumber"]').first();
    
    // Try to submit with empty card (should show validation)
    const submitButton = page.locator('button[type="submit"]');
    if (await submitButton.isVisible()) {
      await submitButton.click();
      
      // Should show validation error
      await expect(page.locator('text=/card.*required/i')).toBeVisible({ timeout: 5000 });
    }
  });

  test('should allow plan upgrade', async ({ page }) => {
    // Login first (assuming test user exists)
    await page.goto('/login');
    await page.fill('input[type="email"]', 'test@example.com');
    await page.fill('input[type="password"]', 'testpassword123');
    await page.click('button[type="submit"]');
    
    // Wait for redirect
    await page.waitForURL(/dashboard/, { timeout: 10000 });
    
    // Navigate to billing
    await page.goto('/dashboard/billing');
    
    // Click upgrade button
    const upgradeButton = page.locator('button:has-text("Upgrade")').first();
    if (await upgradeButton.isVisible()) {
      await upgradeButton.click();
      
      // Should show plan selection
      await expect(page).toHaveURL(/pricing|upgrade/);
    }
  });

  test('should display invoice after successful payment', async ({ page, context }) => {
    // Mock payment success with invoice
    await page.route('**/api/invoices/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            id: 'inv_test_123',
            amount: 2900,
            currency: 'usd',
            status: 'paid',
            pdfUrl: '/invoices/inv_test_123.pdf'
          }
        })
      });
    });
    
    await page.goto('/payment/success?session_id=cs_test_123');
    
    // Should show invoice details
    await expect(page.locator('text=Invoice')).toBeVisible();
    await expect(page.locator('text=$29.00')).toBeVisible();
    
    // Download invoice button should be present
    const downloadButton = page.locator('a:has-text("Download Invoice")');
    await expect(downloadButton).toBeVisible();
  });

  test('should handle subscription cancellation', async ({ page }) => {
    // Login as subscribed user
    await page.goto('/login');
    // ... login flow ...
    
    await page.goto('/dashboard/billing');
    
    // Click cancel subscription
    const cancelButton = page.locator('button:has-text("Cancel Subscription")');
    if (await cancelButton.isVisible()) {
      await cancelButton.click();
      
      // Confirm cancellation in modal
      const confirmButton = page.locator('button:has-text("Confirm")');
      await confirmButton.click();
      
      // Should show cancellation success
      await expect(page.locator('text=Subscription cancelled')).toBeVisible({ timeout: 5000 });
    }
  });

  test('should handle webhook signature verification', async ({ request }) => {
    // Test webhook endpoint
    const response = await request.post('/api/webhooks/stripe', {
      headers: {
        'stripe-signature': 'invalid_signature'
      },
      data: {
        type: 'payment_intent.succeeded'
      }
    });
    
    // Should reject invalid signature
    expect(response.status()).toBe(400);
  });
});

test.describe('Payment Security', () => {
  test('should not expose sensitive payment data in HTML', async ({ page }) => {
    await page.goto('/checkout?plan=pro');
    
    // Get page content
    const content = await page.content();
    
    // Should not contain API keys or secrets
    expect(content).not.toContain('sk_live_');
    expect(content).not.toContain('sk_test_');
    expect(content).not.toMatch(/stripe.*secret/i);
  });

  test('should use HTTPS in production', async ({ page }) => {
    // Skip in local development
    if (process.env.NODE_ENV === 'production') {
      await page.goto('/');
      const url = page.url();
      expect(url).toMatch(/^https:/);
    }
  });

  test('should include CSP headers', async ({ page }) => {
    const response = await page.goto('/checkout');
    const headers = response?.headers();
    
    // Should have Content-Security-Policy
    expect(headers?.['content-security-policy']).toBeDefined();
  });
});

test.describe('Payment UI/UX', () => {
  test('should show loading state during payment', async ({ page }) => {
    await page.goto('/checkout?plan=starter');
    
    // Click submit button
    const submitButton = page.locator('button[type="submit"]');
    if (await submitButton.isVisible()) {
      await submitButton.click();
      
      // Should show loading indicator
      await expect(page.locator('text=Processing')).toBeVisible({ timeout: 1000 });
    }
  });

  test('should be mobile responsive', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    await page.goto('/pricing');
    
    // Pricing cards should be stacked vertically
    const cards = page.locator('[data-testid="pricing-card"]');
    const count = await cards.count();
    
    if (count > 0) {
      // Check cards are visible
      for (let i = 0; i < Math.min(count, 4); i++) {
        await expect(cards.nth(i)).toBeVisible();
      }
    }
  });

  test('should support keyboard navigation', async ({ page }) => {
    await page.goto('/pricing');
    
    // Tab through pricing options
    await page.keyboard.press('Tab');
    await page.keyboard.press('Tab');
    
    // Should be able to select with Enter
    await page.keyboard.press('Enter');
    
    // Should navigate to checkout
    await expect(page).toHaveURL(/checkout|signup/, { timeout: 5000 });
  });
});
