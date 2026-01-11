// Payment Flow E2E Tests with Playwright
// Prevents payment bugs before they cost customers
// Tests complete checkout journey including error handling

const { test, expect } = require('@playwright/test');

// Test configuration
const TEST_BASE_URL = process.env.TEST_URL || 'http://localhost:3000';
const API_BASE_URL = process.env.API_URL || 'http://localhost:3001';

// Test data
const TEST_USERS = {
  newCustomer: {
    email: 'test.new@example.com',
    name: 'Test New Customer',
  },
  existingStarter: {
    email: 'test.starter@example.com',
    sessionToken: 'mock-starter-session',
  },
  existingPro: {
    email: 'test.pro@example.com',
    sessionToken: 'mock-pro-session',
  },
};

const STRIPE_TEST_CARDS = {
  success: '4242424242424242',
  declined: '4000000000000002',
  insufficient: '4000000000009995',
  expired: '4000000000000069',
  requires3ds: '4000002500003155',
};

test.describe('Payment Flow - Complete Checkout Journey', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to pricing page before each test
    await page.goto(`${TEST_BASE_URL}/pricing`);
    await expect(page).toHaveURL(/\/pricing/);
  });

  test('should display all pricing tiers correctly', async ({ page }) => {
    // Verify all 4 tiers are visible
    await expect(page.locator('[data-testid="starter-tier"]')).toBeVisible();
    await expect(page.locator('[data-testid="pro-tier"]')).toBeVisible();
    await expect(page.locator('[data-testid="business-tier"]')).toBeVisible();
    await expect(page.locator('[data-testid="enterprise-tier"]')).toBeVisible();

    // Verify pricing
    await expect(page.locator('[data-testid="starter-price"]')).toContainText('$29');
    await expect(page.locator('[data-testid="pro-price"]')).toContainText('$99');
    await expect(page.locator('[data-testid="business-price"]')).toContainText('$299');
    
    // Verify annual discount display
    await expect(page.locator('[data-testid="annual-discount"]')).toContainText('17%');
  });

  test('should complete successful checkout for Pro tier', async ({ page }) => {
    // Select Pro tier
    await page.click('[data-testid="pro-tier-button"]');
    
    // Should navigate to checkout
    await expect(page).toHaveURL(/\/checkout/);
    await expect(page.locator('[data-testid="checkout-header"]'))
      .toContainText('Pro Plan - $99/month');

    // Fill customer information
    await page.fill('[data-testid="email"]', TEST_USERS.newCustomer.email);
    await page.fill('[data-testid="name"]', TEST_USERS.newCustomer.name);

    // Fill payment information
    await page.fill('[data-testid="card-number"]', STRIPE_TEST_CARDS.success);
    await page.fill('[data-testid="card-expiry"]', '12/28');
    await page.fill('[data-testid="card-cvc"]', '123');
    await page.fill('[data-testid="card-zip"]', '12345');

    // Accept terms
    await page.check('[data-testid="terms-checkbox"]');

    // Submit payment
    await page.click('[data-testid="submit-payment"]');

    // Wait for processing
    await expect(page.locator('[data-testid="payment-processing"]'))
      .toBeVisible({ timeout: 5000 });

    // Wait for success
    await expect(page.locator('[data-testid="success-message"]'))
      .toBeVisible({ timeout: 15000 });
    
    // Verify success details
    await expect(page.locator('[data-testid="success-message"]'))
      .toContainText('Payment successful');
    
    // Verify subscription ID is present
    const subscriptionId = await page.getAttribute(
      '[data-testid="subscription-id"]',
      'data-subscription-id'
    );
    expect(subscriptionId).toBeTruthy();
    expect(subscriptionId).toMatch(/^sub_/);

    // Verify redirect to dashboard
    await page.waitForURL(/\/dashboard/, { timeout: 10000 });
    await expect(page.locator('[data-testid="welcome-message"]')).toBeVisible();
  });

  test('should handle card decline gracefully', async ({ page }) => {
    await page.click('[data-testid="pro-tier-button"]');
    
    // Fill with declined card
    await page.fill('[data-testid="email"]', TEST_USERS.newCustomer.email);
    await page.fill('[data-testid="name"]', TEST_USERS.newCustomer.name);
    await page.fill('[data-testid="card-number"]', STRIPE_TEST_CARDS.declined);
    await page.fill('[data-testid="card-expiry"]', '12/28');
    await page.fill('[data-testid="card-cvc"]', '123');
    await page.check('[data-testid="terms-checkbox"]');

    await page.click('[data-testid="submit-payment"]');

    // Should show error message
    await expect(page.locator('[data-testid="error-message"]'))
      .toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="error-message"]'))
      .toContainText(/declined|failed/i);

    // Should suggest PayPal alternative
    await expect(page.locator('[data-testid="try-paypal"]')).toBeVisible();
    
    // Should allow retry
    await expect(page.locator('[data-testid="retry-button"]')).toBeVisible();
    
    // Payment form should still be visible
    await expect(page.locator('[data-testid="card-number"]')).toBeVisible();
  });

  test('should handle insufficient funds error', async ({ page }) => {
    await page.click('[data-testid="business-tier-button"]');
    
    await page.fill('[data-testid="email"]', TEST_USERS.newCustomer.email);
    await page.fill('[data-testid="card-number"]', STRIPE_TEST_CARDS.insufficient);
    await page.fill('[data-testid="card-expiry"]', '12/28');
    await page.fill('[data-testid="card-cvc"]', '123');
    await page.check('[data-testid="terms-checkbox"]');

    await page.click('[data-testid="submit-payment"]');

    // Should show specific error
    await expect(page.locator('[data-testid="error-message"]'))
      .toContainText(/insufficient funds/i);
    
    // Should not create subscription
    const apiResponse = await page.evaluate(() => 
      fetch('/api/payments/subscription/latest').then(r => r.json())
    );
    expect(apiResponse.subscription).toBeFalsy();
  });

  test('should validate form inputs', async ({ page }) => {
    await page.click('[data-testid="pro-tier-button"]');

    // Try to submit empty form
    await page.click('[data-testid="submit-payment"]');

    // Should show validation errors
    await expect(page.locator('[data-testid="email-error"]'))
      .toContainText('Email is required');
    await expect(page.locator('[data-testid="card-error"]'))
      .toContainText('Card number is required');

    // Test invalid email
    await page.fill('[data-testid="email"]', 'invalid-email');
    await page.blur('[data-testid="email"]');
    await expect(page.locator('[data-testid="email-error"]'))
      .toContainText('Invalid email');

    // Test invalid card
    await page.fill('[data-testid="card-number"]', '1234');
    await page.blur('[data-testid="card-number"]');
    await expect(page.locator('[data-testid="card-error"]'))
      .toContainText('Invalid card number');
  });

  test('should support annual billing with discount', async ({ page }) => {
    await page.click('[data-testid="pro-tier-button"]');

    // Toggle to annual billing
    await page.click('[data-testid="annual-toggle"]');

    // Should show discounted price
    await expect(page.locator('[data-testid="total-amount"]'))
      .toContainText('$987'); // $99 * 12 * 0.83 (17% off)
    
    await expect(page.locator('[data-testid="savings-display"]'))
      .toContainText('Save $201');

    // Complete checkout
    await page.fill('[data-testid="email"]', TEST_USERS.newCustomer.email);
    await page.fill('[data-testid="card-number"]', STRIPE_TEST_CARDS.success);
    await page.fill('[data-testid="card-expiry"]', '12/28');
    await page.fill('[data-testid="card-cvc"]', '123');
    await page.check('[data-testid="terms-checkbox"]');
    await page.click('[data-testid="submit-payment"]');

    // Verify annual subscription created
    await expect(page.locator('[data-testid="success-message"]'))
      .toBeVisible({ timeout: 15000 });
    await expect(page.locator('[data-testid="billing-cycle"]'))
      .toContainText('Annual');
  });
});

test.describe('Subscription Management', () => {
  test('should allow subscription upgrade', async ({ page, context }) => {
    // Mock logged-in Starter customer
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingStarter.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing`);
    
    // Click upgrade button
    await page.click('[data-testid="upgrade-button"]');

    // Should show upgrade modal with tier options
    await expect(page.locator('[data-testid="upgrade-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="upgrade-to-pro"]')).toBeVisible();
    await expect(page.locator('[data-testid="upgrade-to-business"]')).toBeVisible();

    // Select Pro tier upgrade
    await page.click('[data-testid="upgrade-to-pro"]');

    // Should show prorated amount
    const proratedText = await page.textContent('[data-testid="prorated-amount"]');
    expect(proratedText).toMatch(/\$\d+/);
    
    // Should explain proration
    await expect(page.locator('[data-testid="proration-explanation"]'))
      .toContainText('prorated');

    // Confirm upgrade
    await page.click('[data-testid="confirm-upgrade"]');

    // Wait for success
    await expect(page.locator('[data-testid="upgrade-success"]'))
      .toBeVisible({ timeout: 10000 });

    // Verify new plan is active
    await expect(page.locator('[data-testid="current-plan"]'))
      .toContainText('Pro');
    await expect(page.locator('[data-testid="plan-price"]'))
      .toContainText('$99');
  });

  test('should allow subscription downgrade', async ({ page, context }) => {
    // Mock Pro customer
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingPro.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing`);
    
    // Click downgrade
    await page.click('[data-testid="manage-plan"]');
    await page.click('[data-testid="downgrade-to-starter"]');

    // Should show confirmation
    await expect(page.locator('[data-testid="downgrade-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="downgrade-warning"]'))
      .toContainText('lose access');

    // List features that will be lost
    await expect(page.locator('[data-testid="lost-features"]')).toBeVisible();

    // Confirm downgrade
    await page.click('[data-testid="confirm-downgrade"]');

    // Should schedule downgrade for end of period
    await expect(page.locator('[data-testid="downgrade-scheduled"]'))
      .toContainText('will change to Starter');
    
    const changeDate = await page.textContent('[data-testid="change-date"]');
    expect(new Date(changeDate)).toBeInstanceOf(Date);
  });

  test('should handle subscription cancellation with retention', async ({ page, context }) => {
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingPro.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing`);
    
    // Start cancellation
    await page.click('[data-testid="cancel-subscription"]');

    // Should show exit survey
    await expect(page.locator('[data-testid="exit-survey"]')).toBeVisible();
    
    // Fill survey
    await page.click('[data-testid="reason-too-expensive"]');
    await page.fill('[data-testid="feedback"]', 'Need a cheaper option');
    await page.click('[data-testid="continue-cancel"]');

    // Should show retention offer
    await expect(page.locator('[data-testid="retention-offer"]')).toBeVisible();
    await expect(page.locator('[data-testid="discount-offer"]'))
      .toContainText('30% off');

    // Decline retention offer
    await page.click('[data-testid="decline-offer"]');

    // Confirm cancellation
    await page.click('[data-testid="confirm-cancel"]');

    // Should maintain access until period end
    await expect(page.locator('[data-testid="cancellation-notice"]'))
      .toContainText('active until');
    
    const accessUntil = await page.textContent('[data-testid="access-until"]');
    const accessDate = new Date(accessUntil);
    expect(accessDate).toBeInstanceOf(Date);
    expect(accessDate.getTime()).toBeGreaterThan(Date.now());

    // Should offer reactivation
    await expect(page.locator('[data-testid="reactivate-button"]')).toBeVisible();
  });

  test('should allow subscription reactivation', async ({ page, context }) => {
    // Mock cancelled subscription
    await context.addCookies([{
      name: 'session',
      value: 'mock-cancelled-session',
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing`);
    
    // Should show cancelled status
    await expect(page.locator('[data-testid="subscription-status"]'))
      .toContainText('Cancelled');

    // Click reactivate
    await page.click('[data-testid="reactivate-button"]');

    // Should confirm reactivation
    await expect(page.locator('[data-testid="reactivate-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-reactivate"]');

    // Should succeed
    await expect(page.locator('[data-testid="reactivate-success"]'))
      .toBeVisible({ timeout: 10000 });
    
    await expect(page.locator('[data-testid="subscription-status"]'))
      .toContainText('Active');
  });
});

test.describe('Payment Method Management', () => {
  test('should allow adding new payment method', async ({ page, context }) => {
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingPro.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing`);
    
    // Add payment method
    await page.click('[data-testid="add-payment-method"]');
    
    await page.fill('[data-testid="new-card-number"]', STRIPE_TEST_CARDS.success);
    await page.fill('[data-testid="new-card-expiry"]', '12/28');
    await page.fill('[data-testid="new-card-cvc"]', '123');
    
    await page.click('[data-testid="save-card"]');

    // Should show success
    await expect(page.locator('[data-testid="card-added-success"]'))
      .toBeVisible();
    
    // Should appear in payment methods list
    await expect(page.locator('[data-testid="payment-methods-list"]'))
      .toContainText('•••• 4242');
  });

  test('should allow setting default payment method', async ({ page, context }) => {
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingPro.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing`);
    
    // Should show multiple payment methods
    const methods = page.locator('[data-testid="payment-method-item"]');
    await expect(methods).toHaveCount(2, { timeout: 5000 });

    // Set second method as default
    await page.click('[data-testid="set-default-1"]');

    // Should show success
    await expect(page.locator('[data-testid="default-updated"]')).toBeVisible();
    
    // Should show default badge
    await expect(page.locator('[data-testid="default-badge-1"]'))
      .toContainText('Default');
  });

  test('should allow removing payment method', async ({ page, context }) => {
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingPro.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing`);
    
    // Remove non-default method
    await page.click('[data-testid="remove-payment-1"]');
    
    // Confirm removal
    await expect(page.locator('[data-testid="confirm-remove-modal"]')).toBeVisible();
    await page.click('[data-testid="confirm-remove"]');

    // Should be removed from list
    await expect(page.locator('[data-testid="payment-method-1"]'))
      .not.toBeVisible({ timeout: 5000 });
  });
});

test.describe('Invoice Management', () => {
  test('should display invoice history', async ({ page, context }) => {
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingPro.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing/invoices`);
    
    // Should show invoice table
    await expect(page.locator('[data-testid="invoices-table"]')).toBeVisible();
    
    // Should have invoice rows
    const invoices = page.locator('[data-testid="invoice-row"]');
    await expect(invoices.first()).toBeVisible();

    // Verify invoice details
    await expect(invoices.first()).toContainText(/\$\d+/); // Amount
    await expect(invoices.first()).toContainText(/\d{4}-\d{2}-\d{2}/); // Date
    await expect(invoices.first()).toContainText(/paid|pending/i); // Status
  });

  test('should allow downloading PDF invoice', async ({ page, context }) => {
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingPro.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing/invoices`);
    
    // Start download
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="download-invoice-0"]'),
    ]);

    // Verify download
    expect(download.suggestedFilename()).toMatch(/invoice.*\.pdf$/i);
    
    // Save and verify file
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('should allow retrying failed payment', async ({ page, context }) => {
    await context.addCookies([{
      name: 'session',
      value: TEST_USERS.existingPro.sessionToken,
      domain: 'localhost',
      path: '/',
    }]);

    await page.goto(`${TEST_BASE_URL}/dashboard/billing/invoices`);
    
    // Find failed invoice
    const failedInvoice = page.locator('[data-testid="invoice-row"]')
      .filter({ hasText: /failed|unpaid/i });
    
    if (await failedInvoice.count() > 0) {
      await failedInvoice.first().locator('[data-testid="retry-payment"]').click();

      // Should show retry modal
      await expect(page.locator('[data-testid="retry-modal"]')).toBeVisible();
      await page.click('[data-testid="confirm-retry"]');

      // Should process retry
      await expect(page.locator('[data-testid="retry-processing"]'))
        .toBeVisible({ timeout: 5000 });
      
      await expect(page.locator('[data-testid="retry-result"]'))
        .toBeVisible({ timeout: 15000 });
    }
  });
});

// Performance tests
test.describe('Performance', () => {
  test('should load pricing page within 3 seconds', async ({ page }) => {
    const startTime = Date.now();
    await page.goto(`${TEST_BASE_URL}/pricing`);
    const loadTime = Date.now() - startTime;
    
    expect(loadTime).toBeLessThan(3000);
  });

  test('should complete checkout within 10 seconds', async ({ page }) => {
    await page.goto(`${TEST_BASE_URL}/pricing`);
    await page.click('[data-testid="pro-tier-button"]');
    
    const startTime = Date.now();
    
    await page.fill('[data-testid="email"]', TEST_USERS.newCustomer.email);
    await page.fill('[data-testid="card-number"]', STRIPE_TEST_CARDS.success);
    await page.fill('[data-testid="card-expiry"]', '12/28');
    await page.fill('[data-testid="card-cvc"]', '123');
    await page.check('[data-testid="terms-checkbox"]');
    await page.click('[data-testid="submit-payment"]');
    
    await expect(page.locator('[data-testid="success-message"]'))
      .toBeVisible({ timeout: 15000 });
    
    const checkoutTime = Date.now() - startTime;
    expect(checkoutTime).toBeLessThan(10000);
  });
});
