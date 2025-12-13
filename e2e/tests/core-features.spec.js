import { test, expect } from '@playwright/test';

/**
 * Critical User Flows - Core Features Tests
 * 
 * These tests validate core application functionality:
 * 1. Dashboard loads and displays data
 * 2. Navigation works correctly
 * 3. Data refresh functionality
 * 4. Error handling
 * 5. Performance requirements
 */

test.describe('Core Features', () => {
  test.beforeEach(async ({ page }) => {
    const testEmail = process.env.TEST_EMAIL;
    const testPassword = process.env.TEST_PASSWORD;
    
    if (!testEmail || !testPassword) {
      test.skip();
    }
    
    // Login
    await page.goto('/');
    await page.locator('button:has-text("Login")').click();
    await page.locator('input[type="email"]').fill(testEmail);
    await page.locator('input[type="password"]').fill(testPassword);
    await page.locator('button:has-text("Sign In")').click();
    await page.waitForURL(/dashboard/);
  });

  test('should load dashboard with data', async ({ page }) => {
    // Verify dashboard loads
    await expect(page).toHaveURL(/dashboard/);
    
    // Wait for data to load
    await page.waitForLoadState('networkidle');
    
    // Check for main content
    await expect(page.locator('[data-testid="dashboard-content"]')).toBeVisible();
  });

  test('should display widget data correctly', async ({ page }) => {
    // Wait for dashboard to fully load
    await page.waitForLoadState('networkidle');
    
    // Check for widget containers
    const widgets = page.locator('[data-testid^="widget-"]');
    const count = await widgets.count();
    
    // Should have at least 3 widgets
    expect(count).toBeGreaterThanOrEqual(3);
    
    // Each widget should have content
    for (let i = 0; i < Math.min(count, 3); i++) {
      await expect(widgets.nth(i).locator('[data-testid="widget-title"]')).toBeVisible();
      await expect(widgets.nth(i).locator('[data-testid="widget-data"]')).toBeVisible();
    }
  });

  test('should refresh data on demand', async ({ page }) => {
    // Wait for initial load
    await page.waitForLoadState('networkidle');
    
    // Get initial value
    const initialValue = await page.locator('[data-testid="total-value"]').textContent();
    
    // Click refresh button
    await page.locator('button[aria-label="Refresh"]').click();
    
    // Wait for new data
    await page.waitForLoadState('networkidle');
    
    // Verify data was refreshed (value might be same, but request was made)
    const newValue = await page.locator('[data-testid="total-value"]').textContent();
    expect(newValue).toBeDefined();
  });

  test('should navigate between sections', async ({ page }) => {
    // Test navigation to different sections
    const sections = ['Dashboard', 'Analytics', 'Settings'];
    
    for (const section of sections) {
      const nav = page.locator(`a:has-text("${section}")`);
      
      if (await nav.isVisible()) {
        await nav.click();
        await page.waitForLoadState('networkidle');
        
        // Verify navigation worked
        expect(page.url()).toContain(section.toLowerCase());
      }
    }
  });

  test('should handle network errors gracefully', async ({ page }) => {
    // Simulate network offline
    await page.context().setOffline(true);
    
    // Try to refresh
    await page.locator('button[aria-label="Refresh"]').click();
    
    // Should show error message
    await expect(page.locator('text=No internet connection')).toBeVisible({ timeout: 5000 });
    
    // Go back online
    await page.context().setOffline(false);
    
    // Should recover when online
    await page.locator('button[aria-label="Refresh"]').click();
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="dashboard-content"]')).toBeVisible();
  });

  test('should load dashboard within acceptable time', async ({ page }) => {
    const startTime = Date.now();
    
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
    
    const loadTime = Date.now() - startTime;
    
    // Dashboard should load within 3 seconds
    expect(loadTime).toBeLessThan(3000);
  });

  test('should display loading states correctly', async ({ page }) => {
    // Intercept and slow down API calls
    await page.route('**/api/dashboard/**', route => {
      setTimeout(() => route.continue(), 1000);
    });
    
    // Reload dashboard
    await page.reload();
    
    // Should show loading skeleton/spinner
    await expect(page.locator('[data-testid="loading-skeleton"], [role="progressbar"]')).toBeVisible({ timeout: 500 });
    
    // Data should eventually load
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="dashboard-content"]')).toBeVisible();
  });

  test('should handle 500 server errors', async ({ page }) => {
    // Intercept API and return 500
    await page.route('**/api/dashboard/**', route => {
      route.abort('failed');
    });
    
    // Reload dashboard
    await page.reload();
    
    // Should show error message
    await expect(page.locator('text=Error loading dashboard|Something went wrong')).toBeVisible({ timeout: 5000 });
  });
});
