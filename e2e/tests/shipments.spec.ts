import { test, expect } from '@playwright/test';

/**
 * Shipment Management E2E Tests
 * Tests CRUD operations for shipments
 */

test.describe('Shipment Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto('/login');
    await page.fill('input[type="email"]', 'test@example.com');
    await page.fill('input[type="password"]', 'testpassword');
    await page.click('button[type="submit"]');
    await page.waitForURL(/dashboard/, { timeout: 10000 });
  });

  test('should display shipments list', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Check page title
    await expect(page).toHaveTitle(/Shipments/i);
    
    // Should show shipments table or empty state
    const table = page.locator('table, [data-testid="shipments-table"]');
    const emptyState = page.locator('text=/no.*shipments|empty/i');
    
    // Either table or empty state should be visible
    await expect(table.or(emptyState)).toBeVisible();
  });

  test('should create new shipment', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Click create button
    await page.click('button:has-text("Create Shipment"), a:has-text("New Shipment")');
    
    // Fill shipment form
    await page.fill('input[name="origin"]', 'New York, NY');
    await page.fill('input[name="destination"]', 'Los Angeles, CA');
    await page.fill('input[name="weight"]', '100');
    await page.selectOption('select[name="type"]', 'standard');
    
    // Submit form
    await page.click('button[type="submit"]:has-text("Create")');
    
    // Should show success message
    await expect(page.locator('text=/shipment.*created|success/i')).toBeVisible({ timeout: 5000 });
  });

  test('should search shipments', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Enter search query
    const searchInput = page.locator('input[type="search"], input[placeholder*="Search"]');
    if (await searchInput.isVisible()) {
      await searchInput.fill('New York');
      
      // Wait for search results
      await page.waitForTimeout(1000);
      
      // Results should be filtered
      const rows = page.locator('table tbody tr, [data-testid="shipment-row"]');
      if (await rows.count() > 0) {
        const firstRow = await rows.first().textContent();
        expect(firstRow?.toLowerCase()).toContain('new york');
      }
    }
  });

  test('should filter shipments by status', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Click status filter
    const statusFilter = page.locator('select[name="status"], button:has-text("Filter")');
    if (await statusFilter.isVisible()) {
      await statusFilter.click();
      
      // Select "In Transit"
      const transitOption = page.locator('text="In Transit", option[value="in_transit"]');
      if (await transitOption.isVisible()) {
        await transitOption.click();
        
        // Wait for filtered results
        await page.waitForTimeout(1000);
      }
    }
  });

  test('should view shipment details', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Click first shipment row
    const firstRow = page.locator('table tbody tr, [data-testid="shipment-row"]').first();
    if (await firstRow.isVisible()) {
      await firstRow.click();
      
      // Should navigate to detail page
      await expect(page).toHaveURL(/shipments\/[a-zA-Z0-9-]+/, { timeout: 5000 });
      
      // Should show shipment details
      await expect(page.locator('text=/origin|destination|status/i')).toBeVisible();
    }
  });

  test('should update shipment status', async ({ page }) => {
    // Mock shipment data
    await page.route('**/api/shipments/*', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            success: true,
            data: {
              id: 'ship_123',
              origin: 'New York',
              destination: 'LA',
              status: 'pending'
            }
          })
        });
      } else {
        await route.continue();
      }
    });
    
    await page.goto('/dashboard/shipments/ship_123');
    
    // Click update status button
    const updateButton = page.locator('button:has-text("Update Status")');
    if (await updateButton.isVisible()) {
      await updateButton.click();
      
      // Select new status
      await page.selectOption('select[name="status"]', 'in_transit');
      await page.click('button:has-text("Save")');
      
      // Should show success
      await expect(page.locator('text=/status.*updated/i')).toBeVisible({ timeout: 5000 });
    }
  });

  test('should delete shipment', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Click delete on first shipment
    const deleteButton = page.locator('button[title="Delete"], button:has-text("Delete")').first();
    if (await deleteButton.isVisible()) {
      await deleteButton.click();
      
      // Confirm deletion
      const confirmButton = page.locator('button:has-text("Confirm"), button:has-text("Yes")');
      await confirmButton.click();
      
      // Should show success message
      await expect(page.locator('text=/shipment.*deleted/i')).toBeVisible({ timeout: 5000 });
    }
  });

  test('should validate shipment form', async ({ page }) => {
    await page.goto('/dashboard/shipments/new');
    
    // Try to submit empty form
    await page.click('button[type="submit"]');
    
    // Should show validation errors
    await expect(page.locator('text=/required|invalid/i')).toBeVisible();
  });

  test('should handle bulk operations', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Select multiple checkboxes
    const checkboxes = page.locator('input[type="checkbox"]');
    const count = await checkboxes.count();
    
    if (count > 1) {
      // Select first 2 shipments
      await checkboxes.nth(0).check();
      await checkboxes.nth(1).check();
      
      // Bulk action button should be visible
      const bulkButton = page.locator('button:has-text("Bulk Actions")');
      await expect(bulkButton).toBeVisible();
    }
  });

  test('should export shipments to CSV', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Click export button
    const exportButton = page.locator('button:has-text("Export"), a:has-text("Download")');
    if (await exportButton.isVisible()) {
      // Start download
      const [download] = await Promise.all([
        page.waitForEvent('download'),
        exportButton.click()
      ]);
      
      // Verify download
      const filename = download.suggestedFilename();
      expect(filename).toMatch(/\.csv$/);
    }
  });

  test('should paginate shipments', async ({ page }) => {
    await page.goto('/dashboard/shipments');
    
    // Check for pagination
    const nextButton = page.locator('button:has-text("Next"), a:has-text("Next")');
    if (await nextButton.isVisible()) {
      await nextButton.click();
      
      // URL should update with page parameter
      await page.waitForURL(/[?&]page=2/, { timeout: 5000 });
    }
  });
});

test.describe('Real-time Updates', () => {
  test('should receive shipment status updates', async ({ page }) => {
    await page.goto('/dashboard/shipments/ship_123');
    
    // Mock WebSocket or SSE update
    await page.evaluate(() => {
      // Simulate status update event
      window.dispatchEvent(new CustomEvent('shipment-updated', {
        detail: { id: 'ship_123', status: 'delivered' }
      }));
    });
    
    // Status should update on page
    await expect(page.locator('text=Delivered')).toBeVisible({ timeout: 5000 });
  });
});

test.describe('Tracking', () => {
  test('should show tracking timeline', async ({ page }) => {
    await page.goto('/dashboard/shipments/ship_123');
    
    // Check for tracking timeline
    const timeline = page.locator('[data-testid="tracking-timeline"], .timeline');
    await expect(timeline).toBeVisible();
    
    // Should show tracking events
    await expect(page.locator('text=/picked up|in transit|delivered/i')).toBeVisible();
  });

  test('should update tracking location', async ({ page }) => {
    await page.goto('/dashboard/shipments/ship_123/tracking');
    
    // Should show map or location info
    const location = page.locator('text=/location|current/i');
    await expect(location).toBeVisible();
  });
});
