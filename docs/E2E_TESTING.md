# E2E Testing with Playwright

End-to-End (E2E) tests validate complete user workflows across the entire application stack. This guide explains how to write, run, and maintain E2E tests using Playwright.

## Overview

**What**: Tests that simulate real user interactions (clicking, typing, navigation)  
**Where**: `e2e/tests/` directory  
**How**: Playwright test framework  
**Why**: Catch regressions that unit tests miss, validate full workflows

## Quick Start

### Install Playwright

```bash
npm install -D @playwright/test
npx playwright install
```

### Run Tests Locally

```bash
# Run all tests
npx playwright test

# Run tests in UI mode (interactive)
npx playwright test --ui

# Run specific test file
npx playwright test e2e/tests/auth.spec.js

# Run tests matching pattern
npx playwright test --grep "login"

# Run in debug mode
npx playwright test --debug
```

### View Test Report

```bash
# After running tests
npx playwright show-report
```

## Test Structure

### Authentication Test (`e2e/tests/auth.spec.js`)

Tests the login workflow:

- Landing page loads
- Login page accessible
- Form validation
- Invalid credentials handling
- Successful login
- Session management

### Billing Test (`e2e/tests/billing.spec.js`)

Tests billing functionality:

- Billing page loads
- Payment methods display
- Invoice listing
- Usage information
- Error handling
- Pagination

### Core Features Test (`e2e/tests/core-features.spec.js`)

Tests general application features:

- Dashboard loads
- Data display
- Refresh functionality
- Navigation
- Network error handling
- Performance requirements
- Loading states
- Server error handling

## Writing Tests

### Basic Test Structure

```javascript
import { test, expect } from "@playwright/test";

test.describe("Feature Name", () => {
  test.beforeEach(async ({ page }) => {
    // Setup before each test
    await page.goto("/");
  });

  test("should do something", async ({ page }) => {
    // Test steps
    await page.locator("button").click();

    // Assertions
    await expect(page.locator("text=Success")).toBeVisible();
  });
});
```

### Locating Elements

**Text locators:**

```javascript
page.locator("text=Click me"); // Exact text match
page.locator("text=/click/i"); // Regex match
```

**CSS selectors:**

```javascript
page.locator("button.primary");
page.locator("#submit-button");
page.locator('[data-testid="login-btn"]');
```

**XPath:**

```javascript
page.locator('//button[contains(text(), "Login")]');
```

**Best practice: Use data-testid attributes:**

```html
<!-- In your app -->
<button data-testid="login-button">Login</button>

<!-- In test -->
page.locator('[data-testid="login-button"]')
```

### Common Actions

```javascript
// Navigate
await page.goto("/dashboard");

// Click
await page.locator("button").click();

// Type
await page.locator('input[type="email"]').fill("test@example.com");

// Select
await page.locator("select").selectOption("option1");

// Check checkbox
await page.locator('input[type="checkbox"]').check();

// Uncheck checkbox
await page.locator('input[type="checkbox"]').uncheck();

// Upload file
await page.locator('input[type="file"]').uploadFile("path/to/file");

// Wait for element
await page.locator("text=Loading...").waitFor();

// Wait for URL
await page.waitForURL("/dashboard");

// Wait for navigation
await page.waitForLoadState("networkidle");
```

### Common Assertions

```javascript
// Visibility
await expect(page.locator("text=Success")).toBeVisible();
await expect(page.locator("text=Error")).not.toBeVisible();

// Text content
await expect(page.locator("h1")).toHaveText("Dashboard");
await expect(page.locator("p")).toContainText("Welcome");

// Input value
await expect(page.locator("input")).toHaveValue("john@example.com");

// Attribute
await expect(page.locator("button")).toHaveAttribute("disabled");

// CSS class
await expect(page.locator("div")).toHaveClass("active");

// Count
await expect(page.locator("li")).toHaveCount(3);

// URL
await expect(page).toHaveURL("/dashboard");
await expect(page).toHaveTitle("Dashboard");

// Element enabled/disabled
await expect(page.locator("button")).toBeEnabled();
await expect(page.locator("button")).toBeDisabled();
```

## Environment Setup

### Required Environment Variables

```bash
# .env.test
TEST_EMAIL=test@example.com
TEST_PASSWORD=your-test-password
BASE_URL=http://localhost:3000
```

For CI/CD, set these as GitHub Secrets:

```
Settings → Secrets and variables → Actions
TEST_EMAIL
TEST_PASSWORD
```

## Test Data Management

### Option 1: Use Test User Account

Create a dedicated test user in your database:

```sql
INSERT INTO users (email, password, name)
VALUES ('test@example.com', 'hashed_password', 'Test User');
```

### Option 2: API Setup

Use API calls to setup test data:

```javascript
test.beforeEach(async ({ request }) => {
  // Create test order via API
  await request.post('/api/orders', {
    data: {
      items: [...],
      total: 100
    }
  });
});
```

### Option 3: Database Reset

Reset test database before running tests:

```bash
npm run db:reset:test
```

## Best Practices

### 1. Use Page Object Model (For Large Test Suites)

```javascript
// pages/LoginPage.js
export class LoginPage {
  constructor(page) {
    this.page = page;
    this.emailInput = page.locator('input[type="email"]');
    this.passwordInput = page.locator('input[type="password"]');
    this.submitButton = page.locator('button[type="submit"]');
  }

  async login(email, password) {
    await this.emailInput.fill(email);
    await this.passwordInput.fill(password);
    await this.submitButton.click();
  }
}

// In test
test("should login", async ({ page }) => {
  const loginPage = new LoginPage(page);
  await loginPage.login("test@example.com", "password");
  await expect(page).toHaveURL("/dashboard");
});
```

### 2. Test Critical User Flows Only

Focus on:

- Authentication
- Payments/Billing
- Data operations (create, read, update, delete)
- Error cases

Skip:

- Minor UI changes
- Styling details
- Individual component interaction (use unit tests instead)

### 3. Use Meaningful Assertions

❌ Bad:

```javascript
await page.waitForTimeout(1000); // Never use arbitrary waits
```

✅ Good:

```javascript
await page.locator("text=Loading...").waitFor(); // Wait for element
await page.waitForLoadState("networkidle"); // Wait for network
```

### 4. Handle Flakiness

```javascript
// Retry on specific errors
test("should handle flaky network", async ({ page }) => {
  try {
    await page.goto("/dashboard");
  } catch {
    // Retry once
    await page.reload();
  }
});

// Use proper timeouts
test("should load data", async ({ page }) => {
  await expect(page.locator('[data-testid="data"]')).toBeVisible({
    timeout: 10000,
  }); // 10 seconds
});
```

## CI/CD Integration

Tests run automatically in GitHub Actions on:

- Every push to `main` or `develop`
- Every pull request
- Daily schedule (2 AM UTC)

### Viewing Results

1. Go to GitHub Actions tab
2. Select "E2E Tests" workflow
3. Click on latest run
4. Check results per browser (Chromium, Firefox, WebKit)
5. Download artifacts for detailed reports

### Debugging Failed Tests

```bash
# Run failed test locally
npx playwright test --grep "failing test name" --debug

# Run with video recording
npx playwright test --video on

# Run with trace recording
npx playwright test --trace on
```

## Adding New Tests

### Step 1: Create Test File

```bash
mkdir -p e2e/tests
touch e2e/tests/feature.spec.js
```

### Step 2: Write Test

```javascript
import { test, expect } from "@playwright/test";

test.describe("Feature", () => {
  test("should do something", async ({ page }) => {
    // Test implementation
  });
});
```

### Step 3: Run Test

```bash
npx playwright test e2e/tests/feature.spec.js
```

### Step 4: Commit

```bash
git add e2e/tests/feature.spec.js
git commit -m "test: add feature E2E tests"
git push
```

## Performance Testing

Tests track these metrics:

- Page load time (should be < 3 seconds)
- API response time
- Memory usage
- CSS/JavaScript parsing time

If tests fail due to performance:

1. Review browser console for errors
2. Check network tab for slow requests
3. Profile with DevTools (`page.pause()` in debug mode)

## Troubleshooting

### Tests Timeout

**Problem**: Tests take too long  
**Solution**: Increase timeout in playwright.config.js

```javascript
timeout: 60000,  // 60 seconds
```

### Login Fails in CI

**Problem**: Tests fail during login  
**Solution**: Verify TEST_EMAIL and TEST_PASSWORD are set in GitHub Secrets

### Flaky Tests

**Problem**: Tests pass sometimes, fail other times  
**Solution**:

- Wait for elements explicitly (not timeouts)
- Avoid hardcoded delays
- Check for race conditions

### Elements Not Found

**Problem**: `page.locator()` can't find element  
**Solution**:

- Add `data-testid` attributes to elements
- Use `page.pause()` to debug
- Run in headed mode: `npx playwright test --headed`

## Resources

- [Playwright Documentation](https://playwright.dev)
- [Playwright Best Practices](https://playwright.dev/docs/best-practices)
- [Debugging Tests](https://playwright.dev/docs/debug)
- [Test Reports](https://playwright.dev/docs/test-reporters)

---

**Last Updated**: December 13, 2025  
**Status**: Production-ready  
**Maintenance**: Add tests for new features before deployment
