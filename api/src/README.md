## Quick Commands

```bash
# install pnpm via Corepack (if needed)
corepack enable
corepack prepare pnpm@7.5.1 --activate


```javascript
const { generateToken } = require('./middleware/security');
const { authHybrid, apiKeyAuth, jwtAuth } = require('./middleware/auth.hybrid');
const express = require('express');
const router = express.Router();

const token = generateToken(
  { sub: 'user123', email: 'user@example.com', scopes: ['user:read', 'user:write'] },
  '1h'
);

router.post('/api/data', authHybrid, (req, res) => {
  res.json({ subject: req.auth.subject, mode: req.auth.mode, scopes: req.auth.scopes });
});

router.post('/api/internal', apiKeyAuth, (req, res) => {
  res.json({ ok: true });
});

router.get('/api/profile', jwtAuth, (req, res) => {
  res.json({ user: req.user });
});

// Centralized auth error handler
app.use((err, req, res, next) => {
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'Token expired',
      message: 'Your session has expired. Please log in again.',
      code: 'TOKEN_EXPIRED',
    });
  }
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid token',
      message: 'Authentication token is invalid.',
      code: 'INVALID_TOKEN',
    });
  }
  if (err.name === 'NotBeforeError') {
    return res.status(401).json({
      error: 'Token not yet valid',
      message: 'This token cannot be used yet.',
      code: 'TOKEN_NOT_ACTIVE',
    });
  }
  return res.status(401).json({
    error: 'Authentication failed',
    message: 'Unable to verify authentication token.',
    code: 'AUTH_ERROR',
  });
});
```

Example (client-side error handling):

```javascript
fetch('/api/users', {
  headers: { Authorization: `Bearer ${token}` },
}).then((response) => {
  if (!response.ok) {
    return response.json().then((data) => {
      switch (data.code) {
        case 'TOKEN_EXPIRED':
          return refreshToken();
        case 'INVALID_TOKEN':
          logout();
          break;
        case 'TOKEN_NOT_ACTIVE':
          setTimeout(() => retry(), 1000);
          break;
        default:
          // handle generic auth error
          break;
      }
    });
  }
  return response.json();
});
```
// In server.js
const healthRoutes = require("./api/health");
const config = require("./core/config");
```

## Import Path Reference

### From `server.js`
```javascript
require("./api/health")           // API routes
require("./core/config")          // Configuration
require("./core/swagger")         // API documentation
require("./middleware/logger")    // Middleware
```

### From `api/*.js` (route files)
```javascript
require("../ai/aiSyntheticClient")  // AI services
require("../middleware/security")    // Middleware
require("../middleware/validation")  // Validation
require("../db/prisma")             // Database
```

### From `ai/*.js` (AI services)
```javascript
require("../middleware/logger")   // Logging
require("../core/config")         // Configuration
```

## Migration Notes

### What Changed
1. `routes/` → `api/` - Better reflects RESTful API nature
2. `services/` → `ai/` - Isolated AI-specific logic
3. `config.js`, `swagger.js` → `core/` - Grouped core utilities
4. `__tests__/` → `tests/` - Centralized test organization
5. Added `index.js` files for cleaner imports

### What Stayed the Same
- `middleware/` - Already well-organized
- `db/` - Database layer remains separate
- `server.js` - Entry point at root of src/

## Testing

Tests are now organized by feature area in `tests/`:
```bash
# Run all tests
pnpm test

# Test specific feature
pnpm test tests/api
pnpm test tests/ai
```

## Adding New Code

### Adding a Route
1. Create file in `api/newRoute.js`
2. Export router: `module.exports = router;`
3. Import in `server.js`: `const newRoute = require("./api/newRoute");`
4. Mount route: `app.use("/api", newRoute);`
5. Add to `api/index.js` for centralized exports (optional)

### Adding a Service
1. Create file in appropriate directory (ai/, core/, etc.)
2. Add tests in `tests/<category>/`
3. Export functions/classes
4. Add to directory's `index.js` (optional)

### Adding Middleware
1. Create file in `middleware/newMiddleware.js`
2. Export function(s)
3. Add to `middleware/index.js`
4. Import in routes or `server.js`

## Benefits of This Structure

✅ **Clear separation** - Each directory has distinct purpose  
✅ **Scalable** - Easy to add new features without clutter  
✅ **Testable** - Tests organized by feature, not scattered  
✅ **Maintainable** - Easier to find and update code  
✅ **Professional** - Follows industry best practices  
✅ **Onboarding** - New developers can quickly understand organization  

## Future Enhancements

Consider these improvements as the codebase grows:

1. **Sub-directories in api/**
   ```
   api/
   ├── admin/
   ├── public/
   └── internal/
   ```

2. **Shared utilities**
   ```
   src/
   └── utils/
       ├── validators.js
       ├── formatters.js
       └── helpers.js
   ```

3. **Domain-driven design**
   ```
   src/
   ├── shipments/
   │   ├── routes.js
   │   ├── service.js
   │   └── tests/
   └── users/
       ├── routes.js
       ├── service.js
       └── tests/
   ```

## API Routes

- POST /ai/command
  - Description: Execute an AI command. Defaults to v1; set version via `X-API-Version: v2` for enhanced responses, streaming, and batch endpoints.
  - Auth: `Authorization: Bearer <jwt>` and scope `ai:command`
  - Body (v1): `{ "command": string, "payload?": object, "meta?": object }`
  - Body (v2): `{ "command": string, "payload?": object, "meta?": object, "options?": { timeout?, retryCount?, priority? } }`
  - See also: API versioning at `../API_VERSIONING.md`

- GET /shipments
  - Description: List shipments with optional filters.
  - Auth: `Authorization: Bearer <jwt>` and scope `shipments:read`
  - Query: `status?`, `driverId?`
  - Response: `{ ok: true, shipments: [...] }`

- GET /metrics
  - Description: Prometheus metrics endpoint (text exposition format).
  - Path: `/api/metrics`
  - Notes: Provided by prom-client with `ife_api_` prefix for default metrics.

- POST /auth/login
  - Description: Issue a JWT for authenticated users.
  - Status: Not implemented in this service. Provide a valid Bearer token issued by your identity provider; middleware validates JWTs with 1h max age.
  - See: Authentication section below for token handling

## Authentication

### JWT Authentication

- **Generate JWT** with expiration:
  ```javascript
  generateToken(payload, expiresIn = '1h')
  ```

- **Verify JWT** with max age check:
  ```javascript
  verifyToken(token)
  ```

```javascript
const { generateToken } = require('./middleware/security');

const token = generateToken({
  sub: 'user123',
  email: 'user@example.com',
  scopes: ['user:read', 'user:write']
}, '1h');

const { authHybrid } = require('./middleware/auth.hybrid');

router.post('/api/data', authHybrid, (req, res) => {
  // req.auth contains authentication info
  // req.auth.mode: 'api-key' or 'jwt'
  // req.auth.subject: user id or 'ai-synthetic-engine'
  // req.auth.scopes: array of permission scopes
});

const { apiKeyAuth } = require('./middleware/auth.hybrid');

router.post('/api/internal', apiKeyAuth, (req, res) => {
  // Only allows X-API-Key header authentication
});

const { jwtAuth } = require('./middleware/auth.hybrid');

router.get('/api/profile', jwtAuth, (req, res) => {
  // Only allows Bearer token authentication
  console.log(req.user); // Decoded JWT payload
});

catch (err) {
  // TokenExpiredError - token has expired
  if (err.name === "TokenExpiredError") {
    return res.status(401).json({ 
      error: "Token expired", 
      message: "Your session has expired. Please log in again.",
      code: "TOKEN_EXPIRED"  // ✨ New error code
    });
  }
  
  // JsonWebTokenError - invalid signature or format
  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({ 
      error: "Invalid token", 
      message: "Authentication token is invalid.",
      code: "INVALID_TOKEN"  // ✨ New error code
    });
  }
  
  // NotBeforeError - token not yet valid (nbf claim)
  if (err.name === "NotBeforeError") {
    return res.status(401).json({ 
      error: "Token not yet valid", 
      message: "This token cannot be used yet.",
      code: "TOKEN_NOT_ACTIVE"  // ✨ New error code
    });
  }
  
  // Catch-all for unexpected errors
  return res.status(401).json({ 
    error: "Authentication failed", 
    message: "Unable to verify authentication token.",
    code: "AUTH_ERROR"  // ✨ New error code
  });
}

// Handle auth errors by error code
fetch('/api/users', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```
    return response.json().then(data => {
      switch (data.code) {
        case 'TOKEN_EXPIRED':
          // Refresh token or redirect to login
          return refreshToken();
        case 'INVALID_TOKEN':
          // Clear token and login again
          logout();
          break;
        case 'TOKEN_NOT_ACTIVE':
          // Wait and retry
          setTimeout(() => retry(), 1000);
          break;
      }
    });
  }
  return response.json();
});
```
 
