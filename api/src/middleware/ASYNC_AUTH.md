# Async Authentication Middleware

## Overview

All authentication middleware functions have been converted to `async` functions for better flexibility and future extensibility.

## Updated Functions

### 1. authHybrid (Hybrid Authentication)
```javascript
async function authHybrid(req, res, next) {
  // Supports both API key and JWT token authentication
  // Now async for potential database lookups
}
```

### 2. apiKeyAuth (API Key Only)
```javascript
async function apiKeyAuth(req, res, next) {
  // API key validation
  // Can now perform async key validation from database
}
```

### 3. jwtAuth (JWT Only)
```javascript
async function jwtAuth(req, res, next) {
  // JWT token validation
  // Can now check token revocation list asynchronously
}
```

### 4. authenticate (Legacy/Basic JWT)
```javascript
async function authenticate(req, res, next) {
  // Basic JWT authentication
  // Now async for consistency
}
```

## Benefits of Async

### 1. **Database Lookups**
```javascript
async function authHybrid(req, res, next) {
  // Can now check if user is active in database
  if (req.auth.mode === "jwt") {
    const user = await prisma.user.findUnique({
      where: { id: req.auth.subject }
    });
    
    if (!user || !user.isActive) {
      return res.status(401).json({ 
        error: "User inactive",
        code: "USER_INACTIVE" 
      });
    }
  }
  
  next();
}
```

### 2. **Token Revocation Check**
```javascript
async function jwtAuth(req, res, next) {
  // Verify token not in revocation list
  const decoded = jwt.verify(token, JWT_SECRET, {...});
  
  const isRevoked = await redis.get(`revoked:${decoded.jti}`);
  if (isRevoked) {
    return res.status(401).json({ 
      error: "Token revoked",
      code: "TOKEN_REVOKED" 
    });
  }
  
  req.user = decoded;
  next();
}
```

### 3. **Rate Limiting by User**
```javascript
async function authenticate(req, res, next) {
  const decoded = jwt.verify(token, secret, { maxAge: "1h" });
  
  // Check user-specific rate limits
  const rateLimitKey = `ratelimit:${decoded.sub}`;
  const count = await redis.incr(rateLimitKey);
  
  if (count > 1000) {
    return res.status(429).json({ 
      error: "Rate limit exceeded for user" 
    });
  }
  
  req.user = decoded;
  next();
}
```

### 4. **Audit Logging**
```javascript
async function authHybrid(req, res, next) {
  // ... authentication logic ...
  
  // Log authentication event asynchronously
  await prisma.authLog.create({
    data: {
      userId: req.auth.subject,
      method: req.auth.mode,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      timestamp: new Date()
    }
  }).catch(err => logger.error('Failed to log auth event', err));
  
  next();
}
```

### 5. **External API Validation**
```javascript
async function apiKeyAuth(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  
  // Validate with external service
  try {
    const isValid = await validateApiKeyWithExternalService(apiKey);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid API key" });
    }
  } catch (err) {
    logger.error('API key validation failed', err);
    return res.status(500).json({ error: "Validation service unavailable" });
  }
  
  req.auth = { mode: "api-key", ... };
  next();
}
```

## Usage Examples

### Basic Usage (No Change)
```javascript
const { authHybrid } = require('./middleware/auth.hybrid');

// Works exactly the same as before
router.post('/api/data', authHybrid, async (req, res) => {
  // Your route handler
});
```

### With Try-Catch (Recommended for Route Handlers)
```javascript
router.post('/api/users', authHybrid, async (req, res, next) => {
  try {
    // Your async operations
    const user = await createUser(req.body);
    res.json(user);
  } catch (err) {
    next(err);
  }
});
```

### Chaining Multiple Async Middleware
```javascript
const checkUserStatus = async (req, res, next) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user.sub }
  });
  
  if (user.status !== 'active') {
    return res.status(403).json({ error: 'Account inactive' });
  }
  
  req.userDetails = user;
  next();
};

router.get('/api/profile', 
  jwtAuth,           // async
  checkUserStatus,   // async
  async (req, res) => {
    res.json(req.userDetails);
  }
);
```

## Error Handling

Async middleware errors are automatically caught by Express 5+ or can be handled with async error wrapper:

### With Async Error Wrapper
```javascript
const asyncHandler = fn => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// Wrap middleware if needed
router.use('/api', asyncHandler(authHybrid));
```

### Or use express-async-errors package
```javascript
// At the top of server.js
require('express-async-errors');

// Now all async errors are caught automatically
```

## Migration Notes

### No Breaking Changes
- All existing synchronous code still works
- Functions are now async-ready for future enhancements
- No changes needed in route handlers

### Future Enhancements Enabled
✅ Database user validation  
✅ Token revocation checks  
✅ Redis-based rate limiting  
✅ Audit logging  
✅ External API validation  
✅ Multi-factor authentication checks  

## Performance Considerations

- **Current Impact**: None - functions return immediately if no async operations
- **Future**: Add caching for database lookups to minimize latency
- **Best Practice**: Keep authentication fast (<100ms)

## Testing

Tests continue to work as before:

```javascript
describe('authHybrid', () => {
  it('should authenticate with valid token', async () => {
    const token = jwt.sign({ sub: 'user123' }, secret);
    req.headers.authorization = `Bearer ${token}`;
    
    await authHybrid(req, res, next);
    
    expect(next).toHaveBeenCalled();
    expect(req.auth).toBeDefined();
  });
});
```

## Related Files

- [api/src/middleware/auth.hybrid.js](auth.hybrid.js)
- [api/src/middleware/security.js](security.js)
- [api/src/tests/middleware/auth.hybrid.test.js](../tests/middleware/auth.hybrid.test.js)
