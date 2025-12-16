# Authentication Error Codes Reference

This document provides a comprehensive reference for all authentication error codes returned by the API.

## JWT Token Error Codes

### TOKEN_EXPIRED
**Status Code**: 401 Unauthorized  
**Error**: "Token expired"  
**Message**: "Your session has expired. Please log in again."

**Cause**: The JWT token has exceeded its expiration time (1 hour default)

**Client Action**: Request a new token by logging in again

**Example Response**:
```json
{
  "error": "Token expired",
  "message": "Your session has expired. Please log in again.",
  "code": "TOKEN_EXPIRED"
}
```

---

### INVALID_TOKEN
**Status Code**: 401 Unauthorized  
**Error**: "Invalid token"  
**Message**: "Authentication token is invalid."

**Causes**:
- Token signature is invalid
- Token was tampered with
- Token format is malformed
- Wrong secret key used to verify

**Client Action**: Check token format and ensure it's properly signed. Request a new token if needed.

**Example Response**:
```json
{
  "error": "Invalid token",
  "message": "Authentication token is invalid.",
  "code": "INVALID_TOKEN"
}
```

---

### TOKEN_NOT_ACTIVE
**Status Code**: 401 Unauthorized  
**Error**: "Token not yet valid"  
**Message**: "This token cannot be used yet."

**Cause**: Token's "not before" (nbf) claim is in the future

**Client Action**: Wait until the token becomes valid or request a new token

**Example Response**:
```json
{
  "error": "Token not yet valid",
  "message": "This token cannot be used yet.",
  "code": "TOKEN_NOT_ACTIVE"
}
```

---

### AUTH_ERROR
**Status Code**: 401 Unauthorized  
**Error**: "Authentication failed"  
**Message**: "Unable to verify authentication token."

**Cause**: Unexpected error during token verification (catch-all)

**Client Action**: Request a new token. If issue persists, contact support.

**Example Response**:
```json
{
  "error": "Authentication failed",
  "message": "Unable to verify authentication token.",
  "code": "AUTH_ERROR"
}
```

---

## API Key Error Codes

### Missing API Key
**Status Code**: 401 Unauthorized  
**Error**: "Missing API key"  
**Message**: "X-API-Key header is required"

**Cause**: X-API-Key header not provided

**Client Action**: Include X-API-Key header in request

---

### Invalid API Key
**Status Code**: 401 Unauthorized  
**Error**: "Invalid API key"  
**Message**: "The provided API key is not valid"

**Cause**: X-API-Key header value doesn't match configured key

**Client Action**: Verify API key is correct

---

## General Authentication Errors

### Missing Bearer Token
**Status Code**: 401 Unauthorized  
**Error**: "Missing bearer token"  
**Message**: "Authorization header with Bearer token is required"

**Cause**: Authorization header missing or doesn't start with "Bearer "

**Client Action**: Include Authorization header with format: `Bearer <token>`

---

### Unauthorized
**Status Code**: 401 Unauthorized  
**Error**: "Unauthorized"  
**Message**: "Missing or invalid authentication credentials"

**Cause**: No valid authentication method provided (hybrid auth only)

**Client Action**: Provide either valid Bearer token or X-API-Key header

---

### Insufficient Scope
**Status Code**: 403 Forbidden  
**Error**: "Insufficient scope"

**Cause**: User doesn't have required permissions (scope)

**Client Action**: Request proper permissions or use account with required access

---

### Authentication Not Configured
**Status Code**: 500 Internal Server Error  
**Error**: "Authentication not configured"

**Cause**: JWT_SECRET environment variable not set (server misconfiguration)

**Client Action**: Contact system administrator

---

## Usage in Client Code

### JavaScript/TypeScript Example

```typescript
async function handleAuthError(response: Response) {
  const data = await response.json();
  
  switch (data.code) {
    case 'TOKEN_EXPIRED':
      // Redirect to login or refresh token
      await refreshAuthToken();
      break;
      
    case 'INVALID_TOKEN':
      // Clear invalid token and redirect to login
      clearAuthToken();
      redirectToLogin();
      break;
      
    case 'TOKEN_NOT_ACTIVE':
      // Wait and retry or get new token
      await new Promise(resolve => setTimeout(resolve, 1000));
      return retryRequest();
      
    case 'AUTH_ERROR':
    default:
      // Request new token
      redirectToLogin();
      break;
  }
}
```

### React Example

```typescript
import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

function useAuthErrorHandler() {
  const navigate = useNavigate();
  
  useEffect(() => {
    const handleResponse = async (response: Response) => {
      if (response.status === 401) {
        const data = await response.json();
        
        if (data.code === 'TOKEN_EXPIRED') {
          // Show message and redirect
          toast.error(data.message);
          navigate('/login');
        }
      }
    };
    
    // Set up global fetch interceptor
    // ... implementation
  }, [navigate]);
}
```

---

## Best Practices

1. **Always include error codes** - Check for `code` field in error responses
2. **Implement token refresh** - Don't wait for TOKEN_EXPIRED, refresh proactively
3. **Log error codes** - Track authentication failures for security monitoring
4. **Clear invalid tokens** - Remove tokens that return INVALID_TOKEN
5. **Retry strategy** - Implement exponential backoff for AUTH_ERROR

---

## Server-Side Logging

All authentication errors are logged with appropriate severity:

- **WARN**: Invalid tokens, expired tokens (expected user behavior)
- **ERROR**: Unexpected errors, missing configuration

Example log output:
```
WARN: Token expired - attempt from IP: 192.168.1.1
WARN: Invalid JWT token: jwt malformed
ERROR: Unexpected JWT verification error: secret must be provided
```

---

## Related Documentation

- [JWT Authentication Guide](../README.md#jwt-authentication)
- [API Key Setup](../README.md#api-key-authentication)
- [Security Middleware](./security.js)
- [Hybrid Authentication](./auth.hybrid.js)
