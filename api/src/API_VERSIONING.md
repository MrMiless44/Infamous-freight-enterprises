# API Versioning Guide

## Overview

The Infamous Freight API supports multiple versions to maintain backward compatibility while introducing new features. This document explains the versioning strategy and migration path.

## Current Versions

### v1 (Stable)
- **Status**: Stable, maintained
- **Default**: Yes
- **Features**:
  - Circuit breaker protection
  - Basic error handling
  - Audit logging
  - Single command execution

### v2 (Active Development)
- **Status**: Active, recommended for new integrations
- **Features**:
  - All v1 features
  - Enhanced error responses with retry information
  - Streaming support (Server-Sent Events)
  - Batch command processing
  - Response caching
  - Detailed performance metrics
  - Circuit breaker health in responses

## Version Detection

The API detects version from multiple sources (in priority order):

### 1. Header (Recommended)
```bash
curl -H "X-API-Version: v2" \
  https://api.example.com/api/ai/command
```

### 2. Query Parameter
```bash
curl "https://api.example.com/api/ai/command?version=v2"
```

### 3. Path Prefix
```bash
curl https://api.example.com/api/v2/ai/command
```

### 4. Accept Header
```bash
curl -H "Accept: application/vnd.api.v2+json" \
  https://api.example.com/api/ai/command
```

If no version is specified, **v1** is used by default.

## API Endpoints

### Single Command (Both Versions)

**Endpoint**: `POST /api/ai/command`

**v1 Request**:
```json
{
  "command": "analyze_shipment",
  "payload": {
    "shipmentId": "123"
  },
  "meta": {
    "source": "web"
  }
}
```

**v1 Response**:
```json
{
  "ok": true,
  "response": {
    "result": "analysis data"
  },
  "version": "v1",
  "timestamp": "2025-12-16T10:30:00Z"
}
```

**v2 Request** (with options):
```json
{
  "command": "analyze_shipment",
  "payload": {
    "shipmentId": "123"
  },
  "meta": {
    "source": "web"
  },
  "options": {
    "timeout": 5000,
    "priority": "high",
    "retryCount": 2
  }
}
```

**v2 Response** (enhanced):
```json
{
  "ok": true,
  "data": {
    "result": "analysis data"
  },
  "meta": {
    "version": "v2",
    "timestamp": "2025-12-16T10:30:00Z",
    "duration": 245,
    "requestId": "req_1702728600000"
  },
  "health": {
    "circuitBreakers": {
      "synthetic": "closed",
      "openai": "closed",
      "anthropic": "closed"
    }
  }
}
```

### Streaming (v2 Only)

**Endpoint**: `POST /api/v2/ai/command/stream`

```bash
curl -N -H "Content-Type: application/json" \
  -d '{"command":"analyze","payload":{}}' \
  https://api.example.com/api/v2/ai/command/stream
```

**Response** (Server-Sent Events):
```
event: start
data: {"status":"started","timestamp":"2025-12-16T10:30:00Z"}

event: data
data: {"result":"partial response"}

event: done
data: {"status":"completed","timestamp":"2025-12-16T10:30:05Z"}
```

### Batch Processing (v2 Only)

**Endpoint**: `POST /api/v2/ai/command/batch`

**Request**:
```json
{
  "commands": [
    {
      "command": "analyze_shipment",
      "payload": {"shipmentId": "123"}
    },
    {
      "command": "calculate_route",
      "payload": {"origin": "NYC", "destination": "LA"}
    }
  ],
  "options": {
    "concurrency": 5,
    "stopOnError": false
  }
}
```

**Response**:
```json
{
  "ok": true,
  "data": [
    {
      "index": 0,
      "ok": true,
      "data": {"result": "analysis"},
      "duration": 150
    },
    {
      "index": 1,
      "ok": true,
      "data": {"route": "I-80"},
      "duration": 200
    }
  ],
  "meta": {
    "version": "v2",
    "timestamp": "2025-12-16T10:30:00Z",
    "batchDuration": 250,
    "stats": {
      "total": 2,
      "successful": 2,
      "failed": 0,
      "avgDuration": 175
    }
  }
}
```

## Error Responses

### v1 Error
```json
{
  "ok": false,
  "error": "Command execution failed",
  "timestamp": "2025-12-16T10:30:00Z"
}
```

### v2 Error (Enhanced)
```json
{
  "ok": false,
  "error": {
    "message": "Circuit breaker is OPEN",
    "code": "CIRCUIT_OPEN",
    "type": "CircuitBreakerError",
    "circuitBreaker": {
      "synthetic": "open",
      "openai": "closed",
      "anthropic": "closed"
    },
    "retryAfter": 30
  },
  "meta": {
    "version": "v2",
    "timestamp": "2025-12-16T10:30:00Z",
    "duration": 10,
    "requestId": "req_1702728600000"
  }
}
```

## Migration Guide

### Migrating from v1 to v2

#### 1. Update Request Format

**Before (v1)**:
```javascript
const response = await fetch('/api/ai/command', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    command: 'analyze',
    payload: { data: 'test' }
  })
});
const { ok, response: data } = await response.json();
```

**After (v2)**:
```javascript
const response = await fetch('/api/ai/command', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'X-API-Version': 'v2'  // Add version header
  },
  body: JSON.stringify({
    command: 'analyze',
    payload: { data: 'test' },
    options: {              // Optional v2 features
      timeout: 5000,
      priority: 'high'
    }
  })
});
const { ok, data, meta } = await response.json();
```

#### 2. Update Response Handling

**Before (v1)**:
```javascript
if (json.ok) {
  return json.response;
}
```

**After (v2)**:
```javascript
if (json.ok) {
  // Response data is now in 'data' field
  console.log('Duration:', json.meta.duration);
  console.log('Request ID:', json.meta.requestId);
  return json.data;
}
```

#### 3. Enhanced Error Handling

**v2 Specific**:
```javascript
if (!json.ok) {
  const { error, meta } = json;
  
  // Check for circuit breaker issues
  if (error.code === 'CIRCUIT_OPEN') {
    console.log(`Retry after ${error.retryAfter} seconds`);
    console.log('Circuit states:', error.circuitBreaker);
  }
  
  // Use request ID for support
  console.error('Request ID:', meta.requestId);
}
```

#### 4. Leverage New Features

**Streaming**:
```javascript
const eventSource = new EventSource('/api/v2/ai/command/stream');

eventSource.addEventListener('start', (e) => {
  console.log('Started:', JSON.parse(e.data));
});

eventSource.addEventListener('data', (e) => {
  console.log('Data chunk:', JSON.parse(e.data));
});

eventSource.addEventListener('done', (e) => {
  console.log('Completed:', JSON.parse(e.data));
  eventSource.close();
});
```

**Batch Processing**:
```javascript
const response = await fetch('/api/v2/ai/command/batch', {
  method: 'POST',
  headers: { 
    'Content-Type': 'application/json',
    'X-API-Version': 'v2'
  },
  body: JSON.stringify({
    commands: [
      { command: 'cmd1', payload: {} },
      { command: 'cmd2', payload: {} }
    ],
    options: {
      concurrency: 5
    }
  })
});

const { data, meta } = await response.json();
console.log('Stats:', meta.stats);
```

## Best Practices

### 1. Always Specify Version
```javascript
// Good - explicit version
headers: { 'X-API-Version': 'v2' }

// Avoid - relies on default
headers: {}
```

### 2. Handle Version-Specific Responses
```javascript
function handleResponse(json) {
  if (json.version === 'v2') {
    return json.data;  // v2 format
  } else {
    return json.response;  // v1 format
  }
}
```

### 3. Use Request IDs for Debugging
```javascript
const { meta } = await response.json();
logger.error('Request failed', { requestId: meta.requestId });
```

### 4. Check Circuit Breaker Health
```javascript
if (json.health?.circuitBreakers) {
  const allClosed = Object.values(json.health.circuitBreakers)
    .every(state => state === 'closed');
  
  if (!allClosed) {
    console.warn('Some circuit breakers are open');
  }
}
```

### 5. Use Batch for Multiple Commands
```javascript
// Instead of multiple requests
for (const item of items) {
  await fetch('/api/ai/command', ...);
}

// Use batch
await fetch('/api/v2/ai/command/batch', {
  body: JSON.stringify({
    commands: items.map(item => ({
      command: 'process',
      payload: item
    }))
  })
});
```

## Version Lifecycle

### Deprecation Policy
- Versions are supported for **minimum 12 months** after successor release
- Deprecation warnings sent via `X-API-Deprecated` header
- Sunset date provided via `X-API-Sunset` header

### Checking Deprecation
```javascript
const response = await fetch('/api/ai/command');
if (response.headers.get('X-API-Deprecated')) {
  console.warn('Version deprecated:', 
    response.headers.get('X-API-Deprecation-Message'));
  console.warn('Sunset date:', 
    response.headers.get('X-API-Sunset'));
}
```

## Environment Variables

### v2 Specific Configuration
```bash
# Batch processing limits
AI_MAX_BATCH_SIZE=10
AI_BATCH_CONCURRENCY=5

# Circuit breaker settings (shared)
AI_HTTP_TIMEOUT_MS=8000
```

## Testing

### Test v1 Endpoint
```bash
curl -X POST http://localhost:3001/api/ai/command \
  -H "Content-Type: application/json" \
  -d '{"command":"test","payload":{}}'
```

### Test v2 Endpoint
```bash
curl -X POST http://localhost:3001/api/ai/command \
  -H "Content-Type: application/json" \
  -H "X-API-Version: v2" \
  -d '{"command":"test","payload":{},"options":{"priority":"high"}}'
```

### Test v2 Batch
```bash
curl -X POST http://localhost:3001/api/v2/ai/command/batch \
  -H "Content-Type: application/json" \
  -d '{
    "commands":[
      {"command":"test1","payload":{}},
      {"command":"test2","payload":{}}
    ]
  }'
```

### Test v2 Stream
```bash
curl -N -X POST http://localhost:3001/api/v2/ai/command/stream \
  -H "Content-Type: application/json" \
  -d '{"command":"test","payload":{}}'
```

## Related Files

- [ai/commands/v1/](../ai/commands/v1/) - v1 implementation
- [ai/commands/v2/](../ai/commands/v2/) - v2 implementation
- [middleware/versionDetection.js](../middleware/versionDetection.js) - Version detection logic
- [api/ai.commands.js](../api/ai.commands.js) - Route definitions

## Support

For version-specific issues:
- Check [CIRCUIT_BREAKER.md](CIRCUIT_BREAKER.md) for circuit breaker details
- See [ZOD_VALIDATION.md](middleware/ZOD_VALIDATION.md) for schema validation
- Review [ERROR_CODES.md](ERROR_CODES.md) for error handling
