# Circuit Breaker Pattern for AI Services

## Overview

Circuit breaker pattern implemented using [Opossum](https://nodeshift.dev/opossum/) to protect against cascading failures and provide graceful degradation for AI service calls.

## Configuration

### Circuit Breaker Settings

```javascript
const breakerOptions = {
  timeout: 3000,                  // Request timeout (3 seconds)
  errorThresholdPercentage: 50,   // Open circuit at 50% failure rate
  resetTimeout: 30000,            // Retry after 30 seconds
  rollingCountTimeout: 10000,     // 10-second rolling window
  rollingCountBuckets: 10,        // Statistics granularity
  volumeThreshold: 5              // Min requests before checking percentage
};
```

### What This Means

- **Timeout (3s)**: If AI service doesn't respond within 3 seconds, treat as failure
- **Error Threshold (50%)**: Open circuit if 50% of requests fail in rolling window
- **Reset Timeout (30s)**: Wait 30 seconds before testing if service recovered
- **Volume Threshold (5)**: Need at least 5 requests before calculating failure rate

## Circuit Breaker States

### 🟢 CLOSED (Normal Operation)
- All requests pass through to AI service
- Success and failure counts are tracked
- If error threshold exceeded, transitions to OPEN

### 🔴 OPEN (Service Degraded)
- Requests immediately fail with 503 error
- No requests sent to failing AI service
- After `resetTimeout`, transitions to HALF-OPEN

### 🟡 HALF-OPEN (Testing Recovery)
- Allows one test request through
- If successful, transitions back to CLOSED
- If fails, stays OPEN for another `resetTimeout`

## API Endpoints

### Check Circuit Breaker Status

```bash
GET /api/health/circuit-breakers
```

**Response (Healthy)**:
```json
{
  "status": "healthy",
  "circuitBreakers": {
    "synthetic": {
      "name": "Synthetic-AI-Breaker",
      "state": "closed",
      "stats": {
        "fires": 150,
        "failures": 2,
        "successes": 148,
        "rejects": 0,
        "timeouts": 0
      }
    },
    "openai": {
      "name": "OpenAI-Breaker",
      "state": "closed",
      "stats": { ... }
    },
    "anthropic": {
      "name": "Anthropic-Breaker",
      "state": "closed",
      "stats": { ... }
    }
  },
  "timestamp": "2025-12-16T04:30:00.000Z"
}
```

**Response (Degraded)**:
```json
{
  "status": "degraded",
  "circuitBreakers": {
    "synthetic": {
      "name": "Synthetic-AI-Breaker",
      "state": "open",
      "stats": {
        "fires": 100,
        "failures": 55,
        "successes": 45,
        "rejects": 10,
        "timeouts": 5
      }
    }
  }
}
```

## Error Handling

### Circuit Open Error

When circuit breaker is open, requests receive:

```json
{
  "error": "AI service temporarily unavailable (circuit breaker open)",
  "status": 503,
  "code": "CIRCUIT_OPEN"
}
```

### Client Handling Example

```javascript
try {
  const result = await sendCommand('analyze', { data: '...' });
  console.log(result);
} catch (err) {
  if (err.code === 'CIRCUIT_OPEN') {
    // Circuit breaker is open - use fallback
    console.error('AI service unavailable, using cached response');
    return getCachedResponse();
  }
  // Handle other errors
  throw err;
}
```

## Monitoring & Logging

### Circuit Breaker Events

The system logs all circuit breaker state changes:

**Circuit Opened** (⚠️ WARN):
```
Circuit breaker opened: Synthetic-AI-Breaker
```

**Circuit Half-Open** (ℹ️ INFO):
```
Circuit breaker half-open (testing): Synthetic-AI-Breaker
```

**Circuit Closed** (✅ INFO):
```
Circuit breaker closed (recovered): Synthetic-AI-Breaker
```

**Request Failure** (❌ ERROR):
```
Circuit breaker failure: Synthetic-AI-Breaker
{
  error: "Connection timeout",
  status: 504
}
```

**Request Rejected** (⚠️ WARN):
```
Circuit breaker rejected request: Synthetic-AI-Breaker
```

## Usage

### Standard Usage (With Circuit Breaker)

```javascript
const { sendCommand } = require('./ai/aiSyntheticClient');

// Automatically protected by circuit breaker
const result = await sendCommand('process', { text: 'hello' });
```

### Direct Usage (Bypass Circuit Breaker)

```javascript
const { sendCommandDirect } = require('./ai/aiSyntheticClient');

// Bypass circuit breaker (not recommended for production)
const result = await sendCommandDirect('process', { text: 'hello' });
```

### Get Circuit Breaker Statistics

```javascript
const { getCircuitBreakerStats } = require('./ai/aiSyntheticClient');

const stats = getCircuitBreakerStats();
console.log(stats.synthetic.state); // 'closed', 'open', or 'half-open'
console.log(stats.synthetic.stats); // Request statistics
```

## Benefits

### 1. **Prevent Cascading Failures**
- Failing AI service doesn't overwhelm system
- Requests fail fast when service is down

### 2. **Automatic Recovery Detection**
- Periodically tests if service recovered
- Automatically resumes normal operation

### 3. **Resource Protection**
- Stops sending requests to failing service
- Preserves resources for other operations

### 4. **Better User Experience**
- Fast failures instead of long timeouts
- Clear error messages about service status

### 5. **Observability**
- Detailed statistics on success/failure rates
- State change logging for debugging
- Health check endpoint for monitoring

## Tuning Guidelines

### High-Traffic Scenarios

```javascript
{
  timeout: 2000,               // Faster timeout
  errorThresholdPercentage: 30, // More sensitive
  volumeThreshold: 20          // Higher sample size
}
```

### Low-Traffic/Development

```javascript
{
  timeout: 5000,               // More lenient
  errorThresholdPercentage: 70, // Less sensitive
  volumeThreshold: 3           // Lower sample size
}
```

### Critical Services

```javascript
{
  resetTimeout: 60000,         // Wait longer before retry
  errorThresholdPercentage: 25, // Very sensitive
  volumeThreshold: 10
}
```

## Integration with Monitoring

### Prometheus Metrics (Future Enhancement)

```javascript
const breaker = new CircuitBreaker(sendCommand, {
  ...options,
  prometheus: {
    enabled: true,
    registry: prometheusRegistry
  }
});
```

### Custom Alerting

```javascript
syntheticBreaker.on('open', () => {
  // Send alert to Slack/PagerDuty
  alerting.send({
    severity: 'warning',
    message: 'AI Synthetic service circuit breaker opened'
  });
});
```

## Testing

### Simulate Circuit Opening

```javascript
// Send many failing requests
for (let i = 0; i < 10; i++) {
  try {
    await sendCommand('invalid', {});
  } catch (err) {
    // Expected to fail
  }
}

// Check if circuit is now open
const stats = getCircuitBreakerStats();
console.log(stats.synthetic.state); // Should be 'open'
```

### Test Recovery

```javascript
// Wait for resetTimeout
await new Promise(resolve => setTimeout(resolve, 31000));

// Next request should test service (half-open)
try {
  await sendCommand('valid', { test: true });
  // If successful, circuit closes
} catch (err) {
  // If fails, circuit stays open
}
```

## Related Files

- [api/src/ai/aiSyntheticClient.js](./aiSyntheticClient.js) - Circuit breaker implementation
- [api/src/api/health.js](../api/health.js) - Health check endpoints
- [api/package.json](../../package.json) - Opossum dependency

## Further Reading

- [Opossum Documentation](https://nodeshift.dev/opossum/)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Release It! (Michael Nygard)](https://pragprog.com/titles/mnee2/release-it-second-edition/)
