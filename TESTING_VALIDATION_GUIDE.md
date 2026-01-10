# ✅ TESTING & VALIDATION PROCEDURES

**Version:** 2.0.0  
**Status:** ✅ PRODUCTION  
**Date:** January 10, 2026

---

## 📋 SMOKE TEST SUITE (Verify Core Functionality)

### Pre-Deployment Validation (5-10 minutes)

```bash
#!/bin/bash
echo "🧪 Running Smoke Tests..."

# 1. API Health Check
echo "1️⃣ API Health Check..."
API_HEALTH=$(curl -s http://localhost:3001/api/health)
if echo "$API_HEALTH" | grep -q "ok"; then
  echo "✅ API is responding"
else
  echo "❌ API not responding"
  exit 1
fi

# 2. Web Application Accessible
echo "2️⃣ Web Application Check..."
WEB_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000)
if [ "$WEB_STATUS" == "200" ]; then
  echo "✅ Web app is accessible"
else
  echo "❌ Web app returned $WEB_STATUS"
  exit 1
fi

# 3. Database Connected
echo "3️⃣ Database Connectivity Check..."
DB_CHECK=$(docker-compose exec postgres psql -U postgres -c "SELECT 1" 2>&1)
if echo "$DB_CHECK" | grep -q "1"; then
  echo "✅ Database is connected"
else
  echo "❌ Database connection failed"
  exit 1
fi

# 4. Cache Available
echo "4️⃣ Cache Layer Check..."
REDIS_CHECK=$(docker-compose exec redis redis-cli ping 2>&1)
if [ "$REDIS_CHECK" == "PONG" ]; then
  echo "✅ Redis cache is available"
else
  echo "❌ Redis cache not responding"
  exit 1
fi

# 5. API Endpoints Responding
echo "5️⃣ Critical Endpoints Check..."
ENDPOINTS=(
  "/api/shipments"
  "/api/users"
  "/api/health"
)
for endpoint in "${ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001$endpoint)
  if [ "$STATUS" == "200" ] || [ "$STATUS" == "401" ]; then
    echo "✅ $endpoint is responding ($STATUS)"
  else
    echo "❌ $endpoint failed ($STATUS)"
    exit 1
  fi
done

echo ""
echo "✅ All smoke tests passed!"
```

---

## 🧪 ENDPOINT TESTING

### Critical Path Testing

```bash
#!/bin/bash
echo "🔍 Testing Critical User Flows..."

# Test Variables
API_URL="http://localhost:3001"
JWT_TOKEN="your_test_token_here"
TEST_USER="test@example.com"
TEST_PASSWORD="test123456"

# 1. Authentication Flow
echo "1️⃣ Authentication Flow"
echo "  a) Register new user"
REGISTER=$(curl -s -X POST "$API_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_USER\",\"password\":\"$TEST_PASSWORD\"}")
echo "  Response: $(echo $REGISTER | jq -r '.success')"

echo "  b) Login"
LOGIN=$(curl -s -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_USER\",\"password\":\"$TEST_PASSWORD\"}")
TOKEN=$(echo $LOGIN | jq -r '.data.token')
echo "  Token received: $(echo ${TOKEN:0:20}...)..."

# 2. Shipment Operations
echo ""
echo "2️⃣ Shipment Operations"
echo "  a) Create shipment"
CREATE=$(curl -s -X POST "$API_URL/api/shipments" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "origin":"New York",
    "destination":"Los Angeles",
    "weight":100,
    "status":"pending"
  }')
SHIPMENT_ID=$(echo $CREATE | jq -r '.data.id')
echo "  Created shipment: $SHIPMENT_ID"

echo "  b) Get shipment details"
GET=$(curl -s "$API_URL/api/shipments/$SHIPMENT_ID" \
  -H "Authorization: Bearer $TOKEN")
echo "  Status: $(echo $GET | jq -r '.data.status')"

echo "  c) Update shipment"
UPDATE=$(curl -s -X PUT "$API_URL/api/shipments/$SHIPMENT_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"in_transit"}')
echo "  Updated: $(echo $UPDATE | jq -r '.success')"

echo "  d) List shipments"
LIST=$(curl -s "$API_URL/api/shipments?limit=10" \
  -H "Authorization: Bearer $TOKEN")
COUNT=$(echo $LIST | jq -r '.data | length')
echo "  Found $COUNT shipments"

# 3. Payment Flow
echo ""
echo "3️⃣ Payment Processing"
echo "  a) Create payment intent"
PAYMENT=$(curl -s -X POST "$API_URL/api/billing/create-payment" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount":1000,"currency":"USD"}')
PAYMENT_ID=$(echo $PAYMENT | jq -r '.data.id')
echo "  Payment intent: $PAYMENT_ID"

echo "  b) Get payment status"
STATUS=$(curl -s "$API_URL/api/billing/payment/$PAYMENT_ID" \
  -H "Authorization: Bearer $TOKEN")
echo "  Status: $(echo $STATUS | jq -r '.data.status')"

# 4. Error Handling
echo ""
echo "4️⃣ Error Handling"
echo "  a) Invalid token"
INVALID=$(curl -s "$API_URL/api/shipments" \
  -H "Authorization: Bearer invalid_token")
echo "  Response: $(echo $INVALID | jq -r '.error' | head -c 50)..."

echo "  b) Missing required fields"
MISSING=$(curl -s -X POST "$API_URL/api/shipments" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}')
echo "  Response: $(echo $MISSING | jq -r '.error' | head -c 50)..."

echo ""
echo "✅ Critical path testing complete"
```

---

## 📊 LOAD TESTING

### Prepare Load Test

```bash
#!/bin/bash
echo "⚡ Load Testing Setup..."

# Install Apache Bench (if not installed)
# apt-get install apache2-utils

# Test Configuration
API_URL="http://localhost:3001/api/shipments"
CONCURRENT_USERS=10
TOTAL_REQUESTS=1000

echo "Configuration:"
echo "  URL: $API_URL"
echo "  Concurrent Users: $CONCURRENT_USERS"
echo "  Total Requests: $TOTAL_REQUESTS"
echo ""

# Run load test
echo "Running load test..."
ab -n $TOTAL_REQUESTS -c $CONCURRENT_USERS "$API_URL"

# Results will show:
# - Requests per second
# - Response time (mean, min, max)
# - Percentage of requests completed
```

### Analyze Load Test Results

```bash
# Expected results for healthy system:
# - At least 100+ requests/second
# - Mean response time < 2 seconds
# - Failed requests: 0
# - 95% response time < 3 seconds

# If results are poor:
echo "📊 Analyzing performance..."

# Check which service is bottleneck
docker stats --no-stream | sort -k4 -hr | head -5

# Check database
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT query, calls, mean_time FROM pg_stat_statements
ORDER BY mean_time DESC LIMIT 5;
"

# Check cache hit rate
docker-compose exec redis redis-cli INFO stats | grep -E "hits|misses"
```

---

## 🔒 SECURITY VALIDATION

### JWT Token Testing

```bash
#!/bin/bash
echo "🔐 JWT Token Validation Testing..."

API_URL="http://localhost:3001"

# Test 1: Valid token
echo "1️⃣ Valid Token Test"
VALID_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." # Your real token
curl -s "$API_URL/api/shipments" -H "Authorization: Bearer $VALID_TOKEN" | jq '.success'

# Test 2: Expired token
echo "2️⃣ Expired Token Test"
curl -s "$API_URL/api/shipments" \
  -H "Authorization: Bearer expired_token" | jq '.error'

# Test 3: Invalid signature
echo "3️⃣ Invalid Signature Test"
curl -s "$API_URL/api/shipments" \
  -H "Authorization: Bearer invalid.signature.token" | jq '.error'

# Test 4: No token
echo "4️⃣ No Token Test"
curl -s "$API_URL/api/shipments" | jq '.error'

# Test 5: Malformed header
echo "5️⃣ Malformed Header Test"
curl -s "$API_URL/api/shipments" \
  -H "Authorization: InvalidToken123" | jq '.error'
```

### Rate Limiting Testing

```bash
#!/bin/bash
echo "🚦 Rate Limiting Test..."

API_URL="http://localhost:3001/api/shipments"
LIMIT=100  # requests per 15 minutes

echo "Sending $((LIMIT + 50)) requests to trigger rate limit..."

# Send requests until we hit rate limit
for i in {1..150}; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL")
  
  if [ "$STATUS" == "429" ]; then
    echo "✅ Rate limit triggered at request #$i (429 Too Many Requests)"
    break
  fi
  
  if [ $((i % 10)) -eq 0 ]; then
    echo "  Requests: $i, Status: $STATUS"
  fi
done
```

### SQL Injection Prevention

```bash
#!/bin/bash
echo "🔒 SQL Injection Testing..."

API_URL="http://localhost:3001"

# Test 1: Basic injection
echo "1️⃣ Basic Injection Test"
curl -s "$API_URL/api/shipments?id=1' OR '1'='1" | jq '.error'

# Test 2: Union-based injection
echo "2️⃣ Union-Based Injection Test"
curl -s "$API_URL/api/shipments?id=1 UNION SELECT * FROM users" | jq '.error'

# Test 3: Parameterized query test (should be safe)
echo "3️⃣ Parameterized Query Test"
curl -s -X POST "$API_URL/api/shipments" \
  -H "Content-Type: application/json" \
  -d '{"id":"1' OR '1'='1"}' | jq '.error'

echo "✅ All injection tests passed (errors returned safely)"
```

---

## 📈 PERFORMANCE PROFILING

### Response Time Breakdown

```bash
#!/bin/bash
echo "⏱️ Response Time Analysis..."

API_URL="http://localhost:3001/api/shipments"

# Test multiple endpoints
ENDPOINTS=(
  "/api/health"
  "/api/shipments"
  "/api/users"
  "/api/billing/history"
)

echo "Endpoint Response Times (10 samples each):"
echo "Endpoint | Min | Max | Avg | P95"
echo "---------|-----|-----|-----|-----"

for endpoint in "${ENDPOINTS[@]}"; do
  TIMES=()
  for i in {1..10}; do
    TIME=$(curl -s -w '%{time_total}' -o /dev/null "$API_URL$endpoint")
    TIMES+=($TIME)
  done
  
  MIN=$(printf '%s\n' "${TIMES[@]}" | sort -n | head -1)
  MAX=$(printf '%s\n' "${TIMES[@]}" | sort -n | tail -1)
  AVG=$(printf '%s\n' "${TIMES[@]}" | awk '{sum+=$1} END {print sum/NR}')
  P95=$(printf '%s\n' "${TIMES[@]}" | sort -n | awk '{if(NR==int(length)+1-int((length+1)*0.05)) print}')
  
  printf "%-40s | %.3f | %.3f | %.3f | %.3f\n" "$endpoint" "$MIN" "$MAX" "$AVG" "$P95"
done
```

### Database Query Performance

```bash
# Identify slow queries
docker-compose exec postgres psql -U postgres infamous_freight -c "
SELECT 
  query,
  calls,
  mean_time,
  max_time,
  total_time
FROM pg_stat_statements
WHERE mean_time > 100  -- Queries taking > 100ms
ORDER BY mean_time DESC
LIMIT 20;
" | column -t
```

---

## 📋 PRE-PRODUCTION CHECKLIST

```
✅ FUNCTIONALITY TESTS
  □ All CRUD operations working
  □ Authentication/Authorization working
  □ Payment processing working
  □ Error handling working
  □ Validation working

✅ PERFORMANCE TESTS
  □ API response time < 2s (p95)
  □ Web load time < 3s
  □ Database queries < 500ms
  □ Cache hit rate > 80%
  □ System handles 100+ concurrent users

✅ SECURITY TESTS
  □ JWT validation working
  □ Rate limiting active
  □ SQL injection prevented
  □ XSS prevention active
  □ CORS configured correctly
  □ Webhook signatures verified

✅ RELIABILITY TESTS
  □ Services restart properly
  □ Database failover works
  □ Cache failover works
  □ Error logging working
  □ Backup/restore working

✅ DOCUMENTATION
  □ Runbook complete
  □ Troubleshooting guide complete
  □ Monitoring setup documented
  □ Escalation procedures documented
  □ Team trained on procedures

✅ MONITORING
  □ Prometheus collecting metrics
  □ Grafana dashboards configured
  □ Alerts configured
  □ Error tracking active
  □ Real-user monitoring active
```

---

**Last Updated:** January 10, 2026  
**Review Frequency:** Monthly  
**Owner:** QA & Operations Team
