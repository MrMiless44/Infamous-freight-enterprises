#!/bin/bash
# API Startup & Health Check Script

set -e

API_URL="${API_URL:-http://localhost:4000}"
MAX_RETRIES=30
RETRY_DELAY=1

echo "🚀 Starting API server..."
cd /workspaces/Infamous-freight-enterprises/src/apps/api

# Build if not already built
if [ ! -d "dist" ]; then
  echo "📦 Building API..."
  pnpm build
fi

# Start server in background
npm run start &
API_PID=$!

echo "⏳ Waiting for API to be ready (max 30 seconds)..."

for i in $(seq 1 $MAX_RETRIES); do
  if curl -s "$API_URL/api/health" > /dev/null 2>&1; then
    echo "✅ API is ready!"
    echo ""
    echo "🔍 Health check:"
    curl -s "$API_URL/api/health" | jq .
    echo ""
    echo "Server running at $API_URL"
    echo "PID: $API_PID"
    break
  fi
  
  if [ $i -eq $MAX_RETRIES ]; then
    echo "❌ API failed to start after ${MAX_RETRIES}s"
    kill $API_PID 2>/dev/null || true
    exit 1
  fi
  
  echo "  Waiting... ($i/$MAX_RETRIES)"
  sleep $RETRY_DELAY
done
