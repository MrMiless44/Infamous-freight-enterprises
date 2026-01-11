#!/bin/bash
set -e

echo "🚀 Starting Infamous Freight Enterprises Development Server"
echo ""

# Check if API directory exists
if [ ! -d "api" ]; then
  echo "❌ API directory not found"
  exit 1
fi

# Check if API has dependencies
if [ ! -d "api/node_modules" ]; then
  echo "📦 Installing API dependencies..."
  cd api && npm install && cd ..
fi

# Check if packages/shared exists and build it
if [ -d "packages/shared" ]; then
  echo "🔨 Building shared packages..."
  cd packages/shared
  if [ ! -d "node_modules" ]; then
    npm install
  fi
  npm run build 2>/dev/null || echo "✅ Shared packages ready"
  cd ../..
fi

# Start the API server
echo "🌐 Starting API server on port 3001..."
cd api
npm run dev

