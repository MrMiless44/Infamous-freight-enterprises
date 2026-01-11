#!/bin/bash
# Robust runtime script that works without npm/pnpm package managers

set -e

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   🚀 Infamous Freight Enterprises - Runtime Starter      ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# Find node executable
NODE_CMD=""

# Try common node locations
for path in "$(which node 2>/dev/null)" "/usr/bin/node" "/usr/local/bin/node" "/opt/node/bin/node"; do
    if [ -n "$path" ] && [ -f "$path" ]; then
        # Try to execute it
        if "$path" --version &>/dev/null; then
            NODE_CMD="$path"
            break
        fi
    fi
done

if [ -z "$NODE_CMD" ]; then
    echo "❌ Error: No working Node.js installation found"
    echo "   Tried: /usr/local/bin/node, /usr/bin/node, which node"
    exit 1
fi

echo "✅ Node.js found: $NODE_CMD"
echo "✅ Version: $($NODE_CMD --version 2>&1 || echo 'unknown')"
echo ""

# Check API directory
if [ ! -d "api" ]; then
    echo "❌ API directory not found. Please ensure you're in the project root."
    exit 1
fi

if [ ! -f "api/src/server.js" ]; then
    echo "❌ API server file not found at api/src/server.js"
    exit 1
fi

echo "✅ API directory found"
echo "✅ Server file located: api/src/server.js"
echo ""

# Set environment variables
export NODE_ENV="${NODE_ENV:-development}"
export API_PORT="${API_PORT:-3001}"
export WEB_PORT="${WEB_PORT:-3000}"

echo "🌍 Environment:"
echo "   NODE_ENV:  $NODE_ENV"
echo "   API_PORT:  $API_PORT"
echo "   WEB_PORT:  $WEB_PORT"
echo ""

# Start the server
echo "🚀 Starting API server..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd api

# Run server directly with node
exec $NODE_CMD src/server.js
