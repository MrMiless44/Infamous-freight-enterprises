#!/bin/bash
# Fly.io Deployment Helper Script
# This script helps diagnose and fix common Fly.io deployment issues

set -e

echo "🚀 Infamous Freight - Fly.io Deployment Helper"
echo "================================================"
echo ""

# Check if flyctl is installed
if ! command -v flyctl &> /dev/null; then
    echo "❌ flyctl is not installed"
    echo "📦 Install it with: curl -L https://fly.io/install.sh | sh"
    exit 1
fi

echo "✅ flyctl is installed"
echo ""

# Check if logged in
if ! flyctl auth whoami &> /dev/null; then
    echo "❌ Not logged in to Fly.io"
    echo "🔐 Run: flyctl auth login"
    exit 1
fi

echo "✅ Logged in to Fly.io as: $(flyctl auth whoami)"
echo ""

# Check if app exists
APP_NAME="infamous-freight-api"
if flyctl apps list | grep -q "$APP_NAME"; then
    echo "✅ App '$APP_NAME' exists"
else
    echo "⚠️  App '$APP_NAME' not found"
    echo "📝 Creating app..."
    flyctl apps create "$APP_NAME" --region iad
fi

echo ""

# Check database
echo "🗄️  Checking database..."
if flyctl pg list | grep -q "infamous-freight-db"; then
    echo "✅ PostgreSQL database exists"
else
    echo "⚠️  No PostgreSQL database found"
    echo "📝 Would you like to create one? (y/n)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        flyctl pg create --name infamous-freight-db --region iad
        flyctl pg attach infamous-freight-db -a "$APP_NAME"
        echo "✅ Database created and attached"
    fi
fi

echo ""

# Check required secrets
echo "🔐 Checking required secrets..."
REQUIRED_SECRETS=(
    "JWT_SECRET"
    "DATABASE_URL"
)

MISSING_SECRETS=()
for secret in "${REQUIRED_SECRETS[@]}"; do
    if flyctl secrets list -a "$APP_NAME" | grep -q "$secret"; then
        echo "✅ $secret is set"
    else
        echo "❌ $secret is missing"
        MISSING_SECRETS+=("$secret")
    fi
done

if [ ${#MISSING_SECRETS[@]} -gt 0 ]; then
    echo ""
    echo "⚠️  Missing secrets detected. Set them with:"
    for secret in "${MISSING_SECRETS[@]}"; do
        echo "   flyctl secrets set $secret=<value> -a $APP_NAME"
    done
    echo ""
    echo "📝 Example JWT_SECRET generation:"
    echo "   flyctl secrets set JWT_SECRET=$(openssl rand -base64 32) -a $APP_NAME"
fi

echo ""

# Validate Dockerfile
echo "🐋 Validating Dockerfile..."
if [ -f "Dockerfile.fly" ]; then
    echo "✅ Dockerfile.fly exists"
else
    echo "❌ Dockerfile.fly not found"
    exit 1
fi

# Validate fly.toml
echo "📋 Validating fly.toml..."
if [ -f "fly.toml" ]; then
    echo "✅ fly.toml exists"
else
    echo "❌ fly.toml not found"
    exit 1
fi

echo ""

# Check for common issues
echo "🔍 Checking for common issues..."

# Check if pnpm-lock.yaml exists
if [ -f "pnpm-lock.yaml" ]; then
    echo "✅ pnpm-lock.yaml exists"
else
    echo "❌ pnpm-lock.yaml not found - run 'pnpm install' first"
fi

# Check if API package.json exists
if [ -f "src/apps/api/package.json" ]; then
    echo "✅ API package.json exists"
else
    echo "❌ API package.json not found"
fi

# Check if Prisma schema exists
if [ -f "src/apps/api/prisma/schema.prisma" ]; then
    echo "✅ Prisma schema exists"
else
    echo "❌ Prisma schema not found"
fi

echo ""
echo "================================================"
echo "🎯 Next Steps:"
echo ""
echo "1. Set missing environment variables (if any)"
echo "2. Deploy with: flyctl deploy"
echo "3. Monitor logs: flyctl logs -a $APP_NAME"
echo "4. Check status: flyctl status -a $APP_NAME"
echo ""
echo "🆘 If deployment fails, check:"
echo "   - Build logs: flyctl logs -a $APP_NAME"
echo "   - Recent deployments: flyctl releases -a $APP_NAME"
echo "   - VM status: flyctl vm status -a $APP_NAME"
echo ""
