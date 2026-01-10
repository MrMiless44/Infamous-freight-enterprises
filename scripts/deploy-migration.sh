#!/bin/bash
# Database Migration & Index Deployment Script
# Applies Prisma migrations and performance indexes

set -e

echo "🗄️  Starting database migration..."

# Check DATABASE_URL
if [ -z "$DATABASE_URL" ]; then
  echo "❌ DATABASE_URL not set. Please set it before running this script."
  echo "   export DATABASE_URL='postgresql://user:password@host:5432/database'"
  exit 1
fi

cd src/apps/api

# Generate Prisma client
echo "📦 Generating Prisma client..."
pnpm prisma:generate

# Run migrations
echo "🔄 Running Prisma migrations..."
pnpm prisma:migrate:dev --name "deployment"

# Deploy indexes
echo "📊 Deploying performance indexes..."
if [ -f "prisma/migrations/20260110_add_performance_indexes.sql" ]; then
  psql "$DATABASE_URL" -f prisma/migrations/20260110_add_performance_indexes.sql
  echo "✅ Performance indexes deployed"
else
  echo "⚠️  Index migration file not found, skipping..."
fi

echo ""
echo "✅ Database migration complete!"
echo ""
echo "Indexes created:"
psql "$DATABASE_URL" -c "
SELECT indexname FROM pg_indexes 
WHERE tablename IN ('Shipment', 'Driver', 'User', 'Organization')
ORDER BY indexname;"

echo ""
echo "Next: Deploy API and Web to production"
