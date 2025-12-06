#!/bin/sh
set -e

echo "Running Prisma migrations (production)..."

npm run prisma:generate
npm run prisma:migrate

echo "Production migrations applied."
