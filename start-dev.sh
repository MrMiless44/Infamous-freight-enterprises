#!/bin/sh
echo "Starting Infæmous Freight DEV environment..."
cp .env.example .env 2>/dev/null || true
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
