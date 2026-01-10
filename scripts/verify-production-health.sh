#!/bin/bash

# Production Health Check Script
# Verifies all services are running and responding

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
    else
        echo -e "${RED}✗${NC} $2"
    fi
}

echo "Production Health Check - $(date)"
echo "======================================"

# Check Docker
echo -e "\n${YELLOW}Docker & Compose:${NC}"
docker --version > /dev/null 2>&1 && print_status 0 "Docker installed" || print_status 1 "Docker not found"
docker-compose --version > /dev/null 2>&1 && print_status 0 "Docker Compose installed" || print_status 1 "Docker Compose not found"

# Check running containers
echo -e "\n${YELLOW}Running Services:${NC}"
CONTAINER_COUNT=$(docker-compose -f docker-compose.production.yml ps -q 2>/dev/null | wc -l)
if [ $CONTAINER_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓${NC} $CONTAINER_COUNT containers running"
    docker-compose -f docker-compose.production.yml ps
else
    echo -e "${RED}✗${NC} No containers running"
fi

# API Health
echo -e "\n${YELLOW}API Health:${NC}"
API_HEALTH=$(curl -s http://localhost:3001/api/health 2>/dev/null | grep -o '"status":"ok"' || echo "")
if [ -n "$API_HEALTH" ]; then
    print_status 0 "API responding"
else
    print_status 1 "API not responding"
fi

# Web Health
echo -e "\n${YELLOW}Web Application:${NC}"
WEB_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 2>/dev/null || echo "000")
if [ "$WEB_HEALTH" = "200" ] || [ "$WEB_HEALTH" = "404" ]; then
    print_status 0 "Web server responding (HTTP $WEB_HEALTH)"
else
    print_status 1 "Web server not responding (HTTP $WEB_HEALTH)"
fi

# Database
echo -e "\n${YELLOW}Database:${NC}"
if docker-compose -f docker-compose.production.yml exec -T postgres pg_isready -U infamous > /dev/null 2>&1; then
    print_status 0 "PostgreSQL connected"
else
    print_status 1 "PostgreSQL not responding"
fi

# Redis
echo -e "\n${YELLOW}Redis Cache:${NC}"
if docker-compose -f docker-compose.production.yml exec -T redis redis-cli ping | grep -q PONG; then
    print_status 0 "Redis responding"
else
    print_status 1 "Redis not responding"
fi

# Monitoring
echo -e "\n${YELLOW}Monitoring Stack:${NC}"
PROM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9090 2>/dev/null || echo "000")
if [ "$PROM_STATUS" = "200" ]; then
    print_status 0 "Prometheus available (HTTP $PROM_STATUS)"
else
    print_status 1 "Prometheus not available (HTTP $PROM_STATUS)"
fi

GRAF_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3002 2>/dev/null || echo "000")
if [ "$GRAF_STATUS" = "200" ] || [ "$GRAF_STATUS" = "302" ]; then
    print_status 0 "Grafana available (HTTP $GRAF_STATUS)"
else
    print_status 1 "Grafana not available (HTTP $GRAF_STATUS)"
fi

echo -e "\n${YELLOW}Health Check Complete${NC}"

