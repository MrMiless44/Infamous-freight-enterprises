# Docker Compose Configurations

This project includes multiple Docker Compose files for different use cases.

## Available Configurations

### 1. `docker-compose.simple.yml` - Minimal Setup
**Use case**: Quick start with just API + Database

```bash
docker-compose -f docker-compose.simple.yml up
```

**Services**:
- `api` - API server (port 4000)
- `db` - PostgreSQL 15 (port 5432)

**Features**:
- Simple configuration
- Fixed credentials (for development only)
- Single database volume

### 2. `docker-compose.yml` - Full Stack (Default)
**Use case**: Complete development environment

```bash
docker-compose up
# or
docker-compose up -d  # detached mode
```

**Services**:
- `postgres` - PostgreSQL 15 Alpine (port 5432)
- `api` - API server with hot reload (port 3001)
- `web` - Next.js frontend (port 3000)
- `nginx` - Reverse proxy (port 80)

**Features**:
- Full monorepo support with pnpm
- Hot module replacement
- Named volumes for caching
- Health checks
- Environment variable support
- Custom network

### 3. `docker-compose.dev.yml` - Development Override
**Use case**: Development with volume mounts

```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

**Additional Features**:
- Source code volume mounts
- Development dependencies
- Debug ports exposed

### 4. `docker-compose.prod.yml` - Production
**Use case**: Production deployment

```bash
docker-compose -f docker-compose.prod.yml up
```

**Features**:
- Optimized builds
- Production environment variables
- No source mounts
- Minimal attack surface

## Quick Start Guide

### Simple Setup (API + DB Only)

1. **Create environment file**:
```bash
echo "DATABASE_URL=postgresql://admin:securepass@db:5432/infamous_freight" > .env
echo "NODE_ENV=production" >> .env
```

2. **Start services**:
```bash
docker-compose -f docker-compose.simple.yml up -d
```

3. **Run migrations**:
```bash
docker-compose -f docker-compose.simple.yml exec api sh -c "cd /app && npx prisma migrate deploy"
```

4. **Access API**:
```bash
curl http://localhost:4000/health
```

### Full Stack Setup

1. **Copy environment template**:
```bash
cp .env.example .env.local
# Edit .env.local with your values
```

2. **Start all services**:
```bash
docker-compose up -d
```

3. **Check status**:
```bash
docker-compose ps
docker-compose logs -f
```

4. **Access services**:
- Frontend: http://localhost:3000
- API: http://localhost:3001
- Nginx: http://localhost:80

## Common Commands

### Start Services
```bash
# Simple setup
docker-compose -f docker-compose.simple.yml up

# Full stack
docker-compose up

# Production
docker-compose -f docker-compose.prod.yml up -d
```

### Stop Services
```bash
# Stop
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Stop specific file
docker-compose -f docker-compose.simple.yml down
```

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api
docker-compose logs -f db

# Last 100 lines
docker-compose logs --tail=100
```

### Execute Commands
```bash
# Access API container
docker-compose exec api sh

# Access database
docker-compose exec db psql -U admin -d infamous_freight

# Run migrations
docker-compose exec api npx prisma migrate deploy

# Run seeds
docker-compose exec api npx prisma db seed
```

### Rebuild Services
```bash
# Rebuild all
docker-compose build

# Rebuild specific service
docker-compose build api

# Rebuild and start
docker-compose up --build

# Force rebuild (no cache)
docker-compose build --no-cache
```

### Clean Up
```bash
# Remove stopped containers
docker-compose rm

# Remove all (including volumes)
docker-compose down -v --remove-orphans

# Remove images
docker-compose down --rmi all
```

## Configuration Comparison

| Feature | simple.yml | docker-compose.yml | dev.yml | prod.yml |
|---------|------------|-------------------|---------|----------|
| API | ✅ | ✅ | ✅ | ✅ |
| Database | ✅ | ✅ | ✅ | ✅ |
| Frontend | ❌ | ✅ | ✅ | ✅ |
| Nginx | ❌ | ✅ | ✅ | ✅ |
| Hot Reload | ❌ | ✅ | ✅ | ❌ |
| Health Checks | ✅ | ✅ | ✅ | ✅ |
| Volume Caching | ❌ | ✅ | ✅ | ❌ |
| Custom Network | ❌ | ✅ | ✅ | ✅ |

## Environment Variables

### Simple Configuration
```env
# Required for docker-compose.simple.yml
DATABASE_URL=postgresql://admin:securepass@db:5432/infamous_freight
NODE_ENV=production
API_PORT=4000
```

### Full Configuration
```env
# Database
POSTGRES_USER=infamous
POSTGRES_PASSWORD=infamouspass
POSTGRES_DB=infamous_freight
POSTGRES_PORT=5432

# API
API_PORT=3001
NODE_ENV=development

# Web
WEB_PORT=3000
NEXT_PUBLIC_API_URL=http://localhost:3001

# Nginx
NGINX_PORT=80
```

## Port Mapping

### Simple Setup
- API: `4000` → Container: `4000`
- DB: `5432` → Container: `5432`

### Full Stack
- Nginx: `80` → Container: `80`
- Web: `3000` → Container: `3000`
- API: `3001` → Container: `3001`
- DB: `5432` → Container: `5432`

## Volumes

### Simple Setup
- `db-data` - PostgreSQL data persistence

### Full Stack
- `pgdata` - PostgreSQL data
- `pnpm-store` - Shared pnpm cache
- `node-modules-api` - API dependencies
- `node-modules-web` - Web dependencies
- `nextjs-cache` - Next.js build cache

## Troubleshooting

### Port Already in Use
```bash
# Check what's using the port
lsof -ti:4000

# Kill the process
lsof -ti:4000 | xargs kill -9

# Or change the port in docker-compose
ports:
  - "4001:4000"  # Map host 4001 to container 4000
```

### Database Connection Failed
```bash
# Check if database is ready
docker-compose exec db pg_isready -U admin

# Check logs
docker-compose logs db

# Restart database
docker-compose restart db
```

### API Not Responding
```bash
# Check API logs
docker-compose logs api

# Check API health
curl http://localhost:4000/health

# Restart API
docker-compose restart api
```

### Volume Issues
```bash
# Remove all volumes and restart
docker-compose down -v
docker-compose up

# Prune unused volumes
docker volume prune
```

### Build Issues
```bash
# Clean rebuild
docker-compose down
docker-compose build --no-cache
docker-compose up
```

## Best Practices

### 1. Use Specific Compose File
```bash
# Always specify which file you're using
docker-compose -f docker-compose.simple.yml up
```

### 2. Environment Files
```bash
# Never commit .env files with real credentials
# Use .env.example as template
cp .env.example .env
```

### 3. Named Volumes
```bash
# Backup database volume
docker run --rm -v infamous_db-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/db-backup.tar.gz /data
```

### 4. Health Checks
```bash
# Wait for healthy services before running commands
docker-compose up -d
docker-compose exec api sh -c "until wget -q -O- http://localhost:4000/health; do sleep 1; done"
```

### 5. Logs Management
```bash
# Limit log size in production
docker-compose -f docker-compose.prod.yml up -d --log-opt max-size=10m
```

## Next Steps

- See [README.md](README.md) for project overview
- See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow
- See [api/Dockerfile](api/Dockerfile) for build details
- See [docs/deployment/](docs/deployment/) for deployment guides
