# Docker Setup for API Service

## Dockerfile Overview

The API service uses a multi-stage Docker build for optimized production images.

### Build Stages

#### Stage 1: Builder (Build Dependencies)
```dockerfile
FROM node:20-alpine AS builder
```
- Installs Python3, make, g++ for native dependencies
- Runs `npm ci --only=production` for fast, reproducible installs
- Generates Prisma Client

#### Stage 2: Production (Runtime)
```dockerfile
FROM node:20-alpine AS production
```
- Minimal runtime image
- Non-root user for security
- Health check included
- Only production dependencies

## Building the Image

### Basic Build
```bash
cd api
docker build -t infamous-freight-api:latest .
```

### Build with Custom Tag
```bash
docker build -t infamous-freight-api:2.0.0 .
```

### Build with Build Args
```bash
docker build \
  --build-arg NODE_ENV=production \
  -t infamous-freight-api:latest \
  .
```

### Build from Root Directory
```bash
# From project root
docker build -f api/Dockerfile -t infamous-freight-api:latest ./api
```

## Running the Container

### Basic Run
```bash
docker run -p 4000:4000 infamous-freight-api:latest
```

### Run with Environment Variables
```bash
docker run -p 4000:4000 \
  -e DATABASE_URL="postgresql://user:pass@host:5432/db" \
  -e JWT_SECRET="your-secret-key" \
  -e NODE_ENV="production" \
  infamous-freight-api:latest
```

### Run with .env File
```bash
docker run -p 4000:4000 \
  --env-file .env.production \
  infamous-freight-api:latest
```

### Run in Background (Detached)
```bash
docker run -d \
  --name freight-api \
  -p 4000:4000 \
  --restart unless-stopped \
  --env-file .env.production \
  infamous-freight-api:latest
```

### Run with Volume Mount (Development)
```bash
docker run -p 4000:4000 \
  -v $(pwd)/src:/app/src \
  --env-file .env.local \
  infamous-freight-api:latest
```

## Docker Compose

### Production
```yaml
version: '3.8'
services:
  api:
    build: ./api
    ports:
      - "4000:4000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=${DATABASE_URL}
      - JWT_SECRET=${JWT_SECRET}
    restart: unless-stopped
    depends_on:
      - postgres
  
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: freight
      POSTGRES_USER: admin
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data

volumes:
  postgres-data:
```

### Run with Docker Compose
```bash
docker-compose up -d
docker-compose logs -f api
docker-compose down
```

## Environment Variables

Required environment variables:

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/freight

# Authentication
JWT_SECRET=your-secret-key-change-in-production

# Server
API_PORT=4000
NODE_ENV=production

# Optional: AI Services
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
AI_SYNTHETIC_ENGINE_URL=https://ai.example.com
AI_SYNTHETIC_API_KEY=your-api-key

# Optional: Payment Services
STRIPE_SECRET_KEY=sk_...
PAYPAL_CLIENT_ID=...
PAYPAL_CLIENT_SECRET=...
```

## Health Check

The container includes a health check that runs every 30 seconds:

```bash
# Check container health status
docker ps
# Look for "healthy" in STATUS column

# View health check logs
docker inspect --format='{{json .State.Health}}' <container-id> | jq
```

Health check endpoint: `GET http://localhost:4000/api/health`

Expected response:
```json
{
  "status": "ok",
  "service": "infamous-freight-api",
  "version": "2.0.0",
  "timestamp": "2025-12-16T04:00:00.000Z",
  "uptime": 123.45
}
```

## Container Management

### View Logs
```bash
docker logs freight-api
docker logs -f freight-api  # Follow logs
docker logs --tail 100 freight-api  # Last 100 lines
```

### Execute Commands in Container
```bash
# Open shell
docker exec -it freight-api sh

# Run Prisma migrations
docker exec freight-api npx prisma migrate deploy

# Check Node version
docker exec freight-api node --version
```

### Stop/Start Container
```bash
docker stop freight-api
docker start freight-api
docker restart freight-api
```

### Remove Container
```bash
docker stop freight-api
docker rm freight-api
```

### Remove Image
```bash
docker rmi infamous-freight-api:latest
```

## Optimization Tips

### 1. Layer Caching
The Dockerfile is optimized for layer caching:
- Package files copied first
- Dependencies installed before source code
- Source code copied last (changes most frequently)

### 2. Multi-Stage Build
- Builder stage: ~500MB (includes build tools)
- Production stage: ~150MB (runtime only)
- Reduces final image size by 70%

### 3. .dockerignore
Excludes unnecessary files:
- node_modules (rebuilt in container)
- Tests, coverage, docs
- Development files (.env, .vscode)

### 4. Non-Root User
Runs as `nodejs` user (UID 1001) for security

### 5. Production Dependencies Only
Uses `npm ci --only=production` to skip dev dependencies

## Debugging

### Build with No Cache
```bash
docker build --no-cache -t infamous-freight-api:latest .
```

### Inspect Build Steps
```bash
docker build --progress=plain -t infamous-freight-api:latest .
```

### Run Interactive Shell
```bash
docker run -it --rm \
  --entrypoint sh \
  infamous-freight-api:latest
```

### Check Container Resources
```bash
docker stats freight-api
```

## Security Best Practices

✅ **Non-root user** - Runs as nodejs:nodejs (1001:1001)  
✅ **Minimal base image** - Alpine Linux (~5MB base)  
✅ **No secrets in image** - Uses environment variables  
✅ **Health checks** - Automatic container restart on failure  
✅ **Read-only filesystem** - Can be enforced with `--read-only`  
✅ **Resource limits** - Set with `--memory` and `--cpus`  

### Run with Security Options
```bash
docker run \
  -p 4000:4000 \
  --read-only \
  --tmpfs /tmp \
  --memory="512m" \
  --cpus="1.0" \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  --env-file .env.production \
  infamous-freight-api:latest
```

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Build Docker Image
  run: |
    docker build -t ${{ secrets.REGISTRY }}/freight-api:${{ github.sha }} ./api
    docker tag ${{ secrets.REGISTRY }}/freight-api:${{ github.sha }} \
               ${{ secrets.REGISTRY }}/freight-api:latest

- name: Push to Registry
  run: |
    echo "${{ secrets.DOCKER_PASSWORD }}" | docker login -u "${{ secrets.DOCKER_USERNAME }}" --password-stdin
    docker push ${{ secrets.REGISTRY }}/freight-api:${{ github.sha }}
    docker push ${{ secrets.REGISTRY }}/freight-api:latest
```

## Troubleshooting

### Container Won't Start
```bash
# Check logs for errors
docker logs freight-api

# Common issues:
# - Missing DATABASE_URL
# - Invalid JWT_SECRET
# - Port already in use
```

### Database Connection Failed
```bash
# Check if database is accessible from container
docker exec freight-api ping postgres

# Try connecting with psql
docker exec -it freight-api sh -c "apk add postgresql-client && psql $DATABASE_URL"
```

### High Memory Usage
```bash
# Check memory stats
docker stats freight-api

# Restart with memory limit
docker run --memory="512m" ...
```

## Related Files

- [Dockerfile](Dockerfile) - Multi-stage build configuration
- [.dockerignore](.dockerignore) - Files excluded from build
- [docker-compose.yml](../docker-compose.yml) - Orchestration config
- [package.json](package.json) - Dependencies and scripts
