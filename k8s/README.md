# Kubernetes Deployment Guide

## Overview

This directory contains Kubernetes manifests for the Infamous Freight Enterprises monorepo, organized by deployment stage.

## Manifests

### 01-infrastructure.yaml
Infrastructure components (namespace, ConfigMap, Secrets, PV/PVC, and databases):
- **Namespace**: `infamous-freight`
- **ConfigMap**: Shared environment variables (NODE_ENV, DB name, etc.)
- **Secrets**: Sensitive data (passwords, API keys)
- **PostgreSQL**: StatefulSet with persistent storage
- **Redis**: Deployment with memory limits

### 02-services.yaml
Application services:
- **API**: Main backend service (replicas: 2, port 3001)
- **AI Service**: AI processing service (replicas: 2, port 4001)
- **AI Worker**: Background job worker (replicas: 2, processes BullMQ queue)
- Each with liveness/readiness probes and resource limits

### 03-ingress-hpa.yaml
Networking and auto-scaling:
- **Ingress**: Routes for api.infamous-freight.local and ai-service.infamous-freight.local
- **HPA**: Horizontal Pod Autoscalers for CPU/memory-based scaling

## Prerequisites

1. **Kubernetes cluster** (v1.20+)
   ```bash
   # E.g., via minikube, Docker Desktop, or cloud provider
   minikube start --cpus=4 --memory=8192
   ```

2. **kubectl** installed and configured
   ```bash
   kubectl cluster-info
   ```

3. **NGINX Ingress Controller** (for Ingress routes)
   ```bash
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml
   ```

4. **cert-manager** (optional, for TLS)
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.1/cert-manager.yaml
   ```

## Deployment

### 1. Apply infrastructure
```bash
kubectl apply -f k8s/01-infrastructure.yaml
```

### 2. Build and push Docker images
```bash
# From repo root
docker build -f api/Dockerfile -t infamousfreight/api:latest ./api
docker build -f Dockerfile.ts-service -t infamousfreight/ai-service:latest ./packages/ai-service
docker build -f Dockerfile.ts-service -t infamousfreight/ai-worker:latest ./packages/ai-worker

# Push to registry (e.g., Docker Hub)
docker push infamousfreight/api:latest
docker push infamousfreight/ai-service:latest
docker push infamousfreight/ai-worker:latest
```

### 3. Apply services
```bash
kubectl apply -f k8s/02-services.yaml
```

### 4. Apply ingress and HPA
```bash
kubectl apply -f k8s/03-ingress-hpa.yaml
```

## Verification

```bash
# Check namespace and pods
kubectl get pods -n infamous-freight

# Check services
kubectl get svc -n infamous-freight

# Check ingress
kubectl get ingress -n infamous-freight

# Logs
kubectl logs -n infamous-freight deployment/api
kubectl logs -n infamous-freight deployment/ai-service
kubectl logs -n infamous-freight deployment/ai-worker

# Port-forward to test locally
kubectl port-forward -n infamous-freight svc/api 3001:3001
# Then: curl http://localhost:3001/health
```

## Configuration

### Environment Variables

Edit `app-config` ConfigMap in `01-infrastructure.yaml`:
```yaml
data:
  NODE_ENV: "production"
  AI_QUEUE_NAME: "ai-commands"
  POSTGRES_DB: "infamous_freight"
  POSTGRES_USER: "infamous"
```

### Secrets

Edit `app-secrets` Secret in `01-infrastructure.yaml`:
```yaml
stringData:
  POSTGRES_PASSWORD: "your-secure-password"
  JWT_SECRET: "your-jwt-secret"
  AI_SYNTHETIC_API_KEY: "your-api-key"
```

## Scaling

### Manual scaling
```bash
kubectl scale deployment api -n infamous-freight --replicas=5
kubectl scale deployment ai-worker -n infamous-freight --replicas=10
```

### Auto-scaling (HPA)
Configured in `03-ingress-hpa.yaml`. Check status:
```bash
kubectl get hpa -n infamous-freight
kubectl describe hpa api-hpa -n infamous-freight
```

## Cleanup

```bash
# Remove all resources
kubectl delete namespace infamous-freight

# Or remove individual manifests
kubectl delete -f k8s/03-ingress-hpa.yaml
kubectl delete -f k8s/02-services.yaml
kubectl delete -f k8s/01-infrastructure.yaml
```

## Monitoring

Consider adding:
- **Prometheus** for metrics collection
- **Grafana** for visualization
- **ELK Stack** for centralized logging

Example Prometheus scrape config:
```yaml
- job_name: 'api'
  kubernetes_sd_configs:
    - role: pod
      namespaces:
        names:
          - infamous-freight
  relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app]
      action: keep
      regex: api
```

## Troubleshooting

### Pods not starting
```bash
kubectl describe pod <pod-name> -n infamous-freight
kubectl logs <pod-name> -n infamous-freight
```

### Database connection errors
- Verify PostgreSQL StatefulSet is healthy: `kubectl get statefulset -n infamous-freight`
- Check DATABASE_URL env variable uses correct host: `postgres.infamous-freight.svc.cluster.local`

### AI Worker not processing jobs
- Verify Redis is running: `kubectl get deployment redis -n infamous-freight`
- Check worker logs: `kubectl logs deployment/ai-worker -n infamous-freight`

---

For detailed K8s docs, see [kubernetes.io](https://kubernetes.io/docs/).
