# Monitoring Stack Integration (Prometheus, Loki, Grafana, Promtail)

This document describes how to bring in the monitoring assets from the provided `infra/monitoring` tree into this monorepo as an optional, developer-friendly stack.

## Source (provided)

```
infra/monitoring/
├── docker-compose.monitoring.yml
├── prometheus.yml
├── loki-config.yml
├── promtail-config.yml
└── grafana-dashboards/
```

## Target Layout

Option A (docs-first):
- Place the configs under `docs/monitoring/` and provide a copy command to a local `monitoring/` directory.

Option B (first-class):
- Create a top-level `monitoring/` folder with the exact configs and a `docker-compose.monitoring.yml` that references them.

This repo will default to Option A until the original files are uploaded.

## Integration Steps

1) Upload configs
- Add the five items listed above into `docs/monitoring/` or `monitoring/`.

2) Bring up the monitoring stack

```bash
# from repo root, assuming files live under ./monitoring
docker compose -f monitoring/docker-compose.monitoring.yml up -d
```

3) Wire the API to export metrics (done)
- `prom-client` is added to the API
- Read-only metrics exposed at `/api/metrics`
- Update `prometheus.yml` to scrape the API (e.g., `http://host.docker.internal:3001/api/metrics` or network alias)

4) Centralize logs
- Configure Promtail to tail API logs (Docker driver or file mounts)
- Verify logs in Grafana via Loki data source

## Security & Ops
- Keep the monitoring compose opt-in for developers
- For production, provide dedicated infra (k8s manifests or managed services) and secure credentials
- Use Grafana provisioning to ship dashboards under `grafana-dashboards/`

## Next Actions
- Upload the provided monitoring files to `docs/monitoring/`
- Decide on Option A vs Option B for layout
- If desired, I can draft the `/metrics` implementation and the compose overrides referencing the uploaded configs
