# Environment Protection Checklist

Configure environment protections to control deployments from GitHub Actions to your servers.

## Environments to Configure

- `staging`
- `production`

## Steps

1. Go to GitHub → Repository → Settings → Environments.
2. Create environment `staging` and `production` if not present.
3. For each environment:
   - Add required reviewers (e.g., yourself or a small group).
   - Optionally add a wait timer (e.g., 10 minutes) before jobs proceed.
   - Restrict environment secrets to that environment (SSH_HOST/USER/KEY[/PORT], GHCR_USERNAME, GHCR_TOKEN, etc.).
   - Optionally restrict branch patterns (e.g., only `main` for production).
4. Save changes.

## Notes

- Our deploy workflows should target these environments so protection rules apply.
- Use environment-scoped secrets to avoid accidental cross-environment usage.
- Promotion workflow reuses digests from the latest successful staging deploy — environment protections can enforce approvals.
