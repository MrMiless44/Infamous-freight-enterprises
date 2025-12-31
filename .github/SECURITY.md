# GitHub Actions Security & Secrets Management

## Secrets Rotation Schedule

**Calendar reminders should be set for:**

| Secret                   | Rotation Interval       | Last Rotated | Next Due    | Owner       |
| ------------------------ | ----------------------- | ------------ | ----------- | ----------- |
| `JWT_SECRET`             | Every 90 days           | [DATE]       | [DATE+90d]  | DevOps Lead |
| `RENDER_DEPLOY_HOOK_URL` | When regenerated        | [DATE]       | On-demand   | DevOps Lead |
| `VERCEL_TOKEN`           | Every 6 months          | [DATE]       | [DATE+180d] | Web Lead    |
| `OPENAI_API_KEY`         | Every 3 months          | [DATE]       | [DATE+90d]  | AI Lead     |
| `ANTHROPIC_API_KEY`      | Every 3 months          | [DATE]       | [DATE+90d]  | AI Lead     |
| `DATABASE_URL`           | When credentials change | [DATE]       | On-demand   | DBA         |

---

## Secret Rotation Procedures

### JWT_SECRET

**When:** Every 90 days

**Steps:**

1. Generate new secret: `openssl rand -base64 32`
2. Update in GitHub Secrets
3. Deploy code that supports both old and new secret (validate signature with both)
4. Monitor logs for invalid signature errors
5. Remove old secret after grace period (1 week)

**Impact:** May invalidate existing JWT tokens

**Rollback:** Keep old secret in environment as `JWT_SECRET_OLD` temporarily

---

### RENDER_DEPLOY_HOOK_URL

**When:** After regeneration or compromise

**Steps:**

1. Go to Render dashboard → Settings → Deploy Hooks
2. Regenerate hook URL
3. Copy new URL
4. Update GitHub Secret `RENDER_DEPLOY_HOOK_URL`
5. Test deployment to confirm it works

**Impact:** Deployments will fail with old hook URL

**Testing:** Trigger manual deployment after update

---

### VERCEL_TOKEN

**When:** Every 6 months or after compromise

**Steps:**

1. Go to Vercel → Settings → Tokens
2. Delete old token
3. Generate new token with same scopes
4. Update GitHub Secret `VERCEL_TOKEN`
5. Test deployment to Vercel

**Impact:** Vercel deployments blocked with old token

---

### API Keys (OpenAI, Anthropic)

**When:** Every 3 months

**Steps:**

1. Log in to provider dashboard (OpenAI/Anthropic)
2. Revoke old API key
3. Generate new API key
4. Update corresponding GitHub Secret
5. Test API calls in development
6. Deploy and monitor for errors

**Impact:** AI features will fail if key invalid

---

## Security Best Practices

### ✅ DO

- [ ] Store all secrets in GitHub Secrets, never in code
- [ ] Use minimal permissions for API tokens (read-only when possible)
- [ ] Rotate secrets on schedule regardless of breaches
- [ ] Use environment-specific secrets (staging vs production)
- [ ] Audit who has access to secrets
- [ ] Log all secret rotations in changelog
- [ ] Use masked secrets in workflow outputs

### ❌ DON'T

- [ ] Commit secrets to git repository
- [ ] Log secrets to stdout/stderr
- [ ] Share secrets in Slack/Discord/email
- [ ] Use same token for multiple purposes
- [ ] Extend rotation interval without approval
- [ ] Grant secrets to all workflows (use environment restrictions)
- [ ] Keep compromised secrets active

---

## Monitoring Secrets Usage

### Audit Trail

Check what workflows use each secret:

```bash
# Search for secret references in workflows
grep -r "secrets\." .github/workflows/

# List all secrets used (safe, no values shown)
git ls-files '.github/workflows/*.yml' | \
  xargs grep "secrets\." | \
  cut -d: -f2- | sort -u
```

### Workflows Using Each Secret

**JWT_SECRET:**

- `ci-cd.yml` (Test environment)
- `e2e.yml` (E2E test environment)
- `docker-build.yml` (Build environment)

**RENDER_DEPLOY_HOOK_URL:**

- `render-deploy.yml` (Production deployment)

**VERCEL_TOKEN:**

- `vercel-deploy.yml` (Web deployment)

**DATABASE_URL:**

- `ci-cd.yml` (Test database)
- `e2e.yml` (Test database)
- `docker-build.yml` (Prisma generation)

**OPENAI_API_KEY / ANTHROPIC_API_KEY:**

- `ci-cd.yml` (Optional - tests)
- `docker-build.yml` (Optional - build)

---

## Environment-Specific Secrets

For maximum security, use GitHub Environments:

### Development Environment

- Lower security requirements
- Shorter rotation intervals
- Staging databases/keys

### Production Environment

- Strict access controls
- Frequent rotations
- Production credentials only
- Requires approval for deployments

**Configuration:**

1. Go to Settings → Environments
2. Create `development`, `staging`, `production`
3. Set secrets per environment
4. Configure deployment reviewers for production

---

## Incident Response

### If Secret is Compromised

1. **IMMEDIATE (within 5 minutes):**
   - Revoke compromised secret in provider dashboard
   - Disable GitHub Secret temporarily
   - Notify DevOps team in #security channel

2. **SHORT-TERM (within 1 hour):**
   - Generate new secret
   - Update GitHub Secret
   - Deploy fix to all environments
   - Monitor logs for unauthorized access

3. **POST-INCIDENT (within 24 hours):**
   - Document root cause
   - Add preventative controls
   - Update this runbook
   - Brief team on incident

### Escalation

- **Low Risk** (test secret): Rotate immediately
- **Medium Risk** (staging secret): Rotate within 2 hours
- **High Risk** (production secret): Notify security lead, executive decision on rotation

---

## Compliance

### SOC2 / Security Standards

- [ ] Secrets rotated on schedule
- [ ] No secrets in git history
- [ ] Audit trail maintained for all rotations
- [ ] Access logs reviewed monthly
- [ ] Encryption in transit (GitHub HTTPS)
- [ ] Encryption at rest (GitHub encryption)

### Audit Checklist (Monthly)

- [ ] Review all active secrets
- [ ] Confirm rotation schedule followed
- [ ] Check for expired credentials
- [ ] Verify access permissions still appropriate
- [ ] Update documentation if needed

---

## Tools & Commands

### Generate Secure Secrets

```bash
# Generate 32-byte base64 secret (recommended)
openssl rand -base64 32

# Generate 256-bit hex secret
openssl rand -hex 32

# Generate UUID-based secret
uuidgen
```

### Check Secret Usage

```bash
# Find all secret references
grep -r "\${{ secrets\." .github/workflows/

# Count secret usage
grep -r "\${{ secrets\." .github/workflows/ | wc -l

# Find which workflows use specific secret
grep -r "secrets\.JWT_SECRET" .github/workflows/
```

### Validate GitHub Actions Secrets

```bash
# List all secrets (names only, values masked)
gh secret list

# Create/update secret
gh secret set SECRET_NAME -b "value"

# Delete secret
gh secret delete SECRET_NAME

# View secret (GitHub CLI)
gh secret view SECRET_NAME
```

---

## References

- [GitHub Secrets Documentation](https://docs.github.com/actions/security-guides/encrypted-secrets)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [GitHub CLI Documentation](https://cli.github.com/manual/)
- [OWASP Secret Management](https://owasp.org/www-project-secrets-management)

---

**Last Updated:** December 31, 2025
**Next Rotation Due:** [CALCULATED FROM TABLE ABOVE]
