# Security Policy & Secret Rotation

## Overview

This document outlines the secret rotation schedule and security policies for Infamous Freight Enterprises.

## Critical Secrets Management

### Secrets Inventory

| Secret                | Type         | Rotation Cycle      | Owner          | Location          |
| --------------------- | ------------ | ------------------- | -------------- | ----------------- |
| JWT_SECRET            | Signing Key  | 90 days             | DevOps         | `.env.production` |
| STRIPE_SECRET_KEY     | API Key      | 90 days             | Finance/DevOps | `.env.production` |
| STRIPE_WEBHOOK_SECRET | Webhook Key  | As-needed           | Finance/DevOps | `.env.production` |
| PAYPAL_CLIENT_ID      | OAuth ID     | 180 days            | Finance/DevOps | `.env.production` |
| PAYPAL_SECRET         | OAuth Secret | 180 days            | Finance/DevOps | `.env.production` |
| OPENAI_API_KEY        | API Key      | 90 days             | AI/DevOps      | `.env.production` |
| ANTHROPIC_API_KEY     | API Key      | 90 days             | AI/DevOps      | `.env.production` |
| DATABASE_URL          | Connection   | Manual on migration | DevOps         | `.env.production` |
| POSTGRES_PASSWORD     | DB Password  | 180 days            | DevOps         | `.env.production` |
| GITHUB_TOKEN          | CI/CD        | 365 days            | DevOps         | GitHub Secrets    |
| SENTRY_DSN            | Monitoring   | As-needed           | DevOps         | `.env.production` |

## Rotation Schedule

### Immediate (Monthly)

- **JWT_SECRET**
  - **Reason**: Most frequently used, highest risk of compromise
  - **Process**:
    1. Generate new 256-bit key: `openssl rand -hex 32`
    2. Update `.env.production` with new secret
    3. Deploy API (existing tokens remain valid for 24h grace period)
    4. Monitor for auth failures for 48 hours
    5. Archive old secret in secure vault

- **OpenAI & Anthropic API Keys**
  - **Reason**: Used for AI inference, external service
  - **Process**:
    1. Log into provider dashboard
    2. Generate new API key
    3. Update `.env.production`
    4. Test with `pnpm test:ai` to verify
    5. Revoke old key in provider dashboard

### Quarterly (90 days)

- **STRIPE_SECRET_KEY**
  - **Process**:
    1. Log into Stripe Dashboard
    2. Navigate to Developers > API Keys
    3. Click "Reveal test key" and copy it
    4. Create new secret key (click "Create restricted key")
    5. Update `.env.production`
    6. Test payment flow: `pnpm test:billing`
    7. Revoke old key in Stripe

### Semi-Annual (180 days)

- **PAYPAL_CLIENT_ID & SECRET**
  - **Process**:
    1. Log into PayPal Developer Dashboard
    2. Navigate to Apps & Credentials
    3. Under Sandbox/Production, click the app name
    4. Click "Show" next to Secret
    5. Copy new Client ID and Secret
    6. Update `.env.production`
    7. Run integration tests
    8. Generate new credentials after update

- **POSTGRES_PASSWORD**
  - **Process**:
    1. Generate new password: `openssl rand -base64 32`
    2. In production RDS, change master password
    3. Update `.env.production` and backup
    4. Restart API pods (will reconnect with new password)
    5. Monitor connection pool for errors
    6. Document old password in secure vault

## Rotation Procedure

### Step 1: Generate New Secret

```bash
# For API keys
openssl rand -hex 32

# For passwords
openssl rand -base64 32

# For PKCS#8 keys
openssl genrsa -out private.pem 2048
```

### Step 2: Update in Vault

1. **GitHub Secrets**:

   ```bash
   gh secret set SECRET_NAME -b "$(openssl rand -hex 32)"
   ```

2. **Environment Files**:
   - Update `.env.production` securely
   - Never commit to git (use `git-crypt` or sealed secrets)
   - Verify with `git status` that `.env` is not staged

3. **Backup Old Secret**:
   - Store in secure vault (1Password, AWS Secrets Manager, etc.)
   - Include rotation date and time
   - Keep for 30 days for rollback

### Step 3: Deploy & Verify

```bash
# Deploy with new secret
fly secrets set JWT_SECRET=$(openssl rand -hex 32)

# Monitor logs for errors
fly logs --app infamous-freight-api

# Run smoke tests
pnpm test:smoke
```

### Step 4: Cleanup

```bash
# Revoke old secret in external services (Stripe, PayPal, OpenAI)
# Archive in secure vault with metadata:
# - Old value
# - Rotation date
# - Reason for rotation
# - Who authorized
```

## Emergency Rotation (Breach)

If a secret is compromised:

1. **Immediate (within 30 min)**:
   - Rotate the compromised secret immediately
   - Notify security team and service owner
   - Check logs for unauthorized usage

2. **Within 1 hour**:
   - Audit all API calls using the compromised secret
   - Check for unauthorized changes to:
     - Payment methods
     - User data
     - Configuration
   - Revoke the old secret in external services

3. **Within 24 hours**:
   - Publish incident report (internal)
   - Implement additional monitoring
   - Review access controls to prevent future breaches

4. **Post-incident**:
   - Conduct security audit of secret storage
   - Update rotation procedures
   - Train team on secret handling

## Secret Storage

### Development

```bash
# Use .env.local (git-ignored)
cp .env.example .env.local
echo "JWT_SECRET=dev-secret-12345" >> .env.local

# Never commit:
git config core.hooksPath .husky
```

### Production

**Option A: GitHub Secrets** (Recommended for CI/CD)

```bash
gh secret set JWT_SECRET
gh secret set STRIPE_SECRET_KEY
# Use in workflows:
# ${{ secrets.JWT_SECRET }}
```

**Option B: AWS Secrets Manager** (Recommended for long-term)

```bash
aws secretsmanager create-secret \
  --name infamous-freight/jwt-secret \
  --secret-string "$(openssl rand -hex 32)"

aws secretsmanager get-secret-value \
  --secret-id infamous-freight/jwt-secret
```

**Option C: Fly.io Secrets** (For deployed apps)

```bash
fly secrets set JWT_SECRET=$(openssl rand -hex 32)
fly secrets list
```

## Access Control

### Who Can Rotate Secrets?

- **DevOps Team**: All secrets
- **Finance Team**: Stripe, PayPal keys only
- **AI Team**: OpenAI, Anthropic keys only
- **Engineering Lead**: Emergency rotations

### Audit Trail

All secret rotations must be logged:

```bash
# Example log entry
{
  "timestamp": "2026-01-02T14:30:00Z",
  "secret": "JWT_SECRET",
  "action": "rotate",
  "authorized_by": "devops-lead@infamous-freight.com",
  "reason": "Scheduled quarterly rotation",
  "service": "infamous-freight-api",
  "verified": true
}
```

## Monitoring & Alerts

### Alert on Secret Exposure

```bash
# GitHub: Enable secret scanning
# AWS: Enable CloudTrail logging
# Stripe: Enable webhook notifications for API key changes
```

### Automated Checks

```bash
# Pre-commit hook to prevent secret commits
# Git: Update hooks/pre-commit to scan for patterns
git diff --cached --stage=staged | grep -E "(SECRET|PASSWORD|KEY)" && exit 1

# CI/CD: Scan for hardcoded secrets
pnpm run check:secrets
```

## Compliance

### Regulatory Requirements

- **PCI DSS**: API keys rotated every 90 days ✅
- **SOC 2**: Audit trail for all secret changes ✅
- **GDPR**: Encryption of secrets in transit & at rest ✅
- **ISO 27001**: Access control & monitoring ✅

### Audit Commands

```bash
# List all rotations in past 90 days
aws secretsmanager list-secret-version-ids \
  --secret-id infamous-freight/jwt-secret

# Check GitHub secret audit log
gh secret list --limit 100

# Verify production secrets are not in code
git log -p | grep -i "secret="
```

## Emergency Contacts

| Role                    | Contact                          | Backup                                |
| ----------------------- | -------------------------------- | ------------------------------------- |
| DevOps Lead             | devops-lead@infamous-freight.com | engineering-lead@infamous-freight.com |
| Security                | security@infamous-freight.com    | devops-lead@infamous-freight.com      |
| Finance (Stripe/PayPal) | finance@infamous-freight.com     | operations@infamous-freight.com       |

## Quick Reference: Rotation Checklist

- [ ] Identify expiring secrets from calendar
- [ ] Generate new secrets
- [ ] Test new secrets in staging
- [ ] Deploy to production (blue-green preferred)
- [ ] Monitor logs for errors (30 min)
- [ ] Revoke old secrets in external services
- [ ] Archive old secrets in vault (add date & reason)
- [ ] Document rotation in changelog
- [ ] Notify team in #security Slack channel

## References

- [GitHub Secret Management](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/)
- [Stripe API Security](https://stripe.com/docs/security)
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

**Last Updated**: January 2, 2026
**Next Review**: April 2, 2026
