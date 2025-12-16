# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

We take security seriously. If you discover a security vulnerability within Infamous Freight Enterprises, please send an email to:

**security@infamous-freight.com** (or create a private security advisory on GitHub)

### What to Include

Please include the following information:

- Type of vulnerability (e.g., SQL injection, XSS, authentication bypass)
- Full paths of affected source file(s)
- Location of the affected code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment (what an attacker could do)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity (critical issues within 7 days)
- **Public disclosure**: After patch is released and deployed

## Security Measures

### Current Protections

- **Authentication**: JWT-based with scope-based RBAC
- **Rate Limiting**: Per-endpoint rate limits to prevent abuse
- **Input Validation**: express-validator on all user inputs
- **SQL Injection**: Parameterized queries via Prisma ORM
- **XSS Protection**: Helmet security headers with CSP
- **CORS**: Whitelist-based origin validation
- **Secrets Management**: Environment variables, never committed
- **Dependency Scanning**: Dependabot automated updates
- **Error Tracking**: Sentry integration for production monitoring

### Known Limitations

- AI service endpoints require valid API keys (not included in repo)
- Billing webhooks require HTTPS in production (configured separately)
- Database backups are responsibility of hosting provider

## Security Best Practices for Contributors

1. **Never commit secrets** - Use `.env.local` (gitignored)
2. **Validate all inputs** - Use provided validators from `api/src/middleware/validation.js`
3. **Use parameterized queries** - Always use Prisma ORM, never raw SQL
4. **Follow scope-based auth** - Check `requireScope()` middleware patterns
5. **Test security controls** - Write tests for auth/validation failures
6. **Update dependencies** - Run `pnpm audit` regularly

## Security-Related Configuration

### Environment Variables (Required)

```bash
JWT_SECRET=<strong_random_string>  # Generate: openssl rand -base64 32
CORS_ORIGINS=<comma_separated_allowed_origins>
DATABASE_URL=<postgresql_connection_with_ssl_in_prod>
```

### Production Deployment Checklist

- [ ] `NODE_ENV=production` set
- [ ] Strong `JWT_SECRET` generated
- [ ] `CORS_ORIGINS` restricted to production domains
- [ ] Database uses SSL/TLS connections
- [ ] Sentry configured for error tracking
- [ ] Rate limiting enabled (verify middleware)
- [ ] Security headers validated (check `/api/health`)
- [ ] Secrets stored in platform secret manager (Fly.io/Vercel)

## Vulnerability Disclosure Policy

We follow **coordinated disclosure**:

1. Report received and acknowledged privately
2. Fix developed and tested internally
3. Patch released to production
4. Public disclosure after 90 days or patch deployment (whichever is sooner)
5. Credit given to reporter (if desired)

## Contact

- **Security Email**: security@infamous-freight.com
- **GitHub Security Advisories**: https://github.com/MrMiless44/Infamous-freight-enterprises/security/advisories
- **General Issues**: https://github.com/MrMiless44/Infamous-freight-enterprises/issues

Thank you for helping keep Infamous Freight Enterprises secure!
