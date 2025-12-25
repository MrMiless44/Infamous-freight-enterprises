# 🚚 Infamous Freight Enterprise

AI Synthetic Intelligence ♊️–powered **AI Operations Workforce for Freight**.

Infamous Freight Enterprise deploys the **Infamous AI Dispatch Operator™**—an AI Operations Workforce that runs dispatch autonomously, predicts issues before they surface, and coaches drivers in real time. Sub-roles include Dispatch Operator AI, Driver Coach AI, Fleet Intelligence AI, and Customer Ops AI.

This is enterprise software built for autonomous operations with auditable accountability.

[![CI](https://github.com/MrMiless44/Infamous-freight-enterprises/actions/workflows/ci.yml/badge.svg)](https://github.com/MrMiless44/Infamous-freight-enterprises/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/MrMiless44/Infamous-freight-enterprises/branch/main/graph/badge.svg)](https://codecov.io/gh/MrMiless44/Infamous-freight-enterprises)

## ✨ Key Features

- 🤖 **Autonomous AI Dispatch** - AI-powered dispatch operations with real-time decision making
- 🚛 **Driver Coaching** - Real-time AI coaching for drivers
- 📊 **Fleet Intelligence** - Predictive analytics for fleet management
- 🎯 **Customer Operations AI** - Automated customer service and support
- 🔒 **SOC2-Ready** - Enterprise-grade security with human oversight
- 📱 **Multi-Platform** - Web dashboard, mobile app, and API access
- 🔄 **Real-time Updates** - WebSocket-based real-time data synchronization
- 📈 **Analytics & Monitoring** - Comprehensive metrics and monitoring

## 🏗️ Monorepo Structure

```
infamous-freight-enterprise/
├── src/
│   ├── apps/
│   │   ├── api/              # Express.js backend (CommonJS)
│   │   ├── web/              # Next.js dashboard (TypeScript/ESM)
│   │   └── mobile/           # React Native/Expo app
│   └── packages/
│       └── shared/           # Shared types, constants, and utilities
├── tests/e2e/                # Playwright end-to-end tests
├── configs/
│   ├── ci-cd/                # Provider configuration (Codecov, Fly.io, Vercel)
│   ├── docker/               # Docker Compose definitions (dev/prod/override)
│   ├── linting/              # ESLint and formatting baselines
│   ├── testing/              # Playwright test configuration
│   └── validation/           # HTML/CSS validation rules
├── docs/                     # Comprehensive documentation
└── scripts/                  # Build and deployment scripts
```

## 🚀 Quick Start

### Prerequisites

- **Node.js** 20 or higher
- **pnpm** 8.15.9
- **Docker** (for PostgreSQL and services)
- **Git**

### Installation

```bash
# Clone the repository
git clone https://github.com/MrMiless44/Infamous-freight-enterprises.git
cd Infamous-freight-enterprises

# Install dependencies
pnpm install

# Copy environment variables
cp .env.example .env

# Start services with Docker
docker compose -f configs/docker/docker-compose.yml -f configs/docker/docker-compose.dev.yml up -d

# Start development servers
pnpm dev
```

The application will be available at:
- **Web Dashboard**: http://localhost:3000
- **API**: http://localhost:4000 (or 3001 in Docker)
- **API Documentation**: http://localhost:4000/api-docs

For detailed setup instructions, see the [Developer Guide](docs/developer-guide.md).

## 📚 Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- **[Developer Guide](docs/developer-guide.md)** - Complete development setup and workflow
- **[Developer Onboarding](docs/development/developer-onboarding.md)** - Quick-start steps and required commands
- **[API Reference](docs/api/API_REFERENCE.md)** - API endpoints and usage
- **[Testing Guide](docs/TESTING.md)** - Testing strategy and practices
- **[Deployment Guide](docs/deployment/)** - Deployment procedures
- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and design
- **[Quick Reference](docs/QUICK_REFERENCE.md)** - Common commands and tips

See the [Documentation Index](docs/README.md) for a complete list.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Code of Conduct
- Development workflow
- Pull request process
- Coding standards
- Testing requirements

### Development Workflow

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

## 🧹 Validation & Quality Gates

- **Run everything**: `pnpm validate` (HTML via `html-validate`, CSS via `stylelint`, JS/TS via ESLint)
- **Configs** live in `configs/validation/` (HTML & CSS) and `configs/linting/` (ESLint)
- **Playwright config**: `configs/testing/playwright.config.js`
- **CI**: `.github/workflows/ci.yml` runs validation, linting, tests, coverage, and uploads to Codecov

## 🧪 Testing

```bash
# Run all tests
pnpm test

# Run tests for specific workspace
pnpm --filter api test
pnpm --filter web test

# Run end-to-end tests
pnpm test:e2e

# Run with coverage (uploads to Codecov in CI)
pnpm test:coverage
```

See the [Testing Guide](docs/TESTING.md) for more details.

## 🔒 Security

Security is a top priority. We follow industry best practices:

- JWT-based authentication with scope-based authorization
- Rate limiting on all API endpoints
- Input validation and sanitization
- Secure secret management
- Regular security audits with CodeQL
- SOC2-ready architecture

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

## 📊 Project Status

**Status**: Production-grade foundation with active development

- ✅ Core API and authentication
- ✅ Web dashboard
- ✅ Mobile app foundation
- ✅ CI/CD pipelines
- ✅ Test coverage >75%
- ✅ Deployment automation
- 🚧 Advanced AI features (in progress)
- 🚧 Real-time WebSocket updates (in progress)

See [CHANGELOG.md](CHANGELOG.md) for version history.

## 🛠️ Tech Stack

### Backend
- **Runtime**: Node.js 20+
- **Framework**: Express.js
- **Database**: PostgreSQL with Prisma ORM
- **Authentication**: JWT with scope-based authorization
- **Testing**: Jest
- **Language**: JavaScript (CommonJS)

### Frontend
- **Framework**: Next.js 14
- **Language**: TypeScript (ESM)
- **Styling**: CSS Modules
- **Testing**: Jest + React Testing Library
- **Build**: Webpack (via Next.js)

### Mobile
- **Framework**: React Native with Expo
- **Language**: TypeScript
- **Platform**: iOS, Android, Web

### DevOps
- **CI/CD**: GitHub Actions
- **Containerization**: Docker
- **Hosting**: Vercel (web), Render/Fly.io (api)
- **Monitoring**: Sentry, Codecov
- **Package Manager**: pnpm (workspaces)

## 📋 Execution Plan

The full go-to-market and operational rollout is documented in [`docs/AI_DISPATCH_OPERATOR_EXECUTION_PLAN.md`](docs/AI_DISPATCH_OPERATOR_EXECUTION_PLAN.md), covering:

- Autonomous dispatch mode
- Driver trust framework
- Dispatch Brain API
- Pricing strategy
- Compliance requirements
- Enterprise sales motion

## 📄 License

This project is licensed under the terms specified in [LICENSE](LICENSE).

## 👥 Team & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/MrMiless44/Infamous-freight-enterprises/issues)
- **GitHub Discussions**: [Ask questions and discuss](https://github.com/MrMiless44/Infamous-freight-enterprises/discussions)
- **Documentation**: [Full documentation](docs/)

## 🙏 Acknowledgments

Built with modern best practices and industry-standard tools. Special thanks to all contributors and the open-source community.

---

**Ready to revolutionize freight operations?** Get started with the [Developer Guide](docs/developer-guide.md) or explore the [documentation](docs/)!
