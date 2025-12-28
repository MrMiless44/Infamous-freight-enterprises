# Architecture Overview

## Monorepo Layout

- **src/apps/api**: Node/Express API with Prisma ORM
- **src/apps/web**: Next.js web application (TypeScript/ESM)
- **src/apps/mobile**: Expo/React Native app (TypeScript)
- **src/packages/shared**: Shared TypeScript utilities and types
- **tests/e2e**: Playwright end-to-end tests

## Data Flow

- **Web/UI → API (REST) → Database (PostgreSQL via Prisma)**
- **Shared package** provides domain models and validation (Zod)

## Deployments

- **Web**: Next.js (Dockerized, deployed to Vercel)
- **API**: Node/Express (Dockerized, deployed to Fly.io/Render), Prisma migrations

## CI/CD

- **Lint**: ESLint, Prettier, Stylelint, html-validate
- **Tests**: Jest with coverage gates (currently 85% for shared, 0% for web, targeting 100%)
- **Container builds**: Docker multi-stage builds
- **Security scans**: CodeQL, Trivy, Dependabot

## Detailed Documentation

For comprehensive architecture details, see:

➡️ [docs/architecture.md](docs/architecture.md)
