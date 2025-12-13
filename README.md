# Infamous Freight Enterprises

A modern full-stack freight management platform with AI-powered features, real-time voice capabilities, and integrated billing system.

## 📋 Project Overview

Infamous Freight Enterprises is a comprehensive logistics and fleet management solution built as a monorepo with:

- **Backend**: Node.js/Express API with PostgreSQL database
- **Frontend**: Next.js React application with TypeScript
- **Mobile**: React Native/Expo mobile application
- **Shared Package**: Common types, utilities, and constants
- **AI Integration**: OpenAI and Anthropic APIs for intelligent features
- **Payment Processing**: Stripe and PayPal integration
- **Voice**: Real-time voice communication capabilities
- **Infrastructure**: Docker containerization with deployment to Fly.io, Render, or Vercel

## ✨ Latest Updates (December 2025)

🎉 **Major Architecture Improvements:**

- ✅ Converted to **pnpm workspace monorepo** for better dependency management
- ✅ Created **shared package** (`@infamous-freight/shared`) for code reuse
- ✅ Added **mobile app** as workspace package
- ✅ Enhanced **CI/CD pipeline** with better testing and coverage
- ✅ Consolidated **documentation** and improved navigation
- ✅ Automated **setup script** for streamlined onboarding

See [IMPROVEMENTS_COMPLETE.md](IMPROVEMENTS_COMPLETE.md) for full details.

## 🚀 Quick Start

### Prerequisites

- Node.js 20+
- PostgreSQL 14+ (or Docker)
- Git

### One-Command Setup

```bash
# Run automated setup script
./setup.sh
```

This will:

- Install pnpm (if needed)
- Install all dependencies
- Build shared package
- Setup environment template
- Configure git hooks
- Generate Prisma client

### Manual Setup

1. **Install pnpm**

   ```bash
   curl -fsSL https://get.pnpm.io/install.sh | sh -
   source ~/.bashrc  # or restart terminal
   ```

2. **Install Dependencies**

   ```bash
   pnpm install
   ```

3. **Build Shared Package**

   ```bash
   pnpm --filter @infamous-freight/shared build
   ```

4. **Configure Environment**

   ```bash
   cp .env.example .env.local
   # Edit .env.local with your actual values
   ```

5. **Initialize Database**

   ```bash
   cd api
   pnpm prisma:migrate:dev
   pnpm prisma:seed  # Optional: seed initial data
   ```

6. **Start Development**

   ```bash
   # Start all services
   pnpm dev

   # Or start individually:
   pnpm api:dev      # API on http://localhost:3001
   pnpm web:dev      # Web on http://localhost:3000
   ```

## 📁 Project Structure

```
├── api/                           # Express.js backend
│   ├── prisma/                   # Database schema and migrations
│   ├── src/
│   │   ├── routes/               # API endpoints
│   │   ├── services/             # Business logic
│   │   ├── middleware/           # Security & utilities
│   │   └── server.js             # Express server
│   └── scripts/                  # Database and utility scripts
├── web/                          # Next.js frontend
│   ├── pages/                    # API routes and pages
│   ├── components/               # React components
│   ├── hooks/                    # Custom React hooks
│   └── styles/                   # Global styles
├── mobile/                       # React Native mobile app
│   ├── App.tsx                   # Main app component
│   └── assets/                   # Mobile assets
├── packages/
│   └── shared/                   # Shared TypeScript package
│       ├── src/
│       │   ├── types.ts         # Common types
│       │   ├── constants.ts     # App constants
│       │   ├── utils.ts         # Utility functions
│       │   └── env.ts           # Environment helpers
│       └── package.json
├── e2e/                          # Playwright E2E tests
├── docs/                         # Documentation
│   ├── deployment/               # Deployment guides
│   └── history/                  # Project history
├── nginx/                        # Reverse proxy configuration
├── pnpm-workspace.yaml           # Monorepo configuration
├── .github/workflows/            # CI/CD pipelines
└── docker-compose*.yml           # Container orchestration
```

## 🔧 Development

### Available Scripts

**From Root** (recommended):

```bash
pnpm dev              # Start all services in parallel
pnpm api:dev          # Start only API service
pnpm web:dev          # Start only web service
pnpm build            # Build all services
pnpm test             # Run all tests
pnpm test:coverage    # Run tests with coverage
pnpm lint             # Lint all services
pnpm lint:fix         # Fix linting issues
pnpm e2e              # Run E2E tests
pnpm clean            # Clean all node_modules
```

**Individual Services:**

```bash
# API
pnpm --filter infamous-freight-api dev
pnpm --filter infamous-freight-api test
pnpm --filter infamous-freight-api prisma:migrate

# Web
pnpm --filter infamous-freight-web dev
pnpm --filter infamous-freight-web build
npm run start            # Start production server
npm run lint             # Run ESLint
```

### Database Management

- **Run Migrations**: `cd api && npx prisma migrate dev`
- **Studio (GUI)**: `cd api && npm run prisma:studio`
- **Generate Client**: `cd api && npm run prisma:generate`
- **Seed Database**: `cd api && npx prisma db seed`

### Code Quality

```bash
# Lint web application
cd web && npm run lint

# Validate API environment
cd api && npm run validate:env
```

## 🐳 Docker

### Development with Docker

```bash
docker-compose -f docker-compose.dev.yml up
```

### Production Build

```bash
docker-compose -f docker-compose.prod.yml up
```

## 🚢 Deployment

Deployment guides are available for:

- **Fly.io**: See [deploy/fly-env.md](deploy/fly-env.md)
- **Render**: See [deploy/render-env.md](deploy/render-env.md)
- **Vercel** (Frontend): See [deploy/vercel-env.md](deploy/vercel-env.md)

## 🏗️ Architecture

### API Routes

- `/api/health` - Health check endpoint
- `/api/billing` - Billing and payment management
- `/api/voice` - Voice communication endpoints
- `/api/ai/commands` - AI command processing
- `/api/ai/sim` - AI simulation endpoints

### Database Models

- **User** - Application users with roles
- **Driver** - Fleet drivers with status tracking
- **Shipment** - Freight shipments with tracking
- **AiEvent** - AI event logging

## 🔐 Security Features

- JWT authentication
- CORS configuration
- Helmet.js security headers
- Rate limiting
- Input validation
- Secure environment variable handling

## 📦 Technologies

### Backend

- Express.js - HTTP server
- Prisma - ORM & migrations
- PostgreSQL - Database
- JWT - Authentication
- Helmet - Security headers
- CORS - Cross-origin requests
- Rate Limiter Flexible - Rate limiting

### Frontend

- Next.js 14 - React framework
- TypeScript - Type safety
- SWR - Data fetching
- Tailwind CSS - Styling (via global.css)

### APIs & Services

- OpenAI - LLM capabilities
- Anthropic - AI features
- Stripe - Payment processing
- PayPal - Payment processing
- Multer - File uploads

## 📝 Environment Variables

See [.env.example](.env.example) for all available configuration options.

Key variables:

- `NODE_ENV` - Environment (development/production)
- `API_PORT` - API server port
- `WEB_PORT` - Web server port
- `DATABASE_URL` - PostgreSQL connection string
- `API_KEY_*` - Third-party API keys (OpenAI, Stripe, etc.)

## 🤝 Contributing

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Commit changes: `git commit -am 'Add feature'`
3. Push to branch: `git push origin feature/your-feature`
4. Open a pull request

## 📄 License

See [LICENSE](LICENSE) file for details.

## 🆘 Troubleshooting

**Database Connection Issues**

- Verify PostgreSQL is running
- Check `DATABASE_URL` in `.env`
- Run migrations: `npx prisma migrate dev`

**Port Already in Use**

- API default: `4000`
- Web default: `3000`
- Change in `.env` if needed

**Missing Dependencies**

```bash
# Reinstall all dependencies
rm -rf node_modules package-lock.json
npm install
```

## 📞 Support

For issues or questions, please open a GitHub issue or contact the development team.
