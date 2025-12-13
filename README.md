# Infamous Freight Enterprises

A modern full-stack freight management platform with AI-powered features, real-time voice capabilities, and integrated billing system.

## 📋 Project Overview

Infamous Freight Enterprises is a comprehensive logistics and fleet management solution built with:
- **Backend**: Node.js/Express API with PostgreSQL database
- **Frontend**: Next.js React application with TypeScript
- **AI Integration**: OpenAI and Anthropic APIs for intelligent features
- **Payment Processing**: Stripe and PayPal integration
- **Voice**: Real-time voice communication capabilities
- **Infrastructure**: Docker containerization with deployment to Fly.io, Render, or Vercel

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ and npm
- PostgreSQL 14+ (or Docker)
- Git

### Installation

1. **Clone and Install Dependencies**
   ```bash
   # API setup
   cd api
   npm install

   # Web setup
   cd ../web
   npm install
   ```

2. **Configure Environment Variables**
   ```bash
   # Copy environment template
   cp ../.env.example api/.env
   cp .env.example web/.env.local

   # Edit the files with your actual values
   ```

3. **Initialize Database**
   ```bash
   cd api
   npx prisma migrate dev
   npx prisma db seed  # Optional: seed initial data
   ```

4. **Start Development Servers**
   ```bash
   # From root directory
   ./start-dev.sh
   
   # Or separately:
   cd api && npm run dev      # Runs on http://localhost:4000
   cd web && npm run dev      # Runs on http://localhost:3000
   ```

## 📁 Project Structure

```
├── api/                    # Express.js backend
│   ├── prisma/            # Database schema and migrations
│   ├── src/
│   │   ├── routes/        # API endpoints
│   │   ├── services/      # Business logic
│   │   ├── middleware/    # Security & utilities
│   │   └── server.js      # Express server
│   └── scripts/           # Database and utility scripts
├── web/                   # Next.js frontend
│   ├── pages/            # API routes and pages
│   ├── components/       # React components
│   ├── hooks/            # Custom React hooks
│   └── styles/           # Global styles
├── nginx/                # Reverse proxy configuration
├── deploy/               # Deployment guides
└── docker-compose*.yml   # Container orchestration

```

## 🔧 Development

### Available Scripts

**API** (from `api/` directory):
```bash
npm run dev              # Start development server
npm run start            # Start production server
npm run prisma:migrate   # Run database migrations
npm run prisma:studio    # Open Prisma Studio GUI
npm run validate:env     # Validate environment variables
```

**Web** (from `web/` directory):
```bash
npm run dev              # Start development server
npm run build            # Build for production
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