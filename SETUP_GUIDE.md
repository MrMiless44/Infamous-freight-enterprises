# Infamous Freight — Full-Stack Website & App

A modern full-stack web application for logistics and freight management. Built with **React** (frontend), **Express.js** (backend), and deployed on **GitHub Pages**.

## 🚀 Features

- ✅ **React + Vite** - Fast, modern frontend with HMR
- ✅ **Express.js API** - Secure backend with CORS, Helmet, rate limiting
- ✅ **Error Handling** - React Error Boundary + API error middleware
- ✅ **Responsive Design** - Modern UI with dark theme
- ✅ **Environment Config** - .env.example for easy setup
- ✅ **ESLint + Prettier** - Code quality & formatting
- ✅ **GitHub Pages Deploy** - Automated gh-pages deployment
- ✅ **Devcontainer Ready** - Full dev environment included

## 📋 Quick Start

### Prerequisites

- **Node.js** 18+ (or use devcontainer)
- **pnpm** (or npm/yarn)
- **Git**

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/MrMiless44/Infamous-freight-enterprises.git
   cd deploy-site
   ```

2. **Install dependencies**
   ```bash
   pnpm install
   # or: npm install
   ```

3. **Setup environment**
   ```bash
   cp .env.example .env.local
   # Edit .env.local as needed
   ```

4. **Start development servers**
   ```bash
   pnpm dev
   ```
   - Client: http://localhost:3000
   - API: http://localhost:3001

### Build & Deploy

```bash
# Build client and server
pnpm build

# Deploy to gh-pages
bash deploy.sh

# Or manually deploy
git add -A
git commit -m "Production build"
git push origin main
```

## 📁 Project Structure

```
deploy-site/
├── client/                  # React frontend (Vite)
│   ├── src/
│   │   ├── main.jsx        # App entry point
│   │   ├── App.jsx         # Root component with routing
│   │   ├── ErrorBoundary.jsx
│   │   └── pages/
│   │       ├── Home.jsx
│   │       └── About.jsx
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   └── dist/               # Built output
│
├── server/                 # Express API backend
│   ├── src/
│   │   └── index.js        # API server
│   └── package.json
│
├── deploy.sh              # Deployment script to gh-pages
├── package.json           # Root workspace config
├── .devcontainer/         # Dev container setup
├── .env.example          # Environment template
├── .prettierrc.json      # Code formatting config
└── README.md             # This file
```

## 🛠️ Available Scripts

### Root (monorepo)

```bash
pnpm dev              # Start both client & server in watch mode
pnpm build            # Build client and server for production
pnpm start            # Start production server
pnpm lint             # Run ESLint on all code
pnpm test             # Run tests (when configured)
```

### Client

```bash
cd client
pnpm dev              # Vite dev server on port 3000
pnpm build            # Build to dist/ for production
pnpm preview          # Preview production build
pnpm lint             # Lint React code
```

### Server

```bash
cd server
pnpm dev              # Nodemon watch mode on port 3001
pnpm start            # Start production server
pnpm build            # Echo (no build step for Node)
```

## 🔌 API Reference

### Health Check

```bash
curl http://localhost:3001/api/health

# Response
{
  "status": "OK",
  "timestamp": "2026-01-11T09:30:00.000Z",
  "uptime": 123.45
}
```

### Server Info

```bash
curl http://localhost:3001/api/info

# Response
{
  "name": "Infamous Freight API",
  "version": "1.0.0",
  "environment": "development"
}
```

## 🔐 Security

The application includes several security best practices:

- **Helmet.js** - Sets secure HTTP headers
- **CORS** - Configurable cross-origin requests
- **Rate Limiting** - Prevents abuse (100 req/15min by default)
- **Compression** - Reduces payload size
- **Error Boundaries** - Graceful error handling on frontend
- **Environment Variables** - Sensitive config kept in .env

### Setup Secrets

Create `.env.local` (never commit this):

```bash
PORT=3001
NODE_ENV=production
CORS_ORIGIN=https://your-domain.com
```

## 🚢 Deployment

### GitHub Pages (Static)

```bash
bash deploy.sh
```

Automatically:
1. Creates/updates `gh-pages` branch
2. Syncs current files via rsync
3. Commits and pushes to remote
4. Live at: https://MrMiless44.github.io/Infamous-freight-enterprises/

### Heroku / Railway / Render (Full-Stack)

1. Set environment variables
2. Point to production branch
3. App deploys client + server together

## 🧪 Development Workflow

### Code Quality

```bash
# Format code
pnpm run lint:fix

# Check for issues
pnpm lint
```

### Local Testing

```bash
# Terminal 1: Start API
cd server && pnpm dev

# Terminal 2: Start client
cd client && pnpm dev

# Visit http://localhost:3000
```

### Production Build

```bash
pnpm build
# Creates:
# - client/dist/  (Vite bundle)
# - ready for deploy.sh
```

## 🐳 Docker / Devcontainer

### Using Devcontainer (VS Code)

1. Install "Dev Containers" extension
2. Open folder in container: `Ctrl+Shift+P` → "Dev Containers: Reopen in Container"
3. Inside container:
   ```bash
   pnpm install
   pnpm dev
   ```

Includes:
- Alpine Linux with Node.js
- Git, rsync, Python3
- ESLint, Prettier extensions
- Port forwarding (3000, 3001, 8080)

## 📝 Environment Variables

Copy `.env.example` to `.env.local` and customize:

```env
PORT=3001
NODE_ENV=development
CORS_ORIGIN=http://localhost:3000
VITE_API_URL=http://localhost:3001/api
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

## 🔧 Troubleshooting

### Node Permission Denied

```bash
# In devcontainer, rebuild
Ctrl+Shift+P → Dev Containers: Rebuild Container
```

### Port Already in Use

```bash
# Kill process on port 3000
lsof -i :3000 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

### Vite Build Issues

```bash
rm -rf client/dist
pnpm build
```

## 📚 Additional Resources

- [React Documentation](https://react.dev)
- [Vite Guide](https://vitejs.dev)
- [Express.js Docs](https://expressjs.com)
- [GitHub Pages Docs](https://pages.github.com)

## 🤝 Contributing

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Commit changes: `git commit -m 'Add feature'`
3. Push: `git push origin feature/my-feature`
4. Open a Pull Request

## 📄 License

Proprietary. See [LICENSE](./LICENSE) for details.

## 👤 Author

**Santorio Djuan Miles** (@MrMiless44)  
Infamous Freight Enterprises

---

**Last Updated:** January 11, 2026  
**Version:** 1.0.0  
**Status:** ✅ Production Ready
