import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import compression from 'compression'
import rateLimit from 'express-rate-limit'

const app = express()
const PORT = process.env.PORT || 3001
const NODE_ENV = process.env.NODE_ENV || 'development'

// Middleware
app.use(helmet())
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}))
app.use(compression())
app.use(express.json())

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000'),
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'),
  message: 'Too many requests, please try again later.',
})
app.use(limiter)

// Routes
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  })
})

app.get('/api/info', (req, res) => {
  res.json({ 
    name: 'Infamous Freight API', 
    version: '1.0.0',
    environment: NODE_ENV,
  })
})

// Serve static files from client build
const staticPath = new URL('../client/dist', import.meta.url).pathname
app.use(express.static(staticPath))

// API error handling
app.use('/api', (err, req, res, next) => {
  console.error('API Error:', err)
  res.status(err.status || 500).json({
    error: NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
    status: err.status || 500,
  })
})

// Fallback to index.html for SPA
app.get('*', (req, res) => {
  res.sendFile(`${staticPath}/index.html`)
})

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global Error:', err)
  res.status(err.status || 500).json({
    error: NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
  })
})

app.listen(PORT, () => {
  console.log(`[${NODE_ENV}] Server running on http://localhost:${PORT}`)
})
