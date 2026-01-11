import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import compression from 'compression'
import rateLimit from 'express-rate-limit'

const app = express()
const PORT = process.env.PORT || 3001

// Middleware
app.use(helmet())
app.use(cors())
app.use(compression())
app.use(express.json())

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
})
app.use(limiter)

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() })
})

app.get('/api/info', (req, res) => {
  res.json({ name: 'Infamous Freight API', version: '1.0.0' })
})

// Serve static files from client build
app.use(express.static('../client/dist'))

// Fallback to index.html for SPA
app.get('*', (req, res) => {
  res.sendFile(new URL('../client/dist/index.html', import.meta.url).pathname)
})

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`)
})
