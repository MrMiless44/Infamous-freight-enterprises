const express = require('express')
const cors = require('cors')
require('dotenv').config()

const app = express()
const PORT = Number(process.env.API_PORT || 4000)
const HOST = process.env.API_HOST || '0.0.0.0'
const API_BASE_PATH = process.env.API_BASE_PATH || '/api'

app.use(cors())
app.use(express.json())

const healthHandler = (req, res) => {
  res.json({
    status: 'ok',
    service: 'api',
    timestamp: new Date().toISOString()
  })
}

const healthPaths = ['/health', `${API_BASE_PATH}/health`]
healthPaths.forEach((path) => app.get(path, healthHandler))

app.get(`${API_BASE_PATH}/ping`, (req, res) => {
  res.json({ pong: true, timestamp: new Date().toISOString() })
})

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' })
})

app.listen(PORT, HOST, () => {
  console.log(`API server listening on http://${HOST}:${PORT}`)
})
