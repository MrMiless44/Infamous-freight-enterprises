import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const API_PROXY_TARGET = process.env.VITE_API_PROXY_TARGET || 'http://api:4000'
const WEB_PORT = Number(process.env.WEB_PORT || 3000)

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: WEB_PORT,
    strictPort: true,
    proxy: {
      '/api': {
        target: API_PROXY_TARGET,
        changeOrigin: true,
        secure: false,
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: WEB_PORT,
  },
})
