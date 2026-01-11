import { Routes, Route } from 'react-router-dom'
import ErrorBoundary from './ErrorBoundary'
import Home from './pages/Home'
import About from './pages/About'

export default function App() {
  return (
    <ErrorBoundary>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </ErrorBoundary>
  )
}

function NotFound() {
  return (
    <div style={{ padding: '40px', textAlign: 'center' }}>
      <h1>404 - Page Not Found</h1>
      <a href="/">Back to Home</a>
    </div>
  )
}
