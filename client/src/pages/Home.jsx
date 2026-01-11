import axios from 'axios'
import { useEffect, useState } from 'react'

export default function Home() {
  const [status, setStatus] = useState('Loading...')

  useEffect(() => {
    axios
      .get('/api/health')
      .then((res) => setStatus(res.data.status))
      .catch(() => setStatus('Error'))
  }, [])

  return (
    <div style={{ padding: '40px', textAlign: 'center' }}>
      <h1>Infamous Freight</h1>
      <h2>Full-Stack Web App</h2>
      <p>API Status: {status}</p>
      <nav>
        <a href="/">Home</a> | <a href="/about">About</a>
      </nav>
    </div>
  )
}
