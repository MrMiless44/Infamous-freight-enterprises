import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api'

const metricCards = [
  { title: 'Live Shipments', value: '128', detail: '+5.2% week-over-week' },
  { title: 'On-Time Rate', value: '96.4%', detail: 'Target >= 95%' },
  { title: 'Exceptions', value: '3 critical', detail: '2 weather / 1 customs' }
]

function App() {
  const [health, setHealth] = useState({
    loading: true,
    error: null,
    data: null,
    refreshedAt: null
  })

  const fetchHealth = useCallback(async () => {
    setHealth((prev) => ({ ...prev, loading: true, error: null }))
    try {
      const response = await fetch(`${API_BASE_URL}/health`, {
        headers: { 'Content-Type': 'application/json' }
      })

      if (!response.ok) {
        throw new Error(`API responded with ${response.status}`)
      }

      const payload = await response.json()
      setHealth({
        loading: false,
        error: null,
        data: payload,
        refreshedAt: new Date()
      })
    } catch (error) {
      setHealth({
        loading: false,
        error: error.message,
        data: null,
        refreshedAt: new Date()
      })
    }
  }, [])

  useEffect(() => {
    fetchHealth()
  }, [fetchHealth])

  const statusTag = useMemo(() => {
    if (health.loading) return { label: 'Checking status...', tone: 'pending' }
    if (health.error) return { label: 'API offline', tone: 'offline' }
    return { label: 'API healthy', tone: 'online' }
  }, [health])

  return (
    <div className="app-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Infamous Freight Enterprises</p>
          <h1>Control Center</h1>
          <p className="lede">
            Observe live logistics telemetry, track exceptions, and keep every
            lane optimized from a single glass pane.
          </p>
        </div>
        <div className="status-panel">
          <div className={`status-pill ${statusTag.tone}`}>
            <span />
            {statusTag.label}
          </div>
          <button className="refresh" type="button" onClick={fetchHealth}>
            {health.loading ? 'Refreshing...' : 'Refresh status'}
          </button>
          <dl>
            <dt>API base URL</dt>
            <dd>{API_BASE_URL}</dd>
            <dt>Last check</dt>
            <dd>
              {health.refreshedAt
                ? health.refreshedAt.toLocaleTimeString()
                : '--'}
            </dd>
          </dl>
          {health.error && <p className="error">{health.error}</p>}
        </div>
      </section>

      <section className="metrics">
        <h2>Key telemetry</h2>
        <div className="metrics-grid">
          {metricCards.map((card) => (
            <article key={card.title} className="metric-card">
              <p className="metric-label">{card.title}</p>
              <p className="metric-value">{card.value}</p>
              <p className="metric-detail">{card.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="callout">
        <div>
          <p className="callout-title">Pipeline sync</p>
          <p>
            Connect upstream carrier feeds and downstream TMS to unlock live lane
            forecasting, anomaly clustering, and adaptive routing suggestions.
          </p>
        </div>
        <a className="callout-link" href="mailto:ops@infamousfreight.com">
          Get in touch
        </a>
      </section>
    </div>
  )
}

export default App
