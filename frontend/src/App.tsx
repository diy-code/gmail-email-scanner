import React, { useState, useCallback } from 'react'
import type { AnalyzeRequest, AnalyzeResponse, HealthStatus } from './types'
import { checkHealth, analyzeEmail } from './api'
import ConfigBar from './components/ConfigBar'
import EmailForm from './components/EmailForm'
import ResultsDashboard from './components/ResultsDashboard'

const DEFAULT_FORM: AnalyzeRequest = {
  subject: '',
  sender: '',
  reply_to: null,
  authentication_results: null,
  received_headers: [],
  body_plain: '',
  body_html: '',
  urls: [],
  message_date: null,
}

type PageState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'result'; data: AnalyzeResponse }
  | { kind: 'error'; message: string }

export default function App() {
  const [url, setUrl]       = useState('http://127.0.0.1:8080')
  const [apiKey, setApiKey] = useState('this_is_a_random_key')
  const [health, setHealth]            = useState<HealthStatus>('idle')
  const [healthVersion, setHealthVer]  = useState('')
  const [form, setForm]   = useState<AnalyzeRequest>(DEFAULT_FORM)
  const [page, setPage]   = useState<PageState>({ kind: 'idle' })

  const ping = useCallback(async () => {
    setHealth('checking')
    try {
      const h = await checkHealth(url)
      setHealth('ok')
      setHealthVer(h.version)
    } catch {
      setHealth('error')
    }
  }, [url])

  const run = useCallback(async () => {
    setPage({ kind: 'loading' })
    try {
      const result = await analyzeEmail(url, apiKey, form)
      setPage({ kind: 'result', data: result })
    } catch (e: unknown) {
      setPage({ kind: 'error', message: e instanceof Error ? e.message : String(e) })
    }
  }, [url, apiKey, form])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <ConfigBar
        url={url} apiKey={apiKey}
        health={health} healthVersion={healthVersion}
        onUrlChange={setUrl} onKeyChange={setApiKey}
        onPing={ping}
      />

      <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '400px 1fr', minHeight: 0 }}>

        {/* ── Left: Form ── */}
        <div style={{
          borderRight: '1px solid var(--border)',
          padding: '20px',
          overflowY: 'auto',
          background: 'var(--bg-base)',
        }}>
          <EmailForm
            form={form}
            onChange={setForm}
            onSubmit={run}
            loading={page.kind === 'loading'}
          />
        </div>

        {/* ── Right: Results ── */}
        <div style={{ overflowY: 'auto', background: 'var(--bg-base)', padding: '24px' }}>
          {page.kind === 'idle' && <EmptyState />}
          {page.kind === 'loading' && <LoadingState />}
          {page.kind === 'error' && <ErrorState message={page.message} />}
          {page.kind === 'result' && <ResultsDashboard data={page.data} />}
        </div>
      </div>
    </div>
  )
}

function EmptyState() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 16, color: 'var(--text-muted)' }}>
      <div style={{ fontSize: 72, opacity: .15 }}>🛡</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-secondary)' }}>No analysis yet</div>
      <div style={{ fontSize: 13 }}>Select a preset or fill in the form, then click Analyze Email</div>
      <div style={{ display: 'flex', gap: 24, marginTop: 12 }}>
        {[
          { icon: '🔐', label: 'Header Analysis', desc: 'SPF / DKIM / DMARC' },
          { icon: '🔗', label: 'URL Scanning',     desc: 'VirusTotal + Safe Browsing' },
          { icon: '🌐', label: 'IP Reputation',    desc: 'AbuseIPDB lookup' },
          { icon: '📛', label: 'Domain Age',       desc: 'WHOIS validation' },
          { icon: '🧠', label: 'Behavior',         desc: 'Urgency & credential patterns' },
        ].map(c => (
          <div key={c.label} style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)', padding: '14px 16px',
            textAlign: 'center', minWidth: 110,
          }}>
            <div style={{ fontSize: 24, marginBottom: 6 }}>{c.icon}</div>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 3 }}>{c.label}</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{c.desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function LoadingState() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 16 }}>
      <div style={{ position: 'relative', width: 64, height: 64 }}>
        <div style={{
          width: 64, height: 64, border: '3px solid var(--border)',
          borderTopColor: 'var(--blue)', borderRadius: '50%',
          animation: 'spin .8s linear infinite',
        }} />
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22 }}>🛡</div>
      </div>
      <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-secondary)' }}>Scanning email…</div>
      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Running parallel threat intelligence checks</div>
      <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
        {['Headers', 'URLs', 'IP Rep', 'Domain', 'Behavior'].map((l, i) => (
          <span key={l} style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 20, padding: '3px 10px', fontSize: 11, color: 'var(--text-muted)',
            animation: `pulse 1.5s ${i * .2}s infinite`,
          }}>{l}</span>
        ))}
      </div>
    </div>
  )
}

function ErrorState({ message }: { message: string }) {
  return (
    <div style={{
      background: '#1a0505', border: '1px solid #7f1d1d',
      borderRadius: 'var(--radius-lg)', padding: '24px',
      maxWidth: 600,
    }}>
      <div style={{ color: 'var(--danger)', fontWeight: 700, fontSize: 16, marginBottom: 10 }}>❌ Analysis Failed</div>
      <pre style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: '#fca5a5', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
        {message}
      </pre>
    </div>
  )
}
