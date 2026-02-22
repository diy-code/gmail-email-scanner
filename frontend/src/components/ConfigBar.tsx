import React from 'react'
import type { HealthStatus } from '../types'

interface Props {
  url: string
  apiKey: string
  health: HealthStatus
  healthVersion: string
  onUrlChange: (v: string) => void
  onKeyChange: (v: string) => void
  onPing: () => void
}

const DOT_COLOR: Record<HealthStatus, string> = {
  idle: '#444d5c',
  checking: '#f59e0b',
  ok: '#22c55e',
  error: '#ef4444',
}

const DOT_LABEL: Record<HealthStatus, string> = {
  idle: 'Not checked',
  checking: 'Checking…',
  ok: '',
  error: 'Unreachable',
}

export default function ConfigBar({ url, apiKey, health, healthVersion, onUrlChange, onKeyChange, onPing }: Props) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      borderBottom: '1px solid var(--border)',
      padding: '12px 20px',
      display: 'flex',
      alignItems: 'center',
      gap: 16,
      flexWrap: 'wrap',
    }}>
      {/* Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginRight: 8 }}>
        <span style={{ fontSize: 22 }}>🛡</span>
        <div>
          <div style={{ fontWeight: 800, fontSize: 13, letterSpacing: '-.01em' }}>Email Scanner</div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Debug UI</div>
        </div>
      </div>

      <div style={{ width: 1, height: 36, background: 'var(--border)' }} />

      {/* URL */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <label style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.06em' }}>Backend URL</label>
        <input
          value={url}
          onChange={e => onUrlChange(e.target.value)}
          style={inputStyle}
          placeholder="http://127.0.0.1:8080"
        />
      </div>

      {/* API Key */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <label style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.06em' }}>API Key</label>
        <input
          value={apiKey}
          onChange={e => onKeyChange(e.target.value)}
          type="password"
          style={{ ...inputStyle, width: 180 }}
          placeholder="X-API-Key value"
        />
      </div>

      {/* Health */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto' }}>
        <span style={{
          width: 8, height: 8, borderRadius: '50%',
          background: DOT_COLOR[health],
          display: 'inline-block',
          boxShadow: health === 'ok' ? '0 0 6px #22c55e' : health === 'checking' ? '0 0 6px #f59e0b' : 'none',
          animation: health === 'checking' ? 'pulse 1s infinite' : 'none',
        }} />
        <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
          {health === 'ok' ? `v${healthVersion} — healthy` : DOT_LABEL[health]}
        </span>
        <button onClick={onPing} style={pingBtnStyle}>Ping /health</button>
      </div>
    </div>
  )
}

const inputStyle: React.CSSProperties = {
  background: 'var(--bg-input)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--text-primary)',
  padding: '5px 10px',
  width: 220,
  outline: 'none',
  fontSize: 13,
}

const pingBtnStyle: React.CSSProperties = {
  background: 'var(--bg-elevated)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--text-secondary)',
  padding: '5px 12px',
  fontSize: 12,
  fontWeight: 500,
  transition: 'all .15s',
}
