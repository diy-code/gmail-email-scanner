import React from 'react'
import type { Signal } from '../types'

const CAT_STYLE: Record<string, { bg: string; color: string }> = {
  header:   { bg: '#0f2040', color: '#60a5fa' },
  url:      { bg: '#0a2010', color: '#4ade80' },
  ip:       { bg: '#1a0a24', color: '#e879f9' },
  domain:   { bg: '#1f1400', color: '#fbbf24' },
  behavior: { bg: '#12141a', color: '#94a3b8' },
}

const SEV_STYLE: Record<string, { bg: string; color: string }> = {
  critical: { bg: '#3b0a0a', color: '#fca5a5' },
  high:     { bg: '#2d0a0a', color: '#f87171' },
  medium:   { bg: '#1a1200', color: '#fcd34d' },
  low:      { bg: '#052e16', color: '#86efac' },
}

export function CatTag({ cat }: { cat: string }) {
  const s = CAT_STYLE[cat] ?? { bg: '#111', color: '#888' }
  return (
    <span style={{ background: s.bg, color: s.color, borderRadius: 4, padding: '2px 7px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.04em' }}>
      {cat}
    </span>
  )
}

export function SevTag({ sev }: { sev: string }) {
  const s = SEV_STYLE[sev] ?? { bg: '#111', color: '#888' }
  return (
    <span style={{ background: s.bg, color: s.color, borderRadius: 4, padding: '2px 7px', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.04em' }}>
      {sev}
    </span>
  )
}

interface Props {
  signals: Signal[]
}

export default function TopContributors({ signals }: Props) {
  if (!signals.length) return null

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 12 }}>
      {signals.map((s, i) => (
        <div key={i} style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          padding: '16px',
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
          position: 'relative',
          overflow: 'hidden',
        }}>
          {/* Rank badge */}
          <div style={{
            position: 'absolute', top: 10, right: 12,
            width: 24, height: 24, borderRadius: '50%',
            background: i === 0 ? '#7f1d1d' : 'var(--bg-elevated)',
            color: i === 0 ? '#fca5a5' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, fontWeight: 700,
          }}>#{i + 1}</div>

          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            <CatTag cat={s.category} />
            <SevTag sev={s.severity} />
          </div>

          <div>
            <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4 }}>{s.name}</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{s.description}</div>
          </div>

          {s.value && (
            <div style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)',
              padding: '5px 9px',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11,
              color: 'var(--blue)',
              wordBreak: 'break-all',
            }}>{s.value}</div>
          )}

          <div style={{
            display: 'flex', alignItems: 'baseline', gap: 4,
            borderTop: '1px solid var(--border)', paddingTop: 10, marginTop: 2,
          }}>
            <span style={{ fontSize: 26, fontWeight: 900, color: 'var(--danger)', lineHeight: 1 }}>+{s.points}</span>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>points</span>
          </div>
        </div>
      ))}
    </div>
  )
}
