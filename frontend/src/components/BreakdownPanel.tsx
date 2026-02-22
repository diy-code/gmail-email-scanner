import React from 'react'
import type { ScoringBreakdown } from '../types'

const CAT_META: Record<string, { cap: number; color: string; icon: string }> = {
  header:   { cap: 45, color: '#3b82f6', icon: '🔐' },
  url:      { cap: 55, color: '#22c55e', icon: '🔗' },
  ip:       { cap: 20, color: '#d946ef', icon: '🌐' },
  domain:   { cap: 20, color: '#f59e0b', icon: '📛' },
  behavior: { cap: 10, color: '#94a3b8', icon: '🧠' },
}

interface Props {
  breakdown: ScoringBreakdown
}

export default function BreakdownPanel({ breakdown }: Props) {
  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 20, display: 'flex', flexDirection: 'column', gap: 18 }}>

      {/* Totals row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {[
          { label: 'Raw Points', value: breakdown.total_points, sub: 'before caps' },
          { label: 'After Caps', value: breakdown.capped_points, sub: 'category-limited' },
          { label: 'Max Possible', value: breakdown.max_points, sub: 'theoretical max' },
        ].map(s => (
          <div key={s.label} style={{
            background: 'var(--bg-elevated)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)', padding: '14px', textAlign: 'center',
          }}>
            <div style={{ fontSize: 28, fontWeight: 900, lineHeight: 1 }}>{s.value}</div>
            <div style={{ fontSize: 12, fontWeight: 600, marginTop: 4 }}>{s.label}</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{s.sub}</div>
          </div>
        ))}
      </div>

      {/* Category bars */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {Object.entries(CAT_META).map(([cat, meta]) => {
          const pts  = breakdown.category_points?.[cat] ?? 0
          const pct  = meta.cap > 0 ? Math.min(100, (pts / meta.cap) * 100) : 0
          const over = pts > meta.cap

          return (
            <div key={cat} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 64px', alignItems: 'center', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'flex-end' }}>
                <span style={{ fontSize: 13 }}>{meta.icon}</span>
                <span style={{ fontSize: 11, color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{cat}</span>
              </div>
              <div style={{ position: 'relative', height: 10, background: 'var(--border)', borderRadius: 99, overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${pct}%`,
                  background: meta.color,
                  borderRadius: 99,
                  transition: 'width .7s cubic-bezier(.4,0,.2,1)',
                  boxShadow: pts > 0 ? `0 0 8px ${meta.color}60` : 'none',
                }} />
              </div>
              <div style={{ fontSize: 12, fontWeight: 700, color: over ? 'var(--danger)' : 'var(--text-primary)', textAlign: 'right' }}>
                {pts}<span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>/{meta.cap}</span>
              </div>
            </div>
          )
        })}
      </div>

      {/* Formula */}
      <div style={{ background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '10px 14px' }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 5 }}>Scoring Formula</div>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#a5b4fc', wordBreak: 'break-all', lineHeight: 1.6 }}>
          {breakdown.formula}
        </div>
      </div>
    </div>
  )
}
