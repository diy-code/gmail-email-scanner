import React from 'react'
import type { AnalyzeResponse } from '../types'
import ScoreGauge from './ScoreGauge'

const VERDICT_META = {
  SAFE:       { icon: '✅', color: '#22c55e', bg: '#052e16', border: '#166534', glow: 'rgba(34,197,94,.2)' },
  SUSPICIOUS: { icon: '⚠️', color: '#f59e0b', bg: '#1a0f00', border: '#92400e', glow: 'rgba(245,158,11,.2)' },
  MALICIOUS:  { icon: '🚨', color: '#ef4444', bg: '#1a0505', border: '#991b1b', glow: 'rgba(239,68,68,.2)' },
}

const CONF_COLOR = { High: '#22c55e', Medium: '#f59e0b', Low: '#ef4444' }

interface Props {
  data: AnalyzeResponse
}

export default function VerdictHero({ data }: Props) {
  const meta = VERDICT_META[data.verdict]
  const confColor = CONF_COLOR[data.confidence_label]

  return (
    <div style={{
      background: `linear-gradient(135deg, var(--bg-surface), ${meta.bg})`,
      border: `1px solid ${meta.border}`,
      borderRadius: 'var(--radius-xl)',
      padding: '28px 32px',
      display: 'flex',
      alignItems: 'center',
      gap: 32,
      boxShadow: `0 0 40px ${meta.glow}`,
      flexWrap: 'wrap',
    }}>
      {/* Score */}
      <ScoreGauge score={data.score} verdict={data.verdict} size={130} />

      {/* Verdict + Meta */}
      <div style={{ flex: 1, minWidth: 200 }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: 10,
          padding: '8px 20px',
          borderRadius: 'var(--radius-md)',
          border: `1px solid ${meta.border}`,
          background: meta.bg,
          marginBottom: 14,
        }}>
          <span style={{ fontSize: 20 }}>{meta.icon}</span>
          <span style={{ fontSize: 22, fontWeight: 900, color: meta.color, letterSpacing: '.06em' }}>{data.verdict}</span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {[
            { label: 'Score', value: `${data.score}/100`, color: meta.color },
            { label: 'Signals', value: data.signals.length },
            { label: 'Analysis', value: `${data.analysis_time_ms} ms` },
            { label: 'Request ID', value: data.request_id.slice(0, 8) + '…', mono: true },
          ].map(c => (
            <div key={c.label} style={{
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border)',
              borderRadius: 20,
              padding: '5px 14px',
              display: 'flex', gap: 6, alignItems: 'center',
            }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{c.label}</span>
              <span style={{
                fontSize: 12, fontWeight: 700,
                color: c.color ?? 'var(--text-primary)',
                fontFamily: c.mono ? "'JetBrains Mono', monospace" : undefined,
              }}>{String(c.value)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Confidence */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
        <div style={{
          width: 80, height: 80, borderRadius: '50%',
          border: `3px solid ${confColor}`,
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          boxShadow: `0 0 16px ${confColor}40`,
        }}>
          <span style={{ fontSize: 20, fontWeight: 900, color: confColor, lineHeight: 1 }}>{data.confidence}%</span>
        </div>
        <span style={{ fontSize: 11, color: confColor, fontWeight: 700 }}>{data.confidence_label} Confidence</span>
      </div>
    </div>
  )
}
