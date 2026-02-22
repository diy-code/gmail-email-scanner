import React from 'react'

interface Props {
  score: number
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  size?: number
}

const VERDICT_COLOR = {
  SAFE: '#22c55e',
  SUSPICIOUS: '#f59e0b',
  MALICIOUS: '#ef4444',
}

export default function ScoreGauge({ score, verdict, size = 120 }: Props) {
  const color  = VERDICT_COLOR[verdict]
  const r      = (size / 2) - 10
  const circ   = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: 'rotate(-90deg)' }}>
        {/* Glow filter */}
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Track */}
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke="var(--border)"
          strokeWidth={10}
        />
        {/* Value arc */}
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          filter="url(#glow)"
          style={{ transition: 'stroke-dashoffset .8s cubic-bezier(.4,0,.2,1), stroke .4s' }}
        />
      </svg>

      {/* Center label */}
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ fontSize: size * .26, fontWeight: 900, color, lineHeight: 1, letterSpacing: '-.03em' }}>{score}</span>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1 }}>/ 100</span>
      </div>
    </div>
  )
}
