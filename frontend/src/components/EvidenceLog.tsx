import React, { useState } from 'react'
import type { EvidenceItem } from '../types'

interface Props {
  evidence: EvidenceItem[]
}

export default function EvidenceLog({ evidence }: Props) {
  const [open, setOpen] = useState(false)

  if (!evidence.length) return null

  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
      <button
        onClick={() => setOpen(p => !p)}
        style={{
          width: '100%', background: 'none', border: 'none',
          padding: '14px 18px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          color: 'var(--text-primary)', fontSize: 13, fontWeight: 700, cursor: 'pointer',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = '#ffffff05')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      >
        <span>🗂 Evidence Log ({evidence.length} items)</span>
        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div style={{ borderTop: '1px solid var(--border)', overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 500 }}>
            <thead>
              <tr style={{ background: 'var(--bg-elevated)' }}>
                {['Signal', 'Source', 'Raw Value', 'Points'].map(h => (
                  <th key={h} style={{ padding: '8px 14px', textAlign: 'left', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {evidence.map((e, i) => (
                <tr key={i} style={{ borderTop: '1px solid var(--border)' }}
                  onMouseEnter={ev => (ev.currentTarget.style.background = '#ffffff05')}
                  onMouseLeave={ev => (ev.currentTarget.style.background = 'transparent')}
                >
                  <td style={{ padding: '9px 14px', fontWeight: 600, fontSize: 12, whiteSpace: 'nowrap' }}>{e.signal}</td>
                  <td style={{ padding: '9px 14px', color: 'var(--text-muted)', fontSize: 12 }}>{e.source}</td>
                  <td style={{ padding: '9px 14px', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--blue)', maxWidth: 260, wordBreak: 'break-all' }}>{e.raw_value}</td>
                  <td style={{ padding: '9px 14px', color: 'var(--danger)', fontWeight: 700, fontSize: 13 }}>+{e.points}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
