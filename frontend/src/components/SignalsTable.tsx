import React, { useState } from 'react'
import type { Signal } from '../types'
import { CatTag, SevTag } from './TopContributors'

interface Props {
  signals: Signal[]
}

type SortKey = 'points' | 'severity' | 'category' | 'name'
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 }

export default function SignalsTable({ signals }: Props) {
  const [sort, setSort] = useState<SortKey>('points')
  const [asc, setAsc] = useState(false)
  const [filter, setFilter] = useState('')

  const sorted = [...signals]
    .filter(s => !filter || s.name.toLowerCase().includes(filter) || s.category.includes(filter) || s.description.toLowerCase().includes(filter))
    .sort((a, b) => {
      let diff = 0
      if (sort === 'points')   diff = a.points - b.points
      if (sort === 'severity') diff = (SEV_ORDER[a.severity] ?? 0) - (SEV_ORDER[b.severity] ?? 0)
      if (sort === 'category') diff = a.category.localeCompare(b.category)
      if (sort === 'name')     diff = a.name.localeCompare(b.name)
      return asc ? diff : -diff
    })

  const toggleSort = (key: SortKey) => {
    if (sort === key) setAsc(p => !p)
    else { setSort(key); setAsc(false) }
  }

  if (!signals.length) return (
    <div style={{
      background: 'var(--bg-surface)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-md)', padding: '32px',
      textAlign: 'center', color: 'var(--text-muted)', fontSize: 14,
    }}>✅ No threat signals fired</div>
  )

  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
      {/* Toolbar */}
      <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
        <input
          value={filter}
          onChange={e => setFilter(e.target.value.toLowerCase())}
          placeholder="Filter signals…"
          style={{
            flex: 1, background: 'var(--bg-input)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', padding: '5px 10px',
            fontSize: 12, outline: 'none',
          }}
        />
        <span style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{sorted.length} signal{sorted.length !== 1 ? 's' : ''}</span>
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 620 }}>
          <thead>
            <tr style={{ background: 'var(--bg-elevated)' }}>
              {(['name', 'category', 'severity', 'points'] as SortKey[]).map(k => (
                <th key={k} onClick={() => toggleSort(k)} style={{
                  padding: '9px 14px', textAlign: 'left', fontSize: 10, fontWeight: 700,
                  textTransform: 'uppercase', letterSpacing: '.06em',
                  color: sort === k ? 'var(--blue)' : 'var(--text-muted)',
                  cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
                }}>
                  {k} {sort === k ? (asc ? '↑' : '↓') : ''}
                </th>
              ))}
              <th style={{ padding: '9px 14px', textAlign: 'left', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', color: 'var(--text-muted)' }}>Description</th>
              <th style={{ padding: '9px 14px', textAlign: 'left', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', color: 'var(--text-muted)' }}>Value</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((s, i) => (
              <tr key={i} style={{ borderTop: '1px solid var(--border)' }}
                onMouseEnter={e => (e.currentTarget.style.background = '#ffffff05')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                <td style={{ padding: '10px 14px', fontWeight: 600, fontSize: 13, whiteSpace: 'nowrap' }}>{s.name}</td>
                <td style={{ padding: '10px 14px' }}><CatTag cat={s.category} /></td>
                <td style={{ padding: '10px 14px' }}><SevTag sev={s.severity} /></td>
                <td style={{ padding: '10px 14px', color: 'var(--danger)', fontWeight: 700, fontSize: 14 }}>+{s.points}</td>
                <td style={{ padding: '10px 14px', color: 'var(--text-secondary)', fontSize: 12, maxWidth: 280 }}>{s.description}</td>
                <td style={{ padding: '10px 14px', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: 'var(--blue)', maxWidth: 180, wordBreak: 'break-all' }}>
                  {s.value ?? <span style={{ color: 'var(--text-muted)' }}>—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
