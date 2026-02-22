import React, { useState } from 'react'

interface Props {
  data: unknown
}

function colorize(json: string) {
  return json
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, (match) => {
      let cls = 'color:#a5b4fc' // number
      if (/^"/.test(match)) {
        if (/:$/.test(match)) cls = 'color:#7dd3fc' // key
        else cls = 'color:#86efac' // string value
      } else if (/true|false/.test(match)) cls = 'color:#f59e0b'
      else if (/null/.test(match)) cls = 'color:#ef4444'
      return `<span style="${cls}">${match}</span>`
    })
}

export default function JsonViewer({ data }: Props) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const raw = JSON.stringify(data, null, 2)

  const copy = async () => {
    await navigator.clipboard.writeText(raw)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

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
        <span>{'{}'} Raw JSON Response</span>
        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div style={{ borderTop: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', padding: '8px 14px', borderBottom: '1px solid var(--border)' }}>
            <button
              onClick={copy}
              style={{
                background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', color: copied ? 'var(--safe)' : 'var(--text-secondary)',
                padding: '4px 12px', fontSize: 11, fontWeight: 600,
              }}
            >
              {copied ? '✓ Copied' : '📋 Copy JSON'}
            </button>
          </div>
          <div style={{ padding: 16, maxHeight: 460, overflowY: 'auto' }}>
            <pre
              style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, lineHeight: 1.7, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
              dangerouslySetInnerHTML={{ __html: colorize(raw) }}
            />
          </div>
        </div>
      )}
    </div>
  )
}
