import React, { useState } from 'react'
import type { AnalyzeRequest } from '../types'
import { PRESETS } from '../presets'

interface Props {
  form: AnalyzeRequest
  onChange: (form: AnalyzeRequest) => void
  onSubmit: () => void
  loading: boolean
}

export default function EmailForm({ form, onChange, onSubmit, loading }: Props) {
  const [tab, setTab]           = useState<'form' | 'json'>('form')
  const [jsonText, setJsonText] = useState('')
  const [jsonError, setJsonError] = useState('')

  const applyJson = () => {
    setJsonError('')
    try {
      const parsed = JSON.parse(jsonText)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        setJsonError('Must be a JSON object')
        return
      }
      onChange({
        subject:                parsed.subject                ?? '',
        sender:                 parsed.sender                 ?? '',
        reply_to:               parsed.reply_to               ?? null,
        authentication_results: parsed.authentication_results ?? null,
        received_headers:       Array.isArray(parsed.received_headers) ? parsed.received_headers : [],
        body_plain:             parsed.body_plain             ?? '',
        body_html:              parsed.body_html              ?? '',
        urls:                   Array.isArray(parsed.urls)    ? parsed.urls.slice(0, 10) : [],
        message_date:           parsed.message_date           ?? null,
      })
      setJsonError('')
      setTab('form')
    } catch (e) {
      setJsonError('Invalid JSON — ' + (e instanceof Error ? e.message : String(e)))
    }
  }

  const set = (key: keyof AnalyzeRequest) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => onChange({ ...form, [key]: e.target.value })

  const setReceivedHeaders = (raw: string) =>
    onChange({ ...form, received_headers: raw.split('\n').filter(Boolean) })

  const setUrls = (raw: string) =>
    onChange({ ...form, urls: raw.split('\n').filter(Boolean).slice(0, 10) })

  const tabBtn = (id: 'form' | 'json', label: string, icon: string) => (
    <button
      onClick={() => { setTab(id); setJsonError('') }}
      style={{
        flex: 1,
        padding: '8px 0',
        border: 'none',
        borderRadius: 'var(--radius-sm)',
        background: tab === id ? 'linear-gradient(135deg,#1d4ed8,#7c3aed)' : 'transparent',
        color: tab === id ? 'white' : 'var(--text-muted)',
        fontWeight: 700,
        fontSize: 12,
        cursor: 'pointer',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        transition: 'all .15s',
      }}
    >
      <span>{icon}</span> {label}
    </button>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Tab switcher ── */}
      <div style={{
        display: 'flex',
        gap: 4,
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        padding: 4,
      }}>
        {tabBtn('form', 'Fill Form', '📝')}
        {tabBtn('json', 'Paste JSON', '{ }')}
      </div>

      {/* ── JSON Tab ── */}
      {tab === 'json' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <textarea
            autoFocus
            style={{ ...textareaS, minHeight: 320, fontSize: 12 }}
            value={jsonText}
            onChange={e => { setJsonText(e.target.value); setJsonError('') }}
            placeholder={'Paste an AnalyzeRequest JSON object here:\n\n{\n  "subject": "...",\n  "sender": "user@domain.com",\n  "reply_to": null,\n  "authentication_results": "spf=pass ...",\n  "received_headers": [],\n  "body_plain": "...",\n  "body_html": "",\n  "urls": []\n}'}
            spellCheck={false}
          />
          {jsonError && (
            <div style={{
              fontSize: 12, color: 'var(--danger)',
              background: 'rgba(239,68,68,.08)',
              border: '1px solid rgba(239,68,68,.3)',
              borderRadius: 'var(--radius-sm)',
              padding: '8px 12px',
            }}>
              ⚠ {jsonError}
            </div>
          )}
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={applyJson}
              disabled={!jsonText.trim()}
              style={{
                flex: 1, padding: '10px',
                borderRadius: 'var(--radius-md)', border: 'none',
                background: jsonText.trim() ? 'linear-gradient(135deg,#1d4ed8,#7c3aed)' : 'var(--bg-elevated)',
                color: jsonText.trim() ? 'white' : 'var(--text-muted)',
                fontWeight: 700, fontSize: 13, cursor: jsonText.trim() ? 'pointer' : 'not-allowed',
                boxShadow: jsonText.trim() ? '0 0 20px rgba(59,130,246,.25)' : 'none',
              }}
            >
              ✓ Apply JSON
            </button>
            <button
              onClick={() => { setJsonText(JSON.stringify(form, null, 2)); setJsonError('') }}
              title="Export current form state as JSON"
              style={{
                padding: '10px 14px',
                borderRadius: 'var(--radius-md)', border: '1px solid var(--border)',
                background: 'var(--bg-input)', color: 'var(--text-secondary)',
                fontWeight: 600, fontSize: 12, cursor: 'pointer',
              }}
            >
              ↗ Export
            </button>
          </div>
        </div>
      )}

      {/* ── Form Tab ── */}
      {tab === 'form' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Presets — threat spectrum */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <SectionLabel>Threat Spectrum (0 → 100)</SectionLabel>
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>click any to load</span>
            </div>
            <div style={{
              height: 4, borderRadius: 99, marginBottom: 10,
              background: 'linear-gradient(to right, #22c55e, #84cc16, #eab308, #f97316, #ef4444)',
            }} />
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
              {PRESETS.map(p => {
                const score = p.expectedScore
                const color  = score <= 30 ? '#22c55e' : score <= 65 ? '#f59e0b' : '#ef4444'
                const bg     = score <= 30 ? '#052e16' : score <= 65 ? '#1a1200' : '#1a0505'
                const border = score <= 30 ? '#166534' : score <= 65 ? '#92400e' : '#7f1d1d'
                return (
                  <button
                    key={p.id}
                    onClick={() => onChange(p.data)}
                    title={`~${score} pts — ${p.label}`}
                    style={{
                      padding: '7px 6px', borderRadius: 'var(--radius-sm)',
                      border: `1px solid ${border}`, background: bg, color,
                      fontWeight: 600, fontSize: 11,
                      display: 'flex', flexDirection: 'column', alignItems: 'center',
                      gap: 3, cursor: 'pointer', lineHeight: 1.2,
                    }}
                  >
                    <span style={{ fontSize: 16 }}>{p.icon}</span>
                    <span style={{ textAlign: 'center', wordBreak: 'break-word' }}>{p.label}</span>
                    <span style={{ fontSize: 10, opacity: .7 }}>~{score}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Email Details */}
          <Section title="Email Details">
            <Field label="Subject" required>
              <input style={inputS} value={form.subject} onChange={set('subject')} placeholder="Email subject line" />
            </Field>
            <Field label="From (Sender)" required>
              <input style={inputS} value={form.sender} onChange={set('sender')} placeholder="Display Name <user@domain.com>" />
            </Field>
            <Row>
              <Field label="Reply-To">
                <input style={inputS} value={form.reply_to ?? ''} onChange={set('reply_to')} placeholder="optional" />
              </Field>
              <Field label="Message Date">
                <input style={inputS} value={form.message_date ?? ''} onChange={set('message_date')} placeholder="RFC 2822 date" />
              </Field>
            </Row>
          </Section>

          {/* Headers */}
          <Section title="Authentication Headers">
            <Field label="Authentication-Results">
              <textarea style={{ ...textareaS, minHeight: 64 }} value={form.authentication_results ?? ''} onChange={set('authentication_results')} placeholder="spf=pass dkim=pass dmarc=pass" />
            </Field>
            <Field label="Received Headers" hint="One header per line">
              <textarea style={{ ...textareaS, minHeight: 72 }} value={form.received_headers.join('\n')} onChange={e => setReceivedHeaders(e.target.value)} placeholder={'Received: from mail.evil.com ([1.2.3.4]) by mx.google.com'} />
            </Field>
          </Section>

          {/* Body */}
          <Section title="Email Body">
            <Field label="Plain Text Body" required>
              <textarea style={{ ...textareaS, minHeight: 96 }} value={form.body_plain} onChange={set('body_plain')} placeholder="Paste plain-text body..." />
            </Field>
            <Field label="HTML Body" hint="Optional">
              <textarea style={{ ...textareaS, minHeight: 56 }} value={form.body_html} onChange={set('body_html')} placeholder="<html>…</html>" />
            </Field>
          </Section>

          {/* URLs */}
          <Section title="URLs (max 10)">
            <Field label="Extracted URLs" hint="One per line">
              <textarea style={{ ...textareaS, minHeight: 64 }} value={form.urls.join('\n')} onChange={e => setUrls(e.target.value)} placeholder={'https://example.com/link'} />
            </Field>
          </Section>

          {/* Submit */}
          <button
            onClick={onSubmit}
            disabled={loading || !form.subject || !form.sender}
            style={{
              padding: '13px', borderRadius: 'var(--radius-md)', border: 'none',
              background: loading ? 'var(--bg-elevated)' : 'linear-gradient(135deg, #1d4ed8, #7c3aed)',
              color: loading ? 'var(--text-muted)' : 'white',
              fontWeight: 700, fontSize: 14, letterSpacing: '.02em',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              opacity: loading || !form.subject || !form.sender ? .5 : 1,
              boxShadow: loading ? 'none' : '0 0 24px rgba(59,130,246,.25)',
              cursor: loading || !form.subject || !form.sender ? 'not-allowed' : 'pointer',
            }}
          >
            {loading ? (
              <>
                <span style={{ width: 16, height: 16, border: '2px solid #fff3', borderTopColor: '#fff', borderRadius: '50%', display: 'inline-block', animation: 'spin .7s linear infinite' }} />
                Analyzing…
              </>
            ) : '🔍 Analyze Email'}
          </button>
        </div>
      )}
    </div>
  )
}

/* ─── sub-components ─── */
function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.1em', color: 'var(--text-muted)' }}>
      {children}
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
      <SectionLabel>{title}</SectionLabel>
      {children}
    </div>
  )
}

function Field({ label, required, hint, children }: { label: string; required?: boolean; hint?: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
        <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{label}</span>
        {required && <span style={{ fontSize: 10, color: 'var(--danger)' }}>*</span>}
        {hint && <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 4 }}>{hint}</span>}
      </div>
      {children}
    </div>
  )
}

function Row({ children }: { children: React.ReactNode }) {
  return <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>{children}</div>
}

const inputS: React.CSSProperties = {
  background: 'var(--bg-input)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  color: 'var(--text-primary)',
  padding: '7px 10px',
  width: '100%',
  outline: 'none',
}

const textareaS: React.CSSProperties = {
  ...inputS,
  resize: 'vertical',
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: 12,
  lineHeight: 1.6,
}
