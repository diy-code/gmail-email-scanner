import React from 'react'
import type { AnalyzeRequest } from '../types'
import { PRESETS } from '../presets'

interface Props {
  form: AnalyzeRequest
  onChange: (form: AnalyzeRequest) => void
  onSubmit: () => void
  loading: boolean
}

export default function EmailForm({ form, onChange, onSubmit, loading }: Props) {
  const set = (key: keyof AnalyzeRequest) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => onChange({ ...form, [key]: e.target.value })

  const setReceivedHeaders = (raw: string) =>
    onChange({ ...form, received_headers: raw.split('\n').filter(Boolean) })

  const setUrls = (raw: string) =>
    onChange({ ...form, urls: raw.split('\n').filter(Boolean).slice(0, 10) })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, height: '100%' }}>

      {/* Presets */}
      <div>
        <SectionLabel>Quick Presets</SectionLabel>
        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
          {PRESETS.map(p => (
            <button
              key={p.id}
              onClick={() => onChange(p.data)}
              style={{
                flex: 1,
                padding: '9px 12px',
                borderRadius: 'var(--radius-md)',
                border: `1px solid ${p.variant === 'safe' ? '#166534' : '#7f1d1d'}`,
                background: p.variant === 'safe' ? '#052e16' : '#1a0a0a',
                color: p.variant === 'safe' ? '#4ade80' : '#fca5a5',
                fontWeight: 600,
                fontSize: 12,
                transition: 'all .15s',
              }}
            >
              {p.icon} {p.label}
            </button>
          ))}
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
          <textarea
            style={{ ...textareaS, minHeight: 64 }}
            value={form.authentication_results ?? ''}
            onChange={set('authentication_results')}
            placeholder="spf=pass dkim=pass dmarc=pass"
          />
        </Field>
        <Field label="Received Headers" hint="One header per line">
          <textarea
            style={{ ...textareaS, minHeight: 72 }}
            value={form.received_headers.join('\n')}
            onChange={e => setReceivedHeaders(e.target.value)}
            placeholder={'Received: from mail.evil.com ([1.2.3.4]) by mx.google.com'}
          />
        </Field>
      </Section>

      {/* Body */}
      <Section title="Email Body">
        <Field label="Plain Text Body" required>
          <textarea
            style={{ ...textareaS, minHeight: 96 }}
            value={form.body_plain}
            onChange={set('body_plain')}
            placeholder="Paste plain-text body..."
          />
        </Field>
        <Field label="HTML Body" hint="Optional">
          <textarea
            style={{ ...textareaS, minHeight: 56 }}
            value={form.body_html}
            onChange={set('body_html')}
            placeholder="<html>…</html>"
          />
        </Field>
      </Section>

      {/* URLs */}
      <Section title="URLs (max 10)">
        <Field label="Extracted URLs" hint="One per line">
          <textarea
            style={{ ...textareaS, minHeight: 64 }}
            value={form.urls.join('\n')}
            onChange={e => setUrls(e.target.value)}
            placeholder={'https://example.com/link'}
          />
        </Field>
      </Section>

      {/* Submit */}
      <button
        onClick={onSubmit}
        disabled={loading || !form.subject || !form.sender}
        style={{
          padding: '13px',
          borderRadius: 'var(--radius-md)',
          border: 'none',
          background: loading
            ? 'var(--bg-elevated)'
            : 'linear-gradient(135deg, #1d4ed8, #7c3aed)',
          color: loading ? 'var(--text-muted)' : 'white',
          fontWeight: 700,
          fontSize: 14,
          letterSpacing: '.02em',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 8,
          transition: 'opacity .15s',
          opacity: loading || !form.subject || !form.sender ? .5 : 1,
          boxShadow: loading ? 'none' : '0 0 24px rgba(59,130,246,.25)',
        }}
      >
        {loading ? (
          <>
            <span style={{ width: 16, height: 16, border: '2px solid #fff3', borderTopColor: '#fff', borderRadius: '50%', display: 'inline-block', animation: 'spin .7s linear infinite' }} />
            Analyzing…
          </>
        ) : (
          <> 🔍 Analyze Email </>
        )}
      </button>
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
