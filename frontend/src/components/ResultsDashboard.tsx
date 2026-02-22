import React from 'react'
import type { AnalyzeResponse } from '../types'
import VerdictHero from './VerdictHero'
import TopContributors from './TopContributors'
import SignalsTable from './SignalsTable'
import BreakdownPanel from './BreakdownPanel'
import EvidenceLog from './EvidenceLog'
import JsonViewer from './JsonViewer'

interface Props {
  data: AnalyzeResponse
}

function SectionHeader({ emoji, title, count }: { emoji: string; title: string; count?: number }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
      <h2 style={{ fontSize: 14, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
        <span>{emoji}</span> {title}
      </h2>
      {count !== undefined && (
        <span style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 12, padding: '1px 8px', fontSize: 11, color: 'var(--text-muted)' }}>
          {count}
        </span>
      )}
    </div>
  )
}

export default function ResultsDashboard({ data }: Props) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }} className="animate-fadein">

      {/* ─ Verdict Hero ─ */}
      <VerdictHero data={data} />

      {/* ─ AI Explanation ─ */}
      <div style={{
        background: 'linear-gradient(135deg, #0f1630, #1a0f2e)',
        border: '1px solid #2e2d5e',
        borderRadius: 'var(--radius-lg)',
        padding: '20px 24px',
        display: 'flex',
        gap: 16,
      }}>
        <span style={{ fontSize: 32, flexShrink: 0 }}>🤖</span>
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.1em', color: '#818cf8', marginBottom: 8 }}>
            AI Analysis — GPT-4o
          </div>
          <p style={{ fontSize: 14, lineHeight: 1.8, color: '#c7d2fe' }}>{data.explanation}</p>
        </div>
      </div>

      {/* ─ Top Contributors ─ */}
      {data.top_contributors.length > 0 && (
        <div>
          <SectionHeader emoji="🏆" title="Top Contributors" count={data.top_contributors.length} />
          <TopContributors signals={data.top_contributors} />
        </div>
      )}

      {/* ─ Scoring Breakdown ─ */}
      <div>
        <SectionHeader emoji="📊" title="Scoring Breakdown" />
        <BreakdownPanel breakdown={data.scoring_breakdown} />
      </div>

      {/* ─ All Signals ─ */}
      <div>
        <SectionHeader emoji="📋" title="All Signals" count={data.signals.length} />
        <SignalsTable signals={data.signals} />
      </div>

      {/* ─ Evidence Log ─ */}
      <EvidenceLog evidence={data.evidence} />

      {/* ─ Raw JSON ─ */}
      <JsonViewer data={data} />
    </div>
  )
}
