export interface AnalyzeRequest {
  subject: string
  sender: string
  reply_to?: string | null
  authentication_results?: string | null
  received_headers: string[]
  body_plain: string
  body_html: string
  urls: string[]
  message_date?: string | null
}

export interface Signal {
  name: string
  category: 'header' | 'url' | 'ip' | 'domain' | 'behavior'
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  value?: string | null
  points: number
}

export interface EvidenceItem {
  signal: string
  source: string
  raw_value: string
  points: number
}

export interface ScoringBreakdown {
  total_points: number
  capped_points: number
  max_points: number
  formula: string
  category_points: Record<string, number>
}

export interface AnalyzeResponse {
  request_id: string
  score: number
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
  confidence: number
  confidence_label: 'High' | 'Medium' | 'Low'
  signals: Signal[]
  top_contributors: Signal[]
  evidence: EvidenceItem[]
  scoring_breakdown: ScoringBreakdown
  explanation: string
  analysis_time_ms: number
}

export interface HealthResponse {
  status: string
  version: string
}

export type HealthStatus = 'idle' | 'checking' | 'ok' | 'error'
