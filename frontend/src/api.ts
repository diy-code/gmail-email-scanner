import type { AnalyzeRequest, AnalyzeResponse, HealthResponse } from './types'

export async function checkHealth(baseUrl: string): Promise<HealthResponse> {
  const resp = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(5000) })
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json()
}

export async function analyzeEmail(
  baseUrl: string,
  apiKey: string,
  payload: AnalyzeRequest
): Promise<AnalyzeResponse> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (apiKey) headers['X-API-Key'] = apiKey

  const resp = await fetch(`${baseUrl}/analyze`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  })

  const data = await resp.json()
  if (!resp.ok) throw new Error(data.detail ?? `HTTP ${resp.status}`)
  return data as AnalyzeResponse
}
