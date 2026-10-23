/** API client for the FastAPI backend. */
const BASE_URL = (import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000/api').replace(/\/$/, '')

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      ...options,
      headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
    })
  } catch (error) {
    throw new Error(`Cannot reach ${BASE_URL}. Check that the API is running and CORS is configured. ${error.message}`)
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    let detail = text || res.statusText
    try { detail = JSON.parse(text).detail || JSON.parse(text).message || detail } catch { /* response is not JSON */ }
    throw new Error(`HTTP ${res.status}: ${detail}`)
  }
  if (res.status === 204) return null
  const contentType = res.headers.get('content-type') || ''
  return contentType.includes('application/json') ? res.json() : res.text()
}

export function startInvestigation(target) {
  return request('/investigations', { method: 'POST', body: JSON.stringify({ target }) })
}
export function getInvestigations() { return request('/investigations') }
export function getInvestigation(id) { return request(`/investigations/${encodeURIComponent(id)}`) }
export function getFindings(id) { return request(`/investigations/${encodeURIComponent(id)}/findings`) }
export function getExecutions(id) { return request(`/investigations/${encodeURIComponent(id)}/executions`) }
export function getPendingApprovals() { return request('/approvals/pending') }
export function approveAction(id) { return request(`/approvals/${encodeURIComponent(id)}/approve`, { method: 'POST' }) }
export function rejectAction(id) { return request(`/approvals/${encodeURIComponent(id)}/reject`, { method: 'POST' }) }
export function getHealth() { return request('/health') }
