/**
 * API client for the FastAPI backend.
 *
 * Matches the REAL routes in backend/routes/{investigations,approvals,health}.py
 * and backend/schemas/api_schemas.py (confirmed, not assumed):
 *
 *   POST   /api/investigations                  { target } -> InvestigationResponse
 *   GET    /api/investigations                              -> InvestigationResponse[]
 *   GET    /api/investigations/:id                           -> InvestigationResponse
 *   GET    /api/investigations/:id/findings                  -> FindingResponse[]
 *   GET    /api/investigations/:id/executions                -> ToolExecutionResponse[]
 *   GET    /api/investigations/:id/approvals                 -> ApprovalResponse[] (all, any status)
 *   GET    /api/approvals/pending                             -> ApprovalResponse[] (GLOBAL, not per-investigation)
 *   POST   /api/approvals/:id/approve                         -> ApprovalResponse
 *   POST   /api/approvals/:id/reject                          -> ApprovalResponse
 *   GET    /api/health                                        -> health status
 *
 * Note: InvestigationResponse has NO decision_log, NO embedded findings,
 * and NO max_steps field — those live in the agent's internal
 * InvestigationState, not in the DB-backed API response. The dashboard
 * uses /executions as the closest equivalent to an "agent activity" feed.
 */

const BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000/api'

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`API error ${res.status}: ${text || res.statusText}`)
  }
  return res.json()
}

export function startInvestigation({ target, scope, metadata }) {
  return request('/investigations', {
    method: 'POST',
    body: JSON.stringify({ target, scope, metadata }),
  })
}



export function getInvestigation(id) {
  return request(`/investigations/${id}`)
}

export function getFindings(id) {
  return request(`/investigations/${id}/findings`)
}

export function getExecutions(id) {
  return request(`/investigations/${id}/executions`)
}

export function getPendingApprovals() {
  // Global endpoint — caller should filter by investigation_id if needed.
  return request('/approvals/pending')
}

export function approveAction(approvalId) {
  return request(`/approvals/${approvalId}/approve`, { method: 'POST' })
}

export function rejectAction(approvalId) {
  return request(`/approvals/${approvalId}/reject`, { method: 'POST' })
}

export function getHealth() {
  return request('/health')
}