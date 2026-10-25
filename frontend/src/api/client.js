// API client for the FastAPI backend
// Provides functions to interact with backend routes.

const BASE_URL = import.meta.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000/api';

/**
 * Generic request helper.
 * Logs request details for debugging and throws on non‑2xx responses.
 */
async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  console.log('API request', path, 'status', res.status);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`API error ${res.status}: ${text || res.statusText}`);
  }
  return res.json();
}

// Investigation endpoints
export function startInvestigation({ target, scope, metadata }) {
  return request('/investigations', {
    method: 'POST',
    body: JSON.stringify({
      target,
      scope,
      ...(metadata ? { metadata } : {}),
    }),
  });
}

export function getInvestigation(id) {
  return request(`/investigations/${id}`);
}

export function getFindings(id) {
  return request(`/investigations/${id}/findings`);
}

export function getExecutions(id) {
  return request(`/investigations/${id}/executions`);
}

// Approval endpoints
export function getPendingApprovals() {
  return request('/approvals/pending');
}

export function approveAction(approvalId) {
  return request(`/approvals/${approvalId}/approve`, { method: 'POST' });
}

export function rejectAction(approvalId) {
  return request(`/approvals/${approvalId}/reject`, { method: 'POST' });
}

// Health check
export function getHealth() {
  return request('/health');
}