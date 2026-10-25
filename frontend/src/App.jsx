import { useEffect, useRef, useState } from 'react'
import TargetInput from './components/TargetInput.jsx'
import StatusPanel from './components/StatusPanel.jsx'
import ActivityLog from './components/ActivityLog.jsx'
import FindingsList from './components/FindingsList.jsx'
import ApprovalPanel from './components/ApprovalPanel.jsx'
import {
  startInvestigation,
  getInvestigation,
  getFindings,
  getExecutions,
  getPendingApprovals,
  approveAction,
  rejectAction,
} from './api/client.js'

const POLL_INTERVAL_MS = 3000
const ACTIVE_STATUSES = new Set(['running', 'awaiting_approval'])

export default function App() {
  const [investigation, setInvestigation] = useState(null)
  const [findings, setFindings] = useState([])
  const [executions, setExecutions] = useState([])
  const [pendingApprovals, setPendingApprovals] = useState([])
  const [error, setError] = useState(null)
  const pollRef = useRef(null)

  const isActive = investigation && ACTIVE_STATUSES.has(investigation.status)

  async function handleStart({ target, scope, metadata }) {
    console.log('handleStart invoked with', { target, scope, metadata });
    setError(null);
    try {
      const payload = {
        target,
        scope,
        ...(metadata ? { metadata: { description: metadata } } : {}),
      };
      const inv = await startInvestigation(payload);
      setInvestigation(inv);
      setFindings([]);
      setExecutions([]);
      setPendingApprovals([]);
    } catch (e) {
      console.error('Error starting investigation:', e);
      setError(`Could not start investigation (${e.message}). Confirm the backend is running at the configured VITE_BACKEND_URL and the target/scope are within authorized boundaries.`);
    }
  }




  async function refresh() {
    if (!investigation?.id) return
    try {
      const [inv, findingsRes, execRes, allPending] = await Promise.all([
        getInvestigation(investigation.id),
        getFindings(investigation.id),
        getExecutions(investigation.id),
        getPendingApprovals(),
      ])
      setInvestigation(inv)
      setFindings(findingsRes)
      setExecutions(execRes)
      // Pending approvals endpoint is global — scope it to this investigation.
      setPendingApprovals(
        allPending.filter((a) => a.investigation_id === investigation.id)
      )
      setError(null)
    } catch (e) {
      setError(`Lost connection to backend: ${e.message}`)
    }
  }

  async function handleApprove(approvalId) {
    try {
      await approveAction(approvalId)
      await refresh()
    } catch (e) {
      setError(`Could not approve: ${e.message}`)
    }
  }

  async function handleReject(approvalId) {
    try {
      await rejectAction(approvalId)
      await refresh()
    } catch (e) {
      setError(`Could not reject: ${e.message}`)
    }
  }

  useEffect(() => {
    if (!investigation?.id) return undefined

    refresh()
    if (isActive) {
      pollRef.current = setInterval(refresh, POLL_INTERVAL_MS)
    }
    return () => clearInterval(pollRef.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigation?.id, isActive])

  return (
    <div className="app-shell">
      <header>
        <h1>Agentic AI for Active Directory Security</h1>
        <p className="subtitle">Investigation Dashboard</p>
      </header>

      <TargetInput onStart={handleStart} disabled={isActive} />

      {error && <div className="error-banner">{error}</div>}

      {investigation && (
        <>
          <StatusPanel investigation={investigation} />
          <ApprovalPanel
            pendingApprovals={pendingApprovals}
            onApprove={handleApprove}
            onReject={handleReject}
          />
          <div className="dashboard-columns">
            <ActivityLog executions={executions} />
            <FindingsList findings={findings} />
          </div>
        </>
      )}
    </div>
  )
}