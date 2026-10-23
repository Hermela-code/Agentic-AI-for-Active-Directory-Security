import { useCallback, useEffect, useRef, useState } from 'react'
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
  getHealth,
  approveAction,
  rejectAction,
} from './api/client.js'

const POLL_INTERVAL_MS = 3000
const ACTIVE_STATUSES = new Set(['running', 'awaiting_approval'])
const NAV_ITEMS = [
  { id: 'overview', icon: '▦', label: 'Overview' },
  { id: 'investigation', icon: '◎', label: 'Investigation' },
  { id: 'findings', icon: '◇', label: 'Security findings' },
  { id: 'activity', icon: '≋', label: 'Agent activity' },
  { id: 'approvals', icon: '✓', label: 'Approvals' },
]

function MetricCard({ label, value, note, icon, tone = '' }) {
  return (
    <article className="metric-card">
      <div className={`metric-icon ${tone}`}>{icon}</div>
      <div className="metric-copy"><span>{label}</span><strong>{value}</strong><small>{note}</small></div>
    </article>
  )
}

function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}

export default function App() {
  const [investigation, setInvestigation] = useState(null)
  const [findings, setFindings] = useState([])
  const [executions, setExecutions] = useState([])
  const [pendingApprovals, setPendingApprovals] = useState([])
  const [health, setHealth] = useState('checking')
  const [error, setError] = useState(null)
  const [activeNav, setActiveNav] = useState('overview')
  const [busyApproval, setBusyApproval] = useState(null)
  const pollRef = useRef(null)

  const isActive = investigation && ACTIVE_STATUSES.has(investigation.status)

  const checkHealth = useCallback(async () => {
    try {
      await getHealth()
      setHealth('online')
    } catch {
      setHealth('offline')
    }
  }, [])

  const refresh = useCallback(async () => {
    if (!investigation?.id) return
    try {
      const [inv, findingsRes, execRes, allPending] = await Promise.all([
        getInvestigation(investigation.id),
        getFindings(investigation.id),
        getExecutions(investigation.id),
        getPendingApprovals(),
      ])
      setInvestigation(inv)
      setFindings(Array.isArray(findingsRes) ? findingsRes : [])
      setExecutions(Array.isArray(execRes) ? execRes : [])
      setPendingApprovals((Array.isArray(allPending) ? allPending : []).filter(
        (approval) => approval.investigation_id === inv.id
      ))
      setError(null)
      setHealth('online')
    } catch (e) {
      setError(`Unable to refresh investigation: ${e.message}`)
      setHealth('offline')
    }
  }, [investigation?.id])

  async function handleStart(target) {
    setError(null)
    try {
      const inv = await startInvestigation(target)
      setInvestigation(inv)
      setFindings([])
      setExecutions([])
      setPendingApprovals([])
      setActiveNav('investigation')
      setHealth('online')
    } catch (e) {
      setError(`Could not start investigation: ${e.message}. Confirm the backend is running and the target is within the configured authorized scope.`)
      await checkHealth()
    }
  }

  async function handleApproval(approvalId, action) {
    setBusyApproval(approvalId)
    try {
      if (action === 'approve') await approveAction(approvalId)
      else await rejectAction(approvalId)
      await refresh()
    } catch (e) {
      setError(`Could not ${action} request: ${e.message}`)
    } finally {
      setBusyApproval(null)
    }
  }

  useEffect(() => {
    checkHealth()
    const healthTimer = setInterval(checkHealth, 15000)
    return () => clearInterval(healthTimer)
  }, [checkHealth])

  useEffect(() => {
    if (!investigation?.id) return undefined
    refresh()
    if (isActive) pollRef.current = setInterval(refresh, POLL_INTERVAL_MS)
    return () => clearInterval(pollRef.current)
  }, [investigation?.id, isActive, refresh])

  const criticalCount = findings.filter((f) => ['critical', 'high'].includes(String(f.severity || '').toLowerCase())).length
  const completedExecutions = executions.filter((e) => String(e.status).toLowerCase() === 'completed' || String(e.status).toLowerCase() === 'success').length

  function navigate(id) {
    setActiveNav(id)
    const section = document.getElementById(id)
    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark"><span>AD</span><i /></div>
          <div>
  <strong>Agentic AI</strong>
  <small>AD SECURITY PLATFORM</small>
</div>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          {NAV_ITEMS.map((item) => (
            <button key={item.id} className={`nav-item ${activeNav === item.id ? 'active' : ''}`} onClick={() => navigate(item.id)}>
              <span className="nav-icon">{item.icon}</span><span>{item.label}</span>
              {item.id === 'approvals' && pendingApprovals.length > 0 && <b className="nav-count">{pendingApprovals.length}</b>}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="scope-card"><div className="scope-title"><span className="scope-dot"/> Authorized scope</div><p>Investigations are restricted by the backend's configured target allowlist.</p></div>
          <div className="sidebar-user"><div className="user-avatar">AI</div><div><strong>Security analyst</strong><small>Investigation console</small></div><span className="user-menu">•••</span></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumbs"><span>Security operations</span><b>/</b><strong>{NAV_ITEMS.find((item) => item.id === activeNav)?.label || 'Overview'}</strong></div>
          <div className="topbar-right"><div className={`connection-pill ${health}`}><span className="connection-dot"/>{health === 'online' ? 'Backend connected' : health === 'offline' ? 'Backend offline' : 'Checking backend'}</div><div className="topbar-avatar">AI</div></div>
        </header>

        <div className="page-content" id="overview">
          <section className="page-heading">
            <div><div className="eyebrow"><span className="eyebrow-line"/> SECURITY INTELLIGENCE</div><h1>Active Directory <span>Security</span></h1><p>Investigate your directory environment, surface security risks, and review agent actions.</p></div>
            <div className="heading-status"><span className={`status-indicator ${isActive ? 'pulse' : ''}`}/><div><strong>{isActive ? 'Investigation in progress' : 'Monitoring workspace'}</strong><small>{investigation ? `Updated ${formatDate(investigation.created_at)}` : 'Ready for a new investigation'}</small></div></div>
          </section>

          {error && <div className="error-banner" role="alert"><span className="error-symbol">!</span><div><strong>Something needs attention</strong><p>{error}</p></div><button onClick={() => setError(null)} aria-label="Dismiss error">×</button></div>}

          <section className="metrics-grid" aria-label="Investigation summary">
            <MetricCard label="Investigation status" value={investigation ? (investigation.status || 'Unknown').replaceAll('_', ' ') : 'Standby'} note={investigation ? `Step ${investigation.current_step ?? '—'}` : 'No active session'} icon="◎" tone="blue" />
            <MetricCard label="Security findings" value={findings.length} note={criticalCount ? `${criticalCount} high / critical` : 'High and critical findings'} icon="◇" tone="violet" />
            <MetricCard label="Tool executions" value={executions.length} note={`${completedExecutions} successful / completed`} icon="⌘" tone="cyan" />
            <MetricCard label="Pending approvals" value={pendingApprovals.length} note={pendingApprovals.length ? 'Review required' : 'No action waiting'} icon="✓" tone="amber" />
          </section>

          <section className="panel investigation-panel" id="investigation">
            <div className="panel-heading"><div><span className="section-kicker">01 / NEW SESSION</span><h2>Start an investigation</h2><p>Enter a target that is explicitly authorized for assessment.</p></div><span className="panel-icon">⌁</span></div>
            <TargetInput onStart={handleStart} disabled={Boolean(isActive)} />
            {investigation && <div className="current-session"><div className="session-indicator"/><div className="session-main"><strong>Current session <span className={`inline-status status-${investigation.status}`}>{String(investigation.status || 'unknown').replaceAll('_', ' ')}</span></strong><span>{investigation.target} <i>·</i> Started {formatDate(investigation.created_at)}</span></div><button className="subtle-button" onClick={refresh}>↻ Refresh</button></div>}
          </section>

          {investigation ? <>
            <section className="panel detail-panel">
              <div className="panel-heading"><div><span className="section-kicker">02 / SESSION DETAILS</span><h2>Investigation overview</h2></div><span className="muted-meta">ID: {investigation.id}</span></div>
              <StatusPanel investigation={investigation} />
            </section>
            <section className="panel" id="approvals">
              <div className="panel-heading"><div><span className="section-kicker">03 / HUMAN-IN-THE-LOOP</span><h2>Approval queue</h2><p>Review gated actions before the agent proceeds.</p></div><span className="count-chip">{pendingApprovals.length} pending</span></div>
              <ApprovalPanel pendingApprovals={pendingApprovals} busyApproval={busyApproval} onApprove={(id) => handleApproval(id, 'approve')} onReject={(id) => handleApproval(id, 'reject')} />
            </section>
            <div className="content-grid">
              <section className="panel content-panel" id="activity"><div className="panel-heading"><div><span className="section-kicker">04 / EXECUTION TRACE</span><h2>Agent activity</h2></div><span className="count-chip">{executions.length} events</span></div><ActivityLog executions={executions} /></section>
              <section className="panel content-panel" id="findings"><div className="panel-heading"><div><span className="section-kicker">05 / DETECTION RESULTS</span><h2>Security findings</h2></div><span className="count-chip">{findings.length} findings</span></div><FindingsList findings={findings} /></section>
            </div>
          </> : <section className="empty-dashboard panel"><div className="empty-illustration"><div className="empty-orbit orbit-one"/><div className="empty-orbit orbit-two"/><div className="empty-shield">⌑</div><span className="orbit-node node-one"/><span className="orbit-node node-two"/><span className="orbit-node node-three"/></div><span className="section-kicker">READY WHEN YOU ARE</span><h2>Your security workspace is ready</h2><p>Start an authorized investigation to see execution activity, discovered findings, and any actions that require your approval.</p><div className="empty-features"><span><i>✓</i> Scoped investigations</span><span><i>✓</i> Evidence-led findings</span><span><i>✓</i> Human approval gates</span></div></section>}

          <footer className="app-footer">
  <span>
    <span className="footer-dot" /> Agentic AI for AD Security
  </span>
  <span>
    Security operations console <i>·</i> All actions subject to authorization scope
  </span>
</footer>
        </div>
      </main>
    </div>
  )
}
