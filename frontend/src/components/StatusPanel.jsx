const STATUS_LABELS = { running: 'Running', awaiting_approval: 'Awaiting approval', completed: 'Completed', failed: 'Failed' }
function displayDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString()
}
export default function StatusPanel({ investigation }) {
  if (!investigation) return null
  return <div className="status-panel">
    <div className="status-summary"><span className={`status-badge status-${investigation.status}`}><i/> {STATUS_LABELS[investigation.status] || investigation.status || 'Unknown'}</span><span className="status-summary-target">Target <strong>{investigation.target || '—'}</strong></span></div>
    <dl className="status-grid">
      <div><dt>Current step</dt><dd>{investigation.current_step ?? '—'}</dd></div>
      <div><dt>Discovered domain</dt><dd>{investigation.discovered_domain || 'Not discovered'}</dd></div>
      <div><dt>Domain controller</dt><dd>{investigation.discovered_dc || 'Not discovered'}</dd></div>
      <div><dt>Started</dt><dd>{displayDate(investigation.created_at)}</dd></div>
      {investigation.completed_at && <div><dt>Completed</dt><dd>{displayDate(investigation.completed_at)}</dd></div>}
    </dl>
  </div>
}
