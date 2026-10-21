const STATUS_LABELS = {
  running: 'Running',
  awaiting_approval: 'Awaiting Approval',
  completed: 'Completed',
  failed: 'Failed',
}

export default function StatusPanel({ investigation }) {
  if (!investigation) return null

  return (
    <div className="status-panel">
      <div className={`status-badge status-${investigation.status}`}>
        {STATUS_LABELS[investigation.status] || investigation.status}
      </div>
      <dl className="status-grid">
        <dt>Target</dt>
        <dd>{investigation.target}</dd>

        <dt>Step</dt>
        <dd>{investigation.current_step}</dd>

        <dt>Discovered Domain</dt>
        <dd>{investigation.discovered_domain || '—'}</dd>

        <dt>Discovered DC</dt>
        <dd>{investigation.discovered_dc || '—'}</dd>

        <dt>Started</dt>
        <dd>{new Date(investigation.created_at).toLocaleString()}</dd>

        {investigation.completed_at && (
          <>
            <dt>Completed</dt>
            <dd>{new Date(investigation.completed_at).toLocaleString()}</dd>
          </>
        )}
      </dl>
    </div>
  )
}