function prettyStatus(status) { return String(status || 'unknown').replaceAll('_', ' ') }
export default function ActivityLog({ executions }) {
  const sorted = [...(executions || [])].sort((a, b) => new Date(b.executed_at) - new Date(a.executed_at))
  return <div className="activity-log">
    {sorted.length === 0 ? <div className="component-empty"><span className="empty-mini-icon">≋</span><strong>No activity recorded yet</strong><p>Agent tool executions will appear here as the investigation progresses.</p></div> : <ul>{sorted.map((exec, index) => <li key={exec.id ?? `${exec.capability}-${exec.executed_at}-${index}`} className="activity-entry">
      <span className={`activity-timeline-dot ${String(exec.status).toLowerCase()}`}/><div className="activity-entry-body"><div className="activity-entry-header"><span className="activity-capability">{exec.capability || 'Tool execution'}</span><span className={`activity-status status-text-${String(exec.status || '').toLowerCase()}`}>{prettyStatus(exec.status)}</span></div>
      {exec.output_summary && <p className="activity-summary">{exec.output_summary}</p>}<span className="activity-time">{exec.executed_at ? new Date(exec.executed_at).toLocaleString() : 'Time unavailable'}</span></div>
    </li>)}</ul>}
  </div>
}
