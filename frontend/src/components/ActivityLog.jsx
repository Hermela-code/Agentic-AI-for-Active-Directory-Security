/**
 * Shows tool executions as the agent's activity feed.
 * There is no decision_log field in the API — ToolExecutionResponse
 * (capability, status, output_summary, executed_at) is the closest
 * real equivalent of "what has the agent done so far".
 */
export default function ActivityLog({ executions }) {
  const sorted = [...(executions || [])].sort(
    (a, b) => new Date(a.executed_at) - new Date(b.executed_at)
  )

  return (
    <div className="activity-log">
      <h2>Agent Activity</h2>
      {sorted.length === 0 && (
        <p className="empty-state">No activity yet. Start an investigation above.</p>
      )}
      <ul>
        {sorted.map((exec) => (
          <li key={exec.id} className={`activity-entry status-${exec.status}`}>
            <div className="activity-entry-header">
              <span className="activity-capability">{exec.capability}</span>
              <span className="activity-status">{exec.status}</span>
            </div>
            {exec.output_summary && (
              <p className="activity-summary">{exec.output_summary}</p>
            )}
            <span className="activity-time">
              {new Date(exec.executed_at).toLocaleTimeString()}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}