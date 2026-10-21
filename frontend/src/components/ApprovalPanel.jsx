export default function ApprovalPanel({ pendingApprovals, onApprove, onReject }) {
  if (!pendingApprovals || pendingApprovals.length === 0) return null

  return (
    <div className="approval-panel">
      <h2>⚠ Approval Required</h2>
      {pendingApprovals.map((req) => (
        <div key={req.id} className="approval-card">
          <dl>
            <dt>Action</dt>
            <dd>{req.capability}</dd>
            <dt>Target</dt>
            <dd>{req.target}</dd>
            <dt>Rationale</dt>
            <dd>{req.rationale}</dd>
            <dt>Risk</dt>
            <dd>{req.risk_assessment}</dd>
          </dl>
          <div className="approval-actions">
            <button className="approve-btn" onClick={() => onApprove(req.id)}>
              Approve
            </button>
            <button className="reject-btn" onClick={() => onReject(req.id)}>
              Reject
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}