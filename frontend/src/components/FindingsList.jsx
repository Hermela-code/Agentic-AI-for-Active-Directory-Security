const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export default function FindingsList({ findings }) {
  const sorted = [...(findings || [])].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 99) -
      (SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 99)
  )

  return (
    <div className="findings-list">
      <h2>Findings</h2>
      {sorted.length === 0 && (
        <p className="empty-state">No findings yet.</p>
      )}
      {sorted.map((finding, i) => (
        <div
          key={i}
          className={`finding-card severity-${(finding.severity || 'info').toLowerCase()}`}
        >
          <div className="finding-header">
            <span className="finding-severity">{finding.severity}</span>
            <span className="finding-title">{finding.title}</span>
          </div>
          <p className="finding-description">{finding.description}</p>
          {finding.evidence && (
            <p className="finding-evidence">
              <strong>Evidence:</strong> {finding.evidence}
            </p>
          )}
        </div>
      ))}
    </div>
  )
}