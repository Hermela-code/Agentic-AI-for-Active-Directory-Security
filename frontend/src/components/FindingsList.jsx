import { useMemo, useState } from 'react'
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
export default function FindingsList({ findings }) {
  const [filter, setFilter] = useState('all')
  const sorted = useMemo(() => [...(findings || [])].filter((item) => filter === 'all' || String(item.severity || 'info').toLowerCase() === filter).sort((a, b) => (SEVERITY_ORDER[String(a.severity).toLowerCase()] ?? 99) - (SEVERITY_ORDER[String(b.severity).toLowerCase()] ?? 99)), [findings, filter])
  return <div className="findings-list">
    <div className="findings-toolbar"><span>{findings?.length || 0} total detections</span><select aria-label="Filter findings by severity" value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Informational</option></select></div>
    {sorted.length === 0 ? <div className="component-empty"><span className="empty-mini-icon">◇</span><strong>{findings?.length ? 'No findings match this filter' : 'No findings reported yet'}</strong><p>Detected security issues and their available evidence will be listed here.</p></div> : <div className="finding-stack">{sorted.map((finding, index) => { const severity = String(finding.severity || 'info').toLowerCase(); return <article key={finding.id ?? `${finding.title}-${index}`} className={`finding-card severity-${severity}`}><div className="finding-header"><span className={`finding-severity severity-label-${severity}`}>{severity}</span><span className="finding-title">{finding.title || 'Untitled finding'}</span></div>{finding.description && <p className="finding-description">{finding.description}</p>}{finding.evidence && <div className="finding-evidence"><strong>Evidence</strong><p>{finding.evidence}</p></div>}</article> })}</div>}
  </div>
}
