import { useState } from 'react'

export default function TargetInput({ onStart, disabled }) {
  const [target, setTarget] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    const value = target.trim()
    if (!value) { setError('Enter an IP address, CIDR range, or hostname.'); return }
    setError(null)
    setSubmitting(true)
    try { await onStart(value) } finally { setSubmitting(false) }
  }

  return (
    <form className="target-input" onSubmit={handleSubmit}>
      <label htmlFor="target">Target IP address or hostname</label>
      <div className="target-input-row">
        <div className="target-field-icon">⌕</div>
        <input id="target" name="target" type="text" placeholder="e.g. 192.168.56.11 or dc01.lab.local" value={target} onChange={(event) => setTarget(event.target.value)} disabled={disabled || submitting} aria-describedby="target-help" />
        <button type="submit" disabled={disabled || submitting}>{submitting ? <><span className="button-spinner"/> Starting…</> : <><span>＋</span> Start investigation <span className="button-arrow">→</span></>}</button>
      </div>
      <div className="target-input-footer"><span id="target-help"><span className="lock-symbol">▣</span> Only assess systems you are authorized to test.</span><span className="scope-note">Backend scope validation enforced</span></div>
      {disabled && <p className="input-hint">An investigation is active. Wait for it to finish before starting another.</p>}
      {error && <p className="input-error" role="alert">{error}</p>}
    </form>
  )
}
