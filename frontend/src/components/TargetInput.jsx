import { useState } from 'react'

export default function TargetInput({ onStart, disabled }) {
  const [target, setTarget] = useState('')
  const [scope, setScope] = useState('')
  const [metadata, setMetadata] = useState('')
  const [error, setError] = useState(null)

  function handleSubmit(e) { console.log('Submitting target input');
    e.preventDefault()
    const trimmedTarget = target.trim()
    const trimmedScope = scope.trim()
    if (!trimmedTarget) {
      setError('Enter a target IP or hostname.')
      return
    }
    if (!trimmedScope) {
      setError('Enter an authorized CIDR scope.')
      return
    }
    setError(null)
    // Pass both target and scope (and optional metadata) to parent handler
    console.log('Calling onStart with', { target: trimmedTarget, scope: trimmedScope, metadata: metadata.trim() });
    onStart({ target: trimmedTarget, scope: trimmedScope, metadata: metadata.trim() })
  }

  return (
    <form className="target-input" onSubmit={handleSubmit}>
      <label htmlFor="target">Target Host / Domain</label>
      <div className="target-input-row">
        <input
          id="target"
          type="text"
          placeholder="e.g. 192.168.56.11 or dc.corporate.local"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={disabled}
        />
      </div>

      <label htmlFor="scope">Authorized Scope / CIDR</label>
      <div className="target-input-row">
        <input
          id="scope"
          type="text"
          placeholder="e.g. 192.168.56.0/24 or 10.0.0.0/16"
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          disabled={disabled}
        />
        <small className="helper-text">Defines the hard boundary the agent cannot scan outside of.</small>
      </div>

      <label htmlFor="metadata">Investigation Metadata (optional)</label>
      <div className="target-input-row">
        <input
          id="metadata"
          type="text"
          placeholder="Tag / Description"
          value={metadata}
          onChange={(e) => setMetadata(e.target.value)}
          disabled={disabled}
        />
      </div>

      <div className="target-input-row">
        <button
          type="submit"
          disabled={disabled || !target.trim() || !scope.trim()}
        >
          {disabled ? 'Investigating…' : 'Start Investigation'}
        </button>
      </div>

      {error && <p className="input-error">{error}</p>}
    </form>
  )
}