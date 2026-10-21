import { useState } from 'react'

export default function TargetInput({ onStart, disabled }) {
  const [target, setTarget] = useState('')
  const [error, setError] = useState(null)

  function handleSubmit(e) {
    e.preventDefault()
    const trimmed = target.trim()
    if (!trimmed) {
      setError('Enter a target IP or hostname.')
      return
    }
    setError(null)
    onStart(trimmed)
  }

  return (
    <form className="target-input" onSubmit={handleSubmit}>
      <label htmlFor="target">Authorized target</label>
      <div className="target-input-row">
        <input
          id="target"
          type="text"
          placeholder="e.g. 192.168.56.11"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={disabled}
        />
        <button type="submit" disabled={disabled}>
          {disabled ? 'Investigating…' : 'Start Investigation'}
        </button>
      </div>
      {error && <p className="input-error">{error}</p>}
    </form>
  )
}