import { useCallback, useEffect, useMemo, useState } from 'react'
import { Activity, AlertTriangle, Blocks, ChevronRight, ClipboardList, KeyRound, LogOut, Plus, RefreshCw, Search, Shield, X, Server, Radio } from 'lucide-react'

const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

function readError(payload, fallback) {
  return payload?.error?.message || payload?.detail || fallback
}

function stateClass(value = '') {
  const state = String(value).toLowerCase()
  if (['verified', 'approved', 'recorded', 'completed', 'resolved', 'success', 'encrypted'].includes(state)) return 'success'
  if (['failed', 'rejected', 'evidence_encryption_failed', 'dismissed', 'critical', 'high', 'unhealthy'].includes(state)) return 'failed'
  if (['unavailable', 'unknown', 'blocked', 'timeout'].includes(state)) return 'unavailable'
  if (['not_performed', 'not_requested', 'manual_review', 'expired'].includes(state)) return 'muted'
  if (['mock_recorded', 'simulation', 'simulated', 'demo'].includes(state)) return 'simulation'
  return 'pending'
}

function Status({ value, label }) {
  return <span className={`badge ${stateClass(value)}`}>{label || String(value || 'unknown').replaceAll('_', ' ')}</span>
}

function Login({ onLogin, error, busy }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  return (
    <main className="login-page">
      <form className="login-card" onSubmit={(event) => { event.preventDefault(); onLogin(username, password) }}>
        <div className="brand-mark"><Shield size={23} /></div>
        <span className="eyebrow">SECURITY OPERATIONS</span>
        <h1>Sign in to QuantumSHIELD</h1>
        <p>Use an account provisioned by your administrator.</p>
        {error && <div className="error-box">{error}</div>}
        <label>Username<input autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} /></label>
        <label>Password<input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <button className="primary full" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </main>
  )
}

function IncidentForm({ onSubmit, onClose, busy, error }) {
  const [form, setForm] = useState({ source: '', incident_type: '', summary: '', description: '', encryption_required: false })
  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }))
  return (
    <div className="overlay" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
      <form className="dialog" onSubmit={(event) => { event.preventDefault(); onSubmit(form) }}>
        <div className="dialog-head"><div><span className="eyebrow">INCIDENT INTAKE</span><h2>Submit a security event</h2></div><button type="button" className="icon-button" onClick={onClose}><X size={18} /></button></div>
        {error && <div className="error-box">{error}</div>}
        <label>Source<input required maxLength="160" value={form.source} onChange={(e) => update('source', e.target.value)} placeholder="e.g. api-gateway" /></label>
        <label>Incident type<input required maxLength="120" value={form.incident_type} onChange={(e) => update('incident_type', e.target.value)} placeholder="e.g. suspicious_activity" /></label>
        <label>Summary<input required minLength="4" maxLength="240" value={form.summary} onChange={(e) => update('summary', e.target.value)} /></label>
        <label>Evidence<textarea required maxLength="30000" rows="5" value={form.description} onChange={(e) => update('description', e.target.value)} /></label>
        <label className="check-row"><input type="checkbox" checked={form.encryption_required} onChange={(e) => update('encryption_required', e.target.checked)} />Require PQC key establishment and authenticated encryption for stored evidence</label>
        <p className="hint">Required encryption is rejected before persistence if its provider or recipient key is unavailable.</p>
        <div className="dialog-actions"><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Submitting…' : 'Submit and analyze'}</button></div>
      </form>
    </div>
  )
}

function IncidentDetail({ incident, audit, onAnalyze, onStatus, busy, error, role }) {
  const canTriage = ['administrator', 'security_analyst'].includes(role)
  const canResolve = ['administrator', 'operator'].includes(role)
  return (
    <section className="detail-panel">
      <div className="detail-heading"><div><span className="eyebrow">INCIDENT / {incident.id}</span><h2>{incident.summary}</h2><p>{incident.source} · {incident.incident_type} · {new Date(incident.created_at).toLocaleString()}</p></div><button className="icon-button" onClick={() => onStatus(null)} aria-label="Close details"><X size={18} /></button></div>
      {error && <div className="error-box">{error}</div>}
      <div className="detail-actions">
        <Status value={incident.severity} label={`severity · ${incident.severity}`} /><Status value={incident.status} label={`status · ${incident.status}`} />
        {canTriage && incident.description && <button className="secondary" disabled={busy} onClick={onAnalyze}><RefreshCw size={14} /> Re-run analysis</button>}
        {canTriage && ['detected'].includes(incident.status) && <button className="secondary" disabled={busy} onClick={() => onStatus('triaged')}>Mark triaged</button>}
        {['detected', 'triaged'].includes(incident.status) && (canTriage || canResolve) && <button className="secondary" disabled={busy} onClick={() => onStatus('investigating')}>Investigate</button>}
        {canResolve && ['triaged', 'investigating'].includes(incident.status) && <button className="secondary" disabled={busy} onClick={() => onStatus('resolved')}>Resolve</button>}
      </div>
      <div className="detail-grid">
        <article className="detail-card"><h3><Activity size={15} /> AI analysis</h3><dl><dt>Result</dt><dd><Status value={incident.ai_status} /></dd><dt>Classification</dt><dd>{incident.classification || '—'}</dd><dt>Confidence</dt><dd>{incident.confidence == null ? '—' : `${(incident.confidence * 100).toFixed(1)}%`} {incident.analysis_details?.calibrated === false && <small>(uncalibrated class probability)</small>}</dd><dt>Recommended action</dt><dd>{incident.recommended_action || '—'}</dd><dt>Auto-healing eligibility</dt><dd>{incident.auto_healing_eligible == null ? 'Not available' : incident.auto_healing_eligible ? 'Eligible for policy review' : 'Not eligible'}</dd><dt>Dataset</dt><dd>{incident.analysis_details?.dataset_notice || '—'}</dd></dl></article>
        <article className="detail-card"><h3><KeyRound size={15} /> Cryptographic integrity</h3><dl><dt>Record SHA-256</dt><dd className="mono break">{incident.record_hash || 'Not performed'}</dd><dt>ML-DSA status</dt><dd><Status value={incident.pqc_status} /></dd><dt>Signature verified</dt><dd>{incident.signature_verified === true ? <Status value="verified" /> : incident.signature_verified === false ? <Status value="failed" /> : <Status value="not_performed" />}</dd><dt>Encryption</dt><dd><Status value={incident.encryption_status} /></dd><dt>Key encapsulation</dt><dd>{incident.kem_algorithm || 'Not performed'}</dd></dl></article>
        <article className="detail-card"><h3><Blocks size={15} /> Blockchain audit</h3><dl><dt>Provider</dt><dd><Status value={incident.blockchain_provider} /></dd><dt>Recording</dt><dd><Status value={incident.blockchain_status} /></dd><dt>Ledger integrity</dt><dd>{incident.blockchain_provider === 'mock' ? <Status value="simulation" label={incident.blockchain_verified ? 'MOCK · HASH MATCH' : 'MOCK · NOT VERIFIED'} /> : incident.blockchain_verified === true ? <Status value="verified" /> : incident.blockchain_verified === false ? <Status value="failed" /> : <Status value="not_performed" />}</dd><dt>Transaction</dt><dd className="mono break">{incident.blockchain_tx_id || '—'}</dd></dl></article>
        <article className="detail-card"><h3><AlertTriangle size={15} /> Response</h3><dl><dt>Healing decision</dt><dd><Status value={incident.healing_status} /></dd><dt>Execution</dt><dd><Status value="simulation" label="SIMULATION · no cluster mutation" /></dd><dt>Evidence</dt><dd>{incident.encryption_required ? (incident.encryption_status === 'encrypted' && incident.encrypted_payload ? 'Encrypted evidence retained' : 'Evidence discarded because required encryption failed') : incident.description || 'Not available'}</dd></dl></article>
      </div>
      <article className="audit-card"><div className="section-title"><h3><ClipboardList size={16} /> Audit trail</h3><span>{audit.length} event{audit.length === 1 ? '' : 's'}</span></div>
        {audit.length === 0 ? <div className="empty">No audit events returned.</div> : <ol className="audit-list">{audit.map((event) => <li key={event.id}><span className={`audit-dot ${stateClass(event.result)}`} /><div><strong>{event.event_type.replaceAll('.', ' ')}</strong><span>{event.actor_type}{event.actor_id ? ` · ${event.actor_id}` : ''} · <Status value={event.result} /></span><code>{JSON.stringify(event.event_data)}</code></div><time>{new Date(event.created_at).toLocaleString()}</time></li>)}</ol>}
      </article>
    </section>
  )
}

function KubernetesPanel({ request, user, busy, setBusy, onApprovals }) {
  const [data, setData] = useState({ status: null, nodes: [], pods: [], conditions: [], conditionHistory: [], incidents: [], remediations: [], approvals: [], audit: [] })
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const load = useCallback(async () => {
    setError(''); setMessage('')
    try {
      const [status, nodes, pods, conditions, conditionHistory, incidents, remediations, approvals, audit] = await Promise.all([
        request('/api/v1/kubernetes/status'), request('/api/v1/kubernetes/nodes'), request('/api/v1/kubernetes/pods'),
        request('/api/v1/kubernetes/conditions'), request('/api/v1/kubernetes/conditions/history'), request('/api/v1/kubernetes/incidents'),
        request('/api/v1/kubernetes/remediations'), request('/api/v1/kubernetes/approvals'), request('/api/v1/kubernetes/audit'),
      ])
      setData({ status, nodes: nodes.items || [], pods: pods.items || [], conditions: conditions.conditions || [], conditionHistory, incidents, remediations, approvals, audit })
    } catch (err) { setError(err.message) }
  }, [request])
  useEffect(() => { load() }, [load])
  async function poll() {
    setBusy(true); setError('')
    try { const result = await request('/api/v1/kubernetes/poll', { method: 'POST' }); setMessage(`${result.conditions.length} condition(s), ${result.incidents.length} new incident(s) · ${result.status}`); await load() }
    catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  async function runDemo() {
    setBusy(true); setError('')
    try { const result = await request('/api/v1/kubernetes/demo/run', { method: 'POST' }); setMessage(`DEMO · ${result.conditions.length} condition(s) · ${result.incidents.length} new incident(s) · PQC unavailable by demo configuration · blockchain ${result.incidents[0]?.blockchain_status || 'mock'}`); await load() }
    catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  async function requestApproval(incident) {
    setBusy(true); setError('')
    try {
      await request('/api/v1/kubernetes/approvals', { method: 'POST', body: JSON.stringify({
        incident_id: incident.id, action: 'restart_deployment', namespace: incident.namespace,
        deployment: incident.resource, reason: 'Review detected deployment availability condition.',
      }) })
      setMessage('Approval requested. A different authorized operator or administrator must approve it.')
      await load(); onApprovals()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  async function simulate(incident) {
    setBusy(true); setError(''); setMessage('')
    try {
      const result = await request('/api/v1/kubernetes/remediations/simulate', { method: 'POST', body: JSON.stringify({
        incident_id: incident.id, action: 'restart_deployment', namespace: incident.namespace || 'default',
        deployment: incident.resource || '',
      }) })
      setMessage(`Response ${result.status} · verification ${result.verification_status || 'NOT_PERFORMED'} · cluster mutated: ${String(result.cluster_mutated)} · PQC ${result.integrity?.pqc_status || 'unavailable'} · ledger ${result.integrity?.blockchain_status || 'unavailable'}`)
      await load()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  const isMock = ['mock', 'demo'].includes(data.status?.provider)
  const canRespond = ['administrator', 'operator'].includes(user?.role)
  const canRequest = ['administrator', 'operator', 'security_analyst'].includes(user?.role)
  return <section className="kube-panel">
    <div className="section-title"><div><h2><Server size={17} /> Kubernetes / Response</h2><p>Observation is labeled by provider; mock data is never presented as a live cluster.</p></div><div className="panel-buttons">{data.status?.provider === 'demo' && <button className="secondary" disabled={busy} onClick={runDemo}>Run deterministic demo</button>}<button className="secondary" onClick={load}><RefreshCw size={14} /> Refresh</button><button className="primary" disabled={busy} onClick={poll}><Radio size={14} /> Poll &amp; detect</button></div></div>
    {error && <div className="error-box">{error}</div>}{message && <div className="notice-box"><Status value={message.includes('BLOCKED') ? 'blocked' : 'simulation'} label={message} /></div>}
    <div className="kube-mode"><Status value={data.status?.available ? (isMock ? 'simulation' : 'verified') : 'unavailable'} label={!data.status ? 'checking' : !data.status.available ? 'UNAVAILABLE · no cluster configured' : data.status.provider === 'demo' ? 'DEMO · deterministic fixture, not a live cluster' : data.status.provider === 'mock' ? 'MOCK · simulated provider, not a live cluster' : 'CONNECTED · read-only observation'} />
      <Status value="simulation" label="REMEDIATION MODE · SIMULATION BY DEFAULT" />
    </div>
    <div className="summary-grid kube-summary"><div className="summary-card"><span>NODES</span><strong>{data.nodes.length}</strong></div><div className="summary-card"><span>PODS</span><strong>{data.pods.length}</strong></div><div className="summary-card"><span>DETECTED CONDITIONS</span><strong>{data.conditions.length}</strong></div><div className="summary-card"><span>RELATED INCIDENTS</span><strong>{data.incidents.length}</strong></div></div>
    <article className="table-card"><div className="section-title"><div><h3>Detected conditions</h3><p>Operational anomalies and security-relevant events; a Kubernetes error alone is not classified as an attack.</p></div></div>
      {data.conditions.length ? <div className="condition-list">{data.conditions.map((condition) => {
        const related = data.incidents.find((item) => item.namespace === condition.namespace && item.resource === condition.resource && item.incident_type === condition.condition_type)
        return <div className="condition-row" key={condition.fingerprint}><div><Status value={condition.classification} /><strong>{condition.summary}</strong><small>{condition.namespace}/{condition.resource} · {condition.condition_type}</small><code>{JSON.stringify(condition.evidence)}</code></div>
          <div className="condition-response">{related ? <><Status value={related.severity} label={`severity · ${related.severity}`} /><span>{related.classification || `AI ${related.ai_status}`} · {related.recommended_action || 'No AI recommendation'}</span><Status value={related.response_policy.decision} label={`policy · ${related.response_policy.decision}`} /><span>{related.response_policy.reason}</span><span>incident {related.id.slice(0, 8)}</span>{canRespond && <button className="secondary" disabled={busy} onClick={() => simulate(related)}>Simulate response</button>}{canRequest && condition.condition_type === 'failed_deployment' && !data.approvals.some((item) => item.incident_id === related.id && item.decision === 'PENDING') && <button className="secondary" disabled={busy} onClick={() => requestApproval(related)}>Request approval</button>}</> : <span>Not polled into incident queue yet</span>}</div></div>
      })}</div> : <div className="empty">{data.status?.available ? 'No configured conditions detected.' : 'No cluster observations available.'}</div>}
    </article>
    <article className="table-card"><div className="section-title"><div><h3>Persistent condition correlation</h3><p>Active duplicates update observation counts; a condition absent from a complete snapshot is resolved. Reappearance creates a new incident.</p></div></div>{data.conditionHistory.length ? <div className="condition-list">{data.conditionHistory.map((item) => <div className="condition-row" key={item.id}><div><strong>{item.summary}</strong><small>{item.provider}/{item.cluster_id} · {item.namespace}/{item.resource} · seen {item.occurrence_count} time(s)</small></div><div className="condition-response"><Status value={item.status} /><span>first {new Date(item.first_seen).toLocaleString()}</span><span>last {new Date(item.last_seen).toLocaleString()}</span>{item.resolved_at && <span>resolved {new Date(item.resolved_at).toLocaleString()}</span>}</div></div>)}</div> : <div className="empty">No persisted condition history yet.</div>}</article>
    <div className="detail-grid kube-detail"><article className="detail-card"><h3>Node health</h3>{data.nodes.length ? data.nodes.map((node) => { const meta = node.metadata || {}; const conditions = node.status?.conditions || []; const ready = conditions.find((item) => item.type === 'Ready')?.status === 'True'; return <p key={meta.uid || meta.name}><Status value={ready ? 'verified' : 'failed'} label={ready ? 'READY' : 'NOT READY'} /> {meta.name}</p> }) : <p className="empty">No node data.</p>}</article>
      <article className="detail-card"><h3>Pod health</h3>{data.pods.length ? data.pods.slice(0, 30).map((pod) => { const meta = pod.metadata || {}; const phase = pod.status?.phase || 'Unknown'; const restarts = (pod.status?.containerStatuses || []).reduce((n, c) => n + (c.restartCount || 0), 0); return <p key={meta.uid || `${meta.namespace}/${meta.name}`}><Status value={phase === 'Running' || phase === 'Succeeded' ? 'verified' : 'failed'} label={phase} /> {meta.namespace}/{meta.name} · restarts {restarts}</p> }) : <p className="empty">No pod data.</p>}</article></div>
    <article className="table-card"><div className="section-title"><div><h3>Remediation records</h3><p>Simulation never mutates the cluster. Real mode requires the server gate, allowlists, policy permission, and operator approval.</p></div></div>{data.remediations.length ? <div className="condition-list">{data.remediations.map((item) => <div className="condition-row" key={item.id}><div><strong>{item.action.replaceAll('_', ' ')}</strong><small>incident {item.incident_id.slice(0, 8)} · {new Date(item.created_at).toLocaleString()}</small></div><div className="condition-response"><Status value={item.mode} label={item.mode === 'REAL' ? 'REAL EXECUTION' : item.mode} /><Status value={item.status} /><Status value={item.verification_status} label={`verification · ${item.verification_status}`} /></div></div>)}</div> : <div className="empty">No remediation actions recorded.</div>}</article>
    <article className="audit-card"><div className="section-title"><h3><ClipboardList size={16} /> Kubernetes and response audit</h3><span>{data.audit.length} recent events</span></div>{data.audit.length ? <ol className="audit-list">{data.audit.map((event) => <li key={event.id}><span className={`audit-dot ${stateClass(event.result)}`} /><div><strong>{event.event_type.replaceAll('.', ' ')}</strong><span>{event.actor_type} · <Status value={event.result} /></span><code>{JSON.stringify(event.event_data)}</code></div><time>{new Date(event.created_at).toLocaleString()}</time></li>)}</ol> : <div className="empty">No Kubernetes response audit events.</div>}</article>
  </section>
}

function ApprovalsPanel({ request, user, busy, setBusy }) {
  const [approvals, setApprovals] = useState([])
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const canDecide = ['administrator', 'operator'].includes(user?.role)
  const load = useCallback(async () => {
    setError('')
    try { setApprovals(await request('/api/v1/kubernetes/approvals')) }
    catch (err) { setError(err.message) }
  }, [request])
  useEffect(() => { load() }, [load])
  async function decide(item, decision) {
    setBusy(true); setError(''); setMessage('')
    try {
      await request(`/api/v1/kubernetes/approvals/${encodeURIComponent(item.id)}/${decision}`, {
        method: 'POST', body: JSON.stringify({ reason: decision === 'approve' ? 'Approved after operator review.' : 'Rejected after operator review.' }),
      })
      setMessage(`Approval ${decision}d.`); await load()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  async function simulateApproved(item) {
    setBusy(true); setError(''); setMessage('')
    try {
      const params = item.action_parameters
      const result = await request('/api/v1/kubernetes/remediations/simulate', { method: 'POST', body: JSON.stringify({
        incident_id: item.incident_id, action: item.requested_action, namespace: params.namespace,
        deployment: params.deployment, replicas: params.replicas, approval_id: item.id,
      }) })
      setMessage(`Approved request passed through ${result.status}; ${result.verification_status}; cluster mutated: ${String(result.cluster_mutated)}.`)
      await load()
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }
  return <section className="table-card approval-panel">
    <div className="section-title"><div><h2>Remediation approvals</h2><p>Policy describes permitted actions; this separate workflow records human approval. Requesters cannot approve their own requests by default.</p></div><button className="secondary" onClick={load}><RefreshCw size={14} /> Refresh</button></div>
    {error && <div className="error-box">{error}</div>}{message && <div className="notice-box">{message}</div>}
    {approvals.length ? <div className="condition-list">{approvals.map((item) => {
      const mayApprove = canDecide && item.decision === 'PENDING' && item.requested_by !== user?.id
      const mayReject = canDecide && item.decision === 'PENDING'
      return <article className="approval-card" key={item.id}><div className="approval-head"><div><Status value={item.decision} /><strong>{item.incident_summary}</strong><small>{item.incident_id} · {item.condition?.summary || 'Manual incident'}</small></div><span>{new Date(item.requested_at).toLocaleString()}</span></div>
        <div className="approval-grid"><div><small>REQUESTED RESPONSE</small><strong>{item.requested_action.replaceAll('_', ' ')} · {item.action_parameters.namespace}/{item.action_parameters.deployment}</strong></div><div><small>POLICY</small><strong>{item.policy_decision}: {item.policy_reason}</strong></div><div><small>REQUESTER</small><strong>{item.requester} · {item.requested_by}</strong></div><div><small>EXPIRES</small><strong>{new Date(item.expires_at).toLocaleString()}</strong></div><div><small>REQUEST REASON</small><strong>{item.requester_reason || '—'}</strong></div><div><small>DECISION REASON</small><strong>{item.reason || '—'}</strong></div></div>
        {item.decision === 'APPROVED' && item.remediation_action_id && <p className="hint">Linked remediation {item.remediation_action_id}</p>}
        <div className="approval-actions">{mayApprove && <button className="primary" disabled={busy} onClick={() => decide(item, 'approve')}>Approve</button>}{mayReject && <button className="secondary" disabled={busy} onClick={() => decide(item, 'reject')}>Reject</button>}{canDecide && item.decision === 'APPROVED' && !item.remediation_action_id && <button className="secondary" disabled={busy} onClick={() => simulateApproved(item)}>Simulate approved action</button>}</div>
      </article>
    })}</div> : <div className="empty">No approval requests yet.</div>}
  </section>
}

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem('qs_token') || '')
  const [user, setUser] = useState(null)
  const [incidents, setIncidents] = useState([])
  const [selected, setSelected] = useState(null)
  const [audit, setAudit] = useState([])
  const [filters, setFilters] = useState({ severity: '', status: '', incident_type: '' })
  const [loginError, setLoginError] = useState('')
  const [pageError, setPageError] = useState('')
  const [busy, setBusy] = useState(false)
  const [loginBusy, setLoginBusy] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [formError, setFormError] = useState('')
  const [detailError, setDetailError] = useState('')
  const [apiStatus, setApiStatus] = useState('checking')
  const [view, setView] = useState('incidents')
  const [approvalReload, setApprovalReload] = useState(0)

  const request = useCallback(async (path, options = {}) => {
    const response = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers },
    })
    const payload = await response.json().catch(() => ({}))
    if (response.status === 401) {
      sessionStorage.removeItem('qs_token')
      setToken('')
      setUser(null)
    }
    if (!response.ok) throw new Error(readError(payload, `Request failed (${response.status})`))
    return payload
  }, [token])

  const query = useMemo(() => {
    const params = new URLSearchParams()
    Object.entries(filters).forEach(([key, value]) => { if (value) params.set(key, value) })
    return params.toString()
  }, [filters])

  const loadIncidents = useCallback(async () => {
    if (!token) return
    try {
      setPageError('')
      setIncidents(await request(`/api/v1/incidents${query ? `?${query}` : ''}`))
      setApiStatus('online')
    } catch (error) {
      setPageError(error.message)
      setApiStatus('offline')
    }
  }, [query, request, token])

  const loadDetail = useCallback(async (incident) => {
    setSelected(incident)
    setDetailError('')
    try {
      const [full, events] = await Promise.all([
        request(`/api/v1/incidents/${encodeURIComponent(incident.id)}`),
        request(`/api/v1/incidents/${encodeURIComponent(incident.id)}/audit`),
      ])
      setSelected(full)
      setAudit(events)
    } catch (error) { setDetailError(error.message) }
  }, [request])

  useEffect(() => {
    if (!token) return
    request('/api/v1/auth/me').then(setUser).catch((error) => setPageError(error.message))
  }, [token, request])

  useEffect(() => { loadIncidents() }, [loadIncidents])

  async function login(username, password) {
    setLoginBusy(true); setLoginError('')
    try {
      const response = await fetch(`${API_URL}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(readError(data, 'Sign in failed'))
      sessionStorage.setItem('qs_token', data.access_token)
      setToken(data.access_token)
    } catch (error) { setLoginError(error.message) } finally { setLoginBusy(false) }
  }

  async function createIncident(form) {
    setBusy(true); setFormError('')
    try {
      const created = await request('/api/v1/incidents', { method: 'POST', body: JSON.stringify(form) })
      setShowForm(false); await loadIncidents(); await loadDetail(created)
    } catch (error) { setFormError(error.message) } finally { setBusy(false) }
  }

  async function analyze() {
    if (!selected) return
    setBusy(true); setDetailError('')
    try { const updated = await request(`/api/v1/incidents/${encodeURIComponent(selected.id)}/analyze`, { method: 'POST' }); await loadIncidents(); await loadDetail(updated) }
    catch (error) { setDetailError(error.message) } finally { setBusy(false) }
  }

  async function updateStatus(nextStatus) {
    if (!selected) { setSelected(null); return }
    setBusy(true); setDetailError('')
    try {
      const note = nextStatus === 'resolved' ? window.prompt('Describe the verification performed:') : null
      if (nextStatus === 'resolved' && !note) return
      const updated = await request(`/api/v1/incidents/${encodeURIComponent(selected.id)}/status`, { method: 'PATCH', body: JSON.stringify({ status: nextStatus, note }) })
      await loadIncidents(); await loadDetail(updated)
    } catch (error) { setDetailError(error.message) } finally { setBusy(false) }
  }

  function logout() { sessionStorage.removeItem('qs_token'); setToken(''); setUser(null); setIncidents([]); setSelected(null) }

  if (!token) return <Login onLogin={login} error={loginError} busy={loginBusy} />

  const severityCounts = ['critical', 'high', 'medium', 'low'].map((level) => [level, incidents.filter((item) => item.severity === level).length])

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><Shield size={20} /></div><div><strong>QuantumSHIELD</strong><span>Security operations</span></div></div>
        <div className="nav-label">WORKSPACE</div><button className={`nav ${view === 'incidents' ? 'active' : ''}`} onClick={() => setView('incidents')}><Activity size={17} /> Incidents</button>
        <button className={`nav ${view === 'kubernetes' ? 'active' : ''}`} onClick={() => setView('kubernetes')}><Server size={17} /> Kubernetes / Response</button>
        <button className={`nav ${view === 'approvals' ? 'active' : ''}`} onClick={() => setView('approvals')}><ClipboardList size={17} /> Approvals</button>
        <div className="nav muted-nav"><KeyRound size={17} /> PQC integrity</div><div className="nav muted-nav"><Blocks size={17} /> Ledger</div>
        <div className="sidebar-foot"><span className={`dot ${apiStatus}`} /> API {apiStatus}<span className="role">{user?.role?.replaceAll('_', ' ')}</span></div>
      </aside>
      <main>
        <header><div><div className="eyebrow">SECURITY OPERATIONS / {view.toUpperCase()}</div><h1>{view === 'incidents' ? 'Incident dashboard' : view === 'approvals' ? 'Remediation approvals' : 'Kubernetes / Response'}</h1><p>{view === 'incidents' ? 'Authenticated event intake, analysis, and audit state' : view === 'approvals' ? 'Separate, auditable human decisions for proposed remediation' : 'Cluster observation, detected conditions, and controlled response'}</p></div><div className="header-actions">{view === 'incidents' && <><button className="secondary" onClick={loadIncidents}><RefreshCw size={14} /> Refresh</button><button className="primary" onClick={() => { setFormError(''); setShowForm(true) }}><Plus size={15} /> New incident</button></>}<button className="icon-button" title="Sign out" onClick={logout}><LogOut size={17} /></button></div></header>
        {pageError && <div className="error-box">{pageError}</div>}
        {view === 'incidents' && <><section className="summary-grid"><div className="summary-card total"><span>VISIBLE INCIDENTS</span><strong>{incidents.length}</strong></div>{severityCounts.map(([label, count]) => <div className={`summary-card ${label}`} key={label}><span>{label.toUpperCase()}</span><strong>{count}</strong></div>)}</section>
        <section className="table-card">
          <div className="section-title"><div><h2>Incident queue</h2><p>Only records returned by the authenticated API are shown.</p></div><span className="queue-count">{incidents.length} shown</span></div>
          <div className="filters"><label><Search size={14} /><input aria-label="Filter by incident type" placeholder="Incident type" value={filters.incident_type} onChange={(e) => setFilters((s) => ({ ...s, incident_type: e.target.value }))} /></label><select aria-label="Filter severity" value={filters.severity} onChange={(e) => setFilters((s) => ({ ...s, severity: e.target.value }))}><option value="">All severity</option>{['critical', 'high', 'medium', 'low', 'unknown'].map((item) => <option key={item}>{item}</option>)}</select><select aria-label="Filter status" value={filters.status} onChange={(e) => setFilters((s) => ({ ...s, status: e.target.value }))}><option value="">All status</option>{['detected', 'triaged', 'investigating', 'resolved', 'dismissed'].map((item) => <option key={item}>{item}</option>)}</select></div>
          <div className="table-wrap"><table><thead><tr><th>INCIDENT</th><th>SOURCE</th><th>SEVERITY</th><th>AI</th><th>PQC</th><th>BLOCKCHAIN</th><th>STATUS</th><th /></tr></thead><tbody>
            {incidents.map((incident) => <tr key={incident.id} onClick={() => loadDetail(incident)} className="clickable"><td><strong>{incident.summary}</strong><small className="mono">{incident.id}</small></td><td>{incident.source}<small>{incident.incident_type}</small></td><td><Status value={incident.severity} /></td><td><Status value={incident.ai_status} /></td><td><Status value={incident.pqc_status} /></td><td><Status value={incident.blockchain_status} /></td><td><Status value={incident.status} /></td><td><ChevronRight size={15} /></td></tr>)}
            {incidents.length === 0 && <tr><td colSpan="8" className="empty">{pageError ? 'Incidents could not be loaded.' : 'No live incidents match these filters.'}</td></tr>}
          </tbody></table></div>
        </section>
        {selected && <IncidentDetail incident={selected} audit={audit} onAnalyze={analyze} onStatus={updateStatus} busy={busy} error={detailError} role={user?.role} />}
        </>}
        {view === 'kubernetes' && <KubernetesPanel request={request} user={user} busy={busy} setBusy={setBusy} onApprovals={() => setApprovalReload((value) => value + 1)} />}
        {view === 'approvals' && <ApprovalsPanel key={approvalReload} request={request} user={user} busy={busy} setBusy={setBusy} />}
        <footer>Confidence is uncalibrated; DEMO AI results are deterministic fixtures. Mock ledger entries are not Fabric commits. Real Kubernetes remediation requires the server gate, allowlists, and a separate approval.</footer>
      </main>
      {showForm && <IncidentForm onSubmit={createIncident} onClose={() => setShowForm(false)} busy={busy} error={formError} />}
    </div>
  )
}
