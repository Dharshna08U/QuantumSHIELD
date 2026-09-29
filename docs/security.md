# Security behavior and limits

- `JWT_SECRET` must be configured with at least 32 characters and cannot use the example placeholder. JWT signing is pinned to HS256. CORS requires explicit origins and rejects `*`. Passwords use Argon2. Public registration assigns the analyst role; administrators are provisioned locally.
- The API uses bearer authentication, database-backed user/role lookup, and permission checks. A user with an insufficient role receives 403; missing/invalid credentials receive 401.
- Request validation limits evidence length and rejects likely credential field names in attributes. API exceptions use structured responses without stack traces or raw dependency errors.
- AI errors are distinguished from predictions. AI output is schema-validated; confidence is a class probability, not a calibrated score. The bundled training data is synthetic.
- SHA-256, ML-DSA verification, ML-KEM key establishment, AES-GCM encryption, and ledger status are separate fields. A missing PQC provider returns unavailable/not-performed status. A signature is marked verified only when the provider returns true.
- Required encryption is rejected before persistence unless a provider and recipient public key are available. If encryption fails at runtime, the plaintext description is discarded and the record reports failure. Evidence sent to the AI service is not PQC-encrypted by this storage-encryption step; use HTTPS for a remote AI service.
- The default ledger is a process-local mock and visibly reports `mock`. The Fabric bridge uses a shared bearer service token and TLS Fabric Gateway identity. Keep its token, private identity key, certificates, and endpoints outside source control.
- Kubernetes is unavailable by default. Mock observations identify themselves as mock; the dashboard does not present them as live cluster state.
- Real observation requires an explicitly selected HTTPS API provider, bearer token, and trusted CA configuration. Deploy credentials must be externally provisioned and least-privileged.
- Mutation is disabled unless `KUBERNETES_REMEDIATION_ENABLED=true`. Simulation is the default and never calls a mutating API.
- Remediation is restricted to Deployment restart/scale, validated names, server-side namespace/Deployment allowlists, and a replica ceiling. No arbitrary shell, `kubectl`, namespace deletion, RBAC, secret, network policy, or storage mutation is supported.
- Persistent approval records bind incident, action, exact parameters, requester, policy result, expiry, and approver. Only operators/administrators can decide; analysts cannot. With separation-of-duties enabled, requesters cannot approve their own request. Expired, rejected, mismatched, consumed, closed-incident, and disallowed requests cannot authorize execution. Policy, approval, execution/simulation, and every bounded verification outcome are audited.
- Response evidence is hashed and sent through configured PQC and blockchain adapters. Mock ledger entries are local simulations, not Fabric commits.

## Kubernetes threat model and limitations

This remains a research/prototype framework. Kubernetes error events indicate observed conditions; they do not by themselves establish malicious activity. The synthetic AI dataset is not evidence of production threat detection.

The watch service is interval polling, not a Kubernetes streaming watch. It runs inside the API process, so deployments with multiple API workers can poll concurrently; the unique database fingerprint protects durable identity, but production rollout should use a single watcher instance or a distributed lease. Restart verification observes rollout generation rather than proving application-level health. Scale verification checks desired/ready replica counts. API acceptance can be followed by delayed convergence, so `TIMEOUT` may need later operator review. Protect the API, database, signing keys, Kubernetes credentials, and Fabric bridge as separate trust boundaries. This focused source review is not a formal security audit or production deployment validation.

This is a development implementation. It has not received a security audit or production deployment validation.
