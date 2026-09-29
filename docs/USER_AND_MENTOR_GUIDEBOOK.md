# QuantumSHIELD User and Mentor Guidebook

This manual describes the code and controls in this repository. It is for local learning and demonstration, not production incident response.

## 1. What QuantumSHIELD is

QuantumSHIELD is a prototype security-operations workflow. It accepts an incident, obtains a structured triage result, records lifecycle/audit information, computes an integrity hash, and can correlate Kubernetes-like conditions with incident records. It has role-based controls and an explicit approval workflow around supported response actions.

It addresses a systems-integration question: how can incident intake, machine-assisted triage, integrity evidence, operational observations, human approval, and response records be joined into one reviewable flow? The demo is not an autonomous attack detector and does not prove a live blockchain, quantum-resistant deployment, or production cluster integration.

## 2. Architecture and components

- **React/Vite frontend** (`frontend/`): login form, incident dashboard/detail, Kubernetes/Response panel, and Approvals panel. It calls authenticated FastAPI routes; incident counts are derived from API-returned data.
- **FastAPI backend** (`backend/`): login/JWT, role permissions, incident pipeline, audit trail, Kubernetes routes, approval workflow, and health endpoint.
- **Database**: SQLAlchemy and Alembic; SQLite is the local default. PostgreSQL is optional through Compose. Incident, user, audit, condition, approval, and action rows are persisted.
- **AI service** (`ai_engine/`): TF-IDF features and LogisticRegression trained from the bundled synthetic CSV. In normal mode, its class probability is returned as an uncalibrated confidence. With `DEMO_MODE=true`, the backend uses a fixed `DemoAIClient` response and does not call this service for incident analysis.
- **Integrity/PQC** (`pqc/`): canonical serialization and SHA-256 are used for record integrity. An optional `liboqs` adapter contains ML-DSA-65 signing/verification and ML-KEM-768 key establishment followed by HKDF and AES-256-GCM. In demo mode PQC is explicitly unavailable; no private keys are bundled.
- **Ledger** (`blockchain_service/`, `blockchain-service/`, `chaincode/`): a process-local mock is the demo provider. Optional Node Fabric bridge and chaincode source exist, but a Fabric network/identity is not supplied. Demo ledger records do not survive backend restarts.
- **Kubernetes/response** (`kubernetes/`): unavailable, mock, deterministic demo, or HTTPS REST providers; conservative condition rules; durable fingerprint history; response policy; approvals; simulation; separately gated real-execution code. Current demo selects the deterministic demo provider and simulation.

## 3. Local setup and service lifecycle

Use Python 3.12, Node.js 20+, and npm. Run from the project root to keep the SQLite file and `.env` resolution consistent.

```sh
cp .env.example .env
```

Edit `.env` and replace `JWT_SECRET` with a locally generated random string of at least 32 characters. Keep secrets only in `.env`; do not paste them into screenshots or this guide. For a mentor demo use `DEMO_MODE=true`, `KUBERNETES_REMEDIATION_ENABLED=false`, `KUBERNETES_WATCH_ENABLED=false`, `PQC_PROVIDER=unavailable`, and `BLOCKCHAIN_PROVIDER=mock`. The CORS example allows the two exact local Vite origins.

Install and initialize once:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r ai-engine/requirements.txt -e '.[dev]'
npm --prefix frontend ci
npm --prefix blockchain-service ci
alembic upgrade head
python -m backend.app.cli
python -m ai_engine.train
```

The CLI asks for an administrator username, email, and password twice; keep that credential in a local password manager. Do not put it in documentation. The AI model artifact is local and ignored by Git. It is unnecessary for the deterministic backend classifier, but is used by the standalone AI service and normal non-demo model flow.

Start three terminals from the project root:

```sh
# Terminal 1
. .venv/bin/activate && uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
# Terminal 2
. .venv/bin/activate && uvicorn ai_engine.app:app --reload --host 127.0.0.1 --port 8001
# Terminal 3
npm --prefix frontend run dev -- --host 127.0.0.1
```

The backend and AI health routes are `/health`; the frontend is at <http://127.0.0.1:5173/>. Stop each by pressing Ctrl+C in its terminal. Do not delete the SQLite file to stop or reset the service. A real reset destroys local demo data and requires a deliberate backup/reset procedure.

## 4. Login and workspace overview

Sign in with the administrator created locally. The login endpoint returns a bearer token; the browser keeps it in `sessionStorage` for the tab session. The backend looks up the active user on each authenticated request, so missing/expired tokens receive 401 and insufficient roles receive 403. Use **Logout** on a shared screen.

The default workspace is **Incident dashboard**. The top counters and incident queue come from `GET /api/v1/incidents`, not a hard-coded UI sample. Filters alter the API query by severity, status, or incident type. Selecting a row fetches the full record and its audit events.

### Incident detail sections

- **AI analysis**: status, classification, severity (shown in actions/queue), confidence, recommendation, eligibility, and dataset/mode notice. Demo output is fixed and clearly identified. Model confidence is not calibrated.
- **Cryptographic integrity**: SHA-256 record hash; ML-DSA status/verification; optional evidence-encryption and KEM fields. A hash detects a change relative to a trusted expected value; it does not encrypt data.
- **Blockchain audit**: provider, record status, integrity verification, and transaction reference. `mock_recorded` means the local mock accepted and compared a hash; it is not a Fabric transaction.
- **Response**: policy/healing decision and simulation status. The incident pipeline itself does not execute a Kubernetes operation.
- **Audit trail**: chronological event type, actor, result, metadata, and time. It is an application database audit log, not immutable storage by itself.

## 5. Actions: effects and demo safety

All state-changing actions require authentication and create database records and/or audit events as noted. In the recommended demo configuration, no action mutates a cluster. Use synthetic examples only.

| UI action | What happens | Data / audit effect | Mode and expected result | Mentor-demo safety |
|---|---|---|---|---|
| **Open incident row** | Fetches incident detail plus `/audit`. | Read-only; no audit event is created. | Shows the selected API record and lifecycle history. | Safe. |
| **Filter severity/status/type** | Reloads the incident list with query parameters. | Read-only; no audit event. | Queue/counters reflect returned rows. | Safe. |
| **Refresh** (incidents or Kubernetes panel) | Re-fetches current API records. | Read-only; no audit event. | Updates visible status and history. | Safe. |
| **New incident** | Opens the incident intake form. | No server change until submission. | Form collects source, type, summary, description; optional required encryption. | Safe to open; do not submit secrets, personal data, or real incident evidence. |
| **Submit and analyze** | `POST /api/v1/incidents` persists the incident, calls the configured/demo analyzer, applies severity/policy, computes SHA-256/PQC status, records optional ledger result. | Creates an incident, initial simulated healing record, and multiple audit events; persistent in the DB. | Demo uses a deterministic analysis, unavailable PQC, and mock ledger. | Safe with synthetic data; avoid sensitive data. Required encryption fails closed if unavailable. |
| **Re-run analysis** | `POST /incidents/{id}/analyze` repeats analysis/policy/integrity. The UI refreshes the record. | Can update incident fields and adds analysis/integrity audit events. | Demo remains deterministic. It is rejected if description is absent or a ledger record has made it immutable. | Safe for demo incidents; may return 409 on immutable ledger-recorded incidents. |
| **Mark triaged** | Changes `detected` to `triaged`. | Persists status and `incident.status_changed` audit event. | Status badge becomes `triaged`. | Safe; database change is intentional. |
| **Investigate** | Changes eligible `detected`/`triaged` state to `investigating`. | Persists status and status-change audit event. | Status badge becomes `investigating`. | Safe; database change is intentional. |
| **Resolve** | Prompts for a verification note and requests `resolved`. | Persists status/note-presence event; operators/admins only. | Only allowed from `triaged` or `investigating`; resolved incidents cannot transition again. | Safe with a truthful demo note; do not claim an external remediation was verified. |
| **Close detail** | Hides the detail panel. | UI-only; no API call or audit. | Returns to the queue. | Safe. |
| **Run deterministic demo** | `POST /api/v1/kubernetes/demo/run` observes deterministic fixtures, detects/correlates conditions, and sends new findings through the incident pipeline. | Persists condition rows, new incidents when fingerprints are new/reopened, and observation/demo audit events. Repeated active fingerprints increment observations instead of duplicating incidents. | Only available when the configured provider is `demo`; output is labeled `DEMO`/`SIMULATION`. | Recommended. It writes demo data but never accesses a live cluster. |
| **Poll & detect** | `POST /api/v1/kubernetes/poll` snapshots the configured provider, runs rules, deduplicates, and creates incidents for new findings. | Persists observations, condition history, incidents, and audit events. | In this demo configuration it is deterministic. With a REST provider it contacts a real cluster for read-only observation. | Safe only when status visibly says DEMO/MOCK or UNAVAILABLE. Do not use against a live provider during a mentor demo. |
| **Request approval** | Creates a persistent approval bound to the incident, action, namespace/deployment, policy, requester, and expiry. | Persists approval and audit event; does not mutate a cluster. Repeated matching pending requests may return the existing one. | Starts `PENDING`; allowed action is still not permission to execute. | Safe; use synthetic/demo resource names. A different admin/operator must approve by default. |
| **Approve / Reject** | Records a human decision through the approval API. | Persists decision, actor, timestamp, reason, and audit event. | `APPROVED` or `REJECTED`; approval may expire or be blocked by policy/separation-of-duties. | Safe for demo; it does not itself execute a cluster action. Do not self-approve. |
| **Simulate response** | Calls `/remediations/simulate` for a related condition. | Creates simulated remediation and integrity/audit records. | Returns `SIMULATION`; `cluster_mutated` is false; verification remains simulation/unavailable. | Recommended. No cluster mutation. |
| **Simulate approved action** | Sends the approval-bound parameters to the same simulation route. | Creates a simulated action and response/integrity audit events; may link/consume the approval. | Shows simulation and no cluster mutation. | Recommended once an approved demo request exists. |
| **Logout** | Removes the tab token and clears user/list/detail state. | No server-side incident change; no explicit audit event in the current UI handler. | Login form returns. | Safe; recommended on a shared screen. |

### Actions that must not be used in this configuration

- Do not call `POST /api/v1/kubernetes/remediations/execute`. It is a real-execution route guarded by multiple server checks, but it is not needed for this demo.
- Do not enable `KUBERNETES_REMEDIATION_ENABLED`, configure real cluster tokens/allowlists, or set `KUBERNETES_WATCH_ENABLED` for a mentor presentation.
- Do not configure `BLOCKCHAIN_PROVIDER=fabric`, Fabric credentials/certificates, or PQC private keys for the local demo. A source adapter is not proof of a network deployment.
- Do not enable required evidence encryption unless a real, externally managed recipient public key/provider is deliberately configured and verified.

## 6. Kubernetes / Response and Approvals

The panel shows provider identity and availability first. `DEMO`/`MOCK` is not a live cluster; `UNAVAILABLE` means the provider cannot be contacted/configured. A successful REST connection is read-only for observations. Conditions are conservative rules (pod restart/crash, health/readiness gaps, selected event reasons, and Deployment readiness); a Kubernetes error is not automatically an attack.

Fingerprint correlation is persistent. A repeated active condition updates its count without another incident. A condition missing from a complete successful snapshot is resolved; reappearance creates a new incident. Provider failures do not resolve active findings.

Response policy is advisory. It distinguishes record-only/recommendation/approval-required/blocked outcomes. A real REST mutation requires the global setting, operator/admin permission, allowlists, an allowed action, and a fresh matching approval. This is a deliberately strict gate; this guide recommends staying on the simulation route.

Approvals show requested operation and resource, policy rationale, requester, expiry, and decision. For a fresh mentor flow, register/sign in as a Security Analyst to request an approval, then log in as a different Administrator/Operator to approve it. Public registration cannot create operators or administrators. Separation of duties blocks self-approval by default.

## 7. Deterministic demo and recommended 10–15 minute mentor demo

Prepare the `.env`/services as above. Use synthetic records. This sequence assumes `DEMO_MODE=true` and no live providers:

| Time / step | What to click | What to say | Concept demonstrated |
|---|---|---|---|
| 0:00–1:00 Start | Start the three documented processes; check health routes. | “The local stack has separate UI, API, and optional AI services.” | Service boundaries and health checks. |
| 1:00–2:00 Login | Sign in as the locally provisioned admin. | “Public users cannot register as administrators; the API checks bearer tokens and roles.” | Authentication/RBAC. |
| 2:00–3:00 Dashboard | Show counts, filters, and an incident row. | “The queue is fetched from the authenticated API and backed by the local database.” | API-backed UI and persistence. |
| 3:00–4:00 Incident detail | Open a synthetic incident. | “Each record carries lifecycle, integration, and audit states.” | Incident data model. |
| 4:00–5:00 AI analysis | Point to result, class, confidence, dataset notice. | “Demo mode returns a deterministic fixture, not a live AI prediction. The trained model path uses synthetic data and uncalibrated class probabilities.” | Responsible ML reporting. |
| 5:00–6:00 Integrity/PQC | Show SHA-256 and unavailable PQC labels. | “SHA-256 is available for integrity; it is not encryption. PQC is explicitly unavailable because no provider/keys are configured.” | Hash vs signature vs encryption. |
| 6:00–7:00 Ledger | Show `mock`/`mock_recorded`. | “The mock compares hashes in process memory. It is not Hyperledger Fabric and is lost on restart.” | Honest integration status. |
| 7:00–8:00 Audit | Walk through incident-created, AI, severity, integrity, and ledger events. | “The audit trail records application actions in the database; it is not by itself tamper-proof storage.” | Traceability and limits. |
| 8:00–10:00 Kubernetes demo | Open Kubernetes/Response; click **Run deterministic demo**. | “These observations come from a fixture. Fingerprints deduplicate repeated active conditions.” | Detection/correlation lifecycle. |
| 10:00–11:00 Approval request | Use a Security Analyst account and click **Request approval** for an eligible synthetic failure condition. | “The request binds an action and exact resource; it changes no cluster state.” | Human-in-the-loop controls. |
| 11:00–12:00 Approval | Switch to a different admin/operator; open Approvals and **Approve**. | “The requester cannot self-approve; approvals expire and are auditable.” | Separation of duties. |
| 12:00–13:00 Simulate | Click **Simulate approved action**. | “This follows approval but uses the no-mutation route; the cluster-mutated result is false.” | Safe response simulation. |
| 13:00–15:00 Wrap-up | Show remediation and audit records; logout. | “Real Fabric, live PQC, and real cluster mutation remain unconfigured and unvalidated.” | Accurate scope and next steps. |

The database may already contain old demo rows; demo execution can create zero new incidents when all fingerprints are active. Explain the returned condition and observation counts rather than promising a new incident every click. A new approval demonstration requires an eligible condition, a requester account, and a different decision-maker; if the UI has no eligible row, show the existing approval history without inventing a successful flow.

## 8. Common API map

- Auth: `POST /api/v1/auth/login`, `GET /api/v1/auth/me`, public `POST /api/v1/auth/register` (analyst only).
- Incidents: `POST/GET /api/v1/incidents`, `GET /{id}`, `POST /{id}/analyze`, `PATCH /{id}/status`, `GET /{id}/audit`, `GET /{id}/ledger`.
- Kubernetes/reporting: `GET /api/v1/kubernetes/status|nodes|pods|conditions|conditions/history|incidents|remediations|approvals|audit`.
- Demo/response: `POST /api/v1/kubernetes/demo/run`, `/poll`, `/remediations/simulate`; an execution route exists but must not be used for this demo.

## 9. Viva / mentor questions

1. **Why blockchain?** To explore a separately verifiable integrity receipt for selected incident metadata. The current configured provider is a local mock, so the project does not claim distributed trust.
2. **Why Hyperledger Fabric?** Its permissioned identities and policy model fit organizational participants better than an anonymous public chain. The adapter/chaincode source exists; no Fabric network is included.
3. **Why a permissioned blockchain?** Security incident data is sensitive and participating organizations need known identities/access controls. A permissioned network still needs careful privacy and governance design.
4. **Why post-quantum cryptography?** To prototype algorithms intended to resist known quantum-capable attacks on public-key schemes. This demo does not run a live PQC provider.
5. **Why ML-DSA?** It is the signature family implemented by the optional OQS adapter for signing and verifying canonical incident records.
6. **Why ML-KEM?** It establishes a shared secret for encryption; it does not sign records or encrypt application data directly.
7. **ML-DSA vs ML-KEM?** ML-DSA provides digital signatures; ML-KEM establishes shared key material. The roles are complementary, not interchangeable.
8. **Why SHA-256 with PQC?** SHA-256 is a digest for canonical record integrity. PQC signatures provide public-key authenticity; neither makes the other redundant, and a hash alone is not encryption.
9. **Why AI?** To produce a structured triage label/recommendation that can be reviewed alongside rules and policy, not to autonomously declare an attack.
10. **What does AI classify?** The synthetic model labels resource exhaustion, application failure, or suspicious activity; demo mode instead returns a fixed `operational_anomaly` fixture.
11. **How is confidence calculated?** The standalone classifier returns the predicted class's `predict_proba` value. Demo mode returns a fixed fixture value, not a model probability.
12. **What does uncalibrated mean?** A value such as 0.8 is not established to correspond to an 80% empirical correctness rate; no calibration evaluation is supplied.
13. **Why Kubernetes?** It is a common workload platform with observable pod, node, event, and Deployment health signals. This demo observes fixtures only.
14. **What is BackOff/CrashLoopBackOff?** Kubernetes reports repeated container-start failures with increasing delays; the detector uses container waiting reason and restart counts as a condition, not proof of compromise.
15. **How is deduplication performed?** A SHA-256 fingerprint is built from cluster identity, condition type, namespace, resource, and stable title; active duplicates update a persistent row/count.
16. **Why human approval?** Automated remediation can disrupt services; policy and an independent human decision add safeguards and accountability.
17. **Why not remediate everything automatically?** Severity and classifier output can be wrong, and even valid actions can worsen an incident. The code requires policy, allowlists, role, approval, and a global gate for real actions.
18. **How is RBAC implemented?** JWT identifies a database user; dependency functions enforce a permission map for Administrator, Security Analyst, and Operator roles.
19. **How are incidents persisted?** SQLAlchemy stores them in SQLite by default; Alembic migrations define schema changes. PostgreSQL is an optional deployment path.
20. **What goes on the ledger?** The configured metadata includes incident ID/hash plus timestamp, source/type, severity, classification, confidence, recommendation, healing state, and crypto statuses. Raw description text is not included in ledger metadata; its digest contributes to the canonical record hash.
21. **Why not store everything on blockchain?** Replication is expensive and sensitive data is hard to erase. Keep detailed evidence in controlled storage and put only minimal integrity metadata on-chain; real network privacy still needs design review.
22. **What is the audit trail?** Database events for incident, AI/severity, PQC, ledger, status, Kubernetes observation, approval, remediation, and verification transitions. It is useful traceability but not immutable by itself.
23. **What happens when PQC is unavailable?** Status is recorded as unavailable; it is never reported as verified. Requests requiring encryption fail closed before persisting plaintext evidence.
24. **What happens when Fabric is unavailable?** The configured Fabric client returns an unavailable/failed state and audits it; demo mode uses a separately labeled mock instead.
25. **What happens when Kubernetes is unavailable?** The provider reports unavailable and records observation failure; an incomplete/failed snapshot does not resolve active conditions.
26. **What is simulation mode?** It records the proposed action/result and audit evidence without calling a mutating Kubernetes method; output explicitly says no cluster mutation occurred.
27. **What is actually implemented?** API/UI, authentication/RBAC, DB persistence/migrations, incident pipeline, synthetic model service, SHA-256, optional adapter code, condition correlation, policy, approvals, simulation, audit, and tests.
28. **What is currently simulated?** Deterministic Kubernetes fixture observations, the fixed DemoAI response, mock in-memory ledger records, and all demo remediation.
29. **What is unavailable?** Live Fabric, live Kubernetes in the current demo, and the PQC provider/keys. The default project does not provision these systems.
30. **What are the main limitations?** Synthetic small dataset; uncalibrated score; process-local mock ledger; SQLite local default; no live integration validation; limited frontend automated tests; no production operations controls.
31. **How would it become production-ready?** Threat modeling, data minimization, calibrated/evaluated model, live integration testing in isolated environments, managed keys/secrets, PostgreSQL HA/backups, observability, deployment hardening, SSO, and operational incident procedures.
32. **Does approval mean a real action happened?** No. Approval is a persisted decision. In this demo, a subsequent simulation still makes no cluster change.
33. **Does `verified` on a mock ledger mean Fabric endorsement?** No. It means the mock compared the expected hash to its in-memory record.
34. **Can a Security Analyst resolve an incident?** No. Analyst permission allows triage and investigation; only an Operator/Administrator can resolve, and a verification note is required.
35. **Does demo mode call the trained model?** No. The backend chooses `DemoAIClient`; its result is fixed. The independent AI service can still be started and queried separately.
36. **Is the audit trail tamper-proof?** No. It is stored in the same application database. Stronger tamper evidence requires a deployed ledger, separation of duties, retention controls, and threat analysis.
