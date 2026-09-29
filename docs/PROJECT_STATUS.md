# QuantumSHIELD Project Status

Status reviewed: 2026-09-29. This is a development/research prototype. A passing local test suite is not a production certification or live-integration validation.

## Runtime environment

Presentation checks ran in the local Linux/WSL workspace using Python 3.12.3, Node.js 22.23.1, and npm 10.9.2. The configured local database is SQLite. The UI is Vite development mode; FastAPI and the optional AI service are run with Uvicorn. `.env`, the database, and generated model artifacts are local-only and excluded from Git.

## IMPLEMENTED + VERIFIED

- FastAPI authentication and JWT bearer validation, Argon2 password verification, role-to-permission mapping, analyst-only public registration, and locally provisioned administrators.
- SQLAlchemy persistence and Alembic migrations for users, incidents, audit events, Kubernetes condition history, response records, and approval records. SQLite is the local default; PostgreSQL configuration and Compose service are present.
- Incident creation/list/detail/filtering, allowed lifecycle transitions, audit endpoint, severity/AI result storage, field validation, and error handling.
- Synthetic-data TF-IDF/LogisticRegression training and classification service code. The service returns a class probability explicitly marked uncalibrated. The shipped training examples are synthetic.
- Deterministic `DemoAIClient` behavior, with a fixed simulated classification and fixed confidence (not a model prediction), selected when `DEMO_MODE=true`.
- Canonical record serialization and SHA-256 hashing; provider-unavailable states are explicit. OQS/PQC operations have unit tests using test adapters/mocks, but that does not validate a live liboqs runtime.
- Process-local mock ledger record/read/existence/hash-compare behavior, and a separately implemented HTTP/Fabric bridge plus chaincode source. Bridge tests validate unavailable/failure behavior and adapter contracts, not a live Fabric deployment.
- Kubernetes unavailable/mock/demo providers, conservative rule-based condition detection, persistent fingerprint deduplication/reopening, status reporting, response policy, approval rules, simulation/no-mutation recording, and bounded verification logic under tests using test providers.
- React/Vite UI for login, API-fed incident queue/detail, AI/PQC/ledger state, incident audit, Kubernetes/Response, approval history, and simulated response. Production build completes. The frontend currently has no dedicated automated test script.
- Security-oriented configuration defaults: explicit CORS allowlist (wildcards rejected), JWT secret validation, optional integrations disabled/unavailable by default, and real remediation disabled by default.

Final local verification for this presentation pass: **2026-09-29**.

- Python unit/API suite: **44 passed** (`python -m unittest discover -s tests -v`). The run emitted a Python `ResourceWarning` for an unclosed test socket and a Starlette/httpx deprecation warning; no test failed.
- Node blockchain bridge suite: **2 passed** (`npm test --prefix blockchain-service`).
- Frontend production build: **passed** (`npm run build --prefix frontend`; Vite transformed 1,579 modules).
- Python compilation check: **passed** (`python -m compileall -q backend ai_engine blockchain_service kubernetes pqc tests`).
- No dedicated frontend test script is defined in `frontend/package.json`.
- Runtime smoke check: frontend, API, and AI service returned HTTP 200 on ports 5173, 8000, and 8001; local admin login and authenticated `/me` returned HTTP 200 with Administrator role. No credentials were printed.

## IMPLEMENTED + SIMULATED

- Kubernetes observations in `DEMO_MODE=true` use deterministic fixture data and identify as `demo`; they do not connect to a cluster.
- Demo AI incident analysis returns fixed `operational_anomaly` / medium-severity output with a fixture confidence. It does not call the standalone AI model service for incident analysis.
- Incident response policy can create a simulation action. Explicit remediation simulation stores `SIMULATION`, a simulation verification result, and `cluster_mutated=false`; it does not invoke the provider's mutation method.
- Blockchain demo records are stored in a process-local mock and use a hash comparison. They are not Hyperledger Fabric transactions and are lost when the backend process restarts.
- Approval records and decisions are persisted and auditable; approval does not itself perform an action. A followed-up approved simulation remains no-mutation.

## IMPLEMENTED + NOT CURRENTLY AVAILABLE

- **Live PQC provider:** optional OQS code exists for ML-DSA-65 and ML-KEM-768 with HKDF/AES-256-GCM; current demo marks it unavailable and includes no key material. No live provider/key lifecycle has been validated here.
- **Hyperledger Fabric:** Node bridge and chaincode source exist. No peer/orderer network, identity, TLS material, channel, deployed chaincode, or live commit is included or verified.
- **Live Kubernetes provider:** an HTTPS REST observer and narrowly scoped Deployment actions exist in source; current demo has no cluster credentials or network. Live observation/remediation is unverified.
- **Production deployment:** no HA topology, production secrets manager/KMS/HSM, SSO, tenant isolation, monitoring stack, disaster-recovery runbook, or deployment hardening is supplied.
- **Calibrated/validated AI:** bundled data is synthetic and limited; no representative held-out benchmark, calibration study, drift evaluation, or production false-positive/false-negative rate is established.

## FUTURE WORK

- Browser/component test suite; larger permission, concurrency, integration-failure, and CORS test coverage.
- Reproducible dependency constraints, CI, SBOM, dependency/security scans, and release process.
- Representative consented dataset, per-class evaluation, calibrated confidence, drift monitoring, model versioning, and explanation/evaluation study.
- Live, isolated liboqs validation and managed key lifecycle; Fabric test network and ledger privacy/governance review; disposable Kubernetes observation and safety evaluation.
- PostgreSQL concurrency/backup/restore tests; production observability, secrets management, SSO, HA, tenant isolation, and disaster recovery.
- See [Future Improvements](FUTURE_IMPROVEMENTS.md) for staged proposals, cost/difficulty, infrastructure, and paper extensions.

## Security and demo guidance

Use synthetic incidents only. The API may send incident descriptions to the configured AI service in non-demo mode before storage encryption. Required evidence encryption fails closed when the provider/recipient key is unavailable. Keep `.env`, `.local-admin-credentials`, databases, model artifacts, credentials, private keys, certificates, virtual environments, node modules, logs, and build output out of Git. Never enable the real remediation route or provide production credentials during the mentor demo.

See [Security](security.md), [Architecture](architecture.md), and the [User and Mentor Guidebook](USER_AND_MENTOR_GUIDEBOOK.md).
