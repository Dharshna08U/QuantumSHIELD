# Development workflow

Use Python 3.12, Node.js 20+, npm, and (for PostgreSQL) Docker Compose. From the repository root, install Python dependencies with `pip install -r ai-engine/requirements.txt -e '.[dev]'`; AI requirements include the backend requirements. Frontend and blockchain bridge dependencies use the committed lockfiles with `npm --prefix frontend ci` and `npm --prefix blockchain-service ci`. The chaincode has its own manifest and requires a separate `npm install` from `chaincode/quantumshield` only when packaging/deploying chaincode; do not install it for the local demo. Optional OQS support is separate: `pip install -r backend/requirements-pqc.txt`; importing it may build native liboqs, requiring build tools/network when no system library exists. No dependency is needed for demo mode. The frontend and bridge installs are reproducible from committed lockfiles; the optional chaincode package does not currently include a lockfile.

Copy `.env.example` to `.env`, then replace the JWT placeholder. Apply migrations with `alembic upgrade head`. Provision the initial administrator using `python -m backend.app.cli`; that command prompts for the account and password. Train the demo model with `python -m ai_engine.train`.

Run `python -m unittest discover -s tests -v`. The API tests need the full backend dependency set; the connected deterministic demo-flow test runs without external infrastructure once those dependencies are installed. Frontend build: `npm --prefix frontend run build`. Node bridge tests: `npm test --prefix blockchain-service`. Migration and end-to-end Fabric, PostgreSQL, and real-liboqs checks require those services/providers to be installed and configured.

Local defaults: SQLite persistence, `BLOCKCHAIN_PROVIDER=mock`, `PQC_PROVIDER=unavailable`, and Kubernetes unavailable with remediation disabled. The mock ledger is process-local. For PostgreSQL, start `docker compose up -d postgres` and set `DATABASE_URL` in `.env` to the matching PostgreSQL URL. Fabric setup requires the Fabric bridge variables documented in `.env.example` and a provisioned network. Key file paths refer to external files and must never point into committed source.

## Phase 3 Kubernetes workflow

Kubernetes unit tests use an in-memory mock and do not need a cluster. API tests are skipped when FastAPI/SQLAlchemy/auth dependencies are unavailable.

For read-only observation, configure `KUBERNETES_PROVIDER=rest`, `KUBERNETES_API_URL` (HTTPS), `KUBERNETES_BEARER_TOKEN`, and `KUBERNETES_CA_FILE`. The token should only read nodes, namespaces, pods, Deployments, and events. Use the dashboard or `GET /api/v1/kubernetes/status` to confirm provider identity and availability. Poll manually through `POST /api/v1/kubernetes/poll`, or set `KUBERNETES_WATCH_ENABLED=true` and configure its polling interval to enable the API lifespan watcher. Watcher polling and manual polling share persistent condition correlation.

To test real actions, use a disposable cluster and deliberately enable `KUBERNETES_REMEDIATION_ENABLED=true`, namespace/Deployment allowlists, and a low replica maximum. The REST identity also needs Deployment patch permission only for those test resources. Create a request, have a separate operator/admin approve it, then execute. Simulation is the default and can be used without any cluster mutation permission. Verification is bounded by attempt count and delay and can be repeated through the verification endpoint.

Set `DEMO_MODE=true` to run the dashboard flow using a deterministic fixture. It demonstrates observation, incident analysis, unavailable PQC, mock ledger recording, approval, simulation, and audit without contacting Kubernetes, AI, Fabric, or liboqs. Demo outputs are explicitly marked simulated.
