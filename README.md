# QuantumSHIELD

QuantumSHIELD is a local research prototype for security incident intake, lightweight ML-assisted triage, integrity recording, Kubernetes condition correlation, and approval-gated response simulation. It demonstrates how these workflows can be connected while labeling unavailable and simulated integrations honestly.

> **Current demo:** Kubernetes observations use deterministic demo fixtures, the ledger uses a process-local mock, PQC is unavailable, and all remediation shown in the demo is simulation only. This repository is not a production threat-detection or incident-response system.

## Architecture overview

```text
React/Vite dashboard ── bearer JWT ──> FastAPI + SQLite/PostgreSQL
                                             ├── AI service (TF-IDF + LogisticRegression outside deterministic demo mode)
                                             ├── incident, audit, approval, and condition persistence
                                             ├── integrity: SHA-256; optional external liboqs provider
                                             ├── ledger: process-local mock or separately configured Fabric bridge
                                             └── Kubernetes: unavailable/demo/mock/read-only REST; tightly gated actions
```

## Key features

- Authenticated incident intake, role-based permissions, status transitions, and per-incident audit history.
- A synthetic-data AI service and a fixed deterministic classifier used when `DEMO_MODE=true`.
- Canonical-record SHA-256 and optional ML-DSA / ML-KEM adapters; demo mode marks PQC unavailable.
- Kubernetes condition detection, persistent fingerprint correlation, approval requests, and no-mutation simulation.
- Optional Fabric bridge and chaincode source; no network, identity, or live Fabric commit is included or implied.

## Technology stack

Python 3.12, FastAPI, SQLAlchemy, Alembic, SQLite (local default) or PostgreSQL; React 19 and Vite; Node.js bridge/chaincode sources; scikit-learn; optional liboqs integration.

## Repository structure

| Path | Purpose |
|---|---|
| `backend/` | FastAPI routes, auth, services, database models, migrations |
| `ai_engine/` | Synthetic dataset, model training, and model inference service |
| `pqc/` | Canonical hashing, optional PQC adapter, authenticated encryption flow |
| `blockchain_service/` | Python mock ledger and Fabric bridge client |
| `blockchain-service/` | Node Fabric adapter and its tests |
| `chaincode/quantumshield/` | Fabric chaincode source |
| `kubernetes/` | Providers, condition detection, policies, approvals/remediation, watcher |
| `frontend/` | React/Vite dashboard |
| `tests/` | Python API, integration, security-policy, and Kubernetes tests |
| `docs/` | Architecture, security, development, user/mentor guide, status, roadmap |

## Quick start

Requirements: Python 3.12, Node.js 20+, and npm. Run commands from the repository root so the relative SQLite URL resolves consistently.

```sh
cp .env.example .env
# Edit .env: set JWT_SECRET to a private random value of at least 32 characters.
python3 -m venv .venv
. .venv/bin/activate
pip install -r ai-engine/requirements.txt -e '.[dev]'
npm --prefix frontend ci
npm --prefix blockchain-service ci
alembic upgrade head
python -m backend.app.cli       # creates a local admin interactively
python -m ai_engine.train      # creates ignored synthetic model artifact
```

For the recommended deterministic demo, set `DEMO_MODE=true` in `.env`. Keep `KUBERNETES_REMEDIATION_ENABLED=false`, `KUBERNETES_WATCH_ENABLED=false`, `PQC_PROVIDER=unavailable`, and `BLOCKCHAIN_PROVIDER=mock`. Do not configure production credentials or keys for the mentor demo. Start one process per terminal:

```sh
. .venv/bin/activate && uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
. .venv/bin/activate && uvicorn ai_engine.app:app --reload --host 127.0.0.1 --port 8001
npm --prefix frontend run dev -- --host 127.0.0.1
```

Open <http://127.0.0.1:5173/>. The API defaults to <http://127.0.0.1:8000/>; exact localhost and 127.0.0.1 frontend origins are explicitly allowlisted in the example configuration. Press Ctrl+C in each service terminal to stop it. The local admin credentials are created by the operator and are not shipped with this repository.

See [the complete User and Mentor Guidebook](docs/USER_AND_MENTOR_GUIDEBOOK.md) for setup troubleshooting and the click-by-click demo.

## Demo instructions

1. Confirm `/health` returns 200 on ports 8000 and 8001 and Vite serves port 5173.
2. Sign in using the local administrator created with `backend.app.cli`.
3. Inspect the API-backed incident queue and open an incident.
4. Explain the deterministic AI result, SHA-256 value, unavailable PQC status, and mock ledger status.
5. Open **Kubernetes / Response** and click **Run deterministic demo** when `DEMO_MODE=true`. The call persists condition observations and audit events; it never connects to a live cluster.
6. For a fresh approval flow, use a Security Analyst account to request an approval, then sign in as a different administrator/operator to approve. Use **Simulate approved action** to demonstrate a no-mutation result.

The demo is stateful: database rows and audit entries persist, while mock ledger records are process-local and do not survive a backend restart.

## Screenshots

_Add reviewed screenshots here before publication. Use synthetic records only; crop usernames, tokens, private paths, terminal history, and machine-specific details._

## Security notes

- Never commit `.env`, `.local-admin-credentials`, databases, logs, private keys, certificates with private material, `.venv`, `node_modules`, model artifacts, or generated build output.
- `.env.example` contains placeholders and empty integration settings. Use a new random JWT secret locally; do not reuse a production secret.
- Passwords use Argon2. Public registration assigns only the Security Analyst role. Administrator provisioning is local and interactive.
- Demo mode sends no Kubernetes, Fabric, or liboqs calls. Incident descriptions may be sent to the configured AI service in non-demo mode before storage encryption; do not submit sensitive evidence to an untrusted service.
- No live PQC provider, Fabric network, or Kubernetes cluster is part of the default setup. Never enable the `/remediations/execute` path during this demo.

## Current limitations

- Demo classifications are deterministic fixtures; the optional trained model uses small synthetic data and uncalibrated class probabilities.
- The mock ledger is in memory and is not a distributed ledger.
- PQC adapters exist, but the demo provider is unavailable and no keys are supplied.
- The configured Kubernetes demo is fixture-driven. REST observation and guarded Deployment mutation have not been validated against a live cluster.
- SQLite is for local development. There is no HA deployment, SSO, multi-tenancy, production monitoring, or operational recovery process.

## Testing

```sh
. .venv/bin/activate
python -m unittest discover -s tests -v
npm test --prefix blockchain-service
npm --prefix frontend run build
python -m compileall -q backend ai_engine blockchain_service kubernetes pqc tests
```

The frontend currently has a production build but no dedicated frontend test script. See [project status](docs/PROJECT_STATUS.md) for the latest validation and [future improvements](docs/FUTURE_IMPROVEMENTS.md) for planned work.

## Project status

This is an academic/demo prototype intended for local evaluation. See [docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md) for the honest implemented/simulated/unavailable breakdown.

## License

No license has been selected yet. Unless a license is added, do not assume that the code is licensed for reuse.
