# Infrastructure

The root Compose file provisions only PostgreSQL. Fabric and Kubernetes manifests are intentionally deferred until network identities, endorsement policy, least-privilege RBAC, and operational boundaries are specified. Do not deploy application containers with default credentials.
