"""Closed set of Kubernetes mutations supported by the prototype."""
ALLOWED_ACTIONS = frozenset({"restart_deployment", "scale_deployment"})
