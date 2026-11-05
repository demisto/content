## NVIDIA OpenShell

The OpenShell gateway is usually reachable only inside the AI infrastructure (default `127.0.0.1:17670`). Run this integration on an engine that can reach the gateway. If the gateway listens on localhost, install the engine on the same host and run integration containers with host networking.

### Authentication

The gateway uses mutual TLS by default. Copy these files from the machine where the OpenShell CLI is configured, usually `~/.config/openshell/gateways/<gateway>/mtls/`:

| Instance parameter | File |
| --- | --- |
| Gateway CA certificate | `ca.crt` |
| Client certificate | `tls.crt` |
| Client private key | `tls.key` |

For gateways configured for OIDC, use the **OIDC bearer token** parameter instead.

### Safety

- `openshell-sandbox-delete` and `openshell-provider-detach` cannot be undone and require `confirm=yes`.
- Policy changes are recorded as new policy revisions on the gateway. Use `openshell-policy-history` to review them.
