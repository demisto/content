## NVIDIA OpenShell

The OpenShell gateway is usually reachable only inside the AI infrastructure. Run this integration on an engine that can reach the gateway, and enter its host and port, for example `openshell-gateway.example.com:17670`. If the gateway listens on localhost, install the engine on the same host and run integration containers with host networking.

### Authentication

The gateway uses mutual TLS by default. Copy these files from the machine where the OpenShell CLI is configured, usually `~/.config/openshell/gateways/<gateway>/mtls/`:

| Instance parameter | File |
| --- | --- |
| Gateway CA certificate | `ca.crt` |
| Client certificate | `tls.crt` |
| Client private key | `tls.key` |

For gateways configured for OIDC, use the **OIDC bearer token** parameter instead. The token is not refreshed automatically, so use a long-lived token and update the parameter before it expires. If the gateway certificate is signed by a public CA, leave **Gateway CA certificate** empty to use the system trust store.
