# NVIDIA OpenShell

[NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) runs AI agents in sandboxes and enforces a network and credential policy for each agent. This pack lets a playbook or an analyst contain an agent through the OpenShell gateway.

## What does this pack do?

| Action | Command |
| --- | --- |
| Stop, start, suspend or resume an agent sandbox | `openshell-sandbox-stop`, `openshell-sandbox-start`, `openshell-sandbox-suspend`, `openshell-sandbox-resume` |
| Block an agent from reaching a host, while the agent keeps running | `openshell-egress-block-host` |
| Remove a network rule, endpoint or binary from the sandbox policy | `openshell-policy-rule-remove`, `openshell-policy-endpoint-remove`, `openshell-policy-binary-remove` |
| Stop an agent from receiving credentials | `openshell-provider-detach` |
| Investigate an agent | `openshell-sandbox-logs`, `openshell-policy-get`, `openshell-policy-history` |

## This pack includes

| Content | Name | Purpose |
| --- | --- | --- |
| Integration | NVIDIA OpenShell | Sandbox lifecycle, network policy, logs and credential providers |
| Playbook | NVIDIA OpenShell - Contain AI Agent Sandbox | Gets the sandbox state and recent logs, waits for analyst approval, stops the sandbox and verifies that it stopped |

## Requirements

- OpenShell gateway 0.1.6 or later.
- An engine that can reach the gateway. The gateway is usually private, so a cloud-hosted integration cannot reach it.
- Gateway mTLS credentials (`ca.crt`, `tls.crt`, `tls.key`) or an OIDC bearer token.

## Limitations

- The integration does not run commands inside a sandbox.
- `openshell-sandbox-suspend` requires a sandbox driver that supports suspend.
