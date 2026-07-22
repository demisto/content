# RelayShield

Real-time identity-compromise and agent-security threat intelligence for Cortex XSOAR.

## What's included

- **Generic reputation commands** (`domain`, `ip`, `email`) — auto-invoked by any
  existing enrichment playbook that calls generic reputation commands. No playbook
  changes needed to pick up RelayShield as an additional source.
- **`relayshield-mcp-registry-risk`** — typosquat/supply-chain/registry risk check for
  an MCP server URL or package name, before an agent connects to it.
- **`relayshield-cert-expiry`** — TLS certificate expiry risk for a domain.
- **`relayshield-supply-chain`** — combined breach/infostealer risk across up to 10
  vendor domains or emails in one call.

## Setup

1. Get an API key at [api.relayshield.net/developers](https://api.relayshield.net/developers)
   (self-serve, pay-as-you-go, no subscription required).
2. Configure a new RelayShield instance in XSOAR with the key as the integration credential.
3. Run **Test** to confirm connectivity.

## DBotScore philosophy

A clean ("no known finding") result maps to DBotScore **Unknown (0)**, not **Good (1)**.
"No known finding" means nothing was flagged in the sources RelayShield actually
queried — it is not a verified-safe claim. See `RelayShield_description.md` for the
full mapping and rationale.

## Support

Community-supported. Questions and issues: support@relayshield.net or
[api.relayshield.net/developers](https://api.relayshield.net/developers).
