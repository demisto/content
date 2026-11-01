# RelayShield

Real-time identity-compromise and agent-security threat intelligence for Cortex.

## What does this pack do?

- **Generic reputation commands** (`domain`, `ip`, `email`) are auto-invoked by any
  existing enrichment playbook that calls generic reputation commands. No playbook
  changes are needed to pick up RelayShield as an additional source.
- **`relayshield-mcp-registry-risk`** checks an MCP server URL or package name for
  typosquat/supply-chain/registry risk before an agent connects to it.
- **`relayshield-cert-expiry`** reports TLS certificate expiry risk for a domain.
- **`relayshield-supply-chain`** reports combined breach/infostealer risk across up to
  10 vendor domains or emails in one call.

## Setup

1. Get an API key at [api.relayshield.net/developers](https://api.relayshield.net/developers)
   (self-serve, pay-as-you-go, no subscription required).
2. Configure a new RelayShield instance in Cortex with the key as the integration credential.
3. Run **Test** to confirm connectivity.

## DBotScore mapping

A clean ("no known finding") result maps to DBotScore **Unknown (0)**, not **Good (1)**.
"No known finding" means nothing was flagged in the sources RelayShield actually
queried. It is not a verified-safe claim. CRITICAL/HIGH findings map to **Bad (3)** and
MEDIUM/LOW findings map to **Suspicious (2)**.

| RelayShield result | DBotScore |
| --- | --- |
| CRITICAL | 3 (Bad) |
| HIGH | 3 (Bad) |
| MEDIUM | 2 (Suspicious) |
| LOW | 2 (Suspicious) |
| No known finding | 0 (Unknown) |

Because a clean result is never scored **Good (1)**, RelayShield does not contribute a
"clean" vote to a Cortex playbook's aggregate "all sources clean, auto-close" logic.
Only a genuine finding moves the needle.

## Support

Community-supported. Questions and issues: support@relayshield.net or
[api.relayshield.net/developers](https://api.relayshield.net/developers).
