## RelayShield

Real-time identity-compromise and agent-security threat intelligence. Implements the
generic `domain`/`ip`/`email` reputation commands — these are automatically invoked by
any existing enrichment playbook that calls generic reputation commands, with no
playbook changes needed — plus three RelayShield-specific commands: MCP server registry
risk, certificate expiry, and supply-chain vendor risk.

### Get your API key

Sign up at [api.relayshield.net/developers](https://api.relayshield.net/developers) —
self-serve, pay-as-you-go, no subscription or monthly minimum required to start.

### DBotScore mapping

A clean result ("no known finding") is mapped to DBotScore **Unknown (0)**, never
**Good (1)**. "No known finding" means nothing was flagged in the sources RelayShield
actually queried — it is not a verified-safe guarantee, and treating it as "Good" would
claim more certainty than the underlying data supports. CRITICAL/HIGH findings map to
**Bad (3)**, MEDIUM/LOW findings map to **Suspicious (2)**.

This means RelayShield does not contribute a "clean" vote to a playbook's aggregate
"all sources clean, auto-close" logic — only a genuine finding moves the needle.
