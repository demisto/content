## RelayShield

To use this integration you need a RelayShield API key. RelayShield authenticates every
request with a single API key sent in the `X-RS-API-KEY` header. There are no OAuth flows,
tenant IDs, or additional permissions to grant.

### Get your API key

1. Go to [api.relayshield.net/developers](https://api.relayshield.net/developers).
2. Enter the email address the key should be issued to and submit the signup form.
3. Complete the self-serve signup. Pay-as-you-go is available with no subscription or
   monthly minimum.
4. Copy the API key from the confirmation page. It begins with `rs_live_`. The key is also
   emailed to the address you entered.

### Configure the integration instance in Cortex

1. Leave **Server URL** at `https://api.relayshield.net` unless you have been given a
   dedicated endpoint.
2. Paste the key from step 4 above into the **API Key** field.
3. Click **Test** to verify the connection. The test performs a single live domain lookup
   against your key.

### Required permissions

The API key must be entitled to the endpoints backing the commands you intend to run:

| Command | Endpoint |
| --- | --- |
| `domain` | `/v1/metered/domain` |
| `ip` | `/v1/metered/ip-intel` |
| `email` | `/v1/metered/breach`, `/v1/metered/session-risk` |
| `relayshield-mcp-registry-risk` | `/v1/metered/mcp-registry-risk` |
| `relayshield-cert-expiry` | `/v1/metered/cert-expiry` |
| `relayshield-supply-chain` | `/v1/metered/supply-chain` |

Self-serve pay-as-you-go keys are entitled to all six by default.

### DBotScore mapping

A clean result ("no known finding") is mapped to DBotScore **Unknown (0)**, never
**Good (1)**. "No known finding" means nothing was flagged in the sources RelayShield
actually queried. It is not a verified-safe guarantee, and treating it as "Good" would
claim more certainty than the underlying data supports. CRITICAL/HIGH findings map to
**Bad (3)**, MEDIUM/LOW findings map to **Suspicious (2)**.

This means RelayShield does not contribute a "clean" vote to a Cortex playbook's aggregate
"all sources clean, auto-close" logic. Only a genuine finding moves the needle.

### Troubleshooting

- **Test fails with an authorization error.** Confirm the key was copied in full and begins
  with `rs_live_`. Keys are deactivated when the underlying subscription is cancelled.
- **Test fails with a connection or timeout error.** Confirm the Cortex engine can reach
  `https://api.relayshield.net` over HTTPS on port 443. If outbound traffic is proxied,
  enable **Use system proxy settings**.
- **A command returns "no known finding" for an indicator you expect to be flagged.**
  This is a clean result, not an error. RelayShield reports only on sources it queried;
  see the DBotScore mapping above.
- **A command fails with a quota or payment error.** Check the balance and entitlements on
  your account at [api.relayshield.net/developers](https://api.relayshield.net/developers).

For anything else, contact [support@relayshield.net](mailto:support@relayshield.net).
