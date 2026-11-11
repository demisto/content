# Haseen Threat Intel

Fetches indicators of compromise from a STIX 2.x threat-intelligence feed and parses them into Cortex XSOAR indicators.

## Authentication

Requires a **minimum role of Analyst** (and an account with access granted to the Haseen Threat Intelligence portal) to obtain the API token.

Per the Haseen API Integration Guide, authentication is:

1. **Token-based** — a `token` is sent as a URL query parameter on every request:
   `https://share.haseen.gov.sa/api/v1/threat-intelligence/export/{exportID}?token=<token>`
2. **Basic authentication** (optional) — for specific exports that require it in
   addition to the token. Username is the account email; password is the API token
   (found on the settings page).

## Rate limits

Haseen permits **2 requests per hour per export type**. Exceeding this returns a
`429` (`Request was throttled. Expected available in 3588 seconds`). Configure the
**Feed Fetch Interval** to 60 minutes or higher to stay within the limit.

## Feed specifics

This is a **full-dump** STIX 2.x endpoint — it returns the entire bundle on every
request rather than a `modified_after` delta. The integration parses the bundle
and relies on the Cortex XSOAR feed engine to deduplicate and merge indicators, applying
the configured **Tags**, **Reputation**, **Source Reliability**, **TLP Color**, and
**Bypass exclusion list** settings.
