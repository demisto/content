## Imperva Incapsula Community Event Collector

**This is a community-maintained integration. It is not developed, reviewed, or supported by Imperva or
Palo Alto Networks.** Validate it thoroughly against your own tenant before relying on it in production.

This integration is for Imperva Cloud WAF (Incapsula) accounts whose **SIEM Logs → Log Configuration**
connection type is **Imperva API** — the short-term log buffer served from
`https://logs<N>.incapsula.com/<account>_<id>/`. If your account's connection type is **Amazon S3**,
use the native ingestion path documented in the `Imperva Incapsula` pack instead; this integration does
not apply to that connection type.

### Get your Logs URL, API ID, and API Key

1. In the Imperva Cloud WAF console, go to **SIEM Logs → Log Configuration** and confirm the connection
   type is Imperva API.
2. Copy the **Logs URL** shown there (for example `https://logs1.incapsula.com/123456_456789/`).
3. Get the **API ID** and **API Key** from your account's API settings page.

### If log encryption is enabled

Some accounts encrypt the log buffer. If yours does, you will also need:
- The **RSA private key** (PEM) that corresponds to the public key you registered with Imperva for log
  encryption.
- The numeric **Public Key ID** Imperva assigns to that key (visible in the log file headers as
  `publicKeyId:`).

Leave both fields blank if your account does not use log encryption.