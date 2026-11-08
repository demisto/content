# KELA Identity Guard

This pack integrates [KELA Identity Guard](https://www.kelacyber.com/platform/identity-guard/) with Cortex.

Identity Guard monitors for compromised credentials and identities belonging to your organization,
detected across infostealer-infected machines ("bots"), leaked credential lists, data breaches,
cybercrime chatter, bot-marketplace listings and compromised session cookies. It is organized around
**workspaces**, each configured with the assets it monitors.

This pack covers the three Identity Guard "search" endpoints that return incident-like data:

- **General incidents** (`search-incidents`) - compromised credentials/identities.
- **Bot-market alerts** (`search-bot-markets`) - bots/webmails offered for sale on marketplaces.
- **Cookie incidents** (`search-cookie-incidents`) - compromised session cookies.

## What does this pack do?

- Automatically fetch new/unresolved incidents from all three sources into Cortex
  (fetch-incidents), each independently toggleable in the instance configuration.
- Set how far back the very first fetch looks (the "First fetch time" instance parameter).
- Search and filter each of the three sources on demand with dedicated commands.

## Configure KELA Identity Guard in Cortex

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for **KELA Identity Guard**.
3. Click **Add instance** and set the required parameters:
   - Server URL and API Key.
   - Default Workspace ID (required for fetch-incidents; optional for manual commands, which can
     override it per call - useful for MSSP accounts).
   - Fetch incidents, Incident type, Maximum number of incidents per fetch (applied per source),
     First fetch time, Minimum severity to fetch.
   - Fetch bot-market alerts / Fetch compromised session-cookie incidents - uncheck either to
     exclude that source from the automatic fetch (the manual search commands stay available
     either way).
4. Click **Test** to validate the connection.

Note: the interval between fetch cycles is set with the instance's "Incidents Fetch Interval"
setting (in minutes, default 1).

## API reference

This pack's client (`KELAIdentityGuard.py`) targets the `bots-client-api` v1 REST API
(`https://api.ke-la.com/bots-client-api/v1`), confirmed against KELA's official OpenAPI 3.1 spec
(`kela-api-IdentityGuard.yaml`) and smoke-tested against the live API. Authentication is a
query-string parameter (`apiToken`), not a header.

Only the three "search" endpoints are implemented. The spec also documents write/management
endpoints (editing incidents, updating bot status, managing MSSP tenants and workspace
configuration) that are intentionally out of scope for this pack.
