# Grafana Cloud

Integrates the Grafana API with the Cortex Platform, collecting the identity, credential and
connection inventory from a Grafana instance into Cortex Platform datasets, mapping it to the XDM
data model, and detecting credential-hygiene and configuration-abuse scenarios with correlation
rules.

The collectors read the Grafana **instance** HTTP API, which is the same on Grafana Cloud,
Grafana Enterprise and Grafana OSS. The pack follows a per-endpoint collector design: each API
surface has its own event collector and dataset, so log types can be modelled, retained and
correlated independently.

## Event collectors

| Collector | Source | Dataset |
| --- | --- | --- |
| Grafana Cloud Service Accounts Event Collector | `GET /api/serviceaccounts/search` plus `/{id}/tokens` (machine credentials) | `grafana_service_accounts_raw` |
| Grafana Cloud Data Sources Event Collector | `GET /api/datasources` (backend connections) | `grafana_datasources_raw` |
| Grafana Cloud Organisation Users Event Collector | `GET /api/org/users` (human identities) | `grafana_org_users_raw` |

All three are snapshot collectors. There is no event stream behind them, only current state, so
each re-sends its full inventory on every run. Duplicate rows across runs are expected and
correct, because comparing successive snapshots is what makes a change detectable.

### What this pack does not cover, and why

**The Grafana instance API has no audit log and no sign-in event stream.** Every read endpoint it
exposes describes current state rather than a history of actions. That is a property of the API,
not a gap in this pack, and it shapes everything above: there is no "who changed this and when"
to collect, so change is detected by comparing snapshots instead.

Sessions are the nearest thing to authentication the API offers, through
`GET /api/admin/users/{id}/auth-tokens`, and they are deliberately not collected. That endpoint
needs the `users:read` and `users.authtoken:read` permissions, which is a real privilege increase
on the token for what is still only inventory: a sign-in that ends between two polls is never
visible. Grafana Cloud audit logs, where enabled, are delivered into a Loki data source rather
than through this API.

## Getting started

1. In Grafana, go to **Administration > Users and access > Service accounts** and add a service
   account with the **Admin** role in the organisation you want to collect.
2. Add a service account token to it and copy the `glsa_` value. Grafana replaced standalone API
   keys with service account tokens, so a legacy API key will not work.
3. Note your Grafana instance URL, the `https://your-stack.grafana.net` form.
4. Configure an instance of each collector you want, providing the URL and the token.
5. Records land in the datasets listed above and are mapped to XDM automatically.

## Datasets

- `grafana_service_accounts_raw`: one record per service account per snapshot, with its role,
  external and disabled state, and a summary of its tokens including how many never expire.
- `grafana_datasources_raw`: one record per data source per snapshot, with its type, access mode,
  URL and authentication shape.
- `grafana_org_users_raw`: one record per organisation member per snapshot, with role, identity
  provider labels and last-seen time.

## Requirements

- A Grafana service account token with the Admin role, or a custom role carrying
  `serviceaccounts:read`, `datasources:read` and `org.users:read`. All endpoints are read-only.

No credential material is ever collected. Service account token secrets are not returned by the
Grafana API, and data source credentials live in `secureJsonData`, which the list endpoint omits.

## Licence

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
Copyright (c) GoCortexIO.

## About GoCortex

Independent tools, projects, and ideas to complement and extend the Palo Alto Networks Cortex
ecosystem.

[gocortex.io](https://gocortex.io)

## Version History (Managed by GoCortex Spellbook)

<!-- spellbook:version-history:start -->
### 1.0.12

- Apply the upstream formatter output, so the committed source matches what the contribution pipeline produces and a submission is not failed for a purely cosmetic difference.

### 1.0.11

- Replace the scaffold default pack description with one that names what is collected, what is mapped into the Cortex XDM data model, and what the pack detects.

### 1.0.10

- Detects a Grafana service account newly appearing in the inventory while holding a token that never expires. Service accounts are Grafana's machine-credential surface, and a token with no expiry is a permanent way back in, so one created outside the normal review cycle is worth confirming.
- The Grafana instance API publishes no audit log, so novelty is inferred by comparing successive inventory snapshots rather than read from a creation event. The alert says so, and reports when the account first became visible to collection rather than when it was created.
- Expect one alert per existing account on the first collection, because on a first run every object is new and no query can tell that apart from genuine novelty. The rule settles within the three hour age threshold and is quiet afterwards.

### 1.0.9

- Added modelling rules for all three datasets, so the Grafana inventory is queryable through the Cortex XDM data model rather than only as raw columns. Verified on the tenant: row parity between raw and `datamodel` on all three, with no unmodelled records.
- Each object is modelled as a cloud resource with its identity, and the posture facts are carried into `xdm.target.resource.value` as a marker set. Raw columns cannot be read in `datamodel` mode, so a correlation that needs to know a token has no expiry, a data source stores a credential, or an account is externally provisioned can only do so if that fact is mapped at ingest.
- Each marker restates something the Grafana API reports. None asserts a severity or an intent, which stays with the correlation rules.
- The authentication story is deliberately not mapped on any of the three. The Grafana instance API exposes no sign-in events, so there is no logon, session or source address to map, and an authentication story here would be an invention. Each rule header states this so the omission is not later read as an oversight.

<!-- spellbook:version-history:end -->
