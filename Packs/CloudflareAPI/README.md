# Cloudflare API

Integrates the Cloudflare API with the Cortex Platform, collecting Cloudflare account,
security, and Zero Trust Access activity into Cortex Platform datasets, mapping it to the XDM
data model, and detecting account-takeover and configuration-abuse scenarios with correlation
rules.

The pack follows a per-endpoint collector design: each Cloudflare API surface has its own event
collector and dataset, so log types can be modelled, retained, and correlated independently.

## Event collectors

| Collector | Source | Dataset |
| --- | --- | --- |
| Cloudflare Audit Logs Event Collector | `GET /accounts/{id}/audit_logs` (version 1 audit API) | `cloudflare_account_audit_raw` |
| Cloudflare Audit Logs V2 Event Collector | `GET /accounts/{id}/logs/audit` (version 2 audit API, including sign-ins) | `cloudflare_account_audit_v2_raw` |
| Cloudflare Security Insights Event Collector | `GET /accounts/{id}/security-center/insights` (Security Center findings) | `cloudflare_security_insights_raw` |
| Cloudflare Workers Event Collector | `GET /accounts/{id}/workers/scripts` (edge script inventory, bindings and served hostnames) | `cloudflare_workers_raw` |
| Cloudflare Access Authentication Logs Event Collector | `GET /accounts/{id}/access/logs/access_requests` (Zero Trust Access logins) | `cloudflare_access_auth_raw` |

Both audit collectors use rolling high-water-mark collection. The Security Insights and Workers
collectors take periodic snapshots of current state. The Access collector produces data only for
accounts that use Cloudflare Zero Trust Access.

### Why there are two audit collectors, and why you want both

Cloudflare exposes two audit APIs. They are not two versions of one feed: they return
**different records with different identifier schemes**, and no record appears in both.

| | Version 1, `/audit_logs` | Version 2, `/logs/audit` |
| --- | --- | --- |
| Sign-in events | **None** | **Yes**, as a `LOGIN` record |
| Actor identity and source IP on a sign-in | n/a | Email address and IP address |
| Record identifiers | Cloudflare's own id format | UUID, no overlap with version 1 |
| Pagination | `page` plus `per_page` | Opaque cursor; `page` is ignored and `per_page` has no effect |
| Bounds | `since` optional | `since` **and** `before` both required |

DNS record changes, certificate packs, and account and settings changes appear in both. Workers
script deploy, update and create appear only in version 1. Sign-in events and analytics queries
appear only in version 2.

**Each endpoint is the sole source of something the other never reports.** Version 1 is the only
place a Workers code deployment appears, which is the audit trail for who changed the code running
at the edge. Version 2 is the only place a sign-in appears, and is what lets this pack satisfy the
Cortex XDM authentication field set.

Neither is a superset of the other and neither is redundant, so configure both. An account running
only version 1 records no authentication at all; an account running only version 2 records no
Workers deployment.

## Detection content

The pack ships XDM modelling for the account audit and security insights datasets, and the
following correlation rules:

| Correlation | Detects | MITRE |
| --- | --- | --- |
| Cloudflare - API Token Created or Rolled | A new or rolled API token, a persistence vector after account compromise | TA0003 / T1098 |
| Cloudflare - Bulk DNS Record Deletion | An actor deleting many DNS records in a short window, a destructive or disruptive action | TA0040 / T1565 |
| Cloudflare - Security or Configuration Setting Changed | A change to a security or firewall setting | TA0005 / T1562 |
| Cloudflare - Security Posture Finding | A Security Center finding above an informational severity | Posture |

## Getting started

1. Create a Cloudflare **API Token** scoped to the account, with these permissions:
   **Account Settings - Read** (audit logs), **Account Security Center Insights - Read**
   (security insights), and **Access: Audit Logs - Read** (Access authentication logs).
2. Note your Cloudflare **Account ID**.
3. Configure an instance of each collector you want, providing the token and the account ID.
   Configure BOTH audit collectors: they return different records and neither replaces the other.
   See "Why there are two audit collectors" above.
4. Events land in the datasets listed above and are mapped to XDM automatically.

## Datasets

- `cloudflare_account_audit_raw`: one event per version 1 audit-log record, `_time` from the
  record time. Carries account and configuration activity, and no sign-in events.
- `cloudflare_account_audit_v2_raw`: one event per version 2 audit-log record. Carries the same
  classes of activity plus authentication, and is the dataset to query for sign-ins.
- `cloudflare_security_insights_raw`: current Security Center findings, snapshot per fetch.
- `cloudflare_access_auth_raw`: one event per Zero Trust Access authentication (if Access is in use).

- `cloudflare_workers_raw`: one event per Worker script per snapshot, with its bindings,
  the hostnames it serves and its logging configuration.

## Requirements

- A Cloudflare API Token with the permissions listed above. The endpoints are read-only.

## Licence

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
Copyright (c) GoCortexIO.

## About GoCortex

Independent tools, projects, and ideas to complement and extend the Palo Alto Networks Cortex
ecosystem.

[gocortex.io](https://gocortex.io)

## Version History (Managed by GoCortex Spellbook)

<!-- spellbook:version-history:start -->
### 2.2.10

- Point Worker attribution at the data that holds it, and stop dropping a severity tier. Both Worker rules told the responder to check who deployed the script via a field the modelling rule documents as the deployment channel, so it renders as dashboard, api or wrangler and never as a person. The Worker inventory carries no deploying identity at all, so the alerts now say what the field is and send attribution to the account audit log, where a script deploy does name the actor. The Security Center rule promised findings above informational while its filter admitted only Medium and above, leaving the Low tier unevaluated and indistinguishable from having no findings.

### 2.2.9

- Apply the upstream formatter output, so the committed source matches what the contribution pipeline produces and a submission is not failed for a purely cosmetic difference.

### 2.2.8

- Extend the pack description to name the endpoint families it now covers and the detections it ships. It still described the single audit log collector the pack started with.
- Stop the unit tests leaking a collector error message to stdout, which the demisto-sdk harness treats as a failure. The collector still logs the error at runtime; only the tests suppress it.

### 2.2.7

- Settled why the pack ships two audit collectors, with the measurement behind it. Each endpoint is the sole source of something the other never reports: version 1 is the only place a Workers code deployment appears, and version 2 is the only place a sign-in appears. Neither is a superset of the other, so both are required.
- Replaced the earlier note suggesting version 2 might eventually replace version 1. Measured over an identical fortnight, 32 Workers deploy, update and create records appear only in version 1 and have no version 2 counterpart, so retiring it would have silently removed the audit trail for changes to edge code.

### 2.2.6

- Detects repeated failed sign-ins to the Cloudflare account by one identity, the shape of password guessing or credential stuffing against the control plane for DNS, certificates and edge code. This is the pack's first authentication detection, made possible by the version 2 audit dataset.
- The alert carries the distinct source addresses, the sign-in channel and the first and last attempt times, and directs the analyst to check whether any sign-in for the same identity succeeded in the window, since failures followed by a success is the shape of a completed brute force.
- Search window and schedule are set from a measured ingestion lag of five minutes from sign-in to dataset, rather than an assumed one.

### 2.2.5

- Added the pack's first authentication correlation, detecting repeated failed sign-ins to the Cloudflare account by one identity. This release ships the rule with a reduced query; the full aggregation follows in 2.2.6.

### 2.2.4

- Recorded the measured ingestion lag from sign-in to dataset, so correlation search windows are set from a real figure rather than an assumed one.

### 2.2.3

- Documented why the pack ships two audit collectors and why both are needed. Cloudflare exposes two audit APIs that return different records with different identifier schemes, and no record appears in both. Only the version 2 API reports sign-ins, and only the version 1 dataset feeds the pack's existing DNS and configuration correlations.
- Added a comparison of the two endpoints covering sign-in coverage, identifier schemes, pagination and required bounds, so the difference is visible before an operator decides which to configure.
- The getting-started steps now state explicitly that both audit collectors should be configured.

### 2.2.2

- Documented the version 1 audit rule's authentication branch as dormant by design. That endpoint carries no sign-in events, so the branch has never matched a record, and its presence should not be read as evidence that authentication is captured. Authentication is served by the version 2 dataset.

### 2.2.1

- Added a modelling rule for the `cloudflare_account_audit_v2_raw` dataset, classified per record: a sign-in maps as an authentication event and everything else as a cloud audit event, with no record dropped.
- A `LOGIN` record now satisfies the complete Cortex XDM authentication field set, carrying the identity as a UPN, the real source IP address, the outcome, and the sign-in channel (dashboard or API) as the authentication service. This is the first Cloudflare source in the pack able to do so.
- The sign-in is identified by the event description rather than the action type. In this source the action type is a coarse verb and a login carries `update`, so a rule keyed on the action type never matches. The version 1 modelling rule keys on the action type, which is why its authentication branch has never produced a row.
- The source IP address is taken from the record and never padded, so an authentication detection has a real address to correlate on.

### 2.2.0

- Added an event collector for Cloudflare's version 2 audit API, ingesting it into the `cloudflare_account_audit_v2_raw` dataset. This is the only Cloudflare source that reports dashboard sign-ins, so it is what makes authentication detection possible for this pack.
- Cloudflare exposes two audit APIs that return different records with different identifiers. Measured over an identical fortnight, the version 1 endpoint returned 235 records containing no sign-in of any kind, while version 2 returned 244 including `LOGIN` events. An account can therefore appear fully audited while every login goes unrecorded, which is why both collectors are needed and neither replaces the other.
- A `LOGIN` record carries the actor's email address, source IP address and outcome, which is the field set an authentication detection needs.
- The endpoint requires both a start and an end bound on every request, and it ignores page numbers: requesting page 1, 2 or 3 returns the identical records. Paging is by an opaque cursor, which the collector follows until exhausted. A page loop would re-send the same events indefinitely.
- Collected as a time series with a rolling high-water mark, so a sign-in is read once. Event time comes from the audit record rather than ingest time.

### 2.1.5

- Added a source reference block to the top of the query in all 7 correlation rules. Each rule now cites up to three references that informed its design, typically the MITRE ATT&CK technique page and the vendor documentation for the mechanism being detected. A detection is a security claim, so the reasoning behind it should be traceable by whoever tunes the rule later. Every URL was checked before publication.

### 2.1.4

- Detects a Worker answering on a sign-in or identity provider lookalike hostname. A Worker runs code at the edge in front of a hostname, so this pattern can serve a credential harvesting page from infrastructure the organisation owns, which defeats domain reputation checks. The hostname patterns are generic (sign-in, SSO and the common identity providers) rather than tied to any tenant's names.
- Detects a Worker whose hostname labels use command and control or malware vocabulary. This is either live abuse of the account or offensive test infrastructure left publicly reachable, and the alert asks the analyst to establish which.
- Detects a Worker that holds a secret binding while observability is switched off, so code with access to credential material runs with no execution trail. The exposure is the combination, not either half, which is why neither condition alerts on its own.
- All three rules read the newest snapshot per Worker and suppress on the script identity, so an inventory finding raises one alert rather than one per collection cycle.

### 2.1.3

- Completed the `cloudflare_workers_raw` mapping. Each Worker is modelled as a cloud resource: the script name is the resource identity, the hostnames it answers on become the target hostname, and the owning DNS zones become the resource parent.
- Carried the binding facts into `xdm.target.resource.value` as a marker set. Raw columns cannot be read in `datamodel` mode, so a correlation that needs to know a Worker holds a secret binding, has observability switched off, registers a scheduled handler, or serves a public hostname can only do so if that fact is mapped at ingest.
- Each marker restates something the Cloudflare API reports. None of them asserts a severity or an intent, which stays with the correlation rules.
- Mapped the deployment channel (`last_deployed_from`) so a Worker deployed through the dashboard can be told apart from one deployed through the API or a pipeline.
- Mapped the deployed code version from `etag`, so a change to a Worker's code is visible in the data model.

### 2.1.2

- Completed the `cloudflare_workers_raw` mapping. Each Worker is modelled as a cloud resource: the script name is the resource identity, the hostnames it answers on become the target hostname, and the owning DNS zones become the resource parent.
- Carried the binding facts into `xdm.target.resource.value` as a marker set. Raw columns cannot be read in `datamodel` mode, so a correlation that needs to know a Worker holds a secret binding, has observability switched off, registers a scheduled handler, or serves a public hostname can only do so if that fact is mapped at ingest.
- Each marker restates something the Cloudflare API reports. None of them asserts a severity or an intent, which stays with the correlation rules.
- Mapped the deployment channel (`last_deployed_from`) so a Worker deployed through the dashboard can be told apart from one deployed through the API or a pipeline.

### 2.1.1

- Added the `cloudflare_workers_raw` dataset to the modelling rule, so the Workers script inventory is reachable through the Cortex XDM data model. This release maps the script identity only; the full mapping follows in 2.1.2.

### 2.1.0

- Added an event collector for the Cloudflare Workers script inventory, ingesting it into the `cloudflare_workers_raw` dataset as a full snapshot per run. A Worker is code running on Cloudflare's edge in front of a hostname, so the inventory answers what is deployed, what it can reach, and which hostname it serves. The account audit log already reports that a script changed, but not what exists now, which is what makes a change assessable.
- Collected each script's bindings, which are how a Worker reaches a secret, a KV namespace, an R2 bucket, a D1 database, a queue or another service, and flattened them into columns so a correlation can filter on them without parsing. Binding types and names are collected; binding values are not.
- Joined the hostname to script mapping onto each record, so a script is reported alongside the hostnames it answers on.
- The scripts endpoint accepts pagination parameters and ignores them, returning the full list regardless, so it is requested once per account rather than paged.

### 2.0.6

- Isolated a failing account so it can no longer discard the collection cursor of every other account. Previously an error on one account aborted the whole fetch before the cursors were saved, which made every configured account re-read its entire window on the next run. A failing account now keeps its own cursor untouched and the remaining accounts continue.
- Applied the same per-account isolation, so one failing account cannot cause repeated re-collection across the others.

### 2.0.5

- Stamped each collected finding with the collection time, so successive snapshots of the same finding can be told apart from a genuine change. This brings the collector into line with every other snapshot collector in the GoCortexIO packs.
- Added a unit test suite covering the collection and stamping behaviour, the preference for the finding timestamp over the collection time, the page size the insights endpoint requires, pagination limits and multi-account tagging.

### 2.0.4

- Maintenance release. Republishes the bulk DNS record deletion rule so tenants pick up the detection changes introduced in 2.0.3, in which the rule was scoped to human and API-token actors, switched to counting distinct records, grouped by DNS zone, and extended to carry the affected zone, deleted record identifiers, deletion time window and actor source IP address into the alert.

### 2.0.3

- Excluded Cloudflare's own system actor from the rule. Cloudflare deletes and recreates DNS records routinely during zone synchronisation, which raised alerts for activity that was not attributable to any person or credential. The rule now alerts only on deletions performed by a human or API-token actor.
- Counted distinct DNS records rather than audit events. Repeated deletions of the same record previously inflated the count, so the reported figure now reflects how many records were actually removed.
- Grouped the rule by DNS zone, so deletions in unrelated zones no longer merge into a single alert.
- Added the affected zone, the deleted record identifiers, the deletion time window, the actor's source IP address and the raw event count to the alert output, so the alert is actionable without a manual query.
- Added a drilldown query that pivots from the alert to the underlying audit events for the affected zone.

### 2.0.2

- Added a rule-level description to every correlation rule, so the intent of each detection is clear in the rule list and in generated alerts.
- Aligned the correlation rule file names with the marketplace naming convention (each file now begins with the pack folder name).

### 2.0.1

- Standardised the integration logos to the uniform GoCortexIO house style (dark navy text on a transparent background, consistent size across all collectors). No functional changes.

### 2.0.0

- **Cloudflare Audit Logs Event Collector** collects account and configuration activity from
- **Cloudflare Security Insights Event Collector** collects Security Center findings into the
- **Cloudflare Access Authentication Logs Event Collector** collects Zero Trust Access
- Added the **Cloudflare API Modeling Rule**, which maps the account audit and security insights
- **Cloudflare - API Token Created or Rolled** alerts on a new or rolled API token, a
- **Cloudflare - Bulk DNS Record Deletion** alerts when an actor deletes many DNS records in a
- **Cloudflare - Security or Configuration Setting Changed** alerts on a change to a security or
- **Cloudflare - Security Posture Finding** alerts on a Security Center finding above an

<!-- spellbook:version-history:end -->
