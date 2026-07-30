# Portkey API

Integrates the Portkey API with the Cortex Platform, collecting Portkey control-plane
activity into Cortex Platform datasets and mapping it to the XDM data model.

## What this pack ships

| Content | Purpose |
| --- | --- |
| Portkey Audit Logs Event Collector | Admin API audit logs from `GET /audit-logs` into `portkey_audit_raw`, high-water-mark collection. |
| Portkey API Keys Event Collector | API key inventory from `GET /api-keys` into `portkey_api_keys_raw`, full snapshot per run. |
| Portkey Workspaces Event Collector | Workspace security posture from `GET /admin/workspaces` into `portkey_workspaces_raw`, full snapshot per run. |
| Portkey Configs Event Collector | Gateway config inventory from `GET /configs` into `portkey_configs_raw`, full snapshot per run. |
| Portkey LLM Request Logs Event Collector | Gateway request logs, including prompt, completion, model, tokens and cost, into `portkey_llm_requests_raw` via the asynchronous log export. |
| Portkey API Modeling Rule | Maps the collected datasets to the Cortex XDM data model. |
| Correlation rules | Seven detections covering API key hygiene, workspace permission posture, config ownership and new key creation. |

The pack follows a per-endpoint collector design: each Portkey API endpoint family gets its own
thin event collector and its own dataset, so log types can be modelled, retained, and correlated
independently.

The audit collector answers what changed and when. The inventory collectors answer what the
current configuration actually permits, which is what turns an audit alert into an assessable
one: a key created is routine, a key created with no expiry and the ability to create further
keys is not.

## Getting started

1. Create an **organisation-scoped Portkey admin API key**. Audit logs are a Portkey Enterprise
   feature. Grant the scopes for the collectors you intend to run:
   - Audit logs: `audit_logs.list`
   - API keys: `organisation_service_api_keys.list`, `workspace_service_api_keys.list`,
     `workspace_user_api_keys.list`
   - Workspaces: `workspaces.list`, `workspaces.read`
   - Configs: `configs.list`
   - LLM request logs: `logs.list`, `logs.view`, `logs.export`
2. Configure an instance of each collector with the key. The organisation is implied by the key,
   so no organisation ID is required.
3. Events land in the datasets below.

## Datasets

- `portkey_audit_raw`: one event per audit-log record, `_time` from the record `timestamp`.
- `portkey_api_keys_raw`: one event per API key per snapshot, with `scope_count`,
  `rate_limit_count`, `has_usage_limit` and `has_expiry` flattened for querying.
- `portkey_workspaces_raw`: one event per workspace per snapshot, with the `security_settings`
  permission model flattened to top-level boolean columns.
- `portkey_configs_raw`: one event per gateway config per snapshot, with its owner, last editor
  and status.
- `portkey_llm_requests_raw`: one event per gateway request, with the model and provider, the
  prompt and completion, token usage, cost, latency and upstream status.

## Detection content

| Rule | What it catches |
| --- | --- |
| API Key Without Expiry | A credential that stays valid until somebody revokes it by hand. |
| API Key Able to Manage API Keys | A key that can mint or delete further keys. |
| API Key Without Spend or Rate Limit | Uncapped model spend and request volume. |
| Workspace Lets Members Create API Keys | Ordinary members can issue gateway credentials. |
| Workspace Guardrails Writable By Members | Members can weaken the prompt and response controls. |
| Gateway Config Changed By Non Owner | Routing or guardrail changes made by an unexpected editor. |
| New API Key Created | A key issued outside the normal process, with actor and source address. |

The posture rules read snapshot datasets, which re-send the full inventory on every poll, so each
rule takes only the newest snapshot per object. A finding therefore raises one alert rather than
one per collection cycle.

## About GoCortex

Independent tools, projects, and ideas to complement and extend the Palo Alto Networks Cortex
ecosystem.

[gocortex.io](https://gocortex.io)

## Version History (Managed by GoCortex Spellbook)

<!-- spellbook:version-history:start -->
### 1.9.6

- Report how much traffic the guardrail actually evaluates, so a control that is mostly not running is visible as posture and a fall in coverage is visible as an alert.

### 1.9.5

- Treat a blank audit action as absent rather than letting the empty string become the event identity, and name those records from the method and resource the vendor does supply.

### 1.9.4

- Extend the pack description to name every endpoint family it now covers and the detections it ships. It still described the single audit log collector the pack started with.
- Stop the unit tests leaking a collector error message to stdout, which the demisto-sdk harness treats as a failure. The collector still logs the error at runtime; only the tests suppress it.

### 1.9.3

- Added a source reference block to the top of the query in all 15 correlation rules. Each rule now cites up to three references that informed its design, typically the MITRE ATT&CK technique page and the vendor documentation for the mechanism being detected. A detection is a security claim, so the reasoning behind it should be traceable by whoever tunes the rule later. Every URL was checked before publication.

### 1.9.2

- Set the search window to two hours, following validation against twelve hours of recorded traffic. The window comfortably exceeds the ten minute schedule plus the collection and export lag, so an event near a boundary cannot be missed.

### 1.9.1

- Collected Portkey's own guardrail results for each request, flattening the verdict, the deny decision, the flagged categories, the checks that ran and the highest scoring moderation category into queryable fields. Portkey records these under two levels of nested array, which the data model cannot traverse, so the flattening is done during collection.
- Removed the prompt classification from the modelling rule. The rule previously asserted a set of injection technique families that GoCortexIO had defined, which is not something the source reports. A modelling rule should describe what the vendor reports, so the classification has moved to the correlation rules where the detection logic belongs and can be revised without redeploying the model.
- Mapped Portkey's guardrail verdict instead, which is the authoritative classification for a request: the gateway's decision is carried on the observer action, the flagged categories on the event outcome reason, and the checks that ran on the observer name.
- Mapped the user's prompt to the target resource value, so a correlation can match against the content. Data model queries cannot read raw dataset columns, so content a correlation needs must be carried into a data model field.
- Detects a request that Portkey's own guardrails denied or flagged, which carries more weight than any inference drawn from the prompt text.
- Moved the technique matching out of the modelling rule and into each correlation, against the mapped prompt. The families and phrasings are unchanged, so the measured precision is unchanged; only the layer they are evaluated at has moved.

### 1.9.0

- Detects a prompt containing the control tokens a model uses to separate system, user and assistant turns. A user has no legitimate reason to send them, so this is among the highest confidence indications of an attempt to forge a turn boundary.
- Detects a prompt that revokes the model's operating instructions or substitutes an unrestricted persona.
- Detects instructions arriving inside tool output rather than typed by a person, the path in which retrieved or third-party content carries the attack and the user may be unaware of it.
- Detects a prompt seeking the model's own instructions or context, including requests to re-encode the material so it is not returned literally.
- Detects a prompt casting the model as a terminal or command runner, claiming an authority that permits disclosure, or dictating the opening words of the reply to steer it past a refusal.
- Detects a prompt matching a known injection technique that the model then answered successfully, separating an attempt that was refused or blocked upstream from one that reached the model and produced output.
- Detects one identity making repeated attempts across several technique families in a short window, which distinguishes deliberate probing from a single opportunistic prompt. The techniques attempted and the time span are included so the progression can be read from the alert.
- Extended the prompt-injection classification to ten technique families, adding indirect injection through tool content, and covering XML style turn tags, initialisation-material extraction, command interpreter impersonation and further instruction override phrasings.
- Re-measured at scale against 751 live requests covering 272 distinct prompts. Forty two distinct attacks matched with no false positive against the benign traffic, which includes customer questions about passwords and account recovery.

### 1.8.1

- Isolated the user-authored text of each request into its own field, so prompt-injection classification sees the user's input alone.
- Corrected the prompt-injection classification to match only the user's input. It previously matched the whole request object, which includes the system prompt. A system prompt legitimately contains the vocabulary an attack uses, so an application whose own instructions mention base64 or classified material had every one of its requests marked suspicious. Observed against live traffic before release.

### 1.8.0

- Added modelling for the LLM request dataset, mapping the model and provider called, the user, the upstream destination and status, the outcome and the token and cost figures to the Cortex XDM data model.
- Added prompt-injection classification at ingest. Each request is matched against the publicly documented injection technique families, and the families that match are recorded on the event so a correlation can filter them without re-reading the prompt. Classifying once during modelling avoids every rule scanning a payload of twenty kilobytes or more.
- The families covered are control-token injection, instruction override, persona jailbreak, system-prompt extraction, encoded exfiltration, authority pretexting, reply-prefix injection, tool impersonation and delimiter spoofing. Measured against live traffic, thirty-five of forty-four attack prompts matched with no false positives across the benign requests.
- Fiction framing, sentence completion and non-English requests are deliberately left unclassified, because pattern matching cannot separate them from legitimate use. Homoglyph substitution evades matching by design. The classification narrows the field for an analyst, it does not replace a guardrail.

### 1.7.0

- Added an event collector for Portkey gateway request logs, ingesting them into the `portkey_llm_requests_raw` dataset. Each event carries the model and provider the request was routed to, the prompt and completion, token usage, cost, latency and the upstream status, which is the telemetry needed to detect misuse of the models themselves rather than of the configuration around them.
- Portkey offers no endpoint that lists request logs, so the collector drives the asynchronous log export: it creates an export for a time window, starts it, polls it on later runs and ingests the result once it completes. An export takes longer than a collection run should wait for, so the job is carried across runs and its runtime affects collection latency only.
- Collection is driven by a watermark rather than by the collection interval, and the watermark advances only once the data has been downloaded. A failed export retries the same window, so records are neither lost nor collected twice. The export window is half-open, so consecutive windows meet exactly with no gap and no overlap.
- An export is capped at fifty thousand records. The count is reported when the export is created, before it runs, so an oversized window is measured and split rather than silently truncated, and a window holding no records skips the export entirely.
- The prompt and completion bodies can be excluded, for deployments where the metadata alone is wanted or where prompt content should not leave Portkey.
- The workspace is identified by its slug. The export API accepts a workspace UUID, returns success and then matches no records, so the configuration field and the connection test both call this out.

### 1.6.2

- Set the collection interval to five minutes by default. Audit logs are the near real time source in this pack, so a short interval is appropriate, but the correlation that reads them runs every ten minutes and collecting more often than every five minutes adds no detection speed. This completes the interval defaults across the pack, the three snapshot collectors having moved to hourly in the previous release.

### 1.6.1

- Set the collection interval to one hour by default. The key inventory is a snapshot that changes rarely, and the posture correlations that read it run every six hours, so collecting it every minute produced a large number of identical records for no additional detection.
- Set the collection interval to one hour by default, for the same reason. Workspace permissions are a posture snapshot and change rarely.
- Set the collection interval to one hour by default, for the same reason. The config inventory is a snapshot and changes rarely.

### 1.6.0

- Detects an API key with no expiry date, so a leaked or forgotten credential that stays valid indefinitely is surfaced.
- Detects an API key whose scopes let it create or delete other keys, a privilege escalation path in which one credential mints further credentials that outlive its revocation.
- Detects an API key with neither a usage limit nor a rate limit, leaving model spend and request volume uncapped if the key is abused.
- Detects a workspace whose permission model lets ordinary members, not only managers, issue API keys or provider credentials.
- Detects a workspace where ordinary members may change guardrails or routing configs, allowing the controls that filter prompts and responses to be weakened without an administrator being involved.
- Detects a gateway config whose last editor was not its owner, surfacing an unexpected change to request routing or attached guardrails.
- Detects the creation of a new API key from the audit log, including the actor, source address and country, so a credential issued outside the normal process is noticed while it is still recent.
- The six posture rules read snapshot datasets, which re-send the full inventory on every poll. Each rule therefore takes only the newest snapshot per object before raising an alert, so a finding produces a single alert rather than one per collection cycle.

### 1.5.0

- Added modelling for the API key, workspace posture and config datasets, mapping each to the Cortex XDM data model alongside the existing audit mapping.
- Encoded the posture facts that correlations depend on into the data model. Raw dataset columns are not readable in data model queries, so key hygiene findings such as a missing expiry, an absent usage or rate limit, the ability to create further API keys, and a workspace granting write permissions to ordinary members, are carried as markers on the target resource value.
- Mapped the enumerations over their full specification membership rather than the values currently present, so a key that becomes exhausted, a key minted through the API rather than the console, and the workspace key families all classify correctly the first time they appear.
- Recorded config ownership and the last editor, so a config changed by someone other than its owner is detectable.

### 1.4.0

- Added an event collector for the Portkey gateway config inventory, ingesting `GET /configs` into the `portkey_configs_raw` dataset as a full snapshot per run. A config determines how requests are routed, including the provider and model selected, the fallback behaviour and the attached guardrails, so a change to one is a governance change worth detecting.
- Recorded whether the last editor of a config was also its owner, so a correlation can surface a config changed by someone other than the person who owns it.
- The configs endpoint accepts no parameters and is not paginated, returning the same full list whatever page is requested. The collector therefore issues a single request per run, and reports in the debug log if the endpoint ever returns fewer records than it claims to hold.

### 1.3.0

- Added an event collector for the Portkey API key inventory, ingesting `GET /api-keys` into the `portkey_api_keys_raw` dataset as a full snapshot per run, so comparing snapshots detects a key that was newly created, had its scopes widened, or had its expiry removed.
- Flattened the values correlations filter on into top-level columns, so no JSON parsing is needed at query time: scope count, rate limit count, whether a usage limit is configured and whether an expiry is set.
- Added an event collector for the Portkey workspace security posture, ingesting `GET /admin/workspaces` into the `portkey_workspaces_raw` dataset as a full snapshot per run.
- Flattened the workspace permission model to top-level boolean columns, covering the view and write permissions held by members, managers and organisation administrators over API keys, configs, guardrails, prompts, logs and workspace membership.
- Added a count of the write permissions granted to ordinary members, so a posture correlation can rank workspaces by how far the permission model has been widened.
- Standardised the integration logo to match the other collectors in the pack. No functional changes.

### 1.2.0

- Added a modelling rule for the `portkey_audit_raw` dataset, mapping Portkey control-plane audit records to the Cortex XDM data model.
- Classified the administrative action into an XDM operation verb. The Portkey API defines the action and resource type as free-form strings, so the verb is derived from the action text and falls back to the HTTP method, rather than matching only the values seen to date.
- Mapped the actor, the target resource and its parent workspace, the organisation, the HTTP method, response code and URL, and the originating address and country.
- Recorded the request outcome from the HTTP response status, and summarised each record in a readable event description.

### 1.1.0

- Corrected the audit-logs pagination, which is zero-based. The collector previously requested page 1 as its first page, which skips the first page of results and returns no events.
- Stopped sending the organisation ID to the audit-logs endpoint. The organisation is implied by the API key, and supplying it explicitly causes the endpoint to reject the request as unauthorised.
- Removed the Organisation ID configuration parameter. Each audit record carries its own organisation identifier, which the collector now stamps onto the event.
- Clarified in the documentation that the integration needs an organisation-scoped admin API key with the audit logs list scope, and that Portkey audit logs are an Enterprise plan feature.

### 1.0.1

- Standardised the integration logo to the uniform GoCortexIO house style (dark navy text on a transparent background). No functional changes.

<!-- spellbook:version-history:end -->
