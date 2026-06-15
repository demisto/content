# ConnectUs Migration — Branch 06 Summary

| Field | Value |
|---|---|
| **Branch number** | 06 (of 13) |
| **Git branch (at session start)** | `jl-connectus-migration-06` (intended) |
| **Git branch (current, externally changed)** | `jl-connectus-migration-01` |
| **Assignee** | `jlevypaloalto` |
| **Date/time (UTC)** | 2026-06-15 11:35 UTC (summary written) — migration work performed earlier same session |
| **Total integrations in this branch** | 10 (across 5 connectors) |

> **Note on git branch:** The session was started on `jl-connectus-migration-06`, but the
> active branch was changed externally to `jl-connectus-migration-01` before this summary was
> written. Per instructions, the summary proceeds as branch 06. All workflow state lives in
> `connectus/connectus-migration-pipeline.csv` (mutated only via the `workflow_state.py` CLI),
> so the working branch does not affect the recorded migration state.

> **Environment blocker (applies to ALL integrations):** Steps 8–14 (generated manifest →
> validate → handler coverage → param parity → code review/merge → precommit/RN) could not be
> executed because the manifest generator must write connector folders into the sibling
> `../unified-connectors-content` repo, and this sandbox denies all writes outside the content
> workspace. Per user decision, all 10 integrations were taken through the CSV-only steps (1–7)
> and the manifest pipeline was deferred. Every integration is therefore parked at step
> **#8 `generated manifest`** with 7/15 complete.

---

## Per-integration table

| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step reached | Status | Notes |
|---|---|---|---|---|---|
| Blocklist_de Feed | Blocklist.de | `NoneRequired` | `generated manifest` (#8/15) | ⏳ in-progress | Public feed, no creds. Uses `HTTPFeedApiModule`. Manifest deferred (blocker). |
| CelonisEventCollector | Celonis Collection | `Passthrough` (OAuth2 client-creds) | `generated manifest` (#8/15) | ⏳ in-progress | `max_events_per_fetch` manually elevated to `fetch-events`; recorded default 600 (branch-c, no code edit). Manifest deferred. |
| OpenLDAP | OpenLDAP | `Plain` (LDAP simple bind) | `generated manifest` (#8/15) | ⏳ in-progress | 8 collection params attributed across commands via call-tree tracing. Manifest deferred. |
| McAfee Advanced Threat Defense | Trellix ePO | `Plain` (user/pass session login) | `generated manifest` (#8/15) | ⏳ in-progress | Deprecated hidden `username`/`password` excluded. `baseUrl` UNCERTAIN resolved as connection-provided. Manifest deferred. |
| McAfee ESM v2 | Trellix ePO | `Plain` (user/pass JWT login) | `generated manifest` (#8/15) | ⏳ in-progress | `timezone` traced to 10 time-handling commands. Manifest deferred. |
| McAfee Threat Intelligence Exchange V2 | Trellix ePO | `Passthrough` (mTLS/DXL certs) | `generated manifest` (#8/15) | ⏳ in-progress | Multi-secret (CA bundle + client cert + private key) collapsed to one profile. `integrationReliability` → `file` cmd. Manifest deferred. |
| McAfee ePO v2 | Trellix ePO | `Plain` (HTTP Basic) | `generated manifest` (#8/15) | ⏳ in-progress | All command params are auth/connection-only; commands arg-driven. Manifest deferred. |
| RedCanary | Zscaler | `APIKey` (X-Api-Key header) | `generated manifest` (#8/15) | ⏳ in-progress | `api_key_creds.password` (hiddenusername); deprecated hidden `api_key` excluded. 3 fetch params → fetch-incidents. Manifest deferred. |
| Zscaler | Zscaler | `Passthrough` (user+pass+API key) | `generated manifest` (#8/15) | ⏳ in-progress | Multi-secret login collapsed to one profile. `auto_logout`/`auto_activate` traced to 30/16 commands. Manifest deferred. |
| ZscalerZIdentity | Zscaler | `Passthrough` (OAuth2 client-creds, ZIdentity) | `generated manifest` (#8/15) | ⏳ in-progress | `reliability`/`suspicious_categories`/`auto_activate` traced across reputation + write commands. Manifest deferred. |

**Tally: 0 complete · 10 in-progress · 0 blocked.**
(All 10 reached the manifest gate cleanly via steps 1–7; none are blocked on a failed checkpoint — the manifest pipeline is environment-deferred, not failed.)

---

## Workflow-data written

JSON read back via `workflow_state.py context "<id>"` (authoritative, persisted values). `Release Notes` was not set for any integration (still `null`) and is omitted below.

### Blocklist_de Feed

**Auth Details**
```json
{
  "auth_types": [],
  "other_connection": ["insecure", "polling_timeout", "proxy", "services"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "blocklist_de-get-indicators": [],
    "test-module": []
  },
  "integration": "Blocklist_de Feed"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Threat Intelligence & Enrichment": [],
  "general_configurations": []
}
```

### CelonisEventCollector

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "test-module": [],
    "celonis-get-events": [],
    "fetch-events": ["max_events_per_fetch"]
  },
  "integration": "Celonis"
}
```
**Params for test with default in code**
```json
{
  "max_events_per_fetch": 600
}
```
**Params to Capabilities**
```json
{
  "Log Collection": ["max_events_per_fetch"],
  "general_configurations": []
}
```

### OpenLDAP

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["base_dn", "connection_type", "host", "insecure", "ldap_server_vendor", "port", "proxy", "ssl_version"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "test-module": ["custom_attributes"],
    "ad-authenticate": ["user_identifier_attribute", "group_identifier_attribute", "user_filter_class", "custom_attributes"],
    "ad-groups": ["fetch_groups", "group_filter_class", "group_identifier_attribute", "page_size"],
    "ad-authenticate-and-roles": ["user_identifier_attribute", "group_identifier_attribute", "user_filter_class", "custom_attributes", "group_filter_class", "member_identifier_attribute", "page_size"],
    "ad-entries-search": []
  },
  "integration": "LDAP Authentication"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Automation": ["custom_attributes", "user_identifier_attribute", "group_identifier_attribute", "user_filter_class", "fetch_groups", "group_filter_class", "page_size", "member_identifier_attribute"],
  "general_configurations": []
}
```

### McAfee Advanced Threat Defense

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["baseUrl", "proxy", "unsecure"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "atd-check-status": [],
    "atd-file-upload": [],
    "atd-get-report": [],
    "atd-get-task-ids": [],
    "atd-list-analyzer-profiles": [],
    "atd-list-user": [],
    "atd-login": [],
    "detonate-file": [],
    "detonate-url": [],
    "test-module": []
  },
  "integration": "McAfee Advanced Threat Defense"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Automation": [],
  "general_configurations": []
}
```

### McAfee ESM v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "url", "version"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "esm-fetch-fields": [],
    "esm-search": ["timezone"],
    "esm-fetch-alarms": ["timezone"],
    "esm-acknowledge-alarms": [],
    "esm-unacknowledge-alarms": [],
    "esm-delete-alarms": [],
    "esm-get-alarm-event-details": ["timezone"],
    "esm-list-alarm-events": ["timezone"],
    "esm-get-case-list": ["timezone"],
    "esm-get-case-detail": ["timezone"],
    "esm-get-case-statuses": [],
    "esm-edit-case": ["timezone"],
    "esm-add-case": ["timezone"],
    "esm-add-case-status": [],
    "esm-edit-case-status": [],
    "esm-delete-case-status": [],
    "esm-get-organization-list": [],
    "esm-get-user-list": [],
    "esm-get-case-event-list": ["timezone"],
    "esm-get-watchlists": [],
    "esm-create-watchlist": [],
    "esm-delete-watchlist": [],
    "esm-watchlist-add-entry": [],
    "esm-watchlist-delete-entry": [],
    "esm-watchlist-list-entries": [],
    "fetch-incidents": ["fetchLimitAlarms", "fetchLimitCases", "fetchTime", "fetchType", "startingFetchID", "timezone"],
    "test-module": []
  },
  "integration": "McAfee ESM v2"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Issues": ["fetchLimitAlarms", "fetchLimitCases", "fetchTime", "fetchType", "startingFetchID"],
  "general_configurations": ["timezone"]
}
```

### McAfee Threat Intelligence Exchange V2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "dxl_certs",
      "xsoar_param_map": {
        "broker_ca_bundle": "broker_ca_bundle",
        "cert_file": "client_cert",
        "private_key": "private_key"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["broker_urls"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "file": ["integrationReliability"],
    "test-module": [],
    "tie-file-references": [],
    "tie-set-file-reputation": []
  },
  "integration": "McAfee Threat Intelligence Exchange v2"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Automation": ["integrationReliability"],
  "general_configurations": []
}
```

### McAfee ePO v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "authentication",
      "xsoar_param_map": {
        "authentication.identifier": "username",
        "authentication.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["address", "insecure", "proxy", "timeout"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "epo-advanced-command": [],
    "epo-apply-tag": [],
    "epo-assign-policy-to-group": [],
    "epo-assign-policy-to-system": [],
    "epo-clear-tag": [],
    "epo-command": [],
    "epo-create-issue": [],
    "epo-delete-issue": [],
    "epo-find-client-task": [],
    "epo-find-policy": [],
    "epo-find-system": [],
    "epo-find-systems": [],
    "epo-get-current-dat": [],
    "epo-get-latest-dat": [],
    "epo-get-system-tree-group": [],
    "epo-get-tables": [],
    "epo-get-version": [],
    "epo-help": [],
    "epo-list-issues": [],
    "epo-list-tag": [],
    "epo-move-system": [],
    "epo-query-table": [],
    "epo-update-client-dat": [],
    "epo-update-issue": [],
    "epo-update-repository": [],
    "epo-wakeup-agent": [],
    "test-module": []
  },
  "integration": "McAfee ePO v2"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Automation": [],
  "general_configurations": []
}
```

### RedCanary

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key_creds",
      "xsoar_param_map": {
        "api_key_creds.password": "key"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["domain", "insecure", "proxy"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "fetch-incidents": ["fetch_time", "fetch_limit", "isFetchAcknowledged"],
    "redcanary-acknowledge-detection": [],
    "redcanary-execute-playbook": [],
    "redcanary-get-detection": [],
    "redcanary-get-endpoint": [],
    "redcanary-get-endpoint-detections": [],
    "redcanary-list-detections": [],
    "redcanary-list-endpoints": [],
    "redcanary-update-remediation-state": [],
    "test-module": []
  },
  "integration": "Red Canary"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Issues": ["fetch_time", "fetch_limit", "isFetchAcknowledged"],
  "general_configurations": []
}
```

### Zscaler

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "zscaler_login",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "creds_key.password": "api_key"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["cloud", "insecure", "proxy", "requestTimeout"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "domain": ["reliability", "auto_logout"],
    "ip": ["reliability", "auto_logout"],
    "url": ["reliability", "auto_logout"],
    "test-module": ["auto_logout"],
    "zscaler-sandbox-report": ["reliability", "auto_logout"],
    "zscaler-blacklist-url": ["auto_logout", "auto_activate"],
    "zscaler-undo-blacklist-url": ["auto_logout", "auto_activate"],
    "zscaler-whitelist-url": ["auto_logout", "auto_activate"],
    "zscaler-undo-whitelist-url": ["auto_logout", "auto_activate"],
    "zscaler-blacklist-ip": ["auto_logout", "auto_activate"],
    "zscaler-undo-blacklist-ip": ["auto_logout", "auto_activate"],
    "zscaler-whitelist-ip": ["auto_logout", "auto_activate"],
    "zscaler-undo-whitelist-ip": ["auto_logout", "auto_activate"],
    "zscaler-category-add-url": ["auto_logout", "auto_activate"],
    "zscaler-category-add-ip": ["auto_logout", "auto_activate"],
    "zscaler-category-remove-url": ["auto_logout", "auto_activate"],
    "zscaler-category-remove-ip": ["auto_logout", "auto_activate"],
    "zscaler-list-ip-destination-groups": ["auto_logout", "auto_activate"],
    "zscaler-edit-ip-destination-group": ["auto_logout", "auto_activate"],
    "zscaler-create-ip-destination-group": ["auto_logout", "auto_activate"],
    "zscaler-delete-ip-destination-groups": ["auto_logout", "auto_activate"],
    "zscaler-get-categories": ["auto_logout"],
    "zscaler-get-blacklist": ["auto_logout"],
    "zscaler-get-whitelist": ["auto_logout"],
    "zscaler-activate-changes": ["auto_logout"],
    "zscaler-url-quota": ["auto_logout"],
    "zscaler-get-users": ["auto_logout"],
    "zscaler-update-user": ["auto_logout"],
    "zscaler-get-departments": ["auto_logout"],
    "zscaler-get-usergroups": ["auto_logout"],
    "zscaler-login": [],
    "zscaler-logout": []
  },
  "integration": "Zscaler Internet Access"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Automation": ["reliability", "auto_logout", "auto_activate"],
  "general_configurations": []
}
```

### ZscalerZIdentity

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "server_url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "zia-denylist-list": [],
    "zia-denylist-update": ["auto_activate"],
    "zia-allowlist-list": [],
    "zia-allowlist-update": ["auto_activate"],
    "zia-category-list": [],
    "zia-category-update": ["auto_activate"],
    "zia-url-quota-get": [],
    "zia-ip-destination-group-list": [],
    "zia-ip-destination-group-update": ["auto_activate"],
    "zia-ip-destination-group-add": ["auto_activate"],
    "zia-ip-destination-group-delete": ["auto_activate"],
    "zia-user-list": [],
    "zia-user-update": ["auto_activate"],
    "zia-groups-list": [],
    "zia-departments-list": [],
    "zia-sandbox-report-get": ["reliability"],
    "zia-activate-changes": [],
    "url": ["reliability", "suspicious_categories"],
    "ip": ["reliability", "suspicious_categories"],
    "domain": ["reliability", "suspicious_categories"],
    "test-module": []
  },
  "integration": "Zscaler Internet Access via ZIdentity"
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{
  "Automation": ["auto_activate", "reliability", "suspicious_categories"],
  "general_configurations": []
}
```

---

## File changes

### Content repo (`/Users/jlevy/dev/demisto/content`)

**Attributable to THIS session:** only `connectus/connectus-migration-pipeline.csv` was modified, exclusively
via the `workflow_state.py` CLI setters (never edited directly). The `connectus/migration-summaries/` directory
(this file) was created. **No `.py`/`.yml` integration files were edited by this session** (no `Params for test
with default in code` required a code edit — all were empty or branch-c records). The many modified `.py` files
below are **pre-existing working-tree changes unrelated to this session.**

`git status --short`:
```
 M Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py
 M Packs/BitSight/Integrations/BitSightEventCollector/BitSightEventCollector.py
 M Packs/BmcHelixRemedyForce/Integrations/BmcHelixRemedyForce/BmcHelixRemedyForce.py
 M Packs/BmcITSM/Integrations/BmcITSM/BmcITSM.py
 M Packs/Carbon_Black_Enterprise_Response/Integrations/CarbonBlackResponseV2/CarbonBlackResponseV2.py
 M Packs/DigitalGuardian/Integrations/DigitalGuardianARCEventCollector/DigitalGuardianARCEventCollector.py
 M Packs/Exabeam/Integrations/Exabeam/Exabeam.py
 M Packs/ExabeamSecurityOperationsPlatform/Integrations/ExabeamSecOpsPlatform/ExabeamSecOpsPlatform.py
 M Packs/FeedDHS/Integrations/DHSFeedV2/DHSFeedV2.py
 M Packs/FeedDHS/Integrations/DHS_Feed/DHS_Feed.py
 M Packs/FeedElasticsearch/Integrations/FeedElasticsearch/FeedElasticsearch.py
 M Packs/FeedMISP/Integrations/FeedMISP/FeedMISP.py
 M Packs/FireEyeCM/Integrations/FireEyeCM/FireEyeCM.py
 M Packs/FireEyeHelix/Integrations/FireEyeHelix/FireEyeHelix.py
 M Packs/ForcepointDLP/Integrations/ForcepointEventCollector/ForcepointEventCollector.py
 M Packs/MailListener/Integrations/MailListenerV2/MailListenerV2.py
 M Packs/MailListener_-_POP3/Integrations/MailListener_POP3/MailListener_POP3.py
 M Packs/Netmiko/Integrations/Netmiko/Netmiko.py
 M Packs/Netskope/Integrations/NetskopeAPIv2/NetskopeAPIv2.py
 M Packs/Rapid7_Nexpose/Integrations/Rapid7_Nexpose/Rapid7_Nexpose.py
 M Packs/SAPCloudForCustomerC4C/Integrations/SAPCloudForCustomerC4C/SAPCloudForCustomerC4C.py
 M Packs/TheHiveProject/Integrations/TheHiveProject/TheHiveProject.py
 M connectus/connectus-migration-pipeline.csv       <-- THIS SESSION (via CLI)
?? capabilities_output.json                          <-- analyzer scratch output (capabilities_collector)
?? connectus/.batch10_contexts.jsonl
?? connectus/.idex_ctx_tmp/
?? connectus/.summary_ctx.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/                    <-- THIS SESSION (this summary file)
```

`git diff --stat`:
```
 Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py  |   2 +-
 .../BitSightEventCollector.py                      |   2 +-
 .../BmcHelixRemedyForce/BmcHelixRemedyForce.py     |   4 +-
 Packs/BmcITSM/Integrations/BmcITSM/BmcITSM.py      |   2 +-
 .../CarbonBlackResponseV2/CarbonBlackResponseV2.py |   2 +-
 .../DigitalGuardianARCEventCollector.py            |   2 +-
 Packs/Exabeam/Integrations/Exabeam/Exabeam.py      |   4 +-
 .../ExabeamSecOpsPlatform/ExabeamSecOpsPlatform.py |   4 +-
 Packs/FeedDHS/Integrations/DHSFeedV2/DHSFeedV2.py  |   4 +-
 Packs/FeedDHS/Integrations/DHS_Feed/DHS_Feed.py    |   4 +-
 .../FeedElasticsearch/FeedElasticsearch.py         |   6 +-
 Packs/FeedMISP/Integrations/FeedMISP/FeedMISP.py   |   2 +-
 .../FireEyeCM/Integrations/FireEyeCM/FireEyeCM.py  |   2 +-
 .../Integrations/FireEyeHelix/FireEyeHelix.py      |   8 +-
 .../ForcepointEventCollector.py                    |   2 +-
 .../Integrations/MailListenerV2/MailListenerV2.py  |   4 +-
 .../MailListener_POP3/MailListener_POP3.py         |   2 +-
 Packs/Netmiko/Integrations/Netmiko/Netmiko.py      |   2 +-
 .../Integrations/NetskopeAPIv2/NetskopeAPIv2.py    |   6 +-
 .../Integrations/Rapid7_Nexpose/Rapid7_Nexpose.py  |   3 +-
 .../SAPCloudForCustomerC4C.py                      |   2 +-
 .../Integrations/TheHiveProject/TheHiveProject.py  |   2 +-
 connectus/connectus-migration-pipeline.csv         | 468 +++++++++++++++------
 23 files changed, 370 insertions(+), 169 deletions(-)
```

### Unified-connectors-content repo (`/Users/jlevy/dev/demisto/unified-connectors-content`)

`git status --short`: *(empty — no changes)*

`git diff --stat`: *(empty — no changes)*

**Connector folders created/modified under `connectors/`:** **NONE.** The manifest step (which would
create `connectors/<slug>/` folders for Blocklist.de, Celonis Collection, OpenLDAP, Trellix ePO, and
Zscaler) was blocked by the sandbox write restriction and was not run.

---

## Blockers / follow-ups

1. **HARD BLOCKER — manifest pipeline (steps 8–14) for all 10 integrations.** The manifest generator
   (`manifest_generator.py`) must write connector folders into `../unified-connectors-content/connectors/`,
   but this environment denies all writes outside the content workspace
   (`/Users/jlevy/dev/demisto/content`). Confirmed via a direct write test (`PermissionError: Operation
   not permitted`). To resume: grant write access to the sibling repo (or run from an environment where it
   is writable), then for each integration run
   `manifest_generator.py <yml> "<Connector ID>" '<Params-to-Capabilities>' '<Auth Details>'` →
   `set-connector-path` → `markpass "generated manifest"`, then continue through validate / handler-coverage /
   param-parity / review / merge / precommit / Release Notes.

2. **`interpolated: true` on every classified profile (expected, not a fallback decision).** Per the skill's
   ALWAYS-INTERPOLATE GATE, `set-auth` forces `interpolated: true` onto every `auth_types[]` entry and
   short-circuits the parity test. This applies to all 8 integrations that have profiles (the 2 NoneRequired/empty
   cases — only Blocklist_de Feed — have no profiles). This is the documented behavior, **not** a per-integration
   fallback for a parity failure. No parity tests were run (deferred with the manifest pipeline), so no
   `--force` overrides were needed anywhere.

3. **No checkpoint failures and no `--force` usage.** All steps 1–7 passed cleanly for every integration.
   `check_handler_param_coverage` (step 9) was not reached.

4. **Items needing human review at resume time:**
   - **McAfee ESM v2 / Zscaler / ZscalerZIdentity / OpenLDAP** — per-command param attributions for
     module-baseline params (`timezone`, `auto_logout`, `auto_activate`, `suspicious_categories`, and the 8
     LDAP collection params) were derived by manual static call-tree tracing because Docker-based dynamic
     analysis was unavailable in this environment. Worth a quick re-verify with the dynamic analyzer where possible.
   - **CelonisEventCollector** — `check_param_defaults` flagged `max_events_per_fetch` as "unsafe," but the
     code already has an `or DEFAULT_FETCH_LIMIT` (600) fallback (branch-c). Recorded `{"max_events_per_fetch": 600}`
     in the defaults cell with no code edit. Confirm this is acceptable at review.
   - **McAfee Advanced Threat Defense** — `baseUrl` flagged UNCERTAIN (cross-function flow through `re.sub`);
     resolved as a required connection param already in `other_connection` (connection always supplies it).
     No `or ""` guard added.
   - **RedCanary connector grouping** — `Connector ID` is `Zscaler` (per the CSV) even though RedCanary is a
     distinct product; the manifest title will therefore place it under the Zscaler connector folder. Confirm
     this is intended before generating the manifest.

5. **Capabilities note (McAfee TIE V2).** `capabilities_collector` returned only `Automation` for an
   enrichment integration with a `file` reputation command. Used as-is (collector is deterministic from YML
   flags); flag for review if a `Threat Intelligence & Enrichment` capability is expected.

---

## Reproduce

**Git branch (intended for this batch):**
```
jl-connectus-migration-06
```
(Current working branch was externally switched to `jl-connectus-migration-01`; re-checkout
`jl-connectus-migration-06` to resume on the intended branch. Migration state is branch-independent —
it lives in the pipeline CSV.)

**Integration IDs in this batch (in work order):**
```json
["Blocklist_de Feed", "CelonisEventCollector", "OpenLDAP", "McAfee Advanced Threat Defense", "McAfee ESM v2", "McAfee Threat Intelligence Exchange V2", "McAfee ePO v2", "RedCanary", "Zscaler", "ZscalerZIdentity"]
```

**Connectors (5):** Blocklist.de (1) · Celonis Collection (1) · OpenLDAP (1) · Trellix ePO (4: McAfee ATD,
McAfee ESM v2, McAfee TIE V2, McAfee ePO v2) · Zscaler (3: RedCanary, Zscaler, ZscalerZIdentity).

**CLI invocation note for resume:** run `workflow_state.py` as
`.venv/bin/python connectus/workflow_state.py <verb> ...` from the content-repo root
(`/Users/jlevy/dev/demisto/content`). In this sandbox the parent-cwd form and the `content/` path prefix are
blocked; the workspace IS the content repo, and the repo's `.venv` provides the required `yaml`/deps.

**To resume each integration:** `.venv/bin/python connectus/workflow_state.py context "<Integration ID>"` →
continue from step #8 `generated manifest` once sibling-repo write access is available.
