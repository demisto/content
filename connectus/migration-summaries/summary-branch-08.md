# ConnectUs Migration — Batch 8 Summary

| Field | Value |
|---|---|
| **Branch number** | 08 (of 13) |
| **Git branch** | `jl-connectus-migration-08` (NOTE: the working tree currently reports branch `jl-connectus-migration-01`; per session instruction this is ignored and the batch is treated as branch 08) |
| **Assignee** | `jlevypaloalto` |
| **Date/time (UTC)** | 2026-06-15 11:35 UTC |
| **Total integrations in this branch** | 10 (across 5 connectors) |
| **Scope note** | Per operator instruction, steps **8–15 were skipped** for all integrations. Each integration was driven through steps 0–7 (assignee → Auth Details → Collect Capabilities → Params to Commands → Params for test with default in code → UCP param-default review → Params to Capabilities) and stopped at the **#8 generated manifest** gate. |

---

## Per-integration table

| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step reached | Status | Notes |
|---|---|---|---|---|---|
| Box v2 | Box | `OAuth2JWT` (jwt_service_account) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Box App config JSON → JWT-bearer. `cred_json.password → credentials_file`. Hidden legacy `credentials_json` (type 4) excluded. Step 8 blocked by connector slug collision (see Blockers). |
| BoxEventsCollector | Box | `OAuth2JWT` (jwt_service_account) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Same Box JWT flow. `credentials_json.password → credentials_file`. Step 8 blocked by connector slug collision. |
| Cisco ASA | Cisco ASA | `Plain` (basic) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | HTTP Basic from `credentials`. `isASAv` toggle placed in `other_connection` (connection-wide ASAv token-exchange selector, non-secret). |
| Elasticsearch v2 | ElasticSearch | `Passthrough` (api_key_auth) + `Plain` (credentials) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Multi-auth `auth_type` selector. Basic+Bearer merged into one `Plain` (identical keyset); API-key (2-field) → `Passthrough`. Selector omitted. `client_type`/`timeout` in other_connection. |
| ElasticsearchEventCollector | ElasticSearch | `Passthrough` (api_key_auth) + `Plain` (credentials) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Identical shared auth code to Elasticsearch v2. |
| ElasticsearchFeed | ElasticSearch | `Plain` (credentials) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Single credential pair; legacy `_api_key_id:` prefix overload uses same fields → single `Plain` profile. 3 code-side default fixes applied (Step 6). |
| NetskopeAPIv1 | Netskope | `APIKey` (api_token) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Token as `token` query param. `credentials.password → key`. Step 6: max_fetch/max_events_fetch/url confirmed safe (existing `or DEFAULT` fallbacks), suppressed. |
| NetskopeEventCollector_v2 | Netskope | `APIKey` (api_token) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Token as `Netskope-Api-Token` header. Step 6: max_fetch/url confirmed safe (existing `or 10000` fallback), suppressed. |
| netskope_api_v2 | Netskope | `APIKey` (api_token) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Token as `Netskope-Api-Token` header. Per-command params (fetch-incidents, update-remote-system) attributed. 3 code-side default fixes applied (Step 6). |
| Prisma Access Egress IP feed | Prisma Access GP Cloud | `APIKey` (api_key) | generated manifest (#8/15) — 7/15 done | ⏳ in-progress | Key as `header-api-key`. `credentials.password → key`. Deprecated hidden `api_key` (type 4) excluded. Step 6: proxy/tlp_color confirmed safe, suppressed. |

All 10 are at `current_step = "generated manifest"` (#8), `completed_steps = 7/15`, `all_complete = false`. None reached Step 8 (intentionally — per skip instruction; Box additionally blocked).

---

## Workflow-data written

### Box v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "OAuth2JWT",
      "name": "jwt_service_account",
      "xsoar_param_map": { "cred_json.password": "credentials_file" },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "Box v2",
  "commands": {
    "box-create-file-share-link": [],
    "box-create-folder-share-link": [],
    "box-create-user": [],
    "box-delete-user": [],
    "box-download-file": [],
    "box-file-delete": [],
    "box-find-file-folder-by-share-link": [],
    "box-folder-create": [],
    "box-get-current-user": [],
    "box-get-folder": [],
    "box-get-shared-link-by-file": [],
    "box-get-shared-link-by-folder": [],
    "box-list-enterprise-events": [],
    "box-list-folder-items": [],
    "box-list-user-events": [],
    "box-list-users": [],
    "box-move-folder": [],
    "box-remove-file-share-link": [],
    "box-remove-folder-share-link": [],
    "box-search-content": [],
    "box-trashed-item-delete-permanently": [],
    "box-trashed-item-restore": [],
    "box-trashed-items-list": [],
    "box-update-file-share-link": [],
    "box-update-folder-share-link": [],
    "box-update-user": [],
    "box-upload-file": [],
    "fetch-incidents": [],
    "test-module": ["as_user", "default_user"]
  }
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
  "Fetch Issues": [],
  "general_configurations": ["as_user", "default_user"]
}
```

**Release Notes** — not set (empty).

---

### BoxEventsCollector

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "OAuth2JWT",
      "name": "jwt_service_account",
      "xsoar_param_map": { "credentials_json.password": "credentials_file" },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "BoxEventsCollector",
  "commands": {
    "box-get-events": [],
    "fetch-events": [],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{
  "Log Collection": [],
  "general_configurations": []
}
```

**Release Notes** — not set (empty).

---

### Cisco ASA

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "basic",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "isASAv", "proxy", "server"]
}
```

**Params to Commands**
```json
{
  "integration": "Cisco ASA",
  "commands": {
    "cisco-asa-backup": [],
    "cisco-asa-create-network-object": [],
    "cisco-asa-create-rule": [],
    "cisco-asa-delete-rule": [],
    "cisco-asa-edit-rule": [],
    "cisco-asa-get-rule-by-id": [],
    "cisco-asa-list-interfaces": [],
    "cisco-asa-list-local-user": [],
    "cisco-asa-list-local-user-group": [],
    "cisco-asa-list-network-object-group": [],
    "cisco-asa-list-network-objects": [],
    "cisco-asa-list-rules": [],
    "cisco-asa-list-security-object-group": [],
    "cisco-asa-list-time-range": [],
    "cisco-asa-list-user-object": [],
    "cisco-asa-write-memory": [],
    "test-module": []
  }
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

**Release Notes** — not set (empty).

---

### Elasticsearch v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "api_key_auth",
      "xsoar_param_map": {
        "api_key_auth_credentials.identifier": "api_key_id",
        "api_key_auth_credentials.password": "api_key_secret"
      },
      "interpolated": true
    },
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
  "other_connection": ["client_type", "insecure", "proxy", "timeout", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "Elasticsearch v2",
  "commands": {
    "es-eql-search": [],
    "es-esql-search": [],
    "es-get-indices-statistics": [],
    "es-index": [],
    "es-integration-health-check": [],
    "es-search": [],
    "fetch-incidents": [],
    "get-mapping-fields": [],
    "search": [],
    "test-module": []
  }
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
  "Fetch Issues": [],
  "general_configurations": []
}
```

**Release Notes** — not set (empty).

---

### ElasticsearchEventCollector

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "api_key_auth",
      "xsoar_param_map": {
        "api_key_auth_credentials.identifier": "api_key_id",
        "api_key_auth_credentials.password": "api_key_secret"
      },
      "interpolated": true
    },
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
  "other_connection": ["client_type", "insecure", "proxy", "timeout", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "ElasticsearchEventCollector",
  "commands": {
    "es-get-events": [],
    "fetch-events": [],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{
  "Log Collection": [],
  "general_configurations": []
}
```

**Release Notes** — not set (empty).

---

### ElasticsearchFeed

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
  "other_connection": ["client_type", "insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "ElasticsearchFeed",
  "commands": {
    "es-get-indicators": [],
    "test-module": []
  }
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

**Release Notes** — not set (empty).

---

### NetskopeAPIv1

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_token",
      "xsoar_param_map": { "credentials.password": "key" },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "NetskopeAPIv1",
  "commands": {
    "fetch-incidents": [],
    "netskope-alert-list": [],
    "netskope-client-list": [],
    "netskope-event-list": [],
    "netskope-file-hash-list-update": [],
    "netskope-host-associated-user-list": [],
    "netskope-quarantined-file-get": [],
    "netskope-quarantined-file-list": [],
    "netskope-quarantined-file-update": [],
    "netskope-url-list-update": [],
    "netskope-user-associated-host-list": [],
    "test-module": []
  }
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
  "Fetch Issues": [],
  "general_configurations": []
}
```

**Release Notes** — not set (empty).

---

### NetskopeEventCollector_v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_token",
      "xsoar_param_map": { "credentials.password": "key" },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "NetskopeEventCollector_v2",
  "commands": {
    "fetch-events": [],
    "netskope-get-events": [],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{
  "Log Collection": [],
  "general_configurations": []
}
```

**Release Notes** — not set (empty).

---

### netskope_api_v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_token",
      "xsoar_param_map": { "credentials.password": "key" },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "netskope_api_v2",
  "commands": {
    "fetch-incidents": [
      "alerts_query",
      "event_types",
      "fetch_dlp_incidents",
      "fetch_events",
      "max_dlp_incidents_fetch",
      "max_events_fetch",
      "max_fetch"
    ],
    "get-mapping-fields": [],
    "get-modified-remote-data": [],
    "get-remote-data": [],
    "netskope-alert-list": [],
    "netskope-client-list": [],
    "netskope-event-list": [],
    "netskope-incident-dlp-list": [],
    "netskope-url-list-add": [],
    "netskope-url-list-create": [],
    "netskope-url-list-delete": [],
    "netskope-url-list-update": [],
    "netskope-url-lists-list": [],
    "test-module": [],
    "update-remote-system": ["close_netskope_incident"]
  }
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
  "Fetch Issues": [
    "alerts_query",
    "event_types",
    "fetch_dlp_incidents",
    "fetch_events",
    "max_dlp_incidents_fetch",
    "max_events_fetch",
    "max_fetch"
  ],
  "general_configurations": []
}
```

**Release Notes** — not set (empty).

---

### Prisma Access Egress IP feed

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_param_map": { "credentials.password": "key" },
      "interpolated": true
    }
  ],
  "other_connection": ["URL", "insecure", "proxy"]
}
```

**Params to Commands**
```json
{
  "integration": "Prisma Access Egress IP feed",
  "commands": {
    "prisma-access-get-indicators": [],
    "test-module": []
  }
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

**Release Notes** — not set (empty).

---

## File changes

> **Important:** The working tree contained many **pre-existing** uncommitted changes (other integrations' `.py` files and CSV rows) before this batch began. The files actually modified **by this session** are only:
> - `Packs/FeedElasticsearch/Integrations/FeedElasticsearch/FeedElasticsearch.py` (3 lines — Step 6 default fixes)
> - `Packs/Netskope/Integrations/NetskopeAPIv2/NetskopeAPIv2.py` (3 lines — Step 6 default fixes)
> - `connectus/connectus-migration-pipeline.csv` (written exclusively via `workflow_state.py` CLI for the 10 batch integrations; the CLI also re-normalizes other rows on save)

### `content` repo — `git status --short`
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
 M Packs/FeedElasticsearch/Integrations/FeedElasticsearch/FeedElasticsearch.py   <-- THIS SESSION
 M Packs/FeedMISP/Integrations/FeedMISP/FeedMISP.py
 M Packs/FireEyeCM/Integrations/FireEyeCM/FireEyeCM.py
 M Packs/FireEyeHelix/Integrations/FireEyeHelix/FireEyeHelix.py
 M Packs/ForcepointDLP/Integrations/ForcepointEventCollector/ForcepointEventCollector.py
 M Packs/MailListener/Integrations/MailListenerV2/MailListenerV2.py
 M Packs/MailListener_-_POP3/Integrations/MailListener_POP3/MailListener_POP3.py
 M Packs/Netmiko/Integrations/Netmiko/Netmiko.py
 M Packs/Netskope/Integrations/NetskopeAPIv2/NetskopeAPIv2.py                     <-- THIS SESSION
 M Packs/Rapid7_Nexpose/Integrations/Rapid7_Nexpose/Rapid7_Nexpose.py
 M Packs/SAPCloudForCustomerC4C/Integrations/SAPCloudForCustomerC4C/SAPCloudForCustomerC4C.py
 M Packs/TheHiveProject/Integrations/TheHiveProject/TheHiveProject.py
 M connectus/connectus-migration-pipeline.csv                                     <-- THIS SESSION (via CLI)
?? capabilities_output.json
?? connectus/.batch10_contexts.jsonl
?? connectus/.idex_ctx_tmp/
?? connectus/.summary_ctx.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/                                                <-- THIS SESSION (this file)
```

### `content` repo — `git diff --stat`
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

### `unified-connectors-content` repo
**Not touched.** No connector folders were created or modified under `connectors/` by this session. (One `manifest_generator.py` invocation for the `Box` connector was attempted but raised an exception **before writing anything** due to the SSPM slug collision; no manifest steps were run for any integration since steps 8–15 were skipped.)

### Code changes made this session (Step 6 UCP param-default fixes)
- **`FeedElasticsearch.py`**
  - `feed_type = params.get("feed_type")` → `params.get("feed_type") or "Cortex XSOAR MT Shared Feed"` (was crashing on `FEED_TYPE_GENERIC in None`)
  - `time_method = params.get("time_method")` → `params.get("time_method") or "Simple-Date"` (was crashing on `"..." in None`)
  - `query = params.get("es_query")` → `params.get("es_query") or "*"` (None → malformed query)
- **`NetskopeAPIv2.py`**
  - `arg_to_number(params["max_fetch"]) or MAX_LIMIT` → `arg_to_number(params.get("max_fetch") or 50) or MAX_LIMIT` (KeyError under UCP)
  - `arg_to_number(params["max_events_fetch"])` → `arg_to_number(params.get("max_events_fetch") or 50)` (KeyError under UCP)
  - `int(params["max_dlp_incidents_fetch"])` → `int(params.get("max_dlp_incidents_fetch") or 50)` (KeyError under UCP)

---

## Blockers / follow-ups

1. **⛔ Box connector slug collision (Box v2 + BoxEventsCollector).** The `Box` Connector ID slugs to `box`, which already exists in `unified-connectors-content/connectors/box` as a **different, non-XSOAR connector owned by the SSPM team** (`metadata.ownership.team = SSPM`, "SaaS Posture Security for Box"). `manifest_generator.py` hard-rejects adding an XSOAR handler to another team's connector ("There's already exist a non-xsoar connector with this id."). **This blocks Step 8 (generated manifest) for both Box integrations.** Needs coordination with the SSPM connector owners (or a distinct connector slug) before manifests can be generated. Operator chose to defer (skip steps 8+) rather than rename.

2. **`interpolated: true` fallback — applied to EVERY profile of EVERY integration.** This is by construction: the ALWAYS-INTERPOLATE GATE in `set-auth` forces `interpolated: true` onto every `auth_types[]` entry and short-circuits the parity test (write succeeds once JSON passes schema validation). No profile was individually hand-marked as a workaround; this is the documented default behavior, not a per-integration escape valve.

3. **Step 6 UCP param-default review — suppressed "uncertain"/"unsafe" findings (with reasons), no `--force` used anywhere.**
   - **NetskopeAPIv1**: `max_fetch`, `max_events_fetch` flagged unsafe but are analyzer false-positives — both read sites already carry `... or DEFAULT_*`, and `arg_to_number(None)` returns `None` (not raise). `url` is a required, runtime-injected connection param. All suppressed via `--ignore-params`.
   - **NetskopeEventCollector_v2**: `max_fetch` (already `... or 10000`) and `url` (required connection param) suppressed.
   - **netskope_api_v2**: `max_fetch`/`max_events_fetch`/`max_dlp_incidents_fetch` were **real risks** (subscript `params["..."]` → KeyError under UCP) and were **fixed in code**; `url` (required) and `user_email` (optional `.get()`, None handled by Client) suppressed.
   - **ElasticsearchFeed**: `feed_type`/`time_method`/`es_query` were **real risks** (`in None`/malformed query) and were **fixed in code**; `src_val`/`src_type`/`default_type` (guarded by `if not x: return_error`), `fetch_index` (existing `if not fetch_index: "_all"` fallback), `tlp_color` (truthy-only) suppressed.
   - **Prisma Access Egress IP feed**: `proxy` (connection param, BaseClient handles None) and `tlp_color` (truthy-only) suppressed.

4. **Static-only Params-to-Commands analysis.** The dynamic Docker phase was unavailable in the environment (`docker pull` blocked — `~/.docker/config.json` permission denied), so all `check_command_params` runs fell back to `--static-only`. Per the analyzer manual, static-only results are acceptable (tend to be a superset; "err on inclusion"). Re-running with Docker available could refine the per-command param lists (especially the empty-list commands).

5. **Cisco ASA `isASAv` placement.** Placed in `other_connection` (operator-confirmed) as a connection-wide, non-secret toggle that selects the ASAv-only token-exchange auth overlay. It is not a credential, so it is not in any `xsoar_param_map`. Worth a human sanity-check that the ConnectUs connection model can honor this toggle.

6. **No git commits or PRs were created** (none requested). All workflow state lives in `connectus-migration-pipeline.csv` (written via the CLI) plus the two code edits above.

---

## Reproduce

**Git branch:** `jl-connectus-migration-08`

```bash
git checkout jl-connectus-migration-08
```

**Integration IDs (in batch order):**
```json
["Box v2", "BoxEventsCollector", "Cisco ASA", "Elasticsearch v2", "ElasticsearchEventCollector", "ElasticsearchFeed", "NetskopeAPIv1", "NetskopeEventCollector_v2", "netskope_api_v2", "Prisma Access Egress IP feed"]
```

**Resume a single integration** (run from the idex parent cwd containing `content/` and `unified-connectors-content/` as siblings):
```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"
```

All 10 are currently parked at step **#8 generated manifest** (7/15 complete). To continue, resolve the Box slug collision (blocker #1) and resume from Step 8 per the 15-step workflow.
