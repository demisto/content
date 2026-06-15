# ConnectUs Migration — Branch 04 Summary

| Field | Value |
|---|---|
| **Branch number** | 04 (Branch 4 of 13) |
| **Git branch** | `jl-connectus-migration-04` (working tree currently checked out as `jl-connectus-migration-01`; this batch's work was performed and committed to the CSV under the branch-04 task) |
| **Assignee** | jlevypaloalto |
| **Date/time (UTC)** | 2026-06-15 11:35:32 UTC |
| **Total integrations in branch** | 11 (across 6 connectors) |

> **Scope note.** This session completed **steps 0–7 of 15** (the full pre-manifest decision pipeline: auth classification → capabilities → params-to-commands → param-defaults → UCP review → params-to-capabilities) for every integration. **Steps 8–14 (generated manifest, validate, param-parity, etc.) were deferred** because they require writing into the sibling `../unified-connectors-content/` repo, which is outside the sandbox and denied (`Operation not permitted`). Every integration is therefore parked at step **#8 generated manifest** with all upstream data committed.

---

## Per-integration table

State pulled authoritatively from `workflow_state.py context "<id>"` (current_step / completed_steps).

| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step reached | Status | Notes |
|---|---|---|---|---|---|
| Cylance Protect v2 | Aurora Endpoint Security | Passthrough (3-secret signed JWT) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | 3 creds → JWT sign; legacy hidden params skipped |
| C2sec irisk | C2SEC | APIKey | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | single key as `apikey` query param; role corrected to `key` |
| iManageThreatManager | iManage | Passthrough (2 cred sets, additive) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | user+token creds per event-type; params from source review |
| LookoutMobileEndpointSecurity | Lookout | Passthrough (OAuth client-credentials) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | app_key → Bearer/oauth2 token; long-running collector |
| TAXII 2 Feed | TAXII | Passthrough (basic + client-cert) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | both creds built into one Client |
| TAXII Server | TAXII | Passthrough (basic-auth + HTTPS TLS) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | `collections` kept in general_configurations (not elevated) |
| TAXII2 Server | TAXII | Passthrough (basic-auth + HTTPS TLS) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | res_size UNSAFE → default recorded; `collections`/`cache_duration_hours` not elevated |
| TAXIIFeed | TAXII | Passthrough (basic/api-key + client-cert) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | TAXII 1.x cabby client; `**params` splat |
| FireEye HX Event Collector | Trellix Threat Intel | Plain (basic-auth → session token) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | basic auth → X-FeApi-Token |
| FireEye iSIGHT | Trellix Threat Intel | Passthrough (public+private key HMAC) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | **JavaScript** integration; analyzer Python-only, fully source-reviewed |
| FireEyeFeed | Trellix Threat Intel | Passthrough (public+private key OAuth) | generated manifest (#8/15) | ⛔ blocked at #8 (0–7 ✅) | OAuth client-credentials; `collections_to_fetch` not elevated |

**Status legend:** ✅ complete (all 15) · ⏳ in-progress · ⛔ blocked. All 11 are blocked at #8 (steps 0–7 done) by the sandbox write restriction described in the scope note — not by a content defect.

**Tally: 0/11 fully complete, 11/11 pre-manifest complete (0–7), 11/11 blocked at #8.**

---

## Workflow-data written

Read back via `workflow_state.py context "<id>"`. `Release Notes` was not set for any integration (deferred step #15) — omitted per integration where empty.

### Cylance Protect v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "Cylance JWT",
      "interpolated": true,
      "xsoar_param_map": {
        "app_creds.identifier": "app_id",
        "app_creds.password": "app_secret",
        "api_key.password": "tenant_api_key"
      }
    }
  ],
  "other_connection": ["proxy", "server", "unsecure"]
}
```

**Params to Commands**
```json
{
  "integration": "Cylance Protect v2",
  "commands": {
    "cylance-optics-create-instaquery": [],
    "cylance-optics-get-instaquery-result": [],
    "cylance-optics-list-instaquery": [],
    "cylance-protect-add-hash-to-list": [],
    "cylance-protect-create-zone": [],
    "cylance-protect-delete-devices": [],
    "cylance-protect-delete-hash-from-lists": [],
    "cylance-protect-download-threat": [],
    "cylance-protect-get-device": [],
    "cylance-protect-get-device-by-hostname": [],
    "cylance-protect-get-device-threats": [],
    "cylance-protect-get-devices": [],
    "cylance-protect-get-indicators-report": [],
    "cylance-protect-get-list": [],
    "cylance-protect-get-policies": [],
    "cylance-protect-get-policy-details": [],
    "cylance-protect-get-threat": [],
    "cylance-protect-get-threat-devices": [],
    "cylance-protect-get-threats": [],
    "cylance-protect-get-zone": [],
    "cylance-protect-get-zones": [],
    "cylance-protect-update-device": [],
    "cylance-protect-update-device-threats": [],
    "cylance-protect-update-zone": [],
    "fetch-incidents": [],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{"server": "https://protectapi.cylance.com"}
```

**Params to Capabilities**
```json
{"Automation": [], "Fetch Issues": [], "general_configurations": []}
```

### C2sec irisk

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "C2sec API Key",
      "interpolated": true,
      "xsoar_param_map": {"apikey_creds.password": "key"}
    }
  ],
  "other_connection": ["domainName", "endpointURL", "proxy", "unsecure"]
}
```

**Params to Commands**
```json
{
  "integration": "C2sec irisk",
  "commands": {
    "irisk-add-domain": [],
    "irisk-get-domain-issues": [],
    "irisk-get-scan-results": [],
    "irisk-get-scan-status": [],
    "irisk-rescan-domain": [],
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
{"Automation": [], "general_configurations": []}
```

### iManageThreatManager

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "iManage Credentials",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials_user.identifier": "username",
        "credentials_user.password": "password",
        "credentials_token.identifier": "token",
        "credentials_token.password": "secret"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "iManageThreatManager",
  "commands": {
    "fetch-events": ["event_types", "max_events_per_type"],
    "imanage-threat-manager-get-events": [],
    "test-module": ["event_types"]
  }
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{"Log Collection": ["event_types", "max_events_per_type"], "general_configurations": []}
```

### LookoutMobileEndpointSecurity

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "Lookout App Key",
      "interpolated": true,
      "xsoar_param_map": {"app_key.password": "application_key"}
    }
  ],
  "other_connection": ["insecure", "proxy", "server_url"]
}
```

**Params to Commands**
```json
{
  "integration": "LookoutMobileEndpointSecurity",
  "commands": {
    "long-running-execution": ["event_types", "fetch_interval"],
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
{"Log Collection": ["longRunning", "event_types", "fetch_interval"], "general_configurations": []}
```

### TAXII 2 Feed

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "TAXII2 Credentials",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "creds_certificate.identifier": "certificate",
        "creds_certificate.password": "key"
      }
    }
  ],
  "other_connection": ["collection_to_fetch", "default_api_root", "insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "TAXII 2 Feed",
  "commands": {
    "taxii2-get-collections": [],
    "taxii2-get-indicators": [],
    "taxii2-reset-fetch-indicators": [],
    "test-module": ["fetch_full_feed", "limit"]
  }
}
```

**Params for test with default in code**
```json
{"initial_interval": "1 year"}
```

**Params to Capabilities**
```json
{"Automation": [], "Threat Intelligence & Enrichment": [], "general_configurations": ["fetch_full_feed", "limit"]}
```

### TAXII Server

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "TAXII Server Auth",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "certificate": "certificate",
        "key": "private_key"
      }
    }
  ],
  "other_connection": ["longRunningPort", "service_address"]
}
```

**Params to Commands**
```json
{
  "integration": "TAXII Server",
  "commands": {
    "long-running-execution": ["collections"],
    "test-module": ["collections"]
  }
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{"Automation": ["longRunning", "longRunningPort"], "general_configurations": ["collections"]}
```

### TAXII2 Server

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "TAXII2 Server Auth",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "certificate": "certificate",
        "key": "private_key"
      }
    }
  ],
  "other_connection": ["hsts_header", "longRunningPort", "nginx_global_directives", "nginx_server_conf", "service_address", "version"]
}
```

**Params to Commands**
```json
{
  "integration": "TAXII2 Server",
  "commands": {
    "long-running-execution": ["cache_duration_hours", "collections", "fields_filter", "provide_as_indicator", "res_size"],
    "taxii-server-info": [],
    "taxii-server-list-collections": [],
    "test-module": ["cache_duration_hours", "collections", "fields_filter", "provide_as_indicator", "res_size"]
  }
}
```

**Params for test with default in code**
```json
{"res_size": 2000, "version": "2.1"}
```

**Params to Capabilities**
```json
{"Automation": ["longRunning", "longRunningPort", "fields_filter", "provide_as_indicator", "res_size"], "general_configurations": ["cache_duration_hours", "collections"]}
```

### TAXIIFeed

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "TAXII Credentials",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "creds_certificate.identifier": "certificate",
        "creds_certificate.password": "key"
      }
    }
  ],
  "other_connection": ["collection", "discovery_service", "insecure", "poll_service", "proxy", "subscription_id"]
}
```

**Params to Commands**
```json
{
  "integration": "TAXIIFeed",
  "commands": {
    "get-indicators": ["polling_timeout"],
    "test-module": ["initial_interval", "polling_timeout"]
  }
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{"Threat Intelligence & Enrichment": ["polling_timeout"], "general_configurations": ["initial_interval"]}
```

### FireEye HX Event Collector

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "FireEye HX Basic",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "FireEye HX Event Collector",
  "commands": {
    "fetch-events": ["first_fetch", "max_fetch"],
    "fireeye-hx-get-events": ["max_fetch"],
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
{"Log Collection": ["first_fetch", "max_fetch"], "general_configurations": []}
```

### FireEye iSIGHT

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "iSIGHT HMAC",
      "interpolated": true,
      "xsoar_param_map": {
        "publicKey": "public_key",
        "credentials_private_key.password": "private_key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "version"]
}
```

**Params to Commands**
```json
{
  "integration": "FireEye iSIGHT",
  "commands": {
    "domain": [],
    "file": [],
    "ip": [],
    "isight-get-report": [],
    "isight-submit-file": [],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{"version": "2.5"}
```

**Params to Capabilities**
```json
{"Automation": [], "general_configurations": []}
```

### FireEyeFeed

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "FireEye Feed OAuth",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.identifier": "public_key",
        "credentials.password": "private_key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy"]
}
```

**Params to Commands**
```json
{
  "integration": "FireEyeFeed",
  "commands": {
    "fireeye-get-indicators": ["collections_to_fetch", "polling_timeout", "reputation_interval", "threshold"],
    "fireeye-reset-fetch-indicators": [],
    "test-module": ["collections_to_fetch", "polling_timeout", "reputation_interval", "threshold"]
  }
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{"Threat Intelligence & Enrichment": ["polling_timeout", "reputation_interval", "threshold"], "general_configurations": ["collections_to_fetch"]}
```

---

## File changes

### Content repo — files changed by THIS session

This session's only persisted change is to the pipeline CSV (written exclusively via the `workflow_state.py` CLI). All other modified `.py` files and untracked items listed below pre-existed in the working tree from other branches/sessions and were **not** touched here.

**This session changed:**
- `connectus/connectus-migration-pipeline.csv` — 11 integration rows updated (Auth Details, Collect Capabilities, Params to Commands, Params for test with default in code, Params to Capabilities; UCP param-default review marked passed).

### `git status --short` (full working-tree output)

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
 M connectus/connectus-migration-pipeline.csv
?? capabilities_output.json
?? connectus/.batch10_contexts.jsonl
?? connectus/.idex_ctx_tmp/
?? connectus/.summary_ctx.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/
```

> Of the above, only `connectus/connectus-migration-pipeline.csv` is attributable to this session. `connectus/migration-summaries/` is the new directory created to hold this summary. All `Packs/**/*.py` modifications and the other untracked entries are pre-existing and were not produced here.

### `git diff --stat` (full working-tree output)

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

### unified-connectors-content repo

**No changes.** The manifest generator (step #8) was never able to write to `../unified-connectors-content/connectors/` — every attempt failed with `PermissionError: [Errno 1] Operation not permitted` (path outside the sandbox). **No connector folders were created or modified** under `connectors/`.

---

## Blockers / follow-ups

1. **⛔ Steps 8–14 blocked (sandbox write restriction).** `manifest_generator.py`, the validate gate, and param-parity all write into the sibling `../unified-connectors-content/` repo, which is outside the permitted workspace and denied by the sandbox. **All 11 integrations are parked at step #8.** To finish: either run steps 8–15 outside the sandbox, or widen the sandbox to include `../unified-connectors-content/`.

2. **`interpolated: true` on every profile.** All 11 auth profiles carry `interpolated: true`. This is **not** a fallback decision — it is forced automatically by `set-auth` (the ALWAYS-INTERPOLATE GATE); the parity test is short-circuited by construction. No manual interpolation overrides were needed.

3. **Docker unavailable → static-only analyzer.** `check_command_params.py` could not run its dynamic spy (`docker pull` denied: `config.json` operation not permitted). The static AST pass resolved command handlers but cannot trace params read in `main()` / `**params` splats. Consequently, several `Params to Commands` entries were derived by **direct source review** (user-confirmed on each `set-params-to-commands` prompt): iManageThreatManager, LookoutMobileEndpointSecurity, TAXII Server, TAXII2 Server, TAXIIFeed, FireEye HX Event Collector, FireEyeFeed. **FireEye iSIGHT is JavaScript** — the analyzer is Python-only and skipped it entirely; its mapping is fully source-reviewed.

4. **TAXII2 Server — `res_size` UNSAFE finding (needs human review / optional code fix).** `check_param_defaults.py` flagged `int(demisto.params().get("res_size"))` at `FeedTAXII2/TAXII2Server.py:787` as unsafe (crashes on `None` under ConnectUs — no fallback, unlike the `.get("res_size", 2000)` at line 62). Mitigated for the test path by recording `{"res_size": 2000}` in *Params for test with default in code*. **A code-side fix (`.get("res_size", 2000)`) was deliberately NOT applied** (would require precommit/validate, which are deferred + Docker-blocked). Recommend the code fix during the deferred steps.

5. **`elevated` params intentionally NOT elevated to `other_connection`.** The mapper flagged required test-module params for elevation on TAXII Server (`collections`), TAXII2 Server (`collections`, `cache_duration_hours`), and FireEyeFeed (`collections_to_fetch`). Per user decision, these are feed-content/serving config (not connection-transport metadata), so they were placed in `Params to Capabilities → general_configurations` instead — avoiding a workflow-resetting `set-auth` re-apply. **Revisit if the connector build expects them on the connection.**

6. **Documentation conflict (for skill maintainer).** SKILL.md §7 claims `Params to Capabilities` survives `set-auth` via `preserve_on_reset: true`, but `column-schemas.md` and Critical Rule 6 state `set-auth` wipes it (only `Params to Commands` carries the flag). Treated as wiped (the dominant reading). Worth a maintainer fix.

7. **Tooling notes.** (a) The pipeline CLI requires `.venv/bin/python` — the system `python3` lacks `PyYAML`. (b) `connector_param_mapper.py`'s `-o` output file is not written (only the `.elevated.json` sidecar log fires); mappings were captured from its `--report` stdout envelope instead. (c) The `UCP param-default review` checkpoint occasionally reverted to unchecked after a subsequent mapper run, requiring a re-`markpass` (no data was lost — only the checkpoint bit).

---

## Reproduce

**Git branch:**
```
jl-connectus-migration-04
```

**Integration IDs (in this batch, in work order):**
```json
["Cylance Protect v2", "C2sec irisk", "iManageThreatManager", "LookoutMobileEndpointSecurity", "TAXII 2 Feed", "TAXII Server", "TAXII2 Server", "TAXIIFeed", "FireEye HX Event Collector", "FireEye iSIGHT", "FireEyeFeed"]
```

**Resume command (per integration):**
```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"
```
All 11 resume at step **#8 generated manifest** — continue from there once the `../unified-connectors-content/` write path is available.
