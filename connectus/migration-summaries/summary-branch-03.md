# ConnectUs Migration — Branch 03 Summary

| Field | Value |
|---|---|
| **Branch number** | 03 (of 13) |
| **Intended git branch** | `jl-connectus-migration-03` |
| **Actual current git branch (at write time)** | `jl-connectus-migration-01` — the branch was switched externally; per the run instruction this is ignored and work proceeded as if on `jl-connectus-migration-03` |
| **Assignee** | `jlevypaloalto` |
| **Date/time (UTC)** | 2026-06-15 11:36:41 UTC |
| **Total integrations in this branch** | 11 (across 6 connectors) |

> All workflow state was written **only** via `connectus/workflow_state.py` (never by editing the CSV directly). Authoritative state below was read back via `workflow_state.py context "<id>"`.
>
> **Environment caveats:** the repo `.venv` was required for every `workflow_state.py` call (`yaml` is missing from system Python) — i.e. `.venv/bin/python connectus/workflow_state.py ...`. The shell cwd was the content repo itself (`connectus/` sits directly under it), so the `content/` path prefix from the skill was dropped.

---

## Per-integration status

| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step reached | Status | Notes |
|---|---|---|---|---|---|
| Symantec MSS | Accenture | `Passthrough` (mTLS client cert + passphrase) | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked (sandbox can't write `unified-connectors-content/`) |
| BruteForceBlocker Feed | BruteForceBlocker | `NoneRequired` (public feed, hardcoded URL) | generated manifest (#8/15) | ⛔ blocked | Params-to-Capabilities initially failed to persist (silent no-op); re-applied at summary time, now at #8 |
| JsonWhoIs | JSONWhoIs.com | `APIKey` (token header) | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked |
| MongoDB | MongoDB | `Plain` (username/password, pymongo) | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked |
| MongoDB Key Value Store | MongoDB | `Plain` | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked |
| MongoDB Log | MongoDB | `Plain` | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked |
| MongoDBAtlasEventCollector | MongoDB | `Plain` (HTTP Digest pub/priv key) | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked |
| FireEye ETP Event Collector | Trellix Email Security | `APIKey` + `OAuth2ClientCreds` (XOR) | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked |
| FireEye Email Security | Trellix Email Security | `Plain` (FireEyeApiModule) | generated manifest (#8/15) | ⛔ blocked | UCP review needed a 2nd markpass (1st didn't persist); Step 8 blocked |
| FireEyeNX | Trellix Email Security | `Plain` | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked |
| WildFire-v2 | WildFire Cloud | `APIKey` | generated manifest (#8/15) | ⛔ blocked | Steps 2–7 complete; Step 8 blocked |

**Legend:** ✅ complete (all 15 steps) · ⏳ in-progress · ⛔ blocked (cannot advance past a step in this environment).

All 11 integrations completed the in-repo data steps (Auth Details → Collect Capabilities → Params to Commands → Param defaults → UCP param-default review → Params to Capabilities; steps 2–7) and are parked at **Step 8 "generated manifest" (current step #8/15, 7/15 complete)**, which is blocked — see Blockers section.

---

## Workflow-data written (read back via `context`)

### Symantec MSS

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "mtls",
      "xsoar_param_map": {
        "certificate": "client_certificate",
        "passphrase_creds.password": "certificate_passphrase"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["proxy", "server"]
}
```

**Params to Commands**
```json
{
  "integration": "Symantec MSS",
  "commands": {
    "test-module": [],
    "fetch-incidents": ["incidentType", "isFetch", "severities"],
    "symantec-mss-get-incident": [],
    "symantec-mss-incidents-list": [],
    "symantec-mss-update-incident": []
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
  "Fetch Issues": ["incidentType", "isFetch", "severities"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### BruteForceBlocker Feed

**Auth Details**
```json
{
  "auth_types": [],
  "other_connection": ["insecure", "proxy"]
}
```

**Params to Commands**
```json
{
  "integration": "BruteForceBlocker Feed",
  "commands": {
    "test-module": [],
    "bruteforceblocker-get-indicators": ["cidr_32_to_ip"]
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
  "Threat Intelligence & Enrichment": ["cidr_32_to_ip"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### JsonWhoIs

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_token",
      "xsoar_param_map": {"credentials.password": "key"},
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy"]
}
```

**Params to Commands**
```json
{
  "integration": "JsonWhoIs",
  "commands": {
    "test-module": [],
    "whois": []
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

**Release Notes** — not set (null).

---

### MongoDB

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
  "other_connection": ["auth_source", "database", "insecure", "urls", "use_ssl"]
}
```

**Params to Commands**
```json
{
  "integration": "MongoDB",
  "commands": {
    "test-module": [],
    "mongodb-get-entry-by-id": [],
    "mongodb-query": [],
    "mongodb-insert": [],
    "mongodb-update": [],
    "mongodb-delete": [],
    "mongodb-list-collections": [],
    "mongodb-create-collection": [],
    "mongodb-drop-collection": [],
    "mongodb-pipeline-query": [],
    "mongodb-bulk-update": []
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

**Release Notes** — not set (null).

---

### MongoDB Key Value Store

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
  "other_connection": ["collection", "database", "insecure", "uri", "use_ssl"]
}
```

**Params to Commands**
```json
{
  "integration": "MongoDB Key Value Store",
  "commands": {
    "test-module": [],
    "mongodb-write-key-value": [],
    "mongodb-get-key-value": [],
    "mongodb-list-key-values": [],
    "mongodb-delete-key": [],
    "mongodb-purge-entries": [],
    "mongodb-get-keys-number": [],
    "mongodb-list-incidents": []
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

**Release Notes** — not set (null).

---

### MongoDB Log

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
  "other_connection": ["collection", "database", "insecure", "uri", "use_ssl"]
}
```

**Params to Commands**
```json
{
  "integration": "MongoDB Log",
  "commands": {
    "test-module": [],
    "mongodb-read-log": [],
    "mongodb-write-log": [],
    "mongodb-logs-number": []
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

**Release Notes** — not set (null).

---

### MongoDBAtlasEventCollector

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "digest",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["group_id", "insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "MongoDBAtlasEventCollector",
  "commands": {
    "test-module": [],
    "fetch-events": ["max_events_per_fetch"],
    "mongo-db-atlas-get-events": []
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
  "Log Collection": ["max_events_per_fetch"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### FireEye ETP Event Collector

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_param_map": {"credentials.password": "key"},
      "interpolated": true
    },
    {
      "type": "OAuth2ClientCreds",
      "name": "oauth",
      "xsoar_param_map": {
        "oauth_credentials.identifier": "client_id",
        "oauth_credentials.password": "client_secret",
        "oauth_scopes": "scope"
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
  "integration": "FireEye ETP Event Collector",
  "commands": {
    "test-module": ["outbound_traffic"],
    "fetch-events": ["activity_log_max_fetch", "alerts_max_fetch", "email_trace_max_fetch", "hide_sensitive", "outbound_traffic"],
    "fireeye-etp-get-events": ["activity_log_max_fetch", "alerts_max_fetch", "email_trace_max_fetch", "hide_sensitive", "outbound_traffic"]
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
  "Log Collection": ["outbound_traffic", "activity_log_max_fetch", "alerts_max_fetch", "email_trace_max_fetch", "hide_sensitive"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### FireEye Email Security

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
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "FireEye Email Security",
  "commands": {
    "test-module": [],
    "fetch-incidents": ["first_fetch", "incidentType", "info_level", "isFetch", "max_fetch"],
    "fireeye-ex-get-alerts": [],
    "fireeye-ex-get-alert-details": [],
    "fireeye-ex-get-artifacts-by-uuid": [],
    "fireeye-ex-get-artifacts-metadata-by-uuid": [],
    "fireeye-ex-get-quarantined-emails": [],
    "fireeye-ex-release-quarantined-emails": [],
    "fireeye-ex-delete-quarantined-emails": [],
    "fireeye-ex-download-quarantined-emails": [],
    "fireeye-ex-get-reports": [],
    "fireeye-ex-list-allowedlist": [],
    "fireeye-ex-create-allowedlist": [],
    "fireeye-ex-update-allowedlist": [],
    "fireeye-ex-delete-allowedlist": [],
    "fireeye-ex-list-blockedlist": [],
    "fireeye-ex-create-blockedlist": [],
    "fireeye-ex-update-blockedlist": [],
    "fireeye-ex-delete-blockedlist": []
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
  "Fetch Issues": ["first_fetch", "incidentType", "info_level", "isFetch", "max_fetch"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### FireEyeNX

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
  "other_connection": ["insecure", "proxy", "request_timeout", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "FireEyeNX",
  "commands": {
    "test-module": ["fetch_artifacts", "fetch_mvx_correlated_events", "fetch_type", "first_fetch", "isFetch", "malware_type", "max_fetch", "replace_alert_url"],
    "fetch-incidents": ["fetch_artifacts", "fetch_mvx_correlated_events", "fetch_type", "first_fetch", "incidentType", "isFetch", "malware_type", "max_fetch", "replace_alert_url"],
    "fireeye-nx-get-alerts": ["replace_alert_url"],
    "fireeye-nx-get-artifacts-metadata-by-alert": [],
    "fireeye-nx-get-reports": [],
    "fireeye-nx-get-artifacts-by-alert": [],
    "fireeye-nx-get-events": []
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
  "Fetch Issues": ["fetch_artifacts", "fetch_mvx_correlated_events", "fetch_type", "first_fetch", "incidentType", "isFetch", "malware_type", "max_fetch"],
  "general_configurations": ["replace_alert_url"]
}
```

**Release Notes** — not set (null).

---

### WildFire-v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_param_map": {"credentials.password": "key"},
      "interpolated": true
    }
  ],
  "other_connection": ["credentials_source", "insecure", "proxy", "server"]
}
```

**Params to Commands**
```json
{
  "integration": "WildFire-v2",
  "commands": {
    "test-module": [],
    "file": ["create_relationships", "integrationReliability"],
    "wildfire-report": ["create_relationships", "integrationReliability"],
    "wildfire-get-verdict": ["integrationReliability"],
    "wildfire-get-verdicts": ["integrationReliability"],
    "wildfire-upload": ["suppress_file_type_error"],
    "wildfire-upload-file-url": ["suppress_file_type_error"],
    "wildfire-upload-url": ["suppress_file_type_error"],
    "wildfire-get-sample": [],
    "wildfire-get-url-webartifacts": []
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
  "Automation": ["create_relationships", "integrationReliability", "suppress_file_type_error"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

## File changes

> **Scope note:** the only file this session modified is `connectus/connectus-migration-pipeline.csv` (via the `workflow_state.py` CLI). The many `Packs/**/*.py` modifications and other untracked artifacts shown below were **already present** in the working tree at session start and were **not** touched by this session. The `unified-connectors-content` sibling repo was **not** modified — all writes to it (the Step 8 manifest scaffold) were blocked by the sandbox, so **no connector folders were created or modified** under `connectors/`.

### `git status --short` (content repo)
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
 M connectus/connectus-migration-pipeline.csv         <-- THIS SESSION (via workflow_state.py only)
?? capabilities_output.json
?? connectus/.batch10_contexts.jsonl
?? connectus/.idex_ctx_tmp/
?? connectus/.summary_ctx.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/                     <-- THIS SESSION (this summary file)
```

### `git diff --stat` (content repo)
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
Not modified. The sandbox denied all access outside `/Users/jlevy/dev/demisto/content`, so `manifest_generator.py` (Step 8) could not scaffold any connector folder. **No connector folders created/modified under `connectors/`.** Folders that *would* be created by the deferred manifest step (slugs derived from Connector ID): `accenture`, `bruteforceblocker`, `jsonwhois.com`, `mongodb`, `trellixemailsecurity`, `wildfirecloud`.

---

## Blockers / follow-ups

### Hard blocker — Step 8 (generated manifest) for all 11 integrations
`manifest_generator.py` must scaffold the connector folder under `../unified-connectors-content/connectors/`, which is **outside the sandbox-allowed directory** (`/Users/jlevy/dev/demisto/content`). Every write/`mkdir`/`touch`/`cd` into that path was denied (`PermissionError: Operation not permitted`). Per the user's decision, the manifest write and all downstream steps (9–15) were deferred to an unsandboxed run. This is why every integration is parked at #8.

**To unblock:** run `manifest_generator.py` in a shell with write access to `unified-connectors-content/`, e.g.:
```
.venv/bin/python connectus/connectus_migration/manifest_generator.py \
  <integration_yml> "<Connector ID>" '<Params-to-Capabilities JSON>' '<Auth Details JSON>' \
  --connectors-root ../unified-connectors-content/connectors
```
then `set-connector-path` + `markpass "generated manifest"` and continue steps 9–15.

### `interpolated: true` fallbacks (reason per integration)
`set-auth` forces `interpolated: true` onto every profile (ALWAYS-INTERPOLATE GATE), so all profiles carry it. Cases where it is specifically relied on as the documented fallback (non-HTTP / ApiModule / non-UCP-clean clients):
- **Symantec MSS** — `Passthrough` mTLS via raw `requests` + temp PEM (not `BaseClient`); interpolation is the fallback for a non-UCP-clean client.
- **MongoDB / MongoDB Key Value Store / MongoDB Log** — `pymongo.MongoClient` (not HTTP/`BaseClient`); interpolation is the documented fallback.
- **MongoDBAtlasEventCollector** — `Plain` over `HTTPDigestAuth`; interpolated fallback.
- **FireEye Email Security / FireEyeNX** — use `FireEyeApiModule` (`FireEyeClient`); interpolation is the ApiModule fallback.

### Checkpoints that needed re-running (state-persistence races)
- **FireEye Email Security** — first `markpass "UCP param-default review"` reported success but did **not** persist; required a second `markpass` (verified ✅ before proceeding).
- **BruteForceBlocker Feed** — first `set-params-to-capabilities` reported success but did **not** persist (column read back as `null` at summary time); **re-applied during summary generation** (the same user-approved payload), now persisted and at step #8. *Follow-up:* be aware of this silent no-op pattern; verify with `context` after each setter.

### UCP param-default review — flags judged out-of-scope (no code edits made)
All resolved by `markpass` (no `--force` was used anywhere). Each flag was on an auth/connection param (out of scope for the required-only, non-auth param-defaults column) or a param with an existing in-code fallback:
- **Symantec MSS** — `certificate`, `server` flagged (cross-function flow); both auth/connection params → out of scope.
- **MongoDB Key Value Store**, **MongoDB Log** — `uri` flagged; `other_connection` param → out of scope.
- **MongoDBAtlasEventCollector** — `max_events_per_fetch` flagged UNSAFE, but code already guards with `... or DEFAULT_FETCH_LIMIT` (=2500); also not in `test-module` list → out of scope. No edit.
- **FireEye Email Security** — `proxy` flagged UNSAFE (`argToBoolean(params.get("proxy"))`); `other_connection`/platform-injected param → out of scope.
- **FireEyeNX** — `url`, `request_timeout` (connection params) + `fetch_type`/`first_fetch`/`max_fetch`/`isFetch` (all `required:false`, with downstream defensive handling) flagged UNCERTAIN; none provable breaks, all out of scope.

### Judgment calls (human-confirmed)
- **WildFire-v2 `credentials_source`** — user chose to classify as `APIKey` and place `credentials_source` (non-secret key-type selector that sets the agent header) in `other_connection`, since `APIKey` only permits the role `key`.
- **FireEye ETP Event Collector** — dual XOR auth (OAuth2 client-creds OR API key). `auth_types` had to be ordered `APIKey` before `OAuth2ClientCreds` to satisfy the (type, name) sort validator.

### Things still needing human review
- Re-verify all 11 columns persisted after the noted races (FireEye EX markpass; BruteForceBlocker Feed capabilities) — done at summary time, but worth a final eyeball.
- Steps 9–15 (handler param coverage, validate manifest, param parity, code review, code merge, precommit, Release Notes) for all 11 — not started (blocked behind Step 8).

---

## Reproduce

**Git branch (intended for this batch):**
```
git checkout jl-connectus-migration-03
```
(Note: at summary time the working tree was actually on `jl-connectus-migration-01` due to an external branch switch.)

**Integration IDs in this batch (in work order):**
```json
["Symantec MSS", "BruteForceBlocker Feed", "JsonWhoIs", "MongoDB", "MongoDB Key Value Store", "MongoDB Log", "MongoDBAtlasEventCollector", "FireEye ETP Event Collector", "FireEye Email Security", "FireEyeNX", "WildFire-v2"]
```

**Resume a single integration:**
```
.venv/bin/python connectus/workflow_state.py context "<Integration ID>"
```
(Run from the content-repo root; the `.venv` is required because system Python lacks `yaml`.)
