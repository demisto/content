# ConnectUs Migration — Summary, Branch 02

| Field | Value |
|---|---|
| **Branch number** | 02 |
| **Git branch name** | `jl-connectus-migration-02` (created this session; note: working tree later reported `jl-connectus-migration-01` — per task instruction this is ignored and treated as batch 02) |
| **Assignee** | jlevypaloalto |
| **Date/time (UTC)** | 2026-06-15 11:35 UTC (summary generated 2026-06-15 ~14:05 UTC) |
| **Total integrations in this branch** | 11 |

> **Scope note:** Per an explicit user instruction mid-session ("skip all steps after 7 for all integrations"), each integration was taken through **step 7 (Params to Capabilities)** only. Steps 8–15 (manifest generation, handler param coverage, validate, param parity, code review, code merge, precommit, Release Notes) were intentionally **not** performed, because writing the generated manifest to the sibling `unified-connectors-content` repo is blocked by the sandbox and the user opted to stop at step 7.

---

## Per-integration table

State pulled authoritatively from `python3 content/connectus/workflow_state.py context "<id>"`.

| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step reached | Status | Notes |
|---|---|---|---|---|---|
| IBMMaaS360Security | IBM Security | Passthrough (multi-secret admin login) | handler param coverage (#9/15) | ✅ complete (through step 7 scope) | Step 8 "generated manifest" was marked + connector path `connectors/ibm-security` set *before* the scope change; current step shows #9. Stray `content/unified-connectors-content` manifest output was removed. |
| IBMSecurityGuardium | IBM Security | Plain (basic) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | `report_id` elevated to `other_connection` per param-mapper; required re-`set-auth` + reset-to step 4 to re-do downstream. |
| IBMSecurityVerify | IBM Security | OAuth2ClientCreds | generated manifest (#8/15) | ✅ complete (through step 7 scope) | `isFetchEvents` read at L117 is the framework fetch toggle (not a YML param) — excluded. |
| XFE_v2 | IBM Security | Plain (basic) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | Threat-intel enrichment; `integrationReliability`/`create_relationships` elevated as `main()` blind-spot params. |
| IBM Storage Scale | IBM Storage Scale | Plain (basic) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | `async def main()` not resolvable by static analyzer; all params mapped from source review. |
| SplunkPy | Splunk | Passthrough (dual-mode auth + HEC token) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | 27 commands; deep source-trace needed (module-level `params` global + helper chains). |
| SplunkPy v2 | Splunk | Passthrough (token + HEC token) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | 27 commands; `authentication` token-only (hiddenusername:true). Deep source-trace needed. |
| Nessus | Tenable | Plain (credentials → session token) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | JavaScript integration (analyzer Python-only skip); legacy flat `username`/`password` hidden:true → excluded. |
| Tenable.io | Tenable | Passthrough (access_key + secret_key) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | Two-key API auth; legacy flat `access-key`/`secret-key` hidden:true → excluded. |
| Tenable.sc | Tenable | XOR: Passthrough (API keys) + Plain (credentials) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | Two XOR profiles; `credentials.identifier` suppressed by hiddenusername:true (mechanical rule) though code reads it. auth_types reordered to satisfy `(type,name)` sort. |
| McAfeeDAM | Trellix Database Security | Plain (basic) | generated manifest (#8/15) | ✅ complete (through step 7 scope) | JavaScript integration (analyzer Python-only skip). |

**Tally: 11/11 complete (through the step-7 scope), 0 in-progress, 0 blocked.**

---

## Workflow-data written (read back via `context`)

### IBMMaaS360Security

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "maas360_admin",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "app_access_key.password": "app_access_key",
        "billing_id.password": "billing_id",
        "app_id": "app_id",
        "app_version": "app_version",
        "platform_id": "platform_id"
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
  "integration": "IBM MaaS360 Security",
  "commands": {
    "test-module": [],
    "ibm-maas360-security-get-events": [],
    "fetch-events": []
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

**Release Notes**
```json
null
```

### IBMSecurityGuardium

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
  "other_connection": ["insecure", "proxy", "report_id", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "IBM Security Guardium",
  "commands": {
    "test-module": ["isFetchEvents", "timestamp_field"],
    "fetch-events": ["max_fetch", "timestamp_field"],
    "ibm-guardium-get-events": ["timestamp_field"]
  }
}
```

**Params for test with default in code**
```json
{
  "max_fetch": 10000
}
```

**Params to Capabilities**
```json
{
  "Log Collection": ["timestamp_field", "max_fetch"],
  "general_configurations": ["isFetchEvents"]
}
```

**Release Notes**
```json
null
```

### IBMSecurityVerify

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "client_creds",
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
  "integration": "IBM Security Verify",
  "commands": {
    "test-module": ["max_fetch"],
    "fetch-events": ["max_fetch"],
    "ibm-security-verify-get-events": []
  }
}
```

**Params for test with default in code**
```json
{
  "max_fetch": 10000
}
```

**Params to Capabilities**
```json
{
  "Log Collection": ["max_fetch"],
  "general_configurations": []
}
```

**Release Notes**
```json
null
```

### XFE_v2

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
  "integration": "IBM X-Force Exchange v2",
  "commands": {
    "test-module": [],
    "ip": ["integrationReliability", "ip_threshold"],
    "url": ["integrationReliability", "url_threshold"],
    "domain": ["integrationReliability", "url_threshold"],
    "file": ["create_relationships", "integrationReliability"],
    "cve-search": ["cve_threshold", "integrationReliability"],
    "cve-latest": ["cve_threshold", "integrationReliability"],
    "xfe-search-cves": ["cve_threshold", "integrationReliability"],
    "xfe-whois": []
  }
}
```

**Params for test with default in code**
```json
{
  "create_relationships": true,
  "integrationReliability": "C - Fairly reliable"
}
```

**Params to Capabilities**
```json
{
  "Automation": ["integrationReliability", "ip_threshold", "url_threshold", "create_relationships", "cve_threshold"],
  "general_configurations": []
}
```

**Release Notes**
```json
null
```

### IBM Storage Scale

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
  "other_connection": ["insecure", "proxy", "server_url"]
}
```

**Params to Commands**
```json
{
  "integration": "IBM Storage Scale Beta",
  "commands": {
    "test-module": [],
    "fetch-events": ["max_fetch", "server_timezone"],
    "ibm-storage-scale-get-events": ["server_timezone"],
    "ibm-storage-scale-debug-connection": ["server_timezone"]
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
  "Log Collection": ["max_fetch"],
  "general_configurations": ["server_timezone"]
}
```

**Release Notes**
```json
null
```

### SplunkPy

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "authentication",
      "interpolated": true,
      "xsoar_param_map": {
        "authentication.identifier": "username",
        "authentication.password": "password",
        "cred_hec_token.password": "hec_token"
      }
    }
  ],
  "other_connection": ["app", "hec_url", "host", "port", "proxy", "unsecure"]
}
```

**Params to Commands**
```json
{
  "integration": "SplunkPy",
  "commands": {
    "test-module": ["enabled_enrichments", "fetchQuery", "isFetch", "timezone"],
    "fetch-incidents": ["enabled_enrichments", "extractFields", "fetchQuery", "fetch_limit", "fetch_time", "notable_time_source", "occurrence_look_behind", "parseNotableEventsRaw", "replaceKeys", "splunk_user_field", "timezone", "useSplunkTime", "userMapping", "user_map_lookup_name", "xsoar_user_field"],
    "get-mapping-fields": ["extractFields", "fetchQuery", "fetch_limit", "fetch_time", "parseNotableEventsRaw", "replaceKeys", "timezone", "type_field", "useSplunkTime", "use_cim"],
    "get-modified-remote-data": ["close_end_status_statuses", "close_extra_labels", "comment_tag_from_splunk", "enabled_enrichments", "replaceKeys", "timezone"],
    "get-remote-data": [],
    "splunk-get-username-by-xsoar-user": ["splunk_user_field", "userMapping", "user_map_lookup_name", "xsoar_user_field"],
    "splunk-get-indexes": [],
    "splunk-job-create": [],
    "splunk-job-share": [],
    "splunk-job-status": [],
    "splunk-kv-store-collection-add-entries": [],
    "splunk-kv-store-collection-config": [],
    "splunk-kv-store-collection-create": [],
    "splunk-kv-store-collection-create-transform": [],
    "splunk-kv-store-collection-data-delete": [],
    "splunk-kv-store-collection-data-list": [],
    "splunk-kv-store-collection-delete": [],
    "splunk-kv-store-collection-delete-entry": [],
    "splunk-kv-store-collection-search-entry": [],
    "splunk-kv-store-collections-list": [],
    "splunk-notable-event-edit": [],
    "splunk-parse-raw": [],
    "splunk-reset-enriching-fetch-mechanism": [],
    "splunk-results": [],
    "splunk-search": [],
    "splunk-submit-event": [],
    "splunk-submit-event-hec": []
  }
}
```

**Params for test with default in code**
```json
{
  "fetch_limit": 50,
  "occurrence_look_behind": 15,
  "timezone": 0
}
```

**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Issues": ["enabled_enrichments", "extractFields", "fetchQuery", "fetch_limit", "fetch_time", "notable_time_source", "occurrence_look_behind", "parseNotableEventsRaw", "replaceKeys", "timezone", "useSplunkTime"],
  "general_configurations": ["isFetch", "xsoar_user_field", "splunk_user_field", "user_map_lookup_name", "userMapping"]
}
```

**Release Notes**
```json
null
```

### SplunkPy v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "authentication",
      "interpolated": true,
      "xsoar_param_map": {
        "authentication.password": "token",
        "cred_hec_token.password": "hec_token"
      }
    }
  ],
  "other_connection": ["app", "hec_url", "proxy", "server_url", "unsecure"]
}
```

**Params to Commands**
```json
{
  "integration": "SplunkPy v2",
  "commands": {
    "test-module": ["enabled_enrichments", "extensive_logs", "fetchQuery", "fetch_event_types", "investigations_fetch_query", "isFetch", "note_tag_from_splunk", "note_tag_to_splunk", "parseFindingEventsRaw", "replaceKeys", "unique_id_fields"],
    "fetch-incidents": ["asset_enrich_lookup_tables", "enabled_enrichments", "enrichment_timeout", "extensive_logs", "extractFields", "fetchQuery", "fetch_event_types", "finding_time_source", "first_fetch", "identity_enrich_lookup_tables", "investigations_fetch_query", "investigations_first_fetch", "investigations_max_fetch", "max_fetch", "note_tag_from_splunk", "note_tag_to_splunk", "num_enrichment_events", "occurrence_look_behind", "parseFindingEventsRaw", "replaceKeys", "splunk_user_field", "unique_id_fields", "userMapping", "user_map_lookup_name", "xsoar_user_field"],
    "get-mapping-fields": ["enabled_enrichments", "extensive_logs", "extractFields", "fetchQuery", "first_fetch", "max_fetch", "note_tag_from_splunk", "note_tag_to_splunk", "occurrence_look_behind", "parseFindingEventsRaw", "replaceKeys", "splunk_user_field", "userMapping", "user_map_lookup_name", "xsoar_user_field"],
    "get-modified-remote-data": ["close_end_status_statuses", "close_extra_labels", "enabled_enrichments", "extensive_logs", "fetch_event_types", "note_tag_from_splunk", "splunk_user_field", "userMapping", "user_map_lookup_name", "xsoar_user_field"],
    "splunk-get-username-by-xsoar-user": ["splunk_user_field", "userMapping", "user_map_lookup_name", "xsoar_user_field"],
    "splunk-parse-raw": ["replaceKeys"],
    "splunk-finding-event-edit": [],
    "splunk-get-indexes": [],
    "splunk-investigation-create": [],
    "splunk-investigation-list": [],
    "splunk-update-investigation": [],
    "splunk-job-create": [],
    "splunk-job-share": [],
    "splunk-job-status": [],
    "splunk-kv-store-collection-add-entries": [],
    "splunk-kv-store-collection-config": [],
    "splunk-kv-store-collection-create": [],
    "splunk-kv-store-collection-create-transform": [],
    "splunk-kv-store-collection-data-delete": [],
    "splunk-kv-store-collection-data-list": [],
    "splunk-kv-store-collection-delete": [],
    "splunk-kv-store-collection-delete-entry": [],
    "splunk-kv-store-collection-search-entry": [],
    "splunk-kv-store-collections-list": [],
    "splunk-reset-enriching-fetch-mechanism": [],
    "splunk-results": [],
    "splunk-search": [],
    "splunk-submit-event": [],
    "splunk-submit-event-hec": []
  }
}
```

**Params for test with default in code**
```json
{
  "max_fetch": 50,
  "investigations_max_fetch": 50
}
```

**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Issues": ["asset_enrich_lookup_tables", "enabled_enrichments", "enrichment_timeout", "extensive_logs", "extractFields", "fetchQuery", "fetch_event_types", "finding_time_source", "first_fetch", "identity_enrich_lookup_tables", "investigations_fetch_query", "investigations_first_fetch", "investigations_max_fetch", "max_fetch", "note_tag_from_splunk", "note_tag_to_splunk", "num_enrichment_events", "occurrence_look_behind", "parseFindingEventsRaw", "unique_id_fields"],
  "general_configurations": ["isFetch", "splunk_user_field", "xsoar_user_field", "userMapping", "replaceKeys", "user_map_lookup_name"]
}
```

**Release Notes**
```json
null
```

### Nessus

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
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "Nessus",
  "commands": {
    "test-module": [],
    "nessus-list-scans": [],
    "scans-list": [],
    "nessus-launch-scan": [],
    "scan-launch": [],
    "nessus-scan-details": [],
    "scan-details": [],
    "scan-host-details": [],
    "nessus-scan-host-details": [],
    "nessus-scan-export": [],
    "scan-export": [],
    "scan-report-download": [],
    "nessus-scan-report-download": [],
    "scan-create": [],
    "nessus-scan-create": [],
    "nessus-get-scans-editors": [],
    "scan-export-status": [],
    "nessus-scan-export-status": [],
    "nessus-scan-status": []
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

**Release Notes**
```json
null
```

### Tenable.io

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "api_keys",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials_access_key.password": "access_key",
        "credentials_secret_key.password": "secret_key"
      }
    }
  ],
  "other_connection": ["proxy", "unsecure", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "Tenable Vulnerability Management (formerly Tenable.io)",
  "commands": {
    "test-module": ["assetsFetchInterval"],
    "fetch-events": ["first_fetch", "max_fetch"],
    "tenable-io-list-scans": [],
    "tenable-io-launch-scan": [],
    "tenable-io-get-scan-report": [],
    "tenable-io-get-vulnerability-details": [],
    "tenable-io-get-vulnerabilities-by-asset": [],
    "tenable-io-get-scan-status": [],
    "tenable-io-resume-scan": [],
    "tenable-io-pause-scan": [],
    "tenable-io-get-asset-details": [],
    "tenable-io-export-assets": [],
    "tenable-io-export-vulnerabilities": [],
    "tenable-io-list-scan-filters": [],
    "tenable-io-get-scan-history": [],
    "tenable-io-export-scan": [],
    "tenable-io-get-audit-logs": []
  }
}
```

**Params for test with default in code**
```json
{
  "max_fetch": 1000,
  "first_fetch": "7 days",
  "assetsFetchInterval": 720
}
```

**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Assets and Vulnerabilities": [],
  "Log Collection": ["first_fetch", "max_fetch"],
  "general_configurations": []
}
```

**Release Notes**
```json
null
```

### Tenable.sc

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "creds_keys",
      "xsoar_param_map": {
        "creds_keys.identifier": "access_key",
        "creds_keys.password": "secret_key"
      },
      "interpolated": true
    },
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["proxy", "server", "unsecure"]
}
```

**Params to Commands**
```json
{
  "integration": "Tenable.sc",
  "commands": {
    "test-module": ["assetsFetchInterval"],
    "fetch-incidents": ["fetch_time"],
    "tenable-sc-create-asset": [],
    "tenable-sc-create-policy": [],
    "tenable-sc-create-remediation-scan": [],
    "tenable-sc-create-scan": [],
    "tenable-sc-create-user": [],
    "tenable-sc-delete-asset": [],
    "tenable-sc-delete-scan": [],
    "tenable-sc-delete-user": [],
    "tenable-sc-get-alert": [],
    "tenable-sc-get-all-scan-results": [],
    "tenable-sc-get-asset": [],
    "tenable-sc-get-device": [],
    "tenable-sc-get-organization": [],
    "tenable-sc-get-scan-report": [],
    "tenable-sc-get-scan-status": [],
    "tenable-sc-get-system-information": [],
    "tenable-sc-get-system-licensing": [],
    "tenable-sc-get-vulnerability": [],
    "tenable-sc-launch-scan": [],
    "tenable-sc-list-alerts": [],
    "tenable-sc-list-assets": [],
    "tenable-sc-list-credentials": [],
    "tenable-sc-list-groups": [],
    "tenable-sc-list-plugin-family": [],
    "tenable-sc-list-policies": [],
    "tenable-sc-list-query": [],
    "tenable-sc-list-report-definitions": [],
    "tenable-sc-list-repositories": [],
    "tenable-sc-list-scans": [],
    "tenable-sc-list-users": [],
    "tenable-sc-list-zones": [],
    "tenable-sc-update-asset": [],
    "tenable-sc-update-user": []
  }
}
```

**Params for test with default in code**
```json
{
  "fetch_time": "3 days",
  "assetsFetchInterval": 720
}
```

**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Assets and Vulnerabilities": [],
  "Fetch Issues": ["fetch_time"],
  "general_configurations": []
}
```

**Release Notes**
```json
null
```

### McAfeeDAM

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
  "other_connection": ["secure", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "McAfee DAM",
  "commands": {
    "test-module": [],
    "fetch-incidents": ["batchSize", "ruleName"],
    "dam-get-alert-by-id": [],
    "dam-get-latest-by-rule": []
  }
}
```

**Params for test with default in code**
```json
{
  "batchSize": 100
}
```

**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Issues": ["batchSize", "ruleName"],
  "general_configurations": []
}
```

**Release Notes**
```json
null
```

---

## File changes

### Content repo — `git status --short`

The only file this batch modified is **`connectus/connectus-migration-pipeline.csv`** (written exclusively via `workflow_state.py` CLI setters). The untracked `capabilities_output.json` is a transient scratch file emitted by `capabilities_collector.py`.

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
?? connectus/.summary_ctx.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/
```

> **Attribution note:** The 22 modified `Packs/.../*.py` files and the other untracked entries (`connectus/.batch10_contexts.jsonl`, `connectus/.summary_ctx.json`, `connectus/_split_assignments.py`, `connectus/migration-prompts/`) were **NOT** produced by this batch — they pre-existed in the working tree from other branches/sessions. This batch's only writes were to `connectus/connectus-migration-pipeline.csv` (CSV state, via CLI) and the `capabilities_output.json` scratch file. `connectus/migration-summaries/` is newly created to hold this summary.

### Content repo — `git diff --stat`

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

### unified-connectors-content (sibling repo)

```
(git status --short: empty — no changes)
(git diff --stat: empty)
```

**Connector folders created/modified under `connectors/`:** **None persisted.** A `connectors/ibm-security/` folder was generated *once* for IBMMaaS360Security, but `manifest_generator.py` (with `CONNECTUS_REPO_DIR` unset) wrote it into a stray `content/unified-connectors-content/` instead of the real sibling repo. That stray directory was deleted; the subsequent attempt to write to the real sibling repo (`/Users/jlevy/dev/demisto/unified-connectors-content`) was blocked by the sandbox, so the sibling repo remains clean and contains no `ibm-security` (or any new) connector folder.

---

## Blockers / follow-ups

1. **All step-8+ work is outstanding (by design).** Per the mid-session "skip all steps after 7" instruction, no manifests were generated/validated, no handler-param-coverage / param-parity / precommit / Release Notes ran. These remain to be done for all 11 integrations.

2. **`CONNECTUS_REPO_DIR` is not set in the root `.env`.** Because it was unset, `manifest_generator.py` resolved its connectors root to `content/unified-connectors-content` (a non-existent stray location) instead of the sibling repo. Before resuming step 8, set:
   ```
   CONNECTUS_REPO_DIR=/Users/jlevy/dev/demisto/unified-connectors-content
   ```
   I could **not** edit `.env` this session — writes to it are sandbox-restricted (one-shot deny). The user must add this line manually.

3. **Sandbox blocks writes to the sibling `unified-connectors-content` repo.** Manifest generation / validate / handler-coverage all read/write that repo (outside the `content/` working dir). Resuming steps 8+ requires the operator to approve writes to `/Users/jlevy/dev/demisto/unified-connectors-content`.

4. **`interpolated: true` is set on every profile of every integration.** This is the documented ALWAYS-INTERPOLATE GATE behavior (`set-auth` forces it and short-circuits the parity test). It is *not* a per-integration fallback decision — no integration required a manual interpolation override beyond this gate, and no `--force` was used anywhere.

5. **IBMSecurityGuardium auth re-work.** `report_id` (a required test-module param) had to be elevated to `other_connection`, which required a second `set-auth` (wiped/cleared downstream) plus a `reset-to "Params to Commands"` to re-do steps 4–7 with `report_id` removed from the command lists. Final state is consistent.

6. **Static-analyzer blind spots — heavy reliance on manual source-tracing (needs human review).** Dynamic (Docker) analysis was unavailable all session (`docker pull` failed: `/Users/jlevy/.docker/config.json: operation not permitted`). Consequently:
   - **JavaScript integrations** (Nessus, McAfeeDAM): analyzer skips entirely (Python-only); params mapped purely from manual JS review.
   - **`async def main()`** (IBM Storage Scale): handler resolution failed ("no top-level main()"); params mapped from source review.
   - **`main()` / module-level `params` global blind spots** (SplunkPy, SplunkPy v2, IBM/Tenable fetch params): the analyzer returned empty/partial per-command lists; param→command attributions were derived via deep transitive source-tracing (helper call chains, module-level constants). These attributions, especially for SplunkPy and SplunkPy v2 (27 commands each), warrant a human spot-check.

7. **Tenable.sc `credentials.identifier` suppression nuance.** `credentials` is `hiddenusername: true`, so its identifier leaf is omitted from `xsoar_param_map` per the mechanical suppression rule — even though the Python login code (L3273) actively reads `credentials.identifier` as the username. The username is expected to be interpolated at runtime. Worth a reviewer confirmation that the UCP connection supplies it.

8. **`McAfeeDAM` insecure/secure mismatch (informational).** The JS reads `params.insecure` (L41) but the YML param is named `secure` (validate certificate). Mapped `secure` into `other_connection`. Does not affect auth classification but flagged for awareness.

---

## Reproduce

```bash
git checkout jl-connectus-migration-02
```

Integration IDs for this batch (in work order):

```
["IBMMaaS360Security", "IBMSecurityGuardium", "IBMSecurityVerify", "XFE_v2", "IBM Storage Scale", "SplunkPy", "SplunkPy v2", "Nessus", "Tenable.io", "Tenable.sc", "McAfeeDAM"]
```

Resume any integration with:

```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"
```

(Run from the idex parent cwd that contains `content/` and `unified-connectors-content/` as siblings. In this session the runnable Python was `.venv/bin/python connectus/workflow_state.py ...` from inside the `content/` working dir.)
