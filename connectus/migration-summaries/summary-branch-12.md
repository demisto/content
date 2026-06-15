# ConnectUs Migration — Branch 12 Summary

| Field | Value |
|---|---|
| **Branch number** | 12 |
| **Git branch (intended)** | `jl-connectus-migration-12` (created at session start; the working-tree branch was later switched to `jl-connectus-migration-01` outside this session) |
| **Assignee** | `jlevypaloalto` |
| **Date/time (UTC)** | 2026-06-15 11:36:04 UTC |
| **Total integrations in branch** | 10 (across 5 connectors: DHS, Endgame, Imperva, Rapid7, SentinelOne) |
| **Scope completed this session** | Pre-manifest workflow steps 0–7 for all 10 integrations; each paused at **Step 8 (generated manifest)** because the manifest/validate steps require writing into the sibling `unified-connectors-content/` repo, which is outside the sandbox. |

---

## Per-integration table

State pulled authoritatively from `python3 content/connectus/workflow_state.py context "<id>"`.

| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step reached | Status | Notes |
|---|---|---|---|---|---|
| DHS Feed | DHS | Passthrough (mTLS: private key + certificate) | generated manifest (8/15)* | ⏳ in-progress | Pre-manifest done (7/15). Code: `collection` default `AIS`; `insecure` strict-converter safety fix. |
| DHS Feed v2 | DHS | Passthrough (mTLS: private key + certificate) | generated manifest (8/15)* | ⏳ in-progress | Pre-manifest done (7/15). Code: `limit`/`limit_per_request` strict-converter safety fixes. |
| Endgame | Endgame | Plain (username/password → JWT) | generated manifest (8/15)* | ⏳ in-progress | JavaScript integration; all-empty Params to Commands. |
| Imperva Skyfence | Imperva | Passthrough (OAuth2 client_credentials) | generated manifest (8/15)* | ⏳ in-progress | JavaScript integration; all-empty Params to Commands. |
| Imperva WAF | Imperva | Plain (HTTP Basic → session cookie) | generated manifest (8/15)* | ⏳ in-progress | Python; all-empty Params to Commands (static analyzer confirmed). |
| Incapsula | Imperva | Passthrough (dual API key: x-API-Id + x-API-Key) | generated manifest (8/15)* | ⏳ in-progress | JavaScript integration; 82 commands, all-empty. |
| Rapid7 InsightIDR | Rapid7 | APIKey (X-Api-Key header) | generated manifest (8/15)* | ⏳ in-progress | `is_multi_customer`/`is_v2` mapped per-command; fetch params on fetch-incidents. |
| Rapid7 Nexpose | Rapid7 | Passthrough (Basic + optional 2FA token) | generated manifest (8/15)* | ⏳ in-progress | Code: `connection_error_retries` safety fix; `token` cross-function read manually reviewed safe. |
| rapid7appsec | Rapid7 | APIKey (X-Api-Key header) | generated manifest (8/15)* | ⏳ in-progress | Python; all-empty Params to Commands. |
| SentinelOneEventCollector | SentinelOne | APIKey (`Authorization: ApiToken`) | generated manifest (8/15)* | ⏳ in-progress | Event collector → Log Collection capability; fetch params mapped. |

\* "generated manifest (8/15)" is the **current step** (the next, not-yet-done step). Each integration has **7/15 steps completed** (`completed_steps: 7`, `current_step_index: 8`, `all_complete: false`). They are in-progress (⏳), not complete, because Step 8 onward is blocked by the sandbox (see Blockers).

---

## Workflow-data written (read back via `context`)

### DHS Feed

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "mtls",
      "xsoar_param_map": {
        "key_creds.password": "private_key",
        "crt_creds.password": "certificate"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["base_url", "insecure", "proxy"]
}
```
**Params to Commands**
```json
{
  "integration": "DHS Feed",
  "commands": {
    "fetch-indicators": ["collection", "feedTags", "first_fetch", "tlp_color"],
    "dhs-get-indicators": ["collection", "feedTags"],
    "test-module": ["collection", "first_fetch"]
  }
}
```
**Params for test with default in code**
```json
{ "collection": "AIS" }
```
**Params to Capabilities**
```json
{
  "Threat Intelligence & Enrichment": ["collection", "feedTags", "first_fetch", "tlp_color"],
  "general_configurations": []
}
```
**Release Notes**: not set (`null`).

### DHS Feed v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "mtls",
      "xsoar_param_map": {
        "key.password": "private_key",
        "certificate": "certificate"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["default_api_root", "insecure", "proxy", "url"]
}
```
**Params to Commands**
```json
{
  "integration": "DHS Feed v2",
  "commands": {
    "fetch-indicators": ["collection_to_fetch", "feedTags", "initial_interval", "limit", "limit_per_request", "objects_to_fetch", "observation_operator_mode", "tlp_color"],
    "dhs-get-indicators": ["collection_to_fetch", "feedTags", "limit_per_request", "objects_to_fetch", "observation_operator_mode", "tlp_color"],
    "dhs-get-collections": [],
    "test-module": ["collection_to_fetch", "initial_interval"]
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
  "Threat Intelligence & Enrichment": ["collection_to_fetch", "feedTags", "initial_interval", "limit", "limit_per_request", "objects_to_fetch", "observation_operator_mode", "tlp_color"],
  "general_configurations": []
}
```
**Release Notes**: not set (`null`).

### Endgame

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "basic",
      "xsoar_param_map": {
        "username.identifier": "username",
        "username.password": "password"
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
  "integration": "Endgame",
  "commands": {
    "endgame-deploy": [],
    "endgame-get-deployment-profiles": [],
    "endgame-get-unmanaged-endpoints": [],
    "endgame-get-endpoint-status": [],
    "endgame-create-sensor-profile": [],
    "endgame-get-investigations": [],
    "endgame-create-investigation": [],
    "endgame-get-sensor": [],
    "endgame-investigation-results": [],
    "endgame-investigation-status": [],
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
{ "Automation": [], "general_configurations": [] }
```
**Release Notes**: not set (`null`).

### Imperva Skyfence

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "client_creds",
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "url"]
}
```
**Params to Commands**
```json
{
  "integration": "Imperva Skyfence",
  "commands": {
    "imp-sf-list-endpoints": [],
    "imp-sf-set-endpoint-status": [],
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
{ "Automation": [], "general_configurations": [] }
```
**Release Notes**: not set (`null`).

### Imperva WAF

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
  "integration": "Imperva WAF",
  "commands": {
    "imperva-waf-ip-group-list": [],
    "imperva-waf-ip-group-list-entries": [],
    "imperva-waf-ip-group-remove-entries": [],
    "imperva-waf-sites-list": [],
    "imperva-waf-server-group-list": [],
    "imperva-waf-server-group-list-policies": [],
    "imperva-waf-web-service-custom-policy-list": [],
    "imperva-waf-web-service-custom-policy-get": [],
    "imperva-waf-ip-group-create": [],
    "imperva-waf-ip-group-update-entries": [],
    "imperva-waf-ip-group-delete": [],
    "imperva-waf-web-service-custom-policy-create": [],
    "imperva-waf-web-service-custom-policy-update": [],
    "imperva-waf-web-service-custom-policy-delete": [],
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
{ "Automation": [], "general_configurations": [] }
```
**Release Notes**: not set (`null`).

### Incapsula

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "dual_api_key",
      "xsoar_param_map": {
        "creds.identifier": "api_id",
        "creds.password": "api_key"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["proxy"]
}
```
**Params to Commands** (82 commands + test-module, all empty)
```json
{
  "integration": "Incapsula",
  "commands": {
    "incap-add-managed-account": [], "incap-list-managed-accounts": [], "incap-add-subaccount": [], "incap-list-subaccounts": [], "incap-get-account-status": [], "incap-modify-account-configuration": [], "incap-set-account-log-level": [], "incap-test-account-s3-connection": [], "incap-test-account-sftp-connection": [], "incap-set-account-s3-log-storage": [], "incap-set-account-sftp-log-storage": [], "incap-set-account-default-log-storage": [], "incap-get-account-login-token": [], "incap-delete-managed-account": [], "incap-delete-subaccount": [], "incap-get-account-audit-events": [], "incap-set-account-default-data-storage-region": [], "incap-get-account-default-data-storage-region": [], "incap-add-site": [], "incap-get-site-status": [], "incap-get-domain-approver-email": [], "incap-modify-site-configuration": [], "incap-modify-site-log-level": [], "incap-modify-site-tls-support": [], "incap-modify-site-scurity-config": [], "incap-modify-site-acl-config": [], "incap-modify-site-wl-config": [], "incap-delete-site": [], "incap-list-sites": [], "incap-get-site-report": [], "incap-get-site-html-injection-rules": [], "incap-add-site-html-injection-rule": [], "incap-delete-site-html-injection-rule": [], "incap-create-new-csr": [], "incap-upload-certificate": [], "incap-remove-custom-integration": [], "incap-move-site": [], "incap-check-compliance": [], "incap-set-site-data-storage-region": [], "incap-get-site-data-storage-region": [], "incap-set-site-data-storage-region-geo-override": [], "incap-get-site-data-storage-region-geo-override": [], "incap-purge-site-cache": [], "incap-modify-cache-mode": [], "incap-purge-resources": [], "incap-modify-caching-rules": [], "incap-set-advanced-caching-settings": [], "incap-purge-hostname-from-cache": [], "incap-site-get-xray-link": [], "incap-list-site-rule-revisions": [], "incap-add-site-rule": [], "incap-edit-site-rule": [], "incap-enable-site-rule": [], "incap-delete-site-rule": [], "incap-list-site-rules": [], "incap-revert-site-rule": [], "incap-set-site-rule-priority": [], "incap-add-site-datacenter": [], "incap-edit-site-datacenter": [], "incap-delete-site-datacenter": [], "incap-list-site-datacenters": [], "incap-add-site-datacenter-server": [], "incap-edit-site-datacenter-server": [], "incap-delete-site-datacenter-server": [], "incap-get-statistics": [], "incap-get-visits": [], "incap-upload-public-key": [], "incap-change-logs-collector-configuration": [], "incap-get-infra-protection-statistics": [], "incap-get-infra-protection-events": [], "incap-add-login-protect": [], "incap-edit-login-protect": [], "incap-get-login-protect": [], "incap-remove-login-protect": [], "incap-send-sms-to-user": [], "incap-modify-login-protect": [], "incap-configure-app": [], "incap-get-ip-ranges": [], "incap-get-texts": [], "incap-get-geo-info": [], "incap-get-app-info": [], "incap-get-infra-protection-top-items-table": [], "test-module": []
  }
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{ "Automation": [], "general_configurations": [] }
```
**Release Notes**: not set (`null`).

### Rapid7 InsightIDR

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_param_map": { "apikey_creds.password": "key" },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "region"]
}
```
**Params to Commands**
```json
{
  "integration": "Rapid7 InsightIDR",
  "commands": {
    "rapid7-insight-idr-list-investigations": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-get-investigation": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-close-investigations": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-assign-user": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-set-status": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-add-threat-indicators": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-replace-threat-indicators": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-list-logs": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-list-log-sets": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-download-logs": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-query-log": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-query-log-set": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-create-investigation": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-update-investigation": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-search-investigation": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-list-investigation-alerts": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-list-investigation-product-alerts": ["is_multi_customer", "is_v2"],
    "rapid7-insight-idr-list-users": ["is_multi_customer", "is_v2"],
    "fetch-incidents": ["first_fetch", "incidentType", "isFetch", "is_multi_customer", "is_v2", "max_fetch"],
    "test-module": ["is_multi_customer", "is_v2"]
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
  "Fetch Issues": ["first_fetch", "incidentType", "isFetch", "max_fetch"],
  "general_configurations": ["is_v2", "is_multi_customer"]
}
```
**Release Notes**: not set (`null`).

### Rapid7 Nexpose

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "basic_2fa",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "token.identifier": "two_factor_token"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["connection_error_retries", "proxy", "server", "unsecure"]
}
```
**Params to Commands** (64 commands + test-module, all empty)
```json
{
  "integration": "Rapid7 Nexpose",
  "commands": {
    "nexpose-get-asset": [], "nexpose-get-asset-tags": [], "nexpose-get-assets": [], "nexpose-search-assets": [], "nexpose-get-scan": [], "nexpose-get-asset-vulnerability": [], "nexpose-create-shared-credential": [], "nexpose-create-site": [], "nexpose-create-vulnerability-exception": [], "nexpose-delete-asset": [], "nexpose-delete-scan-schedule": [], "nexpose-delete-shared-credential": [], "nexpose-delete-site-scan-credential": [], "nexpose-delete-site": [], "nexpose-delete-vulnerability-exception": [], "nexpose-get-sites": [], "nexpose-get-report-templates": [], "nexpose-create-asset": [], "nexpose-create-assets-report": [], "nexpose-create-sites-report": [], "nexpose-create-site-scan-credential": [], "nexpose-create-scan-report": [], "nexpose-create-scan-schedule": [], "nexpose-list-assigned-shared-credential": [], "nexpose-list-vulnerability": [], "nexpose-list-scan-schedule": [], "nexpose-list-shared-credential": [], "nexpose-list-site-scan-credential": [], "nexpose-list-vulnerability-exceptions": [], "nexpose-start-site-scan": [], "nexpose-start-assets-scan": [], "nexpose-stop-scan": [], "nexpose-pause-scan": [], "nexpose-resume-scan": [], "nexpose-get-scans": [], "nexpose-disable-shared-credential": [], "nexpose-download-report": [], "nexpose-enable-shared-credential": [], "nexpose-get-report-status": [], "nexpose-update-scan-schedule": [], "nexpose-update-site-scan-credential": [], "nexpose-update-vulnerability-exception-expiration": [], "nexpose-update-vulnerability-exception-status": [], "nexpose-update-shared-credential": [], "nexpose-create-tag": [], "nexpose-delete-tag": [], "nexpose-list-tag": [], "nexpose-update-tag-search-criteria": [], "nexpose-list-tag-asset-group": [], "nexpose-add-tag-asset-group": [], "nexpose-remove-tag-asset-group": [], "nexpose-list-tag-asset": [], "nexpose-add-tag-asset": [], "nexpose-remove-tag-asset": [], "nexpose-add-site-included-asset": [], "nexpose-remove-site-included-asset": [], "nexpose-list-site-included-asset": [], "nexpose-list-site-included-asset-group": [], "nexpose-add-site-excluded-asset": [], "nexpose-remove-site-excluded-asset": [], "nexpose-list-site-excluded-asset": [], "nexpose-list-site-excluded-asset-group": [], "nexpose-create-asset-group": [], "nexpose-list-asset-group": [], "test-module": []
  }
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{ "Automation": [], "Fetch Assets and Vulnerabilities": [], "general_configurations": [] }
```
**Release Notes**: not set (`null`).

### rapid7appsec

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_param_map": { "api_key.password": "key" },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```
**Params to Commands** (23 commands + test-module, all empty)
```json
{
  "integration": "rapid7appsec",
  "commands": {
    "app-sec-vulnerability-update": [], "app-sec-vulnerability-list": [], "app-sec-vulnerability-history-list": [], "app-sec-vulnerability-comment-create": [], "app-sec-vulnerability-comment-update": [], "app-sec-vulnerability-comment-delete": [], "app-sec-vulnerability-comment-list": [], "app-sec-attack-get": [], "app-sec-attack-documentation-get": [], "app-sec-scan-submit": [], "app-sec-scan-action-get": [], "app-sec-scan-action-submit": [], "app-sec-scan-delete": [], "app-sec-scan-list": [], "app-sec-scan-engine-event-list": [], "app-sec-scan-platform-event-list": [], "app-sec-scan-execution-details-get": [], "app-sec-scan-config-list": [], "app-sec-app-list": [], "app-sec-module-list": [], "app-sec-attack-template-list": [], "app-sec-engine-list": [], "app-sec-engine-group-list": [], "test-module": []
  }
}
```
**Params for test with default in code**
```json
{}
```
**Params to Capabilities**
```json
{ "Automation": [], "general_configurations": [] }
```
**Release Notes**: not set (`null`).

### SentinelOneEventCollector

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
  "integration": "SentinelOneEventCollector",
  "commands": {
    "fetch-events": ["event_type", "fetch_limit", "first_fetch", "isFetch"],
    "sentinelone-get-events": ["event_type", "fetch_limit", "first_fetch"],
    "test-module": ["event_type", "fetch_limit"]
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
  "Log Collection": ["event_type", "fetch_limit", "first_fetch", "isFetch"],
  "general_configurations": []
}
```
**Release Notes**: not set (`null`).

---

## File changes

> **Important:** The working tree was switched to branch `jl-connectus-migration-01` after this session's work, so `git status`/`git diff` below include changes from **other batches** that are not part of branch 12. The files changed by **this session** are limited to:
> - `Packs/FeedDHS/Integrations/DHS_Feed/DHS_Feed.py` (UCP param-default safety: `collection` default `AIS`; `argToBoolean(params.get("insecure", False))`)
> - `Packs/FeedDHS/Integrations/DHSFeedV2/DHSFeedV2.py` (UCP param-default safety: `arg_to_number(params.get("limit", -1))`, `arg_to_number(params.get("limit_per_request", DEFAULT_LIMIT_PER_REQUEST))`)
> - `Packs/Rapid7_Nexpose/Integrations/Rapid7_Nexpose/Rapid7_Nexpose.py` (UCP param-default safety: `connection_error_retries` default)
> - `connectus/connectus-migration-pipeline.csv` (workflow state — written ONLY via `workflow_state.py` CLI, never edited directly)

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
 M Packs/FeedDHS/Integrations/DHSFeedV2/DHSFeedV2.py          <- THIS SESSION
 M Packs/FeedDHS/Integrations/DHS_Feed/DHS_Feed.py            <- THIS SESSION
 M Packs/FeedElasticsearch/Integrations/FeedElasticsearch/FeedElasticsearch.py
 M Packs/FeedMISP/Integrations/FeedMISP/FeedMISP.py
 M Packs/FireEyeCM/Integrations/FireEyeCM/FireEyeCM.py
 M Packs/FireEyeHelix/Integrations/FireEyeHelix/FireEyeHelix.py
 M Packs/ForcepointDLP/Integrations/ForcepointEventCollector/ForcepointEventCollector.py
 M Packs/MailListener/Integrations/MailListenerV2/MailListenerV2.py
 M Packs/MailListener_-_POP3/Integrations/MailListener_POP3/MailListener_POP3.py
 M Packs/Netmiko/Integrations/Netmiko/Netmiko.py
 M Packs/Netskope/Integrations/NetskopeAPIv2/NetskopeAPIv2.py
 M Packs/Rapid7_Nexpose/Integrations/Rapid7_Nexpose/Rapid7_Nexpose.py  <- THIS SESSION
 M Packs/SAPCloudForCustomerC4C/Integrations/SAPCloudForCustomerC4C/SAPCloudForCustomerC4C.py
 M Packs/TheHiveProject/Integrations/TheHiveProject/TheHiveProject.py
 M connectus/connectus-migration-pipeline.csv                <- THIS SESSION (via CLI)
?? capabilities_output.json
?? connectus/.batch10_contexts.jsonl
?? connectus/.summary_ctx.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/                           <- this summary file lives here
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
**Not touched this session.** The Step 8 (generated manifest) onward — which is where connector folders under `connectors/` would be created/modified — could not be reached due to the sandbox blocker (see below). **No connector folders were created or modified.**

---

## Blockers / follow-ups

1. **Sandbox blocks the `unified-connectors-content/` sibling repo (primary blocker).** Step 8 (`manifest_generator.py`) and later steps (handler param coverage, `demisto-sdk validate`, etc.) must write into `../unified-connectors-content/connectors/<slug>/`. The sandbox denies all access outside the content repo (`PermissionError: Operation not permitted` on `../unified-connectors-content/connectors/dhs`). All 10 integrations are therefore parked at Step 8. Per user direction, the pre-manifest steps (0–7) were completed for all 10 and the batch paused before each Step 8.

2. **`interpolated: true` on every profile — by construction, not a fallback for a failed parity test.** Per the ALWAYS-INTERPOLATE GATE, `set-auth` forces `interpolated: true` onto every `auth_types[]` entry and short-circuits the parity test. This applies to all 10 integrations. No profile required a manual `interpolated: true` escape-valve for a *failed* verification; the flag is set by the gate by design.

3. **Rapid7 Nexpose — `token` (2FA) marked manually-reviewed-safe in the UCP param-default review.** `check_param_defaults.py` flagged `token` as UNCERTAIN (cross-function value flow into `fetch_assets_command`). Manual review confirmed it is safe: read in `main()` as `params.get("token", "")` (guarded default), inner `params["token"]` reads execute only when truthy, and the value passed downstream is an already-resolved string. The checker was satisfied via `--ignore-params token`. No `--force` was used anywhere in this batch.

4. **DHS Feed — `collection` default added to code.** Required param with no YML default; `params.get("collection")` had no fallback. Set to `"AIS"` (primary CISA AIS feed; other option `CISCP`) per user confirmation, recorded as `{"collection": "AIS"}` in "Params for test with default in code".

5. **JavaScript integrations (Endgame, Imperva Skyfence, Incapsula).** Static param analyzer is Python-only; Params to Commands were derived by manual source review. UCP param-default review reports "not analyzed: non-Python (javascript)" → PASS by default. Worth a human eyeball if JS-specific param-default behavior is a concern.

6. **Feed/event Params to Commands derived by source review (Docker unavailable).** The dynamic analyzer could not pull/run Docker images in this environment, so DHS Feed, DHS Feed v2, Rapid7 InsightIDR, and SentinelOneEventCollector per-command param lists were derived from static analysis + manual source tracing (err-on-inclusion). These should be validated by the param-parity test (Step 11) once the connectors-repo is reachable.

7. **Remaining steps per integration (8 → 15):** generate manifest + `set-connector-path` + markpass; handler param coverage; `demisto-sdk validate`; param parity test; code reviewed; code merged; precommit/validate/unit tests; Release Notes.

---

## Reproduce

**Git branch:** `jl-connectus-migration-12` (recreate/checkout before resuming)

```bash
git checkout jl-connectus-migration-12   # or: git checkout -b jl-connectus-migration-12
```

**Integration IDs (in batch order):**
```json
["DHS Feed", "DHS Feed v2", "Endgame", "Imperva Skyfence", "Imperva WAF", "Incapsula", "Rapid7 InsightIDR", "Rapid7 Nexpose", "rapid7appsec", "SentinelOneEventCollector"]
```

**Connectors (5):** DHS (2), Endgame (1), Imperva (3), Rapid7 (3), SentinelOne (1).

To resume any integration, run from the idex parent cwd (the dir containing `content/` and `unified-connectors-content/`):
```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"
```
Each is currently at **current step #8 "generated manifest"** (7/15 complete). Resume at Step 8 once the `unified-connectors-content/` repo is writable.
