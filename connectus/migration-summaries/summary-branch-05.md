# ConnectUs Migration — Branch 05 Summary

| Field | Value |
|---|---|
| **Branch number** | 05 (of 13) |
| **Git branch (batch)** | `jl-connectus-migration-05` |
| **Git HEAD at write time** | `jl-connectus-migration-01` (HEAD was switched outside this session; CSV/code edits live in the shared working tree and are branch-independent) |
| **Assignee** | jlevypaloalto |
| **Date/time (UTC)** | 2026-06-15T11:30:23Z |
| **Total integrations in this branch** | 10 (across 5 connectors) |

> **Scope note:** Per an in-session decision, work stopped after the **pre-manifest** steps (through Step 7, *Params to Capabilities*). Step 8 (*generated manifest*) and everything downstream were **not** run because the sandbox denies writes to the sibling `../unified-connectors-content/` repo that the manifest generator targets. Every integration is therefore uniformly at **step #8 (generated manifest), 7/15 complete** — i.e. all reachable pre-manifest work is done.

---

## Per-integration table

| Integration ID | Connector ID | Auth type(s) classified | Furthest step reached | Status | Notes |
|---|---|---|---|---|---|
| BitSight Event Collector | BitSight | `Plain` | generated manifest (#8/15) | ⏳ in-progress | `credentials.identifier`→username only (password leaf suppressed via `hiddenpassword: true`; code uses `HTTPBasicAuth(api_key, "")`). Code fix: `max_fetch` default. |
| CapeSandbox | CAPESandbox | `APIKey` + `Plain` (XOR) | generated manifest (#8/15) | ⏳ in-progress | Two mutually-exclusive profiles: API token vs. username/password. `token_credentials.identifier` suppressed (`hiddenusername`). No code fix. |
| Netmiko | Netmiko | `Passthrough` | generated manifest (#8/15) | ⏳ in-progress | SSH auth (key + passphrase + user/pass used together → multi-secret). Code fix: `port` default `"22"`. |
| FireEye Central Management | Trellix Network | `Plain` | generated manifest (#8/15) | ⏳ in-progress | Username/password → FireEye token endpoint (X-FeApi-Token, via FireEyeApiModule). Code fix: `proxy` default. |
| FireEyeHelix | Trellix Network | `Passthrough` | generated manifest (#8/15) | ⏳ in-progress | API key with dual source (modern widget + legacy flat). Initially `APIKey` but schema rejected two fields→`key`; reclassified `Passthrough`. Code fixes: `proxy`, `fetch_time`, `isFetch` defaults. |
| McAfeeNSMv2 | Trellix Network | `Plain` | generated manifest (#8/15) | ⏳ in-progress | base64 `user:pass` → session endpoint → session token. `version` is product-version metadata. No code fix. |
| fireeye | Trellix Network | `Passthrough` | generated manifest (#8/15) | ⏳ in-progress | JavaScript integration. User/pass (login→X-FeApi-Token) **and** client token (X-FeClient-Token) used together → multi-secret. No code fix (JS not analyzed for param-defaults). |
| VMware | VMware Automation and Colection | `Plain` | generated manifest (#8/15) | ⏳ in-progress | vSphere `SmartConnect(user=…, pwd=…)`. UCP review "uncertain" items were command args (not config params) — cleared by manual review. No code fix. |
| VMware Carbon Black EDR v2 | VMware Automation and Colection | `APIKey` | generated manifest (#8/15) | ⏳ in-progress | `credentials.password`→key (X-Auth-Token; identifier suppressed). `test-module` consumes 4 fetch params → mapped to `general_configurations`. Code fix: `params["isFetch"]`→`params.get("isFetch")`. |
| VMware Workspace ONE UEM (AirWatch MDM) | VMware Automation and Colection | `Passthrough` | generated manifest (#8/15) | ⏳ in-progress | HTTP Basic auth **and** `aw-tenant-code` API-key header used together → multi-secret. API key dual source (widget + legacy flat). No code fix. |

**Tally:** 0 ✅ complete · 10 ⏳ in-progress · 0 ⛔ blocked. (All 10 reached the agreed pre-manifest stopping point; none failed a checkpoint.)

---

## Workflow-data written (read back via `context`)

### BitSight Event Collector

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": { "credentials.identifier": "username" },
      "interpolated": true
    }
  ],
  "other_connection": ["base_url", "guid", "insecure", "proxy"]
}
```

**Params to Commands**
```json
{
  "commands": {
    "bitsight-get-events": [],
    "fetch-events": [],
    "test-module": []
  },
  "integration": "BitSight Event Collector"
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{ "Log Collection": [], "general_configurations": [] }
```

**Release Notes** — not set (empty).

---

### CapeSandbox

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_token",
      "xsoar_param_map": { "token_credentials.password": "key" },
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
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "commands": {
    "cape-cuckoo-status-get": [],
    "cape-file-submit": [],
    "cape-file-view": [],
    "cape-machines-list": [],
    "cape-pcap-file-download": [],
    "cape-sample-download": [],
    "cape-task-delete": [],
    "cape-task-poll": [],
    "cape-task-report-get": [],
    "cape-task-screenshot-download": [],
    "cape-tasks-list": [],
    "cape-url-submit": [],
    "test-module": []
  },
  "integration": "Cape Sandbox"
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

**Release Notes** — not set (empty).

---

### Netmiko

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "credentials.credentials.sshkey": "ssh_key"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["TimeoutOverride", "hostname", "platform", "port"]
}
```

**Params to Commands**
```json
{
  "commands": {
    "netmiko-cmds": [],
    "test-module": []
  },
  "integration": "Netmiko"
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

**Release Notes** — not set (empty).

---

### FireEye Central Management

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
  "commands": {
    "fetch-incidents": [],
    "fireeye-cm-alert-acknowledge": [],
    "fireeye-cm-delete-quarantined-emails": [],
    "fireeye-cm-download-quarantined-emails": [],
    "fireeye-cm-get-alert-details": [],
    "fireeye-cm-get-alerts": [],
    "fireeye-cm-get-artifacts-by-uuid": [],
    "fireeye-cm-get-artifacts-metadata-by-uuid": [],
    "fireeye-cm-get-events": [],
    "fireeye-cm-get-quarantined-emails": [],
    "fireeye-cm-get-reports": [],
    "fireeye-cm-release-quarantined-emails": [],
    "test-module": []
  },
  "integration": "FireEye Central Management"
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{ "Automation": [], "Fetch Issues": [], "general_configurations": [] }
```

**Release Notes** — not set (empty).

---

### FireEyeHelix

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "api_key",
      "xsoar_param_map": {
        "h_id_creds.password": "api_key",
        "token": "api_key_legacy",
        "h_id_creds.identifier": "customer_id",
        "h_id": "customer_id_legacy"
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
    "fetch-incidents": [],
    "fireeye-helix-add-list-item": [],
    "fireeye-helix-alert-create-note": [],
    "fireeye-helix-alert-delete-note": [],
    "fireeye-helix-alert-get-notes": [],
    "fireeye-helix-archive-search": [],
    "fireeye-helix-archive-search-get-results": [],
    "fireeye-helix-archive-search-get-status": [],
    "fireeye-helix-create-list": [],
    "fireeye-helix-delete-list": [],
    "fireeye-helix-edit-rule": [],
    "fireeye-helix-get-alert-by-id": [],
    "fireeye-helix-get-cases-by-alert": [],
    "fireeye-helix-get-endpoints-by-alert": [],
    "fireeye-helix-get-events-by-alert": [],
    "fireeye-helix-get-list-by-id": [],
    "fireeye-helix-get-list-items": [],
    "fireeye-helix-get-lists": [],
    "fireeye-helix-list-alerts": [],
    "fireeye-helix-list-rules": [],
    "fireeye-helix-list-sensors": [],
    "fireeye-helix-remove-list-item": [],
    "fireeye-helix-search": [],
    "fireeye-helix-update-list": [],
    "fireeye-helix-update-list-item": [],
    "test-module": []
  },
  "integration": "FireEye Helix"
}
```

**Params for test with default in code**
```json
{}
```

**Params to Capabilities**
```json
{ "Automation": [], "Fetch Issues": [], "general_configurations": [] }
```

**Release Notes** — not set (empty).

---

### McAfeeNSMv2

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
    "nsm-assign-device-policy": [],
    "nsm-assign-interface-policy": [],
    "nsm-create-firewall-policy": [],
    "nsm-create-rule-object": [],
    "nsm-delete-firewall-policy": [],
    "nsm-delete-rule-object": [],
    "nsm-deploy-device-configuration": [],
    "nsm-export-pcap-file": [],
    "nsm-get-alert-details": [],
    "nsm-get-alerts": [],
    "nsm-get-attacks": [],
    "nsm-get-device-configuration": [],
    "nsm-get-domains": [],
    "nsm-get-firewall-policy": [],
    "nsm-get-ips-policies": [],
    "nsm-get-ips-policy-details": [],
    "nsm-get-rule-object": [],
    "nsm-get-sensors": [],
    "nsm-list-device-interface": [],
    "nsm-list-device-policy": [],
    "nsm-list-domain-device": [],
    "nsm-list-domain-firewall-policy": [],
    "nsm-list-domain-rule-object": [],
    "nsm-list-interface-policy": [],
    "nsm-list-pcap-file": [],
    "nsm-update-alerts": [],
    "nsm-update-firewall-policy": [],
    "nsm-update-rule-object": [],
    "test-module": []
  },
  "integration": "McAfee NSM v2"
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

**Release Notes** — not set (empty).

---

### fireeye

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "credentials_client_token.password": "client_token",
        "clientToken": "client_token_legacy"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "proxy", "server", "version"]
}
```

**Params to Commands**
```json
{
  "commands": {
    "fe-alert": [],
    "fe-config": [],
    "fe-report": [],
    "fe-submit": [],
    "fe-submit-result": [],
    "fe-submit-status": [],
    "fe-submit-url": [],
    "fe-submit-url-result": [],
    "fe-submit-url-status": [],
    "test-module": []
  },
  "integration": "FireEye (AX Series)"
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

**Release Notes** — not set (empty).

---

### VMware

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
  "other_connection": ["insecure", "proxy", "redirect_std_out", "url"]
}
```

**Params to Commands**
```json
{
  "commands": {
    "test-module": [],
    "vmware-change-nic-state": [],
    "vmware-clone-vm": [],
    "vmware-create-snapshot": [],
    "vmware-create-vm": [],
    "vmware-delete-vm": [],
    "vmware-get-events": [],
    "vmware-get-vms": [],
    "vmware-hard-reboot": [],
    "vmware-list-vms-by-tag": [],
    "vmware-poweroff": [],
    "vmware-poweron": [],
    "vmware-register-vm": [],
    "vmware-relocate-vm": [],
    "vmware-revert-snapshot": [],
    "vmware-soft-reboot": [],
    "vmware-suspend": [],
    "vmware-unregister-vm": []
  },
  "integration": "VMware"
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

**Release Notes** — not set (empty).

---

### VMware Carbon Black EDR v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "credentials",
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
  "commands": {
    "cb-edr-alert-search": [],
    "cb-edr-alert-update": [],
    "cb-edr-binary-ban": [],
    "cb-edr-binary-bans-list": [],
    "cb-edr-binary-download": [],
    "cb-edr-binary-search": [],
    "cb-edr-binary-summary": [],
    "cb-edr-process-events-list": [],
    "cb-edr-process-get": [],
    "cb-edr-process-segments-get": [],
    "cb-edr-processes-search": [],
    "cb-edr-quarantine-device": [],
    "cb-edr-sensor-installer-download": [],
    "cb-edr-sensors-list": [],
    "cb-edr-unquarantine-device": [],
    "cb-edr-watchlist-create": [],
    "cb-edr-watchlist-delete": [],
    "cb-edr-watchlist-update": [],
    "cb-edr-watchlist-update-action": [],
    "cb-edr-watchlists-list": [],
    "endpoint": [],
    "fetch-incidents": [],
    "test-module": ["alert_feed_name", "alert_query", "alert_status", "isFetch"]
  },
  "integration": "VMware Carbon Black EDR v2"
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
  "general_configurations": ["alert_feed_name", "alert_query", "alert_status", "isFetch"]
}
```

**Release Notes** — not set (empty).

---

### VMware Workspace ONE UEM (AirWatch MDM)

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "aw_tenant_code_creds.password": "api_key",
        "aw_tenant_code": "api_key_legacy"
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
    "vmwuem-device-get": [],
    "vmwuem-device-os-updates-list": [],
    "vmwuem-devices-search": []
  },
  "integration": "VMware Workspace ONE UEM (AirWatch MDM)"
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

**Release Notes** — not set (empty).

---

## File changes

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
 M connectus/connectus-migration-pipeline.csv
?? capabilities_output.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
```

> **Attribution:** This branch-05 session edited exactly **6** files — the pipeline CSV (via the `workflow_state.py` CLI, never by hand) plus **5** integration `.py` files for UCP param-default hardening:
> - `connectus/connectus-migration-pipeline.csv` (all 10 integrations' workflow-data + checkpoints)
> - `Packs/BitSight/Integrations/BitSightEventCollector/BitSightEventCollector.py`
> - `Packs/Carbon_Black_Enterprise_Response/Integrations/CarbonBlackResponseV2/CarbonBlackResponseV2.py`
> - `Packs/FireEyeCM/Integrations/FireEyeCM/FireEyeCM.py`
> - `Packs/FireEyeHelix/Integrations/FireEyeHelix/FireEyeHelix.py`
> - `Packs/Netmiko/Integrations/Netmiko/Netmiko.py`
>
> All **other** `M` entries above (ArcherV2, Bmc*, DigitalGuardian, Exabeam*, Feed*, Forcepoint, MailListener*, Netskope, Rapid7, SAP, TheHive) are pre-existing edits from **prior** migration batches present in the shared working tree — **not** modified by this session. The untracked `capabilities_output.json` is an incidental stray output from the capabilities collector's default path; `connectus/_split_assignments.py` and `connectus/migration-prompts/` are also pre-existing/unrelated to this session.

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

### This-session code diffs (the 5 `.py` hardening fixes)

```diff
# BitSightEventCollector.py
-    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
+    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH)) or DEFAULT_MAX_FETCH

# CarbonBlackResponseV2.py (test_module)
-        if params["isFetch"]:
+        if params.get("isFetch"):

# FireEyeCM.py (main)
-    proxy = argToBoolean(params.get("proxy"))
+    proxy = argToBoolean(params.get("proxy", "false"))

# FireEyeHelix.py (main)
-    proxy = params.get("proxy")
+    proxy = params.get("proxy", False)
-            fetch_time = params.get("fetch_time")
-            is_fetch = params.get("isFetch")
+            fetch_time = params.get("fetch_time", "3 days")
+            is_fetch = params.get("isFetch", False)
-            fetch_time = params.get("fetch_time")   # fetch-incidents branch
+            fetch_time = params.get("fetch_time", "3 days")

# Netmiko.py (main)
-    port = params.get("port")
+    port = params.get("port") or "22"
```

### unified-connectors-content repo

**Not touched.** The sibling `../unified-connectors-content/` repo exists but was **not modified** — the manifest-generation step (Step 8) that writes connector folders under `connectors/` was not run (sandbox denies writes outside the content repo).

**Connector folders created/modified under `connectors/`:** none.

---

## Blockers / follow-ups

1. **Step 8+ blocked by sandbox (all 10 integrations).** The manifest generator writes into `../unified-connectors-content/connectors/<slug>` and the sandbox denies external-directory writes. Steps 8–15 (generated manifest, handler param coverage, validate, param parity, code reviewed, code merged, precommit/validate/unit tests, Release Notes) all remain **to-do** and must be run from a non-sandboxed environment.
2. **`interpolated: true` on every profile (all 10).** This is **not** a manual fallback decision — `set-auth` forces `interpolated: true` onto every `auth_types[]` entry by design (the ALWAYS-INTERPOLATE GATE), and short-circuits the parity test. No profile was hand-marked; no parity diff was resolved. No `--force` was used anywhere.
3. **FireEyeHelix auth reclassification.** Originally modeled as `APIKey` with two fields both → `key`; the schema rejected this (`OPA Check 17` — duplicate role in an `APIKey` profile). Reclassified to `Passthrough` with distinct role names (`api_key`, `api_key_legacy`, `customer_id`, `customer_id_legacy`). Worth a human glance to confirm the legacy flat fields (`token`, `h_id`) should still be carried into the ConnectUs connector vs. dropped as deprecated.
4. **Dual-source / multi-secret auth (FireEyeHelix, fireeye, AirWatch MDM).** All three carry both a modern credentials-widget field and a legacy flat field for the same secret, plus (for fireeye/AirWatch) two distinct credential sets used together. Modeled as `Passthrough` per cross-cutting #2. Confirm during code review that the legacy `*_legacy` role fields are desired.
5. **`fireeye` is JavaScript.** Static param analysis and the UCP param-default checker are Python-only, so both were skipped (reported `pass: true` / "not analyzed"). Params-to-Commands/Capabilities were filled by manual review (no command-specific non-auth params). No code-default hardening possible/needed.
6. **VMware UCP "uncertain" items.** The param-default checker flagged 3 `<dynamic>` reads at `VMware.py:139-141`; manual review confirmed these are **command arguments** (`args.get(...)`, guarded by `if "x" in args`), not config params — cleared as safe, no fix needed.
7. **Stray file.** `capabilities_output.json` was written to the repo root by an early capabilities-collector run that used its default output path (later runs used explicit `-o /tmp/...`). It is untracked and can be deleted; it was not intentionally created by this session and was left untouched per the "do not modify other files" instruction.
8. **Uncommitted.** None of the 6 edited files were committed; they remain in the working tree for review.

---

## Reproduce

**Git branch:**
```bash
git checkout jl-connectus-migration-05
```

**Integration IDs (this batch, in work order):**
```json
["BitSight Event Collector", "CapeSandbox", "Netmiko", "FireEye Central Management", "FireEyeHelix", "McAfeeNSMv2", "fireeye", "VMware", "VMware Carbon Black EDR v2", "VMware Workspace ONE UEM (AirWatch MDM)"]
```

**Resume a single integration** (run from the idex parent cwd that contains `content/` as a sibling):
```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"
```
(In this session the CLI was invoked from the content-repo root as `python3 connectus/workflow_state.py ...` using the repo venv interpreter `./.venv/bin/python`, because `yaml`/deps are only present there.)

**Connectors covered (5):** BitSight · CAPESandbox · Netmiko · Trellix Network (FireEye Central Management, FireEyeHelix, McAfeeNSMv2, fireeye) · VMware Automation and Colection (VMware, VMware Carbon Black EDR v2, VMware Workspace ONE UEM (AirWatch MDM)).
