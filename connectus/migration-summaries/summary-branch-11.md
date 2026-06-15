# ConnectUs Migration — Branch 11 Summary

| Field | Value |
|---|---|
| **Branch number** | 11 |
| **Git branch (intended)** | `jl-connectus-migration-11` (created this session; HEAD has since been switched to `jl-connectus-migration-01` externally — see Reproduce) |
| **Assignee** | `jlevypaloalto` |
| **Date/time (UTC)** | 2026-06-15T11:35:33Z |
| **Total integrations in this branch** | 10 |

> **Scope note.** Per the operator decision this session, all 10 integrations were
> taken through the pre-manifest steps (Step 0 → Step 7 `Params to Capabilities`)
> and **paused at Step 8 (generated manifest)**. Manifest generation and everything
> downstream are blocked because the sandbox denies writes to the sibling
> `../unified-connectors-content/` repo (and `.env` has no `CONNECTUS_REPO_DIR`).
> JSON-write confirmation prompts were waived for the session ("run straight through").

---

## Per-integration table

State pulled authoritatively from `workflow_state.py context "<id>"` for each row.

| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step reached | Status | Notes |
|---|---|---|---|---|---|
| CitrixCloud | Citrix | OAuth2ClientCreds | generated manifest (#8/15) | ⏳ in-progress | 7/15. OAuth2 client_credentials grant. |
| CitrixDaas | Citrix | OAuth2ClientCreds | generated manifest (#8/15) | ⏳ in-progress | 7/15. Same Citrix Cloud OAuth as CitrixCloud; adds `site_name`. |
| Docusign | DocuSign | OAuth2JWT | generated manifest (#8/15) | ⏳ in-progress | 7/15. JWT-bearer + one-time consent flow; `verify_connection_skip: true`. |
| Forcepoint | Forcepoint | Plain | generated manifest (#8/15) | ⏳ in-progress | 7/15. JavaScript integration; HTTP Basic. |
| Forcepoint Security Management Center | Forcepoint | APIKey | generated manifest (#8/15) | ⏳ in-progress | 7/15. API key in `credentials.password`. |
| Forcepoint DLP Event Collector | Forcepoint | Plain | generated manifest (#8/15) | ⏳ in-progress | 7/15. Username/password → session token. **Code edit** (defensive `max_fetch` default). |
| RSA Archer v2 | RSA | Plain | generated manifest (#8/15) | ⏳ in-progress | 7/15. SOAP session login. **Code edit** (defensive `fetch_limit` default). |
| RSA NetWitness Endpoint | RSA | Plain | generated manifest (#8/15) | ⏳ in-progress | 7/15. HTTP Basic auth. |
| RSA NetWitness Security Analytics | RSA | Plain | generated manifest (#8/15) | ⏳ in-progress | 7/15. JavaScript integration; form login. Legacy flat `username`/`password` left unmapped (see Blockers). |
| SpamhausFeed | Samhaus | NoneRequired | generated manifest (#8/15) | ⏳ in-progress | 7/15. Public feed, no credentials. |

Tally: **0 complete / 10 in-progress / 0 blocked** (all stopped at the Step 8 gate by operator choice; Step 8 itself is environmentally blocked — see Blockers).

---

## Workflow-data written

Read back via `context "<id>"`. Columns not set (`Release Notes` for all) are noted.

### CitrixCloud

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "credentials",
      "xsoar_param_map": {
        "client_id": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["customer_id", "insecure", "max_fetch", "proxy", "url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "citrix-cloud-get-events": [],
    "fetch-events": [],
    "test-module": []
  },
  "integration": "Citrix Cloud"
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
**Release Notes**: not set (`null`).

### CitrixDaas

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "credentials",
      "xsoar_param_map": {
        "client_id": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["customer_id", "insecure", "max_fetch", "proxy", "site_name", "url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "citrix-daas-get-events": [],
    "fetch-events": [],
    "test-module": []
  },
  "integration": "Citrix DaaS"
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
**Release Notes**: not set (`null`).

### Docusign

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "OAuth2JWT",
      "name": "jwt",
      "xsoar_param_map": {
        "integration_key": "client_id",
        "user_id": "subject",
        "credentials.password": "private_key",
        "redirect_url": "redirect_uri"
      },
      "interpolated": true,
      "verify_connection_skip": true
    }
  ],
  "other_connection": ["account_id", "insecure", "max_user_events_per_fetch", "organization_id", "proxy", "url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "docusign-auth-test": ["event_types"],
    "docusign-generate-consent-url": ["event_types"],
    "docusign-get-events": [],
    "docusign-reset-access-token": [],
    "fetch-events": ["event_types"],
    "test-module": []
  },
  "integration": "Docusign"
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
  "Log Collection": [],
  "general_configurations": ["event_types"]
}
```
**Release Notes**: not set (`null`).

### Forcepoint

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
  "other_connection": ["insecure", "proxy", "url", "versionCheck"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "fp-add-address-to-category": [],
    "fp-add-category": [],
    "fp-delete-address-from-category": [],
    "fp-delete-categories": [],
    "fp-get-category-detailes": [],
    "fp-list-categories": [],
    "test-module": []
  },
  "integration": "Forcepoint Web Security"
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
**Release Notes**: not set (`null`).

### Forcepoint Security Management Center

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.password": "key"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["insecure", "port", "proxy", "url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "forcepoint-smc-domain-create": [],
    "forcepoint-smc-domain-delete": [],
    "forcepoint-smc-domain-list": [],
    "forcepoint-smc-engine-list": [],
    "forcepoint-smc-firewall-policy-create": [],
    "forcepoint-smc-firewall-policy-delete": [],
    "forcepoint-smc-firewall-policy-list": [],
    "forcepoint-smc-host-create": [],
    "forcepoint-smc-host-delete": [],
    "forcepoint-smc-host-list": [],
    "forcepoint-smc-host-update": [],
    "forcepoint-smc-ip-list-create": [],
    "forcepoint-smc-ip-list-delete": [],
    "forcepoint-smc-ip-list-list": [],
    "forcepoint-smc-ip-list-update": [],
    "forcepoint-smc-policy-template-list": [],
    "forcepoint-smc-rule-create": [],
    "forcepoint-smc-rule-delete": [],
    "forcepoint-smc-rule-list": [],
    "forcepoint-smc-rule-update": [],
    "test-module": []
  },
  "integration": "Forcepoint Security Management Center"
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
**Release Notes**: not set (`null`).

### Forcepoint DLP Event Collector

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
  "other_connection": ["first_fetch", "insecure", "max_fetch", "proxy", "url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "fetch-events": [],
    "forcepoint-dlp-get-events": [],
    "test-module": []
  },
  "integration": "Forcepoint DLP Event Collector (Beta)"
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
  "Log Collection": [],
  "general_configurations": []
}
```
**Release Notes**: not set (`null`).

### RSA Archer v2

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
  "other_connection": ["api_endpoint", "insecure", "instanceName", "proxy", "timeout", "url", "userDomain"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "archer-create-record": [],
    "archer-delete-record": [],
    "archer-execute-statistic-search-by-report": [],
    "archer-get-application-fields": [],
    "archer-get-field": [],
    "archer-get-file": [],
    "archer-get-mapping-by-level": [],
    "archer-get-record": [],
    "archer-get-reports": [],
    "archer-get-search-options-by-guid": [],
    "archer-get-valuelist": [],
    "archer-list-users": [],
    "archer-print-cache": [],
    "archer-reset-cache": [],
    "archer-search-applications": [],
    "archer-search-records": [],
    "archer-search-records-by-report": [],
    "archer-update-record": [],
    "archer-upload-file": [],
    "fetch-incidents": ["applicationDateField", "applicationId", "fetch_limit", "fetch_time", "fetch_xml", "fields_to_fetch"],
    "test-module": ["applicationDateField", "applicationId", "fetch_limit", "fetch_time", "fetch_xml", "fields_to_fetch", "isFetch"]
  },
  "integration": "RSA Archer v2"
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
  "Fetch Issues": ["fetch_limit", "fetch_time", "fetch_xml", "fields_to_fetch"],
  "general_configurations": ["isFetch"]
}
```
**Release Notes**: not set (`null`).

### RSA NetWitness Endpoint

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
  "other_connection": ["insecure", "proxy", "server"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "netwitness-blacklist-domains": [],
    "netwitness-blacklist-ips": [],
    "netwitness-get-machine": [],
    "netwitness-get-machine-iocs": [],
    "netwitness-get-machine-module": [],
    "netwitness-get-machine-modules": [],
    "netwitness-get-machines": [],
    "test-module": []
  },
  "integration": "RSA NetWitness Endpoint"
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
**Release Notes**: not set (`null`).

### RSA NetWitness Security Analytics

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
  "other_connection": ["proxy", "url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "fetch-incidents": [],
    "netwitness-im-add-events-to-incident": [],
    "netwitness-im-create-incident": [],
    "netwitness-im-get-alert-details": [],
    "netwitness-im-get-alert-original": [],
    "netwitness-im-get-alerts": [],
    "netwitness-im-get-available-assignees": [],
    "netwitness-im-get-components": [],
    "netwitness-im-get-event-details": [],
    "netwitness-im-get-events": [],
    "netwitness-im-get-incident-details": [],
    "netwitness-im-list-incidents": [],
    "netwitness-im-login": [],
    "netwitness-im-update-incident": [],
    "nw-add-events-to-incident": [],
    "nw-create-incident": [],
    "nw-get-alert-details": [],
    "nw-get-alert-original": [],
    "nw-get-alerts": [],
    "nw-get-available-assignees": [],
    "nw-get-components": [],
    "nw-get-event-details": [],
    "nw-get-events": [],
    "nw-get-incident-details": [],
    "nw-list-incidents": [],
    "nw-login": [],
    "nw-update-incident": [],
    "test-module": []
  },
  "integration": "RSA NetWitness Security Analytics"
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
**Release Notes**: not set (`null`).

### SpamhausFeed

**Auth Details**
```json
{
  "auth_types": [],
  "other_connection": ["insecure", "polling_timeout", "proxy", "url"]
}
```
**Params to Commands**
```json
{
  "commands": {
    "spamhaus-get-indicators": [],
    "test-module": []
  },
  "integration": "Spamhaus Feed"
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
**Release Notes**: not set (`null`).

---

## File changes

> The working tree contains many modifications carried over from prior
> branches/sessions. **Only two source edits were made by this session:**
> `Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py` and
> `Packs/ForcepointDLP/Integrations/ForcepointEventCollector/ForcepointEventCollector.py`,
> plus the state file `connectus/connectus-migration-pipeline.csv` (written
> exclusively via the `workflow_state.py` CLI). All other listed files are
> pre-existing changes NOT made by this session.

**No `unified-connectors-content` changes** — Step 8 (manifest generation) was
blocked, so **no connector folders were created or modified** under
`connectors/`.

### `git status --short` (content repo)
```
 M Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py                              <-- THIS SESSION
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
 M Packs/ForcepointDLP/Integrations/ForcepointEventCollector/ForcepointEventCollector.py   <-- THIS SESSION
 M Packs/MailListener/Integrations/MailListenerV2/MailListenerV2.py
 M Packs/MailListener_-_POP3/Integrations/MailListener_POP3/MailListener_POP3.py
 M Packs/Netmiko/Integrations/Netmiko/Netmiko.py
 M Packs/Netskope/Integrations/NetskopeAPIv2/NetskopeAPIv2.py
 M Packs/Rapid7_Nexpose/Integrations/Rapid7_Nexpose/Rapid7_Nexpose.py
 M Packs/SAPCloudForCustomerC4C/Integrations/SAPCloudForCustomerC4C/SAPCloudForCustomerC4C.py
 M Packs/TheHiveProject/Integrations/TheHiveProject/TheHiveProject.py
 M connectus/connectus-migration-pipeline.csv                                     <-- THIS SESSION (via CLI)
?? capabilities_output.json
?? connectus/.batch10_contexts.jsonl
?? connectus/.summary_ctx.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/                                                 <-- THIS SESSION (this file)
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

### This session's source edits (the only Packs/ edits owned here)
- `Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py:1698`
  `arg_to_number(params.get("fetch_limit")) or 10` → `arg_to_number(params.get("fetch_limit") or 10)`
- `Packs/ForcepointDLP/Integrations/ForcepointEventCollector/ForcepointEventCollector.py:294`
  `arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH` → `arg_to_number(params.get("max_fetch") or DEFAULT_MAX_FETCH)`

Both are behavior-preserving defensive fixes to satisfy the UCP param-default
review (the strict converter `arg_to_number()` could receive `None` under
ConnectUs when the param arrives absent).

---

## Blockers / follow-ups

1. **Step 8 (generated manifest) environmentally blocked — affects all 10.**
   `manifest_generator.py` must create the connector folder under
   `../unified-connectors-content/connectors/<slug>`, but the sandbox denies all
   writes outside the content repo (`PermissionError: Operation not permitted`).
   Additionally `.env` has no `CONNECTUS_REPO_DIR`. To resume Step 8 → Step 10,
   grant write access to that sibling repo (and set `CONNECTUS_REPO_DIR`), or run
   the manifest/handler-coverage/validate steps outside the sandbox.

2. **`interpolated: true` on every profile.** This is forced by `set-auth`
   (ALWAYS-INTERPOLATE gate) and is not a manual fallback — applied to all
   classified profiles by construction. No per-integration override decision was
   needed.

3. **Docusign `verify_connection_skip: true`** — set deliberately: auth requires a
   one-time browser consent (`docusign-generate-consent-url`) before the JWT
   exchange can succeed, so the connection cannot be auto-verified at test time.

4. **RSA NetWitness Security Analytics — legacy auth params left unmapped.**
   The integration exposes both a modern `credentials` (type 9) widget and
   deprecated flat `username` (type 0) + `password` (type 4) params; the JS prefers
   `credentials` and falls back to the flat pair. Classified `Plain` on the
   canonical `credentials` widget only. The schema rejected mapping both sources to
   the same role (OPA Check 17 — duplicate role in a `Plain` profile), so the legacy
   flat `username`/`password` are NOT in the auth map or `other_connection`.
   **Human review at the manifest stage:** confirm handler-param-coverage (Step 9)
   is satisfied, or decide whether the deprecated flat params should be dropped from
   the YML.

5. **No `--force` was used anywhere.** UCP param-default UNSAFE flags
   (Forcepoint DLP `max_fetch`, RSA Archer `fetch_limit`) were resolved by
   upstream code fixes, not overrides. RSA Archer's three UNCERTAIN items
   (`applicationId`, `applicationDateField` — required params read via `params[...]`;
   `fetch_xml` — optional, guarded) were reviewed and judged safe before `markpass`.

6. **Release Notes / pre-commit pending.** Two `.py` edits were made (item under
   File changes). When the workflow reaches Step 14 (precommit/validate/unit tests)
   and Step 15 (Release Notes), those will need a pre-commit run + RN entries for
   the ArcherRSA and ForcepointDLP packs.

---

## Reproduce

**Git branch (intended for this batch):**
```bash
git checkout jl-connectus-migration-11
```

**Integration IDs (in work order):**
```json
["CitrixCloud", "CitrixDaas", "Docusign", "Forcepoint", "Forcepoint Security Management Center", "Forcepoint DLP Event Collector", "RSA Archer v2", "RSA NetWitness Endpoint", "RSA NetWitness Security Analytics", "SpamhausFeed"]
```

**Resume each from its current state:**
```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"
```
(All 10 are at Step #8 `generated manifest`, 7/15 complete.)
