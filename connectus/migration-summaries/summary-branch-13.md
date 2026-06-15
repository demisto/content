# ConnectUs Migration Summary — Branch 13

| Field | Value |
|---|---|
| **Branch number** | 13 of 13 |
| **Git branch (at session start)** | `jl-connectus-migration-13` |
| **Git branch (current, renamed mid-session)** | `jl-connectus-migration-01` |
| **Assignee** | `jlevypaloalto` |
| **Date/time (UTC)** | 2026-06-15 11:32 UTC |
| **Total integrations in this branch** | 10 |
| **Connectors** | Fortra (2), Gamma.AI (1), MISP (3), SAP (3), TheHive (1) |

> **Scope note:** This session executed steps 1–7 of the 15-step workflow for all 10
> integrations. Steps 8–15 (generate manifest, handler param coverage, validate, param
> parity, code review/merge, pre-commit, release notes) were **deferred** because the
> sandbox denies all access to the sibling `unified-connectors-content` repo (see
> Blockers). No connector folders were created.

---

## Per-integration table

State pulled authoritatively from `python3 content/connectus/workflow_state.py context "<id>"`.

| Integration ID | Connector ID | Auth type(s) classified | Furthest workflow step reached | Status | Notes |
|---|---|---|---|---|---|
| DigitalGuardianARCEventCollector | Fortra | `Passthrough` (OAuth2 client_credentials) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. Code fix at `.py:279` for `export_calls_per_fetch` default. |
| Tripwire | Fortra | `Plain` (HTTP Basic Auth) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. |
| Gamma | Gamma.AI | `APIKey` (X-API-Key) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. Pattern #7: hidden legacy `api_key` dropped. |
| FeedMISPThreatActors | MISP | `NoneRequired` (public feed) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. No credentials; `auth_types: []`. |
| MISP Feed | MISP | `Passthrough` (API token + optional mTLS cert, AND-lumped) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. Code fix at `.py:652` for `timeout` default. |
| MISP V3 | MISP | `Passthrough` (API key + optional mTLS cert, AND-lumped) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. |
| SAP-IAM | SAP | `Plain` (HTTP Basic Auth, IAMApiModule) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. `deactivate_uri` in other_connection. |
| SAPBTP | SAP | `Passthrough` ×2 (XOR: Non-mTLS vs mTLS client_credentials) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. `auth_type` selector implicit (dropped); `client_id` shared across both profiles. |
| SAPCloudForCustomerC4C | SAP | `Plain` (HTTP Basic Auth) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. `report_id` elevated to connection (other_connection); re-applied set-auth. Code fix at `.py:485` for `max_fetch` default. |
| TheHive Project | TheHive | `APIKey` (Bearer token) | generated manifest (#8/15) | ⏳ in-progress | 7/15 complete. Pattern #7: hidden legacy `apiKey` dropped; `mirror` hidden on platform (excluded). Code fix at `.py:868` for `max_fetch` default. |

**Tally:** 0 ✅ complete · 10 ⏳ in-progress · 0 ⛔ blocked (all reached step 8 boundary; further progress blocked by environment — see Blockers).

---

## Workflow-data written

All values read back via `context "<id>"` (the persisted CSV cells). `Release Notes` was
not set for any integration (deferred to step 15).

### DigitalGuardianARCEventCollector

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "credentials",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      }
    }
  ],
  "other_connection": ["auth_server_url", "gateway_base_url", "insecure", "proxy"]
}
```

**Params to Commands**
```json
{
  "integration": "DigitalGuardianARCEventCollector",
  "commands": {
    "digital-guardian-get-events": ["export_profile"],
    "fetch-events": ["export_calls_per_fetch", "export_profile"],
    "test-module": ["export_calls_per_fetch", "export_profile"]
  }
}
```

**Params for test with default in code**
```json
{
  "export_profile": "defaultExportProfile",
  "export_calls_per_fetch": 1
}
```

**Params to Capabilities**
```json
{
  "Log Collection": ["export_profile", "export_calls_per_fetch"],
  "general_configurations": []
}
```

**Release Notes**: not set.

### Tripwire

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
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
  "integration": "Tripwire",
  "commands": {
    "tripwire-versions-list": [],
    "tripwire-rules-list": [],
    "tripwire-elements-list": [],
    "tripwire-nodes-list": [],
    "fetch-incidents": ["first_fetch", "max_fetch", "node_oids", "rule_oids"],
    "test-module": ["first_fetch", "isFetch", "node_oids", "rule_oids"]
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
  "Fetch Issues": ["first_fetch", "max_fetch", "node_oids", "rule_oids"],
  "general_configurations": ["isFetch"]
}
```

**Release Notes**: not set.

### Gamma

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "credentials_api_key",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials_api_key.password": "key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "Gamma",
  "commands": {
    "gamma-get-violation-list": [],
    "gamma-get-violation": [],
    "gamma-update-violation": [],
    "fetch-incidents": ["first_fetch", "max_fetch"],
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
  "Fetch Issues": ["first_fetch", "max_fetch"],
  "general_configurations": []
}
```

**Release Notes**: not set.

### FeedMISPThreatActors

**Auth Details**
```json
{
  "auth_types": [],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "FeedMISPThreatActors",
  "commands": {
    "mispthreatactors-get-indicators": [],
    "fetch-indicators": [],
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

**Release Notes**: not set.

### MISP Feed

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "MISP Feed authentication",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.password": "key",
        "certificate.identifier": "client_cert",
        "certificate.password": "private_key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "timeout", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "MISP Feed",
  "commands": {
    "misp-feed-get-indicators": ["performance"],
    "fetch-indicators": ["attribute_tags", "attribute_types", "max_indicator_to_fetch", "performance", "query"],
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
  "Threat Intelligence & Enrichment": ["performance", "attribute_tags", "attribute_types", "max_indicator_to_fetch", "query"],
  "general_configurations": []
}
```

**Release Notes**: not set.

### MISP V3

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "MISP V3 authentication",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.password": "key",
        "certificate.identifier": "client_cert",
        "certificate.password": "private_key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "MISP V3",
  "commands": {
    "misp-search-events": [],
    "domain": ["allowed_orgs", "attributes_limit", "benign_tag_ids", "check_to_ids", "integrationReliability", "malicious_tag_ids", "search_warninglists", "suspicious_tag_ids"],
    "email": ["allowed_orgs", "attributes_limit", "benign_tag_ids", "check_to_ids", "integrationReliability", "malicious_tag_ids", "search_warninglists", "suspicious_tag_ids"],
    "file": ["allowed_orgs", "attributes_limit", "benign_tag_ids", "check_to_ids", "integrationReliability", "malicious_tag_ids", "search_warninglists", "suspicious_tag_ids"],
    "url": ["allowed_orgs", "attributes_limit", "benign_tag_ids", "check_to_ids", "integrationReliability", "malicious_tag_ids", "search_warninglists", "suspicious_tag_ids"],
    "ip": ["allowed_orgs", "attributes_limit", "benign_tag_ids", "check_to_ids", "integrationReliability", "malicious_tag_ids", "search_warninglists", "suspicious_tag_ids"],
    "misp-create-event": [],
    "misp-add-attribute": [],
    "misp-delete-event": [],
    "misp-remove-tag-from-event": [],
    "misp-add-tag-to-event": [],
    "misp-add-tag-to-attribute": [],
    "misp-remove-tag-from-attribute": [],
    "misp-add-sighting": [],
    "misp-add-events-from-feed": [],
    "misp-add-file-object": [],
    "misp-add-email-object": [],
    "misp-add-domain-object": [],
    "misp-add-url-object": [],
    "misp-add-object": [],
    "misp-add-custom-object": [],
    "misp-add-ip-object": [],
    "misp-search-attributes": [],
    "misp-update-attribute": [],
    "misp-delete-attribute": [],
    "misp-publish-event": [],
    "misp-set-event-attributes": [],
    "misp-check-warninglist": [],
    "misp-add-user": [],
    "misp-get-organization-info": [],
    "misp-get-role-info": [],
    "misp-get-warninglist": [],
    "misp-get-warninglists": [],
    "misp-change-warninglist": [],
    "test-module": ["attributes_limit", "malicious_tag_ids", "suspicious_tag_ids"]
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
  "Automation": ["allowed_orgs", "attributes_limit", "benign_tag_ids", "check_to_ids", "integrationReliability", "malicious_tag_ids", "search_warninglists", "suspicious_tag_ids"],
  "general_configurations": []
}
```

**Release Notes**: not set.

### SAP-IAM

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      }
    }
  ],
  "other_connection": ["deactivate_uri", "insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "SAP-IAM",
  "commands": {
    "iam-get-user": ["mapper_in"],
    "iam-disable-user": ["disable_user_enabled", "mapper_in"],
    "get-mapping-fields": [],
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
  "Automation": ["mapper_in", "disable_user_enabled"],
  "general_configurations": []
}
```

**Release Notes**: not set.

### SAPBTP

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "Client Credentials",
      "interpolated": true,
      "xsoar_param_map": {
        "client_id": "client_id",
        "client_secret.password": "client_secret"
      }
    },
    {
      "type": "Passthrough",
      "name": "mTLS Client Credentials",
      "interpolated": true,
      "xsoar_param_map": {
        "client_id": "client_id",
        "certificate": "certificate",
        "private_key": "private_key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "token_url", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "SAPBTP",
  "commands": {
    "sap-btp-get-events": [],
    "fetch-events": ["max_fetch"],
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
  "Log Collection": ["max_fetch"],
  "general_configurations": []
}
```

**Release Notes**: not set.

### SAPCloudForCustomerC4C

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "username",
      "interpolated": true,
      "xsoar_param_map": {
        "username.identifier": "username",
        "username.password": "password"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "report_id", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "SAPCloudForCustomerC4C",
  "commands": {
    "sap-cloud-get-events": [],
    "fetch-events": ["max_fetch"],
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
  "Log Collection": ["max_fetch"],
  "general_configurations": []
}
```

**Release Notes**: not set.

### TheHive Project

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "credentials_api_key",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials_api_key.password": "key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "TheHive Project",
  "commands": {
    "thehive-list-cases": [],
    "thehive-get-case": [],
    "thehive-search-cases": [],
    "thehive-update-case": [],
    "thehive-create-case": [],
    "thehive-create-task": [],
    "thehive-remove-case": [],
    "thehive-get-linked-cases": [],
    "thehive-merge-cases": [],
    "thehive-get-case-tasks": [],
    "thehive-get-task": [],
    "thehive-get-attachment": [],
    "thehive-update-task": [],
    "thehive-list-users": [],
    "thehive-get-user": [],
    "thehive-create-local-user": [],
    "thehive-block-user": [],
    "thehive-list-observables": [],
    "thehive-create-observable": [],
    "thehive-update-observable": [],
    "get-mapping-fields": [],
    "get-remote-data": [],
    "thehive-get-version": [],
    "get-modified-remote-data": [],
    "test-module": [],
    "fetch-incidents": ["fetch_closed", "first_fetch", "look_back", "max_fetch"]
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
  "Fetch Issues": ["fetch_closed", "first_fetch", "look_back", "max_fetch"],
  "general_configurations": []
}
```

**Release Notes**: not set.

---

## File changes

### Code edits made by THIS batch (4 defensive default fixes)

These were needed to pass the **UCP param-default review** (step 6). Each makes a
`arg_to_number(params.get(...))` read explicitly default-safe under ConnectUs (where an
optional param may arrive absent). The functional behavior is unchanged (the existing
`or <N>` already produced the same value); the edit also silences the param-default
analyzer's provable-break flag.

```
 Packs/DigitalGuardian/Integrations/DigitalGuardianARCEventCollector/DigitalGuardianARCEventCollector.py | 2 +-   (line 279: export_calls_per_fetch default)
 Packs/FeedMISP/Integrations/FeedMISP/FeedMISP.py                                                        | 2 +-   (line 652: timeout default)
 Packs/SAPCloudForCustomerC4C/Integrations/SAPCloudForCustomerC4C/SAPCloudForCustomerC4C.py              | 2 +-   (line 485: max_fetch default)
 Packs/TheHiveProject/Integrations/TheHiveProject/TheHiveProject.py                                      | 2 +-   (line 868: max_fetch default)
 4 files changed, 4 insertions(+), 4 deletions(-)
```

Plus the workflow state tracking file (written exclusively via the `workflow_state.py`
CLI, never edited directly): `connectus/connectus-migration-pipeline.csv`.

### `git status --short` (full content-repo working tree)

> NOTE: This working tree contains many pre-existing modifications from **other**
> migration batches (Archer, BitSight, BmcITSM, CarbonBlack, Exabeam, FeedDHS,
> FeedElasticsearch, FireEye, Forcepoint, MailListener, Netmiko, Netskope, Rapid7,
> etc.). Those are **not** part of branch 13. The branch-13 changes are the 4 `.py`
> files listed above + `connectus-migration-pipeline.csv`.

```
 M Packs/ArcherRSA/Integrations/ArcherV2/ArcherV2.py
 M Packs/BitSight/Integrations/BitSightEventCollector/BitSightEventCollector.py
 M Packs/BmcHelixRemedyForce/Integrations/BmcHelixRemedyForce/BmcHelixRemedyForce.py
 M Packs/BmcITSM/Integrations/BmcITSM/BmcITSM.py
 M Packs/Carbon_Black_Enterprise_Response/Integrations/CarbonBlackResponseV2/CarbonBlackResponseV2.py
 M Packs/DigitalGuardian/Integrations/DigitalGuardianARCEventCollector/DigitalGuardianARCEventCollector.py   <-- branch 13
 M Packs/Exabeam/Integrations/Exabeam/Exabeam.py
 M Packs/ExabeamSecurityOperationsPlatform/Integrations/ExabeamSecOpsPlatform/ExabeamSecOpsPlatform.py
 M Packs/FeedDHS/Integrations/DHSFeedV2/DHSFeedV2.py
 M Packs/FeedDHS/Integrations/DHS_Feed/DHS_Feed.py
 M Packs/FeedElasticsearch/Integrations/FeedElasticsearch/FeedElasticsearch.py
 M Packs/FeedMISP/Integrations/FeedMISP/FeedMISP.py                                                          <-- branch 13
 M Packs/FireEyeCM/Integrations/FireEyeCM/FireEyeCM.py
 M Packs/FireEyeHelix/Integrations/FireEyeHelix/FireEyeHelix.py
 M Packs/ForcepointDLP/Integrations/ForcepointEventCollector/ForcepointEventCollector.py
 M Packs/MailListener/Integrations/MailListenerV2/MailListenerV2.py
 M Packs/MailListener_-_POP3/Integrations/MailListener_POP3/MailListener_POP3.py
 M Packs/Netmiko/Integrations/Netmiko/Netmiko.py
 M Packs/Netskope/Integrations/NetskopeAPIv2/NetskopeAPIv2.py
 M Packs/Rapid7_Nexpose/Integrations/Rapid7_Nexpose/Rapid7_Nexpose.py
 M Packs/SAPCloudForCustomerC4C/Integrations/SAPCloudForCustomerC4C/SAPCloudForCustomerC4C.py               <-- branch 13
 M Packs/TheHiveProject/Integrations/TheHiveProject/TheHiveProject.py                                       <-- branch 13
 M connectus/connectus-migration-pipeline.csv                                                               <-- branch 13 (via CLI)
?? capabilities_output.json
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/                                                                          <-- this summary
```

### `git diff --stat` (full content-repo working tree)

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

**Not touched.** No connector folders were created or modified under `connectors/`.
Step 8 (`manifest_generator.py`) — which would scaffold the connector folders (e.g.
`connectors/fortra`, `connectors/gamma.ai`, `connectors/misp`, `connectors/sap`,
`connectors/thehive`) — could not run because the sandbox denies all access to
`/Users/jlevy/dev/demisto/unified-connectors-content`.

---

## Blockers / follow-ups

1. **⛔ Cross-repo access blocked (the headline blocker).** Steps 8–15 require write
   access to the sibling repo `/Users/jlevy/dev/demisto/unified-connectors-content`.
   The sandbox permission policy denies every read/write/`cd` outside
   `/Users/jlevy/dev/demisto/content`. `manifest_generator.py` crashed with
   `PermissionError: [Errno 1] Operation not permitted` at
   `connectors/fortra` mkdir. **To resume:** grant access to the UCC path (or set
   `CONNECTUS_REPO_DIR` in the root `.env` to an accessible location). This blocks
   manifest generation, handler param coverage, validate, param parity, code
   review/merge, pre-commit, and release notes for **all 10** integrations.

2. **`interpolated: true` on every classified profile.** This is the standard
   ALWAYS-INTERPOLATE gate (`set-auth` forces it), not a per-integration fallback —
   applied to all profiles for DigitalGuardianARC, Tripwire, Gamma, MISP Feed, MISP V3,
   SAP-IAM, SAPBTP (both profiles), SAPCloudForCustomerC4C, and TheHive Project.
   FeedMISPThreatActors has no profiles (`NoneRequired`), so the flag does not apply.
   No profile was marked interpolated as a *custom* escape-valve fallback beyond the
   standard gate.

3. **4 code edits to pass UCP param-default review (step 6).** Defensive `.get(param,
   default)` additions (see File changes). These should be re-validated with
   `demisto-sdk pre-commit` once step 14 can run. Functionally equivalent to the
   pre-existing `or <N>` fallbacks; low risk.

4. **SAPCloudForCustomerC4C — `report_id` elevated to connection.** The param mapper
   flagged `report_id` (required, no default, consumed by `test-module`) as an
   elevated/connection param. It was moved into `Auth Details.other_connection` via a
   second `set-auth` (which reset to step 5, preserving Params to Commands), and
   removed from `Params to Commands` to keep the columns disjoint. No human review
   needed, but note the auth cell was written twice.

5. **No `--force` overrides were used.** All checkpoints passed without forcing.

6. **UNCERTAIN param-default findings reviewed and accepted as safe** (no code change):
   `MISP Feed` (`feedReputation`, `tlp_color` — `Optional[str]`, passed through
   `build_indicators` with no strict conversion); `MISP V3` (`check_to_ids` — truthiness
   check, None≡False); `SAP-IAM` (`disable_user_enabled` — falsy is "disable not
   enabled"); `SAPBTP` (`<dynamic>` @ `.py:316` — exception-guarded integration-context
   cache read, not a config param); `SAPCloudForCustomerC4C` (`report_id` — required,
   platform-supplied, now in other_connection).

7. **Docker-based dynamic analyzer unavailable** (Docker Hub unauthenticated pull-rate
   limit). All Step 4 analyzer runs used `--static-only`; per-command params for fetch
   loops / `main()` pre-dispatch reads were attributed via manual source review (cited
   in the per-integration approvals during the session).

---

## Reproduce

**Git branch (intended for this batch):**

```bash
git checkout -b jl-connectus-migration-13
```

> The live branch was renamed to `jl-connectus-migration-01` mid-session; treat this
> batch as branch **13** regardless of the current branch name.

**Integration IDs (in work order):**

```json
["DigitalGuardianARCEventCollector", "Tripwire", "Gamma", "FeedMISPThreatActors", "MISP Feed", "MISP V3", "SAP-IAM", "SAPBTP", "SAPCloudForCustomerC4C", "TheHive Project"]
```

**To resume each integration from step 8** (once UCC access is granted), run from the
idex parent cwd (the dir containing `content/` and `unified-connectors-content/`):

```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"
```

All 10 are currently at **step #8 (generated manifest), 7/15 complete**.
