# ConnectUs Migration - Branch 10 Summary

- **Branch number:** 10 (of 13)
- **Git branch (working):** `jl-connectus-migration-10`
- **Assignee:** jlevypaloalto
- **Date/time:** 2026-06-15 11:39:45 UTC
- **Total integrations in this branch:** 10
- **Connectors:** Cisco DUO (2), CybelAngel (1), F5 (3), PhishLabs (3), Retarus (1)

> **Scope note:** This session completed the **content-repo workflow steps (0-7)** for every integration. Steps 8-15 (generated manifest, handler param coverage, validate, param parity, code review/merge, pre-commit, Release Notes) require write access to the `unified-connectors-content` repo, which the execution sandbox denied - so every integration is parked at the **#8 generated manifest** gate. See **Blockers / follow-ups**.

## Per-integration status

| Integration ID | Connector ID | Auth type(s) | Furthest step (name + #/15) | Status | Notes |
|---|---|---|---|---|---|
| DUO Admin | Cisco DUO | Passthrough | generated manifest (#8/15) | (blocked) UCP gate | ikey+skey HMAC signing (two secrets together) -> Passthrough. No behavioral config params. Capabilities write needed re-apply (transient CSV-write miss caught by verification). |
| Duo Event Collector | Cisco DUO | Passthrough | generated manifest (#8/15) | (blocked) UCP gate | ikey+skey HMAC -> Passthrough. Mapper elevated `after`+`limit` to other_connection -> required set-auth re-apply + re-walk of steps 5-7 (Params to Capabilities did NOT survive the set-auth reset in this CLI version; re-applied). |
| CybelAngel Event Collector | CybelAngel | OAuth2ClientCreds | generated manifest (#8/15) | (blocked) UCP gate | OAuth2 client_credentials -> token endpoint. `arg_to_number(...) or <default>` max_fetch* flags were static false-positives (provably safe). |
| F5 ASM | F5 | Plain | generated manifest (#8/15) | (blocked) UCP gate | user/pass -> /mgmt/shared/authn/login -> session token. 53 commands, all with no behavioral params. |
| F5 firewall | F5 | Plain | generated manifest (#8/15) | (blocked) UCP gate | JavaScript integration. user/pass via Basic auth OR login-token (advancedLogin toggle, kept in other_connection). Analyzed with --static-only. |
| F5Silverline | F5 | APIKey | generated manifest (#8/15) | (blocked) UCP gate | Static X-Authorization-Token (APIKey). Auth write needed re-apply (transient CSV-write miss caught by verification). |
| PhishLabs IOC | PhishLabs | Plain | generated manifest (#8/15) | (blocked) UCP gate | HTTP Basic (Plain). integrationReliability -> other_connection. fetch_time/fetch_limit code-traced to fetch-incidents (static missed positional pass-through). |
| PhishLabs IOC DRP | PhishLabs | Plain | generated manifest (#8/15) | (blocked) UCP gate | HTTP Basic (Plain). fetch params code-traced; recorded YML defaults (fetchTime/fetchByDate/fetchLimit) per branch-(a). |
| PhishLabs IOC EIR | PhishLabs | Plain | generated manifest (#8/15) | (blocked) UCP gate | HTTP Basic (Plain). integrationReliability -> other_connection. test-module reads fetchTime (static-detected); fetch-incidents params code-traced. |
| Retarus Secure Email Gateway | Retarus | APIKey | generated manifest (#8/15) | (blocked) UCP gate | Static Bearer token over websocket (APIKey). channel -> other_connection (connection endpoint selector). fetch_interval has code+YML default 60 (branch-c). |

_Status legend:_ complete (all 15 steps) / in-progress / blocked. All 10 are **blocked** at step #8 because steps 8+ need the unified-connectors-content repo (inaccessible in this sandbox). All content-side data columns (steps 2-7) are committed.

## Workflow-data written (read back via `context`)

Each integration's committed workflow-data columns, read directly from the CSV via `workflow_state.py context`. `Release Notes` was not set for any integration (Step 15 is downstream of the UCP gate).

### DUO Admin

**Auth Details:**

```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials_key.identifier": "integration_key",
        "credentials_key.password": "secret_key",
        "integration_key": "integration_key",
        "secret_key": "secret_key"
      },
      "interpolated": true
    }
  ],
  "other_connection": [
    "hostname",
    "insecure",
    "proxy"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "DUO Admin",
  "commands": {
    "duoadmin-associate-device-to-user": [],
    "duoadmin-delete-u2f-token": [],
    "duoadmin-dissociate-device-from-user": [],
    "duoadmin-get-admins": [],
    "duoadmin-get-authentication-logs-by-user": [],
    "duoadmin-get-bypass-codes": [],
    "duoadmin-get-devices": [],
    "duoadmin-get-devices-by-user": [],
    "duoadmin-get-u2f-tokens-by-user": [],
    "duoadmin-get-users": [],
    "duoadmin-modify-admin": [],
    "duoadmin-modify-user": [],
    "test-module": []
  }
}
```

**Params for test with default in code:**

```json
{}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### Duo Event Collector

**Auth Details:**

```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "credentials",
      "xsoar_param_map": {
        "integration_key": "integration_key",
        "secret_key.password": "secret_key"
      },
      "interpolated": true
    }
  ],
  "other_connection": [
    "after",
    "host",
    "limit",
    "proxy"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "Duo Event Collector",
  "commands": {
    "duo-get-events": [
      "after",
      "fetch_delay",
      "limit",
      "logs_type_array",
      "retries"
    ],
    "fetch-events": [
      "after",
      "fetch_delay",
      "limit",
      "logs_type_array",
      "retries"
    ],
    "test-module": [
      "after",
      "fetch_delay",
      "limit",
      "logs_type_array",
      "retries"
    ]
  }
}
```

**Params for test with default in code:**

```json
{
  "fetch_delay": 0
}
```

**Params to Capabilities:**

```json
{
  "Log Collection": [
    "fetch_delay",
    "logs_type_array",
    "retries"
  ],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### CybelAngel Event Collector

**Auth Details:**

```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "client_id",
        "credentials.password": "client_secret"
      },
      "interpolated": true
    }
  ],
  "other_connection": [
    "insecure",
    "proxy",
    "url"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "CybelAngel Event Collector",
  "commands": {
    "cybelangel-archive-report-by-id-get": [],
    "cybelangel-get-events": [],
    "cybelangel-mirror-report-get": [],
    "cybelangel-report-attachment-get": [],
    "cybelangel-report-comment-create": [],
    "cybelangel-report-comments-get": [],
    "cybelangel-report-get": [],
    "cybelangel-report-list": [],
    "cybelangel-report-remediation-request-create": [],
    "cybelangel-report-status-update": [],
    "fetch-events": [
      "event_types_to_fetch",
      "max_fetch",
      "max_fetch_creds",
      "max_fetch_domain"
    ],
    "test-module": [
      "event_types_to_fetch",
      "max_fetch",
      "max_fetch_creds",
      "max_fetch_domain"
    ]
  }
}
```

**Params for test with default in code:**

```json
{
  "max_fetch": 5000,
  "max_fetch_creds": 50,
  "max_fetch_domain": 500
}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "Log Collection": [
    "event_types_to_fetch",
    "max_fetch",
    "max_fetch_creds",
    "max_fetch_domain"
  ],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### F5 ASM

**Auth Details:**

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
  "other_connection": [
    "insecure",
    "proxy",
    "url"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "F5 ASM",
  "commands": {
    "f5-asm-get-policy-md5": [],
    "f5-asm-policy-apply": [],
    "f5-asm-policy-blocking-settings-list": [],
    "f5-asm-policy-blocking-settings-update": [],
    "f5-asm-policy-cookies-add": [],
    "f5-asm-policy-cookies-delete": [],
    "f5-asm-policy-cookies-list": [],
    "f5-asm-policy-cookies-update": [],
    "f5-asm-policy-create": [],
    "f5-asm-policy-delete": [],
    "f5-asm-policy-export-file": [],
    "f5-asm-policy-file-types-add": [],
    "f5-asm-policy-file-types-delete": [],
    "f5-asm-policy-file-types-list": [],
    "f5-asm-policy-file-types-update": [],
    "f5-asm-policy-gwt-profiles-add": [],
    "f5-asm-policy-gwt-profiles-delete": [],
    "f5-asm-policy-gwt-profiles-list": [],
    "f5-asm-policy-gwt-profiles-update": [],
    "f5-asm-policy-hostnames-add": [],
    "f5-asm-policy-hostnames-delete": [],
    "f5-asm-policy-hostnames-list": [],
    "f5-asm-policy-hostnames-update": [],
    "f5-asm-policy-json-profiles-add": [],
    "f5-asm-policy-json-profiles-delete": [],
    "f5-asm-policy-json-profiles-list": [],
    "f5-asm-policy-json-profiles-update": [],
    "f5-asm-policy-list": [],
    "f5-asm-policy-methods-add": [],
    "f5-asm-policy-methods-delete": [],
    "f5-asm-policy-methods-list": [],
    "f5-asm-policy-methods-update": [],
    "f5-asm-policy-parameters-add": [],
    "f5-asm-policy-parameters-delete": [],
    "f5-asm-policy-parameters-list": [],
    "f5-asm-policy-parameters-update": [],
    "f5-asm-policy-server-technologies-add": [],
    "f5-asm-policy-server-technologies-delete": [],
    "f5-asm-policy-server-technologies-list": [],
    "f5-asm-policy-signatures-list": [],
    "f5-asm-policy-urls-add": [],
    "f5-asm-policy-urls-delete": [],
    "f5-asm-policy-urls-list": [],
    "f5-asm-policy-urls-update": [],
    "f5-asm-policy-whitelist-ips-add": [],
    "f5-asm-policy-whitelist-ips-delete": [],
    "f5-asm-policy-whitelist-ips-list": [],
    "f5-asm-policy-whitelist-ips-update": [],
    "f5-asm-policy-xml-profiles-add": [],
    "f5-asm-policy-xml-profiles-delete": [],
    "f5-asm-policy-xml-profiles-list": [],
    "f5-asm-policy-xml-profiles-update": [],
    "test-module": []
  }
}
```

**Params for test with default in code:**

```json
{}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### F5 firewall

**Auth Details:**

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
  "other_connection": [
    "advancedLogin",
    "insecure",
    "port",
    "proxy",
    "url"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "F5 firewall",
  "commands": {
    "f5-create-policy": [],
    "f5-create-rule": [],
    "f5-del-policy": [],
    "f5-del-rule": [],
    "f5-list-all-user-sessions": [],
    "f5-list-rules": [],
    "f5-modify-global-policy": [],
    "f5-modify-rule": [],
    "f5-show-global-policy": [],
    "test-module": []
  }
}
```

**Params for test with default in code:**

```json
{}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### F5Silverline

**Auth Details:**

```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "credentials",
      "xsoar_param_map": {
        "token.password": "key"
      },
      "interpolated": true
    }
  ],
  "other_connection": [
    "insecure",
    "proxy",
    "url"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "F5Silverline",
  "commands": {
    "f5-silverline-ip-object-add": [],
    "f5-silverline-ip-object-delete": [],
    "f5-silverline-ip-objects-list": [],
    "test-module": []
  }
}
```

**Params for test with default in code:**

```json
{}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### PhishLabs IOC

**Auth Details:**

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
  "other_connection": [
    "insecure",
    "integrationReliability",
    "proxy",
    "url"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "PhishLabs IOC",
  "commands": {
    "fetch-incidents": [
      "fetch_limit",
      "fetch_time"
    ],
    "phishlabs-get-incident-indicators": [],
    "phishlabs-global-feed": [],
    "test-module": []
  }
}
```

**Params for test with default in code:**

```json
{}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "Fetch Issues": [
    "fetch_limit",
    "fetch_time"
  ],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### PhishLabs IOC DRP

**Auth Details:**

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
  "other_connection": [
    "insecure",
    "proxy",
    "url"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "PhishLabs IOC DRP",
  "commands": {
    "fetch-incidents": [
      "fetchByDate",
      "fetchLimit",
      "fetchTime"
    ],
    "phishlabs-ioc-drp-get-case-by-id": [],
    "phishlabs-ioc-drp-get-cases": [],
    "phishlabs-ioc-drp-get-closed-cases": [],
    "phishlabs-ioc-drp-get-open-cases": [],
    "test-module": []
  }
}
```

**Params for test with default in code:**

```json
{
  "fetchByDate": "dateModified",
  "fetchLimit": 20,
  "fetchTime": "1 hours"
}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "Fetch Issues": [
    "fetchByDate",
    "fetchLimit",
    "fetchTime"
  ],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### PhishLabs IOC EIR

**Auth Details:**

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
  "other_connection": [
    "insecure",
    "integrationReliability",
    "proxy",
    "url"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "PhishLabs IOC EIR",
  "commands": {
    "fetch-incidents": [
      "fetchLimit",
      "fetchTime"
    ],
    "phishlabs-ioc-eir-get-incident-by-id": [],
    "phishlabs-ioc-eir-get-incidents": [],
    "test-module": [
      "fetchTime"
    ]
  }
}
```

**Params for test with default in code:**

```json
{
  "fetchLimit": 25,
  "fetchTime": "1 hours"
}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "Fetch Issues": [
    "fetchLimit",
    "fetchTime"
  ],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_

### Retarus Secure Email Gateway

**Auth Details:**

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
  "other_connection": [
    "channel",
    "insecure",
    "url"
  ]
}
```

**Params to Commands:**

```json
{
  "integration": "Retarus Secure Email Gateway",
  "commands": {
    "long-running-execution": [
      "fetch_interval"
    ],
    "retarus-get-last-run-results": [],
    "test-module": []
  }
}
```

**Params for test with default in code:**

```json
{
  "fetch_interval": 60
}
```

**Params to Capabilities:**

```json
{
  "Automation": [],
  "Log Collection": [
    "longRunning",
    "fetch_interval"
  ],
  "general_configurations": []
}
```

**Release Notes:** _(not set)_


## File changes

### Content repo - changes made by THIS session

This session mutated **only** `connectus/connectus-migration-pipeline.csv`, exclusively through the `workflow_state.py` CLI (never edited directly).

```
$ git diff --stat connectus/connectus-migration-pipeline.csv
 connectus/connectus-migration-pipeline.csv | 468 ++++++++++++++++++++---------
 1 file changed, 334 insertions(+), 134 deletions(-)
```

### Other working-tree changes - NOT from this session

The working tree (inherited from the branch state I was started on) also contains ~22 modified `.py` files and several untracked files **unrelated to this batch** (none are among the 10 integrations above). I did **not** touch any of them. Full `git status --short` at session end:

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
?? connectus/.batch10_contexts.jsonl
?? connectus/.batch10_jsonblocks.md
?? connectus/.gen_summary.py
?? connectus/.gitstatus.txt
?? connectus/.idex_ctx_tmp/
?? connectus/_split_assignments.py
?? connectus/migration-prompts/
?? connectus/migration-summaries/
```

Full `git diff --stat` (content repo):

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

Untracked scratch files created during the session (tooling output / summary temp files, not intended deliverables): `capabilities_output.json`, `connectus/.batch10_contexts.jsonl`, `connectus/.batch10_jsonblocks.md`, `connectus/.gitstatus.txt`, `connectus/.gitdiffstat.txt`, `connectus/.idex_ctx_tmp/`, `connectus/.summary_ctx.json`.

### unified-connectors-content repo

**Not touched.** The sandbox denied all access to `/Users/jlevy/dev/demisto/unified-connectors-content`, so **no connector folders were created or modified** under `connectors/`. No manifest generation, validate, or param-parity ran.

## Blockers / follow-ups

- **(BLOCKER) UCP repo inaccessible.** Steps 8-15 for all 10 integrations need access to `unified-connectors-content`. The sandbox is locked to the content repo and denies external-directory access, and `CONNECTUS_REPO_DIR` is unset in the root `.env`. Resume from Step 8 in an environment with that repo present.

- **Dynamic per-command analyzer unavailable.** Docker image pulls failed in-sandbox (`/Users/jlevy/.docker/config.json: operation not permitted` + unauthenticated pull-rate limit), so `check_command_params.py` ran **static-only**. For fetch/event integrations I **manually code-traced** params the static pass missed (positional pass-through via `main()`): Duo Event Collector, CybelAngel EC, all 3 PhishLabs, Retarus. Re-verify with the dynamic spy when Docker is available.

- **`interpolated: true` on every profile.** Set on all 10 (every auth type, incl. APIKey/Plain) - the documented ALWAYS-INTERPOLATE behavior that `set-auth` forces; not a per-integration fallback decision.

- **Param-default static false-positives (no code change).** `arg_to_number(params.get(x)) or <default>` patterns flagged unsafe by the heuristic but provably safe (`arg_to_number(None)` returns `None`, never raises): Duo EC (`fetch_delay`), CybelAngel (`max_fetch`/`max_fetch_creds`/`max_fetch_domain`), Retarus (`fetch_interval`). UCP param-default review passed after verification.

- **Transient CSV-write misses (caught & fixed).** Two setters reported success but didn't persist on first write; verification caught both and they were re-applied: F5Silverline `Auth Details`, DUO Admin `Params to Capabilities`. Final verification confirms all 4 data columns persisted for all 10.

- **`set-auth` reset wiped `Params to Capabilities`** on Duo Event Collector's elevation re-apply (only `Params to Commands` survived the reset cascade in this CLI version). Re-walked steps 5-7. Worth confirming intended behavior.

- No checkpoint required `--force`. No outstanding human-review auth ambiguities.

## Reproduce / resume

```bash
git checkout jl-connectus-migration-10

# Integration IDs in this batch (work order):
["DUO Admin", "Duo Event Collector", "CybelAngel Event Collector", "F5 ASM", "F5 firewall", "F5Silverline", "PhishLabs IOC", "PhishLabs IOC DRP", "PhishLabs IOC EIR", "Retarus Secure Email Gateway"]
```

Each is at step #8; resume with the UCP repo accessible:

```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"   # confirm state
# then run Step 8 (manifest_generator.py) onward per the connectus-migration skill
```