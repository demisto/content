# ConnectUs Migration — Branch 07 Summary

| Field | Value |
|---|---|
| **Branch number** | 07 (of 13) |
| **Git branch (live)** | `jl-connectus-migration-01` |
| **Intended batch branch** | `jl-connectus-migration-07` (per batch prompt; live working tree is on `jl-connectus-migration-01`) |
| **Assignee** | jlevypaloalto |
| **Generated (UTC)** | 2026-06-15 11:35:28 UTC |
| **Total integrations in this branch** | 10 |
| **Connectors** | BeyondTrust (2), BMC (3), Centreon (1), Mail Utilities (3), OpenText EnCase Endpoint Security (1) |

> **Scope note.** Per an in-session decision, work was intentionally stopped at **step 7 of 15** for all 10 integrations. Steps 8–15 (generate manifest, handler param coverage, validate, param parity, code review/merge, precommit, Release Notes) require read/write access to the sibling `unified-connectors-content/` repo, which is outside the sandboxed `content/` working directory and was inaccessible. Docker was also unavailable, so the dynamic analyzer never ran (static analysis + manual source review were used instead). State below is read authoritatively from `workflow_state.py context`.

---

## Per-integration status

| Integration ID | Connector ID | Auth type(s) classified | Furthest step reached | Status | Notes |
|---|---|---|---|---|---|
| BeyondTrust Password Safe | BeyondTrust | Passthrough (PS-Auth: api_key + username + password) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. Multi-secret single header → Passthrough. No code edits. |
| BeyondTrust Privilege Management Cloud | BeyondTrust | Passthrough (OAuth2 client-credentials) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. Event collector (Log Collection). No code edits. |
| BMCHelixRemedyforce | BMC | Plain (Salesforce SOAP login, username+password) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. 2 code edits (`request_timeout`, `first_fetch` defaults). 6 fetch params elevated via `params.items()` review. |
| BmcITSM | BMC | Plain (JWT login → AR-JWT, username+password) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. 1 code edit (`first_fetch`). Mirror params hidden→excluded; added `update-remote-system` (YML key case mismatch). |
| Remedy AR | BMC | Plain (JWT login → AR-JWT, username+password) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. URL param is `server`. No code edits. |
| Centreon | Centreon | Plain (auth-token login, username+password) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. No description file. No code edits. |
| Mail Listener v2 | Mail Utilities | Passthrough (IMAP username+password + optional client cert) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. 1 code edit (`port`+`folder` defaults). Cert is additive add-on → single Passthrough. |
| Mail Sender (New) | Mail Utilities | Plain (optional SMTP login, username+password) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. Auth optional (anonymous SMTP supported). No code edits. |
| MailListener - POP3 | Mail Utilities | Plain (POP3 login: `email` + `credentials_password.password`) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. 1 code edit (`ssl` default — fixes secure-by-default regression). |
| Guidance Encase Endpoint | OpenText EnCase Endpoint Security | NoneRequired (no credentials) | Params to Capabilities (#7/15); at #8 generated manifest | ⛔ blocked (step 8 needs sibling repo) | Steps 1–7 ✅. JavaScript integration (`--static-only`). No auth header in code. No code edits. |

**Legend:** "Furthest step reached" = the last data/checkpoint step completed (Params to Capabilities #7) with the workflow now positioned at the next step (#8 generated manifest). All 10 are `completed_steps: 7 / 15`, `all_complete: false`.

---

## Workflow-data written (read back via `context`)

### BeyondTrust Password Safe

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "ps_auth",
      "xsoar_param_map": {
        "credentials_key.password": "api_key",
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
  "integration": "BeyondTrust Password Safe",
  "commands": {
    "beyondtrust-change-credentials": [],
    "beyondtrust-check-in-credentials": [],
    "beyondtrust-create-release-request": [],
    "beyondtrust-get-credentials": [],
    "beyondtrust-get-managed-accounts": [],
    "beyondtrust-get-managed-systems": [],
    "beyondtrust-list-release-requests": [],
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
  "Fetch Secrets": [],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### BeyondTrust Privilege Management Cloud

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
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "BeyondTrust Privilege Management Cloud",
  "commands": {
    "beyondtrust-pm-cloud-get-events": [],
    "fetch-events": ["events_types_to_fetch", "first_fetch", "max_fetch"],
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
  "Log Collection": ["events_types_to_fetch", "first_fetch", "max_fetch"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### BMCHelixRemedyforce

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": {
        "username_creds.identifier": "username",
        "username_creds.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["auth_url", "insecure", "proxy", "request_timeout", "url"]
}
```

**Params to Commands**
```json
{
  "integration": "BMCHelixRemedyforce",
  "commands": {
    "bmc-remedy-account-details-get": [],
    "bmc-remedy-asset-details-get": [],
    "bmc-remedy-broadcast-details-get": [],
    "bmc-remedy-category-details-get": [],
    "bmc-remedy-impact-details-get": [],
    "bmc-remedy-incident-create": [],
    "bmc-remedy-incident-get": [],
    "bmc-remedy-incident-update": [],
    "bmc-remedy-note-create": [],
    "bmc-remedy-queue-details-get": [],
    "bmc-remedy-service-offering-details-get": [],
    "bmc-remedy-service-request-create": [],
    "bmc-remedy-service-request-definition-get": [],
    "bmc-remedy-service-request-get": [],
    "bmc-remedy-service-request-update": [],
    "bmc-remedy-status-details-get": [],
    "bmc-remedy-template-details-get": [],
    "bmc-remedy-urgency-details-get": [],
    "bmc-remedy-user-details-get": [],
    "fetch-incidents": ["category", "fetch_note", "first_fetch", "impact", "max_fetch", "query", "queue", "status", "type", "urgency"],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{
  "request_timeout": 60,
  "first_fetch": "10 minutes"
}
```

**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Issues": ["category", "fetch_note", "first_fetch", "impact", "max_fetch", "query", "queue", "status", "type", "urgency"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### BmcITSM

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
  "integration": "BmcITSM",
  "commands": {
    "bmc-itsm-change-request-create": [],
    "bmc-itsm-change-request-template-list": [],
    "bmc-itsm-change-request-update": [],
    "bmc-itsm-company-list": [],
    "bmc-itsm-incident-create": [],
    "bmc-itsm-incident-template-list": [],
    "bmc-itsm-incident-update": [],
    "bmc-itsm-known-error-create": [],
    "bmc-itsm-known-error-update": [],
    "bmc-itsm-problem-investigation-create": [],
    "bmc-itsm-problem-investigation-update": [],
    "bmc-itsm-service-request-create": [],
    "bmc-itsm-service-request-definition-list": [],
    "bmc-itsm-service-request-update": [],
    "bmc-itsm-support-group-list": [],
    "bmc-itsm-task-create": [],
    "bmc-itsm-task-template-list": [],
    "bmc-itsm-task-update": [],
    "bmc-itsm-ticket-create-relationship": [],
    "bmc-itsm-ticket-delete": [],
    "bmc-itsm-ticket-list": [],
    "bmc-itsm-user-list": [],
    "bmc-itsm-work-order-create": [],
    "bmc-itsm-work-order-template-list": [],
    "bmc-itsm-work-order-update": [],
    "bmc-itsm-worklog-add": [],
    "bmc-itsm-worklog-attachment-get": [],
    "bmc-itsm-worklog-list": [],
    "fetch-incidents": ["first_fetch", "max_fetch", "query", "ticket_impact", "ticket_status", "ticket_type", "ticket_urgency"],
    "get-mapping-fields": [],
    "get-modified-remote-data": [],
    "get-remote-data": [],
    "update-remote-system": [],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{
  "first_fetch": "7 days"
}
```

**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Issues": ["first_fetch", "max_fetch", "query", "ticket_impact", "ticket_status", "ticket_type", "ticket_urgency"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### Remedy AR

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
  "integration": "Remedy AR",
  "commands": {
    "remedy-get-server-details": [],
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

**Release Notes** — not set (null).

---

### Centreon

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
  "integration": "Centreon",
  "commands": {
    "centreon-get-host-status": [],
    "centreon-get-service-status": [],
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

**Release Notes** — not set (null).

---

### Mail Listener v2

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "imap_login",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password",
        "clientCertAndKey.password": "client_cert"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["MailServerURL", "TLS_connection", "folder", "insecure", "port"]
}
```

**Params to Commands**
```json
{
  "integration": "Mail Listener v2",
  "commands": {
    "fetch-incidents": ["Include_raw_body", "delete_processed", "first_fetch", "limit", "permittedFromAdd", "permittedFromDomain", "save_file", "with_headers"],
    "mail-listener-get-email": [],
    "mail-listener-get-email-as-eml": [],
    "mail-listener-list-emails": ["first_fetch", "limit", "permittedFromAdd", "permittedFromDomain", "with_headers"],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{
  "port": 143,
  "folder": "INBOX"
}
```

**Params to Capabilities**
```json
{
  "Automation": [],
  "Fetch Issues": ["Include_raw_body", "delete_processed", "save_file"],
  "general_configurations": ["limit", "first_fetch", "with_headers", "permittedFromDomain", "permittedFromAdd"]
}
```

**Release Notes** — not set (null).

---

### Mail Sender (New)

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
  "other_connection": ["fqdn", "from", "host", "insecure", "port", "tls"]
}
```

**Params to Commands**
```json
{
  "integration": "Mail Sender (New)",
  "commands": {
    "send-mail": [],
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

**Release Notes** — not set (null).

---

### MailListener - POP3

**Auth Details**
```json
{
  "auth_types": [
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": {
        "email": "username",
        "credentials_password.password": "password"
      },
      "interpolated": true
    }
  ],
  "other_connection": ["port", "server", "ssl"]
}
```

**Params to Commands**
```json
{
  "integration": "MailListener - POP3",
  "commands": {
    "fetch-incidents": ["fetch_time"],
    "test-module": []
  }
}
```

**Params for test with default in code**
```json
{
  "ssl": true
}
```

**Params to Capabilities**
```json
{
  "Fetch Issues": ["fetch_time"],
  "general_configurations": []
}
```

**Release Notes** — not set (null).

---

### Guidance Encase Endpoint

**Auth Details**
```json
{
  "auth_types": [],
  "other_connection": ["insecure", "port", "proxy", "server"]
}
```

**Params to Commands**
```json
{
  "integration": "Guidance Encase Endpoint",
  "commands": {
    "encase-copyjob": [],
    "encase-snapshot": [],
    "encase-verifyhash": [],
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

**Release Notes** — not set (null).

---

## File changes

### content repo — `git status --short`

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

> **Attribution note.** Many of the listed modifications (ArcherV2, BitSight, CarbonBlack, DigitalGuardian, Exabeam x2, FeedDHS x2, FeedElasticsearch, FeedMISP, FireEyeCM, FireEyeHelix, Forcepoint, Netmiko, Netskope, Rapid7, SAP, TheHive) were **NOT made in this session** — the working tree is the live `jl-connectus-migration-01` branch carrying prior batch work. The CSV change includes this batch's writes (via `workflow_state.py`, never edited directly). Untracked `capabilities_output.json`, `.batch10_contexts.jsonl`, `.summary_ctx.json`, `_split_assignments.py`, `migration-prompts/` are pre-existing / from other tooling, not this session.

### content repo — `git diff --stat` (full)

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

### content repo — code edits made BY THIS SESSION only (4 files, `git diff --stat`)

```
 .../Integrations/BmcHelixRemedyForce/BmcHelixRemedyForce.py           | 4 ++--
 Packs/BmcITSM/Integrations/BmcITSM/BmcITSM.py                         | 2 +-
 Packs/MailListener/Integrations/MailListenerV2/MailListenerV2.py      | 4 ++--
 .../Integrations/MailListener_POP3/MailListener_POP3.py               | 2 +-
 4 files changed, 6 insertions(+), 6 deletions(-)
```

These 4 `.py` edits are the branch-(a) param-default fallbacks (all confirmed interactively):
- `BmcHelixRemedyForce.py` — `request_timeout` → `int(... or 60)`; `first_fetch` → `... or "10 minutes"`.
- `BmcITSM.py` — `first_fetch` → `... or "7 days"`.
- `MailListenerV2.py` — `port` → `arg_to_number(... or 143)`; `folder` → `... or "INBOX"`.
- `MailListener_POP3.py` — `ssl` → `params.get("ssl", True)` (secure-by-default fix).

### unified-connectors-content repo

**No changes.** This sibling repo was never written to — it is outside the sandboxed `content/` directory and inaccessible. **No connector folders were created or modified** under `connectors/` (step 8 onward, which produces those, was not reached).

---

## Blockers / follow-ups

1. **Hard blocker — sibling repo inaccessible (steps 8–15).** `manifest_generator.py` (step 8) failed with `PermissionError: Operation not permitted` writing to `../unified-connectors-content/connectors/<slug>`. The sandbox denies all access outside `content/`. Steps 8 (generate manifest), 9 (handler param coverage), 10 (validate), 11 (param parity), 12 (code reviewed), 13 (code merged), 14 (precommit/tests), 15 (Release Notes) are all deferred until the environment grants parent/sibling-dir access. All 10 integrations are parked at step #8.
2. **Docker unavailable.** Dynamic analysis (`check_command_params.py`) could not pull/run containers (`docker pull ... operation not permitted`). All Params-to-Commands results came from static analysis + manual source review. Params elevated by manual review (flagged "investigated myself" during the run):
   - **BeyondTrust Privilege Management Cloud** — fetch-events: `events_types_to_fetch`, `first_fetch`, `max_fetch` (read in `main()`).
   - **BMCHelixRemedyforce** — fetch-incidents: `category`, `impact`, `urgency`, `status`, `queue` (via `params.items()` loop) + `first_fetch`.
   - **BmcITSM** — fetch-incidents: all 7 filter params (read in `main()`, passed positionally); added `update-remote-system` command (YML `isremotesyncout` vs `isRemoteSyncOut` case mismatch hid it from the synthesizer).
   - **Mail Listener v2** — fetch-incidents (8) + list-emails (5) params (read in `main()`).
   - **MailListener - POP3** — `fetch_time` (module-level global).
   - **Guidance Encase Endpoint** — JS integration, static analysis Python-only; all commands confirmed args-only by reading the `.js`.
3. **`interpolated: true` on all classified profiles.** Every non-`NoneRequired` profile carries `interpolated: true` — this is the platform's ALWAYS-INTERPOLATE behavior (`set-auth` forces it; it is not a per-integration fallback decision here). Guidance Encase Endpoint has no profiles (`NoneRequired`), so no interpolation applies.
4. **No `--force` was used anywhere.** No checkpoint required override.
5. **Code edits need downstream validation.** The 4 `.py` files edited (5 logical default fixes) still need `demisto-sdk pre-commit`/validate + Release Notes once steps 8–15 are unblocked. They are uncommitted.
6. **CSV transient state observed once.** During BMCHelixRemedyforce, `Collect Capabilities` (step 3) had to be re-run once (it briefly showed unset before `set-params-to-commands`); re-running `set-capabilities` resolved it cleanly. No data loss.

---

## Reproduce

**Intended git branch:** `jl-connectus-migration-07` (the batch prompt's branch; the live working tree was on `jl-connectus-migration-01` during this session).

```bash
git checkout jl-connectus-migration-07   # or continue on the active branch
```

**Integration IDs (in batch order):**

```json
["BeyondTrust Password Safe", "BeyondTrust Privilege Management Cloud", "BMCHelixRemedyforce", "BmcITSM", "Remedy AR", "Centreon", "Mail Listener v2", "Mail Sender (New)", "MailListener - POP3", "Guidance Encase Endpoint"]
```

To resume any integration (run from the idex parent cwd that contains `content/` and `unified-connectors-content/` as siblings):

```bash
python3 content/connectus/workflow_state.py context "<Integration ID>"
# then continue from step #8 (generated manifest) once the sibling repo is accessible
```
