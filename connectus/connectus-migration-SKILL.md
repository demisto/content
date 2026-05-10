---
name: connectus-migration
description: This skill should be used when migrating integrations to connectus
---

# ConnectUs Migration Skill

## Overview

This skill guides the migration of XSOAR/XSIAM integrations to the ConnectUs platform. Each integration follows a workflow tracked in [`connectus/integrations_report.csv`](integrations_report.csv) via the [`connectus/workflow_state.py`](workflow_state.py) CLI tool.

The CSV has two kinds of columns (see [`connectus/Readme.md`](Readme.md) for full details):

- **Data columns** (4) — identity / metadata: `Integration ID`, `Integration File Path`, `Connector ID`, `special cases`.
- **Workflow columns** (16, managed by the state machine):
  - **Workflow data columns** (free-text / JSON; set with dedicated commands): `assignee`, `Auth Details`, `Params to Commands`, `Params for test with default in code`, `Params same in other handlers`.
  - **Workflow checkpoints** (sequential ✅): `generated manifest`, `run manifest make validate`, `wrote/checked code`, `shadowed command test passes`, `write tests`, `precommit/validate/unit tests passed`, `auth parity test passes`, `param parity test passes`, `code reviewed`, `code merged`.
  - **Workflow flag**: `requires auth parity test` (`YES` / `NO` / `N/A`).

Authentication classification is the **prerequisite for everything**: you must set `Auth Details` with `set-auth` before the workflow can meaningfully begin (setting it also resets the workflow). The Validate Auth Classification procedure below is run before invoking `set-auth`.

## Entry Points / Trigger Phrases

The skill supports three top-level invocation styles. Pick the matching flow based on what the user said.

| User phrase (examples) | Action |
|---|---|
| "migrate `<integration id>`" / "work on `<integration id>`" / "status of `<integration id>`" | Single-integration flow — jump straight to [Step 0: Identify the Integration](#step-0-identify-the-integration) and walk the existing 16-step procedure for that one integration. |
| "migrate everything assigned to me" / "what's next for me" / "continue my work" / "keep going" | [Assignee batch flow](#assignee-batch-flow) — enumerate the user's in-progress + assigned integrations and walk them one by one. |
| "migrate connector `<connector_id>`" / "work on connector `<connector_id>`" / "do the whole `<connector>` connector" | [Connector batch flow](#connector-batch-flow) — enumerate that connector's integrations and walk them one by one (with ownership disambiguation up front). |

Both batch flows are an **outer loop** wrapped around the existing per-integration procedure. They never replace or re-implement the 16-step workflow — they pick *which* integration to run that workflow on next.

## Assignee batch flow

Use when the user says something like "migrate everything assigned to me" / "continue my work" / "what's next for me".

1. **Resolve the current user.** Read `git config user.name` (the script uses the same source). If empty, ask the user for their name and stop.
2. **Enumerate candidates.** Run:

   ```bash
   python3 connectus/workflow_state.py next --mine
   ```

   Or from Python: `from connectus.workflow_state import integrations_for_assignee` and call `integrations_for_assignee("<name>")`. Each result dict carries `integration_id`, `connector_id`, `assignee`, `current_step`, `current_step_index`, `completed_steps`, `all_complete`, `has_progress`.
3. **Empty result?** Tell the user there is nothing assigned + in-progress for them, and offer two follow-ups:
   - bulk-assign a connector via `set-assignee-by-connector <connector_id> "<name>"` (suggest running `list-connectors` first to pick one), or
   - browse via `python3 connectus/workflow_state.py dashboard`.
   Then stop.
4. **Multiple results?** Before starting, present them as a numbered list with `Integration ID`, `Connector ID`, current step, and `completed_steps / 16`. Apply the [Order-of-work disambiguation](#order-of-work-disambiguation) heuristic. The order is "obvious" only when:
   - There is exactly one integration, OR
   - All integrations belong to the same connector AND exactly one is clearly furthest along (highest `current_step_index` with `has_progress: true`) — proceed with that one first and confirm.

   Otherwise, **ask the user** for the work order. Suggest a sensible default ("furthest-along first" or "by connector then alphabetical") but let them override.
5. **Walk one integration at a time.** For each integration in the chosen order:
   - Follow the existing per-integration migration procedure starting at [Step 0: Identify the Integration](#step-0-identify-the-integration). Do **not** duplicate the 16 steps here — the rest of this skill already documents them.
   - Between integrations, print a short progress recap (`X/N done in this batch — next: <integration id>`) and confirm before moving on, **unless** the user has explicitly said "do them all without asking" / "no confirmations" / equivalent.
6. **Mid-loop "what's next" check.** Re-run `python3 connectus/workflow_state.py next --mine` after finishing each integration so the queue reflects any newly-assigned or just-completed work.
7. **Finish.** When the queue is empty, summarize what was done and ask whether to start a new batch (e.g., a connector batch, or assigning more work).

## Connector batch flow

Use when the user says something like "migrate connector `<connector_id>`" / "do the whole `<connector>` connector".

1. **Validate the connector id.** Run:

   ```bash
   python3 connectus/workflow_state.py list-by-connector "<connector_id>"
   ```

   Or programmatically: `from connectus.workflow_state import list_integrations_by_connector` → `list_integrations_by_connector("<connector_id>")`. If the result is empty, suggest `python3 connectus/workflow_state.py list-connectors` to discover valid ids and stop.
2. **Inspect ownership** on the matched rows (look at the `assignee` field on each dict). One of three cases applies:
   - **All rows assigned to the current git user** → proceed straight to step 4.
   - **All rows unassigned** → offer to bulk-assign to the current user. Confirm before running:

     ```bash
     python3 connectus/workflow_state.py set-assignee-by-connector "<connector_id>" "<git user name>"
     ```

     Then proceed.
   - **Mixed: some rows owned by other people** → list who owns what (one line per integration: `<integration id>  → <assignee or "unassigned">`) and ask the user which option they want:
     1. Take over the whole connector (`set-assignee-by-connector <connector_id> "<name>"` — note this never wipes migration progress).
     2. Only work on the rows in this connector that are already assigned to them.
     3. Abort and pick a different connector / scope.
3. **Settle ownership before any per-integration work.** Do not start migrating rows you don't own — re-confirm or re-assign first.
4. **Walk one integration at a time.** Apply the [Order-of-work disambiguation](#order-of-work-disambiguation) heuristic to pick the order, ask the user if it isn't obvious, then for each integration follow the existing per-integration procedure starting at [Step 0: Identify the Integration](#step-0-identify-the-integration).
5. **Mid-loop "what's next in this batch" check.** After finishing each integration, run:

   ```bash
   python3 connectus/workflow_state.py next --connector "<connector_id>" --mine
   ```

   to see the remaining in-progress integrations in this connector that belong to you.
6. **Finish.** When the queue is empty, summarize and confirm completion.

## Order-of-work disambiguation

Both batch flows apply this heuristic to pick which integration to work on first.

1. **Skip integrations where `all_complete` is true.** Mention them in the recap ("3 already done in this batch") but don't redo work.
2. **Prefer integrations that are mid-flight** (`has_progress: true` AND `all_complete: false`) over ones that are only assigned-but-not-started. Finish what's started before opening new fronts.
3. Within mid-flight integrations, default to **highest `current_step_index` first** (closest to merge) so feedback loops shorten.
4. Within not-started integrations, default to **same-connector grouping** (auth and params for one connector are usually similar, so doing them back-to-back compounds learning).
5. **If any of these heuristics conflict — stop and ask the user.** Show the candidate orderings and let them pick. Do NOT silently choose. Examples of conflict:
   - Two mid-flight integrations at the same `current_step_index` in different connectors.
   - One mid-flight integration far along + several not-started ones in a different connector the user just said they wanted to "do all of".
   - A mid-flight integration whose `assignee` is someone else but the user is doing a connector batch that includes it.

When in doubt, surface the candidates and the rule that's pulling each direction; let the human break the tie.

## Critical Rules

1. **NEVER edit [`connectus/integrations_report.csv`](integrations_report.csv) directly.** All CSV modifications MUST go through [`connectus/workflow_state.py`](workflow_state.py) CLI commands.
2. **Follow the workflow checkpoints sequentially.** You cannot skip ahead — the state machine enforces ordering.
3. **Always check status first** before doing any work on an integration.
4. **Use `execute_command`** to run all `workflow_state.py` commands from the workspace root.
5. **Use `set-auth` to update Auth Details.** When correcting auth classifications, use `python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>'`. This validates the JSON schema and automatically resets the workflow back to the first checkpoint (`generated manifest`).
6. If a checkpoint does not pass, it might be because a previous step was not done well — go back to it via `fail` or `reset-to`.
7. Try to be efficient in what needs input from the user. If you have an option to read files instead of grep, or batch commands to the cli, it is better.

## Linked Files

- [`connectus/Readme.md`](Readme.md) — Full reference for auth types, CSV columns, walkthrough.
- [`connectus/column-schemas.md`](column-schemas.md) — JSON shapes for `Auth Details`, `Params to Commands`, `Params for test with default in code`, `Params same in other handlers`.
- [`connectus/workflow_state.py`](workflow_state.py) — The state machine CLI (source of truth for workflow).
- [`connectus/integrations_report.csv`](integrations_report.csv) — The tracking spreadsheet (DO NOT EDIT DIRECTLY).

## Step 0: Identify the Integration

When the user asks to migrate an integration, first identify it:

```bash
# List all available integration IDs
python3 connectus/workflow_state.py list

# Check current status
python3 connectus/workflow_state.py status "<Integration ID>"
```

The status output shows:

- **Assignee** — who is working on it
- **File Path** — path to the integration's source files (data column)
- **Connector ID** — the ConnectUs connector this integration belongs to (data column)
- **Auth Details** — authentication detail JSON (with embedded `config` expression)
- **Params to Commands** — JSON mapping of commands → param ids
- **Params for test with default in code** — JSON list of param ids with hardcoded defaults
- **Params same in other handlers** — optional JSON listing shared params
- **Workflow Checkpoints** — which checkpoints are done, which remain
- **Current step** — what to work on next

If the integration has no assignee, set one:

```bash
python3 connectus/workflow_state.py set-assignee "<Integration ID>" "<Name>"
```

## Workflow Steps

### Step 1: Verify Auth Classification (prerequisite — not a checkpoint)

**Before starting any migration work**, rigorously verify that the `Auth Details` for this integration is correct, then write/update it via `set-auth`. The automated classifier analyzed YML param metadata (widget types) and has systematic errors — a manual review of 148 integrations found **71 corrections** (48% error rate). Every integration MUST be validated before proceeding.

`Auth Details` is a workflow data column (not a checkpoint), so there is no `markpass` for it; setting it via `set-auth` is what registers your verification AND resets the workflow back to `generated manifest`.

#### Validation Checklist

Follow this checklist for EVERY integration. Do not skip any step.

1. ☐ Run `workflow_state.py status` to see current `Auth Details`
2. ☐ Locate the integration files (YML + Python)
3. ☐ Extract auth params from YML `configuration` section
4. ☐ Analyze Python code for actual auth mechanism
5. ☐ Cross-reference YML params with code usage
6. ☐ Validate Auth Details JSON structure against [`column-schemas.md`](column-schemas.md)
7. ☐ Determine if corrections are needed
8. ☐ Apply via `set-auth` (this also resets the workflow)

---

#### 1.1 Check Current Classification

```bash
python3 connectus/workflow_state.py status "<Integration ID>"
```

Note the **Auth Details** value from the output (its `config` field is the Auth Config Expression). This is what you will validate.

You can also pretty-print just that value:

```bash
python3 connectus/workflow_state.py show-step "<Integration ID>" "Auth Details"
```

---

#### 1.2 Locate Integration Files

Integration files follow this structure:

- **YML**: `Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>.yml`
- **Python**: `Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>.py`

> **Important:** The Integration ID in the CSV may differ from the directory name (spaces, capitalization, version suffixes). Use `find` to locate:

```bash
find Packs/ -path "*/Integrations/*/*.yml" -name "*.yml" | grep -i "<integration_id>"
```

Once located, you may want to record the path:

```bash
# (No CLI setter for File Path yet — note it for documentation; future iteration may add `set-file-path`.)
```

---

#### 1.3 YML Analysis Procedure

Open the YML file and examine the `configuration` section. Extract ALL auth-related params by checking:

| What to Check | Why |
|---|---|
| Params with `type: 9` (credentials widget) | These are username/password pairs — but may carry OAuth client ID/secret or API keys |
| Params with `type: 4` (encrypted text) | These are encrypted fields — may be API keys, tokens, or OAuth secrets |
| Params with `type: 14` (certificate/key) | Certificate-based auth |
| Params with `type: 15` (select dropdown) | May be an `auth_type` selector for multi-auth integrations |
| `hiddenusername: true` on type=9 params | Often means the credentials widget is being used as an API key, NOT username/password |
| `display` and `displaypassword` labels | Reveal what the credential actually is (e.g., "Client ID" / "Client Secret" vs "Username" / "Password") |
| `hidden: true` params | Excluded from classification but may still be used in code — check if they represent an old input path for the same credential |
| `deprecated: true` or `_deprecated` in param names | Ignore these entirely — they are no longer functional |
| `additionalinfo` text | Often describes the auth mechanism in plain English |
| Params named `auth_type` with `type: 15` | Indicates multi-auth integrations with user-selectable auth flow |

**Key rule for hidden/deprecated params:**

- If a hidden param and a visible param carry the same credential (old/new migration), the classification should reflect only the visible param's mechanism, **not** `CHOICE` between two types.

---

#### 1.4 Python Code Analysis — Specific Patterns

For each auth type, search the Python file using these patterns:

**OAuth2 Client Credentials:**
```bash
grep -n "client_credentials\|grant_type.*client\|/oauth2/token\|/token\|MicrosoftClient\|oproxy\|get_access_token\|client_id.*client_secret" <file>.py
```

**OAuth2 Authorization Code:**
```bash
grep -n "authorization_code\|redirect_uri\|oauth-start\|oauth-complete\|auth_code\|code_verifier\|PKCE" <file>.py
```

**OAuth2 JWT Bearer:**
```bash
grep -n "jwt\.encode\|jwt-bearer\|ServiceAccountCredentials\|google\.auth\|google\.oauth2\|service_account\|private_key.*sign" <file>.py
```

**OAuth2 ROPC (Resource Owner Password Credentials) — classified as `Other`:**
```bash
grep -n "grant_type.*password\|resource_owner\|ROPC" <file>.py
```

**OAuth2 Device Code — classified as `Other`:**
```bash
grep -n "device_code\|devicecode\|device_authorization" <file>.py
```

**Managed Identity — noted in `notes` field:**
```bash
grep -n "managed_identit\|MANAGED_IDENTITIES\|use_managed_identities\|managed_identities_client_id" <file>.py
```

**API Key:**
```bash
grep -n "X-API-Key\|x-api-key\|apikey.*header\|api_key.*header\|Authorization.*Bearer\|Bearer.*token" <file>.py
```

**Basic Auth:**
```bash
grep -n "HTTPBasicAuth\|auth=.*username.*password\|basic_auth\|base64.*encode.*:" <file>.py
```

---

#### 1.5 Cross-Reference YML Params with Code Usage

For each auth-related param found in the YML:
1. Find where it is read in the Python code (search for the param name in `demisto.params()` calls)
2. Trace how the value is used — is it sent as a header? Used in an OAuth flow? Passed to `HTTPBasicAuth`?
3. Confirm the YML param type matches the actual usage

---

#### 1.6 Known Misclassification Patterns

Based on manual review of 148 integrations (71 corrections found), these are the most common errors:

| # | Pattern | Freq | Classifier Output | Correct Value | How to Detect |
|---|---------|------|-------------------|---------------|---------------|
| 1 | `type=9` credentials used for OAuth2 client_credentials | 9 | `Plain(credentials)` | `OAuth2ClientCreds(credentials)` | Code does `grant_type=client_credentials` or uses `MicrosoftClient` |
| 2 | Bearer token classified as Plain | 8 | `Plain(credentials)` | `APIKey(credentials)` | Code sets `Authorization: Bearer {token}` with a static token from params |
| 3 | False positive OAuth2ClientCreds from code patterns | 25 | `OPTIONAL(OAuth2ClientCreds)` added | Should be removed | Code has `client_id`/`access_token` strings but they're not OAuth2 — they're proprietary token exchange |
| 4 | Microsoft/Azure missing ManagedIdentity | 23 | No mention | Add to notes/auth_types | Code imports `MicrosoftClient` and has `managed_identities_client_id` param |
| 5 | Microsoft/Azure missing DeviceCode | 12 | No mention | Add to notes/auth_types | Code has `device_code` grant type support |
| 6 | OAuth2 ROPC misclassified | 13 | `OAuth2ClientCreds` or `Plain` | `Other` with ROPC note | Code does `grant_type=password` |
| 7 | Hidden old param creates false CHOICE | ~10 | `CHOICE(APIKey, Plain)` | Single mechanism | Old `type=4` param is `hidden: true`, new `type=9` param is visible — same credential |
| 8 | `type=4` OAuth client secret classified as APIKey | ~5 | `APIKey(client_secret)` | `OAuth2ClientCreds(client_secret)` | Param named `client_secret` or `enc_key` used in OAuth flow |

---

#### 1.7 Microsoft/Azure Integration Special Handling

Microsoft/Azure integrations are the most complex (23 corrections in the manual review). Apply this dedicated procedure:

- **If the integration imports `MicrosoftClient` from `MicrosoftApiModule`:**
  - It likely supports **4 auth flows**: OAuth2ClientCreds, OAuth2AuthCode, DeviceCode, ManagedIdentity
  - Check for `auth_type` selector param (`type: 15`) with options like `Client Credentials`, `Authorization Code`, `Device Code`
  - Check for `managed_identities_client_id` param → indicates ManagedIdentity support
  - Check for `redirect_uri` and `auth_code` params → indicates OAuth2AuthCode support
  - The config should typically be: `CHOICE(OAuth2AuthCode, OAuth2ClientCreds, DeviceCode, ManagedIdentity)` or similar
  - DeviceCode and ManagedIdentity are classified as `Other` in the enum but should be noted in the `notes` field

---

#### 1.8 Auth Details JSON Validation

After determining the correct auth types, validate the Auth Details JSON against the rules in [`connectus/column-schemas.md`](column-schemas.md):

1. Must be valid JSON with keys: `auth_types`, `config`, `params`, `notes`
2. `auth_types` entries sorted by `(type, name)`
3. Every param in `params` must appear in `auth_types` (by name)
4. Every type in `config` must appear in at least one param's `type` field, OR be explained in `notes`
5. If `config` is `NoneRequired`, then `auth_types` must be `[]` and `params` must be `{}`
6. If `Other` is used, `notes` MUST be non-null explaining the mechanism
7. `xsoar_type` values must match the YML param types (0=text, 4=encrypted, 8=bool, 9=credentials, 14=cert key, 15=select)
8. `required` values must match the YML param `required` field

---

#### 1.9 Decision Tree for Auth Type

Use this decision tree to determine the correct auth type:

```
Is there a credentials param (type=9)?
├── YES: What does the code do with it?
│   ├── Sends as Basic Auth (HTTPBasicAuth) → Plain
│   ├── Sends as Bearer token (Authorization: Bearer) → APIKey
│   ├── Uses in OAuth2 client_credentials flow → OAuth2ClientCreds
│   ├── Uses in OAuth2 ROPC flow (grant_type=password) → Other (ROPC)
│   └── Uses as username/password for login → Plain
├── NO: Is there an encrypted param (type=4)?
│   ├── YES: What is it?
│   │   ├── Named api_key, apikey, token → APIKey
│   │   ├── Named client_secret, enc_key used in OAuth → OAuth2ClientCreds
│   │   └── Named private_key used for JWT signing → OAuth2JWT
│   └── NO: Is there any auth at all?
│       ├── YES: Check code for auth mechanism → classify accordingly
│       └── NO: NoneRequired
```

---

#### 1.10 Applying Corrections

When corrections are needed (or for the initial set), use `set-auth`:

```bash
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<Auth Details JSON>'
```

This command:

- Validates the Auth Details JSON against the schema (`auth_types`, `config`, `params`, `notes`)
- Sets the `Auth Details` workflow data column in the CSV
- Automatically **resets the workflow** to the first checkpoint (`generated manifest`) and clears all checkpoints + the auth-parity flag
- Rejects invalid JSON with specific error messages

Example:

```bash
python3 connectus/workflow_state.py set-auth "Abnormal Security" '{"auth_types":[{"type":"APIKey","name":"api_key"}],"config":"REQUIRED(APIKey)","params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'
```

After setting, verify it looks correct:

```bash
python3 connectus/workflow_state.py status "<Integration ID>"
```

Note: there is **no `markpass "auth params set"`** anymore — the verification IS the `set-auth` call. The first markpass-able checkpoint is `generated manifest`.

#### Auth Type Reference

See [`connectus/Readme.md`](Readme.md:19) for the full Auth Type definitions.

| Value | Description |
|---|---|
| `OAuth2AuthCode` | OAuth 2.0 Authorization Code flow |
| `OAuth2ClientCreds` | OAuth 2.0 Client Credentials flow |
| `OAuth2JWT` | OAuth 2.0 JWT Bearer flow |
| `APIKey` | API Key, HMAC, and similar static secret mechanisms |
| `Plain` | Plain text fields: username/password, basic auth, bearer tokens, AWS credentials, certificates |
| `Other` | Catch-all (e.g., DeviceCode, ROPC, ManagedIdentity) — `notes` MUST explain the mechanism |
| `NoneRequired` | No authentication needed |

## Analyzing per-command parameters

Use this procedure whenever you are about to populate the `Params to Commands` workflow data column (Step 2 below). The [`connectus/check_command_params.py`](check_command_params.py) analyzer does the heavy lifting: it runs each command in a production-equivalent Docker container, intercepts HTTP traffic via an internal capture proxy, and reports which YML configuration params each command actually consumes. The skill's job is to invoke it correctly, interpret its output, and merge its findings with a source-code review before writing the polished result to the pipeline.

### 1. When to run the analyzer

Run the analyzer for any integration that requires the `Params to Commands` column to be populated — i.e., the per-command list of YML configuration params actually consumed by each command. This is the input to Step 2 (`set-params-to-commands`).

### 2. How to invoke it

The analyzer is a self-contained script. It starts its own HTTP capture proxy internally — **the skill does not need to start any external proxy, server, or service**. The only external dependency is Docker (used by default to give each integration its production runtime environment).

Standard invocation:

```bash
python3 connectus/check_command_params.py <integration_dir> \
    --ignore-params-file connectus/default_ignore_params.txt
```

Where `<integration_dir>` is the directory containing the integration's `.yml` and `.py` files (e.g., `Packs/QRadar/Integrations/QRadar_v3`).

Optional flags the skill should know about:

- `--commands cmd1 cmd2 ...` — analyze only specific commands instead of all of them.
- `--static-only` — skip the dynamic phase (no Docker, no proxy). Faster, but lower accuracy. Use only when Docker is unavailable.
- `--timeout SECONDS` — per-command wall-clock timeout (default 30s; the batch runner uses 300s for the whole integration).
- `--docker {auto,always,never}` — `auto` (default) uses Docker when available; `never` runs in host Python (will fail on integrations needing third-party deps); `always` requires Docker.
- `--use-integration-docker` — opt-in: instead of the pinned `demisto/py3-native` image, use the integration's own `script.dockerimage` from its YML. Use this for a targeted re-run when an integration reports `module_not_found` (see Step 1 of the decision tree in section 6 below). Falls back to `--docker-image` if the YML doesn't declare one.

The script writes its result to **stdout** as a single JSON document. All progress and warnings go to **stderr**. Exit code `0` means success; `2` means bad CLI args / path; `3` means an unhandled analyzer error.

### 3. Output schema (annotated example)

```json
{
  "integration": "QRadar v3",
  "commands": {
    "test-module":          ["adv_params", "fetch_query"],
    "fetch-incidents":      ["fetch_query", "max_fetch", "first_fetch"],
    "qradar-offenses-list": ["fetch_query", "filter"]
  },
  "diagnostics": {
    "test-module": {
      "status": "param_caused_failure",
      "captured_requests": 0,
      "failing_params": ["adv_params"],
      "failure_excerpt": "DemistoException: Failed to parse advanced parameter: SENTINEL_PARAM_adv_params"
    },
    "fetch-incidents": {
      "status": "ok",
      "captured_requests": 3
    },
    "qradar-offenses-list": {
      "status": "ok",
      "captured_requests": 1
    }
  }
}
```

`commands` is the **finished, polished result** — these are the per-command param lists the skill writes into the pipeline data.

`diagnostics` is **internal AI signal only** — see section 5 below.

### 4. Status enum reference

| status | meaning |
|---|---|
| `ok` | Command ran cleanly and at least one HTTP request was captured. The param list in `commands[cmd]` is high-confidence. |
| `ok_no_capture` | Command ran cleanly (rc=0) but made no HTTP calls. Either the command genuinely needs no HTTP (rare) OR our seeded params didn't trigger any HTTP path. The param list is from static analysis only. |
| `param_caused_failure` | Command failed AND we identified the specific params that caused the failure (their sentinels appeared in the error message). Those params are pre-elevated into `commands[cmd]`. Other params for that command are static-only. |
| `no_data` | Command failed but no specific param attribution could be made. The param list comes from static analysis only. |
| `timeout` | Command hit the per-command wall-clock timeout. |
| `docker_error` | Docker invocation itself failed (image pull, daemon down, etc.). The whole integration's dynamic phase is unreliable; rely on static. |
| `module_not_found` | Child crashed with `ModuleNotFoundError`. Integration needs a third-party package not in the runtime image. **AI must step in manually** (analogous to JS / PowerShell). The `missing_module` field names the missing package. |

### 5. CRITICAL — Use diagnostics for AI judgment, NEVER write them to pipeline data

> ⚠️ **The `diagnostics` field is stderr-equivalent metadata. It MUST NEVER appear in any persisted pipeline artifact (CSV, manifest, `set-params-to-commands` payload, etc.).**

It exists ONLY for the skill's internal decision-making. The skill MUST:

- Read `diagnostics` to assess confidence in each command's param list.
- Use the `failure_excerpt` and `failing_params` to investigate the integration source code when needed.
- Write **only the polished `commands` data** into the pipeline (CSV / manifest / wherever).
- **Never include `diagnostics`, `failure_excerpt`, `status`, or `captured_requests` in any persisted output.**

The pipeline data is meant to be a clean machine-readable artifact. Diagnostics are debugging context for the AI — they get consumed and discarded. When invoking `set-params-to-commands`, the JSON payload must contain only `integration` and `commands` keys (per [`column-schemas.md`](column-schemas.md)) — strip everything else.

### 6. Decision tree for processing the analyzer's output

Given the analyzer's JSON for an integration, the skill should:

**Step 0** — If MOST commands have `status: "module_not_found"`, the integration depends on a third-party package not in the runtime image. Dynamic analysis produced no useful signal. **Read the integration source code and YML directly to write a polished result manually**, exactly as you would for a JavaScript or PowerShell integration. The `missing_module` field tells you which package was needed.

**Step 1.** If the analyzer process exited non-zero (the batch runner wraps this as `{"error": ..., "stderr": ...}` in the cell): treat as a structural failure. Read the integration source, decide manually what each command needs, write a polished result. Do NOT propagate the error into the pipeline.

**Step 2.** If `commands` is non-empty AND most commands have `status: "ok"`: the analyzer's output is high-confidence. Write `commands` as-is into the pipeline data.

**Step 3.** If many commands have `status: "param_caused_failure"`: the analyzer identified the problematic params. They're already merged into `commands[cmd]`. Read the `failure_excerpt` and the integration source to understand whether the param really applies to all commands or just to startup logic. **When in doubt, leave the param attributed to that command (err on inclusion).**

**Step 4.** If many commands have `status: "no_data"` or `status: "ok_no_capture"`: the analyzer couldn't get a strong signal. Read the integration source and trace which params each command's handler uses. Write the resulting per-command list into the pipeline. **When in doubt, include rather than exclude.**

> **Hybrid Scope-1 narrowing & the err-on-inclusion rule.** The analyzer applies a narrowing pass that only fires for commands which captured ≥1 HTTP request *and* hit ≥1 sentinel — typically only ~10–20% of commands per integration. Those commands are flagged with `diagnostics[cmd].scope_1_narrowed: true` and you can trust their per-command list more (HTTP evidence backed it; the dropped Scope-1 params are listed in `scope_1_dropped` for transparency).
>
> The remaining ~80% of commands still receive the **full Scope-1 static union**, which can include false positives from the `Client(api_key=..., max_fetch=..., custom_credentials=...)` fan-out pattern in `main()`. When you see a column where many commands share a suspiciously-identical large param list (the fan-out signature), consult the source code and prune obvious Client-only params for commands that don't actually use them — but **continue to err on inclusion**: a real param missing silently breaks the migrated integration, while an extra param is merely cosmetic noise.

**Step 5.** Always sanity-check: are there commands in the YML that the analyzer missed? Are there params clearly used in a command's source code that don't appear in the analyzer's list? If yes, add them.

### 7. The "err on inclusion" principle

When the skill is uncertain whether a param belongs to a command, it should INCLUDE the param. The cost of a false positive (an unused param shown in the column) is much lower than a false negative (a real param missing, which would silently break the migrated integration).

Specifically: if the analyzer says param X is NOT relevant for command Y, but the skill's source-code review suggests param X IS used by Y (even indirectly), the skill should add X to Y's list.

### 8. Self-contained operation

The skill does NOT need to:

- Start the capture proxy (the analyzer starts it internally per integration on a free port).
- Manage Docker containers (the analyzer pulls images and spawns containers automatically).
- Manage temp directories (the analyzer uses ephemeral tmp dirs that auto-clean).

By default the analyzer runs the child in `demisto/py3-native:8.9.0.114862` (a single pinned image; the integration's YML `script.dockerimage` is intentionally ignored for batch reproducibility). When the analyzer reports `module_not_found` for an integration, the skill has two options:

1. **Re-run with the integration's own runtime** by adding `--use-integration-docker` to the invocation. This honours `script.dockerimage` from the integration YML, which usually has the missing third-party package (e.g. `httpx`, `pymisp`) preinstalled. Prefer this when the missing package is a standard one and the integration is not exotic — it lets the analyzer recover full dynamic signal automatically.

2. **Read the integration source manually** (the original procedure: analogous to JS / PowerShell handling). Prefer this when the per-integration image is unusually large, unavailable from the registry, or already known to break under the analyzer's bootstrap shim.

The `missing_module` field in the diagnostic names the missing package — use it to decide between (1) and (2). Switching to `--use-integration-docker` is the lower-effort path; manual source review is the safer fallback.

The skill ONLY needs to:

- Have `python3` available on the host.
- Have `docker` available on the host (for non-trivial integrations; otherwise pass `--docker never`).
- Pass [`connectus/default_ignore_params.txt`](default_ignore_params.txt) via `--ignore-params-file` to filter out auth/connection/framework noise.

### 9. Runtime expectations

- Per-integration wall time: ~5–60 seconds (depends on number of commands + whether the integration's Docker image is already cached).
- First-time run on a host: each distinct Docker image needs a one-time pull (20–60s per image).
- Failure modes are loud: the analyzer never silently produces garbage. If something is wrong, you'll see a clear stderr message.

### 10. Non-Python integrations (JavaScript / PowerShell)

The analyzer's two phases handle non-Python integrations
asymmetrically:

- **Static analysis**: graceful skip — empty static set, clear stderr
  log, the analyzer process still exits `0`.
- **Dynamic analysis (current)**: exits non-zero (rc=3) with empty
  stdout. (This asymmetry is a known limitation tracked as a future
  improvement — see
  [`check_command_params_design.md`](check_command_params_design.md:1)
  §"Language asymmetry".)

For the AI, **treat any JavaScript or PowerShell integration the same
way you treat `module_not_found`**: ignore the analyzer's output,
read the integration source + YML directly, and write a polished
per-command param list manually. The batch runner surfaces the rc=3
as `{"error": ..., "stderr": ...}` in the cell — Step 1 of the
decision tree (§6 above) covers this case. **Never propagate the
error into the persisted pipeline data.**

> ⚠️ **One more time, because it matters:** when you write the
> `set-params-to-commands` payload, it must contain ONLY
> `integration` and `commands` keys. No `diagnostics`, no `status`,
> no `failure_excerpt`, no `error`, no `stderr`. The pipeline cell is
> a clean machine-readable artifact; everything else is debugging
> context that must be discarded.

### Step 2: Set Params to Commands (workflow data column)

Define which integration commands need which parameter IDs (excluding connection-level params). See [`connectus/column-schemas.md`](column-schemas.md) for the JSON shape.

```bash
python3 connectus/workflow_state.py set-params-to-commands "<Integration ID>" '<JSON>'
```

Derive the contents from the integration's existing YAML `configuration` and `script.commands` sections, plus any per-command param usage in the Python code.

Example (post-ignore-list — only behavioral params; `url`,
`credentials`, `longRunning`, etc. are stripped by
[`connectus/default_ignore_params.txt`](default_ignore_params.txt)):

```bash
python3 connectus/workflow_state.py set-params-to-commands "QRadar v3" '{"integration":"QRadar v3","commands":{"test-module":["adv_params","fetch_query"],"qradar-offenses-list":["fetch_query","filter"]}}'
```

**Validation:** The command rejects invalid JSON with the parse error.

### Step 3: Set Params for test with default in code (workflow data column)

List the parameter IDs whose default value is hardcoded in the integration source (and therefore must be substituted during testing).

```bash
python3 connectus/workflow_state.py set-params-for-test "<Integration ID>" '<JSON>'
```

Either a JSON array of strings or an object keyed by param ID is accepted (see [`column-schemas.md`](column-schemas.md)).

Example:

```bash
python3 connectus/workflow_state.py set-params-for-test "Cisco Spark" '["bot_token"]'
```

### Step 3.5 (Optional): Set Params same in other handlers

If this integration is part of a multi-handler family, list parameter IDs that are shared verbatim with sibling handlers.

```bash
python3 connectus/workflow_state.py set-shared-params "<Integration ID>" '<JSON>'
```

This column is **optional** — leave it empty if the integration is standalone or has no shared params. It is never a prerequisite for any checkpoint.

### Step 4: Mark `generated manifest` (first checkpoint)

After generating the ConnectUs manifest YAML for the integration:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "generated manifest"
```

Prerequisites: `Params to Commands` AND `Params for test with default in code` must both be set (valid JSON). The state machine enforces this and tells you which one is missing if either is unset.

### Step 5: `run manifest make validate`

Run the manifest's `make validate` step:

```bash
demisto-sdk validate -i Packs/<PackName>/Integrations/<IntegrationName>/
```

When it passes:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "run manifest make validate"
```

If it fails, fix the issues. To reset:

```bash
python3 connectus/workflow_state.py fail "<Integration ID>" "run manifest make validate"
```

### Step 6: `wrote/checked code`

Write or check the Python/JavaScript/PowerShell integration code. Follow patterns in `Templates/Integrations/` and the project's [`AGENTS.md`](../AGENTS.md) rules:

- Import `demistomock as demisto` at the top
- Import `from CommonServerPython import *`
- Use `demisto.params()` for configuration, `demisto.args()` for command arguments
- Use `CommandResults` with `return_results()`
- Use `return_error()` for user-facing errors
- Use `demisto.debug()` / `demisto.info()` for logging, never `print()`

When code is written/checked:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "wrote/checked code"
```

### Step 7: `shadowed command test passes`

Verify that integrations in the same connector do not have conflicting or shadowed commands. (The exact tooling is defined elsewhere; for now this is a manual review.)

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "shadowed command test passes"
```

### Step 8: `write tests`

Write unit tests for the integration:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "write tests"
```

### Step 9: `precommit/validate/unit tests passed`

Run pre-commit, validate, and unit tests via demisto-sdk pre-commit (Docker):

```bash
demisto-sdk pre-commit -i Packs/<PackName>/Integrations/<IntegrationName>/
```

When everything passes (Yuval decides which checks may be skipped):

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "precommit/validate/unit tests passed"
```

### Step 10: Auth Parity Flag

This is a **flag**, not a checkpoint. Set it based on whether the integration requires auth parity testing:

```bash
# If auth parity testing is needed
python3 connectus/workflow_state.py set-auth-flag "<Integration ID>" YES

# If NOT needed (e.g., NoneRequired auth)
python3 connectus/workflow_state.py set-auth-flag "<Integration ID>" NO

# If not applicable
python3 connectus/workflow_state.py set-auth-flag "<Integration ID>" N/A
```

When set to `NO` or `N/A`, the next checkpoint (`auth parity test passes`) is automatically set to `N/A` and skipped.

### Step 11: `auth parity test passes`

Only meaningful if the flag is `YES`. Run the auth parity test to verify authentication works identically:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "auth parity test passes"
```

If the flag was `NO` or `N/A`, this step is auto-skipped.

### Step 12: `param parity test passes`

Run the parameter parity test to verify the ConnectUs integration's parameters match the original:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "param parity test passes"
```

### Step 13: `code reviewed`

After code review is complete:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "code reviewed"
```

### Step 14: `code merged`

After the code is merged to the branch:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "code merged"
```

## Error Recovery Commands

### Fail a checkpoint (resets it and all subsequent checkpoints)

```bash
python3 connectus/workflow_state.py fail "<Integration ID>" "<checkpoint name>"
```

### Reset to a specific checkpoint

```bash
python3 connectus/workflow_state.py reset-to "<Integration ID>" "<checkpoint name>"
```

### Reset all workflow columns

```bash
python3 connectus/workflow_state.py reset "<Integration ID>"
```

## Dashboard and Batch Commands

```bash
# See all integrations with progress
python3 connectus/workflow_state.py dashboard

# See all integrations at a specific checkpoint
python3 connectus/workflow_state.py at-step "<checkpoint name>"

# See all integrations with any progress
python3 connectus/workflow_state.py status-all

# See all integrations assigned to a specific person
python3 connectus/workflow_state.py list-by-assignee "<assignee name>"

# Show one column's value for an integration (pretty-prints JSON)
python3 connectus/workflow_state.py show-step "<Integration ID>" "<column>"

# Set Auth Details (validates JSON schema, resets workflow to 'generated manifest')
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<Auth Details JSON>'
```

### Connector- and assignee-scoped batch commands

These power the [Assignee batch flow](#assignee-batch-flow) and [Connector batch flow](#connector-batch-flow).

```bash
# All distinct connector ids with per-connector counts (total / in progress / complete)
python3 connectus/workflow_state.py list-connectors

# All integrations belonging to one connector (with assignee + current step)
python3 connectus/workflow_state.py list-by-connector "<connector_id>"

# Bulk-assign every integration in a connector to one owner.
# NEVER cascades — existing migration progress is preserved.
python3 connectus/workflow_state.py set-assignee-by-connector "<connector_id>" "<assignee name>"

# `next` flags for batch flows:
python3 connectus/workflow_state.py next --mine                         # in-progress + assigned to current git user (alias of bare `next`)
python3 connectus/workflow_state.py next --connector "<connector_id>"   # in-progress integrations in that connector
python3 connectus/workflow_state.py next --connector "<id>" --mine      # intersection of the above
```

Programmatic API (importable from `connectus.workflow_state`) used by the batch flows:

- `list_integrations_by_connector(connector_id)` → `list[dict]`
- `integrations_for_assignee(assignee_name)` → `list[dict]`
- `assign_connector(connector_id, assignee_name)` → `dict` (no cascade reset)

Each summary dict contains: `integration_id`, `connector_id`, `assignee`, `current_step`, `current_step_index`, `completed_steps`, `all_complete`, `has_progress`.

## Auth Type Reference

When analyzing an integration's authentication, use these enum values inside `Auth Details` `auth_types[].type` and `params.<name>.type`:

| Auth Type Enum | Description |
|---|---|
| `OAuth2AuthCode` | OAuth 2.0 Authorization Code flow |
| `OAuth2ClientCreds` | OAuth 2.0 Client Credentials flow |
| `OAuth2JWT` | OAuth 2.0 JWT Bearer flow |
| `APIKey` | API key authentication (header or query parameter) |
| `Plain` | Simple credentials (username/password, token, etc.) |
| `Other` | Catch-all (DeviceCode, ROPC, ManagedIdentity, custom signing) — `notes` MUST explain |
| `NoneRequired` | No authentication required |

## Auth Requirement Semantics

- **REQUIRED(X)** — Auth type X must be configured
- **OPTIONAL(X)** — Auth type X can optionally be configured
- **CHOICE(X, Y)** — User picks one of X or Y
- **REQUIRED(X) + OPTIONAL(Y)** — X is mandatory, Y is additional/optional

## Mode Switching Guidance

Different workflow steps are best handled in different modes:

| Step | Recommended Mode |
|------|-----------------|
| Analyzing auth class, understanding integration | Ask |
| Planning Params to Commands, designing manifest | Architect |
| Writing integration code, unit tests | Code |
| Fixing validation/test failures | Debug |
| Full migration lifecycle coordination | Orchestrator |

When switching modes, the skill will be re-loaded automatically if the user's request matches the skill trigger.
