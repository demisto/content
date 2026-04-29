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

## Critical Rules

1. **NEVER edit [`connectus/integrations_report.csv`](integrations_report.csv) directly.** All CSV modifications MUST go through [`connectus/workflow_state.py`](workflow_state.py) CLI commands.
2. **Follow the workflow checkpoints sequentially.** You cannot skip ahead — the state machine enforces ordering.
3. **Always check status first** before doing any work on an integration.
4. **Use `execute_command`** to run all `workflow_state.py` commands from the workspace root.
5. **Use `set-auth` to update Auth Details.** When correcting auth classifications, use `python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>'`. This validates the JSON schema and automatically resets the workflow back to the first checkpoint (`generated manifest`).
6. If a checkpoint does not pass, it might be because a previous step was not done well — go back to it via `fail` or `reset-to`.

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

### Step 2: Set Params to Commands (workflow data column)

Define which integration commands need which parameter IDs (excluding connection-level params). See [`connectus/column-schemas.md`](column-schemas.md) for the JSON shape.

```bash
python3 connectus/workflow_state.py set-params-to-commands "<Integration ID>" '<JSON>'
```

Derive the contents from the integration's existing YAML `configuration` and `script.commands` sections, plus any per-command param usage in the Python code.

Example:

```bash
python3 connectus/workflow_state.py set-params-to-commands "QRadar v3" '{"integration":"QRadar v3","commands":{"test-module":["url","credentials"],"qradar-offenses-list":["max_fetch","longRunning"]}}'
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
