---
name: connectus-migration
description: This skill should be used when migrating integrations to connectus
---

# ConnectUs Migration Skill

## Overview

This skill guides the migration of XSOAR/XSIAM integrations to the ConnectUs platform. Each integration follows a **12-step workflow** tracked in `connectus/integrations_report.csv` via the `connectus/workflow_state.py` CLI tool. Step 1 (Verify Auth Classification) is a manual pre-check; steps 2–12 are tracked by the state machine.

## Critical Rules

1. **NEVER edit `connectus/integrations_report.csv` directly.** All CSV modifications MUST go through `connectus/workflow_state.py` CLI commands.
2. **Follow the workflow steps sequentially.** You cannot skip ahead — the state machine enforces ordering.
3. **Always check status first** before doing any work on an integration.
4. **Use `execute_command` to run all workflow_state.py commands** from the workspace root.
5. **Use `set-auth` to update Auth Detail.** When correcting auth classifications, use `python3 connectus/workflow_state.py set-auth "<name>" '<json>'` instead of editing the CSV directly. This validates the JSON schema and automatically resets the workflow to the `auth params set` step.
6. If a step does not pass, such as unit tests passing other any other step, it might be because a previous step was not done well and you should go back to it.

## Linked Files

- `connectus/Readme.md` — Full reference for auth types, CSV columns, and workflow walkthrough
- `connectus/workflow_state.py` — The state machine CLI (source of truth for workflow)
- `connectus/integrations_report.csv` — The tracking spreadsheet (DO NOT EDIT DIRECTLY)

## Step 0: Identify the Integration

When the user asks to migrate an integration, first identify it:

```bash
# List all available integrations
python3 connectus/workflow_state.py list

# Check current status
python3 connectus/workflow_state.py status "<Integration Name>"
```

The status output shows:
- **Assignee** — who is working on it
- **Support Level** — `xsoar`, `partner`, or `community`
- **Provider** — the vendor
- **Auth Detail** — authentication detail JSON (with embedded `config` expression)
- **Workflow Progress** — which steps are done, which remain
- **Current step** — what to work on next

If the integration has no assignee, set one:

```bash
python3 connectus/workflow_state.py set-assignee "<Integration Name>" "<Name>"
```

## Workflow Steps

### Step 1: Verify Auth Classification

**Before starting any migration work**, rigorously verify that the Auth Detail for this integration is correct. The automated classifier analyzed YML param metadata (widget types) and has systematic errors — a manual review of 148 integrations found **71 corrections** (48% error rate). Every integration MUST be validated before proceeding.

#### Validation Checklist

Follow this checklist for EVERY integration. Do not skip any step.

1. ☐ Run `workflow_state.py status` to get current classification
2. ☐ Locate the integration files (YML + Python)
3. ☐ Extract auth params from YML `configuration` section
4. ☐ Analyze Python code for actual auth mechanism
5. ☐ Cross-reference YML params with code usage
6. ☐ Validate Auth Detail JSON structure
7. ☐ Determine if corrections are needed
8. ☐ Apply corrections if needed
9. ☐ Mark step as passed

---

#### 1.1 Check Current Classification

```bash
python3 connectus/workflow_state.py status "<Integration Name>"
```

Note the **Auth Detail** value from the output (its `config` field is the Auth Config Expression). This is what you will validate.

---

#### 1.2 Locate Integration Files

Integration files follow this structure:
- **YML**: `Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>.yml`
- **Python**: `Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>.py`

> **Important:** The integration name in the CSV may differ from the directory name (e.g., spaces, capitalization, version suffixes). Use `find` to locate:

```bash
find Packs/ -path "*/Integrations/*/*.yml" -name "*.yml" | grep -i "<integration_name>"
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

#### 1.8 Auth Detail JSON Validation

After determining the correct auth types, validate the Auth Detail JSON against these rules (from `connectus/auth_class_format_spec.md`):

1. Must be valid JSON with keys: `auth_types`, `config`, `params`, `notes`
2. `auth_types` entries sorted by `(type, name)`
3. Every param in `params` must appear in `auth_types` (by name)
4. Every type in `config` must appear in at least one param's `type` field, OR be explained in `notes`
5. If `config` is `NONE`, then `auth_types` must be `[]` and `params` must be `{}`
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

When corrections are needed, use the `set-auth` command to update the Auth Detail:

```bash
python3 connectus/workflow_state.py set-auth "<Integration Name>" '<Auth Detail JSON>'
```

This command:
- Validates the Auth Detail JSON against the schema (auth_types, config, params, notes)
- Sets the `Auth Detail` column in the CSV
- Automatically resets the workflow to the `auth params set` step (clears all downstream progress)
- Rejects invalid JSON with specific error messages

Example:
```bash
python3 connectus/workflow_state.py set-auth "Abnormal Security" '{"auth_types":[{"type":"APIKey","name":"api_key"}],"config":"REQUIRED(APIKey)","params":{"api_key":{"type":"APIKey","xsoar_type":4,"required":true}},"notes":null}'
```

After setting the auth, verify it looks correct:
```bash
python3 connectus/workflow_state.py status "<Integration Name>"
```

---

#### 1.11 Marking Step as Passed

After verification (whether corrections were needed or not):

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "auth params set"
```

#### Auth Type Reference

See `connectus/Readme.md` for the full Auth Type definitions:

| Value | Description |
|---|---|
| `OAuth2AuthCode` | OAuth 2.0 Authorization Code flow |
| `OAuth2ClientCreds` | OAuth 2.0 Client Credentials flow |
| `OAuth2JWT` | OAuth 2.0 JWT Bearer flow |
| `APIKey` | API Key, HMAC, and similar static secret mechanisms |
| `Plain` | Plain text fields: username/password, basic auth, bearer tokens, AWS credentials, certificates |
| `NoneRequired` | No authentication needed |

### Step 2: Set Script Inputs (column 7)

Before any code generation, you must define the script inputs as valid JSON. This is a prerequisite for all subsequent steps.

```bash
python3 connectus/workflow_state.py set-inputs "<Integration Name>" '<JSON>'
```

The JSON should describe the parameters the integration needs. Derive these from the **Auth Detail** column in the status output and from examining the integration's existing YAML configuration.

- **Auth Detail** column — contains JSON with keys: `auth_types`, `config`, `params`, `notes`. The `config` field uses the Auth Config Expression Format: `Type(params) | Type2(params) — EXPR`.

Example: For an integration whose Auth Detail `config` is `Plain(credentials) — REQUIRED`:
```bash
python3 connectus/workflow_state.py set-inputs "MyIntegration" '{"credentials": {"type": "type9", "required": true, "auth_class": "Plain"}}'
```

**Validation:** The command rejects invalid JSON and tells you the parse error.

### Step 3: Generate Manifest (column 8)

Generate the ConnectUs manifest YAML for the integration. Once generated and verified:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "generated manifest"
```

### Step 4: Write Code (column 9)

Write the Python integration code. Follow the patterns in `Templates/Integrations/` and the project's `AGENTS.md` rules:

- Import `demistomock as demisto` at the top
- Import `from CommonServerPython import *`
- Use `demisto.params()` for configuration, `demisto.args()` for command arguments
- Use `CommandResults` with `return_results()`
- Use `return_error()` for user-facing errors
- Use `demisto.debug()` / `demisto.info()` for logging, never `print()`

When code is written:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "wrote code"
```

### Step 5: Validations Passed (column 10)

Run `demisto-sdk validate` on the integration:

```bash
demisto-sdk validate -i Packs/<PackName>/Integrations/<IntegrationName>/
```

If validation passes:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "validations passed"
```

If validation fails, fix the issues and retry. If you need to reset:

```bash
python3 connectus/workflow_state.py fail "<Integration Name>" "validations passed"
```

### Step 6: Unit Tests Passed (column 11)

Run unit tests via demisto-sdk pre-commit (which runs in Docker):

```bash
demisto-sdk pre-commit -i Packs/<PackName>/Integrations/<IntegrationName>/
```

When tests pass:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "unit tests passed"
```

### Step 7: Param Parity Test Passes (column 12)

Run the parameter parity test to verify the ConnectUs integration's parameters match the original:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "param parity test passes"
```

### Step 8: Shadowed Command Test Passes (column 14)

Verify that integrations in the same connector do not have conflicting or shadowed commands. This is a placeholder step — the specific test procedure will be defined later.

When the test passes:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "shadowed command test passes"
```

### Step 9: Auth Parity Flag (column 15)

This is a **flag**, not a checkpoint. Set it based on whether the integration requires auth parity testing:

```bash
# If auth parity testing is needed
python3 connectus/workflow_state.py set-auth-flag "<Integration Name>" YES

# If NOT needed (e.g., NONE auth type)
python3 connectus/workflow_state.py set-auth-flag "<Integration Name>" NO

# If not applicable
python3 connectus/workflow_state.py set-auth-flag "<Integration Name>" N/A
```

**Important:** When set to `NO` or `N/A`, the next step (auth parity test passes) is automatically set to `N/A` and skipped.

### Step 10: Auth Parity Test Passes (column 16)

Only relevant if the auth flag is `YES`. Run the auth parity test to verify authentication works identically:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "auth parity test passes"
```

If the flag was `NO` or `N/A`, this step is auto-skipped.

### Step 11: Code Reviewed (column 17)

After code review is complete:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "code reviewed"
```

### Step 12: Code Merged (column 18)

After the code is merged to the branch:

```bash
python3 connectus/workflow_state.py markpass "<Integration Name>" "code merged"
```

## Error Recovery Commands

### Fail a step (resets it and all subsequent steps)

```bash
python3 connectus/workflow_state.py fail "<Integration Name>" "<step name>"
```

### Reset to a specific stage

```bash
python3 connectus/workflow_state.py reset-to "<Integration Name>" "<step name>"
```

### Reset all workflow columns

```bash
python3 connectus/workflow_state.py reset "<Integration Name>"
```

## Dashboard and Batch Commands

```bash
# See all integrations with progress
python3 connectus/workflow_state.py dashboard

# See all integrations at a specific step
python3 connectus/workflow_state.py at-step "<step name>"

# See all integrations with any progress
python3 connectus/workflow_state.py status-all

# See all integrations assigned to a specific person
python3 connectus/workflow_state.py list-by-assignee "<assignee name>"

# Set auth detail (validates JSON schema, resets workflow to auth params set)
python3 connectus/workflow_state.py set-auth "<Integration Name>" '<Auth Detail JSON>'
```

## Auth Type Reference

When analyzing an integration's authentication, use these enum values (the `type` field inside Auth Detail's `auth_types` and `params`):

| Auth Type Enum | Description |
|---|---|
| `OAuth2AuthCode` | OAuth 2.0 Authorization Code flow |
| `OAuth2ClientCreds` | OAuth 2.0 Client Credentials flow |
| `OAuth2JWT` | OAuth 2.0 JWT Bearer flow |
| `APIKey` | API key authentication (header or query parameter) |
| `Plain` | Simple credentials (username/password, token, etc.) |
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
| Planning script inputs, designing manifest | Architect |
| Writing integration code, unit tests | Code |
| Fixing validation/test failures | Debug |
| Full migration lifecycle coordination | Orchestrator |

When switching modes, the skill will be re-loaded automatically if the user's request matches the skill trigger.
