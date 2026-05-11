---
name: connectus-migration
description: This skill should be used when migrating integrations to connectus
---

# ConnectUs Migration Skill

## Overview

This skill guides the migration of XSOAR/XSIAM integrations to the ConnectUs platform. Each integration follows a workflow tracked in [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv) via the [`connectus/workflow_state.py`](workflow_state.py) CLI tool.

The CSV has two kinds of columns (see [`connectus/Readme.md`](Readme.md) for full details):

- **Data columns** (3) — identity / metadata: `Integration ID`, `Integration File Path`, `Connector ID`.
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

1. **NEVER edit [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv) directly.** All CSV modifications MUST go through [`connectus/workflow_state.py`](workflow_state.py) CLI commands.
2. **Follow the workflow checkpoints sequentially.** You cannot skip ahead — the state machine enforces ordering.
3. **Always check status first** before doing any work on an integration.
4. **Use `execute_command`** to run all `workflow_state.py` commands from the workspace root.
5. **Use `set-auth` to update Auth Details.** When correcting auth classifications, use `python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>'`. This validates the JSON schema and automatically resets the workflow back to the first checkpoint (`generated manifest`).
6. If a checkpoint does not pass, it might be because a previous step was not done well — go back to it via `fail` or `reset-to`.
7. Try to be efficient in what needs input from the user. If you have an option to read files instead of grep, or batch commands to the cli, it is better.

## Linked Files

- [`connectus/Readme.md`](Readme.md) — Full reference for auth types, CSV columns, walkthrough.
- [`connectus/column-schemas.md`](column-schemas.md) — JSON shapes for `Auth Details`, `Params to Commands`, `Params for test with default in code`, `Params same in other handlers`.
- [`connectus/workflow_state.py`](workflow_state.py) — The state machine CLI (source of truth for workflow). Provides the `files <integration_id>` subcommand and the [`get_integration_files()`](workflow_state.py) helper used to resolve every source file for an integration (see [§1.1](#11-locate-integration-files)).
- [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv) — The tracking spreadsheet (DO NOT EDIT DIRECTLY).

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
- **File Path** — path to the integration's source files (data column). If you need every related file (YML + code + description + README + test), don't infer sibling names — run `python3 connectus/workflow_state.py files "<Integration ID>"` (see [§1.1](#11-locate-integration-files)).
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

### Step 1: Classify Auth (prerequisite — not a checkpoint)

**Before starting any migration work**, the skill must actively read the integration's YML and Python source, derive the correct `Auth Details` JSON from scratch, and write it via `set-auth`. Do **not** trust any pre-existing value in the CSV — past automated classification of 148 integrations had a **48% error rate (71/148 wrong)**. Always re-derive from the source files.

`Auth Details` is a workflow data column (not a checkpoint), so there is no `markpass` for it; calling `set-auth` is what registers the classification AND resets the workflow back to `generated manifest`.

#### Procedure (do every step in order)

1. ☐ Resolve all integration source-file paths via `python3 connectus/workflow_state.py files "<Integration ID>"` (or [`get_integration_files()`](workflow_state.py) programmatically). Do **NOT** search the repo manually with `find` / `ls` / `grep`. See [1.1](#11-locate-integration-files) and [1.2](#12-researching-auth-details--the-four-sources-of-truth).
2. ☐ Walk the four sources of truth in order — see [1.2](#12-researching-auth-details--the-four-sources-of-truth)
3. ☐ Extract every auth-related param from the YML `configuration` section — see [1.3](#13-yml-analysis-procedure)
4. ☐ Read the Python code to determine the actual auth mechanism(s) used at runtime — see [1.4](#14-python-code-analysis--specific-patterns)
5. ☐ Cross-reference each YML param with where/how it is consumed in code — see [1.5](#15-cross-reference-yml-params-with-code-usage)
6. ☐ Classify each connection via the [decision table](#121-classification-decision-table); build each entry per [1.2.2](#122-building-each-auth_types-entry); compose `config` per [1.2.3](#123-building-the-config-expression)
7. ☐ Extract the **connection-adjacent** YML params (URL, proxy, insecure, port, host, region, …) into the sorted `other_connection` list — see [1.2.5](#125-building-the-other_connection-list)
8. ☐ Sanity-check against [Known Misclassification Patterns](#16-known-misclassification-patterns) and the [Decision Tree](#19-decision-tree-for-auth-type)
9. ☐ Run the [Pre-flight self-check](#111-pre-flight-self-check)
10. ☐ Apply via `set-auth` (this validates the JSON schema and resets the workflow) — see [1.10](#110-applying-corrections)
11. ☐ Re-run `status` to confirm the value was stored as intended

The current CSV value, if any, is informational only — show it to the user for context but derive the new value entirely from the source code:

```bash
python3 connectus/workflow_state.py show-step "<Integration ID>" "Auth Details"
```

---

#### 1.1 Locate Integration Files

**The canonical way to get an integration's source files is the `files` subcommand of [`workflow_state.py`](workflow_state.py).** Do **NOT** manually `find` / `ls` / `grep` the repo for these files — the `Integration File Path` column in the CSV is populated for all 609 integrations, and `files` resolves every sibling (YML, code, description, README, test) from it.

```bash
python3 connectus/workflow_state.py files "<Integration ID>"
```

Sample output (default `text` format):

```text
============================================================
  CrowdstrikeFalcon — source files
============================================================
  Directory:    Packs/CrowdStrikeFalcon/Integrations/CrowdStrikeFalcon
  Base:         CrowdStrikeFalcon
  Language:     python

  YML:          Packs/CrowdStrikeFalcon/Integrations/CrowdStrikeFalcon/CrowdStrikeFalcon.yml
  Code:         Packs/CrowdStrikeFalcon/Integrations/CrowdStrikeFalcon/CrowdStrikeFalcon.py
  Description:  Packs/CrowdStrikeFalcon/Integrations/CrowdStrikeFalcon/CrowdStrikeFalcon_description.md
  README:       Packs/CrowdStrikeFalcon/Integrations/CrowdStrikeFalcon/README.md
  Test:         Packs/CrowdStrikeFalcon/Integrations/CrowdStrikeFalcon/CrowdStrikeFalcon_test.py
```

Three output formats are available — pick the one that matches how you'll consume the result:

| Format | Flag | Use when |
|---|---|---|
| `text` (default) | _(none)_ | Human review — eyeball the paths and confirm the integration. |
| `paths` | `--format=paths` | Piping into other tools. Emits one path per line in canonical order (`yml`, `code`, `description`, `readme`, `test`) — ideal for `xargs` / `cat` pipelines, e.g. `python3 connectus/workflow_state.py files "<Integration ID>" --format=paths \| xargs -I{} cat {}`. |
| `json` | `--format=json` | Programmatic / scripted consumption (machine-readable, all fields keyed). |

For in-process Python use, import the helper directly:

```python
from connectus.workflow_state import get_integration_files

files = get_integration_files("<Integration ID>")
# files["yml"], files["code"], files["description"], files["readme"], files["test"], plus any extras
```

The same `Integration File Path` value is also surfaced in `status` output as `File Path:`.

**If `files` returns an error** (e.g. the row's `Integration File Path` is missing or the recorded path no longer exists on disk), the column is missing or stale. **Surface this to the user and ask** — there is currently no `set-file-path` CLI setter; the column is data-imported. Do **NOT** fall back to manually searching the repo with `find` / `ls` / `grep`.

For background only: integration files conventionally live at `Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>.{yml,py,js,ps1}` with sibling `<IntegrationName>_description.md`, `README.md`, and `<IntegrationName>_test.py`. The `files` command is the source of truth — this layout is just background context.

---

#### 1.2 Researching `Auth Details` — the four sources of truth

Before you can write the JSON for `set-auth`, you must derive it from the integration pack itself — never guess from the param list alone. The shape you are building is documented in [`connectus/column-schemas.md`](column-schemas.md:16) and is enforced by [`validate_auth_detail()`](workflow_state.py:521); the validator now checks the `config` expression grammar AND that every name referenced in `config` exists as some `auth_types[].name`. Wrong input is rejected at the CLI — better to catch it at research time.

Read these four files **in this order**, treating each one as a cross-check on the previous:

1. **YML — `Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>.yml`.** Open the `configuration:` list and tabulate every param: `name`, `type`, `display`, `required`, `displaypassword` (if present), `hidden`, and `additionalinfo`. The param `type` codes you must recognize:
   - `0` — Short text (often hostnames, IDs, public keys).
   - `4` — Encrypted text (API keys, tokens, secrets — flat, single value).
   - `8` — Checkbox.
   - `9` — Credentials (compound: a `username`/`identifier` + `password` pair). When this type is used, the field path expands to **two** leaf fields: `<paramid>.identifier` AND `<paramid>.password`.
   - `14` — Authentication Certificate (cert + key).
   - `15` — Single select (often the `auth_type` selector for multi-auth integrations).
   - `16` — Multi select.
   - `17` — TextArea (often used for JSON config / private keys).
   - (Other types like `1`, `12`, `13` exist but are typically connection metadata, not auth secrets.)

   This file tells you *what could be auth* — never *what is auth*. The source code is the only source of truth for which YML param actually feeds which auth flow. If a parameter is hidden or deprecated it should be skipped.

2. **Source — `<IntegrationName>.py` (or `.js` / `.ps1`).** This is the source of truth. Grep / read for:
   - Reads of `demisto.params()` — e.g. `params.get("api_key")`, `params.get("credentials", {}).get("password")`, `params['credentials']['identifier']`. Build a mental list of every YML param id the code actually consumes.
   - HTTP header construction — `Authorization: Bearer <...>`, `X-API-Key: <...>`, `Authorization: Basic <...>`, custom signed headers (HMAC).
   - OAuth helpers / token endpoints — `client_id`, `client_secret`, `grant_type=client_credentials`, `grant_type=password`, `redirect_uri`, JWT signing with a private key, `refresh_token`, `device_code`.
   - The `Client` / `BaseClient` constructor — what auth-related kwargs it takes.
   - The `test-module` command — what it tries to authenticate with (this is usually the cleanest auth flow read).

   For each YML param, trace where its value flows:
   - Becomes an `Authorization` header / API request signature → **auth secret**.
   - Becomes the URL / host / region → **connection metadata, NOT auth**.
   - Becomes a feature flag / fetch cadence / proxy toggle / verify-SSL boolean → **NOT auth**.
   - Sent to a token endpoint as `client_id` / `client_secret` / `assertion` / `refresh_token` → **part of an OAuth connection**.

3. **`<IntegrationName>_description.md`.** The short blurb shown in the XSOAR UI under the integration. Often spells out the auth method in one sentence — e.g. *"Generate an API key from the Settings page"*, *"Use OAuth 2.0 client credentials"*, *"Service account JSON key file required"*. Use it to confirm what the code is doing.

4. **`README.md`** (the per-integration one, in the same directory). Long-form docs. The setup / configuration section frequently spells out exactly which credentials each field requires and how to obtain them — invaluable when the source code is large or obfuscated.

If steps 1 and 2 disagree (e.g. the YML defines a `credentials` param but the code only ever reads `params.get('api_key')`), step 2 wins. Steps 3 and 4 are tiebreakers when the code is ambiguous.

---

#### 1.2.1 Classification decision table

Map "what you saw in the source" → "auth-type enum value" (the values are listed in [`VALID_AUTH_TYPES`](workflow_state.py:118)):

| You see... | Use type |
|---|---|
| `Authorization: Bearer <key>` from a single param, no token exchange | `APIKey` |
| `X-API-Key: <key>` / `apikey=<key>` query param / similar static header | `APIKey` |
| `Authorization: Basic <user>:<pass>` from a credentials (type `9`) or two flat params | `Plain` |
| Username + password posted to a login endpoint that returns a session cookie | `Plain` |
| OAuth2 with user-driven `code` + `redirect_uri` flow | `OAuth2AuthCode` |
| OAuth2 with `client_id` + `client_secret` (no user code, `grant_type=client_credentials`) | `OAuth2ClientCreds` |
| OAuth2 with a signed JWT assertion (private key + claims, `grant_type=jwt-bearer`) | `OAuth2JWT` |
| OAuth2 ROPC (`grant_type=password`), Device Code, Managed Identity, mTLS-only, HMAC signing, custom challenge/response | `Other` |
| No credentials at all (public API, or a feed that just hits a URL) | `NoneRequired` |

---

#### 1.2.2 Building each `auth_types[]` entry

Each `auth_types[]` entry describes **one complete UCP connection type** — one full auth flow, not one XSOAR param. See [`column-schemas.md`](column-schemas.md:34) for the authoritative shape. The rules you'll be applying as you build entries:

- **`type`** — the enum value chosen via the table above.
- **`name`** — a free-form logical id you choose (e.g. `"api_key"`, `"credentials"`, `"oauth_client"`, `"hunting_credentials"`). Must be unique within the row. **`config` references these names**, NOT the YML param ids and NOT the auth-type enum values.
- **`xsoar_params`** — the list of XSOAR field paths that supply the secrets for **this one** connection type:
  - For a flat param (YML type `0`/`4`/`14`/`17` etc.): use the bare param id, e.g. `"api_key"`, `"server_token"`.
  - For a credentials param (YML type `9`): list **both** sub-fields with dotted notation, e.g. `["credentials.identifier", "credentials.password"]`. Listing only one is wrong.
  - For a `Plain` auth built from two **separate** flat params: list both ids directly, e.g. `["server_user", "server_password"]`.
  - The same field path MAY appear in multiple entries (e.g. when one `credentials.password` backs both a Plain profile and an OAuth profile) — that's correct, list it in each entry's `xsoar_params`.
- **`interpolated`** (optional, defaults to `false`) — set to `true` only when the value is templated in at runtime by the manifest generator rather than supplied by the user. Rare; leave it out if you are not certain it applies.
- **Sort order** — entries are sorted by `(type, name)` ascending. The validator now enforces this — `set-auth` will reject unsorted input.

---

#### 1.2.3 Building the `config` expression

The grammar is small. See the worked examples in [`column-schemas.md`](column-schemas.md:73) for the canonical list.

- The literal `NoneRequired` — used **only** when there is genuinely no auth (and `auth_types` is `[]`).
- One or more clauses joined by ` + ` (with spaces around the plus). Each clause is one of:
  - `REQUIRED(name1, name2, ...)` — every listed connection type must be configured.
  - `OPTIONAL(name1, name2, ...)` — each listed connection type may be configured.
  - `CHOICE(name1, name2, ...)` — exactly one of the listed connection types must be configured.
- Operand names refer to `auth_types[].name` values. The validator REJECTS unknown names (it's the most common cause of `set-auth` failures).

Worked examples (re-using the canonical set):

- `REQUIRED(api_key)` — single required connection.
- `REQUIRED(privateApiKey, publicApiKey)` — two required connections.
- `CHOICE(credentials, hunting_credentials)` — pick one of two.
- `REQUIRED(credentials) + OPTIONAL(credentials_consumer)` — mandatory Plain plus optional OAuth.
- `NoneRequired` — no auth.

Don't strictly stick to if the corresponding xsoar parameters are required or not. There might be cases it isnt required due to supporting legacy, now hidden parameters. These should be required in this case if there is no alternate auth acceptable.

---

#### 1.2.5 Building the `other_connection` list

`other_connection` is a **flat sorted list of YML param ids** captured
inside the same `Auth Details` JSON. Its purpose is to record every
connection-adjacent YML param that is **not** an auth secret and **not**
a per-command behavioral param — i.e. everything you reasonably need to
define the integration's connection besides the secrets themselves.

The validator (see [`validate_auth_detail()`](workflow_state.py:521))
requires the key on every `set-auth` write; the field is required even
when empty (use `[]`).

##### What qualifies as connection-adjacent

A YML param qualifies if it is BOTH:

1. **Not an auth secret** (auth secrets go in `auth_types[].xsoar_params`), AND
2. **Not a per-command behavioral param** (those go in `Params to Commands`).

Concretely: things needed to direct the connection at the right server
with the right network settings.

##### Examples to INCLUDE

- `url`, `server_url`, `endpoint`, `host`, `server` — server addressing.
- `port` — network port.
- `insecure`, `unsecure`, `trust_any_certificate`, `verify_certificate`,
  `verify_ssl` — TLS verification toggles.
- `proxy`, `use_system_proxy`, `use_proxy` — proxy toggles.
- `region`, `data_center`, `cloud` — routing selectors **when used purely
  to pick the endpoint**, not to authenticate against a tenant.
- `tenant_id`, `subscription_id`, `account_id` — when used as a routing /
  identifier and **NOT** as an auth secret. (If the param is hashed into
  a signed request → it is an auth secret, classify it under
  `auth_types[].xsoar_params` instead.)
- `api_version` — when it changes the URL path.

##### Examples to EXCLUDE

- **Auth secrets** — already captured in `auth_types[].xsoar_params`. Do
  not list them again here.
- **Per-command behavioral params** — `fetch_interval`, `first_fetch`,
  `max_fetch`, `incident_type`, `mirror_options`, `mirror_direction`,
  `query`, `enrichment`, etc. These belong in `Params to Commands`.
- **XSOAR framework params** — `longRunning`, `feedReputation`,
  `feedExpirationInterval`, `feedReliability`, `feedTags`. Ignored
  entirely; not in `Auth Details`, not in `Params to Commands`.
- **Hidden / deprecated params** — skip per the existing rule for auth.

##### Sorting requirement

The list must be sorted **ascending (alphabetical, case-sensitive)**.
The validator REJECTS unsorted input with a clear suggestion of the
sorted form, e.g.:

```
'other_connection' must be sorted ascending; got ['url', 'proxy'], expected ['proxy', 'url']
```

Strings must also be unique within the list and non-empty. An empty
list `[]` is valid (= "this integration has no connection-adjacent
params besides its auth secrets").

##### Worked mini-example

YML excerpt:

```yaml
- name: url
  display: Server URL
  type: 0
  required: true
- name: insecure
  display: Trust any certificate (not secure)
  type: 8
- name: proxy
  display: Use system proxy settings
  type: 8
```

Resulting field inside `Auth Details`:

```json
"other_connection": ["insecure", "proxy", "url"]
```

---

#### 1.2.4 Two end-to-end worked examples

**Example A — Bearer token API key (single flat param).**

YML excerpt:

```yaml
- name: api_key
  display: API Key
  type: 4
  required: true
```

Code excerpt:

```python
headers = {"Authorization": f"Bearer {params.get('api_key')}"}
```

Suppose the YML also defines `url`, `insecure`, and `proxy` alongside
`api_key` (the typical XSOAR connection-metadata trio). Then the
resulting JSON to pass to `set-auth`:

```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_params": ["api_key"]
    }
  ],
  "config": "REQUIRED(api_key)",
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Example B — Username/password credentials (type `9`) plus optional OAuth client creds reusing a second credentials param.**

YML excerpt:

```yaml
- name: url
  display: Server URL
  type: 0
  required: true
- name: credentials
  display: Username
  type: 9
  required: true
- name: credentials_consumer
  display: Consumer Key / Secret
  type: 9
  required: false
- name: insecure
  display: Trust any certificate (not secure)
  type: 8
- name: proxy
  display: Use system proxy settings
  type: 8
```

Code excerpt:

```python
basic = HTTPBasicAuth(params['credentials']['identifier'], params['credentials']['password'])
oauth = OAuth1(params['credentials_consumer']['identifier'],
               params['credentials_consumer']['password'], ...)
```

Resulting JSON (note entries sorted by `(type, name)` — `OAuth2ClientCreds` < `Plain` alphabetically; `other_connection` sorted ascending):

```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "credentials_consumer",
      "xsoar_params": ["credentials_consumer.identifier", "credentials_consumer.password"]
    },
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_params": ["credentials.identifier", "credentials.password"]
    }
  ],
  "config": "REQUIRED(credentials) + OPTIONAL(credentials_consumer)",
  "other_connection": ["insecure", "proxy", "url"]
}
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

**Managed Identity — classified as `Other`:**
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
| 4 | Microsoft/Azure missing ManagedIdentity | 23 | No mention | Add to `auth_types` as `Other` | Code imports `MicrosoftClient` and has `managed_identities_client_id` param |
| 5 | Microsoft/Azure missing DeviceCode | 12 | No mention | Add to `auth_types` as `Other` | Code has `device_code` grant type support |
| 6 | OAuth2 ROPC misclassified | 13 | `OAuth2ClientCreds` or `Plain` | `Other` (ROPC) | Code does `grant_type=password` |
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
  - DeviceCode and ManagedIdentity are classified as `Other` in the enum

---

#### 1.8 Auth Details JSON Validation

After determining the correct auth types, validate the Auth Details JSON against the rules in [`connectus/column-schemas.md`](column-schemas.md:16). The same rules are enforced at runtime by [`validate_auth_detail()`](workflow_state.py:521):

1. Must be valid JSON with top-level keys `auth_types` (array), `config` (string), AND `other_connection` (array of strings). All three are REQUIRED on every `set-auth` write — the validator rejects payloads missing any of them.
2. Each `auth_types[]` entry has a `type` (one of [`VALID_AUTH_TYPES`](workflow_state.py:118)), a unique `name`, and a non-empty `xsoar_params` array (unless the entry is `NoneRequired`-shaped).
3. `auth_types[]` entries are sorted by `(type, name)` ascending.
4. `config` is either the literal `NoneRequired`, or one or more clauses joined with ` + `, each clause being `REQUIRED(...)`, `OPTIONAL(...)`, or `CHOICE(...)`.
5. Every operand name appearing inside `config`'s parens MUST exist as some `auth_types[].name` (the most common cause of `set-auth` rejection).
6. If `config` is `NoneRequired`, then `auth_types` MUST be `[]`.
7. `other_connection` must be a list of **non-empty unique strings, sorted ascending**. Empty list `[]` is valid. The validator rejects unsorted input with a message that suggests the sorted form. See [1.2.5](#125-building-the-other_connection-list) for what belongs here.

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

- Validates the Auth Details JSON against the schema (`auth_types` + `config`) — see [`validate_auth_detail()`](workflow_state.py:521).
- Sets the `Auth Details` workflow data column in the CSV.
- Automatically **resets the workflow** to the first checkpoint (`generated manifest`) and clears all checkpoints + the auth-parity flag.
- Rejects invalid JSON with specific error messages — including unsorted `auth_types[]`, unknown names referenced from `config`, and malformed `config` expressions.

Example:

```bash
python3 connectus/workflow_state.py set-auth "Abnormal Security" '{"auth_types":[{"type":"APIKey","name":"api_key","xsoar_params":["api_key"]}],"config":"REQUIRED(api_key)","other_connection":["insecure","proxy","url"]}'
```

After setting, verify it looks correct:

```bash
python3 connectus/workflow_state.py status "<Integration ID>"
```

Note: there is **no `markpass "auth params set"`** anymore — the verification IS the `set-auth` call. The first markpass-able checkpoint is `generated manifest`.

---

#### 1.11 Pre-flight self-check

Before invoking `set-auth`, walk this checklist mentally. The validator will catch most of these but it's faster (and clearer) to catch them locally.

- [ ] Every YML param the source code reads as an auth secret is covered by some `auth_types[].xsoar_params`.
- [ ] No NON-auth param (URL, proxy, fetch interval, feature toggle, verify-SSL boolean) is in any `xsoar_params`.
- [ ] Every credentials-typed (YML type `9`) auth param appears as **both** `<id>.identifier` AND `<id>.password` (not just one).
- [ ] Every name referenced in `config` exists as some `auth_types[].name`.
- [ ] `auth_types[]` entries are sorted by `(type, name)` ascending.
- [ ] If there is genuinely no auth, `config` is exactly `NoneRequired` AND `auth_types` is `[]`.
- [ ] Connection metadata (URL, instance host, region) is intentionally NOT in `auth_types` — it goes in `other_connection` instead (see [1.2.5](#125-building-the-other_connection-list)).
- [ ] `other_connection` lists every connection-adjacent YML param (`url`, `proxy`, `insecure`, `port`, `host`, `region`, etc.).
- [ ] `other_connection` does NOT contain any auth-secret param (those are in `auth_types[].xsoar_params`).
- [ ] `other_connection` does NOT contain any per-command behavioral param (those go in `Params to Commands`).
- [ ] `other_connection` list is sorted ascending.

---

#### Auth Type Reference

See [`connectus/Readme.md`](Readme.md:19) for the full Auth Type definitions.

| Value | Description |
|---|---|
| `OAuth2AuthCode` | OAuth 2.0 Authorization Code flow |
| `OAuth2ClientCreds` | OAuth 2.0 Client Credentials flow |
| `OAuth2JWT` | OAuth 2.0 JWT Bearer flow |
| `APIKey` | API Key, HMAC, and similar static secret mechanisms |
| `Plain` | Plain text fields: username/password, basic auth, bearer tokens, AWS credentials, certificates |
| `Other` | Catch-all (e.g., DeviceCode, ROPC, ManagedIdentity, custom signing) |
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
  "integration": "IBM QRadar v3",
  "commands": {
    "test-module":            ["adv_params", "fetch_interval"],
    "qradar-offenses-list":   ["adv_params", "fetch_interval"],
    "long-running-execution": [
      "adv_params", "enrichment", "events_columns", "events_limit",
      "fetch_interval", "fetch_mode", "first_fetch", "incident_type",
      "limit_assets", "mirror_options", "offenses_per_fetch",
      "query", "retry_events_fetch"
    ]
  },
  "diagnostics": {
    "test-module": {
      "status": "param_caused_failure",
      "captured_requests": 0,
      "failure_excerpt": "integration_under_test.DemistoException: Failed to parse advanced parameter: SENTINEL_PARAM_adv_params - please make sure you entered it correctly",
      "failing_params": ["adv_params"]
    },
    "long-running-execution": {
      "status": "param_caused_failure",
      "captured_requests": 0,
      "failure_excerpt": "integration_under_test.DemistoException: Failed to parse advanced parameter: SENTINEL_PARAM_adv_params - please make sure you entered it correctly",
      "failing_params": ["adv_params"]
    }
  }
}
```

`commands` is the **finished, polished result** — these are the per-command param lists the skill writes into the pipeline data.

`diagnostics` is **internal AI signal only** — see section 5 below.

#### 3a. Per-field reference

For each command, the `diagnostics[cmd]` object always has:

- **`status`** — one of `ok` / `ok_no_capture` / `param_caused_failure` / `no_data` / `timeout` / `docker_error` / `module_not_found` (see §4).
- **`captured_requests`** — int. Always present in dynamic mode. Number of HTTP requests the capture proxy observed for this command.

Optional fields, present only under specific conditions:

- **`failure_excerpt`** — string, trimmed to ≤500 chars. Present when `status` is one of the failure-bearing values (`param_caused_failure`, `no_data`, `timeout`, `docker_error`, `module_not_found`); omitted on `ok` / `ok_no_capture`.
- **`failing_params`** — list of param names. Present **only** when `status == "param_caused_failure"`. Populated by scanning the **full child stderr** for `SENTINEL_PARAM_<name>` substrings (not just the trimmed `failure_excerpt`), so a sentinel buried deep in a long traceback still gets attributed.
- **`missing_module`** — string. Present **only** when `status == "module_not_found"`; names the package the child crashed on (e.g. `"pymisp"`).
- **`scope_1_narrowed`** — `true`. Present **only when Hybrid Scope-1 narrowing actually dropped at least one param** for this command. Omitted entirely when narrowing was applied but the captured set was a superset of the static Scope-1 set (i.e. narrowing fired silently and changed nothing). **An absent field therefore does not mean narrowing was skipped** — it could also mean narrowing trivially kept everything. See §6's narrowing callout.
- **`scope_1_dropped`** — list of param names that narrowing dropped. Present iff `scope_1_narrowed` is present.
- **`limitation`** — optional string flag for known structural reasons the dynamic signal cannot fire for this integration. Currently the only documented value is `"capture_proxy_bypassed"`, attached to **every command** of any integration whose source imports `boto3`, `botocore`, or `AWSApiModule` (matched by prefix on `Import` / `ImportFrom` AST nodes). It means the capture proxy could not observe HTTP traffic, so Hybrid Scope-1 narrowing structurally cannot fire for that integration regardless of `status`. Treat the per-command list as the full static union and verify against source.

### 4. Status enum reference

| status | meaning |
|---|---|
| `ok` | Command completed (rc=0, or rc=7 with captures>0) and at least one HTTP request was captured. The param list in `commands[cmd]` is high-confidence. |
| `ok_no_capture` | Command ran cleanly (rc=0) but made no HTTP calls. Either the command genuinely needs no HTTP (rare) OR our seeded params didn't trigger any HTTP path OR the integration is in the proxy-bypass family (see `limitation: capture_proxy_bypassed`). The param list is the full static union. |
| `param_caused_failure` | Command failed AND we identified the specific params that caused the failure (their sentinels appeared anywhere in the child's stderr). Those params are pre-elevated into `commands[cmd]`. The remaining params for that command come from the static union (the integration may have bailed before reaching them). |
| `no_data` | Command failed but no specific param attribution could be made — typically the integration short-circuited with a hardcoded error (e.g. a `Client.__init__` guard) before any sentinel reached the error text. The param list is the full static union. |
| `timeout` | Command hit the per-command wall-clock timeout. The param list is the full static union. |
| `docker_error` | Docker invocation itself failed (image pull, daemon down, rc 125/126/127). The whole integration's dynamic phase is unreliable; rely on static and consider `--docker never`. |
| `module_not_found` | Child crashed with `ModuleNotFoundError`. Integration needs a third-party package not present in the runtime image. The `missing_module` field names the package. First retry with `--use-integration-docker`; if that still fails, fall back to manual source review (analogous to JS / PowerShell). |

### 5. CRITICAL — Use diagnostics for AI judgment, NEVER write them to pipeline data

> ⚠️ **The `diagnostics` field is stderr-equivalent metadata. It MUST NEVER appear in any persisted pipeline artifact (CSV, manifest, `set-params-to-commands` payload, etc.).**

It exists ONLY for the skill's internal decision-making. The skill MUST:

- Read `diagnostics` to assess confidence in each command's param list.
- Use the `failure_excerpt` and `failing_params` to investigate the integration source code when needed.
- Write **only the polished `commands` data** into the pipeline (CSV / manifest / wherever).
- **Never include `diagnostics`, `failure_excerpt`, `status`, or `captured_requests` in any persisted output.**

The pipeline data is meant to be a clean machine-readable artifact. Diagnostics are debugging context for the AI — they get consumed and discarded. When invoking `set-params-to-commands`, the JSON payload must contain only `integration` and `commands` keys (per [`column-schemas.md`](column-schemas.md)) — strip everything else.

### 6. Decision tree — what the AI does for each diagnostic

The full decision is a function of `(status, limitation)`. Walk this table per command (or per integration when the same outcome dominates):

| Diagnostic | What it means | What the AI should do |
|---|---|---|
| `status: ok` (no `limitation`) | Command ran cleanly and the proxy captured HTTP. Hybrid Scope-1 narrowing may have applied (visible only when it actually dropped something). | Trust the param list as-is. |
| `status: ok` + `limitation: capture_proxy_bypassed` | The integration ran without errors but the proxy saw nothing because the HTTP layer (boto3 / botocore / `AWSApiModule`) bypassed it. The param list is the **full static union**; Hybrid narrowing structurally cannot fire. | Treat as static-only output. Verify against source manually, especially the Scope-1 fan-out (credentials, region, etc.) that narrowing would normally trim. |
| `status: ok_no_capture` (no `limitation`) | Command completed cleanly (rc=0) but the proxy saw zero HTTP requests. Either the command is a pure local helper, or the seeded params didn't reach an HTTP path. | Verify against source: a true local helper needs no HTTP and the static union is correct; otherwise consider it under-tested and treat the list as the full static union (err on inclusion). |
| `status: ok_no_capture` + `limitation: capture_proxy_bypassed` | Integration is in the proxy-bypass family and ran cleanly. Same situation as above for the AWS family — zero captures here is structural, not signal. | Use the static union; **do not infer "no params" from zero captures**. |
| `status: param_caused_failure` | A `SENTINEL_PARAM_<name>` substring was found anywhere in the child's stderr (full-stderr scan, not just the trimmed excerpt). `failing_params` lists the suspects and they are pre-elevated into `commands[cmd]`. | Treat `failing_params` as definitely-relevant. Merge the remaining params with the static union (the integration may have bailed before reaching them). When in doubt, leave the failing params attributed to the command (err on inclusion). |
| `status: no_data` | Command failed but no sentinel could be matched — typically the integration short-circuited (e.g. a `Client.__init__` guard with a hardcoded error message) before the sentinel value reached an error path. | Cannot trust the dynamic signal. Use the full static union. Consider re-running with `--use-integration-docker` if the integration has a non-default runtime that might reach further. |
| `status: timeout` | The child process hit the per-command wall-clock timeout. | Use the full static union. Consider raising `--timeout` or re-running on a smaller `--commands` subset. |
| `status: docker_error` | Docker invocation itself failed (rc 125/126/127). | Re-run on the host (`--docker never`) or fix the docker daemon. The whole integration's dynamic phase is unreliable until then. |
| `status: module_not_found` | Child crashed with `ModuleNotFoundError`; `missing_module` names the package. | First retry with `--use-integration-docker` (uses the integration's own production image, which usually has the missing package). If that still fails, fall back to manual source review — the analyzer literally cannot run. |

#### 6a. Hybrid Scope-1 narrowing — what to read into the diagnostic

The analyzer applies a narrowing pass that fires only when a command's dynamic phase **captured ≥1 HTTP request AND hit ≥1 sentinel**. It intersects the static Scope-1 set (pre-dispatch + module-level fan-out shared across all commands) with the captured params. Scope-2 (per-command handler-traced params, including binding-narrowed dispatch-site reads) is preserved unchanged.

**New semantics for `scope_1_narrowed` / `scope_1_dropped` (keep this in mind):**

- **Present** with a non-empty `scope_1_dropped` → narrowing fired AND removed at least one param. Trust the per-command list more; the dropped names are listed for transparency.
- **Absent** → ambiguous on its own. It can mean either (a) narrowing was never attempted (no captures, sentinel-less, or the integration is in the proxy-bypass family), **or** (b) narrowing fired but the captured set was a superset of Scope-1 so nothing was dropped (narrowing happened trivially). Use `status` and `limitation` together to disambiguate: if `status == "ok"` and there is no `limitation`, an absent narrowing field means "narrowing fired, nothing to drop"; otherwise it means "narrowing was not applied at all and the list is the full static union".

The remaining commands (typically ~80% per integration) receive the **full Scope-1 static union**, which can include false positives from the `Client(api_key=..., max_fetch=..., custom_credentials=...)` fan-out pattern in `main()`. When you see a column where many commands share a suspiciously-identical large param list (the fan-out signature), consult the source code and prune obvious Client-only params for commands that don't actually use them — but **continue to err on inclusion**: a real param missing silently breaks the migrated integration, while an extra param is merely cosmetic noise.

#### 6b. Why Hybrid Scope-1 narrowing is retained

Even after the static analyzer was extended (helper-function recursion, alias-chain matching, nested pre-dispatch flattening, etc.), Hybrid narrowing was **kept on purpose**. It is the only mechanism that trims **module-level globals** of the CrowdStrike `PARAMS = demisto.params()` style — `collect_module_level_params` is explicitly outside the static binding-narrowing pipeline because those reads fan out to every command unconditionally. Static binding-narrowing handles the intra-`main()` `Client(api_key=params.get("apikey"))` pattern but cannot touch module-scope `CLIENT_ID = PARAMS.get("client_id")`.

Concrete justification (from [`connectus/check_command_params_validation_report.md`](check_command_params_validation_report.md:1)): on CrowdStrike Falcon, narrowing dropped 7 of 9 module-level Scope-1 params from 65 of 96 commands — every drop manually verified as a genuine false positive. Without narrowing, those 7 params would appear on every command of every CrowdStrike-style integration.

#### 6c. The `capture_proxy_bypassed` family (boto3 / AWS)

`boto3` / `botocore` (and the shared `AWSApiModule` that wraps them) do not honour `HTTPS_PROXY` / `HTTP_PROXY` the way the capture proxy expects — they manage their own HTTP layer that has to be configured per-client via `Config(proxies=...)`. The analyzer detects this **statically** by walking the integration's `Import` / `ImportFrom` AST nodes for any name matching the prefixes in `_PROXY_BYPASS_MODULE_PREFIXES` (currently `boto3`, `botocore`, `AWSApiModule`). When detected, every per-command diagnostic receives `limitation: "capture_proxy_bypassed"`.

For these integrations:

- Expect `status: ok_no_capture` (or `no_data` if the sentinel trips an early validator) on every command, regardless of whether the integration actually ran successfully.
- Hybrid Scope-1 narrowing will **never** fire — `_merge_command_params()` correctly skips itself when `captured_requests == 0`, so there is no risk of accidentally narrowing with an empty captured set and zeroing out the per-command list.
- The per-command output is the **full static `scope_1 | scope_2` union** as-is. Treat AWS integrations as **static-only effectively** and verify against source.

#### 6d. Patterns the static analyzer now handles correctly

The following patterns previously needed AI workaround. They are now handled inside the static phase, so **the AI should not add defensive logic for them** — trust the analyzer's static set and only intervene if a sanity-check against source disagrees.

- **Helper-function shared-client construction** (`client = build_client(args)` where `build_client` reads `demisto.params()` internally): traced via `_params_consumed_by_function` and helper recursion in `trace_params_in_function`. (AWS-EC2 pattern.)
- **`command == "X" or command == "Y"` alias chains:** matched recursively in `_if_test_matches_command` via a `BoolOp(Or)` walk. (AWS-IAM pattern.)
- **Stub `.py` files in the integration directory:** `find_integration_files` applies a deny-list (`demistomock.py`, `CommonServerUserPython.py`, etc.) and prefers the file whose stem matches the directory name or YML stem.
- **Pre-dispatch bindings nested inside `try:` / `with:` / `if:` blocks:** `_iter_pre_dispatch_stmts` flattens these so binding-narrowing fires regardless of nesting. (MDATP pattern.)
- **Named dict-dispatch tables:** any local dict can be the dispatch table, not just one literally named `commands`. (AzureKeyVault, MongoDB.)

#### 6e. Decision-tree summary (operational order)

Given the analyzer's JSON for an integration, the skill should:

**Step 0** — If MOST commands have `status: "module_not_found"`, the integration depends on a third-party package not in the runtime image. First retry with `--use-integration-docker`. If still failing, **read the integration source and YML directly to write a polished result manually**, exactly as you would for a JavaScript or PowerShell integration. The `missing_module` field tells you which package was needed.

**Step 1.** If the analyzer process exited non-zero (the batch runner wraps this as `{"error": ..., "stderr": ...}` in the cell): treat as a structural failure. Read the integration source, decide manually what each command needs, write a polished result. Do NOT propagate the error into the pipeline.

**Step 2.** If `commands` is non-empty AND most commands have `status: "ok"` (no `limitation`): the analyzer's output is high-confidence. Write `commands` as-is into the pipeline data.

**Step 3.** If the integration has `limitation: "capture_proxy_bypassed"` on every command: treat the analyzer output as **static-only**. Hybrid narrowing structurally cannot fire here. Cross-check the per-command lists against source, especially for the Client fan-out pattern.

**Step 4.** If many commands have `status: "param_caused_failure"`: the failing params are already pre-elevated into `commands[cmd]`. Read the `failure_excerpt` and the integration source to confirm whether the param really applies to all commands or just to startup logic. **When in doubt, leave the param attributed to that command (err on inclusion).**

**Step 5.** If many commands have `status: "no_data"` or `status: "ok_no_capture"` (without the proxy-bypass limitation): the analyzer couldn't get a strong signal. Read the integration source and trace which params each command's handler uses. Write the resulting per-command list into the pipeline. **When in doubt, include rather than exclude.**

**Step 6.** Always sanity-check: are there commands in the YML that the analyzer missed? Are there params clearly used in a command's source code that don't appear in the analyzer's list? If yes, add them.

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
python3 connectus/workflow_state.py set-params-to-commands "QRadar v3" '{"integration":"IBM QRadar v3","commands":{"test-module":["adv_params","fetch_interval"],"qradar-offenses-list":["adv_params","fetch_interval"]}}'
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
| `Other` | Catch-all (DeviceCode, ROPC, ManagedIdentity, custom signing) |
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
