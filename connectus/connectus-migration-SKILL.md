---
name: connectus-migration
description: This skill should be used when migrating integrations to connectus
---

# ConnectUs Migration Skill

## Overview

> _The workflow now has 12 steps (2026-05-31, schema_version=2 with FIXES-TODO combined #4+#6+New_RN re-sequencing): the historical `wrote/checked code` and `auth parity test passes` checkpoints were removed earlier (2026-05). The 2026-05-31 changes dropped two more steps — `Shadowed Integration Commands` (the shadow-rename design was unsustainable; see FIXES-TODO #4/#5) and `write tests` (the no-edit-case was the common one and added no value over `precommit/validate/unit tests passed`; see FIXES-TODO #6) — and inserted a new `Release Notes` data step. The per-profile `verify_connection_skip` boolean inside each `auth_types[]` entry of `Auth Details` remains the replacement signal (see §A.5 below) for the historical `verify button placement` step removed in 2026-05Q3._

This skill guides the migration of XSOAR/XSIAM integrations to the ConnectUs platform. Each integration follows a workflow tracked in [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv) via the [`connectus/workflow_state.py`](workflow_state.py) CLI tool.

The CSV has two kinds of columns:

- **Identity / metadata** (3): `Integration ID`, `Integration File Path`, `Connector ID`.
- **Workflow columns** (12, managed by the state machine — CSV total is 15):
  - **Workflow data columns** (free-text / JSON; set with dedicated commands): `assignee`, `Auth Details`, `Params to Commands`, `Params for test with default in code`, `Params to Capabilities`, `Release Notes` (6).
  - **Workflow flag**: _(none)_
  - **Workflow checkpoints** (6, sequential ✅): `generated manifest`, `run manifest make validate`, `precommit/validate/unit tests passed`, `param parity test passes`, `code reviewed`, `code merged`.

> _Schema_version=2 (2026-05) breaking change: the standalone `wrote/checked code` and `auth parity test passes` checkpoints were removed. Code authorship/review was redundant with the downstream `precommit/validate/unit tests passed` gate; auth parity is now enforced **inside `set-auth`** itself — the candidate `Auth Details` JSON is run through [`check_auth_parity.py`](check_auth_parity.py) before the cell is committed, and the write is rejected unless parity passes or short-circuits structurally (`NO_BASECLIENT` / `NON_PYTHON` / `ALL_INTERPOLATED` / `CONNECTION_INTERPOLATED` / `INTEGRATION_REJECTS_HTTP`). A successful `set-auth` therefore *means* "parity has been verified"; see [§1.12 Auth-parity gate inside `set-auth`](#112-auth-parity-gate-inside-set-auth)._

Authentication classification is the **prerequisite for everything**: you must set `Auth Details` with `set-auth` before the workflow can meaningfully begin (setting it also resets the workflow). The Validate Auth Classification procedure below is run before invoking `set-auth`.

## Entry Points / Trigger Phrases

The skill supports three top-level invocation styles. Pick the matching flow based on what the user said.

| User phrase (examples) | Action |
|---|---|
| "migrate `<integration id>`" / "work on `<integration id>`" / "status of `<integration id>`" | Single-integration flow — jump straight to [Step 0: Identify the Integration](#step-0-identify-the-integration) and walk the existing 12-step procedure for that one integration. |
| "migrate everything assigned to me" / "what's next for me" / "continue my work" / "keep going" | [Assignee batch flow](#assignee-batch-flow) — enumerate the user's in-progress + assigned integrations and walk them one by one. |
| "migrate connector `<connector_id>`" / "work on connector `<connector_id>`" / "do the whole `<connector>` connector" | [Connector batch flow](#connector-batch-flow) — enumerate that connector's integrations and walk them one by one (with ownership disambiguation up front). |

Both batch flows are an **outer loop** wrapped around the existing per-integration procedure. They never replace or re-implement the 12-step workflow — they pick *which* integration to run that workflow on next.

> **CLI column references accept numbers too.** Every CLI verb in this
> skill that takes a column name (`show-step`, `markpass`, `skip`, `fail`,
> `reset-to`) also accepts a **1-based CSV column number** (1..18).
> Identity columns (#1-#3) are addressable only by read-only `show-step`;
> write verbs reject them. Example:
> `python3 connectus/workflow_state.py show-step CrowdstrikeFalcon 5`
> resolves to `Auth Details`.

## Assignee batch flow

Use when the user says something like "migrate everything assigned to me" / "continue my work" / "what's next for me".

1. **Resolve the current user.** Read `git config user.name` (the script uses the same source). If empty, ask the user for their name and stop.
2. **Enumerate candidates.** Run:

   ```bash
   python3 connectus/workflow_state.py next --mine
   ```

   Or from Python: `from workflow_state import integrations_for_assignee` and call `integrations_for_assignee("<name>")`. Each result dict carries `integration_id`, `connector_id`, `assignee`, `current_step`, `current_step_index`, `completed_steps`, `all_complete`, `has_progress`.
3. **Empty result?** Tell the user there is nothing assigned + in-progress for them, and offer two follow-ups:
   - bulk-assign a connector via `set-assignee-by-connector <connector_id> "<name>"` (suggest running `list-connectors` first to pick one), or
   - browse via `python3 connectus/workflow_state.py dashboard`.
   Then stop.
4. **Multiple results?** Before starting, present them as a numbered list with `Integration ID`, `Connector ID`, current step, and `completed_steps / 14`. Apply the [Order-of-work disambiguation](#order-of-work-disambiguation) heuristic. The order is "obvious" only when:
   - There is exactly one integration, OR
   - All integrations belong to the same connector AND exactly one is clearly furthest along (highest `current_step_index` with `has_progress: true`) — proceed with that one first and confirm.

   Otherwise, **ask the user** for the work order. Suggest a sensible default ("furthest-along first" or "by connector then alphabetical") but let them override.
5. **Walk one integration at a time.** For each integration in the chosen order:
   - Follow the existing per-integration migration procedure starting at [Step 0: Identify the Integration](#step-0-identify-the-integration). Do **not** duplicate the 12 steps here — the rest of this skill already documents them.
   - Between integrations, print a short progress recap (`X/N done in this batch — next: <integration id>`) and confirm before moving on, **unless** the user has explicitly said "do them all without asking" / "no confirmations" / equivalent.
6. **Mid-loop "what's next" check.** Re-run `python3 connectus/workflow_state.py next --mine` after finishing each integration so the queue reflects any newly-assigned or just-completed work.
7. **Finish.** When the queue is empty, summarize what was done and ask whether to start a new batch (e.g., a connector batch, or assigning more work).

## Connector batch flow

Use when the user says something like "migrate connector `<connector_id>`" / "do the whole `<connector>` connector".

1. **Validate the connector id.** Run:

   ```bash
   python3 connectus/workflow_state.py list-by-connector "<connector_id>"
   ```

   Or programmatically: `from workflow_state import list_integrations_by_connector` → `list_integrations_by_connector("<connector_id>")`. If the result is empty, suggest `python3 connectus/workflow_state.py list-connectors` to discover valid ids and stop.
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

> **Architecture.** The source of truth for the workflow's shape (steps, columns, markers, interactions) is [`connectus/workflow_state_config.yml`](workflow_state_config.yml). The CLI dispatch, validators, state machine, CSV I/O, and display helpers live in the [`connectus/workflow_state/`](workflow_state/__init__.py) package. The CLI entry script [`connectus/workflow_state.py`](workflow_state.py) delegates to [`workflow_state.cli.main()`](workflow_state/cli.py:1). Canonical Python import is `from workflow_state import …`.
>
> **Q2 2026-05 BREAKING CHANGE — strict checkpoint values.** [`is_checked()`](workflow_state/state_machine.py:24) now accepts ONLY `"✅"` and `"N/A"` as "done". Historical aliases (`"YES"`, `"true"`, `"True"`, `"done"`, `"Done"`, `"DONE"`) are no longer recognized. The canonical list lives in `markers.checkpoint_done_values` in [`workflow_state_config.yml:22-24`](workflow_state_config.yml:22).

1. **NEVER edit [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv) directly.** All CSV modifications MUST go through [`connectus/workflow_state.py`](workflow_state.py) CLI commands.
2. **Follow the workflow checkpoints sequentially.** You cannot skip ahead — the state machine enforces ordering.
3. **Always check status first** before doing any work on an integration.
4. **Use `execute_command`** to run all `workflow_state.py` commands from the workspace root.
5. **Use `set-auth` to update Auth Details.** When correcting auth classifications, use `python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>'`. This validates the JSON schema and automatically resets the workflow back to the first checkpoint (`generated manifest`).
6. If a checkpoint does not pass, it might be because a previous step was not done well — go back to it via `fail` or `reset-to`. Both verbs **preserve** `Params to Commands` only (the historical `Params for test with default in code` and `Params same in other handlers` columns were removed in 2026-05; today only `Params to Commands` carries `preserve_on_reset: true` in [`connectus/workflow_state_config.yml`](workflow_state_config.yml)) so per-command param research survives a failed checkpoint. The CLI prints `Preserved (preserve_on_reset=true): [...]` listing what was kept; the api response includes the same names in `result["preserved"]`. **`set-auth` is NOT covered by this carve-out** — auth changes invalidate downstream artifacts, so `set-auth` continues to wipe `Params to Commands` by design (see Step 1 below). Plain `reset` (the "wipe the whole row" verb) also wipes it; preservation is for `reset-to`/`fail` only.
7. Try to be efficient in what needs input from the user. If you have an option to read files instead of grep, or batch commands to the cli, it is better.

## Cross-cutting Decisions (2026-05-31)

The following four decisions were locked during the 2026-05-31 FIXES-TODO
walkthrough. They are referenced throughout this document by name (e.g.
"per the **Hints policy**", "per **cross-cutting #3**"). Tracking them in
one place avoids re-litigating the same questions in every section.

1. **Hints policy.** Scripts emit accurate, factual descriptions of what
   went wrong. Hints (telling the operator what to *do*) are only
   included when the prescription is **unambiguous** (one obvious right
   answer, no judgment call). When multiple valid paths exist, the
   diagnostic describes accurately and points to the relevant skill
   section; prescription lives in the skill, not in the tool. Examples:
   - **Unambiguous → hint OK.** "use `--static-only` for non-Python
     integrations" (FIXES-TODO #11), "mark `interpolated: true`"
     (FIXES-TODO #12 ApiModule case).
   - **Multiple valid paths → describe + point to skill.** "UCP-strip
     crash; see skill §1.12 for the two fix paths" (FIXES-TODO #13 —
     `_apply_ucp_plain` override vs. `is_ucp_enabled()` gating).

2. **XOR-only auth relations.** The auth-profile relation model is
   exclusive-OR only. There is no `and` relation, no `any` / concurrent
   relation. Integrations with multiple distinct credentials (e.g.
   AbuseIPDB's primary + Hunting key) are classified as `Passthrough`
   — the secrets-bag bucket. The parity gate's coverage of
   `Passthrough` is intentionally reduced; this is documented as
   expected, not a gap. Detection of the multi-secret pattern emits the
   structural-skip code `MULTI_SECRET_PASSTHROUGH` (FIXES-TODO #9). See
   §1.2.2 for the worked example.

3. **`interpolated: true` is the documented fallback.** Operators may
   set `interpolated: true` on **any** auth profile type, including
   `Plain` and `APIKey`, as the documented escape valve when parity
   verification fails or can't be performed (e.g. ApiModule-using
   integrations, integrations whose `Client` doesn't UCP-cleanly).
   There is no validator hard-reject. The skill text frames this
   positively as a fallback, not as a bypass. See §1.2.2 (positive
   framing paragraph) for guidance on when to reach for it.

4. **Project scope is one-shot, no future.** There will be no "next
   migrator" continuing this work past the current user. Resolutions
   are scoped to "what does the current user need to execute," not
   "what should we build for long-term maintainability." Treat this as
   a finite project; do not invest in tooling whose payoff window
   exceeds the current pipeline.

## Interaction Policy

This section defines the **only** points at which the skill must pause for
user input. Everything not listed here runs straight through without
asking — including file reads (`files`, `status`, `show-step`,
`auth-params`, reading YML / Python / README / description),
[`check_command_params.py`](check_command_params.py) analyzer runs,
`markpass`, `skip`, `pre-commit`, `format`, `validate`, test execution,
shadowed-command tests, parity tests, and any other read-only or
derivable operation.

### Pause-and-confirm checkpoints (the only ones)

Pause before executing any of the **4 JSON-write CLI calls** that persist
workflow-data columns to the CSV. For each, present the payload and the
evidence behind it, then wait for the user to reply **yes** (apply),
**no** (revise / abort), or **edit** (user supplies a modified JSON
which is then applied verbatim).

| # | CLI verb | Column written | What to show before asking |
|---|---|---|---|
| 1 | `set-auth` | `Auth Details` | The full JSON payload; a concise bullet list of source-code evidence per `auth_types[]` entry (which YML param + which code site justifies the type); the `other_connection` list. Note that this call resets the workflow + wipes the downstream Params\* columns AND runs the auth-parity test on the candidate payload — the cell is **rejected** unless parity passes or short-circuits structurally (see [§1.12 Auth-parity gate inside `set-auth`](#112-auth-parity-gate-inside-set-auth)). If the gate fails, treat the printed diff as the next problem to solve (most often: a non-standard auth header that needs a `_apply_ucp_<type>` override on the integration's `Client`, or a multi-auth integration with a startup validator that needs `is_ucp_enabled()` gating) — see the same §1.12 for the troubleshooting playbook. |
| 2 | `set-params-to-commands` | `Params to Commands` | The full JSON payload; the analyzer's per-command findings vs. the final list (call out any commands where you overrode the analyzer); the auth-ignore set pulled from `auth-params`. |
| 3 | `set-param-defaults` | `Params for test with default in code` | The full JSON payload AND, for each entry, a one-line attribution: **(a)** *param `foo`: code fallback added — was `params.get("foo")`, now `params.get("foo") or "<yml default>"`, default sourced from YML `defaultvalue`.* **(b)** *param `foo`: NO YML default; proposed default `<value>` — please confirm/edit/skip before the code edit is applied.* **(c)** *param `foo`: code already supplies fallback `<existing default>`; recorded for the cell, no code edit.* Branch (b) is the only sub-confirmation that pauses the workflow per-param (within the same outer pause-before-`set-param-defaults` step). The skill MUST collect all branch-(b) confirmations before applying any `.py` edits, AND before calling `set-param-defaults`. If any branch-(b) param is rejected, drop it from the JSON and skip its code edit. |
| 4 | `set-params-to-capabilities` | `Params to Capabilities` | The full JSON payload from the mapping helper; any `MANUAL_COMMAND_TO_CAPABILITY_JSON` overrides applied and why. |

### Run-through (do NOT ask) operations

For clarity, these run without prompting even though they mutate state:

- `markpass`, `skip`, `fail`, `reset-to`, `reset` — workflow-checkpoint
  bookkeeping. (Rationale: these reflect verification work the skill has
  already done; the JSON writes above are the substantive decisions.)
- `set-assignee`, `set-assignee-by-connector` — ownership writes.
  (Rationale: these are negotiated up front in the batch-flow ownership
  step, which has its own explicit prompts already.)
- All read-only CLI verbs (`status`, `show-step`, `list`, `list-by-connector`,
  `list-connectors`, `next`, `dashboard`, `files`, `auth-params`).
- All analyzer runs, formatter runs, test runs, pre-commit / validate.
- All file reads, greps, code edits, and test-file authorship.

### Order-of-work prompts (batch flows only)

In addition to the 4 JSON writes above, the [Assignee batch flow](#assignee-batch-flow)
and [Connector batch flow](#connector-batch-flow) explicitly require a
user prompt in the specific ambiguous-ordering cases enumerated in
[Order-of-work disambiguation](#order-of-work-disambiguation). Those
prompts stand — this section does NOT override them. When the order is
"obvious" by the rules in that section, proceed silently.

### User-overrides to this policy

Users can widen or narrow the pause list per-session by saying so
explicitly. Common overrides:

- *"don't ask, just do it"* / *"no confirmations"* / *"run the whole thing"* →
  skip the 4 JSON-write prompts for the remainder of the session; still
  honor the order-of-work prompts.
- *"ask before every CLI call"* → pause on every state-mutating verb
  (including `markpass`, `set-assignee`, `fail`, `reset-to`, `reset`),
  not just the 4 JSON writes.
- *"also confirm before rewinds"* → add `fail`, `reset-to`, `reset` to
  the pause list.
- *"also confirm before commits / PRs"* → if/when the workflow reaches
  git-commit or PR-creation steps, pause first.

If the user gives a session-level override, honor it for the rest of
that session and do not re-prompt about it.

## Linked Files

- [`connectus/Readme.md`](Readme.md) — Full reference for auth types, CSV columns, walkthrough.
- [`connectus/column-schemas.md`](column-schemas.md) — JSON shapes for `Auth Details`, `Params to Commands`, `Params for test with default in code`, and `Params to Capabilities`.
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
- **Auth Details** — authentication detail JSON (`auth_types[]` + required `other_connection` — may be an empty list `[]`, but the key MUST be present or the parser raises; profile relations are implicit — see [§1.2.3](#123-profile-relations-are-implicit-no-config-expression))
- **Params to Commands** — JSON mapping of commands → param ids
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
6. ☐ Classify each connection via the [decision table](#121-classification-decision-table); build each entry per [1.2.2](#122-building-each-auth_types-entry); note that profile relations are implicit per [1.2.3](#123-profile-relations-are-implicit-no-config-expression) (no `config` expression to compose)
7. ☐ Extract the **connection-adjacent** YML params (URL, proxy, insecure, port, host, region, …) into the sorted `other_connection` list — see [1.2.5](#125-building-the-other_connection-list)
8. ☐ Sanity-check against [Known Misclassification Patterns](#16-known-misclassification-patterns) and the [Decision Tree](#19-decision-tree-for-auth-type)
9. ☐ Run the [Pre-flight self-check](#111-pre-flight-self-check)
10. ☐ Apply via `set-auth` (this validates the JSON schema, **runs the auth-parity test on the candidate payload**, and on success resets the workflow) — see [1.10](#110-applying-corrections)
11. ☐ If `set-auth` rejects the cell with a parity-gate failure, apply the troubleshooting playbook in [§1.12](#112-auth-parity-gate-inside-set-auth) (UCP header override, startup-validator gating, `interpolated: true` fallback, etc.) and re-run
12. ☐ Re-run `status` to confirm the value was stored as intended

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
from workflow_state import get_integration_files

files = get_integration_files("<Integration ID>")
# files["yml"], files["code"], files["description"], files["readme"], files["test"], plus any extras
```

The same `Integration File Path` value is also surfaced in `status` output as `File Path:`.

**If `files` returns an error** (e.g. the row's `Integration File Path` is missing or the recorded path no longer exists on disk), the column is missing or stale. **Surface this to the user and ask** — there is currently no `set-file-path` CLI setter; the column is data-imported. Do **NOT** fall back to manually searching the repo with `find` / `ls` / `grep`.

For background only: integration files conventionally live at `Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>.{yml,py,js,ps1}` with sibling `<IntegrationName>_description.md`, `README.md`, and `<IntegrationName>_test.py`. The `files` command is the source of truth — this layout is just background context.

---

#### 1.2 Researching `Auth Details` — the four sources of truth

Before you can write the JSON for `set-auth`, you must derive it from the integration pack itself — never guess from the param list alone. The shape you are building is documented in [`connectus/column-schemas.md`](column-schemas.md:16) and is enforced by [`validate_auth_details()`](auth_config_parser/validator.py:24) (called via the [`workflow_state.validators.validate_auth_detail()`](workflow_state/validators.py:25) wrapper). The validator enforces the post-cleanup schema: top-level keys `auth_types` (list) and `other_connection` (list — required; the legacy migration-help error for pre-2026-05 `config` / `xsoar_params` keys was removed in commit `cd09e3ff`, so any unknown top-level keys are now silently ignored). Profile relations are implicit from `len(auth_types)` (see [§1.2.3](#123-profile-relations-are-implicit-no-config-expression)). Wrong input is rejected at the CLI — better to catch it at research time.

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
   - Becomes an `Authorization` header / API request signature → **auth secret** → add as a key in the matching entry's `xsoar_param_map`, with the **role** that secret plays as the value (see §1.2.2 for the role enum per `type`).
   - Becomes the URL / host / region → **connection metadata, NOT auth** → goes in `other_connection`.
   - Becomes a feature flag / fetch cadence / proxy toggle / verify-SSL boolean → **NOT auth**.
   - Sent to a token endpoint as `client_id` / `client_secret` / `assertion` / `refresh_token` → **part of an OAuth connection** → add as a key in the OAuth entry's `xsoar_param_map`, with an OAuth-flavored role string as the value (e.g. `"client_id"`, `"client_secret"`, `"access_token"`).

3. **`<IntegrationName>_description.md`.** The short blurb shown in the XSOAR UI under the integration. Often spells out the auth method in one sentence — e.g. *"Generate an API key from the Settings page"*, *"Use OAuth 2.0 client credentials"*, *"Service account JSON key file required"*. Use it to confirm what the code is doing.

4. **`README.md`** (the per-integration one, in the same directory). Long-form docs. The setup / configuration section frequently spells out exactly which credentials each field requires and how to obtain them — invaluable when the source code is large or obfuscated.

If steps 1 and 2 disagree (e.g. the YML defines a `credentials` param but the code only ever reads `params.get('api_key')`), step 2 wins. Steps 3 and 4 are tiebreakers when the code is ambiguous.

Before you actually use the `set_auth` command, present the evidence to the user for why you decided on the auth types and config structure in a concise and clear way.
---

#### 1.2.1 Classification decision table

Map "what you saw in the source" → "auth-type enum value" (the values are the members of the [`AuthType`](auth_config_parser/types.py:11) enum — import it directly with `from auth_config_parser.types import AuthType` and use `[e.value for e in AuthType]` when you need the string list):

| You see... | Use type |
|---|---|
| `Authorization: Bearer <key>` from a single param, no token exchange | `APIKey` |
| `X-API-Key: <key>` / `apikey=<key>` query param / similar static header | `APIKey` |
| `Authorization: Basic <user>:<pass>` from a credentials (type `9`) or two flat params | `Plain` |
| Username + password posted to a login endpoint that returns a session cookie | `Plain` |
| OAuth2 with user-driven `code` + `redirect_uri` flow | `Passthrough` |
| OAuth2 with `client_id` + `client_secret` (no user code, `grant_type=client_credentials`) | `OAuth2ClientCreds` |
| OAuth2 with a signed JWT assertion (private key + claims, `grant_type=jwt-bearer`) | `OAuth2JWT` |
| OAuth2 ROPC (`grant_type=password`), Device Code, Managed Identity, mTLS-only, HMAC signing, custom challenge/response | `Passthrough` |
| Two or more API keys / secrets used together (regardless of how they're issued — Datadog `api_key`+`application_key`, AWS access_key+secret_key, Akamai EdgeGrid's three tokens, etc.) | `Passthrough` |
| Any auth flow that doesn't cleanly fit one of the five canonical profile types in §1.2.6 | `Passthrough` |
| No credentials at all (public API, or a feed that just hits a URL) | `NoneRequired` |

> **`Passthrough` is the "doesn't fit a profile" catch-all.** The five canonical UCP profile types — `oauth2_client_credentials`, `oauth2_jwt_bearer`, `plain`, `api_key`, and `NoneRequired` — each have a fixed field shape (see §1.2.6 "Authentication Profile Types — Fields Reference"). Anything that doesn't fit one of those shapes (multi-key packages, OAuth2 Authorization Code's browser flow, ROPC, Device Code, Managed Identity, custom HMAC schemes, mTLS, certificate-based flows, etc.) becomes `Passthrough`. When in doubt, prefer `Passthrough` — it is the safe, explicit "we couldn't classify this into a known profile" signal.

---

#### 1.2.2 Building each `auth_types[]` entry

Each `auth_types[]` entry describes **one complete UCP connection type** — one full auth flow, not one XSOAR param. See [`column-schemas.md`](column-schemas.md:34) for the authoritative shape. The rules you'll be applying as you build entries:

- **`type`** — the enum value chosen via the table above.
- **`name`** — a free-form logical id you choose (e.g. `"api_key"`, `"credentials"`, `"oauth_client"`, `"hunting_credentials"`). Must be unique within the row. The name is a free-form identifier you choose to refer to the profile in human-facing diagnostics; it does NOT need to match any YML param id or auth-type enum value.
- **`xsoar_param_map`** — a **JSON object** mapping each XSOAR field path that supplies a secret for **this one** connection type (the key) to the **role** that secret plays inside the ConnectUs envelope (the value). The map is **required and non-empty** for every entry — including entries with `"interpolated": true` (the role still has to be declared even if the value is templated at runtime). Key conventions:
  - For a flat param (YML type `0`/`4`/`14`/`17` etc.): use the bare param id as the key, e.g. `"api_key"`, `"server_token"`.
  - For a credentials param (YML type `9`): use dotted-leaf notation — `"<paramid>.identifier"` for the username slot and `"<paramid>.password"` for the password slot. Both leaves get their own keys IF both are used; suppress `<paramid>.identifier` or `<paramid>.password` according to `hiddenusername:true` / `hiddenpassword:true` flags (see §1.3 for the leaf-suppression rules).
  - For a `Plain` auth built from two **separate** flat params: key each id directly, e.g. `{"server_user": "username", "server_password": "password"}`.
  - The same field path MAY appear as a key in the maps of multiple entries (e.g. one `credentials.password` backing both a Plain profile and an OAuth profile) — that's correct; map it in each entry independently with whatever role applies to that connection.
- **Role enum is constrained per `type`.** The allowed values on the right-hand side of each map entry depend on the entry's `type`:

  | `auth_types[].type` | Allowed `xsoar_param_map` values |
  |---|---|
  | `APIKey` | `"key"` |
  | `Plain` | `"username"`, `"password"` |
  | `OAuth2ClientCreds`, `OAuth2JWT`, `Passthrough` | any non-empty string (enum **deliberately undefined for now** — typical illustrative values: `"client_id"`, `"client_secret"`, `"access_token"`, `"credentials_file"`, `"subject_email"`) |
  | `NoneRequired` | n/a — no entry in `auth_types[]` at all |

  The validator enforces the APIKey and Plain constraints strictly; OAuth/Passthrough values are only checked for "non-empty string".

  > **Enum.** The validator/enum in [`auth_config_parser/types.py`](auth_config_parser/types.py:1) accepts exactly the six values `OAuth2ClientCreds`, `OAuth2JWT`, `APIKey`, `Plain`, `Passthrough`, `NoneRequired`.
- **Multi-secret auth flows: extras go in the SAME profile (see §1.2.2a).** Every entry is one self-contained, mutually-exclusive profile. If an auth flow consumes more than one XSOAR field-path, they all go in the **same** entry's `xsoar_param_map` — never split across multiple entries (because the only inter-profile relation is exclusive-OR, not AND). When the combined shape doesn't fit a canonical profile (no dominant canonical role; co-equal multi-secret packages like Datadog/AWS/Akamai/GitHub App), use `Passthrough`. When one canonical role dominates and the rest are "extras" (e.g. APIKey + a vendor cert), keep the canonical type and add the extras to the same map.
- **`interpolated`** (optional, defaults to `false`) — set to `true` when the value is templated in at runtime by the manifest generator rather than supplied directly by the user. **Only `Plain` and `APIKey` entries may be non-interpolated (i.e., `interpolated: false` or omitted).** All other auth types (`OAuth2ClientCreds`, `OAuth2JWT`, `Passthrough`) MUST set `interpolated: true` — these flows cannot accept raw user input verbatim; their values are always derived/templated at runtime. `xsoar_param_map` is still required and non-empty even when `interpolated: true`.

  > **`interpolated: true` is a documented fallback on ANY profile type** (cross-cutting decision #3). Operators may set it on `Plain` and `APIKey` profiles too, as the escape valve when the parity gate cannot verify the integration cleanly. This is **not** a bypass — it's the documented escape path for these classes of failures:
  >
  > - **ApiModule-using integrations** (FIXES-TODO #12). When the parity gate emits `APIMODULE_INTEGRATION_CANNOT_VERIFY`, the gate cannot inspect transitive `BaseClient` use through e.g. `MicrosoftApiModule` / `OktaApiModule`. Mark the profile `interpolated: true` and move on.
  > - **Custom-header `APIKey` integrations without an override** (FIXES-TODO #10 — tabled). When the gate emits `WRONG_LOCATION` because the integration uses `X-API-Key` instead of `Authorization: Bearer`, the canonical fix is a `_apply_ucp_api_key()` override on the `Client` (see §1.12). When you don't want to write the override now, mark the profile `interpolated: true`.
  > - **Plain auth with unconditional `params["credentials"]["identifier"]` reads** (FIXES-TODO #13). When the gate emits `UCP_STRIP_CRASHED_UNCONDITIONAL_READ`, the canonical fixes are a `_apply_ucp_plain` override or `is_ucp_enabled()` gating (see §1.12). Marking the profile `interpolated: true` is the documented alternative when the integration's runtime cannot be touched.
  >
  > Document the reason in the commit notes ("marked interpolated: true because <reason>") so reviewers can verify the fallback was justified.
- **`verify_connection_skip`** (optional, defaults to `false`) — set to `true` when this profile's `test-module` code path manually raises an exception (`raise DemistoException(...)` / `return_error(...)`) instead of reaching an actual HTTP call. Most commonly OAuth Authorization Code / Device Code / ROPC flows where the user must first run an out-of-band `!auth-start`-style command before the connection-test button can succeed. Per-profile: a multi-profile (exclusive-OR) row may set it `true` on one profile and leave it default on another. Must be a JSON boolean — string `"true"`/`"false"` and int `0`/`1` are rejected.
- **Sort order** — entries are sorted by `(type, name)` ascending. The validator enforces this — `set-auth` will reject unsorted input. Map keys, by contrast, are an unordered dict and have no sort requirement.

---

#### 1.2.2a Multi-secret auth flows — extras go INSIDE the profile

> **Schema change, 2026-05.** Every entry in `auth_types[]` is **one self-contained, mutually-exclusive profile**. The only inter-profile relation is exclusive-OR (implicit when `len(auth_types) >= 2`). AND-ed secrets within a single auth flow live inside **one profile's** `xsoar_param_map` — never as separate profiles.

##### Picking the profile `type` for a multi-field auth flow

For an auth flow that consumes more than one XSOAR field, count the **canonical-role-bearing leaves** (the ones that fit a canonical UCP profile's field list per §1.2.6) and pick the type accordingly:

- **Exactly one canonical-role leaf, plus N "extras"** → keep the canonical type.
  - Examples:
    - **`Plain` + a vendor client certificate** (the cert participates in the TLS handshake alongside username/password): one `Plain` entry whose `xsoar_param_map` holds `<id>.identifier`/`<id>.password` AND the cert leaf.
    - **`APIKey` + a vendor client certificate** (mTLS-protected endpoint that also needs a static API key): one `APIKey` entry whose `xsoar_param_map` holds both the `key` and the cert leaf.
    - **`OAuth2ClientCreds` + an "scopes" or "tenant_id" string that the OAuth flow itself requires**: one `OAuth2ClientCreds` entry whose `xsoar_param_map` holds the OAuth client id + secret AND the extra leaf.
- **Two-or-more co-equal canonical leaves (no obvious "dominant" canonical role)** → `Passthrough`.
  - Examples:
    - **Datadog** (`api_key` + `application_key` — two equal-rank API-key-style values, neither dominates).
    - **AWS SigV4** (`access_key` + `secret_key` — two co-equal HMAC inputs).
    - **Akamai EdgeGrid** (three co-equal tokens).
    - **GitHub App** (`app_id` + `private_key` + `installation_id` — three co-equal inputs).
  - All `Passthrough` entries MUST have `"interpolated": true` (see §1.2.2).

> **Decisive heuristic** — count the **canonical** roles only (`key`, `username`/`password`, `client_id`/`client_secret` for OAuth, `subject_email`/`credentials_file` for JWT). If exactly one canonical pattern is present, the profile keeps that canonical type and the rest are "extras" living inside the same `xsoar_param_map`. If two-or-more independent canonical patterns appear (or none does, e.g. AWS-style two-key HMAC), use `Passthrough`.

> **Where do extras go?** **Inside the profile's `xsoar_param_map`**, NOT in `other_connection`. `other_connection` is reserved for **connection-wide / transport-level metadata that has no bearing on the auth flow** — URL, port, region, insecure, proxy. If a field has any implication on how authentication itself happens (a cert that participates in the handshake; an HMAC salt; a vendor-required header value), it belongs in the profile.
>
> **Caveat (validator role enum).** The validator currently restricts `APIKey` role values to `"key"` and `Plain` to `{"username", "password"}`. Adding an extra leaf with a non-canonical role string (e.g. `{"client_cert": "certificate"}` on an `APIKey` profile) will surface a role-enum violation under the current validator. Until the role enum is relaxed (planned), classifications that need extras on `APIKey`/`Plain` may need to either (a) demote the profile to `Passthrough` so the role enum is free-form, or (b) live with the validator complaint and follow up. The model is correct; the validator just lags behind it.

**Single-secret flows stay on their natural profile type.** If the integration has exactly one API key (one header / one query param / one HMAC secret-of-one) and nothing else auth-relevant, keep it as `APIKey`. If it has exactly one username+password pair (`Plain` profile has two fields by design) and nothing else, keep it as `Plain`. The "extras go in the profile" rule fires only when there ARE extras AND there is still a dominant canonical role; otherwise (no canonical dominance) use `Passthrough`.

**HMAC of one** (single static secret producing per-request signature) stays `APIKey`. **HMAC of two-plus** (e.g. AWS SigV4's pair, Akamai's triple) is multi-secret with no dominant canonical pattern → `Passthrough`. The wire-protocol mechanism (HMAC, Bearer, signed query string, etc.) is irrelevant to the classification — only the **count of co-equal canonical patterns** matters.

---

#### 1.2.2b Multi-secret / multi-flow integrations → one `Passthrough` profile

**Added 2026-05-31** (FIXES-TODO #9 worked example; locked under
cross-cutting decision #2). Some integrations expose **two distinct
optional auth flows** in a single configuration — e.g. AbuseIPDB has the
primary AbuseIPDB API key AND an optional Abuse.ch Hunting API key, each
authenticating against a different service URL. The user can configure
either, both, or just the primary.

Per cross-cutting decision #2 (XOR-only auth), the schema does NOT
support `and` / `any` / concurrent relations. Multi-secret /
multi-flow integrations classify as **one `Passthrough` profile**
carrying all secrets in `xsoar_param_map`:

```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "bag",
      "interpolated": true,
      "xsoar_param_map": {
        "credentials.password":          "primary_api_key",
        "hunting_credentials.password":  "hunting_api_key"
      }
    }
  ],
  "other_connection": ["url", "insecure", "proxy"]
}
```

The parity gate detects this shape and emits the structural-skip code
`MULTI_SECRET_PASSTHROUGH` with a diagnostic that frames the reduced
coverage as "by design, not a failure." Heuristic: 2+ keys in a
`Passthrough` profile's `xsoar_param_map` matching credential-field
name patterns (`password`, `key`, `secret`, `token`, `credential`,
`apikey`, `api_key` — case-insensitive substrings).

**When in doubt** between "one `Passthrough` lumping both" and "two
separate `APIKey` profiles", remember: there is no `any` relation. Two
`APIKey` profiles would (incorrectly) tell the UCP runtime the user must
pick one. `Passthrough` is the honest classification for "user may
configure either, both, or just primary."

---

#### 1.2.3 Profile relations are implicit (no `config` expression)

The pre-2026-05 `config` expression field is **gone**. There is no
`REQUIRED(...)` / `OPTIONAL(...)` / `CHOICE(...)` / `+` grammar to
write. The relationship between profiles is encoded by the **length
and order** of `auth_types[]`:

| `len(auth_types)` | Meaning |
|---|---|
| `0` | The integration requires NO authentication (the historical `NoneRequired`). |
| `1` | A single profile, always used. |
| `>= 2` | **Exclusive-OR.** The user picks exactly one profile at configuration time. There is no AND between profiles, no OPTIONAL, no clause-joining. |

The pre-2026-05 `config` expression key and the per-entry `xsoar_params` key are no longer recognized at all (the migration-help rejection was removed in commit `cd09e3ff`); any such legacy key is silently ignored by the parser, so its presence does NOT cause `set-auth` to fail but it also has no effect. Strip such keys from any pre-2026-05 payload and re-shape `auth_types[]` per [`column-schemas.md`](column-schemas.md:1).

> **Don't strictly stick to whether the corresponding XSOAR parameters are marked `required: true`.** Some integrations leave a legacy hidden alternative in the YML that makes the visible param appear optional even when it is in practice the only configurable path. Treat the visible parameter as required if there is no alternate visible auth path the user could pick.

---

#### 1.2.5 Building the `other_connection` list

`other_connection` is a **flat sorted list of YML param ids** captured
inside the same `Auth Details` JSON. Its purpose is to record every
connection-adjacent YML param that is **not** an auth secret and **not**
a per-command behavioral param — i.e. everything you reasonably need to
define the integration's connection besides the secrets themselves.

The validator (see [`validate_auth_details()`](auth_config_parser/validator.py:47))
requires the key on every `set-auth` write; the field is required even
when empty (use `[]`).

##### What qualifies as connection-adjacent

A YML param qualifies if it is BOTH:

1. **Not an auth secret** (auth secrets are keyed in `auth_types[].xsoar_param_map`), AND
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
  a signed request → it is an auth secret, classify it as a key in
  `auth_types[].xsoar_param_map` instead.)
- `api_version` — when it changes the URL path.

##### Examples to EXCLUDE

- **Auth secrets** — already keyed in `auth_types[].xsoar_param_map`. Do
  not list them again here.
- **Per-command behavioral params** — `fetch_interval`, `first_fetch`,
  `max_fetch`, `incident_type`, `mirror_options`, `mirror_direction`,
  `query`, `enrichment`, etc. These belong in `Params to Commands`.
- **XSOAR framework params** — `longRunning`, `feedReputation`,
  `feedExpirationInterval`, `feedReliability`, `feedTags`. Ignored
  entirely; not in `Auth Details`, not in `Params to Commands`.
- **Hidden / deprecated params** — strictly excluded. A param with `hidden: true` or `hidden: [<list>]` does NOT go in `other_connection`, even if it's a connection-adjacent name like a legacy `host` or `url` alias. Use the visible variant only.

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

#### 1.2.6 Authentication Profile Types — Fields Reference

> **What this section is.** The canonical, copy-paste reference for the five UCP authentication profile types and the user-facing fields each one exposes. Use it to answer "does this integration fit a known profile, or is it `Passthrough`?" while you classify `Auth Details`. The shapes here are the source of truth for the manifest's `metadata.auth.parameter` block; OPA Check 17 rejects duplicate `auth.parameter` values within a profile's effective scope (profile configurations + connection.yaml `general_configurations`).

##### Quick reference — fields by connection type

| Profile Type | Profile-Level Properties | User-Facing `auth.parameter` Fields | Maps from classification |
|---|---|---|---|
| `oauth2_client_credentials` | `discovery_url` **OR** `token_endpoint` | `client_key`, `client_secret` | `OAuth2ClientCreds` |
| `oauth2_jwt_bearer` | `discovery_url` **OR** `token_endpoint` | `subject_email`, `credentials_file` | `OAuth2JWT` |
| `plain` | *(none beyond id/type/title/description)* | `username`, `password` | `Plain` |
| `api_key` | *(none beyond id/type/title/description)* | `api_key` | `APIKey` (single key only) |
| `Passthrough` (no canonical profile) | n/a | n/a — define fields ad-hoc in the manifest | `Passthrough` — includes `oauth2_authorization_code` (browser flow), Device Code, ROPC, Managed Identity, mTLS, dual-key API (e.g. Datadog `api_key`+`application_key`), AWS SigV4, Akamai EdgeGrid, GitHub App, custom signing |

\* For browser-flow OAuth2 Authorization Code, the legacy/sibling profile `oauth2_authorization_code` exists at the profile level (`client_id`, `client_secret`, `discovery_url` **OR** `authorization_endpoint` + `token_endpoint`, `refresh_token_scope`; profile-level `client_id` / `client_secret` MUST use the `{SAAS_REGISTRY.*}` pattern) but it has **no user-facing `auth.parameter` fields** (the entire flow is browser-driven). Per the project-wide rule, **classify it as `Passthrough` regardless** — there is no single profile-type field shape we can pin it to from a classification perspective.

##### Detailed breakdown

###### 1. `oauth2_client_credentials`

- **Profile-level keys:** `id`, `type`, `title`, `description`, (`discovery_url` **OR** `token_endpoint`)
- **`metadata.auth.parameter` fields:**
  - `client_key` — OAuth2 client ID / consumer key (`input`, unmasked)
  - `client_secret` — OAuth2 client secret (`input`, `mask: true`)
- **Classification:** any integration whose code does `grant_type=client_credentials` with exactly two secrets (`client_id` + `client_secret`) fed in directly — no JWT, no browser redirect.

###### 2. `oauth2_jwt_bearer`

- **Profile-level keys:** `id`, `type`, `title`, `description`, (`discovery_url` **OR** `token_endpoint`)
- **`metadata.auth.parameter` fields:**
  - `subject_email` — impersonation subject (`input`, usually in `general_configurations`)
  - `credentials_file` — JSON key file (`file_upload`, `formats: ".json"`, `mask: true`)
- **Classification:** any integration that signs a JWT assertion with a private key (typically a Google service-account JSON file) and posts it to a `grant_type=jwt-bearer` token endpoint.

###### 3. `plain`

- **Profile-level keys:** `id`, `type`, `title`, `description` (nothing more)
- **`metadata.auth.parameter` fields:**
  - `username` — account identifier (`input`, unmasked)
  - `password` — secret (`input`, `mask: true`)
- **Classification:** username + password basic auth, login-form-to-session-cookie flows, any single-pair credential where one half is an identifier and the other half is a secret.

###### 4. `api_key`

- **Profile-level keys:** `id`, `type`, `title`, `description` (nothing more)
- **`metadata.auth.parameter` fields:**
  - `api_key` — token (`input`, `mask: true`)
- **Classification:** **single static secret only.** Bearer tokens, custom headers like `X-API-Key`, query-param API keys, and single-secret HMAC signing all fit here. **Two-or-more-secret packages do NOT fit and become `Passthrough`** (see §1.2.2a) — even when they're conceptually "API keys" (Datadog `api_key`+`application_key`, AWS access_key+secret_key, Akamai EdgeGrid's three tokens, etc.).
- **Legacy note:** older docs mentioned a dual-key `application_key` slot under `api_key`. That slot is **NOT part of the canonical `api_key` profile** in the current schema; dual-key integrations are `Passthrough`.

###### 5. `NoneRequired`

- **Profile-level keys:** none (no profile generated at all)
- **`metadata.auth.parameter` fields:** none
- **Classification:** public APIs, RSS/feed endpoints that need no auth header.

##### All valid `metadata.auth.parameter` values (closed set per profile)

| Parameter | Used By | Notes |
|---|---|---|
| `client_key` | `oauth2_client_credentials` | OAuth client id |
| `client_secret` | `oauth2_client_credentials` | OAuth client secret |
| `username` | `plain` | Basic-auth identifier |
| `password` | `plain` | Basic-auth secret |
| `api_key` | `api_key` | Single static secret |
| `credentials_file` | `oauth2_jwt_bearer` | JSON key file upload |
| `subject_email` | `oauth2_jwt_bearer` | Impersonation subject |

> **Duplicate-value rejection.** OPA Check 17 rejects duplicate `auth.parameter` values within a profile's effective scope (the union of the profile's own `configurations` and the `connection.yaml`'s `general_configurations`). If an integration legitimately needs a second copy of the same role-named field (extremely rare), it cannot fit a canonical profile and must be classified as `Passthrough`.

##### Decision rule (one-line summary)

> **If — and only if — every secret the integration consumes maps cleanly into one of the four canonical profiles' field lists above, use that profile's classification (`OAuth2ClientCreds` / `OAuth2JWT` / `Plain` / `APIKey`). Otherwise, classify as `Passthrough`.** `oauth2_authorization_code` is always `Passthrough` — its user-facing config lives on the profile itself, not in `metadata.auth.parameter`, so it has no canonical field shape to match against from the classification side.

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

Resulting JSON to pass to `set-auth` (no `config` key in the 2026-05 schema; the single profile is implicit):

```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "api_key",
      "xsoar_param_map": {
        "api_key": "key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```


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
      "xsoar_param_map": {
        "api_key": "key"
      }
    }
  ],
  "other_connection": ["insecure", "proxy", "url"]
}
```

**Example A' — APIVoid pattern: APIKey delivered via a credentials widget with `hiddenusername: true`.**

When an integration uses a `type: 9` credentials widget purely to collect an API key (the username slot is hidden via `hiddenusername: true`), the identifier leaf is suppressed and the map keys ONLY the password leaf, with role `"key"`. See §1.3 for the leaf-suppression rules.

YML excerpt:

```yaml
- name: credentials
  display: API Key (Username — hidden)
  type: 9
  hiddenusername: true
  required: true
```

Resulting JSON:

```json
{
  "auth_types": [
    {
      "type": "APIKey",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.password": "key"
      }
    }
  ],
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

Resulting JSON (note entries sorted by `(type, name)` — `OAuth2ClientCreds` < `Plain` alphabetically; `other_connection` sorted ascending; the OAuth entry uses free-form role strings while the Plain entry is constrained to `"username"`/`"password"`):

```json
{
  "auth_types": [
    {
      "type": "OAuth2ClientCreds",
      "name": "credentials_consumer",
      "xsoar_param_map": {
        "credentials_consumer.identifier": "client_id",
        "credentials_consumer.password": "client_secret"
      }
    },
    {
      "type": "Plain",
      "name": "credentials",
      "xsoar_param_map": {
        "credentials.identifier": "username",
        "credentials.password": "password"
      }
    }
  ],
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
| `hiddenusername: true` on type=9 params | Often means the credentials widget is being used as an API key, NOT username/password. The `<id>.identifier` leaf is **suppressed** — do NOT include it as a key in `xsoar_param_map`. The `<id>.password` leaf (if not also hidden) still maps normally. |
| `hiddenpassword: true` on type=9 params | The `<id>.password` leaf is **suppressed** analogously — do NOT include it as a key in `xsoar_param_map`. The `<id>.identifier` leaf (if not also hidden) still maps normally. |
| `display` and `displaypassword` labels | Reveal what the credential actually is (e.g., "Client ID" / "Client Secret" vs "Username" / "Password") |
| `hidden: true` OR `hidden: [<list>]` (any non-empty hidden value) | **Excluded entirely from every CSV column** — does not appear as a key in any `xsoar_param_map`, not in `other_connection`, not in `Params to Commands`. Even if the source code still reads the param as a legacy fallback, the migration treats it as if it does not exist. |
| `deprecated: true` or `_deprecated` in param names | Ignore these entirely — they are no longer functional |
| `additionalinfo` text | Often describes the auth mechanism in plain English |
| Params named `auth_type` with `type: 15` | Indicates multi-auth integrations with user-selectable auth flow |

**Key rule for hidden/deprecated params (strict):**

> Hidden YML params (either `hidden: true` or `hidden: [<list>]`) are **invisible to all migration tooling**. They are excluded from every workflow-data column. The visible siblings define the entire authentication / connection / per-command surface. This rule supersedes the older "check if they represent an old input path" guidance — even if a hidden param backs the same secret as a visible one, you do NOT key the hidden id in any `xsoar_param_map`. Key ONLY the visible id(s).
>
> Rationale: the migration produces a clean, forward-looking ConnectUs manifest. Hidden params are by definition not exposed to the user; carrying them through the migration would re-surface them in places they shouldn't appear and would confuse downstream tooling that has no notion of XSOAR's per-platform `hidden` list.

**Hidden-leaf suppression for `type: 9` credentials (per-leaf, not per-param):**

The `hiddenusername` / `hiddenpassword` flags suppress only the **named leaf** of the credentials widget — they do NOT remove the whole param. The other leaf (if not also hidden) still goes in `xsoar_param_map` as usual.

- `hiddenusername: true` → omit `<id>.identifier` from the map; map `<id>.password` if it carries a secret.
- `hiddenpassword: true` → omit `<id>.password` from the map; map `<id>.identifier` if it carries a secret.
- If both flags are set, the param has no live leaves — treat it as if `hidden: true` applied at the whole-param level and exclude it from `Auth Details` entirely.

**Worked mini-example — APIVoid pattern (`hiddenusername: true` on an APIKey).** The credentials widget collects only the password (used as the API key), so the resulting map has exactly one key:

```yaml
- name: credentials
  display: API Key
  type: 9
  hiddenusername: true
  required: true
```

```json
{
  "type": "APIKey",
  "name": "credentials",
  "xsoar_param_map": {
    "credentials.password": "key"
  }
}
```

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

**OAuth2 ROPC (Resource Owner Password Credentials) — classified as `Passthrough`:**
```bash
grep -n "grant_type.*password\|resource_owner\|ROPC" <file>.py
```

**OAuth2 Device Code — classified as `Passthrough`:**
```bash
grep -n "device_code\|devicecode\|device_authorization" <file>.py
```

**Managed Identity — classified as `Passthrough`:**
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
| 4 | Microsoft/Azure missing ManagedIdentity | 23 | No mention | Add to `auth_types` as `Passthrough` | Code imports `MicrosoftClient` and has `managed_identities_client_id` param |
| 5 | Microsoft/Azure missing DeviceCode | 12 | No mention | Add to `auth_types` as `Passthrough` | Code has `device_code` grant type support |
| 6 | OAuth2 ROPC misclassified | 13 | `OAuth2ClientCreds` or `Plain` | `Passthrough` (ROPC) | Code does `grant_type=password` |
| 7 | Hidden old param creates false CHOICE | ~10 | `CHOICE(APIKey, Plain)` | Single mechanism | Old `type=4` param is `hidden: true`, new `type=9` param is visible — same credential |
| 8 | `type=4` OAuth client secret classified as APIKey | ~5 | `APIKey(client_secret)` | `OAuth2ClientCreds(client_secret)` | Param named `client_secret` or `enc_key` used in OAuth flow |
| 9 | Microsoft cert-thumbprint integrations seed-fail at module load | many | 100% `no_data` across every command | Not a misclassification; analyzer limitation. Use the full static union; do NOT retry with `--use-integration-docker` (failure is in `MicrosoftApiModule.MicrosoftClient.__init__` cert validator, not a missing package). `--ignore-params <name>` does NOT help — the slot is still seeded, it only filters output. | Stderr contains `Error: Odd-length string` or `non-hexadecimal number found in fromhex()`; integration's YML has `certificate_thumbprint` (type=4) or `creds_certificate` (type=9) consumed by `MicrosoftClient`. Until the analyzer ships per-param seed overrides, manual source review is the only path. |

---

#### 1.7 Microsoft/Azure Integration Special Handling

Microsoft/Azure integrations are the most complex (23 corrections in the manual review). Apply this dedicated procedure:

- **If the integration imports `MicrosoftClient` from `MicrosoftApiModule`:**

  > **Important: 4 flows is the upper bound, not the default.** Many Microsoft integrations support only a subset. Common variants observed in the codebase:
  >
  > - **All 4 flows** — `auth_type` selector (type=15) with `Client Credentials` / `Authorization Code` / `Device Code` options + `managed_identities_client_id` param.
  > - **Client-creds-only with cert OR secret + Managed Identity** (Azure Sentinel pattern) — 3 entries: `OAuth2ClientCreds(cert)` + `OAuth2ClientCreds(secret)` + `Passthrough(managed_identity)`. No `auth_type` selector param.
  > - **Pure Client Credentials** (no cert, no MI) — 1 entry.
  >
  > The decisive evidence is **always** the source code, not the import. Read `main()` to determine which auth paths are reachable — never assume "imports `MicrosoftClient` ⇒ all 4 flows".

  - It likely supports **4 auth flows**: `OAuth2ClientCreds`, plus three flavours of `Passthrough` (Authorization Code, Device Code, Managed Identity).
  - Check for `auth_type` selector param (`type: 15`) with options like `Client Credentials`, `Authorization Code`, `Device Code`
  - Check for `managed_identities_client_id` param → indicates Managed Identity support (Passthrough entry)
  - Check for `redirect_uri` and `auth_code` params → indicates Authorization Code support (Passthrough entry)
  - Each supported flow becomes its own entry in `auth_types[]`. The user picks one at configuration time (implicit exclusive-OR; no `config` key needed). Pick distinct `auth_types[].name` values per entry.
  - Authorization Code, Device Code, and Managed Identity are all classified as `Passthrough` (none fits the `oauth2_client_credentials` / `oauth2_jwt_bearer` profile shape).

---

#### 1.8 Auth Details JSON Validation

After determining the correct auth types, validate the Auth Details JSON against the rules in [`connectus/column-schemas.md`](column-schemas.md:16). The same rules are enforced at runtime by [`validate_auth_details()`](auth_config_parser/validator.py:47):

1. Must be valid JSON with top-level keys `auth_types` (array) AND `other_connection` (array of strings — required; may be `[]`). Both keys are required; a missing `other_connection` raises `Missing required key: other_connection`. Any other top-level key is silently ignored (the pre-2026-05 `config` expression key was removed in commit `cd09e3ff`; it no longer triggers a migration-help error).
2. Each `auth_types[]` entry has a `type` (one of the [`AuthType`](auth_config_parser/types.py:11) enum members — import via `from auth_config_parser.types import AuthType`), a unique `name`, and a non-empty `xsoar_param_map` JSON object (the empty object `{}` is rejected; `NoneRequired` integrations have no entries in `auth_types[]` at all so the requirement is moot for them).
3. Every `xsoar_param_map` key is a non-empty string (the XSOAR field path); every value is a non-empty string (the role). The **role enum is constrained per `type`**:
   - `APIKey` → values MUST be `"key"`.
   - `Plain` → values MUST be in `{"username", "password"}`.
   - `OAuth2ClientCreds`, `OAuth2JWT`, `Passthrough` → any non-empty string (enum deliberately undefined for now; typical illustrative values: `"client_id"`, `"client_secret"`, `"access_token"`, `"credentials_file"`, `"subject_email"`).
4. Per-entry keys outside `{type, name, xsoar_param_map, interpolated, verify_connection_skip}` are silently ignored. The pre-2026-05 `xsoar_params: list[str]` field on an entry is no longer recognized at all (the dedicated migration-help error was removed in commit `cd09e3ff`); rewrite any such field as `xsoar_param_map`.
5. `auth_types[]` entries are sorted by `(type, name)` ascending. Map keys, by contrast, are an unordered dict — no sort requirement applies.
6. Profile relations are implicit from `len(auth_types)`: 0 → no auth, 1 → single required, ≥2 → exclusive-OR. The pre-2026-05 top-level `config` expression key is no longer recognized (removed in commit `cd09e3ff`); strip it from any pre-2026-05 payload.
7. `auth_types[].verify_connection_skip` is optional; when present it MUST be a JSON boolean. Defaults to `false` when absent. Set `true` for profiles whose `test-module` code path manually raises (`raise DemistoException(...)` / `return_error(...)`) so the connection-test button cannot exercise the auth. Most common for OAuth Authorization Code and Device Code flows that require an out-of-band `!auth-start`-style command.
9. `other_connection` must be a list of **non-empty unique strings, sorted ascending**. Empty list `[]` is valid (but the key MUST be present). The validator rejects unsorted input with a message that suggests the sorted form. See [1.2.5](#125-building-the-other_connection-list) for what belongs here.

---

#### 1.9 Decision Tree for Auth Type

Use this decision tree to determine the correct auth type:

```
Is there a credentials param (type=9)?
├── YES: What does the code do with it?
│   ├── Sends as Basic Auth (HTTPBasicAuth) → Plain
│   ├── Sends as Bearer token (Authorization: Bearer) → APIKey
│   ├── Uses in OAuth2 client_credentials flow → OAuth2ClientCreds
│   ├── Uses in OAuth2 ROPC flow (grant_type=password) → Passthrough (ROPC)
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

#### 1.9.1 Feed-framework integrations (always `interpolated: true`)

Integrations that import from any `*FeedApiModule` — `JSONFeedApiModule`, `RSSFeedApiModule`, `CSVFeedApiModule`, `FeedApiModule`, etc. — do **NOT** subclass `BaseClient` directly. They use the feed framework's own `Client` class, which is its own auth-injection ecosystem and is incompatible with the parity tool's BaseClient-based UCP injection.

The parity tool short-circuits on these with `ERROR_NO_BASECLIENT` (exit 11). **Required action: classify with `interpolated: true` on every `auth_types[]` entry. There is no code-change alternative** — re-architecting feed integrations on top of `BaseClient` is out of scope for the migration.

**Detection during classification:** grep the integration's `.py` for `from .*FeedApiModule import`. If present, mark `interpolated: true` up front on every entry — do **not** waste time deriving `auth_types[].xsoar_param_map` shapes that the parity tool will never exercise (still populate the map per §1.2.2; the role declarations are required even when `interpolated: true`, but you do not need to second-guess them).

Examples currently in the pipeline: `SpamhausFeed`, `MalwareBazaarFeed`, `AbuseIPDBFeed`, and effectively any pack named `Feed*`.

---

#### 1.10 Applying Corrections

When corrections are needed (or for the initial set), use `set-auth`:

```bash
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<Auth Details JSON>'
```

This command:

- Validates the Auth Details JSON against the schema (`auth_types[]` + required `other_connection`) — see [`validate_auth_details()`](auth_config_parser/validator.py:24).
- Sets the `Auth Details` workflow data column in the CSV.
- Automatically **resets the workflow** to the first checkpoint (`generated manifest`) and clears all checkpoints + the auth-parity flag. **This includes wiping the `Params to Commands` data column**, even though it carries `preserve_on_reset: true` for `reset-to`/`fail` — `set-auth` deliberately ignores that flag because auth-classification changes invalidate every downstream artifact (in particular, the per-command param contract validated by `params_to_commands_no_auth_overlap`).
- Rejects invalid JSON with specific error messages — including unsorted `auth_types[]`, role-enum violations (e.g. `APIKey` entries whose role isn't `"key"`), missing `other_connection`, and unknown enum values. Unknown top-level keys (including the legacy pre-2026-05 `config` / `xsoar_params` keys) are silently ignored — they no longer short-circuit with a dedicated migration-help message (that behaviour was removed in commit `cd09e3ff`).

Example:

```bash
python3 connectus/workflow_state.py set-auth "Abnormal Security" '{"auth_types":[{"type":"APIKey","name":"api_key","xsoar_param_map":{"api_key":"key"}}],"other_connection":["insecure","proxy","url"]}'
```

After setting, verify it looks correct:

```bash
python3 connectus/workflow_state.py status "<Integration ID>"
```

Note: there is **no `markpass "auth params set"`** anymore — the verification IS the `set-auth` call. The first markpass-able checkpoint is `generated manifest`.

---

#### 1.11 Pre-flight self-check

Before invoking `set-auth`, walk this checklist mentally. The validator will catch most of these but it's faster (and clearer) to catch them locally.

- [ ] No `hidden: true` or `hidden: [<list>]` YML param appears as a key in any `auth_types[].xsoar_param_map`, in `other_connection`, or in `Params to Commands`. Hidden params are excluded entirely. (See §1.3.)
- [ ] Every YML param the source code reads as an auth secret is keyed in some `auth_types[].xsoar_param_map`.
- [ ] No NON-auth param (URL, proxy, fetch interval, feature toggle, verify-SSL boolean) is keyed in any `xsoar_param_map`.
- [ ] Every credentials-typed (YML type `9`) auth param appears in `xsoar_param_map` as the appropriate leaves, with `<id>.identifier` suppressed if YML `hiddenusername: true` and `<id>.password` suppressed if YML `hiddenpassword: true`. (See §1.3.)
- [ ] Every map value matches the role-enum for its entry's `type` (APIKey: `"key"`; Plain: `"username"`/`"password"`; OAuth/Passthrough: any non-empty string).
- [ ] Any entry with 2+ map keys whose roles DON'T fit the canonical `plain` profile's `username`+`password` shape is classified as `Passthrough`, not as `APIKey` or `OAuth2*`. See §1.2.2a (multi-secret rule).
- [ ] Any OAuth2 Authorization Code flow (browser redirect, `code` + `redirect_uri`, `oauth-start`/`oauth-complete` commands) is classified as `Passthrough` — there is no canonical `oauth2_authorization_code` profile shape; the user-facing config lives on the profile itself, not in `metadata.auth.parameter`.
- [ ] Every non-`NoneRequired` entry has a non-empty `xsoar_param_map` (even if `interpolated: true`).
- [ ] Every entry whose `type` is NOT `Plain` or `APIKey` has `interpolated: true`. Only `Plain` and `APIKey` entries may be non-interpolated.
- [ ] Every `auth_types[]` entry whose test-module path manually raises (`raise DemistoException(...)` / `return_error(...)`) for this auth — e.g. OAuth Authorization Code, Device Code, ROPC flows that require an out-of-band `!auth-start` command before the connection-test button can succeed — has `"verify_connection_skip": true`. Profiles whose test-module reaches an actual HTTP call leave `verify_connection_skip` at its default (`false`) or omit the key.
- [ ] No `xsoar_params` key is present in any entry — only `xsoar_param_map` is read (any stale `xsoar_params` field is silently ignored, so leaving it in is a silent footgun).
- [ ] `auth_types[]` entries are sorted by `(type, name)` ascending. (Map keys are unordered — no sort requirement.)
- [ ] If there is genuinely no auth, `auth_types` is `[]` (the pre-2026-05 `config: "NoneRequired"` key is no longer used).
- [ ] Connection metadata (URL, instance host, region) is intentionally NOT in `auth_types` — it goes in `other_connection` instead (see [1.2.5](#125-building-the-other_connection-list)).
- [ ] `other_connection` lists every connection-adjacent YML param (`url`, `proxy`, `insecure`, `port`, `host`, `region`, etc.).
- [ ] `other_connection` does NOT contain any auth-secret param (those are keyed in `auth_types[].xsoar_param_map`).
- [ ] `other_connection` does NOT contain any per-command behavioral param (those go in `Params to Commands`).
- [ ] `other_connection` list is sorted ascending.

---

#### 1.12 Auth-parity gate inside `set-auth`

`set-auth` is no longer a pure CSV write. As of schema_version=2 (2026-05), the call invokes [`check_auth_parity.check_auth_parity`](check_auth_parity.py) against the **candidate** `Auth Details` payload before the cell is committed. The parity gate **does not consult the `Params for test with default in code` CSV cell** — per-param value seeding for the analyzer is supplied per-invocation via [`--seed-param NAME=VALUE`](#1.12.A.bis-per-param-value-seeding-via---seed-param) (see below). The persisted `Params for test with default in code` cell still exists, is still set during Step 3a, and is still consumed downstream by the Step 3b manifest generator — it is purely a record consumed by the connector-param mapper, not by the parity gate. The result is evaluated as follows:

| Analyzer outcome | Gate decision | What happens |
|---|---|---|
| All connections return `status: "pass"` (or per-connection `skipped_signed` / `skipped_mtls` / `skipped_passthrough` / `inconclusive`) | **Allow** | The cell is written; downstream Params\* columns are wiped per the normal cascade. |
| `auth_types` is empty (NoneRequired) | **Allow** | No connections to test. The cell is written. |
| Hard error: `ERROR_NO_BASECLIENT` (11), `ERROR_NON_PYTHON` (10), `ERROR_ALL_INTERPOLATED` (12), `ERROR_CONNECTION_INTERPOLATED` (13), `ERROR_INTEGRATION_REJECTS_HTTP` (14) | **Allow (structural skip)** | The integration cannot be parity-tested for a known, accepted reason. Same semantics as the historical "N/A markpass" on the removed `auth parity test passes` checkpoint. The cell is written. |
| Any connection returns `status: "fail"` | **Block** | The cell is NOT written. The row is left untouched. The skill should apply the troubleshooting playbook below and re-run `set-auth`. |
| Infrastructure failure (`ERROR_FILES_LOOKUP`, `ERROR_PARITY_IMPORT`, `ERROR_PARITY_UNHANDLED`, etc.) | **Block** | The cell is NOT written. Inspect the error and fix the prerequisite (missing `Integration File Path`, broken import path, etc.) before re-running. |

When the gate blocks, the api/CLI returns the full analyzer envelope under `result["parity"]` so the skill can attribute the failure to a specific connection / sentinel.

> **Escape hatch (tests only).** Set the env var `CONNECTUS_SKIP_AUTH_PARITY=1` to bypass the gate entirely. This is for unit tests and one-off debugging — do **not** use it as part of the normal migration workflow.

<a id="1.12.A.bis-per-param-value-seeding-via---seed-param"></a>

##### Per-param value seeding via `--seed-param NAME=VALUE` (operator escape hatch)

Some YML params have **format validators** that fire at integration module-load time and reject the analyzer's auto-generated `SENTINEL_PARAM_<name>` placeholder before any HTTP call. The analyzer already auto-coerces a few well-known patterns — params whose NAME (case-insensitive substring match) contains `thumbprint`, `certificate`, or `private_key` get a syntactically-valid stub (40-char hex thumbprint, stub PEM cert, stub PEM private key) instead of the generic sentinel string. That covers the Microsoft cert-thumbprint slot but **does not** cover every format validator in the wild. For example:

- **JWT secrets with a regex format validator** — the integration's `BaseClient.__init__` calls `jwt.decode(secret, …)` at startup; the sentinel string fails the JOSE format check.
- **OIDC issuer URLs** — startup code does `urlparse(issuer).scheme == "https"` and refuses to construct the client when the sentinel doesn't parse as `https://…`.
- **Custom hex / regex-validated tokens** beyond the auto-coerced `thumbprint` substring (e.g. a 64-char hex API token whose YML name is `api_token`).
- **Cert thumbprint validators in `MicrosoftClient`** whose YML name doesn't match the substring (e.g. `cert_fingerprint` — `thumbprint` substring miss).

The escape hatch is the repeatable `--seed-param NAME=VALUE` flag on the `set-auth` verb (and on the standalone [`check_auth_parity.py`](check_auth_parity.py:1) CLI when iterating manually):

```bash
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param NAME=VALUE [--seed-param NAME=VALUE ...]
```

**Semantics:**

- Repeatable; each `--seed-param` appends to an in-memory dict that is forwarded **only** to the parity gate for this single `set-auth` invocation. The dict is **never** persisted to the CSV.
- Values ≥4 chars long act as ad-hoc traceable sentinels (they appear verbatim in captured HTTP, exactly like the auto-generated sentinels).
- The override takes effect inside the type-aware placeholder pass in [`check_command_params.build_param_values`](check_command_params.py:1) — wins over the YML `defaultvalue`, the auto-coercion (cert/thumbprint/private_key), and the generic `SENTINEL_PARAM_<name>` string.

**Dotted-leaf rule for YML `type:9` (credentials) widgets:**

- `--seed-param creds.identifier=<v>` sets the identifier leaf.
- `--seed-param creds.password=<v>` sets the password leaf.
- Either leaf may be omitted — the omitted leaf keeps its default sentinel.
- **Flat `--seed-param creds=<value>` on a `type:9` widget is rejected with exit code 2** and an actionable error pointing at the dotted-leaf form (the integration expects a dict-shaped value at runtime; a flat string would have the wrong shape).
- Stray dotted-leaf overrides (unknown parent param, parent param is the wrong type, leaf is neither `identifier` nor `password`) surface as `[seed] WARNING` lines on stderr and do **NOT** abort the run.

**Auth-overlap rejection (hard error before the parity gate runs):**

If a `--seed-param` key (or its dotted-leaf parent) references a param that is already declared in the candidate `Auth Details` — projected from `auth_types[].xsoar_param_map.keys()` (with dotted leaves collapsing to the segment before the first `.`) unioned with every `other_connection` entry — the `set-auth` call is hard-rejected **before** the parity gate runs with the error envelope:

```
{"error": {"code": "ERROR_SEED_AUTH_OVERLAP", "message": "...", "exit_code": 2}}
```

The reason: any param already declared in `Auth Details` is supplied via UCP credential injection (not via `demisto.params()`) in the new run anyway, so the seed value would be silently discarded by the UCP injection seam — masking real auth-routing bugs. The fix is to either drop the override (the analyzer already routes the secret via UCP; you don't need a sentinel value for it) or, if the param is genuinely NOT an auth param and was misclassified, revert to Step 1 with `set-auth` and remove it from `auth_types[].xsoar_param_map` / `other_connection` first.

**Worked example — Microsoft cert-thumbprint integration:**

```bash
# 40-char hex thumbprint — required by the MicrosoftClient startup validator
# even when the actual cert is supplied via UCP credential injection.
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param certificate_thumbprint=0123456789ABCDEF0123456789ABCDEF01234567
```

**Worked example — JWT secret with format validation:**

```bash
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param jwt_secret=real-jwt-format-secret-12345
```

**Worked example — OIDC issuer URL:**

```bash
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param oidc_issuer=https://login.microsoftonline.com/common/v2.0
```

**Worked example — `type:9` credentials with format-validated password:**

```bash
# Note the dotted-leaf form. Flat 'service_account=<v>' would be rejected
# with exit code 2.
python3 connectus/workflow_state.py set-auth "<Integration ID>" '<json>' \
    --seed-param service_account.identifier=test@example.com \
    --seed-param service_account.password=p@ssw0rd-with-special-chars-12
```

**Recovery loop:** when the parity gate fails with `RUN_FAILED_OLD` and the stderr_excerpt is a format-validator crash at module-load time:

1. Identify the offending param from the stderr excerpt (`ValueError: invalid thumbprint`, `jwt.exceptions.InvalidTokenError`, etc.).
2. Read the integration's `.py` to see what format the validator expects.
3. Re-run `set-auth` with `--seed-param <name>=<a-value-that-passes-the-validator>`.
4. If the auth-overlap rejection fires, the param is actually an auth param — re-classify `Auth Details` to remove the bad seed target (or drop the seed; UCP will route the real secret per-request).

##### Troubleshooting playbook — when the parity gate blocks

The two failure modes you will encounter in practice are (a) the integration uses a non-standard auth header and the default UCP injection writes the secret into the wrong slot, and (b) the integration has a startup-time auth validator that raises before the `Client` is constructed and the parity tool never reaches the request-emission stage. Both have well-defined fixes.

###### A. UCP support for integrations using non-standard auth headers

When UCP is enabled, [`BaseClient._http_request`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:10200) auto-injects credentials via [`_inject_ucp_credentials`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9919) → `_apply_ucp_credentials` → `_apply_ucp_<type>`. The defaults assume vendors use the standard `Authorization` header:

- [`_apply_ucp_api_key`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9855) → writes `Authorization: Bearer <key>`.
- [`_apply_ucp_plain`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9881) → sets `ctx.auth = (username, password)` (a tuple consumed by `requests` as HTTP Basic Auth, equivalent to `Authorization: Basic <base64(user:pass)>`).
- [`_apply_ucp_oauth2`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9836) → writes `Authorization: <token_type> <access_token>` (default token type `Bearer`).

**The problem.** Many vendors do NOT use `Authorization`. APIVoid uses `X-API-Key`; some vendors use `Apikey`; some carry the secret in a custom query parameter; signed-request schemes (HMAC, AWS SigV4) write into multiple headers at once. For any such integration, the default UCP injection writes the secret into the **wrong** header. The integration's own code reads from the ORIGINAL header — which is empty under UCP because the user-facing params were stripped from `demisto.params()`. Net result: **the outbound request goes out unauthenticated**, but no exception is raised at the injection layer.

**Detection.** This manifests as the auth parity result reporting `MISSING_IN_NEW` for the secret's role-tagged sentinel. The old run's `locations` show the secret at the integration's actual header (e.g. `header:x-api-key`); the new run's `locations` are empty.

**Fix.** Override the appropriate `_apply_ucp_<type>` method on the integration's `Client` class (the `BaseClient` subclass). The override receives the UCP credentials dict and a request-context object with mutable `.headers`, `.params`, `.auth`, `.data`, `.json_data` attributes, and is expected to write the secret into the slot the integration's own request code actually reads from.

**Worked example — APIVoid.** APIVoid's `Client.__init__` constructs `headers = {"X-API-Key": apikey, ...}`. To make UCP route the credential into the same slot, add `_apply_ucp_api_key`:

```python
class Client(BaseClient):
    def __init__(self, base_url, apikey, verify, proxy):
        headers = {"X-API-Key": apikey, "Content-Type": "application/json"}
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def _apply_ucp_api_key(self, credentials: dict, ctx: Any) -> None:
        """
        UCP override: write the API key into the non-standard ``X-API-Key`` header
        instead of the default ``Authorization: Bearer ...``.
        """
        api_key_data = credentials.get("api_key", credentials)
        ctx.headers["X-API-Key"] = api_key_data.get("key", "")
```

**Sibling overrides for other auth types.** The same pattern applies to the other two `_apply_ucp_*` methods. The `credentials` argument is the dict returned by the UCP shape (see [`auth_parity_test_design.md`](auth_parity_test_design.md:1) §2.5 for the per-type shapes); `ctx` has mutable `.headers`, `.params`, `.auth`, `.data`, `.json_data` attributes.

- **`Plain` with custom header(s)** — override [`_apply_ucp_plain`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9881):

  ```python
  def _apply_ucp_plain(self, credentials: dict, ctx: Any) -> None:
      plain_data = credentials.get("plain", credentials)
      # Example: vendor wants username + password in two separate custom headers
      ctx.headers["X-Vendor-User"] = plain_data.get("username", "")
      ctx.headers["X-Vendor-Pass"] = plain_data.get("password", "")
      # — OR — preserve Basic Auth but use HTTPBasicAuth for additional flexibility:
      # from requests.auth import HTTPBasicAuth
      # ctx.auth = HTTPBasicAuth(plain_data.get("username", ""), plain_data.get("password", ""))
  ```

- **`OAuth2*` with non-`Authorization: Bearer`** — override [`_apply_ucp_oauth2`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9836):

  ```python
  def _apply_ucp_oauth2(self, credentials: dict, ctx: Any) -> None:
      oauth2_data = credentials.get("oauth2", credentials)
      ctx.headers["X-Auth-Token"] = oauth2_data.get("access_token", "")
  ```

**Cross-reference to CSP source** for the default implementations and the entry point — read these when you need to confirm exactly what defaults you are replacing:

- [`_apply_ucp_api_key`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9855) (default writes `Authorization: Bearer <key>`; docstring shows the canonical override at lines 9865–9870).
- [`_apply_ucp_plain`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9881) (default sets `ctx.auth = (username, password)` for `requests` Basic Auth).
- [`_apply_ucp_oauth2`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9836) (default writes `Authorization: <token_type> <access_token>`).
- [`_inject_ucp_credentials`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:9919) — the per-request entry point invoked from `BaseClient._http_request`.
- [`_http_request`](Packs/Base/Scripts/CommonServerPython/CommonServerPython.py:10200) — the UCP block inside the HTTP request loop.

**Cheat sheet — when you need the override:**

- **YOU NEED IT** if the integration's existing code reads the secret from a non-`Authorization` header. Grep the integration's `Client.__init__` for the `headers={...}` dict it passes to `super().__init__` — anything other than `Authorization: Bearer <...>` (for APIKey / OAuth2) or `Authorization: Basic <...>` / `HTTPBasicAuth(...)` (for Plain) means UCP's default writes to the wrong slot.
- **YOU PROBABLY DON'T NEED IT** if the integration sends `Authorization: Bearer <token>` for APIKey / OAuth2, or uses `HTTPBasicAuth(user, pass)` (or the equivalent `auth=(user, pass)` tuple) for Plain — the defaults already cover these.
- **The parity gate inside `set-auth` will surface `MISSING_IN_NEW`** for the relevant role-tagged sentinel if you forgot the override. Use the rejected `set-auth` payload + `result["parity"]` as the regression catch — apply the override, then re-run `set-auth` with the same payload to confirm the diff goes green.

###### B. Multi-auth integrations with startup-time auth-combo validation

Some integrations (Jira V3 is the canonical example) gate `main()` on a `validate_auth_params()` / `check_credentials()` / `assert_auth()` helper that runs **before** the `Client` is constructed. The helper inspects `demisto.params()` and raises `DemistoException` / `return_error` if some required combination of auth fields is empty. Under UCP this is a precondition that fires before any HTTP call.

**Detection — grep recipe.** Look for a validator function whose body raises before any client is built:

```bash
grep -nE "def (validate_auth|check_credentials|assert_auth)" Packs/<Pack>/Integrations/<Name>/<Name>.py
# then read its body — if it ends in `raise DemistoException(...)` / `return_error(...)`
# AND it is called from `main()` BEFORE the Client constructor, this section applies.
```

**Why it breaks under UCP.** `demisto.params()` is intentionally empty for auth fields under UCP — UCP supplies the secrets per-request via `getUCPCredentials`, not via `params`. The startup validator sees nothing in `params`, concludes no auth was configured, and raises before any HTTP call. The parity tool never reaches the request-emission stage.

**Detection from the parity-gate output.** Identical-shape `RUN_FAILED_OLD` + `RUN_FAILED_NEW` (or `MISSING_IN_BOTH`) errors across **every** auth profile in a multi-profile (exclusive-OR) configuration; the `stderr_excerpt` contains phrases like *"are mandatory"*, *"must be provided together"*, or *"the required parameters were not provided"*.

**TWO valid fixes.**

**Option A — Gate the validator under UCP** (preferred when the integration is going to be a first-class UCP citizen and you want continued parity coverage):

```python
# BEFORE
validate_auth_params(username, api_key, client_id, client_secret, pat)

# AFTER
if not is_ucp_enabled():
    validate_auth_params(username, api_key, client_id, client_secret, pat)
```

Import `is_ucp_enabled` from `CommonServerPython` — it is already exported via `from CommonServerPython import *`. Worked example: [`Packs/Jira/Integrations/JiraV3/JiraV3.py:4857`](Packs/Jira/Integrations/JiraV3/JiraV3.py:4857).

**Option B — Mark every `auth_types[]` entry as `interpolated: true`:**

No code change. Re-classify `Auth Details` so that every `auth_types[]` entry carries `"interpolated": true`. The parity gate's `ERROR_ALL_INTERPOLATED` structural-skip code fires, `set-auth` is allowed through, the workflow advances, and the integration's existing startup validator stays in place untouched. This is the **simpler, faster path** when the integration's UCP behavior is not the migration's first priority.

**When to pick A vs B.**

- Pick **A** if this integration is queued to be migrated to UCP soon AND you want parity coverage to catch the next round of UCP-related bugs (e.g., non-standard auth header overrides — see the previous sub-section).
- Pick **B** if the integration is queued for later, or if its UCP wiring is genuinely complex (multi-auth combined with per-`Client`-construction header building, conditional flags computed from `params` at init, etc.). Re-visit when the integration is actually prioritized.

**Completeness note if you pick A.** Gating the validator is necessary but **not sufficient** for a fully UCP-aware multi-auth integration. If the `Client.__init__` computes flags from params (e.g., Jira's `is_basic_auth = bool(username and api_key)`), those flags will be `False` under UCP and the `Client`'s branching will pick the wrong path at request time. The `Client` itself needs to consult `get_ucp_credentials()` per-request to pick the right header style — see sub-section A above for the per-request override pattern. **For multi-auth integrations, Option A may require BOTH the startup gate AND the `Client` UCP-awareness override.** This is the principal reason Option B (`interpolated: true`) is often the pragmatic choice.

###### C. Structural-skip gate ordering and the boto3 / AWS family

The parity tool's structural-skip gates fire in a **fixed order** — the first one matched wins, and downstream gates are never evaluated. The order is:

1. `ERROR_NON_PYTHON` (exit 10)
2. `ERROR_NO_BASECLIENT` (exit 11) — refined into `APIMODULE_INTEGRATION_CANNOT_VERIFY` (exit 15) when the integration's `.py` contains `from <Foo>ApiModule import` (FIXES-TODO #12). Same structural-skip semantics; clearer diagnostic.
3. `MULTI_SECRET_PASSTHROUGH` (exit 16) — a `Passthrough` profile carrying 2+ credential-named keys (FIXES-TODO #9). Per cross-cutting decision #2, this is by design, not a failure. Fires before `ERROR_ALL_INTERPOLATED` so the more specific code wins.
4. `ERROR_ALL_INTERPOLATED` (exit 12)
5. `ERROR_CONNECTION_INTERPOLATED` (exit 13)
6. `ERROR_INTEGRATION_REJECTS_HTTP` (exit 14)
7. Per-connection skips inside the run: `skipped_signed`, `skipped_mtls`, `skipped_passthrough`.

Per-command crash post-classification (does not short-circuit the gate;
just refines the `RUN_FAILED_NEW` diagnostic):

- `UCP_STRIP_CRASHED_UNCONDITIONAL_READ` (FIXES-TODO #13) — replaces the
  generic `RUN_FAILED_NEW` when the new run crashed reading a key from
  the connection's `xsoar_param_map` (KeyError) or via a defensive
  `.get("credentials").get(...)` chain that hits the stripped parent
  (TypeError: NoneType not subscriptable). See sub-section D below.

**Boto3 / AWS integrations always trip `ERROR_NO_BASECLIENT` first**, NOT `skipped_signed`. They use `boto3.Session.client()` directly rather than subclassing `BaseClient`, so gate #2 catches them before gate #6 is even reached. The `skipped_signed` path conceptually exists for boto3 but is structurally unreachable for it — `skipped_signed` only fires for integrations that DO subclass `BaseClient` AND ALSO import `hmac` (or another signed-request module).

**Required action for boto3 / AWS integrations: classify with `interpolated: true` on every `auth_types[]` entry. There is no code-change alternative.** Same reasoning as the feed framework (§1.9.1): no `BaseClient` → no UCP injection → no parity testing possible without re-architecting the integration onto `BaseClient`, which is out of scope.

**Detection during classification:** grep the integration's `.py` for `import boto3|from boto3|import botocore|from botocore|AWSApiModule`. If any match, mark `interpolated: true` up front on every `auth_types[]` entry — `set-auth` will then short-circuit via `ERROR_ALL_INTERPOLATED` and proceed without ever attempting the parity run.

###### D. UCP-strip crash on unconditional `params["credentials"]` reads

**Added 2026-05-31** (FIXES-TODO #13 worked example). When the new
(UCP) run crashes with `KeyError: 'identifier'` (or a similar leaf
from the connection's `xsoar_param_map`), or with `TypeError:
'NoneType' object is not subscriptable` from a
`.get("credentials").get(...)` chain, the parity gate post-classifies
the diff as `UCP_STRIP_CRASHED_UNCONDITIONAL_READ`.

**Why this happens.** The new run, by design, strips every key listed
in the connection's `xsoar_param_map` from the `params` dict before
invoking the child — because UCP is supposed to inject the secret via
`demisto.getUCPCredentials()` instead. Integrations whose `main()`
reads those keys **unconditionally** (e.g. AMPv2's
`client_id = params["credentials"]["identifier"]`) crash.

**TWO valid fixes** (per Hints policy / cross-cutting #1: prescription
ambiguous, choose by context).

**Fix path 1 — keep the integration UCP-clean (add an override).**
Add `_apply_ucp_plain` (or the analogous APIKey/OAuth2 override) on
the `Client` class so it consumes UCP-shape credentials directly:

```python
class Client(BaseClient):
    def _apply_ucp_plain(self, credentials: dict, ctx: Any) -> None:
        plain_data = credentials.get("plain", credentials)
        ctx.auth = (
            plain_data.get("username", ""),
            plain_data.get("password", ""),
        )
```

This is the right path when the integration is going to be a
first-class UCP citizen and you want continued parity coverage.

**Fix path 2 — minimal diff (`is_ucp_enabled()` gating).** Gate the
unconditional `params[...]` read on `is_ucp_enabled()`:

```python
# BEFORE
client_id = params["credentials"]["identifier"]
api_key   = params["credentials"]["password"]

# AFTER
if is_ucp_enabled():
    creds = demisto.getUCPCredentials()
    client_id = creds["plain"]["username"]
    api_key   = creds["plain"]["password"]
else:
    client_id = params["credentials"]["identifier"]
    api_key   = params["credentials"]["password"]
```

This is the right path when the integration's `Client` doesn't
subclass `BaseClient` cleanly (e.g. constructs `requests` manually
with `auth=(client_id, api_key)`) so the override approach can't
fully fix the dotted-access pattern.

**Fix path 3 (escape valve) — mark `interpolated: true`.** When you
just need to advance the migration, classify the profile
`interpolated: true` per cross-cutting decision #3. Document the
reason in the commit notes. This is the documented fallback.

###### E. Permanent `interpolated: true` candidates (no parity testing possible)

Three categories of integrations are permanent `interpolated: true` candidates — the parity tool will short-circuit on them, and that is the **correct** outcome (not a bug to chase):

1. **Legacy HTTP layer / no `BaseClient` subclass** — short-circuits with `ERROR_NO_BASECLIENT`. Example: CrowdStrike Falcon.
2. **Feed-framework integrations** (any `*FeedApiModule` import) — short-circuits with `ERROR_NO_BASECLIENT`. See §1.9.1.
3. **`boto3` / `botocore` / `AWSApiModule` integrations** — short-circuits with `ERROR_NO_BASECLIENT` (see sub-section C above).

For all three, the fix is to classify with `interpolated: true` on every `auth_types[]` entry. Do **not** attempt to refactor the integration onto `BaseClient` just to make the parity tool reachable — that is out of scope for the migration.

###### F. Sentinel grammar (for grepping diagnostics)

Parity sentinels encode both the XSOAR path AND the **role** the secret plays, in the form `__AUTHPARITY__<connection>__<xsoar_path>__<role>__<uuid8>` — e.g. `__AUTHPARITY__credentials__credentials.password__key__86ad7936`. Diff messages can be grepped by role, which makes "missing-in-new on the `key` sentinel of `credentials`" trivially attributable to a missing `_apply_ucp_api_key` override (sub-section A above). See [`auth_parity_test_design.md`](auth_parity_test_design.md:1) §2.3 for the full sentinel grammar.

##### Manual re-runs of `check_auth_parity.py` (for debugging only)

The parity gate inside `set-auth` is the canonical entry point. If you want to inspect the analyzer's output without committing the cell — for instance, while iterating on a UCP override or a `--seed-param` recovery — you can run it directly:

```bash
AUTH='{"auth_types":[...]}'  # the candidate payload
python3 connectus/check_auth_parity.py Packs/<PackName>/Integrations/<IntegrationName> \
    --integration-id "<id>" \
    --auth-details "$AUTH" \
    [--seed-param NAME=VALUE ...]   # mirror whatever set-auth would receive
```

The same JSON envelope is what `set-auth` evaluates internally. Once the manual run goes green, re-run `set-auth` with the same payload (and the same `--seed-param` flags, if any).

---

#### Auth Type Reference

See [`connectus/Readme.md`](Readme.md:19) for the full Auth Type definitions and §1.2.6 below for the canonical UCP profile-type field shapes.

| Value | UCP profile type | Description |
|---|---|---|
| `OAuth2ClientCreds` | `oauth2_client_credentials` | OAuth 2.0 Client Credentials flow (`client_id` + `client_secret`) |
| `OAuth2JWT` | `oauth2_jwt_bearer` | OAuth 2.0 JWT Bearer flow (service-account / signed-assertion) |
| `APIKey` | `api_key` | Single API key, single-secret HMAC, or other single-static-secret mechanisms |
| `Plain` | `plain` | Single username + password pair (basic auth, login form, etc.) |
| `Passthrough` | n/a (no canonical profile shape) | Authorization Code (browser flow), Device Code, ROPC, Managed Identity, mTLS, multi-secret packages (Datadog 2-key, AWS SigV4, Akamai EdgeGrid, GitHub App, etc.), custom signing, and anything else that doesn't cleanly fit one of the four profile shapes above. When in doubt, prefer `Passthrough`. |
| `NoneRequired` | n/a | No authentication needed |


## Analyzing per-command parameters

Use this procedure whenever you are about to populate the `Params to Commands` workflow data column (Step 2 below). The [`connectus/check_command_params.py`](check_command_params.py) analyzer does the heavy lifting: it runs each command in a production-equivalent Docker container, intercepts HTTP traffic via an internal capture proxy, and reports which YML configuration params each command actually consumes. The skill's job is to invoke it correctly, interpret its output, and merge its findings with a source-code review before writing the polished result to the pipeline.

### 1. When to run the analyzer

Run the analyzer for any integration that requires the `Params to Commands` column to be populated — i.e., the per-command list of YML configuration params actually consumed by each command. This is the input to Step 2 (`set-params-to-commands`).

### 2. How to invoke it

The analyzer is a self-contained script. It starts its own HTTP capture proxy internally — **the skill does not need to start any external proxy, server, or service**. The only external dependency is Docker (used by default to give each integration its production runtime environment).

Standard invocation:

```bash
python3 connectus/check_command_params.py <integration_dir> \
    --ignore-params-file connectus/default_ignore_params.txt \
    --integration-id "<Integration ID>"
```

Where `<integration_dir>` is the directory containing the integration's `.yml` and `.py` files (e.g., `Packs/QRadar/Integrations/QRadar_v3`).

The `--integration-id "<Integration ID>"` flag is **strongly recommended inside the migration workflow.** When supplied, the analyzer additionally calls [`workflow_state.py auth-params <id>`](workflow_state/cli.py:1) and unions every YML param id declared in the integration's `Auth Details` cell (auth-secret params projected from `auth_types[].xsoar_param_map.keys()` — dotted leaves collapse to the segment before the first `.` — plus every `other_connection` entry) into its own ignore set. This removes the entire burden of "remembering which params already live in `Auth Details`" from the AI — those params will simply not appear in the analyzer's per-command output. The flag is OPTIONAL; standalone runs (outside the migration workflow, or on integrations that haven't been classified yet) can omit it and the analyzer falls back to the file-based ignore set with a single-line stderr WARNING.

Optional flags the skill should know about:

- `--commands cmd1 cmd2 ...` — analyze only specific commands instead of all of them.
- `--static-only` — skip the dynamic phase (no Docker, no proxy). Faster, but lower accuracy. Use only when Docker is unavailable.
- `--timeout SECONDS` — per-command wall-clock timeout (default 30s; the batch runner uses 300s for the whole integration).
- `--docker {auto,always,never}` — `auto` (default) uses Docker when available; `never` runs in host Python (will fail on integrations needing third-party deps); `always` requires Docker.
- `--use-integration-docker` — opt-in: instead of the pinned `demisto/py3-native` image, use the integration's own `script.dockerimage` from its YML. Use this for a targeted re-run when an integration reports `module_not_found` (see Step 1 of the decision tree in section 6 below). Falls back to `--docker-image` if the YML doesn't declare one.
- `--integration-id <id>` — OPTIONAL. When supplied, the analyzer pulls the auth-derived ignore set from [`workflow_state.py auth-params <id>`](workflow_state/cli.py:1) and unions it with the file-based ignore set, guaranteeing that any param already declared in the integration's `Auth Details` cell cannot leak into the per-command output. The analyzer logs a single-line stderr INFO with the pulled list. Inside the migration workflow, ALWAYS pass this flag — `set-params-to-commands` will reject overlap regardless, so pulling the exclusion list up front saves a round-trip. If the integration is not in the workflow CSV, or its `Auth Details` is unset, the analyzer logs a single-line stderr WARNING and proceeds with just the file-based ignore set (it is intentionally not a fatal error).
- `--no-sentinel-coercion` — disable automatic sentinel-value coercion. By default the analyzer coerces sentinels for params whose **NAME** (case-insensitive substring match) contains `thumbprint`, `certificate`, or `private_key`, replacing the generic `SENTINEL_PARAM_<name>` string with a syntactically-valid stub (40-char hex thumbprint, stub PEM cert, stub PEM private key). This prevents the cert-thumbprint-hex-validator pattern (see §1.6 row #9) from killing the entire dynamic phase. Pass `--no-sentinel-coercion` for strict-sentinel debug mode.
- `--seed-param NAME=VALUE` — repeatable. Operator/AI escape hatch: provide an explicit value to seed for a specific YML param, overriding all other sources (YML default, cert coercion, generic sentinel). Use this when an integration has a param the auto-coercion didn't anticipate (e.g., a different format-validating credential, an enum-value selector that needs a specific value to traverse a code path). Values >= 4 chars long act as ad-hoc sentinels — they're grep-able in captured HTTP and the post-hoc attribution code looks for them too.
- `--no-auto-retry-integration-docker` — disable the automatic retry. By default, when the FIRST command's diagnostic comes back as `module_not_found` AND the analyzer is using the default `demisto/py3-native` image, it will automatically restart the dynamic phase with `--use-integration-docker` (which uses the integration's own production image, usually with the missing package preinstalled). Pass `--no-auto-retry-integration-docker` to disable, in which case the analyzer fast-fails the remaining commands as `module_not_found` (~30s × N saved) and returns immediately.
- `--with-diagnostics` — opt-in. Emits a top-level `diagnostics` key in the stdout JSON in addition to `integration` and `commands`. **Do NOT pass this flag inside the migration workflow** — `set-params-to-commands` will reject any payload containing extra top-level keys. Only pass it for interactive / debug use when you specifically want to read per-command status / failure attribution / Hybrid narrowing signal. (See §§3a/4/5/6 below; all of that documentation applies only when `--with-diagnostics` is set.)

The script writes its result to **stdout** as a single JSON document. All progress and warnings go to **stderr**. Exit code `0` means success; `2` means bad CLI args / path; `3` means an unhandled analyzer error.

### 3. Output schema (annotated example)

> **Default payload is two keys: `integration` + `commands`.** Diagnostics are **opt-in** via `--with-diagnostics` (the analyzer flipped its default after a breaking change to prevent `diagnostics` from leaking into `Params to Commands` when stdout was piped verbatim into `set-params-to-commands`). The schema below shows the diagnostic-rich payload; with the default flags you will see only the first two keys.

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
  "diagnostics": {                         // ONLY present with --with-diagnostics
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

`diagnostics` is **internal AI signal only**, and is only present when you re-ran the analyzer with `--with-diagnostics` — see section 5 below. **In normal workflow usage you will not see the `diagnostics` block at all.** If you need the diagnostic signal (e.g., a command failed unexpectedly and you want to see the failure_excerpt), re-invoke the analyzer with `--with-diagnostics` to inspect it, then RE-INVOKE WITHOUT THE FLAG to get the clean payload to persist.

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
| `status: no_data` across **every** command + stderr containing `Error: Odd-length string` or `non-hexadecimal` | Cert-thumbprint hex validator in `MicrosoftClient.__init__` rejected the analyzer's sentinel value before any command dispatched. Structural; affects most Microsoft cert-auth integrations. | Use the **full static union**. Do NOT retry with `--use-integration-docker` (failure is in `MicrosoftApiModule`, not in a missing package). `--ignore-params <name>` does NOT help. Until the analyzer ships a `--seed-override` flag, manual source review is the only path. |

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

#### 6f. Analyzer blind spot — client-side post-response params

The dynamic phase observes outbound HTTP traffic only. Params that are consumed **after** the API response — typically when building XSOAR result objects (`Common.DBotScore`, `CommandResults` with computed `outputs`, etc.) — leave no network footprint and will be missed by dynamic capture, even when the integration ran cleanly.

**Common shapes:**
- **Reputation `integrationReliability`** — passed into `Common.DBotScore(... reliability=reliability ...)` only when constructing the indicator; never sent to the API.
- **Per-indicator threshold params** (e.g. `bad`, `suspicious`, `malicious`) — used to map an API numeric score onto an XSOAR severity AFTER the API responds.
- **Output formatting toggles** — e.g. `human_readable_format`, `output_simplified`.

**Detection:** the analyzer reports `status: ok` and a list of params for the command, but a manual source-review reveals additional params consumed in the result-building code path. The fix is to **add them manually** (skill §7 "err on inclusion"). The analyzer cannot detect this class structurally because it has no signal that the command consumed the param.

Concrete example: APIVoid's reputation commands (`apivoid-ip`, `apivoid-domain`, `apivoid-url`, plus the bare `ip`/`domain`/`url`) all read `integrationReliability` to build the DBotScore object — but the analyzer reports it on zero of them. Add it manually to all six.

#### 6g. Analyzer blind spot — pre-dispatch fan-out helpers

Some integrations have a pre-dispatch helper that merges params into the per-command args dict before any handler is dispatched. The OpenAI ChatGPT v3 shape is the canonical case:

```python
def setup_args(args, params):
    for p in ("max_tokens", "temperature", "top_p"):
        args.setdefault(p, params.get(p))
    return args

def main():
    args = setup_args(demisto.args(), demisto.params())
    # ... dispatch ...
```

The analyzer's per-handler tracer sees `args.get("max_tokens")` inside the handler — looks like a pure command arg, not a param read. Static binding-narrowing doesn't fire because the params reach the handler only via the merged args dict. Dynamic only attributes when the param's value is actually consumed (e.g., `int(args["max_tokens"])`); commands that bail before that cast have no sentinel attribution.

**Detection:** look for any pre-dispatch helper in `main()` that iterates over a list of param names and writes them into the args dict. When found, **every** command receiving those merged args reads those params indirectly. Add them manually to every affected command's per-command list. The analyzer cannot detect this class structurally without modeling the args-dict mutation.

Watch also for in-place mutation patterns like `args.update({k: params.get(k) for k in BEHAVIOURAL_PARAMS})` and `args = {**args, **{k: params.get(k) for k in ...}}`.

#### 6h. Recovery loop using `--seed-param`

When the analyzer reports `status: no_data` AND the failure_excerpt suggests a format-validator failure on a credential-shaped param that the auto-coercion didn't catch (skill §1.6 row #9 covers the common Microsoft cert-thumbprint case), the recovery loop is:

1. Inspect the failing param's YML type and the source code's first-touch validator. Determine what shape the integration expects.
2. Re-run the analyzer with `--seed-param <name>=<plausible-value>`:
   ```bash
   python3 connectus/check_command_params.py <dir> \
       --ignore-params-file connectus/default_ignore_params.txt \
       --integration-id "<id>" \
       --seed-param my_jwt_secret='base64-encoded-stub' \
       --seed-param my_oidc_issuer='https://example.com/issuer'
   ```
3. If a different validator fires next, repeat with another `--seed-param`. The escape hatch is repeatable; each invocation can pass multiple `--seed-param` flags.
4. The seed values you supply (>= 4 chars) double as ad-hoc sentinels: they appear verbatim in any captured HTTP request, so the analyzer's post-hoc attribution can still attribute them to commands.

**Common shapes you'll need to seed:**
- JWT signing secrets: a base64-decodable random byte string ≥ 16 chars.
- OIDC issuer URLs: a full `https://...` URL that passes URL validators.
- Splunk session tokens: a 32-char hex string.
- API tokens with prefix prefixes (e.g., GitHub `ghp_...`): supply a plausible stub matching the prefix convention.

Coerced auto-defaults (cert/thumbprint/private_key) do NOT need `--seed-param` — they're already handled. Use `--seed-param` only when the auto-coercion misses a case.

**YML `type:9` credentials widgets use the dotted-leaf form.** When the integration code reads `params.get("<name>", {}).get("identifier")` / `.get("password")` (the standard XSOAR credentials-widget shape), the analyzer seeds a dict-shaped value by default. To override either leaf, use `--seed-param <name>.identifier=<value>` and/or `--seed-param <name>.password=<value>`. Each leaf can be supplied independently — omitted leaves keep their `SENTINEL_PARAM_<name>_identifier` / `SENTINEL_PARAM_<name>_password` defaults.

The common case: an integration's `Client.__init__` (or test-module path) validates the password leaf as JSON, a PEM key, or another structured format, and the generic sentinel string fails validation. Seed the password leaf with a plausible structured stub:

```bash
# Google service-account JWT — code validates user_creds.password as JSON
--seed-param 'user_creds.identifier=stub@stub.iam.gserviceaccount.com' \
--seed-param 'user_creds.password={"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n","client_email":"stub@stub.iam.gserviceaccount.com",...}'
```

**Flat `--seed-param <name>=<value>` on a `type:9` credentials param is rejected with exit code 2** and an actionable error pointing at the dotted-leaf form. The reason: integration code expects `params.get(name, {}).get(...)` to return a leaf value from a dict; a flat string replacement makes the whole value a string and crashes the consumer with `AttributeError: 'str' object has no attribute 'get'`.

**Stray dotted-leaf overrides surface as `[seed] WARNING` lines** without aborting the run:
- `--seed-param ghost.password=x` where `ghost` isn't a YML param → "dotted-leaf override(s) … reference parent(s) that are not in this integration's visible YML config".
- `--seed-param api_key.identifier=x` where `api_key` is a YML `type:4` (encrypted) param, not `type:9` → "dotted-leaf override(s) … are invalid. Dotted-leaf form is only supported for YML type:9 credentials widgets".
- `--seed-param creds.weird_leaf=x` where `creds` IS type:9 but `weird_leaf` isn't `identifier`/`password` → same WARNING with `leaf 'weird_leaf' not in {'identifier', 'password'}`.

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
- **Set `DEMISTO_SDK_LOG_FILE_PATH` to a workspace-local directory** when running in a sandboxed environment (e.g., from inside the IDEX agent). The analyzer's dynamic phase shells out to `demisto-sdk prepare-content`, which uses `loguru` to open a debug log file. By default `demisto-sdk` writes to `~/.demisto-sdk/logs/demisto_sdk_debug.log`, which is outside the workspace and triggers `PermissionError: [Errno 1] Operation not permitted` (EPERM from macOS sandboxd / TCC, not from POSIX perms) → the analyzer crashes with `DynamicPrepError: prepare-content failed: rc=1` and exits rc=3. Workaround: prepend the analyzer invocation with `DEMISTO_SDK_LOG_FILE_PATH="$PWD/.tmp_migration/sdk-logs"` (the env var is inherited by the `demisto-sdk` subprocess). Any workspace-writable directory works.

  ```bash
  DEMISTO_SDK_LOG_FILE_PATH="$PWD/.tmp_migration/sdk-logs" \
    python3 connectus/check_command_params.py <integration_dir> \
      --ignore-params-file connectus/default_ignore_params.txt \
      --integration-id "<Integration ID>"
  ```

  Same applies to any other `demisto-sdk` invocation made from the agent (Step 7 `validate`, Step 9 `pre-commit`). When in doubt, set the env var. The directory does not need to exist beforehand — `demisto-sdk` creates it on first write.

  > **2026-05-31 update.** The connectus analyzers (`check_auth_parity.py`, `check_command_params.py`) now auto-apply this workaround when `DEMISTO_SDK_LOG_FILE_PATH` is unset: they default it to `<repo>/.tmp_migration/sdk-logs` and create the directory on demand. You only need to set the env var manually for `demisto-sdk` invocations you make YOURSELF (validate, pre-commit, update-release-notes, etc.) — the analyzer invocations are now self-fixing.

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

- **Pull the auth-aware ignore list first.** Run `python3 connectus/workflow_state.py auth-params "<Integration ID>"` to get every YML param id that's already declared in `Auth Details` (both the auth-secret params projected from `auth_types[].xsoar_param_map.keys()` — dotted leaves collapse to the segment before the first `.` — and every entry in `other_connection`). These params MUST NOT appear in `Params to Commands` — `set-params-to-commands` will hard-reject the call if any of them does. The analyzer can pull this list automatically — pass `--integration-id "<Integration ID>"` (see "Analyzing per-command parameters" → "How to invoke it" above) and the auth-derived ids are unioned into the analyzer's ignore set up front.
- Hidden YML params (`hidden: true` or `hidden: [<list>]`) MUST NOT appear in any per-command list. The `set-params-to-commands` validator does not currently enforce this; it is the analyst's responsibility per skill §1.3.

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

**Validation:** The command rejects (a) invalid JSON with the parse error, AND (b) any payload whose per-command param lists overlap with the integration's `Auth Details` cell — every offending `(command, param_id)` pair is named, the auth-detail source for each offending param is named (e.g. `param 'credentials' overlaps with auth_types[].name='credentials' (xsoar_param_map keys=['credentials.identifier','credentials.password'])` or `param 'proxy' overlaps with other_connection`), and the row is NOT mutated.

#### When `set-params-to-commands` is rejected for overlap

If `set-params-to-commands` rejects your payload because a param is already in `Auth Details`, **stop and think about what the issue really is.** Two scenarios:

1. **The param really belongs to Auth Details** (e.g., the analyzer picked up `proxy` for a command but `proxy` is just a connection-level toggle). Strip it from your per-command payload, re-invoke `set-params-to-commands` with the cleaned list, and proceed.

2. **The param was misclassified into Auth Details and is genuinely used per-command** (rare but real — e.g., a YML param that doubles as both a connection setting AND a per-command override). Revert to Step 1: re-run `set-auth` with a corrected `Auth Details` JSON that removes the param from `auth_types[].xsoar_param_map` / `other_connection`. This will reset the workflow back to `generated manifest`, but that's the correct outcome — the original auth classification was wrong and downstream artifacts need to be regenerated against the fix. Do NOT bypass the rejection by hand-stripping just to make the call go through.

Use `python3 connectus/workflow_state.py auth-params "<Integration ID>"` at any time to inspect the current exclusion list. The same list is what the analyzer pulls when invoked with `--integration-id "<Integration ID>"`, so re-running the analyzer with the flag after fixing scenario (2) will produce a payload that is disjoint from `Auth Details` by construction.

Whenever you set params to command not strictly what the script returned, present the evidence clearly and concisely to the user why you decided to do it, and allow them to tweak the input.

### Step 3a: Set `Params for test with default in code` (data column)

This column records the **per-param defaults that `test-module` relies on** when UCP / the connectus runtime omits the YML default. The cell is consumed by [`connectus/connectus_migration/connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:1) as the `PARAM_DEFAULTS_JSON` positional argument, and by [`connectus/check_auth_parity.py`](check_auth_parity.py:1) as the first-precedence source of non-auth required param values.

**JSON shape is unchanged** — a flat object `{<yml_param_id>: <default value>}`. Empty `{}` is valid. The schema is enforced by [`validate_param_defaults()`](workflow_state/validators.py:155) (top-level JSON object, non-empty string keys, any JSON-typed values). What changes in this revision is **which params qualify** for the cell and **what code edits the migration must perform** as a side effect.

#### Qualification rule — derived from `Params to Commands`, NOT from source-code review

> **2026-05 rule change.** The qualification source for this column is the `test-module` entry of the already-validated `Params to Commands` cell (Step 2). Do NOT re-derive by reading the integration source or running the analyzer again — Step 2 already curated, validated, and persisted that list, and re-doing the work invites drift between the two columns.

The canonical qualification list is:

```bash
python3 connectus/workflow_state.py test-module-params "<Integration ID>"
```

(`--format=json` for programmatic consumption; the same value is available programmatically as [`test_module_params(integration_id)`](workflow_state/api.py:1) returning `list[str]`.)

**What that list contains and excludes, by construction:**

- It is exactly `commands["test-module"]` from the `Params to Commands` cell.
- It is already disjoint from `Auth Details` — `set-params-to-commands` rejected any overlap when Step 2 was applied, so no further auth-exclusion check is needed at this step.
- It already excludes hidden YML params (per skill §1.3) and the framework noise in [`connectus/default_ignore_params.txt`](default_ignore_params.txt).

**Additional filter — REQUIRED params only.** Of the params in the qualification list, this column applies ONLY to those whose YML configuration carries `required: true`. Optional params (`required: false` or omitted) are intentionally **excluded** even when test-module consumes them, because:

- The YML `required: false` contract is "operator may leave this unset; integration code must handle absence". Inventing a migration-defined default for an optional param contradicts that contract.
- Under UCP / connectus runtime the param will simply be absent when the operator didn't set it; the code's existing `params.get(name)` returns `None` (or its own existing fallback), and that's the documented behavior.
- This column is for params where omission would break test-module — i.e. required params that the connectus runtime might fail to inject.

**Filter the list:**

1. Get the canonical qualification list via `test-module-params`.
2. For each param, open the integration's YML `configuration` section, find the param entry, check its `required:` field.
3. Drop every param whose `required:` is `false` (or absent — XSOAR treats absent `required:` as `false`).
4. The remaining list (required + test-module-consumed) is what applies for the branch (a/b/c) workflow below.

**When the filtered list is empty (`[]`):** the payload for this column is `{}`. Skip the branch (a/b/c) workflow entirely; record an empty object via `set-param-defaults` and move on. This is the **most common case** in practice — most integrations only have auth-secret params marked `required: true`, and those are excluded by the `Auth Details` disjointness rule above.

**When the filtered list is non-empty:** iterate per-param and apply branch (a/b/c) as documented below.

**Why this changed:** the previous rule said "consumed by the test-module code path (per source review of `test_module()` and every helper it calls)". In practice this conflated three different things — (1) params read in `main()` before dispatch but never reaching `test_module`, (2) params read by `test_module` directly, (3) params read by `main()` and passed into `test_module`. Source review consistently over-counted (1), because those reads happen on every command invocation including test-module. The `Params to Commands` analyzer already disambiguates: it captures the params each command actually used end-to-end, and test-module's entry is the answer this column needs. Trust it.

**Precondition:** Step 2 must be complete. If `Params to Commands` is not set, the CLI helper exits with a clear error pointing at Step 2 — do that first.

#### Per-qualifying-param workflow

For each YML param that qualifies, apply exactly one of these three branches:

**(a) YML declares a `defaultvalue` AND the Python code does NOT already supply a fallback** (no `or "..."`/`or <literal>` after `params.get("foo")` or `demisto.params().get("foo")` or equivalent).

- Edit the integration's `.py` file: change `params.get("foo")` to `params.get("foo") or "<yml default>"`. Use the exact YML default value verbatim (preserve type — strings stay quoted, numbers stay unquoted, booleans become `True`/`False`).
- Record the YML default value under key `"foo"` in the JSON payload for this cell.
- Rationale: under UCP / the connectus runtime, the YML default is not necessarily injected; the code-side `or "<default>"` keeps `test-module` working in both the XSOAR environment AND under connectus.

**(b) YML declares NO `defaultvalue`.**

- **PAUSE and ask the user** (this is the per-param confirmation interaction; see §B.2): "Param `foo` is consumed by `test-module` but has no YML default. Propose a reasonable default value: `<your suggestion>`. Confirm, edit, or skip?"
- Once confirmed, edit the integration's `.py` to add the same `or "<confirmed default>"` fallback as branch (a).
- Record the confirmed default under key `"foo"` in the JSON payload.
- Suggest a default that matches the param's semantics. Recommended starters:
  - **`false`** for booleans (`type:8`).
  - **`50`** for incident/page limits.
  - **`"2 minutes"`** for `first_fetch` (small window keeps test-module fast and avoids backfilling huge ranges on misconfigured instances). Use a longer window only if the integration's `parse_date_range` raises on `"2 minutes"` or similar.
  - **`""`** for optional free-text params.
  - **`[]`** for optional multi-select params (`type:16`).
  Be explicit about the type. For per-integration overrides (e.g. a vendor whose `first_fetch` parser doesn't accept sub-hour windows), the user override at confirmation time wins.

#### Presenting branch-(b) defaults for confirmation

When you have multiple branch-(b) params, format the proposal as **one decision per line** so the user can edit one without re-reading the others. Always annotate the **source** of every default so the user can see at a glance which defaults are pre-existing vs proposed-new:

```
Branch (b) — NEW defaults to confirm (no YML default, no code fallback; .py edit will be added):
  drive_item_search_field  → ""              (PROPOSED — line 687)
  drive_item_search_value  → ""              (PROPOSED — line 687)
  isFetch                  → false           (PROPOSED — line 712)

Branch (c) — PRE-EXISTING code fallback, no code edit:
  action_detail_case_include  → ""              (PRE-EXISTING — line 284: args.get(..., ""))
  first_fetch                 → "10 minutes"   (PRE-EXISTING — line 684: params.get(..., "10 minutes"))
  max_fetch                   → 50             (PRE-EXISTING — line 1904: params.get(..., 50))
```

Source-tag conventions:
- **`PROPOSED — <line>`** — branch (b), this migration is adding the fallback at the named line. The user can override the default at confirmation time.
- **`PRE-EXISTING — <line>: <expression>`** — branch (c), the code already supplies this fallback. The user can still override, but doing so requires editing the integration's code (the cell value otherwise drifts from runtime behavior).
- **`YML defaultvalue — added at line <N>`** — branch (a), YML declares a default, this migration is adding the matching `or "<yml default>"` fallback in the .py.

Don't dump the JSON payload at this stage — that's for the final `set-param-defaults` confirmation.

**(c) Code ALREADY supplies a fallback** (`params.get("foo", "bar")` or `params.get("foo") or "bar"`).

- No code edit required.
- Still record the effective default under key `"foo"` in the JSON payload — the cell is the canonical record of what `test-module` will see in the connectus runtime.

> **`params.get("foo", "bar")` vs `params.get("foo") or "bar"`.** Branch (c) accepts either form, but the two are NOT semantically equivalent: `params.get("foo", "bar")` returns `"bar"` only when `foo` is absent, whereas `params.get("foo") or "bar"` also returns `"bar"` when `foo` is the empty string `""`, `0`, or `False`. The rule's intent is the `or` semantics (UCP supplies `foo = ""` rather than absent), so when the migration is ADDING a fallback (branches (a) and (b)) it standardizes on the `or` form. When the integration's existing code already uses the safe two-arg form, leave it alone — do NOT rewrite into the `or` form.

#### Discovery procedure (operational)

1. Fetch the canonical qualification list:

   ```bash
   python3 connectus/workflow_state.py test-module-params "<Integration ID>"
   ```

2. If the list is empty, the payload is `{}` — call `set-param-defaults "<id>" '{}'` and proceed to Step 3b. Skip steps 3–5 below.
3. For each param in the list, classify into branch (a) / (b) / (c) by reading the integration's `.py`. The point of this read is **only** to determine the per-param branch — NOT to re-derive whether the param qualifies. Specifically:
   - Look for the param's read site (`params.get("foo")` or `demisto.params().get("foo")`).
   - **Branch (a):** YML declares `defaultvalue` for `foo`, code reads without fallback (`params.get("foo")` with no `or ...` and no two-arg form). → Edit code to add `or "<yml default>"`. Record YML default in JSON.
   - **Branch (b):** YML declares NO `defaultvalue` for `foo`. → Pause and ask the user for a proposed default; edit code; record confirmed default in JSON.
   - **Branch (c):** Code already supplies a fallback (`params.get("foo", "bar")` or `params.get("foo") or "bar"`). → No code edit. Record the effective default in JSON.
4. After all per-param branches are decided, verify the cumulative `.py` diff with `git diff` before calling `set-param-defaults`.
5. Collect the JSON payload (one key per qualifying param) and call `set-param-defaults`.

Example payload:

```json
{
  "fetch_limit": 50,
  "first_fetch": "3 days",
  "isFetchEvents": false,
  "adv_params": ""
}
```

#### Self-check before `set-param-defaults`

- [ ] The set of keys in the JSON equals (or is a subset of) the **required-only** filtered list derived from `workflow_state.py test-module-params "<Integration ID>"`. No keys derived from source-code-only review — that source has been retired.
- [ ] Every key in the JSON corresponds to a YML param with `required: true`. No `required: false` (or absent) params appear.
- [ ] (Implied by the previous check, since `set-params-to-commands` already enforced it in Step 2:) no key in the JSON appears in `Auth Details`.
- [ ] For every key: either the integration's `.py` already supplies a fallback (branch c), OR the migration has just added a `or "<default>"` fallback in `.py` (branches a and b). Verify the edit with a `git diff` of the integration's `.py` BEFORE running `set-param-defaults`.
- [ ] For every branch-(b) key: the user explicitly confirmed the chosen default.
- [ ] If the required-only filtered list is empty, the payload is `{}` (empty object) — branches (a/b/c) do not apply.

```bash
python3 connectus/workflow_state.py set-param-defaults "<Integration ID>" '<JSON>'
```

Validator reference:
[`validate_param_defaults()`](workflow_state/validators.py:147) — enforces
top-level object, non-empty string keys, any JSON value. Full schema in
[`column-schemas.md`](column-schemas.md) §`Params for test with default in code`.

> **Reset semantics.** `Params for test with default in code` is NOT preserved on any reset
> path (`fail`, `reset-to`, `set-auth`, `reset` all wipe it). Only
> `Params to Commands` carries `preserve_on_reset: true` today.

<!--
Step 3a-bis (Shadowed Integration Commands) was REMOVED 2026-05-31 as
part of the FIXES-TODO combined #4+#6+New_RN execution plan. The
underlying CLI commands (`set-shadowed-commands`, `detect-shadowed-
commands`) remain in the codebase but are no longer part of the
workflow sequence; the step has been dropped from
`workflow_state_config.yml` and the matching CSV column has been
removed. See `FIXES-TODO.md` §4 (subsumed by workflow removal) and §5
(skipped — subsumed by #4).
-->

### Step 3b: Set `Params to Capabilities` (data column)

Produce and persist the **bare capability dict** — exactly what
[`connectus/connectus_migration/connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:1)
writes to its `-o` file. Top-level keys are capability names from a
closed enum (`general_configurations`, `Fetch Assets and Vulnerabilities`,
`Fetch Issues`, `Log Collection`, `Fetch Secrets`,
`Threat Intelligence & Enrichment`, `Automation`); each value is a flat
list of YML config param ids. Empty `{}` is valid. See
[`column-schemas.md`](column-schemas.md) §`Params to Capabilities` for
the full schema.

#### Gather the mapper's inputs from earlier pipeline data

Pull the inputs from the workflow CSV — do NOT make the user re-type
anything that already exists upstream in the pipeline. Show the values
to the user before running the script so wrong input is spotted
immediately.

```bash
# 1. Params to Commands cell (already set in Step 2)
python3 connectus/workflow_state.py show-step "<Integration ID>" "Params to Commands"

# 2. Params for test with default in code cell (just set in Step 3a)
python3 connectus/workflow_state.py show-step "<Integration ID>" "Params for test with default in code"

# 3. Integration YML path
python3 connectus/workflow_state.py files "<Integration ID>"
# -> use files["yml"]
```

#### Canonical mapper invocation

[`connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:1)
is a single-command Typer app — invoke it **without** a subcommand name;
the four positionals come straight after the script path:

```bash
python3 connectus/connectus_migration/connector_param_mapper.py \
  '<COMMAND_PARAMS_JSON from Params to Commands cell>' \
  '<PARAM_DEFAULTS_JSON from Params for test with default in code cell>' \
  '<INTEGRATION_YML_PATH from workflow_state.py files>' \
  '<MANUAL_COMMAND_TO_CAPABILITY_JSON — optional, default {}>' \
  -o connectus/connectus_migration/_<integration>_param_mapping.json
```

`MANUAL_COMMAND_TO_CAPABILITY_JSON` should be `'{}'` unless the user
explicitly overrides a command → capability routing decision. Construct
the override using the actual **command names** as outer keys and arrays
of capability names as values, for example:

```json
{"long-running-execution": ["Log Collection"]}
```

#### Persist the mapper's output verbatim

```bash
python3 connectus/workflow_state.py set-params-to-capabilities "<Integration ID>" \
  "$(cat connectus/connectus_migration/_<integration>_param_mapping.json)"
```

Concrete example for Gmail Single User:

```bash
python3 connectus/workflow_state.py set-params-to-capabilities "Gmail Single User" \
  '{"general_configurations":["fetch_limit","query"],"Fetch Issues":["fetch_time"],"Automation":["legacy_name","send_as","redirect_uri"]}'
```

Validator reference:
[`validate_params_to_capabilities()`](workflow_state/validators.py:204) —
enforces top-level object, capability keys drawn from the closed enum,
list-of-unique-non-empty-strings values, no required keys, `{}` valid.

> **Reset semantics.** `Params to Capabilities` is NOT preserved on any
> reset path (`fail`, `reset-to`, `set-auth`, `reset` all wipe it).

### Step 3c: Mark `generated manifest` (first checkpoint)

After generating the ConnectUs manifest YAML for the integration:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "generated manifest"
```

Prerequisite: `Params to Commands` must be set (valid JSON). The state
machine enforces this and tells you what's missing.

### Step 7: `run manifest make validate`

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

<!--
Step 6 (`write tests`) was REMOVED 2026-05-31 as part of the
FIXES-TODO combined #4+#6+New_RN execution plan. Per FIXES-TODO #6
resolution: the step's "no migration-driven edits" case was the
common one (Passthrough integrations with no UCP overrides and no
shadowed-command rename had nothing migration-specific to write a
test for) and a write-tests gate added no value over the downstream
`precommit/validate/unit tests passed` gate which already runs the
existing test suite. The step has been dropped from
`workflow_state_config.yml` and the matching CSV column has been
removed.

Code-editing guidance from the old Step 6 still applies and is
relevant to any code edits made during Step 1 / §1.12 (UCP
`_apply_ucp_*` overrides, `is_ucp_enabled()` startup-validator
gating) or Step 4 (`or "<default>"` fallbacks). Follow patterns in
`Templates/Integrations/` and the project's [`AGENTS.md`](../AGENTS.md)
rules:

  - Import `demistomock as demisto` at the top
  - Import `from CommonServerPython import *`
  - Use `demisto.params()` for configuration, `demisto.args()` for command arguments
  - Use `CommandResults` with `return_results()`
  - Use `return_error()` for user-facing errors
  - Use `demisto.debug()` / `demisto.info()` for logging, never `print()`
-->

### Step 8: `Release Notes` (data column)

**Added 2026-05-31** as part of the FIXES-TODO combined #4+#6+New_RN
execution plan. The step gates the migration on a release-notes file
when the integration's own .py/.yml were modified by the migration.

**Trigger.** `git diff HEAD --name-only -- <integration>.py <integration>.yml`.

- **Empty diff** (no code touch) → the cell auto-passes with
  `{"required": false, "path": null, "verified": false}`. No RN needed.
- **Non-empty diff** → the operator must produce a release-notes file
  containing the exact case-sensitive substring `"Enabled support for UCP"`.

**Operator workflow** (when the trigger fires):

1. Generate the RN scaffold:
   ```bash
   demisto-sdk update-release-notes -i Packs/<PackName>
   # The SDK may expose --update-type documentation (or revision); use
   # whichever flag matches your pack's existing RN convention. When
   # in doubt, omit and let the SDK infer.
   ```
2. Edit the generated `Packs/<PackName>/ReleaseNotes/<Version>.md` to
   include the required substring `"Enabled support for UCP"`
   (anywhere in the file — bullet, paragraph, heading; substring match
   is robust to formatting).
3. Commit the RN file alongside the migration's other code edits.
4. Run the setter:
   ```bash
   python3 connectus/workflow_state.py set-release-notes "<Integration ID>"
   ```

The setter takes **no JSON payload** — it auto-computes the cell shape
from the working tree. If the trigger fired AND the verification did
NOT pass, the setter rejects with a clear diagnostic plus a one-line
hint (per the Hints policy — the prescription is unambiguous):

```
ERROR: Release Notes step rejected for '<id>': <reason>.
  HINT: run `demisto-sdk update-release-notes -i Packs/<PackName>`,
  then edit the generated RN file to include the substring
  'Enabled support for UCP' and re-run set-release-notes.
```

See [`column-schemas.md`](column-schemas.md) §`Release Notes` for the
cell shape and validator rules.

### Step 9: `precommit/validate/unit tests passed`

Run pre-commit, validate, and unit tests via demisto-sdk pre-commit (Docker):

```bash
demisto-sdk pre-commit -i Packs/<PackName>/Integrations/<IntegrationName>/
```

When everything passes (Yuval decides which checks may be skipped):

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "precommit/validate/unit tests passed"
```

> **Workaround note (FIXES-TODO #7, 2026-05-31).** `demisto-sdk
> pre-commit` has a known bug: the cache directory creation lacks
> `exist_ok=True`, so the second and subsequent invocations crash with
> `FileExistsError: [Errno 17] File exists:
> '/Users/<you>/.demisto-sdk/cache/pre-commit'`. The fix is upstream
> (one keyword argument) and tracked separately. Until then, the
> workaround is to delete the cache dir before re-running:
>
> ```bash
> rm -rf ~/.demisto-sdk/cache/pre-commit
> demisto-sdk pre-commit -i Packs/<PackName>/Integrations/<IntegrationName>/
> ```

### Step 10: `param parity test passes`

Run the parameter parity test to verify the ConnectUs integration's parameters match the original:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "param parity test passes"
```

### Step 11: `code reviewed`

After code review is complete:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "code reviewed"
```

### Step 12: `code merged`

After the code is merged to the branch:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "code merged"
```

<!--
Step renumbering history:
- schema_version=2 (2026-05) removed `wrote/checked code` and
  `auth parity test passes`. Auth-parity content moved to §1.12.
- 2026-05-31 (FIXES-TODO combined #4+#6+New_RN) removed
  `Shadowed Integration Commands` (step 5, see FIXES-TODO #4/#5) and
  `write tests` (step 9, see FIXES-TODO #6); inserted `Release Notes`
  (step 8) immediately before `precommit/validate/unit tests passed`.

Current canonical sequence (12 steps):
  1. assignee
  2. Auth Details                                    (data, set-auth)
  3. Params to Commands                              (data, set-params-to-commands)
  4. Params for test with default in code            (data, set-param-defaults)
  5. Params to Capabilities                          (data, set-params-to-capabilities)
  6. generated manifest                              (checkpoint)
  7. run manifest make validate                      (checkpoint)
  8. Release Notes                                   (data, set-release-notes)  -- NEW 2026-05-31
  9. precommit/validate/unit tests passed            (checkpoint)
  10. param parity test passes                       (checkpoint)
  11. code reviewed                                  (checkpoint)
  12. code merged                                    (checkpoint)
-->

## Error Recovery Commands

`fail` and `reset-to` share semantics. Both clear the named step and every later step that is **not** tagged `preserve_on_reset: true` in [`connectus/workflow_state_config.yml`](workflow_state_config.yml). Today only `Params to Commands` carries that tag (per [`workflow_state_config.yml:72`](workflow_state_config.yml:72)); the two adjacent data columns `Params for test with default in code` and `Params to Capabilities` deliberately set `preserve_on_reset: false`. The CLI prints `Preserved (preserve_on_reset=true): [...]` listing what was kept.

**Explicit-target carve-out:** if the user names a preserved step EXPLICITLY as the target of `fail`/`reset-to`, that one step IS cleared (the user's intent wins). Later preserved steps in the same blast radius are still preserved. Example: with the 2026-05 schema, `fail "Auth Details"` keeps `Params to Commands`; `fail "Params to Commands"` clears `Params to Commands` itself (there are no later preserved data columns to keep).

`set-auth` and plain `reset` IGNORE `preserve_on_reset` — see the description of each.

### Fail a checkpoint (clears it and all subsequent non-preserved steps)

```bash
python3 connectus/workflow_state.py fail "<Integration ID>" "<checkpoint name>"
```

### Reset to a specific checkpoint (alias of fail)

```bash
python3 connectus/workflow_state.py reset-to "<Integration ID>" "<checkpoint name>"
```

### Reset all workflow columns (no preserve carve-out)

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

When analyzing an integration's authentication, use these classification values inside `Auth Details` `auth_types[].type`. Each maps to one of the five canonical UCP profile types (see §1.2.6 for the field shapes); `Passthrough` is the explicit "doesn't fit a canonical profile" catch-all.

| Auth Type | UCP Profile | Description |
|---|---|---|
| `OAuth2ClientCreds` | `oauth2_client_credentials` | OAuth 2.0 Client Credentials flow (`client_id` + `client_secret`) |
| `OAuth2JWT` | `oauth2_jwt_bearer` | OAuth 2.0 JWT Bearer flow (`subject_email` + `credentials_file`) |
| `APIKey` | `api_key` | Single static secret (header / query param / single-secret HMAC). Two-or-more keys → `Passthrough`. |
| `Plain` | `plain` | Single username + password pair (`username` + `password`) |
| `Passthrough` | n/a | OAuth2 Authorization Code (browser flow), Device Code, ROPC, Managed Identity, mTLS, dual-key API (Datadog, AWS, Akamai EdgeGrid, GitHub App), custom HMAC/signing, and anything else that doesn't cleanly fit one of the four profiles above. **When in doubt, prefer `Passthrough`.** |
| `NoneRequired` | n/a | No authentication required |



## Profile Relation Semantics (post-2026-05)

Profiles in `auth_types[]` are joined implicitly by **exclusive-OR**. There is no inter-profile AND, no OPTIONAL, no `config` expression key.

- `auth_types: []` → integration requires no authentication.
- `auth_types: [X]` → profile X is always selected.
- `auth_types: [X, Y, ...]` → the user picks exactly ONE of these profiles at configuration time.

AND-ed secrets within a single auth flow (e.g. an API key paired with a vendor-required client certificate) live inside ONE profile's `xsoar_param_map`, not as separate profiles. See §1.2.2a "Multi-secret auth flows" for the classification heuristic.

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
