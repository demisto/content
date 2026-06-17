---
name: connectus-migration
description: Use when migrating an XSOAR/XSIAM integration to ConnectUs / the unified-connectors platform. Triggers like 'migrate <integration>', 'work on <integration>', 'migrate connector <id>', 'what's next for me', 'continue my work', 'migrate the next 10 integrations assigned to Joey'
---

# ConnectUs Migration Skill

## QUICK START — happy path (single integration)

> **Topology / cwd (read first).** The idex shell cwd is the **PARENT** dir that contains `content/` and `unified-connectors-content/` as **siblings** (the runtime-parity Python lives under `content/connectus/...`). **All shell command paths in this skill are written relative to that parent**, so every `python3` invocation carries the `content/` prefix (e.g. `python3 content/connectus/workflow_state.py ...`). Run them as-written from the parent cwd — do **NOT** `cd` into `content/` first, or the `content/` prefix would resolve to a non-existent `content/content/...`.

One up-front read replaces several calls: `python3 content/connectus/workflow_state.py context "<id>"` returns all data columns + file paths + current step + auth-ignore set as one JSON. (`status "<id>" --format=json` is also available.)

| # | Step | Command | § |
|---|------|---------|---|
| 0 | Identify | `context "<id>"` (one call: state + files + auth-ignore set) | Step 0 |
| 1 | Assignee | `set-assignee "<id>" "<name>"` | §1 |
| 2 | Auth Details | `set-auth "<id>" '<json>'` (validate-and-apply in one step) | §2 |
| 3 | Collect Capabilities | `connectus_migration/capabilities_collector.py <yml> -o <path>` → `set-capabilities` | §3 |
| 4 | Params to Commands | run analyzer w/ `--integration-id` → `set-params-to-commands` | §4 |
| 5 | Param defaults | `set-param-defaults "<id>" '<json>'` (required-only) | §5 |
| 6 | UCP param-default review | `check_param_defaults.py --integration-id <id> --human` → present → fix → `markpass "UCP param-default review"` | §6 |
| 7 | Params to Capabilities | mapper → `set-params-to-capabilities` | §7 |
| 8 | Generated manifest | `manifest_generator.py <yml> <title=Connector ID> <Params-to-Capabilities raw> <Auth-Details raw>` → `set-connector-path "<id>" connectors/<slug Connector ID>` → `markpass "generated manifest"` (title comes from the `Connector ID` column so a connector's integrations share one folder) | §8 |
| 9 | Handler param coverage | `check_handler_param_coverage.py --integration-id <id> --json` → **fail-and-ask if `pass:false`** (resolve via IGNORED_PARAMS, fix-upstream, or `--force` override) → `markpass "handler param coverage"` | §9 |
| 10 | Validate manifest | `demisto-sdk validate` → `markpass "run manifest make validate"` | §10 |
| 11 | Param parity | `markpass "param parity test passes"` | §13 |
| 12 | Code reviewed | `markpass "code reviewed"` | §14 |
| 13 | Code merged | `markpass "code merged"` | §15 |
| 14 | Pre-commit/tests | `demisto-sdk pre-commit` → `markpass "precommit/validate/unit tests passed"` (only if RN produced or .py/.yml changed; else `markpass` directly) | §12 |

> **Step order note.** The live CSV workflow has **15 steps**, and `Collect Capabilities` is step **#3** — a hard prerequisite gate that the state machine enforces **before** `Params to Commands`. Do `set-capabilities` first or `set-params-to-commands` will be rejected with `current step is #3 'Collect Capabilities'`. The `UCP param-default review` checkpoint (Step 6) sits right after `Params for test with default in code` and before `Params to Capabilities`. As of 2026-06, the `precommit/validate/unit tests passed` (Step 14) and `Release Notes` (Step 15) steps were moved to the **end** of the workflow — they now run *after* `param parity test passes` (Step 11), `code reviewed` (Step 12), and `code merged` (Step 13), with precommit before Release Notes.

**Pause for user approval ONLY on the 4 JSON-write setters** (`set-auth`, `set-params-to-commands`, `set-param-defaults`, `set-params-to-capabilities`). Everything else (reads, `markpass`, `fail`, `set-capabilities`, analyzer/validate/pre-commit runs) runs straight through. `set-capabilities` is deterministically generated from YML fetch flags by `connectus_migration/capabilities_collector.py`, so it is a run-through (no pause). Setter output already echoes `Current step:` — do NOT re-run `status` to confirm.

**Need depth?** Auth research/examples → [`auth-examples.md`](auth-examples.md) · Auth gate blocked → [`auth-parity-troubleshooting.md`](auth-parity-troubleshooting.md) · Per-command params → [`analyzer-manual.md`](analyzer-manual.md) · JSON shapes → [`column-schemas.md`](column-schemas.md).

## Overview

> _The workflow has 15 steps. The per-profile `verify_connection_skip` boolean inside each `auth_types[]` entry of `Auth Details` is the connection-test-skip signal._

This skill guides the migration of XSOAR/XSIAM integrations to the ConnectUs platform. Each integration follows a workflow tracked in [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv) via the [`connectus/workflow_state.py`](workflow_state.py) CLI tool.

The CSV has two kinds of columns:

- **Identity / metadata** (3): `Integration ID`, `Integration File Path`, `Connector ID`.
- **Workflow columns** (12, managed by the state machine — CSV total is 15):
  - **Workflow data columns** (free-text / JSON; set with dedicated commands): `assignee`, `Auth Details`, `Params to Commands`, `Params for test with default in code`, `Params to Capabilities`, `Release Notes` (6).
  - **Workflow flag**: _(none)_
  - **Workflow checkpoints** (6, sequential ✅): `generated manifest`, `run manifest make validate`, `precommit/validate/unit tests passed`, `param parity test passes`, `code reviewed`, `code merged`.

> _**ALWAYS-INTERPOLATE GATE (2026-06-09):** the auth-parity gate inside `set-auth` no longer parity-tests the candidate `Auth Details`. Instead, `set-auth` **forces `interpolated: true` onto every `auth_types[]` entry** before the cell is committed and then short-circuits the parity test (every connection is interpolated by construction, so there is nothing to verify — the `ERROR_ALL_INTERPOLATED` clean structural skip). The write therefore **always succeeds** once the JSON passes schema validation, and the persisted cell is **guaranteed** to carry `interpolated: true` on every profile. You do **not** need to mark profiles `interpolated: true` yourself — `set-auth` does it for you. See [§1.12 Auth-parity gate inside `set-auth`](#112-auth-parity-gate-inside-set-auth)._

Authentication classification is the **prerequisite for everything**: you must set `Auth Details` with `set-auth` before the workflow can meaningfully begin (setting it also resets the workflow). The Validate Auth Classification procedure below is run before invoking `set-auth`.

## Entry Points / Trigger Phrases

The skill supports three top-level invocation styles. Pick the matching flow based on what the user said.

| User phrase (examples) | Action |
|---|---|
| "migrate `<integration id>`" / "work on `<integration id>`" / "status of `<integration id>`" | Single-integration flow — jump straight to [Step 0: Identify the Integration](#step-0-identify-the-integration-pre-flight) and walk the existing 15-step procedure for that one integration. |
| "migrate everything assigned to me" / "what's next for me" / "continue my work" / "keep going" | [Assignee batch flow](#assignee-batch-flow) — enumerate the user's in-progress + assigned integrations and walk them one by one. |
| "migrate connector `<connector_id>`" / "work on connector `<connector_id>`" / "do the whole `<connector>` connector" | [Connector batch flow](#connector-batch-flow) — enumerate that connector's integrations and walk them one by one (with ownership disambiguation up front). |

Both batch flows are an **outer loop** wrapped around the existing per-integration procedure. They never replace or re-implement the 15-step workflow — they pick *which* integration to run that workflow on next.

> **CLI column references accept numbers too.** Every CLI verb in this
> skill that takes a column name (`show-step`, `markpass`, `skip`, `fail`,
> `reset-to`) also accepts a **1-based CSV column number** (1..18).
> Identity columns (#1-#3) are addressable only by read-only `show-step`;
> write verbs reject them. Example:
> `python3 content/connectus/workflow_state.py show-step CrowdstrikeFalcon 5`
> resolves to `Auth Details`.

## Assignee batch flow

Use when the user says something like "migrate everything assigned to me" / "continue my work" / "what's next for me".

1. **Resolve the current user.** Read `git config user.name` (the script uses the same source). If empty, ask the user for their name and stop.
2. **Enumerate candidates.** Run:

   ```bash
   python3 content/connectus/workflow_state.py next --mine
   ```

   Or from Python: `from workflow_state import integrations_for_assignee` and call `integrations_for_assignee("<name>")`. Each result dict carries `integration_id`, `connector_id`, `assignee`, `current_step`, `current_step_index`, `completed_steps`, `all_complete`, `has_progress`.
3. **Empty result?** Tell the user there is nothing assigned + in-progress for them, and offer two follow-ups:
   - bulk-assign a connector via `set-assignee-by-connector <connector_id> "<name>"` (suggest running `list-connectors` first to pick one), or
   - browse via `python3 content/connectus/workflow_state.py dashboard`.
   Then stop.
4. **Multiple results?** Before starting, present them as a numbered list with `Integration ID`, `Connector ID`, current step, and `completed_steps / 15`. Apply the [Order-of-work disambiguation](#order-of-work-disambiguation) heuristic. The order is "obvious" only when:
   - There is exactly one integration, OR
   - All integrations belong to the same connector AND exactly one is clearly furthest along (highest `current_step_index` with `has_progress: true`) — proceed with that one first and confirm.

   Otherwise, **ask the user** for the work order. Suggest a sensible default ("furthest-along first" or "by connector then alphabetical") but let them override.
5. **Walk one integration at a time.** For each integration in the chosen order:
   - Follow the existing per-integration migration procedure starting at [Step 0: Identify the Integration](#step-0-identify-the-integration-pre-flight). Do **not** duplicate the 15 steps here — the rest of this skill already documents them.
   - Between integrations, print a short progress recap (`X/N done in this batch — next: <integration id>`) and confirm before moving on, **unless** the user has explicitly said "do them all without asking" / "no confirmations" / equivalent.
6. **Mid-loop "what's next" check.** Re-run `python3 content/connectus/workflow_state.py next --mine` after finishing each integration so the queue reflects any newly-assigned or just-completed work.
7. **Finish.** When the queue is empty, summarize what was done and ask whether to start a new batch (e.g., a connector batch, or assigning more work).

## Connector batch flow

Use when the user says something like "migrate connector `<connector_id>`" / "do the whole `<connector>` connector".

1. **Validate the connector id.** Run:

   ```bash
   python3 content/connectus/workflow_state.py list-by-connector "<connector_id>"
   ```

   Or programmatically: `from workflow_state import list_integrations_by_connector` → `list_integrations_by_connector("<connector_id>")`. If the result is empty, suggest `python3 content/connectus/workflow_state.py list-connectors` to discover valid ids and stop.
2. **Inspect ownership** on the matched rows (look at the `assignee` field on each dict). One of three cases applies:
   - **All rows assigned to the current git user** → proceed straight to step 4.
   - **All rows unassigned** → offer to bulk-assign to the current user. Confirm before running:

     ```bash
     python3 content/connectus/workflow_state.py set-assignee-by-connector "<connector_id>" "<git user name>"
     ```

     Then proceed.
   - **Mixed: some rows owned by other people** → list who owns what (one line per integration: `<integration id>  → <assignee or "unassigned">`) and ask the user which option they want:
     1. Take over the whole connector (`set-assignee-by-connector <connector_id> "<name>"` — note this never wipes migration progress).
     2. Only work on the rows in this connector that are already assigned to them.
     3. Abort and pick a different connector / scope.
3. **Settle ownership before any per-integration work.** Do not start migrating rows you don't own — re-confirm or re-assign first.
4. **Walk one integration at a time.** Apply the [Order-of-work disambiguation](#order-of-work-disambiguation) heuristic to pick the order, ask the user if it isn't obvious, then for each integration follow the existing per-integration procedure starting at [Step 0: Identify the Integration](#step-0-identify-the-integration-pre-flight).
5. **Mid-loop "what's next in this batch" check.** After finishing each integration, run:

   ```bash
   python3 content/connectus/workflow_state.py next --connector "<connector_id>" --mine
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
4. **Use `execute_command`** to run all `workflow_state.py` commands from the **idex parent cwd** (e.g `/Users/<username>/dev/connectus-content`). That parent dir contains `content/` and `unified-connectors-content/` as siblings, so every command path in this skill is written relative to that parent — hence the `content/` prefix on `python3 content/connectus/...`. Do **NOT** prepend a `cd` into the content repo; the `content/` prefix already resolves correctly from the parent cwd.
5. **Use `set-auth` to update Auth Details.** When correcting auth classifications, use `python3 content/connectus/workflow_state.py set-auth "<Integration ID>" '<json>'`. This validates the JSON schema and automatically resets the workflow back to the first checkpoint (`generated manifest`).
6. If a checkpoint does not pass, it might be because a previous step was not done well — go back to it via `fail` or `reset-to`. Both verbs **preserve** `Params to Commands` only (it is the sole column carrying `preserve_on_reset: true` in [`connectus/workflow_state_config.yml`](workflow_state_config.yml)) so per-command param research survives a failed checkpoint. The CLI prints `Preserved (preserve_on_reset=true): [...]` listing what was kept; the api response includes the same names in `result["preserved"]`. **`set-auth` is NOT covered by this carve-out** — auth changes invalidate downstream artifacts, so `set-auth` continues to wipe `Params to Commands` by design (see Step 2 below). Plain `reset` (the "wipe the whole row" verb) also wipes it; preservation is for `reset-to`/`fail` only.
7. Try to be efficient in what needs input from the user. If you have an option to read files instead of grep, or batch commands to the cli, it is better.
8. **NEVER use the Neo4j graph (`idex_graph_query`) or `demisto-sdk graph` to resolve, search for, or look up integrations in the ConnectUs migration workflow.** The graph is unrelated to this workflow and is frequently not running. The ONLY source of truth for resolving an integration (its ID, file path, connector, and workflow state) is the [`connectus/workflow_state.py`](workflow_state.py) CLI against [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv). To find an integration by a partial/informal name (e.g. "aha"), run `python3 content/connectus/workflow_state.py list` and match against the result, then use `context "<Integration ID>"`. Do NOT fall back to graph queries, `find`/`ls`/`grep` over the repo, or any other discovery mechanism for this purpose.

### Environment Configuration (unified `.env`)

> **One `.env` at the repo root.** All connectus/UCP tooling reads from a single
> `.env` file at the **content-repo root** (`/<content-repo>/.env`) — never a
> per-tool `.env`. It is created once from the root template:
>
> ```bash
> cp .env.example .env   # run from the content-repo root, then fill it in
> ```
>
> The root [`.env.example`](../.env.example) groups the variables by stage:
> **UCP Connection / Tenant** (`DEMISTO_BASE_URL`, `DEMISTO_API_KEY`,
> `XSIAM_AUTH_ID`, `TENANT_ID`), **ConnectUs Repo** (`CONNECTUS_REPO_DIR`,
> `CONNECTUS_BRANCH` — shared by param-parity, generate-manifest, and validate),
> and per-stage tuning for param-parity / generate-manifest. Real secrets must
> never be committed.
>
> **Rule:** the `.env` is loaded by the shared module
> [`connectus/env_loader.py`](env_loader.py) via `load_env()`, which resolves the
> repo root from `__file__` and loads `<repo_root>/.env` by an explicit path
> (idempotent, import-safe). Every entry point — param-parity scripts,
> [`run_pre_manifest_steps.py`](connectus_migration/run_pre_manifest_steps.py)
> / [`manifest_generator.py`](connectus_migration/manifest_generator.py), and the
> validate gate in [`workflow_state/gates.py`](workflow_state/gates.py) — calls
> `load_env()`. Do **NOT** call `dotenv.load_dotenv()` directly anywhere.

## Cross-cutting Decisions

These four decisions are referenced throughout this document by name
(e.g. "per the **Hints policy**", "per **cross-cutting #3**"). Tracking
them in one place avoids re-litigating the same questions in every
section.

1. **Hints policy.** Scripts emit accurate, factual descriptions of what
   went wrong. Hints (telling the operator what to *do*) are only
   included when the prescription is **unambiguous** (one obvious right
   answer, no judgment call). When multiple valid paths exist, the
   diagnostic describes accurately and points to the relevant skill
   section; prescription lives in the skill, not in the tool. Examples:
   - **Unambiguous → hint OK.** "use `--static-only` for non-Python
     integrations"; "mark `interpolated: true`" for the ApiModule case.
   - **Multiple valid paths → describe + point to skill.** "UCP-strip
     crash; see skill §1.12 for the two fix paths" (`_apply_ucp_plain`
     override vs. `is_ucp_enabled()` gating).

2. **XOR-only auth relations.** The auth-profile relation model is
   exclusive-OR only. There is no `and` relation, no `any` / concurrent
   relation. Integrations with multiple distinct credentials (e.g.
   AbuseIPDB's primary + Hunting key) are classified as `Passthrough`
   — the secrets-bag bucket. The parity gate's coverage of
   `Passthrough` is intentionally reduced; this is documented as
   expected, not a gap. Detection of the multi-secret pattern emits the
   structural-skip code `MULTI_SECRET_PASSTHROUGH`. See
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
| 1 | `set-auth` | `Auth Details` | The full JSON payload; a per-`auth_types[]`-entry evidence table that MUST include, for each profile, the **XSOAR fields** (the `xsoar_param_map` keys) it consumes alongside the role each field plays, the YML param + code site that justifies the type, and any `verify_connection_skip` / `interpolated` flags. Any XSOAR field that appears in more than one profile MUST be **highlighted** (🔶 marker by default) and called out in a mandatory overlap note beneath the table (see [§1.2](#12-researching-auth-details--the-four-sources-of-truth) for the table format and highlight conventions); the `other_connection` list. Note that this call resets the workflow + wipes the downstream Params\* columns. `set-auth` forces `interpolated: true` onto every `auth_types[]` entry and short-circuits the parity test, so the write **always succeeds once the JSON passes schema validation** — there is no parity diff to resolve (see [§1.12 Auth-parity gate inside `set-auth`](#112-auth-parity-gate-inside-set-auth)). |
| 2 | `set-params-to-commands` | `Params to Commands` | The full JSON payload; the analyzer's per-command findings vs. the final list (call out any commands where you overrode the analyzer); the auth-ignore set pulled from `auth-params`. **Include a per-param scores table** (max `rollup_confidence`, top source, and your decision) so the user can see what the analyzer proved vs. what you elevated by source review — explicitly flag the "investigated myself" rows (analyzer score below your inclusion bar) and why. Get scores via a throwaway `--with-diagnostics` run. See [analyzer-manual §12.4](analyzer-manual.md) for the table format and §11/§12 for arg-seeding + the params-access spy (the `dynamic_access` 0.9 source). |
| 3 | `set-param-defaults` | `Params for test with default in code` | The full JSON payload AND, for each entry, a one-line attribution: **(a)** *param `foo`: YML `defaultvalue` is `<yml default>` — use as code fallback? confirm / edit / reject (move to `other_connection`).* **(b)** *param `foo`: NO YML default; proposed default `<value>` — confirm / edit / reject (move to `other_connection`).* **(c)** *param `foo`: code already supplies fallback `<existing default>`; recorded for the cell, no code edit.* Branches (a) AND (b) are per-param sub-confirmations that pause the workflow (within the same outer pause-before-`set-param-defaults` step) — the YML default in branch (a) is NEVER accepted silently. The skill MUST collect all branch-(a)/(b) confirmations before applying any `.py` edits, AND before calling `set-param-defaults`. If a branch-(a)/(b) param is **rejected**, drop it from the JSON, skip its code edit, add it to `other_connection`, and re-apply via `set-auth` first (note: `set-auth` resets the workflow — see Step 5 "Rejecting a default"). |
| 4 | `set-params-to-capabilities` | `Params to Capabilities` | The full JSON payload from the mapping helper; any `MANUAL_COMMAND_TO_CAPABILITY_JSON` overrides applied and why. |

### Final-summary confirmation (end of conversion)

After the last checkpoint of an integration's conversion is reached (or
whenever the user signals the conversion is "done"), the skill MUST close
with a single confirmation message that **presents the final, committed
JSON of every workflow-data column it wrote** for that integration, so the
user can review the complete result in one place. Include, verbatim (as
fenced ```json``` blocks, one per column that was set):

- `Auth Details`
- `Params to Commands`
- `Params for test with default in code` (omit if empty/skipped — say so)
- `Params to Capabilities`
- `Release Notes` (if set)

Read these back from the CSV via `context "<id>"` (its `data_columns`
object already carries every one) rather than reconstructing them from
memory, so what you show is exactly what was persisted. End the message by
asking the user to confirm the final result looks correct (yes / edit /
revise). This is in addition to — not a replacement for — the four
per-column pause-and-confirm prompts above.

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
- [`connectus/column-schemas.md`](column-schemas.md) — JSON shapes for `Auth Details`, `Params to Commands`, `Params for test with default in code`, and `Params to Capabilities`. Read when you need a column's exact JSON shape.
- [`connectus/analyzer-manual.md`](analyzer-manual.md) — full per-command analyzer reference (Step 4). Read when interpreting analyzer output / flags / decision tree.
- [`connectus/auth-parity-troubleshooting.md`](auth-parity-troubleshooting.md) — read when the auth-parity gate BLOCKS (UCP overrides, gating, `--seed-param`, boto3/feed cases).
- [`connectus/auth-examples.md`](auth-examples.md) — worked auth examples, grep catalog, misclassification table, MS/Azure handling, profile-field reference. Read when researching an auth classification.
- [`connectus/workflow_state.py`](workflow_state.py) — The state machine CLI (source of truth for workflow). Provides the `files <integration_id>` subcommand and the [`get_integration_files()`](workflow_state.py) helper used to resolve every source file for an integration (see [§1.1](#11-locate-integration-files)).
- [`connectus/connectus-migration-pipeline.csv`](connectus-migration-pipeline.csv) — The tracking spreadsheet (DO NOT EDIT DIRECTLY).

## Step 0: Identify the Integration (pre-flight)

When the user asks to migrate an integration, first identify it. **The primary recommendation is one `context` call** — it returns state + file paths + Auth Details + Params cells + the auth-ignore set in one shot, replacing separate `status` + `show-step` + `files` round-trips:

> **Lookup source of truth.** Resolve the integration ONLY via the `workflow_state.py` CLI (`list` to find a partial/informal name, then `context "<id>"`). NEVER use the Neo4j graph (`idex_graph_query`) or `demisto-sdk graph`, and never `find`/`ls`/`grep` the repo to locate it — see Critical Rule 8.

```bash
# One call: state + file paths + data columns + auth-ignore set as one JSON
python3 content/connectus/workflow_state.py context "<Integration ID>"
```

The `context` JSON has these top-level keys (read from these directly instead of issuing follow-up calls):

```json
{
  "integration_id": "...", "connector_id": "...", "assignee": "...",
  "file_paths": {"yml": "...", "code": "...", "description": "...", "readme": "...", "test": "..."},
  "data_columns": {
    "Auth Details": <json|null>, "Params to Commands": <json|null>,
    "Params for test with default in code": <json|null>,
    "Params to Capabilities": <json|null>, "Release Notes": <json|null>
  },
  "auth_ignore_params": ["..."],
  "current_step": "...", "current_step_index": <int>,
  "completed_steps": <int>, "total_steps": <int>, "all_complete": <bool>
}
```

(On a stale/missing file path, `file_paths` is `null` and a `file_paths_error` key carries the message; the rest still emits.)

```bash
# Alternatives (still available):
python3 content/connectus/workflow_state.py list                       # list all integration IDs
python3 content/connectus/workflow_state.py status "<Integration ID>"  # human-readable status
python3 content/connectus/workflow_state.py files "<Integration ID>"   # source-file paths only
```

The `context` (and `status`) output shows:

- **Assignee** — who is working on it
- **File Path** — path to the integration's source files (data column). `context` returns every related file path under `file_paths` (YML + code + description + README + test) — no separate `files` call needed (see [§1.1](#11-locate-integration-files)).
- **Connector ID** — the ConnectUs connector this integration belongs to (data column)
- **Auth Details** — authentication detail JSON (`auth_types[]` + required `other_connection` — may be an empty list `[]`, but the key MUST be present or the parser raises; profile relations are implicit — see [§1.2.3](#123-profile-relations-are-implicit-no-config-expression))
- **Params to Commands** — JSON mapping of commands → param ids
- **Workflow Checkpoints** — which checkpoints are done, which remain
- **Current step** — what to work on next

If the integration has no assignee, set one:

```bash
python3 content/connectus/workflow_state.py set-assignee "<Integration ID>" "<Name>"
```

## Workflow Steps

### Step 2: Classify Auth (Auth Details) (prerequisite — not a checkpoint)

**Before starting any migration work**, the skill must actively read the integration's YML and Python source, derive the correct `Auth Details` JSON from scratch, and write it via `set-auth`. Do **not** trust any pre-existing value in the CSV — past automated classification of 148 integrations had a **48% error rate (71/148 wrong)**. Always re-derive from the source files.

`Auth Details` is a workflow data column (not a checkpoint), so there is no `markpass` for it; calling `set-auth` is what registers the classification AND resets the workflow back to `generated manifest`.

#### Procedure (do every step in order)

1. ☐ Resolve all integration source-file paths via `python3 content/connectus/workflow_state.py files "<Integration ID>"` (or [`get_integration_files()`](workflow_state.py) programmatically). Do **NOT** search the repo manually with `find` / `ls` / `grep`. See [1.1](#11-locate-integration-files) and [1.2](#12-researching-auth-details--the-four-sources-of-truth).
2. ☐ Walk the four sources of truth in order — see [1.2](#12-researching-auth-details--the-four-sources-of-truth)
3. ☐ Extract every auth-related param from the YML `configuration` section — see [1.3](#13-yml-analysis-procedure)
4. ☐ Read the Python code to determine the actual auth mechanism(s) used at runtime — see [1.4](#14-python-code-analysis--specific-patterns)
5. ☐ Cross-reference each YML param with where/how it is consumed in code — see [1.5](#15-cross-reference-yml-params-with-code-usage)
6. ☐ Classify each connection via the [decision table](#121-classification-decision-table); build each entry per [1.2.2](#122-building-each-auth_types-entry); note that profile relations are implicit per [1.2.3](#123-profile-relations-are-implicit-no-config-expression) (no `config` expression to compose). **Before settling on more than one `auth_types[]` entry, run the XOR-vs-AND gate (§1.2.2a): 2+ entries means the user picks EXACTLY ONE. If the credential sets are actually used together/additively (built into one `Client` at once, or one set required + others optional add-ons), collapse them into a SINGLE `Passthrough` profile instead — see [§1.2.2a](#122a-multi-secret-auth-flows).**
7. ☐ Extract the **connection-adjacent** YML params (URL, proxy, insecure, port, host, region, …) into the sorted `other_connection` list — see [1.2.5](#125-building-the-other_connection-list)
8. ☐ Sanity-check against [Known Misclassification Patterns](#16-known-misclassification-patterns) and the [Decision Tree](#19-decision-tree-for-auth-type)
9. ☐ Run the [Pre-flight self-check](#111-pre-flight-self-check)
10. ☐ Present the evidence table to the user and get approval.
11. ☐ Apply via `set-auth` once the user approves (this validates the JSON schema, forces `interpolated: true` onto every entry, and on success resets the workflow). The write always succeeds once the JSON passes schema validation — no parity check is performed. See [1.10](#110-applying-corrections).

`set-auth`'s own output echoes the new `Current step:` on success — do **not** re-run `status` to confirm.

The current CSV value, if any, is informational only — show it to the user for context but derive the new value entirely from the source code:

```bash
python3 content/connectus/workflow_state.py show-step "<Integration ID>" "Auth Details"
```

---

#### 1.1 Locate Integration Files

**The canonical way to get an integration's source files is the `files` subcommand of [`workflow_state.py`](workflow_state.py).** Do **NOT** manually `find` / `ls` / `grep` the repo for these files — the `Integration File Path` column in the CSV is populated for all 609 integrations, and `files` resolves every sibling (YML, code, description, README, test) from it.

```bash
python3 content/connectus/workflow_state.py files "<Integration ID>"
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
| `paths` | `--format=paths` | Piping into other tools. Emits one path per line in canonical order (`yml`, `code`, `description`, `readme`, `test`) — ideal for `xargs` / `cat` pipelines, e.g. `python3 content/connectus/workflow_state.py files "<Integration ID>" --format=paths \| xargs -I{} cat {}`. |
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

Before you can write the JSON for `set-auth`, you must derive it from the integration pack itself — never guess from the param list alone. The shape you are building is documented in [`connectus/column-schemas.md`](column-schemas.md:16) and is enforced by [`validate_auth_details()`](auth_config_parser/validator.py:24) (called via the [`workflow_state.validators.validate_auth_detail()`](workflow_state/validators.py:25) wrapper). The validator requires top-level keys `auth_types` (list) and `other_connection` (list, required); unknown top-level keys are silently ignored. Profile relations are implicit from `len(auth_types)` (see [§1.2.3](#123-profile-relations-are-implicit-no-config-expression)). Wrong input is rejected at the CLI — better to catch it at research time.

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

Before you actually use the `set_auth` command, present the evidence to the user for why you decided on the auth types and config structure in a concise and clear way. Present it as a **table with one row per `auth_types[]` profile**, and the table MUST include a column listing the **XSOAR fields** that profile consumes — i.e. the `xsoar_param_map` keys (the dotted-leaf YML field paths such as `credentials_enc_key.password`, `private_key`) and the role each maps to. The recommended columns are:

| Profile (`name`) | Type | XSOAR fields (`xsoar_param_map` → role) | Evidence (YML param + code site) | Flags |
|---|---|---|---|---|

where:
- **XSOAR fields** lists every `xsoar_param_map` key for that profile and the role value it maps to (e.g. `credentials_enc_key.password → client_secret`, `private_key → private_key`). This makes it explicit to the user exactly which XSOAR fields feed each profile so they can spot a misplaced or missing field before the cell is committed.
- **Evidence** cites the YML param id(s) and the code line(s) that justify the classification.
- **Flags** notes `interpolated` / `verify_connection_skip` when set.

Also show the `other_connection` list separately.

##### Highlighting overlapping XSOAR fields

A single XSOAR field path MAY legitimately appear in more than one profile's `xsoar_param_map` (e.g. one `credentials.password` backing both a `Plain` profile and a `Passthrough` profile). When this happens it MUST be **highlighted** in the evidence table so the user can immediately see which fields are shared across profiles and confirm the overlap is intentional rather than a copy-paste error.

Because the evidence table is printed to the user as terminal-rendered CommonMark markdown, **true per-cell background/foreground color is not reliably available** — markdown tables have no per-cell color and raw ANSI escapes break table layout in most renderers. Use one of the following highlight conventions, in this order of preference:

1. **Emoji marker + overlap note (default — portable, survives copy/paste).** Prefix every overlapping field with 🔶 inside the table cell, and add a one-line note directly beneath the table listing each overlapping field and the profiles it appears in. Example:
   - Cell: `🔶 credentials.password → client_secret`
   - Note: `🔶 Overlapping fields: credentials.password appears in profiles [plain, client_creds] — intentional (same secret backs both flows).`
2. **Bold + ⚠️ marker (inline alternative).** Render the shared field as `**credentials.password** ⚠️ → client_secret` instead of the emoji prefix. Still add the overlap note beneath the table.
3. **ANSI color codes (color-capable terminals only).** If — and only if — you know the output target renders ANSI, you MAY wrap the overlapping field token in an ANSI color sequence (e.g. yellow: `\033[33m…\033[0m`). Do NOT use this inside a markdown table (it corrupts the column layout); reserve it for a plain (non-table) bullet-list rendering of the evidence. Always pair it with the same plain-text overlap note so the information survives if the color is stripped.

Whichever convention you use, the **overlap note beneath the table is mandatory** — the color/marker is a visual aid, but the explicit list of `<field> appears in profiles [<a>, <b>]` is the source of truth the user confirms against. If NO field overlaps between profiles, state that explicitly ("No XSOAR fields overlap between profiles.") so the absence of highlighting is unambiguous rather than an oversight.
---

#### 1.2.1 Classification decision table

Map "what you saw in the source" → "auth-type enum value" (the values are the members of the [`AuthType`](auth_config_parser/types.py:11) enum — import it directly with `from auth_config_parser.types import AuthType` and use `[e.value for e in AuthType]` when you need the string list):

> **EVERY classified profile is `interpolated: true` — including `APIKey` and `Plain`.** The "Use type" column below picks the `type` ONLY; the `interpolated: true` flag is NOT optional and is NOT type-specific. Whatever type you pick from this table, the profile you author MUST carry `"interpolated": true`. There is NO such thing as a non-interpolated profile (ALWAYS-INTERPOLATE GATE, §1.12). Never suggest, classify, or output a profile of ANY type without `interpolated: true`.

| You see... | Use type |
|---|---|
| `Authorization: Bearer <key>` from a single param, no token exchange | `APIKey` |
| `X-API-Key: <key>` / `apikey=<key>` query param / similar static header | `APIKey` |
| `Authorization: Basic <user>:<pass>` from a credentials (type `9`) or two flat params | `Plain` |
| Username + password posted to a login endpoint that returns a session cookie | `Plain` |
| OAuth2 with user-driven `code` + `redirect_uri` flow | `Passthrough` |
| OAuth2 with `client_id` + `client_secret` (no user code, `grant_type=client_credentials`) | `Passthrough` |
| OAuth2 with a signed JWT assertion (private key + claims, `grant_type=jwt-bearer`) | `Passthrough` |
| OAuth2 ROPC (`grant_type=password`), Device Code, Managed Identity, mTLS-only, HMAC signing, custom challenge/response | `Passthrough` |
| Two or more API keys / secrets used together (regardless of how they're issued — Datadog `api_key`+`application_key`, AWS access_key+secret_key, Akamai EdgeGrid's three tokens, etc.) | `Passthrough` |
| Any auth flow that doesn't cleanly fit one of the five canonical profile types in §1.2.6 | `Passthrough` |
| No credentials at all (public API, or a feed that just hits a URL) | `NoneRequired` |

> **`Passthrough` is the "doesn't fit a profile" catch-all — and now the home for ALL OAuth2 flows.** The classifier emits exactly four `Auth Details` types: `APIKey`, `Plain`, `Passthrough`, and `NoneRequired`. Every OAuth2 flow — client-credentials, JWT-bearer, Authorization Code's browser flow, ROPC, Device Code — is now classified as `Passthrough` (with `interpolated: true`), as are multi-key packages, Managed Identity, custom HMAC schemes, mTLS, and certificate-based flows. The OAuth2-specific UCP profile shapes (`oauth2_client_credentials`, `oauth2_jwt_bearer`) still exist in the manifest layer, but the skill no longer instructs you to OUTPUT `OAuth2ClientCreds` / `OAuth2JWT` as classification values. When in doubt, prefer `Passthrough` — it is the safe, explicit "we couldn't classify this into a known profile" signal.

---

#### 1.2.2 Building each `auth_types[]` entry

Each `auth_types[]` entry describes **one complete UCP connection type** — one full auth flow, not one XSOAR param. See [`column-schemas.md`](column-schemas.md:34) for the authoritative shape. The rules you'll be applying as you build entries:

- **`type`** — the enum value chosen via the table above.
- **`name`** — a human-readable label that **best describes the kind of authentication this profile represents**, since it surfaces directly as the connection profile's title (`metadata.title`, see §1.6 manifest generation). Choose the name from what the credentials actually are, NOT from the `type` enum or any YML param id:
  - `APIKey` profile → `"API Key"`.
  - `Plain` profile (username + password) → `"Basic Auth"`.
  - Any other recognizable scheme → name it for what it is (e.g. `"OAuth"`, `"Client Credentials"`, `"JWT Bearer"`, `"AWS Signature"`, `"Personal Access Token"`).
  - **NEVER name a profile `"Passthrough"`.** `Passthrough` is an internal `type` enum value, not a user-facing auth name — do not leak it into `name`.
  - **When the auth scheme is totally unclear**, fall back to `"<Integration name> authentication"` (e.g. `"Acme Cloud authentication"`).
  Must be unique within the row — if a single integration has two profiles that would map to the same label, qualify each so they stay distinct (e.g. `"API Key"` vs `"Basic Auth"`, or `"OAuth (read)"` vs `"OAuth (write)"`).
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
  | `Passthrough` | any non-empty string (enum **deliberately undefined for now** — typical illustrative values: `"client_id"`, `"client_secret"`, `"access_token"`, `"credentials_file"`, `"subject_email"`) |
  | `NoneRequired` | n/a — no entry in `auth_types[]` at all |

  The validator enforces the APIKey and Plain constraints strictly; `Passthrough` values are only checked for "non-empty string".

  > **Enum.** The only values you may OUTPUT in an `Auth Details` classification are `APIKey`, `Plain`, `Passthrough`, and `NoneRequired`. (OAuth2 flows classify as Passthrough — see §1.2.)
- **Multi-secret auth flows: extras go in the SAME profile (see §1.2.2a).** Every entry is one self-contained, mutually-exclusive profile. If an auth flow consumes more than one XSOAR field-path, they all go in the **same** entry's `xsoar_param_map` — never split across multiple entries (because the only inter-profile relation is exclusive-OR, not AND). When the combined shape doesn't fit a canonical profile (no dominant canonical role; co-equal multi-secret packages like Datadog/AWS/Akamai/GitHub App), use `Passthrough`. When one canonical role dominates and the rest are "extras" (e.g. APIKey + a vendor cert), keep the canonical type and add the extras to the same map.
- **`interpolated`** (optional in the payload, but **always `true` in the persisted cell**) — **ALWAYS-INTERPOLATE GATE (2026-06-09): EVERY `auth_types[]` entry is interpolated, regardless of `type`.** `set-auth` forces `interpolated: true` onto every entry before committing (see [§1.12](#112-auth-parity-gate-inside-set-auth)), so **do NOT suggest, classify, or hand-author a non-interpolated profile** — there is no longer any such thing as a non-interpolated `Plain` or `APIKey` profile. You may omit the flag in the payload you submit (the gate sets it for you) or set it `true` explicitly, but you must **never** emit `interpolated: false`. `xsoar_param_map` is still required and non-empty on every entry — the role declarations are still needed even though the value is templated at runtime.

  > **`interpolated: true` is a documented fallback on ANY profile type** (cross-cutting decision #3). Operators may set it on `Plain` and `APIKey` profiles too, as the escape valve when the parity gate cannot verify the integration cleanly. This is **not** a bypass — it's the documented escape path for these classes of failures:
  >
  > - **ApiModule-using integrations.** When the parity gate emits `APIMODULE_INTEGRATION_CANNOT_VERIFY`, the gate cannot inspect transitive `BaseClient` use through e.g. `MicrosoftApiModule` / `OktaApiModule`. Mark the profile `interpolated: true` and move on.
  > - **Custom-header `APIKey` integrations without an override.** When the gate emits `WRONG_LOCATION` because the integration uses `X-API-Key` instead of `Authorization: Bearer`, the canonical fix is a `_apply_ucp_api_key()` override on the `Client` (see §1.12). When you don't want to write the override now, mark the profile `interpolated: true`.
  > - **Plain auth with unconditional `params["credentials"]["identifier"]` reads.** When the gate emits `UCP_STRIP_CRASHED_UNCONDITIONAL_READ`, the canonical fixes are a `_apply_ucp_plain` override or `is_ucp_enabled()` gating (see §1.12). Marking the profile `interpolated: true` is the documented alternative when the integration's runtime cannot be touched.
  >
  > Document the reason in the commit notes ("marked interpolated: true because <reason>") so reviewers can verify the fallback was justified.
- **`verify_connection_skip`** (optional, defaults to `false`) — set to `true` when this profile's `test-module` code path manually raises an exception (`raise DemistoException(...)` / `return_error(...)`) instead of reaching an actual HTTP call. Most commonly OAuth Authorization Code / Device Code / ROPC flows where the user must first run an out-of-band `!auth-start`-style command before the connection-test button can succeed. Per-profile: a multi-profile (exclusive-OR) row may set it `true` on one profile and leave it default on another. Must be a JSON boolean — string `"true"`/`"false"` and int `0`/`1` are rejected.
- **Sort order** — entries are sorted by `(type, name)` ascending. The validator enforces this — `set-auth` will reject unsorted input. Map keys, by contrast, are an unordered dict and have no sort requirement.

---

#### 1.2.2a Multi-secret auth flows

Every entry in `auth_types[]` is **one self-contained, mutually-exclusive profile**. The only inter-profile relation is exclusive-OR (implicit when `len(auth_types) >= 2`). AND-ed secrets within a single auth flow live inside **one profile's** `xsoar_param_map` — never as separate profiles.

> **STOP — ask this BEFORE you create a second `auth_types[]` entry.** When an integration has more than one credential set, the most common (and silent) mistake is to make one entry per credential set. That tells the UCP runtime **"pick exactly one"** (exclusive-OR), which is only correct if the sets are genuine *alternatives*. Ask:
>
> **"Are these credential sets ALTERNATIVES (user picks one), or are they used TOGETHER?"**
>
> Answer it from the source code, not the YML `required` flags:
> - **ALTERNATIVES (XOR)** → the code branches: it reads set A *or* set B for the same purpose; configuring both is meaningless or rejected. → Keep them as **separate entries**.
> - **USED TOGETHER (AND)** → the `Client(...)` constructor receives several sets at once; a single code path mints/uses tokens from set A *and* set B; OR one set is **required** and the others are **optional add-ons** that layer extra capability (a bot token, webhook-validation secrets, a hunting key) on top of the primary. → Collapse into **ONE `Passthrough` profile** (`interpolated: true`) whose `xsoar_param_map` carries **all** the secrets.
>
> There is no `and` / `any` / concurrent inter-profile relation — so "used together" can ONLY be expressed as a single lumped `Passthrough` profile. When in doubt, lump into one `Passthrough`: under-splitting is safe (the secrets bag still carries everything), over-splitting actively lies to the runtime about mutual exclusivity.
>
> _Worked example — Zoom._ Account OAuth (`account_id` + `client_id` + `client_secret`, **required**) + Bot OAuth (`botJID` + `bot_client_id` + `bot_client_secret`, optional Team-Chat add-on) + inbound webhook tokens (`secret_token` + `verification_token`, optional mirroring). The `Client` is built with all of them at once and one `get_oauth_token()` call mints both the account and bot tokens — so they are **AND, not XOR** → **one** `Passthrough` profile holding all eight leaves, NOT three profiles.

##### Picking the profile `type` for a multi-field auth flow

For an auth flow that consumes more than one XSOAR field, count the **canonical-role-bearing leaves** (the ones that fit a canonical UCP profile's field list per §1.2.6) and pick the type accordingly:

- **Exactly one canonical-role leaf, plus N "extras"** → keep the canonical type.
  - Examples:
    - **`Plain` + a vendor client certificate** (the cert participates in the TLS handshake alongside username/password): one `Plain` entry whose `xsoar_param_map` holds `<id>.identifier`/`<id>.password` AND the cert leaf.
    - **`APIKey` + a vendor client certificate** (mTLS-protected endpoint that also needs a static API key): one `APIKey` entry whose `xsoar_param_map` holds both the `key` and the cert leaf.
    - **An OAuth2 client-credentials flow + a "scopes" or "tenant_id" string that the flow itself requires**: one `Passthrough` entry (`interpolated: true`) whose `xsoar_param_map` holds the OAuth client id + secret AND the extra leaf. (OAuth2 flows are classified as `Passthrough`, so the extra leaf rides along inside the same free-form map.)
- **Two-or-more co-equal canonical leaves (no obvious "dominant" canonical role)** → `Passthrough`.
  - Examples:
    - **Datadog** (`api_key` + `application_key` — two equal-rank API-key-style values, neither dominates).
    - **AWS SigV4** (`access_key` + `secret_key` — two co-equal HMAC inputs).
    - **Akamai EdgeGrid** (three co-equal tokens).
    - **GitHub App** (`app_id` + `private_key` + `installation_id` — three co-equal inputs).
  - All `Passthrough` entries MUST have `"interpolated": true` (see §1.2.2).

> **Decisive heuristic — count canonical roles only** (`key`, `username`/`password`, `client_id`/`client_secret` for OAuth, `subject_email`/`credentials_file` for JWT). If exactly one canonical pattern is present, the profile keeps that canonical type and the rest are "extras" living inside the same `xsoar_param_map`. If two-or-more independent canonical patterns appear (or none does, e.g. AWS-style two-key HMAC), use `Passthrough`.

> **Where do extras go? INSIDE the profile's `xsoar_param_map`, NOT in `other_connection`.** `other_connection` is reserved for **connection-wide / transport-level metadata that has no bearing on the auth flow** — URL, port, region, insecure, proxy. If a field has any implication on how authentication itself happens (a cert that participates in the handshake; an HMAC salt; a vendor-required header value), it belongs in the profile.
>
> **Caveat (validator role enum).** The validator restricts `APIKey` role values to `"key"` and `Plain` to `{"username", "password"}`. Adding an extra leaf with a non-canonical role string (e.g. `{"client_cert": "certificate"}` on an `APIKey` profile) surfaces a role-enum violation. Classifications that need extras on `APIKey`/`Plain` should demote the profile to `Passthrough` so the role enum is free-form.

**Single-secret flows stay on their natural profile type.** If the integration has exactly one API key (one header / one query param / one HMAC secret-of-one) and nothing else auth-relevant, keep it as `APIKey`. If it has exactly one username+password pair (`Plain` profile has two fields by design) and nothing else, keep it as `Plain`. The "extras go in the profile" rule fires only when there ARE extras AND there is still a dominant canonical role; otherwise (no canonical dominance) use `Passthrough`.

**HMAC of one** (single static secret producing per-request signature) stays `APIKey`. **HMAC of two-plus** (e.g. AWS SigV4's pair, Akamai's triple) is multi-secret with no dominant canonical pattern → `Passthrough`. The wire-protocol mechanism (HMAC, Bearer, signed query string, etc.) is irrelevant to the classification — only the **count of co-equal canonical patterns** matters.

##### Multi-flow integrations → one `Passthrough` profile

Some integrations expose **two distinct optional auth flows** in a single configuration — e.g. AbuseIPDB has the primary AbuseIPDB API key AND an optional Abuse.ch Hunting API key, each authenticating against a different service URL. The user can configure either, both, or just the primary. Since the schema supports XOR only (no `and` / `any` / concurrent relations), these classify as **one `Passthrough` profile** carrying all secrets in `xsoar_param_map`:

```json
{
  "auth_types": [
    {
      "type": "Passthrough",
      "name": "AbuseIPDB authentication",
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

The parity gate detects this shape and emits the structural-skip code `MULTI_SECRET_PASSTHROUGH` with a diagnostic that frames the reduced coverage as "by design, not a failure." Heuristic: 2+ keys in a `Passthrough` profile's `xsoar_param_map` matching credential-field name patterns (`password`, `key`, `secret`, `token`, `credential`, `apikey`, `api_key` — case-insensitive substrings).

**When in doubt** between "one `Passthrough` lumping both" and "two separate `APIKey` profiles", remember: there is no `any` relation. Two `APIKey` profiles would (incorrectly) tell the UCP runtime the user must pick one. `Passthrough` is the honest classification for "user may configure either, both, or just primary."

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

The legacy `config` expression key and the per-entry `xsoar_params` key are not recognized; the parser silently ignores them (their presence does NOT fail `set-auth` but has no effect). Strip such keys and re-shape `auth_types[]` per [`column-schemas.md`](column-schemas.md:1).

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
- **Platform-hidden / deprecated params** — excluded. A param with `hidden: true` OR a `hidden:` list containing `platform` does NOT go in `other_connection`, even if it's a connection-adjacent name like a legacy `host` or `url` alias. Use the visible variant only. A `hidden:` list WITHOUT `platform` (e.g. `hidden: [xsoar]`) is NOT excluded — the param is visible on the platform and IS carried through (see §1.3).

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

> The manifest-layer profile-type field reference (oauth2_client_credentials, oauth2_jwt_bearer, plain, api_key shapes + the closed metadata.auth.parameter set + OPA Check 17) is in [`connectus/auth-examples.md`](auth-examples.md#authentication-profile-types--fields-reference). For classification you only need the 4-value decision rule: every secret that fits `plain`/`api_key` → `Plain`/`APIKey`; everything else (all OAuth2, multi-key, managed identity, mTLS, custom signing) → `Passthrough` (interpolated:true); no auth → NoneRequired.

---

#### 1.2.4 Two end-to-end worked examples

> Full worked examples (Bearer APIKey, APIVoid hiddenusername APIKey, Plain+OAuth credentials) live in [`connectus/auth-examples.md`](auth-examples.md). One minimal inline example:

```json
{
  "auth_types": [{ "type": "APIKey", "name": "API Key", "interpolated": true, "xsoar_param_map": { "api_key": "key" } }],
  "other_connection": ["insecure", "proxy", "url"]
}
```

> **Note the `"interpolated": true` on the `APIKey` profile.** EVERY profile carries it — there is no such thing as a non-interpolated profile (ALWAYS-INTERPOLATE GATE, §1.12). Always emit `"interpolated": true` on every `auth_types[]` entry you author, regardless of `type` (`APIKey`, `Plain`, `Passthrough` — all of them).

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
| `hidden: true` OR a `hidden:` list that contains `platform` | **Excluded entirely from every CSV column** — does not appear as a key in any `xsoar_param_map`, not in `other_connection`, not in `Params to Commands`. Even if the source code still reads the param as a legacy fallback, the migration treats it as if it does not exist. A `hidden:` list that does NOT contain `platform` (e.g. `hidden: [xsoar]`, `hidden: [marketplacev2]`) is **NOT** excluded — the param is still visible on the platform target and must be carried through. |
| `deprecated: true` or `_deprecated` in param names | Ignore these entirely — they are no longer functional |
| `additionalinfo` text | Often describes the auth mechanism in plain English |
| Params named `auth_type` with `type: 15` | Indicates multi-auth integrations with user-selectable auth flow |

**Key rule for hidden/deprecated params (platform-aware):**

> A YML param is excluded from all migration tooling ONLY when it is hidden **on the platform target** — i.e. `hidden: true` (hidden everywhere) OR a `hidden:` list that **contains `platform`**. Such params are **invisible to all migration tooling**: they are excluded from every workflow-data column, the visible siblings define the entire authentication / connection / per-command surface, and even if a platform-hidden param backs the same secret as a visible one, you do NOT key the hidden id in any `xsoar_param_map` — key ONLY the visible id(s).
>
> **A `hidden:` list that does NOT contain `platform` is NOT excluded.** Params hidden only on other modules (`hidden: [xsoar]`, `hidden: [marketplacev2]`, `hidden: [xsoar, marketplacev2]`, etc.) remain **visible on the platform** and MUST be carried through the migration normally — they appear in `xsoar_param_map` / `other_connection` / `Params to Commands` exactly as any visible param would. Only the presence of `platform` in the list (or `hidden: true`) triggers exclusion.
>
> Rationale: the migration produces a clean, forward-looking ConnectUs manifest for the **platform** target. A param the platform user can still see and set must be migrated; only params the platform itself hides are dropped.

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
  "name": "API Key",
  "interpolated": true,
  "xsoar_param_map": {
    "credentials.password": "key"
  }
}
```

---

#### 1.4 Python Code Analysis — Specific Patterns

> The grep-pattern catalog by auth type (OAuth2 variants, API key, basic auth, JWT, ROPC, device code, managed identity) is in [`connectus/auth-examples.md`](auth-examples.md#grep-pattern-catalog-by-auth-type).

---

#### 1.5 Cross-Reference YML Params with Code Usage

For each auth-related param found in the YML:
1. Find where it is read in the Python code (search for the param name in `demisto.params()` calls)
2. Trace how the value is used — is it sent as a header? Used in an OAuth flow? Passed to `HTTPBasicAuth`?
3. Confirm the YML param type matches the actual usage

---

#### 1.6 Known Misclassification Patterns

> The known-misclassification table (the most common classifier errors and how to detect each) is in [`connectus/auth-examples.md`](auth-examples.md#known-misclassification-patterns). Sanity-check your classification against it.

---

#### 1.7 Microsoft/Azure Integration Special Handling

> Microsoft/Azure special handling (MicrosoftClient detection, the 4-flow upper bound, managed identity / device code / auth-code as Passthrough) is in [`connectus/auth-examples.md`](auth-examples.md#microsoftazure-special-handling).

---

#### 1.8 Auth Details JSON Validation

After determining the correct auth types, validate against the rules in [`connectus/column-schemas.md`](column-schemas.md:16), enforced at runtime by [`validate_auth_details()`](auth_config_parser/validator.py:47). Key points (full detail in the sections cited):

1. Top-level keys `auth_types` (array) AND `other_connection` (array of strings, required, may be `[]`) — a missing `other_connection` raises. Unknown top-level keys are silently ignored.
2. Each `auth_types[]` entry: a `type` ([`AuthType`](auth_config_parser/types.py:11) member), a unique `name`, and a non-empty `xsoar_param_map` (empty `{}` rejected). Per-entry keys outside `{type, name, xsoar_param_map, interpolated, verify_connection_skip}` are silently ignored — rewrite any stale `xsoar_params` field as `xsoar_param_map`.
3. Role enum per `type` — see §1.2.2 (`APIKey`→`"key"`; `Plain`→`{"username","password"}`; `Passthrough`→free-form).
4. `auth_types[]` sorted by `(type, name)` ascending (map keys unordered). Profile relations implicit from `len(auth_types)` — see §1.2.3.
5. `verify_connection_skip` optional JSON boolean — see §1.2.2. `other_connection` is a sorted list of non-empty unique strings — see §1.2.5.

---

#### 1.9 Decision Tree for Auth Type

Use this decision tree to determine the correct auth type:

```
Is there a credentials param (type=9)?
├── YES: What does the code do with it?
│   ├── Sends as Basic Auth (HTTPBasicAuth) → Plain
│   ├── Sends as Bearer token (Authorization: Bearer) → APIKey
│   ├── Uses in OAuth2 client_credentials flow → Passthrough (interpolated:true)
│   ├── Uses in OAuth2 ROPC flow (grant_type=password) → Passthrough (ROPC)
│   └── Uses as username/password for login → Plain
├── NO: Is there an encrypted param (type=4)?
│   ├── YES: What is it?
│   │   ├── Named api_key, apikey, token → APIKey
│   │   ├── Named client_secret, enc_key used in OAuth → Passthrough (interpolated:true)
│   │   └── Named private_key used for JWT signing → Passthrough (interpolated:true)
│   └── NO: Is there any auth at all?
│       ├── YES: Check code for auth mechanism → classify accordingly
│       └── NO: NoneRequired
```

> **Read every leaf above as ending in `interpolated: true`.** The `(interpolated:true)` annotations on the OAuth/Passthrough leaves are NOT a contrast with the `APIKey` / `Plain` leaves — ALL leaves, including `APIKey` and `Plain`, produce `interpolated: true` profiles. The annotation is shown only where the `type` itself is also being disambiguated. NEVER author a `Plain` or `APIKey` leaf without `interpolated: true`.

---

#### 1.9.1 Feed-framework integrations (always `interpolated: true`)

Integrations that import from any `*FeedApiModule` — `JSONFeedApiModule`, `RSSFeedApiModule`, `CSVFeedApiModule`, `FeedApiModule`, etc. — do **NOT** subclass `BaseClient` directly. They use the feed framework's own `Client` class, which is its own auth-injection ecosystem and is incompatible with the parity tool's BaseClient-based UCP injection.

The parity tool short-circuits on these with `ERROR_NO_BASECLIENT` (exit 11). **Required action: classify with `interpolated: true` on every `auth_types[]` entry. There is no code-change alternative** — re-architecting feed integrations on top of `BaseClient` is out of scope for the migration.

**Detection during classification:** grep the integration's `.py` for `from .*FeedApiModule import`. If present, mark `interpolated: true` up front on every entry — do **not** waste time deriving `auth_types[].xsoar_param_map` shapes that the parity tool will never exercise (still populate the map per §1.2.2; the role declarations are required even when `interpolated: true`, but you do not need to second-guess them).

Examples currently in the pipeline: `SpamhausFeed`, `MalwareBazaarFeed`, `AbuseIPDBFeed`, and effectively any pack named `Feed*`.

---

#### 1.10 Applying Corrections

##### Committing the value

> **No dry-run step.** `set-auth` only ever forces `interpolated: true` and short-circuits the parity test, so there is nothing to verify ahead of time — the write succeeds the moment the JSON passes schema validation. Just present the evidence table, get user approval, and apply. (The `--dry-run` flag is no longer part of the Auth Details flow.)

When corrections are needed (or for the initial set), use `set-auth`:

```bash
python3 content/connectus/workflow_state.py set-auth "<Integration ID>" '<Auth Details JSON>'
```

This command:

- Validates the Auth Details JSON against the schema (`auth_types[]` + required `other_connection`) — see [`validate_auth_details()`](auth_config_parser/validator.py:24).
- Sets the `Auth Details` workflow data column in the CSV.
- Automatically **resets the workflow** to the first checkpoint (`generated manifest`) and clears all checkpoints + the auth-parity flag. **This includes wiping the `Params to Commands` data column**, even though it carries `preserve_on_reset: true` for `reset-to`/`fail` — `set-auth` deliberately ignores that flag because auth-classification changes invalidate every downstream artifact (in particular, the per-command param contract validated by `params_to_commands_no_auth_overlap`).
- Rejects invalid JSON with specific error messages — including unsorted `auth_types[]`, role-enum violations (e.g. `APIKey` entries whose role isn't `"key"`), missing `other_connection`, and unknown enum values. Unknown top-level keys (including the legacy `config` / `xsoar_params` keys) are silently ignored.

Example:

```bash
python3 content/connectus/workflow_state.py set-auth "Abnormal Security" '{"auth_types":[{"type":"APIKey","name":"API Key","xsoar_param_map":{"api_key":"key"}}],"other_connection":["insecure","proxy","url"]}'
```

`set-auth`'s own output echoes the new `Current step:` — do NOT re-run `status` to confirm.

Note: there is **no `markpass "auth params set"`** anymore — the verification IS the `set-auth` call. The first markpass-able checkpoint is `generated manifest`.

---

#### 1.11 Pre-flight self-check

Before invoking `set-auth`, walk this checklist mentally. The validator will catch most of these but it's faster (and clearer) to catch them locally.

- [ ] No platform-hidden YML param (`hidden: true`, or a `hidden:` list containing `platform`) appears as a key in any `auth_types[].xsoar_param_map`, in `other_connection`, or in `Params to Commands`. Params hidden only on non-platform modules (e.g. `hidden: [xsoar]`) are NOT excluded and ARE carried through. (See §1.3.)
- [ ] Every YML param the source code reads as an auth secret is keyed in some `auth_types[].xsoar_param_map`.
- [ ] No NON-auth param (URL, proxy, fetch interval, feature toggle, verify-SSL boolean) is keyed in any `xsoar_param_map`.
- [ ] Every credentials-typed (YML type `9`) auth param appears in `xsoar_param_map` as the appropriate leaves, with `<id>.identifier` suppressed if YML `hiddenusername: true` and `<id>.password` suppressed if YML `hiddenpassword: true`. (See §1.3.)
- [ ] Every map value matches the role-enum for its entry's `type` (APIKey: `"key"`; Plain: `"username"`/`"password"`; OAuth/Passthrough: any non-empty string).
- [ ] Any entry with 2+ map keys whose roles DON'T fit the canonical `plain` profile's `username`+`password` shape is classified as `Passthrough`, not as `APIKey` or `OAuth2*`. See §1.2.2a (multi-secret rule).
- [ ] **XOR-vs-AND gate (run whenever `len(auth_types) >= 2`).** A multi-entry `auth_types[]` means **EXCLUSIVE-OR — the user picks exactly one profile**. Before keeping 2+ entries, prove from the source code that the credential sets are genuine *alternatives* (the code reads one OR the other; configuring both is meaningless/rejected). If instead the sets are used **together / additively** (the `Client(...)` is constructed with several of them at once; one code path mints tokens from set A *and* set B; one set is required and another is an optional add-on layered on top), they are **AND, not XOR** → collapse them into **ONE `Passthrough` profile** whose `xsoar_param_map` holds all the secrets (see §1.2.2a "Multi-flow → one `Passthrough`"). When unsure, default to one `Passthrough` — there is no `any`/concurrent relation, so multiple entries can only ever mean "pick one," which is wrong for additive credentials.
- [ ] Any OAuth2 Authorization Code flow (browser redirect, `code` + `redirect_uri`, `oauth-start`/`oauth-complete` commands) is classified as `Passthrough` — there is no canonical `oauth2_authorization_code` profile shape; the user-facing config lives on the profile itself, not in `metadata.auth.parameter`.
- [ ] Every non-`NoneRequired` entry has a non-empty `xsoar_param_map` (even if `interpolated: true`).
- [ ] **Every** `auth_types[]` entry is interpolated, regardless of `type` (ALWAYS-INTERPOLATE GATE, see [§1.12](#112-auth-parity-gate-inside-set-auth)). `set-auth` forces `interpolated: true` onto every entry — never suggest, classify, or hand-author a non-interpolated profile, and never emit `interpolated: false` (including on `Plain` / `APIKey`).
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

**ALWAYS-INTERPOLATE GATE (2026-06-09).** `set-auth` no longer parity-tests the candidate `Auth Details`. Instead, the call performs a single deterministic transformation: it **forces `interpolated: true` onto every `auth_types[]` entry** of the candidate payload, then short-circuits the parity test (every connection is now interpolated, so there is genuinely nothing to compare — this is the `ERROR_ALL_INTERPOLATED` clean structural skip). The cell that gets committed is the **forced-interpolated** payload, so the persisted `Auth Details` is guaranteed to carry `interpolated: true` on every profile.

Consequences:

- **The write always succeeds** once the JSON passes schema validation (and any `--seed-param` overlap check). There is no per-connection `pass` / `fail` / `inconclusive` evaluation anymore — no Docker, no proxy, no integration source inspection is performed by the gate.
- **You do not need to set `interpolated: true` yourself.** Even if you submit a payload with `interpolated` omitted or `false` on some entries, `set-auth` rewrites them to `true` before committing.
- The `xsoar_param_map` is still **required and non-empty** on every entry (schema validation enforces this) — the role declarations are still needed even though the value is templated at runtime.

| Outcome | Gate decision | What happens |
|---|---|---|
| Schema-valid `Auth Details` JSON | **Allow** | Every `auth_types[]` entry is forced to `interpolated: true`, the parity test is short-circuited (`ERROR_ALL_INTERPOLATED` clean structural skip), and the forced-interpolated cell is written; downstream Params\* columns are wiped per the normal cascade. |
| Schema-INvalid JSON (missing `other_connection`, empty `xsoar_param_map`, malformed JSON, bad role enum, …) | **Block** | Schema validation runs **before** the always-interpolate step. The cell is NOT written. Fix the JSON and re-run. |
| `--seed-param` key overlaps the candidate `Auth Details` | **Block** | `ERROR_SEED_AUTH_OVERLAP`. The cell is NOT written. Remove the overlapping seed override and re-run. |

The api/CLI returns `result["parity"]` as a structural-skip stub (`{"skipped": "always-interpolate gate: …", "forced_interpolated": <bool>}`) where `forced_interpolated` reports whether any entry had to be rewritten.

> **Escape hatch (tests only).** The legacy env var `CONNECTUS_SKIP_AUTH_PARITY=1` (and the `skip_parity` argument) is retained for backward compatibility but is now a no-op for verification purposes — the gate already short-circuits unconditionally.

> Historical per-failure-class fixes — UCP non-standard-header overrides (`_apply_ucp_*`), startup-validator `is_ucp_enabled()` gating, boto3/feed permanent-interpolated cases, UCP-strip crashes, the full `--seed-param` recovery reference, and the sentinel grammar — are retained in **[`connectus/auth-parity-troubleshooting.md`](auth-parity-troubleshooting.md)** for reference, but the always-interpolate gate means none of those parity failures can occur during `set-auth` anymore.

---

#### Auth Type Reference

See the canonical [Auth Type Reference](#auth-type-reference) table near the end of this document.

## Analyzing per-command parameters (Step 4 input)

Populate `Params to Commands` (Step 4) by running the analyzer, then merging its output with a quick source review.

**Canonical invocation** (pass only `--integration-id` — it now resolves the integration directory from the workflow CSV's `Integration File Path` column AND auto-unions the auth ignore-set, so neither the positional `<integration_dir>` nor a separate `auth-params` call is needed):

```bash
DEMISTO_SDK_LOG_FILE_PATH="$PWD/.tmp_migration/sdk-logs" \
  python3 content/connectus/check_command_params.py \
    --ignore-params-file content/connectus/default_ignore_params.txt \
    --integration-id "<Integration ID>"
```

The positional `<integration_dir>` is still accepted (and wins if both are given) for standalone runs on integrations not in the CSV; inside the migration workflow, omit it and let `--integration-id` supply the path.

Runs all commands in one invocation (Docker + internal capture proxy). Default stdout payload = exactly two keys: `integration` + `commands`.

**Operational decision summary** (per integration):
1. Most commands `status: ok` (no `limitation`) → trust `commands` as-is.
2. `limitation: capture_proxy_bypassed` (boto3/AWS) on every command → treat as static-only; verify against source.
3. Many `param_caused_failure` → `failing_params` are pre-elevated; merge remaining with the static union (err on inclusion).
4. Many `no_data` / `ok_no_capture` / `timeout` / `module_not_found` / JS/PowerShell / non-zero exit → analyzer signal weak or absent; read source + YML and write the per-command list manually.
5. Always sanity-check the YML for commands/params the analyzer missed.

**"Err on inclusion" principle:** when unsure whether a param belongs to a command, INCLUDE it — a false positive is cosmetic, a false negative silently breaks the migrated integration.

**HARD RULE — never persist diagnostics.** The `set-params-to-commands` payload must contain ONLY `integration` and `commands` keys. Never write `diagnostics`, `status`, `failure_excerpt`, `error`, or `stderr` into the cell.

> Full reference (all flags, output schema, status enum, the complete decision tree §6/§6a–§6h, blind spots, `--seed-param` recovery loop, runtime expectations, non-Python handling): **[`connectus/analyzer-manual.md`](analyzer-manual.md)**.

### Step 3: Set `Collect Capabilities` (data column — gate before Params to Commands)

`Collect Capabilities` is step **#3** in the live CSV workflow and the state machine **enforces it before `Params to Commands`** (step #4). If you skip it, `set-params-to-commands` is rejected with `current step is #3 'Collect Capabilities'`.

This column is **deterministically generated** from the integration's YML fetch flags — there is no judgment call, so it is a **run-through** (do NOT pause for user approval; it is not one of the 4 JSON-write setters).

**Shape:** a flat JSON array of capability-name strings from the closed enum (`Fetch Assets and Vulnerabilities`, `Fetch Issues`, `Log Collection`, `Fetch Secrets`, `Threat Intelligence & Enrichment`, `Automation`). `[]` is valid. NOTE: `general_configurations` is NOT allowed here (that value belongs only to `Params to Capabilities`).

**Generate it with the collector helper, then apply.** The collector lives at **`connectus/connectus_migration/capabilities_collector.py`** — note the `connectus_migration/` SUBDIRECTORY (it is NOT directly under `connectus/`; `ls connectus/capabilities_collector.py` will fail — always use the full `connectus/connectus_migration/` path). It is a single-command Typer app — invoke it with the YML path directly, with **NO subcommand name**:

```bash
# Preferred — resolve the YML from the workflow CSV id and ALSO emit the
# reference-aligned JSON envelope ({integration, pass, capabilities}) on stdout.
# The bare array is still written to the -o file for set-capabilities.
python3 content/connectus/connectus_migration/capabilities_collector.py \
  --integration-id "<Integration ID>" \
  -o content/connectus/connectus_migration/_caps.json \
  --report

# Legacy positional form (still supported — pass the YML path directly):
python3 content/connectus/connectus_migration/capabilities_collector.py \
  Packs/<PackName>/Integrations/<Name>/<Name>.yml \
  -o content/connectus/connectus_migration/_caps.json

# Apply (paste the generated array verbatim), then clean up the temp file
python3 content/connectus/workflow_state.py set-capabilities "<Integration ID>" '["Fetch Issues", "Automation"]'
rm -f content/connectus/connectus_migration/_caps.json
```

How the collector maps YML → capabilities (so you can sanity-check, or derive by hand if the script ever fails to run): `isfetch:true` → `Fetch Issues`; `isfetchevents:true` → `Log Collection`; `isFetchCredentials` → `Fetch Secrets`; `feed:true` → `Threat Intelligence & Enrichment`; `isfetchassets:true` → `Fetch Assets and Vulnerabilities`; plus `Automation` when there is ≥1 non-fetch command. (Source: [`capabilities_collector.py`](connectus_migration/capabilities_collector.py) `collect_capabilities()`.) Worked example: a plain command integration with no fetch/feed flags but ≥1 command → only the `Automation` rule fires → `["Automation"]`.

> **Gotchas that cost time if missed:**
> - **The script is under `connectus/connectus_migration/`, NOT `connectus/`.** `ls connectus/capabilities_collector.py` returns "No such file" — that does NOT mean the script is missing. The whole helper family (`capabilities_collector.py`, `connector_param_mapper.py`, `manifest_generator.py`, `run_pre_manifest_steps.py`) lives in the `connectus_migration/` subdirectory. Do NOT conclude the tooling is absent and fall back to a hand-derivation without first checking `connectus/connectus_migration/`.
> - The helper takes **no subcommand** — `capabilities_collector.py <yml> -o <path>`, NOT `capabilities_collector.py generate-capabilities-list <yml>`.
> - Write `-o` to a **workspace path**; `/tmp` is denied by the sandbox.

### Step 4: Set Params to Commands (workflow data column)

Define which integration commands need which parameter IDs (excluding connection-level params). See [`connectus/column-schemas.md`](column-schemas.md) for the JSON shape.

- **The auth-aware ignore list is auto-unioned by the analyzer.** When the analyzer is run with `--integration-id "<Integration ID>"` (the canonical invocation above), the standalone `auth-params` call is NOT needed — the analyzer auto-unions every YML param id already declared in `Auth Details` (both the auth-secret params projected from `auth_types[].xsoar_param_map.keys()` — dotted leaves collapse to the segment before the first `.` — and every entry in `other_connection`) into its ignore set. These params MUST NOT appear in `Params to Commands` — `set-params-to-commands` will hard-reject the call if any of them does. `auth-params` / `context.auth_ignore_params` remain available for human display only.
- Platform-hidden YML params (`hidden: true`, or a `hidden:` list containing `platform`) MUST NOT appear in any per-command list. Params hidden only on non-platform modules (e.g. `hidden: [xsoar]`) ARE included normally. The `set-params-to-commands` validator does not currently enforce this; it is the analyst's responsibility per skill §1.3.

> **Single-capability shortcut (run-through optimization).** When the `Collect Capabilities` cell (Step 3) resolved to **exactly one** capability (e.g. `["Automation"]`), every command trivially routes to that single capability in `Params to Capabilities` (Step 7 uses `connector_param_mapper.py`'s `_single_capability_shortcut`). The only command whose per-command param analysis is still needed for the connection is `test-module`. Pass `--single-capability-test-module-only` to the analyzer to skip analyzing the other commands:
> ```bash
> python3 content/connectus/check_command_params.py --integration-id "<Integration ID>" --static-only --single-capability-test-module-only
> ```
> The flag is **self-guarding**: it requires `--integration-id` (it reads the capability count from the cell), it is a **no-op** when the capability count is 0 (not yet collected) or >1 (a full analysis runs), and an explicit `--commands` always wins. The resulting cell contains just `{"test-module": [...]}`, which is exactly what `test_module_params` / Step 5 and the auth-parity command selection (Step 11) consume — and it directly tells you which non-auth params `test-module` needs. The auto-runner harness ([`run_pre_manifest_steps.py`](connectus_migration/run_pre_manifest_steps.py:1)) applies this same heuristic automatically; the standalone flag brings the manual flow to parity. This remains a run-through step (no extra approval beyond the standard pre-`set-params-to-commands` confirmation).

```bash
python3 content/connectus/workflow_state.py set-params-to-commands "<Integration ID>" '<JSON>'
```

> **The setter reads the JSON from a positional argument, NOT stdin.** Piping the analyzer directly into it (`analyzer | set-params-to-commands "<id>"`) fails. Capture the analyzer output into a shell variable first, then pass it as the argument:
> ```bash
> OUT=$(python3 content/connectus/check_command_params.py --integration-id "<Integration ID>" [--seed-param ...] 2>/dev/null)
> python3 content/connectus/workflow_state.py set-params-to-commands "<Integration ID>" "$OUT"
> ```

Derive the contents from the integration's existing YAML `configuration` and `script.commands` sections, plus any per-command param usage in the Python code.

Example (post-ignore-list — only behavioral params; `url`,
`credentials`, `longRunning`, etc. are stripped by
[`connectus/default_ignore_params.txt`](default_ignore_params.txt)):

```bash
python3 content/connectus/workflow_state.py set-params-to-commands "QRadar v3" '{"integration":"IBM QRadar v3","commands":{"test-module":["adv_params","fetch_interval"],"qradar-offenses-list":["adv_params","fetch_interval"]}}'
```

**Validation:** The command rejects (a) invalid JSON with the parse error, AND (b) any payload whose per-command param lists overlap with the integration's `Auth Details` cell — every offending `(command, param_id)` pair is named, the auth-detail source for each offending param is named (e.g. `param 'credentials' overlaps with auth_types[].name='credentials' (xsoar_param_map keys=['credentials.identifier','credentials.password'])` or `param 'proxy' overlaps with other_connection`), and the row is NOT mutated.

#### When `set-params-to-commands` is rejected for overlap

If `set-params-to-commands` rejects your payload because a param is already in `Auth Details`, **stop and think about what the issue really is.** Two scenarios:

1. **The param really belongs to Auth Details** (e.g., the analyzer picked up `proxy` for a command but `proxy` is just a connection-level toggle). Strip it from your per-command payload, re-invoke `set-params-to-commands` with the cleaned list, and proceed.

2. **The param was misclassified into Auth Details and is genuinely used per-command** (rare but real — e.g., a YML param that doubles as both a connection setting AND a per-command override). Revert to Step 2: re-run `set-auth` with a corrected `Auth Details` JSON that removes the param from `auth_types[].xsoar_param_map` / `other_connection`. This will reset the workflow back to `generated manifest`, but that's the correct outcome — the original auth classification was wrong and downstream artifacts need to be regenerated against the fix. Do NOT bypass the rejection by hand-stripping just to make the call go through.

Use `python3 content/connectus/workflow_state.py auth-params "<Integration ID>"` at any time to inspect the current exclusion list. The same list is what the analyzer pulls when invoked with `--integration-id "<Integration ID>"`, so re-running the analyzer with the flag after fixing scenario (2) will produce a payload that is disjoint from `Auth Details` by construction.

Whenever you set params to command not strictly what the script returned, present the evidence clearly and concisely to the user why you decided to do it, and allow them to tweak the input.

### Step 5: Set `Params for test with default in code` (data column)

This column records the **per-param defaults that `test-module` relies on** when UCP / the connectus runtime omits the YML default. The cell is consumed by [`connectus/connectus_migration/connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:1) as the `PARAM_DEFAULTS_JSON` positional argument, and by [`connectus/check_auth_parity.py`](check_auth_parity.py:1) as the first-precedence source of non-auth required param values.

**JSON shape is unchanged** — a flat object `{<yml_param_id>: <default value>}`. Empty `{}` is valid. The schema is enforced by [`validate_param_defaults()`](workflow_state/validators.py:155) (top-level JSON object, non-empty string keys, any JSON-typed values). What changes in this revision is **which params qualify** for the cell and **what code edits the migration must perform** as a side effect.

#### Qualification rule — derived from `Params to Commands`, NOT from source-code review

> **2026-05 rule change.** The qualification source for this column is the `test-module` entry of the already-validated `Params to Commands` cell (Step 4). Do NOT re-derive by reading the integration source or running the analyzer again — Step 4 already curated, validated, and persisted that list, and re-doing the work invites drift between the two columns.

The canonical qualification list is:

```bash
python3 content/connectus/workflow_state.py test-module-params "<Integration ID>"
```

(`--format=json` for programmatic consumption; the same value is available programmatically as [`test_module_params(integration_id)`](workflow_state/api.py:1) returning `list[str]`.)

**What that list contains and excludes, by construction:**

- It is exactly `commands["test-module"]` from the `Params to Commands` cell.
- It is already disjoint from `Auth Details` — `set-params-to-commands` rejected any overlap when Step 4 was applied, so no further auth-exclusion check is needed at this step.
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

**Precondition:** Step 4 must be complete. If `Params to Commands` is not set, the CLI helper exits with a clear error pointing at Step 4 — do that first.

#### Per-qualifying-param workflow

For each YML param that qualifies, apply exactly one of these three branches:

**(a) YML declares a `defaultvalue` AND the Python code does NOT already supply a fallback** (no `or "..."`/`or <literal>` after `params.get("foo")` or `demisto.params().get("foo")` or equivalent).

- **PAUSE and ask the user to confirm the chosen default** (this is the per-param confirmation interaction). Even though the YML supplies a `defaultvalue`, the skill must NOT silently accept it — present it for approval: "Param `foo` is consumed by `test-module`. The YML `defaultvalue` is `<yml default>` — use this as the code fallback? Confirm, edit, or reject (move to `other_connection`)."
- **If confirmed (or edited):** edit the integration's `.py` file: change `params.get("foo")` to `params.get("foo") or "<confirmed default>"`. Use the value verbatim (preserve type — strings stay quoted, numbers stay unquoted, booleans become `True`/`False`). Record the confirmed default value under key `"foo"` in the JSON payload for this cell.
- **If rejected:** do NOT add a code fallback and do NOT record the param in this cell. Instead the param moves to `other_connection` in `Auth Details` — see [Rejecting a default — move the param to `other_connection`](#rejecting-a-default--move-the-param-to-other_connection) below.
- Rationale: under UCP / the connectus runtime, the YML default is not necessarily injected; the code-side `or "<default>"` keeps `test-module` working in both the XSOAR environment AND under connectus. The confirmation step exists because the YML default is not always the value `test-module` should use under connectus — when it isn't, the param belongs in `other_connection` instead.

**(b) YML declares NO `defaultvalue`.**

- **PAUSE and ask the user** (this is the per-param confirmation interaction): "Param `foo` is consumed by `test-module` but has no YML default. Propose a reasonable default value: `<your suggestion>`. Confirm, edit, or reject (move to `other_connection`)?"
- **If confirmed (or edited):** edit the integration's `.py` to add the same `or "<confirmed default>"` fallback as branch (a). Record the confirmed default under key `"foo"` in the JSON payload.
- **If rejected:** do NOT add a code fallback and do NOT record the param in this cell. Instead the param moves to `other_connection` in `Auth Details` — see [Rejecting a default — move the param to `other_connection`](#rejecting-a-default--move-the-param-to-other_connection) below.
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

#### Rejecting a default — move the param to `other_connection`

This applies to branches **(a)** and **(b)** — the two cases where the skill is about to add a NEW code fallback. When the user **rejects** the proposed default (i.e. decides the chosen default is not good for the connectus runtime), the param does NOT get a code fallback and does NOT belong in the `Params for test with default in code` cell. Instead it is reclassified as **connection metadata** and added to the `other_connection` list of the integration's `Auth Details` (Step 2).

Procedure for each rejected param:

1. **Drop it from this cell.** Do not add a `or "<default>"` fallback in the `.py`, and do not include the param id as a key in the `set-param-defaults` JSON payload.
2. **Add it to `other_connection`.** Take the param id and append it to the sorted `other_connection` list inside the current `Auth Details` JSON (read the current value from the Step-0 `context` output's `data_columns["Auth Details"]`). Keep `other_connection` sorted and de-duplicated.
3. **Re-apply via `set-auth`.** Run `set-auth "<Integration ID>" '<updated Auth Details JSON>'` with the param now present in `other_connection`. Follow the normal Step 2 pause-and-confirm flow — this is a `set-auth` write, so present the evidence table and the updated `other_connection` list to the user before applying.
4. **Mind the reset.** `set-auth` **resets the workflow back to `generated manifest` and wipes the downstream `Params*` columns** (including any `Params for test with default in code` work already done for the OTHER params in this batch). Because of this, **collect ALL branch-(a)/(b) confirmations and rejections for the whole integration FIRST**, then:
   - If there is at least one rejection, do the `set-auth` re-apply (Step 2) for all rejected params **before** re-running Steps 4 and 5 for the surviving params. This avoids losing the param-defaults cell to a later reset.
   - If there are no rejections, proceed straight to `set-param-defaults` as normal.

> **Why `other_connection` and not an `auth_types[]` secret.** A rejected param here is a required, non-auth, test-module-consumed param whose value should come from the connection configuration rather than a code-side default. That is exactly what `other_connection` is for (URL, proxy, host, region, port, and other connection metadata — see [§1.2.5](#125-building-the-other_connection-list)). It is NOT a credential, so it does not go into any `auth_types[]` entry's `xsoar_param_map`.

#### Discovery procedure (operational)

1. Fetch the canonical qualification list:

   ```bash
   python3 content/connectus/workflow_state.py test-module-params "<Integration ID>"
   ```

2. If the list is empty, the payload is `{}` — call `set-param-defaults "<id>" '{}'` and proceed to Step 7. Skip steps 3–6 below.
3. For each param in the list, classify into branch (a) / (b) / (c) by reading the integration's `.py` and YML `required:` field. This reuses the YML/.py already read during Step 2 / available via the Step-0 `context` call — not a fresh read. The point of this read is **only** to determine the per-param branch — NOT to re-derive whether the param qualifies. Specifically:
   - Look for the param's read site (`params.get("foo")` or `demisto.params().get("foo")`).
   - **Branch (a):** YML declares `defaultvalue` for `foo`, code reads without fallback (`params.get("foo")` with no `or ...` and no two-arg form). → **Pause and ask the user to confirm the YML default.** On confirm/edit: edit code to add `or "<confirmed default>"` and record it in JSON. On reject: move the param to `other_connection` (see [Rejecting a default](#rejecting-a-default--move-the-param-to-other_connection)).
   - **Branch (b):** YML declares NO `defaultvalue` for `foo`. → Pause and ask the user for a proposed default. On confirm/edit: edit code; record confirmed default in JSON. On reject: move the param to `other_connection` (see [Rejecting a default](#rejecting-a-default--move-the-param-to-other_connection)).
   - **Branch (c):** Code already supplies a fallback (`params.get("foo", "bar")` or `params.get("foo") or "bar"`). → No code edit. Record the effective default in JSON.
4. **If any branch-(a)/(b) param was rejected,** add each rejected param to `other_connection` and re-apply via `set-auth` FIRST (this resets the workflow — see [Rejecting a default](#rejecting-a-default--move-the-param-to-other_connection)), then re-run Steps 4 and 5 for the surviving params.
5. After all per-param branches are decided, verify the cumulative `.py` diff with `git diff` before calling `set-param-defaults`.
6. Collect the JSON payload (one key per confirmed qualifying param — rejected params are excluded) and call `set-param-defaults`.

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
- [ ] (Implied by the previous check, since `set-params-to-commands` already enforced it in Step 4:) no key in the JSON appears in `Auth Details`.
- [ ] For every key: either the integration's `.py` already supplies a fallback (branch c), OR the migration has just added a `or "<default>"` fallback in `.py` (branches a and b). Verify the edit with a `git diff` of the integration's `.py` BEFORE running `set-param-defaults`.
- [ ] For every branch-(a) and branch-(b) key: the user explicitly confirmed the chosen default.
- [ ] No rejected param appears as a key in the JSON. Every rejected branch-(a)/(b) param was instead added to `other_connection` and re-applied via `set-auth` (and the workflow reset it triggered was handled before this step).
- [ ] If the required-only filtered list is empty, the payload is `{}` (empty object) — branches (a/b/c) do not apply.

```bash
python3 content/connectus/workflow_state.py set-param-defaults "<Integration ID>" '<JSON>'
```

Validator reference:
[`validate_param_defaults()`](workflow_state/validators.py:147) — enforces
top-level object, non-empty string keys, any JSON value. Full schema in
[`column-schemas.md`](column-schemas.md) §`Params for test with default in code`.

> **Reset semantics.** Not preserved on any reset path — see [Error Recovery Commands](#error-recovery-commands).


### Step 6: `UCP param-default review` (checkpoint)

**Why.** Under ConnectUs, integration parameters no longer arrive with the
type-based defaults the XSOAR/XSIAM framework used to inject. Previously an
unchecked checkbox arrived as `False` and an empty numeric field as `0`; now
an unset param arrives **absent / `None` / `""`**. Code that converts a
defaultless param read with a strict converter
(`argToBoolean`, `arg_to_number`, `arg_to_bool_or_none`, `int`, `float`,
`bool`) will then **raise at runtime** (`argToBoolean(None)` and `int(None)`
both throw). Step 5 fixes the *required test-module* params; this step audits
whether the **rest** of the code is safe under default removal.

**This is a present → fix → markpass checkpoint, NOT a self-executing gate.**
The script is the AI's evidence tool; the AI presents, fixes, updates this
skill, and only then markpasses.

#### 1. Run the analyzer

```bash
python3 content/connectus/check_param_defaults.py --integration-id "<Integration ID>" --human
```

It is a read-only static (stdlib `ast`) pass — seconds, no docker. It also
accepts a positional integration directory for standalone runs. Output is a
JSON envelope on stdout (`integration`, `pass`, `unsafe`, `uncertain`,
`safe_count`, optional `note`) plus a human summary on stderr (`--human`).
Exit `0` when `pass` (nothing unsafe, nothing uncertain), `1` otherwise.

Three buckets:

- **UNSAFE** — a provable break: a strict converter on a *literal* defaultless
  param read (`argToBoolean(params.get("x"))`, `int(params["limit"])`), inline
  or via a single-function local var. **Must be fixed.**
- **UNCERTAIN** — **"params still to be checked by AI."** Every static-analysis
  blind spot lands here BY NAME instead of being silently passed: cross-function
  value flow, dynamic / non-literal access (`params.get(var)`), `**params`
  splats, custom read wrappers (`get_param("x")`), and previously-defaulted
  checkbox params whose bare read **escapes a pure-boolean context** (i.e. used
  somewhere other than an `if`/`while`/`not`/`and`/`or` test — see the
  truthy-safe note below). **Each must be manually investigated.**
- **SAFE** (not listed individually; counted in `safe_count`) —
  `params.get("x", False)`, `... or <default>`, command-arg reads
  (`args.get(...)` are out of scope), and checkbox reads used ONLY for their
  truthiness.

> **Truthy/falsey checkbox reads are SAFE (do not over-flag).** A boolean
> param read bare and used only in a truthy context — `if params.get("fetch"):`,
> `not params.get("x")`, `a and params.get("x")` — behaves **identically**
> whether the value is the old injected `False` or the new absent `None`
> (both are falsey). The analyzer already treats these as safe. Only a read
> that **escapes** such a context (compared with `== False` / `is False`,
> stored/returned/passed onward, used arithmetically) is surfaced as uncertain.

#### 2. Present to the user

Present BOTH the `unsafe` list and the `uncertain` ("still to be checked")
list, each entry with its `param`, `site` (`file:line`), and `reason`. State
plainly which are provable breaks and which need your judgment. For non-Python
integrations the verdict is `pass: true` with `note: "not analyzed:
non-Python (...)"` — tell the user it was not analyzed and markpass.

#### 3. Investigate and fix

For every **UNSAFE** entry and every **UNCERTAIN** entry you confirm is a real
risk, fix the code at the read site:

- Add a default: `params.get("x", <default>)` or `params.get("x") or <default>`.
- OR, if the param is connection metadata, move it to `other_connection` in
  `Auth Details` (see [Rejecting a default](#rejecting-a-default--move-the-param-to-other_connection)).
- Verify each edit with `git diff` before markpassing.

Genuinely-safe findings the analyzer cannot prove may be suppressed with an
inline `# noqa: ucp-param-default` on the read line, or via
`--ignore-params NAME ...` / `--ignore-params-file PATH`. Suppress only with a
recorded reason — an ignored param is recorded as resolved, not dropped.

#### 4. UPDATE THIS SKILL

When you learn a new pattern — a custom read wrapper the analyzer flags as
uncertain, a converter not yet enumerated, a recurring false positive — **add
it here** so the next migration handles it deterministically. This is part of
the checkpoint, not optional.

#### 5. Markpass

Once every unsafe and confirmed-uncertain finding is fixed (or justified and
ignored):

```bash
python3 content/connectus/workflow_state.py markpass "<Integration ID>" "UCP param-default review"
```

> **Confidence & scope (honest).** Python loud/crash class ≈ **90%** (inline
> defaultless converts) — high. Python overall ≈ **70–80%** with the YML-aware
> tier. The irreducible residue — interprocedural indirection, dynamic access,
> the semantic ambiguity of the silent class, non-Python — is exactly what the
> UNCERTAIN bucket hands to you, and what the runtime param-parity test
> (Step 11) ultimately backstops. JS/PS are not statically analyzed (no stdlib
> AST) and short-circuit.

> **Reset semantics.** A plain checkpoint with no data cell; cleared like any
> checkpoint on a reset that reaches it. Re-run the script and re-markpass.


### Step 7: Set `Params to Capabilities` (data column)

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

These three inputs are already in the Step-0 `context` output — read
`data_columns["Params to Commands"]`, `data_columns["Params for test
with default in code"]`, and `file_paths["yml"]` from it (or re-run
`context "<id>"` once). No separate show-step/files calls needed. Show
the values to the user before running the script so wrong input is
spotted immediately.

#### Canonical mapper invocation

[`connector_param_mapper.py`](connectus_migration/connector_param_mapper.py:1)
is a single-command Typer app — invoke it **without** a subcommand name.

**Preferred — `--integration-id` (reference-aligned I/O).** The mapper now
resolves all three data inputs (`Params to Commands`, `Params for test with
default in code`, and the integration YML) straight from the workflow CSV id
via [`workflow_state.py`](workflow_state.py), so you no longer hand-paste them.
With `--report` it ALSO emits a JSON envelope
`{"integration", "pass", "mapping", "elevated"}` on stdout (add `--human` for a
stderr summary); the bare mapping is still written to `-o`, and the
`<output>.elevated.json` sidecar is still produced. Exit 0 on success, 2 on a
usage/resolution error.

```bash
python3 content/connectus/connectus_migration/connector_param_mapper.py \
  --integration-id "<Integration ID>" \
  '<MANUAL_COMMAND_TO_CAPABILITY_JSON — optional, default {}>' \
  -o content/connectus/connectus_migration/_<integration>_param_mapping.json \
  --report
```

**Legacy positional form (still supported).** Pass the four positionals
straight after the script path:

```bash
python3 content/connectus/connectus_migration/connector_param_mapper.py \
  '<COMMAND_PARAMS_JSON from Params to Commands cell>' \
  '<PARAM_DEFAULTS_JSON from Params for test with default in code cell>' \
  '<INTEGRATION_YML_PATH from workflow_state.py files>' \
  '<MANUAL_COMMAND_TO_CAPABILITY_JSON — optional, default {}>' \
  -o content/connectus/connectus_migration/_<integration>_param_mapping.json
```

`MANUAL_COMMAND_TO_CAPABILITY_JSON` should be `'{}'` unless the user
explicitly overrides a command → capability routing decision. Construct
the override using the actual **command names** as outer keys and arrays
of capability names as values, for example:

```json
{"long-running-execution": ["Log Collection"]}
```

#### Elevating required test-module params to the connection

The mapper applies two rules to `test-module` params that have **no
default** (i.e. not in the `Params for test with default in code` cell):

1. **Required → elevate to the connection, NOT general.** A `test-module`
   param whose YML `configuration` entry is `required: true` is needed to
   even run the connection test, so it belongs on the connection
   (`other_connection` in `Auth Details`) — **not** in
   `general_configurations`. The mapper keeps it out of every capability
   bucket and lists it for elevation. (It cannot live in the
   `Params to Capabilities` cell anyway — that column's closed enum has no
   `other_connection` key.)
2. **Non-required → unchanged.** A non-required `test-module` param (no
   default) keeps the historical behavior: it lands in
   `general_configurations`. Anything else routes via the normal
   per-command "other decisions".

The mapper writes the elevation list to a sidecar file next to its
output: `<output>.elevated.json` (a flat JSON array, `[]` when nothing
needs elevating), and logs it at INFO. **After running the mapper, do the
elevation when that list is non-empty:**

1. Read the current `Auth Details` from the Step-0 `context` output
   (`data_columns["Auth Details"]`).
2. Append each elevated param id to that JSON's `other_connection` list;
   keep it sorted ascending and de-duplicated.
3. Re-apply via `set-auth "<Integration ID>" '<updated Auth Details JSON>'`
   (normal Step 2 pause-and-confirm). This is the
   "inject into Auth Details" step.

> **`set-auth` resets the workflow — but the capability mapping
> survives.** Re-applying `Auth Details` cascades a reset back to the
> Auth Details step. Because `Params to Capabilities` (and
> `Collect Capabilities` / `Params to Commands`) are
> `preserve_on_reset: true`, the `set-auth` cascade now **honors**
> `preserve_on_reset` and keeps those columns intact. So: persist the
> capability mapping with `set-params-to-capabilities` FIRST (below),
> then do the elevation `set-auth` — the mapping is preserved, and you
> just re-walk the cheap data steps (`Params to Commands`,
> `Params for test with default in code`, `Params to Capabilities` are
> all retained) up to the manifest checkpoint. Plain `reset` (whole-row
> wipe) still clears everything.

#### Persist the mapper's output verbatim

```bash
python3 content/connectus/workflow_state.py set-params-to-capabilities "<Integration ID>" \
  "$(cat content/connectus/connectus_migration/_<integration>_param_mapping.json)"
```

Concrete example for Gmail Single User:

```bash
python3 content/connectus/workflow_state.py set-params-to-capabilities "Gmail Single User" \
  '{"general_configurations":["fetch_limit","query"],"Fetch Issues":["fetch_time"],"Automation":["legacy_name","send_as","redirect_uri"]}'
```

Validator reference:
[`validate_params_to_capabilities()`](workflow_state/validators.py:204) —
enforces top-level object, capability keys drawn from the closed enum,
list-of-unique-non-empty-strings values, no required keys, `{}` valid.

> **Reset semantics.** Not preserved on any reset path — see [Error Recovery Commands](#error-recovery-commands).

### Step 8: Generate the manifest, then mark `generated manifest` (first checkpoint)

This checkpoint has two parts: (1) **run the manifest generator** to
scaffold/append the ConnectUs connector files for the integration, then
(2) **markpass** the checkpoint. Both run straight through — generating
the manifest is deterministic (it is fed entirely from already-confirmed
pipeline cells), so it is NOT one of the 4 JSON-write setters and needs
no extra user approval beyond what Steps 2/7 already collected.

#### The generator and its 4 positional inputs

The generator is
[`connectus/connectus_migration/manifest_generator.py`](connectus_migration/manifest_generator.py:1)
— note the `connectus_migration/` SUBDIRECTORY (it is NOT directly under
`connectus/`; `ls connectus/manifest_generator.py` fails — always use the
full `connectus/connectus_migration/` path). It is a single-command Typer
app: invoke it **with NO subcommand name**, the positionals come straight
after the script path. It auto-decides from-scratch vs. append-handler by
whether `<connectors-root>/<slug>/connector.yaml` already exists.

Every input is **already persisted in the pipeline** from earlier steps —
do NOT re-derive any of them. Pull each from its column with
`show-step --raw` (the machine-consumer contract: emits the cell value
verbatim — no header, no pretty-printing, no flag-default substitution —
so the output can be passed straight into the generator as a JSON arg):

| # | Generator positional | Source pipeline data | How to read it |
|---|---|---|---|
| 1 | `integration_path` (XSOAR integration `.yml`) | `Integration File Path` identity column (the `yml` file path) | `context "<id>"` → `file_paths.yml`, or `files "<id>" --format=paths \| head -1` |
| 2 | `connector_title` | **the `Connector ID` identity column** (`context.connector_id`) — NOT the Integration ID. The directory slug is derived as `title.lower()` with spaces→dashes. Using the Connector ID ensures every integration in a multi-integration connector (e.g. all `AWS - *` integrations) scaffolds/appends into ONE shared `connectors/<slug>/` folder instead of a separate per-integration folder. | from `context "<id>"` (`connector_id`) — pass the Connector ID unless the user gives an explicit connector title |
| 3 | `mapped_params` (JSON `{capability: [params]}`) | **`Params to Capabilities`** cell (Step 7 output) | `show-step --raw "<id>" "Params to Capabilities"` |
| 4 | `auth_methods` (JSON `{auth_types, other_connection}`) | **`Auth Details`** cell (Step 2) | `show-step --raw "<id>" "Auth Details"` |

The `--connectors-root` option points at the ConnectUs repo's
`connectors/` directory (the shared-workspace sibling
`unified-connectors-content`, the same repo Step 10's `make validate`
runs in). The optional `--author-image-path` is keyed by the
**`Connector ID`** identity column (looked up in
[`connectus/connector-id-to-author-image.csv`](connector-id-to-author-image.csv));
omit it if there's no match.

#### Canonical invocation (sourcing every input from the pipeline)

```bash
ID="<Integration ID>"

# 1. integration YML path (identity column, via context's file_paths.yml)
YML=$(python3 content/connectus/workflow_state.py files "$ID" --format=paths | head -1)

# 2. connector title = the Connector ID identity column (groups all of a
#    connector's integrations into ONE connectors/<slug>/ folder).
TITLE=$(python3 content/connectus/workflow_state.py context "$ID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["connector_id"])')

# 3. mapped_params  ← Params to Capabilities cell (Step 7)
MAPPED=$(python3 content/connectus/workflow_state.py show-step --raw "$ID" "Params to Capabilities")

# 4. auth_methods   ← Auth Details cell (Step 2)
AUTH=$(python3 content/connectus/workflow_state.py show-step --raw "$ID" "Auth Details")

# Generate (NO subcommand name; --connectors-root points into the ConnectUs repo)
python3 content/connectus/connectus_migration/manifest_generator.py \
  "$YML" "$TITLE" "$MAPPED" "$AUTH" \
  --connectors-root "../unified-connectors-content/connectors"
```

> **Gotchas:**
> - **Use `show-step --raw`, NOT plain `show-step`.** The default form
>   prints a decorative header + pretty-printed JSON, which is NOT valid
>   to pass as a generator arg. `--raw` emits the verbatim cell value
>   (and nothing at all for an empty cell), which is exactly what the
>   JSON positionals need.
> - **The script is under `connectus/connectus_migration/`, NOT
>   `connectus/`** — same as the other helper family
>   (`capabilities_collector.py`, `connector_param_mapper.py`,
>   `run_pre_manifest_steps.py`). A "No such file" on
>   `connectus/manifest_generator.py` does NOT mean it's missing.
> - **Invoke with NO subcommand** — `manifest_generator.py <yml>
>   <title> <mapped> <auth> ...`, not `manifest_generator.py
>   generate-manifest ...`.
 > - The integration's `provider` (vendor) and pack metadata
> >   (`tags`/`categories`/`supported_modules`) are read from the YML /
> >   `pack_metadata.json` automatically — nothing to pass.
> - The generated `connector.yaml` `settings` block is emitted
>   automatically with `allow_skip_verification: true`, `grouped: true`,
>   and `skip_cut_off_check: true` for **every** connector — do NOT add
>   these by hand.

#### Similarity-guard collision with a same-vendor connector

The from-scratch flow runs a **similarity guard**
([`check_connector_id_title_similarity()`](connectus_migration/manifest_generator.py:579))
BEFORE writing any files. It computes the new connector's id/title from the
**vendor** (`integration_yml["provider"]`) + capability suffix via
[`derive_connector_id_and_title()`](connectus_migration/manifest_generator.py:172)
(e.g. vendor `Atlassian` + collection caps → id `atlassian-automation-and-collection`,
title `Atlassian Automation and Collection`) and rejects it with a
`RuntimeError: found similiray ...` when the new id/title is a
**case/space-insensitive substring** of (or contains) any EXISTING
connector's id/title. Because the vendor prefix is a substring of the
`<vendor>-automation-and-collection` pattern, **any pre-existing
same-vendor connector trips this guard** — e.g. an existing SaaS-posture
`atlassian` connector blocks a new `atlassian-automation-and-collection`
connector, even though they are intentionally distinct products.

**This is the documented decision point — do NOT guess; ask the user.**
The `Connector ID` column is the source of truth for which connector the
integration belongs to. Two legitimate resolutions, picked by what the
`Connector ID` says vs. the existing folder:

1. **The `Connector ID` is the intended SEPARATE connector** (the common
   case for the `<Vendor> Automation and Collection` naming pattern, which
   is deliberately namespaced to be distinct from a same-vendor
   posture/identity connector). The guard is a false positive here. The
   integration should get its OWN connector folder whose slug is
   `title_to_slug(Connector ID)` = `connector_id.lower()` with spaces
   removed (note: the on-disk target slug uses NO dashes, while the
   guard's *derived* id uses dashes — they differ). To proceed, the
   substring collision must be resolved deliberately — confirm with the
   user, then either (a) pass an explicit `connector_title` whose derived
   id is NOT a substring-match of the existing connector, or (b) if the
   project decides the guard is too strict for this naming convention,
   escalate rather than silently editing the guard.
2. **The integration should be a HANDLER under the existing same-vendor
   connector.** Pass `connector_title` equal to the EXISTING connector's
   title (e.g. `"Atlassian"`) so `title_to_slug` matches the existing
   folder and the generator takes the **append-handler** path (which does
   NOT run the from-scratch similarity guard).

Always read the `Connector ID` and inspect the existing same-vendor
folder's product/capabilities before choosing. When the `Connector ID`
clearly denotes a distinct product (different capabilities) from the
existing folder, prefer resolution #1 (separate connector) and confirm
with the user; only consolidate as a handler (resolution #2) when the
integrations genuinely belong to the same connector.

> **Shortcut.** The auto-runner
> [`run_pre_manifest_steps.py`](connectus_migration/run_pre_manifest_steps.py:1)
> performs this exact wiring in
> [`step_3c_generate_manifest()`](connectus_migration/run_pre_manifest_steps.py:686)
> (`integration_path` ← `context.file_paths.yml`, `connector_title` ←
> `context.connector_id` (the Connector ID column — see the table above),
> `mapped_params` ← `Params to Capabilities`, `auth_methods` ←
> `Auth Details`). Running the auto-runner is equivalent to the manual
> invocation above.

#### Record the connector folder path, then markpass the checkpoint

After the generator exits 0, do TWO things, in order:

**1. Write the `Connector Folder Path` identity column.** Record the
connector folder relative to the ConnectUs `connectors/` root —
`connectors/<slugged Connector ID>` — into the CSV via `set-connector-path`.
The slug is the **same mapping the generator uses on disk**
([`title_to_slug()`](connectus_migration/manifest_generator.py:211)): take the
`Connector ID` column, lowercase it, and replace internal whitespace runs with
single dashes (collapsing any `---` to `-`). This guarantees the recorded path
matches the folder the generator just wrote, so Step 11's param-parity resolver
(which reads `Connector Folder Path`) and Step 9's handler-coverage resolver
both find the connector without a manual fix-up.

```bash
# slug = Connector ID, lowercased, spaces → dashes (e.g. "AWS" → "aws",
#        "Cisco Security" → "cisco-security", "Atlassian Automation and
#        Collection" → "atlassian-automation-and-collection")
python3 content/connectus/workflow_state.py set-connector-path "<Integration ID>" "connectors/<slugged Connector ID>"
```

> The `Connector ID` (NOT the Integration ID) is the slug source — every
> integration in a multi-integration connector (e.g. all `AWS - *`
> integrations) shares ONE `connectors/<slug>/` folder, exactly as Step 8's
> generator scaffolds them. `set-connector-path` is an identity-column write:
> it does NOT cascade a workflow reset.

**2. Markpass the checkpoint:**

```bash
python3 content/connectus/workflow_state.py markpass "<Integration ID>" "generated manifest"
```

Prerequisite: `Params to Commands` must be set (valid JSON). The state
machine enforces this and tells you what's missing.

### Step 9: `handler param coverage`

Verify every non-hidden integration YML param is covered by the generated
connector handler. This checkpoint sits between `generated manifest`
(Step 8) and `run manifest make validate` (Step 10).

#### Run the coverage check (reference-aligned I/O)

The script resolves BOTH the handler `handler.yaml` and the integration YML
from the workflow CSV id (via [`workflow_state.py`](workflow_state.py)'s gate
resolvers — the same source `run manifest make validate` uses), mirroring
[`check_param_defaults.py`](check_param_defaults.py) /
[`check_auth_parity.py`](check_auth_parity.py) /
[`check_command_params.py`](check_command_params.py). Pass `--json` to get the
structured envelope on stdout:

```bash
python3 content/connectus/check_handler_param_coverage.py \
  --integration-id "<Integration ID>" --json
```

The stdout JSON envelope is
`{"integration", "pass", "missing", "ignored_params"}`:

- **`pass`** — top-level boolean. `true` ⇒ every non-hidden YML param is
  covered. **Branch on this.**
- **`missing`** — the sorted list of non-hidden YML params NOT covered by the
  handler (the cause of a `false`).
- **`ignored_params`** — the params the script deliberately excludes from the
  coverage requirement (the `IGNORED_PARAMS` constant in
  [`check_handler_param_coverage.py`](check_handler_param_coverage.py:110) —
  mirroring fields, etc.). Surfaced so you can see exactly what was excluded.

(The legacy explicit-path form
`--handler-path <handler.yaml> --integration-yml <yml>` is still supported for
standalone runs; inside the workflow use `--integration-id`.)

Exit codes mirror the reference analyzers: `0` = pass, `1` = at least one
param missing, `2` = usage / resolution error.

#### This step FAILS the workflow when the script fails

**If `pass` is `false` (exit `1`), do NOT `markpass`.** Treat a non-empty
`missing` list as a hard stop. Present the `missing` and `ignored_params`
lists to the user, then **pause and wait for the user's explicit decision** —
the AI must NOT pick a resolution on its own. Offer exactly these three
options:

1. **Mark-pass anyway.** The user judges the missing params are acceptable
   to skip. Only then run
   `markpass "<Integration ID>" "handler param coverage"`.
2. **Add some params to the `IGNORED_PARAMS` constant.** The user names
   which params to add to
   [`IGNORED_PARAMS`](check_handler_param_coverage.py:110); the AI edits the
   constant ONLY for the params the user explicitly approved, re-runs the
   check, and proceeds. **Under no circumstances may the AI decide on its own
   to add any param to `IGNORED_PARAMS`** — that constant is changed only on
   an explicit user instruction naming the params.
3. **Fix an earlier step and re-run from there.** The missing param indicates
   an upstream input was wrong (e.g. a param mis-routed in
   `Params to Capabilities`, or an `Auth Details` / `other_connection`
   classification error). Go back to the relevant step (Step 2 `set-auth`,
   Step 7 `set-params-to-capabilities`, etc.), correct the input, regenerate
   the manifest (Step 8), and re-run this check.
4. **Force-override the gate (`--force`).** When the user explicitly judges
   the uncovered params are known-safe to skip — e.g. a **deprecated,
   label-less auth alternative** (a `type: 9` credentials pair whose only
   label is a `displaypassword` reading "…(Deprecated)" and which the code
   treats as a mutually-exclusive fallback) — the coverage checker accepts a
   `--force` flag. It STILL computes and reports the uncovered params (they
   remain in `missing`) but exits `0` and sets `"forced": true` in the JSON
   envelope, so the override is auditable and the real gap is never hidden:

   ```bash
   # direct checker run (transparency): shows missing + forced:true, exits 0
   python3 content/connectus/check_handler_param_coverage.py \
     --integration-id "<Integration ID>" --json --force
   ```

   To make the **self-executing `markpass` gate** apply the override, set the
   `CONNECTUS_HANDLER_COVERAGE_FORCE` env var (the gate appends `--force` when
   it is truthy):

   ```bash
   CONNECTUS_HANDLER_COVERAGE_FORCE=1 \
     python3 content/connectus/workflow_state.py markpass \
     "<Integration ID>" "handler param coverage"
   ```

   Prefer `--force` over editing `IGNORED_PARAMS` when the skip is a
   one-off, integration-specific judgment (the env var/flag is scoped to a
   single run and does not silently affect every other integration the way a
   shared-constant edit does). Like option 2, `--force` is used ONLY on the
   user's explicit instruction.

Only after the user picks an option and the resulting state is clean (or the
user explicitly chose mark-pass / force) do you run
`markpass "<Integration ID>" "handler param coverage"`.

### Step 10: `run manifest make validate`

This is a **self-executing gate**: `markpass` RUNS `make validate` in the
ConnectUs repo and only writes the checkpoint marker if it exits 0 (no
bypass — mirrors the `precommit` gate at Step 14 and the auth-parity gate
inside `set-auth`).

```bash
python3 content/connectus/workflow_state.py markpass "<Integration ID>" "run manifest make validate"
```

Under the hood this runs `make validate` (JSON Schema + OPA validation of
all connectors) from the ConnectUs repo root. The ConnectUs repo is the
**shared-workspace sibling** of the content repo, resolved as
`<parent-of-content-repo>/unified-connectors-content`. Override the
location with the `CONNECTUS_REPO_DIR` env var when the layout differs:

```bash
CONNECTUS_REPO_DIR=/path/to/unified-connectors-content \
  python3 content/connectus/workflow_state.py markpass "<Integration ID>" "run manifest make validate"
```

If `make validate` fails, the markpass is rejected with the command's exit
code and an output tail — fix the connector manifest in the ConnectUs repo
and re-run the markpass. To explicitly reset the checkpoint:

```bash
python3 content/connectus/workflow_state.py fail "<Integration ID>" "run manifest make validate"
```

#### Recommended: run `make validate` directly first (fast feedback)

**Always run `make validate` yourself before relying on the markpass gate**
— it gives you the schema/OPA errors directly and lets you iterate without
the state-machine ordering constraint (the markpass for this step is
rejected until the earlier steps are complete, but a manual `make validate`
can be run at ANY time once `connectors/<slug>/` exists, e.g. right after
Step 8 generates the manifest). Scope it to the single connector you just
generated with `connector=<path>` so it runs in seconds instead of
validating every connector in the repo:

```bash
cd "$CONNECTUS_REPO_DIR"
make validate connector=connectors/<slug>          # single connector (fast)
make validate connector=connectors/<slug> json=1   # machine-readable output
make validate                                       # ALL connectors (what the gate runs)
```

`make validate` runs two passes — **JSON Schema** validation then **OPA**
policy validation — and prints `✅ <slug>: VALID` / a non-zero exit with
the offending rule on failure. A clean run ends with
`All validations completed successfully!`. Fix any reported error in the
connector manifest, re-run the single-connector command until it is green,
*then* let the markpass gate (which runs the full `make validate`) record
the checkpoint.


### Step 11: `param parity test passes`

#### Machine prerequisites (one-time per engineer)

> **`gke-gcloud-auth-plugin` must be on PATH** before `session_setup.py` will
> pass. On macOS with Homebrew-installed gcloud, the plugin is bundled in the SDK
> but is **not** symlinked onto PATH (the cask only links `gcloud`/`gsutil`/`bq`).
> The binary lives next to the real gcloud, e.g.
> `/opt/homebrew/share/google-cloud-sdk/bin/gke-gcloud-auth-plugin`. Fix:
>
> ```bash
> echo 'export PATH="$(dirname "$(readlink -f "$(which gcloud)")"):$PATH"' >> ~/.zshrc && exec zsh
> gke-gcloud-auth-plugin --version
> ```
>
> **Do NOT rely on these — they do nothing here:**
> - `gcloud components install gke-gcloud-auth-plugin` reports "All components
>   are up to date" but is a **no-op** for Homebrew-managed gcloud (the component
>   manager is disabled).
> - `brew install gke-gcloud-auth-plugin` fails ("No formulae or casks found") —
>   there is **no** standalone formula; the plugin ships inside the
>   `google-cloud-sdk` cask.
>
> This is a **one-time machine setup**: once the SDK bin is on PATH it persists
> for all future runs.

#### Step 13.0 — Session gate (deterministic; this is what makes setup ONE-TIME)

The param-parity runtime needs a live GKE port-forward + gcloud credentials,
established ONCE per work session by a **human** in a normal terminal on the
**israel-gw VPN**. The agent does NOT set this up and does NOT rely on remembering
whether it already asked. Instead, **every time you reach Step 13, first run this
deterministic check** (it is silent, needs no human, and does not establish
anything):

```bash
python3 content/connectus/runtime_demisto.params_parity/session_setup.py --check
```

Branch on its exit code:

* **exit `0` (`SESSION_READY: ...`)** — a live session already exists. **Proceed
  directly to Step 13.1. Do NOT prompt the user.** This is the normal case for
  every integration after the first — the check passes silently, so you never
  re-ask.
* **exit non-zero (`SESSION_NOT_READY: ...`)** — no live session yet (first run
  of the batch, or the session expired / gcloud auth died). ONLY THEN pause and
  ask the user to run, in their terminal on the israel-gw VPN:
  ```bash
  python3 content/connectus/runtime_demisto.params_parity/session_setup.py
  ```
  (If the message says auth expired, they run `gcloud auth login` first.) Wait
  for the user to reply that it printed `✅ SESSION READY`, then re-run the
  `--check` above to confirm exit `0`, and proceed.

Because liveness is a **checked fact** (not a remembered action), setup is
naturally one-time: the human runs `session_setup.py` once, and every subsequent
Step 13 in the batch sees `--check` → exit `0` and continues unattended.

> At the END of the batch, ask the user (once) to run
> `python3 content/connectus/runtime_demisto.params_parity/session_teardown.py` to stop
> the port-forward.
>
> One-time host setting (not something the agent can set): the idex
> **Auto-Approve → Execute** toggle must be ON so the per-integration commands
> run unattended.

#### Step 13.1 — Run the atomic wrapper

> **Prerequisite — `Connector Folder Path` must be set.** The param-parity
> resolver looks up the connector tree from the pipeline CSV's
> `Connector Folder Path` column. Before this step can run, that cell MUST be
> populated:
>
> ```bash
> python3 content/connectus/workflow_state.py set-connector-path "<Integration ID>" connectors/<slug>
> ```
>
> If it is unset, `deploy_and_test.py` returns exit `11` (parity setup-blocked).

Run the **atomic deploy + test wrapper** — ONE command per integration (from the
content-repo root; no `cd`). It assumes the live session (auto-reviving a dead
port-forward), acquires the per-tenant lock, deploys the whole manifest to the
`.env` tenant, runs the param-parity test, and releases the lock (always, via
`try/finally`):

```bash
python3 content/connectus/runtime_demisto.params_parity/deploy_and_test.py --integration-id "<Integration ID>"
```

Branch on the wrapper's exit code (do NOT re-interpret stdout):

* **`0` — deployed + parity PASSED.** Apply the **markpass policy** in Step 13.2.
* **`10` — parity FAILED (real diff).** Do NOT markpass. Read the persisted
  envelope (`results/<connector>__<integration>__<ts>.json`, path echoed on the
  `Result written:` line) and tell the user exactly which params are
  `MISSING_IN_CONNECTOR` / `EXTRA_IN_CONNECTOR` / `VALUE_MISMATCH`, then fix the
  connector YAMLs and re-run the wrapper.
* **`11` — parity BLOCKED (setup).** Do NOT markpass. Most common causes:
  (a) **session not ready** — go back to Step 13.0 (ask the user to run
  `session_setup.py`; if it says gcloud auth expired, `gcloud auth login` first).
  Note: a merely-dead port-forward is auto-revived, so a session exit `11` means
  auth/setup that needs the human. (b) `Connector Folder Path` unset → run
  `set-connector-path`. (c) handler not on disk / `REPO_DIR` unset. A GKE
  control-plane timeout (`Unable to connect to the server: dial tcp <ip>:443:
  i/o timeout` / `Failed to find UCP shell pod`) means the host is off the
  `israel-gw` VPN — ask the user to connect and re-run `session_setup.py`.
* **`20` — deploy FAILED.** Do NOT markpass. Report the failed GitLab jobs +
  pipeline URL; the user fixes the cause and re-runs the wrapper.
* **`21` — deploy TIMEOUT.** Do NOT markpass. Report the still-running pipeline
  URL; re-run later.
* **`30` — tenant lock BUSY (could not acquire).** Do NOT markpass and do NOT
  auto-retry. Report the holder (shell id / integration / since-when) and the
  options to the user: (a) wait and retry later, (b) use a different tenant,
  (c) `python3 content/connectus/runtime_demisto.params_parity/tenant_lock.py force-unlock --tenant <X>` (run from the idex parent cwd as-written, no `cd`) if the holder is dead.

#### Step 13.2 — Markpass policy for exit 0 (confidence-gated)

On exit `0`, read the persisted results envelope and decide:

* **AUTO-markpass (no prompt) when ALL hold** — confident clean pass:
  * `n_fail == 0`, AND
  * no `credentials` `VALUE_MISMATCH`, AND
  * no unexpected `OK_IGNORED` beyond the known hard-ignore set
    (`__params_parity_dump__`, `instance_name`, `ucp_credentials`).
  ```bash
  python3 content/connectus/workflow_state.py markpass "<Integration ID>" "param parity test passes"
  ```
  Then move straight to the next integration (no confirmation) — this is what
  makes an unattended batch possible.
* **PAUSE — present the results + `per_param` and ASK for ACK** when the
  confidence conditions are NOT all met (e.g. a `credentials` `VALUE_MISMATCH`,
  unexpected ignored params, or anything that makes you unsure). Only markpass
  after the user's explicit ACK.

> Deliberate change from the old "exit 0 → always markpass" contract: confident
> clean passes are auto-marked; failures and low-confidence results are escalated.

The wrapper persists every run under `results/` (per-run envelope JSON +
`ledger.csv`); the `param parity test passes = ✅` cell in the pipeline CSV is the
only durable pass recorded.

### Step 12: `code reviewed`

After code review is complete:

```bash
python3 content/connectus/workflow_state.py markpass "<Integration ID>" "code reviewed"
```

### Step 13: `code merged`

After the code is merged to the branch:

```bash
python3 content/connectus/workflow_state.py markpass "<Integration ID>" "code merged"
```

### Step 14: `precommit/validate/unit tests passed`

**Trigger.** Only run pre-commit / unit tests when the migration actually
touched the integration's own source. Run them if EITHER:

- a `Release Notes` file was produced for this integration (Step 15
  required one — i.e. `Release Notes` cell has `"required": true`), OR
- `git diff HEAD --name-only -- <integration>.py <integration>.yml`
  is **non-empty** (the .py and/or .yml were modified).

If NEITHER condition holds (no RN, and the .py/.yml were untouched), there
is nothing for pre-commit/unit tests to verify — **skip the run** and pass
the checkpoint directly:

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "precommit/validate/unit tests passed"
```

Otherwise (RN produced OR .py/.yml changed), run pre-commit, validate, and
unit tests via demisto-sdk pre-commit (Docker):

```bash
demisto-sdk pre-commit -i Packs/<PackName>/Integrations/<IntegrationName>/
```

When everything passes (Yuval decides which checks may be skipped):

```bash
python3 connectus/workflow_state.py markpass "<Integration ID>" "precommit/validate/unit tests passed"
```

> **Workaround note.** `demisto-sdk pre-commit` crashes on the second
> and subsequent invocations with `FileExistsError: [Errno 17] File
> exists: '/Users/<you>/.demisto-sdk/cache/pre-commit'`. Delete the
> cache dir before re-running:
>
> ```bash
> rm -rf ~/.demisto-sdk/cache/pre-commit
> demisto-sdk pre-commit -i Packs/<PackName>/Integrations/<IntegrationName>/
> ```

### Step 15: `Release Notes` (data column)

This step gates the migration on a release-notes file when the
integration's own .py/.yml were modified by the migration.

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


## Deploying to a dev tenant

Use this to push the generated ConnectUs connector manifest to a live dev
tenant for testing (e.g. after Step 8 generates the manifest, or when
verifying auth/params end-to-end). It is **not** a workflow checkpoint —
it is an out-of-band testing action you can run any time the connector
files exist in the ConnectUs repo.

The tool is
[`connectus/runtime_demisto.params_parity/deploy.py`](runtime_demisto.params_parity/deploy.py:1)
(note the `runtime_demisto.params_parity/` SUBDIRECTORY — it is NOT
directly under `connectus/`). What it does, in order:

1. **Git ops** (skipped with `--skip-git`): `git fetch`, then **HARD-RESET**
   `CONNECTUS_BRANCH` to `origin/<BASE_BRANCH>` (default `stable`) and
   **force-push** it. ⚠️ This `git reset --hard` **DISCARDS any
   uncommitted work in the ConnectUs repo** — including a freshly
   generated `connectors/<slug>/` that has not been committed.
2. **Trigger** a GitLab CI *skinny* pipeline on `CONNECTUS_BRANCH` with
   variables `SKINNY_PIPELINE=true`, `TENANT_IDS=<tenant>`,
   `OVERRIDE_REASON=<reason>`.
3. **Poll** the pipeline to completion and print a summary (pipeline URL,
   status, duration, failed jobs).

### CRITICAL: commit before you deploy

Because Step 1 hard-resets to base, the **only safe way** to deploy a
just-generated manifest is:

1. **Commit** the new `connectors/<slug>/` onto `CONNECTUS_BRANCH` in the
   ConnectUs repo (`$CONNECTUS_REPO_DIR`).
2. **Push** that branch to `origin` yourself.
3. Run deploy with **`--skip-git`** so it does NOT reset/force-push — it
   just triggers + polls the pipeline against the already-pushed branch.

Running deploy **without** `--skip-git` against uncommitted manifest work
will wipe it. Only run the full git flow when the work you want deployed
is already committed on `origin/<BASE_BRANCH>` (rare during migration).

> **SSH / signing gotchas (environment-dependent).** The ConnectUs repo
> may be configured to SSH-sign commits (`commit.gpgsign=true`,
> `gpg.format=ssh`) and push over SSH (`git@gitlab...`). If the configured
> key is missing/unloadable, commits fail with `Couldn't load public key`
> and pushes fail with `Permission denied (publickey)`. Do **NOT** edit
> the user's git config to work around this. For a one-off commit you may
> use `git commit --no-gpg-sign` (does not persist config). If `ssh`/push
> is unavailable in your environment, ask the user to `git push` the
> branch themselves, then run deploy with `--skip-git`.

### Canonical invocation

```bash
# (1) In the ConnectUs repo: commit + push the manifest first.
cd "$CONNECTUS_REPO_DIR"
git add connectors/<slug>/
git commit -m "Add UCP manifest for <Integration ID>"   # add --no-gpg-sign if signing is broken
git push origin "$CONNECTUS_BRANCH"

# (2) From the idex parent cwd: trigger + poll the pipeline (no git ops).
python3 content/connectus/runtime_demisto.params_parity/deploy.py --skip-git --tenant <TENANT_ID>
```

### Configuration (priority: CLI args > env vars > .env > defaults)

Read from the unified root `.env` via `load_env()`:

| Var / flag | Purpose | Default |
|---|---|---|
| `--tenant` / `TENANT_ID` | Tenant ID(s) to deploy to (comma-separated). Sent to CI as `TENANT_IDS`. | (required) |
| `--branch` / `CONNECTUS_BRANCH` | Branch in the ConnectUs repo to deploy. | `xsoar` |
| `--base` / `BASE_BRANCH` | Branch `CONNECTUS_BRANCH` is hard-reset to (non-`--skip-git` only). | `stable` |
| `--repo-dir` / `CONNECTUS_REPO_DIR` | Local ConnectUs repo clone (git ops run here). | (required for git ops) |
| `--reason` / `OVERRIDE_REASON` | Dev-override reason string. | `dev-testing` |
| `--gitlab-url` / `GITLAB_URL` | GitLab instance URL. | `https://gitlab.xdr.pan.local` |
| `--token` / `GITLAB_TOKEN` | GitLab PAT with `api` scope. | (required) |
| `--skip-git` | Skip the reset/force-push; only trigger + poll. | off |
| `--poll-interval` / `--max-wait` | Polling cadence / timeout (seconds). | 2 / 600 |
| `--diagnose` | Run GitLab connectivity diagnostics (HTTPS-only) and exit. | off |

The GitLab project is hardcoded
(`xdr/development/platform/unified-connectors-content`). Exit codes:
`0` success, `1` pipeline failed (prints failed jobs), `2` timeout.

> **Troubleshooting.** A `GITLAB_TOKEN`/connectivity problem surfaces as
> 401/404 or a network error from the API calls — run
> `deploy.py --diagnose` to test DNS → TCP → TLS → API → pipeline trigger
> over HTTPS (no SSH needed) before debugging further.


## Error Recovery Commands

`fail` and `reset-to` share semantics. Both clear the named step and every later step that is **not** tagged `preserve_on_reset: true` in [`connectus/workflow_state_config.yml`](workflow_state_config.yml). Today only `Params to Commands` carries that tag (per [`workflow_state_config.yml:72`](workflow_state_config.yml:72)); the two adjacent data columns `Params for test with default in code` and `Params to Capabilities` deliberately set `preserve_on_reset: false`. The CLI prints `Preserved (preserve_on_reset=true): [...]` listing what was kept.

**Explicit-target carve-out:** if the user names a preserved step EXPLICITLY as the target of `fail`/`reset-to`, that one step IS cleared (the user's intent wins). Later preserved steps in the same blast radius are still preserved. Example: with the 2026-05 schema, `fail "Auth Details"` keeps `Params to Commands`; `fail "Params to Commands"` clears `Params to Commands` itself (there are no later preserved data columns to keep).

`set-auth` and plain `reset` IGNORE `preserve_on_reset` — see the description of each.

### Fail a checkpoint (clears it and all subsequent non-preserved steps)

```bash
python3 content/connectus/workflow_state.py fail "<Integration ID>" "<checkpoint name>"
```

### Reset to a specific checkpoint (alias of fail)

```bash
python3 content/connectus/workflow_state.py reset-to "<Integration ID>" "<checkpoint name>"
```

### Reset all workflow columns (no preserve carve-out)

```bash
python3 content/connectus/workflow_state.py reset "<Integration ID>"
```

## Dashboard and Batch Commands

```bash
# ONE-CALL CONTEXT (preferred read for a single integration): emits all
# data columns + file paths + current step + auth-ignore set as one JSON
# document. Replaces separate status + show-step + files + auth-params calls.
python3 content/connectus/workflow_state.py context "<Integration ID>"

# Machine-readable status (JSON list, one element per id)
python3 content/connectus/workflow_state.py status "<Integration ID>" --format=json

# See all integrations with progress
python3 content/connectus/workflow_state.py dashboard

# See all integrations at a specific checkpoint
python3 content/connectus/workflow_state.py at-step "<checkpoint name>"

# See all integrations with any progress
python3 content/connectus/workflow_state.py status-all

# See all integrations assigned to a specific person
python3 content/connectus/workflow_state.py list-by-assignee "<assignee name>"

# Show one column's value for an integration (pretty-prints JSON)
python3 content/connectus/workflow_state.py show-step "<Integration ID>" "<column>"

# Set Auth Details (validates JSON schema, resets workflow to 'generated manifest')
python3 content/connectus/workflow_state.py set-auth "<Integration ID>" '<Auth Details JSON>'
```

### Connector- and assignee-scoped batch commands

These power the [Assignee batch flow](#assignee-batch-flow) and [Connector batch flow](#connector-batch-flow).

```bash
# All distinct connector ids with per-connector counts (total / in progress / complete)
python3 content/connectus/workflow_state.py list-connectors

# All integrations belonging to one connector (with assignee + current step)
python3 content/connectus/workflow_state.py list-by-connector "<connector_id>"

# Bulk-assign every integration in a connector to one owner.
# NEVER cascades — existing migration progress is preserved.
python3 content/connectus/workflow_state.py set-assignee-by-connector "<connector_id>" "<assignee name>"

# `next` flags for batch flows:
python3 content/connectus/workflow_state.py next --mine                         # in-progress + assigned to current git user (alias of bare `next`)
python3 content/connectus/workflow_state.py next --connector "<connector_id>"   # in-progress integrations in that connector
python3 content/connectus/workflow_state.py next --connector "<id>" --mine      # intersection of the above
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
| `APIKey` | `api_key` | Single static secret (header / query param / single-secret HMAC). Two-or-more keys → `Passthrough`. Always `interpolated: true`. |
| `Plain` | `plain` | Single username + password pair (`username` + `password`). Always `interpolated: true`. |
| `Passthrough` | n/a | **All OAuth2 flows** — Client Credentials, JWT-bearer, Authorization Code (browser flow), Device Code, ROPC — plus Managed Identity, mTLS, dual-key API (Datadog, AWS, Akamai EdgeGrid, GitHub App), custom HMAC/signing, and anything else that doesn't cleanly fit `api_key` or `plain`. Always `interpolated: true`. **When in doubt, prefer `Passthrough`.** |
| `NoneRequired` | n/a | No authentication required |

> **OAuth2 flows classify as Passthrough — see §1.2.** The only values you may OUTPUT in `auth_types[].type` are `APIKey`, `Plain`, `Passthrough`, and `NoneRequired`.

> **ALL types present in `auth_types[]` are `interpolated: true`** (`APIKey`, `Plain`, `Passthrough` — `NoneRequired` emits no entry at all). Do NOT treat `interpolated: true` as a `Passthrough`-only flag; that asymmetric reading is the root cause of profiles being suggested without it. Whenever you author or suggest a profile of ANY type, it MUST carry `"interpolated": true`.



## Mode Switching Guidance

Different workflow steps are best handled in different modes:

| Step | Recommended Mode |
|------|-----------------|
| Analyzing auth class, understanding integration | Ask |
| Planning Params to Commands, designing mai nifest | Architect |
| Writing integration code, unit tests | Code |
| Fixing validation/test failures | Debug |
| Full migration lifecycle coordination | Orchestrator |

When switching modes, the skill will be re-loaded automatically if the user's request matches the skill trigger.
