# Release Notes → Pure Checkpoint — Design Proposal

> **STATUS: proposal.** Converts the `Release Notes` workflow step from a
> self-computing **data column** (JSON cell with a `{required, path, verified}`
> shape, auto-evaluated from `git diff` + a required substring) into a **pure
> checkpoint** marked with `markpass`, identical in mechanism to
> `generated manifest` / `code reviewed` / `code merged`.
>
> Authoritative current state for reference:
> - Step config: [`connectus/workflow_state_config.yml:112-118`](workflow_state_config.yml:112)
> - Setter CLI: [`cmd_set_release_notes`](workflow_state/cli.py:872)
> - Verdict compute: [`evaluate_release_notes_for_integration`](workflow_state/api.py:1324)
> - Shape validator: [`validate_release_notes`](workflow_state/validators.py:353)

---

## 1. Motivation

The current `Release Notes` step is over-engineered relative to the value it
delivers:

1. It is a **data column** carrying a JSON "shape"
   (`{"required": bool, "path": str|null, "verified": bool}`) when conceptually
   it is a yes/no "did the release notes get written" gate — i.e. a checkmark.
2. The workflow **re-implements verification** that the standard content
   tooling already does:
   - `evaluate_release_notes_for_integration` runs `git diff HEAD` on the
     integration's `.py`/`.yml` to decide whether RN is *required*
     ([`api.py:1232-1262`](workflow_state/api.py:1232)).
   - It scans `Packs/<Pack>/ReleaseNotes/` for the newest `N_N_N.md` and checks
     for the case-sensitive substring `"Enabled support for UCP"`
     ([`api.py:1288-1321`](workflow_state/api.py:1288)).
   - **`demisto-sdk validate` already fails a pack modified without a
     corresponding `ReleaseNotes/<version>.md`** (the `RN` rule family, e.g.
     `RN103`/`RN106` missing-release-notes checks). That validation runs in the
     **next** workflow checkpoint, `precommit/validate/unit tests passed`, and
     again in CI.
3. The agent already *does the work* (running
   `demisto-sdk update-release-notes` and editing the RN file) — that is an
   explicit run-through (no-prompt) operation in the skill's Interaction
   Policy. The state machine duplicating a correctness check on top of that
   adds maintenance surface (a setter, a verdict computer, a shape validator,
   and a test file) for no net coverage.

**Decision (per user):** the agent runs `demisto-sdk update-release-notes` and
whatever else is needed; the **workflow does not validate** — the standard
`demisto-sdk validate` rule enforces "pack touched ⇒ RN file present for the
right pack." `Release Notes` becomes a **pure `markpass` checkpoint**.

This aligns with cross-cutting decision #4 (one-shot project, no future
maintainer — don't carry tooling whose payoff exceeds the current pipeline)
and the Hints policy (don't re-implement a check the platform already owns).

---

## 2. Contrast with the auth-parity model (and why RN is different)

The user pointed at the auth-parity gate as a model. It is worth being explicit
about *why RN takes the opposite path*, because both are valid patterns for
different cases.

| | auth-parity (`set-auth`) | Release Notes (proposed) |
|---|---|---|
| Verification cost | Expensive (docker subprocess, `check_auth_parity`) | Cheap, but **already done elsewhere** |
| Is it duplicated elsewhere? | **No** — nothing else verifies UCP auth parity | **Yes** — `demisto-sdk validate` (RN rules) + CI |
| Right pattern | Self-executing gate **inside the setter** | **Pure checkpoint** — let the existing gate (validate) do it |
| Mechanism | `_evaluate_parity_for_set_auth` reject-before-commit ([`api.py:655`](workflow_state/api.py:655)) | `apply_step_action(..., cfg.markers.check, ...)` bookkeeping ([`cli.py:1199`](workflow_state/cli.py:1199)) |

The general rule this establishes: **build a self-executing CLI gate only when
the check is otherwise unowned.** When the platform already enforces it
(validate/unit tests), the workflow step is a plain checkpoint and the *real*
enforcement lives in the `precommit/validate/unit tests passed` checkpoint.

---

## 3. Target state

### 3.1 New step definition

Replace the `data` step at
[`workflow_state_config.yml:112-118`](workflow_state_config.yml:112) with a
checkpoint:

```yaml
  - name: "Release Notes"
    kind: checkpoint
    optional: false
    setter: null
    description: >
      Release notes written for the integration. The agent runs
      `demisto-sdk update-release-notes -i Packs/<PackName>` and edits the
      resulting ReleaseNotes/<Version>.md as needed. This is a pure checkpoint:
      correctness (a modified pack having a matching RN file) is enforced by
      demisto-sdk validate in the next checkpoint (precommit/validate/unit
      tests passed) and in CI — the workflow does not re-validate here.
```

Ordering is unchanged: `Release Notes` stays between `run manifest make
validate` and `precommit/validate/unit tests passed`, so the validate gate
that actually enforces RN presence runs immediately after.

### 3.2 What this changes about the step

- `kind: data` → `kind: checkpoint`. It is now marked with
  `markpass "<id>" "Release Notes"` (or `skip` if `optional` — but it stays
  required) instead of `set-release-notes`.
- `setter: set-release-notes` → `setter: null`.
- `json_schema` / `preserve_on_reset` lines are removed (checkpoints have no
  schema; `preserve_on_reset` was already `false`).
- No JSON cell. The cell holds `✅` / `❌` / `N/A` like every other checkpoint,
  governed by `markers.checkpoint_done_values`.

---

## 4. Code changes required

These are scoped to "make `Release Notes` behave exactly like the other
checkpoints, and delete the bespoke RN machinery." No new gate hook is
introduced (that was the alternative the user rejected).

### 4.1 Config — `workflow_state_config.yml`
- Rewrite the `Release Notes` step block as in §3.1.

### 4.2 CLI — `workflow_state/cli.py`
- **Delete** `cmd_set_release_notes` ([`cli.py:872-950`](workflow_state/cli.py:872)).
- Remove `set-release-notes` from the command dispatch table.
- Remove any usage/help text referencing `set-release-notes`.
- No change to `cmd_markpass` — `Release Notes` now flows through the existing
  checkpoint markpass path unchanged ([`cli.py:1133`](workflow_state/cli.py:1133)).

### 4.3 API — `workflow_state/api.py`
Delete the now-unused RN helpers (verify they have no other callers first):
- `evaluate_release_notes_for_integration` ([`api.py:1324-1353`](workflow_state/api.py:1324))
- `_release_notes_trigger_required` ([`api.py:1232-1262`](workflow_state/api.py:1232))
- `_integration_owns_files` ([`api.py:1204-1229`](workflow_state/api.py:1204)) — **only if** not shared by other code (check; it may be reusable/used elsewhere — if so, keep it).
- `find_newest_release_notes_file` ([`api.py:1288-1309`](workflow_state/api.py:1288))
- `verify_release_notes_substring` ([`api.py:1312-1321`](workflow_state/api.py:1312))
- `_VERSION_FILENAME_RE` ([`api.py:1265-1268`](workflow_state/api.py:1265)) and the `RELEASE_NOTES_REQUIRED_SUBSTRING` constant ([`api.py:1201`](workflow_state/api.py:1201)) — remove if no other references.

### 4.4 Validators — `workflow_state/validators.py`
- **Delete** `validate_release_notes` ([`validators.py:353-427`](workflow_state/validators.py:353)).
- Remove its `"release_notes"` registration from `_NAMED_VALIDATORS`
  ([`validators.py:547`](workflow_state/validators.py:547)).

### 4.5 Tests
- Remove / rewrite `connectus/workflow_state/tests/test_release_notes.py`
  (the shape/verdict tests no longer apply). Add a minimal assertion that
  `Release Notes` is a checkpoint that can be `markpass`ed and `fail`ed like
  any other (likely already covered by generic checkpoint tests — prefer
  deleting the bespoke file over keeping dead assertions).

---

## 5. Data migration (existing CSV rows)

`schema_version` is currently `2`. Changing a column's `kind` from `data`
(JSON cell) to `checkpoint` (marker cell) is a **data migration** — bump to
`schema_version: 3` and migrate existing cells:

| Existing `Release Notes` cell | Migrated value | Rationale |
|---|---|---|
| `{"required": false, ...}` | `N/A` | RN was not required (no `.py`/`.yml` diff). |
| `{"required": true, "verified": true, ...}` | `✅` | RN existed and was correct. |
| `{"required": true, "verified": false, ...}` | `` (empty) | Was effectively not-yet-passed; agent must `markpass` after writing RN. |
| empty / unset | `` (empty) | Not reached yet. |

A one-shot migration script (or a normalization branch keyed on
`schema_version` bump in `load_csv`) performs this rewrite. Given cross-cutting
#4 (one-shot project), a standalone migration script run once is preferable to
permanent normalization code.

> **Note on `N/A` for required=false:** mapping not-required → `N/A` matches the
> existing semantic (the bespoke evaluator auto-passed required=false). If you'd
> rather force the agent to always eyeball RN, map it to empty instead — but
> that creates churn on rows that legitimately touched no integration code.
> Recommend `N/A`.

---

## 6. Skill (`connectus-migration-SKILL.md`) updates

- **Interaction Policy table:** remove the `set-release-notes` row from the
  "4 JSON-write pause-and-confirm checkpoints" (it drops to 3 JSON writes:
  `set-auth`, `set-params-to-commands`, `set-param-defaults`,
  `set-params-to-capabilities` — recount and fix the prose that says "4").
- **Run-through list:** `Release Notes` becomes a `markpass` (already in the
  no-prompt list).
- Document the new step semantics: *"the agent runs
  `demisto-sdk update-release-notes` and edits the RN file; then `markpass
  "Release Notes"`. Correctness is enforced by the next checkpoint's
  `demisto-sdk validate`, not by the RN step itself."*
- Update the column inventory ("6 data columns / 6 checkpoints") → **5 data
  columns / 7 checkpoints**, and any "12 workflow columns" counts that break
  down by kind. Total workflow columns stays **12**; CSV total stays **15**.
- Remove references to the RN JSON shape from the skill and from
  `column-schemas.md`.
- **Keep the `"Enabled support for UCP"` substring as a skill instruction.**
  It is no longer enforced by tooling (see §7.3 — decided), so the skill must
  carry it explicitly. In the new `Release Notes` step procedure, instruct the
  agent: *"When editing the generated `ReleaseNotes/<Version>.md`, the entry
  MUST contain the exact text `Enabled support for UCP` (case-sensitive). Verify
  this before `markpass`."* Add the same expectation to the `code reviewed`
  checkpoint guidance so the reviewer confirms the wording.

---

## 7. Risks / things to verify before implementing

1. **Confirm `demisto-sdk validate` actually fails on missing RN** for this
   repo's config (the RN rule family). It does by default; verify it is not
   suppressed in this repo's validation config. If it *is* suppressed, removing
   the bespoke check would lose coverage and we should reconsider.
2. **`_integration_owns_files` reuse.** Grep before deleting — it may be useful
   to other connectus tooling. Keep it if shared.
3. **The `"Enabled support for UCP"` substring is handled by skill + review
   (DECIDED).** That string is a connectus-specific RN convention, not something
   `demisto-sdk validate` checks, so it is intentionally no longer enforced by
   tooling. Coverage moves to two human/agent layers instead:
   - the **skill** instructs the agent to include the exact case-sensitive text
     in the RN entry before `markpass`ing `Release Notes` (see §6), and
   - the **`code reviewed`** checkpoint confirms the wording is present.

   This is a deliberate trade: we accept losing the automated substring check in
   exchange for deleting the bespoke RN machinery, consistent with cross-cutting
   #4 (one-shot project). No further action required beyond the §6 skill edits.
4. **CSV migration correctness** — run the migration on a copy and diff before
   committing; never hand-edit the CSV (Critical Rule #1).

---

## 8. Out of scope (explicitly NOT changing)

- `make validate` checkpoint, `precommit/validate/unit tests passed`,
  `param parity test passes` remain **checkpoints the agent runs and then
  `markpass`es**. The user's broader question ("can the workflow itself run
  validate/tests like the auth-parity test?") is a *separate* proposal: those
  checks are expensive docker/subprocess runs, and the agent already runs them
  as run-through operations. Turning them into self-executing CLI gates
  (markpass actually shells out to `demisto-sdk pre-commit`) is feasible using
  the auth-parity insertion point (`cmd_markpass` between
  [`cli.py:1170`](workflow_state/cli.py:1170) and
  [`cli.py:1199`](workflow_state/cli.py:1199) + a per-`Step` `gate` field), but
  is intentionally deferred — see §2's rule. If wanted, that becomes its own
  design doc.
