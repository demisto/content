---
name: connectus-documentation
description: Use when backfilling human-facing documentation onto already-migrated GROUPED ConnectUs connectors (the 5 YAMLs exist but lack docs). Triggers like 'document connector <slug>', 'do the docs for <connector>', 'what connector needs docs next', 'continue docs', 'document everything assigned to me', 'document the next 10 connectors'.
---

<!--
  STAGING COPY. The `.roo/` folder is protected, so this file is kept here in the
  toolkit. To install the skill, copy this file to:
      .roo/skills/connectus-documentation/SKILL.md
  (and adjust the relative links below, which are written for the .roo/ location).
-->

# ConnectUs Connector Documentation Skill

Backfills documentation onto **grouped** connectors under
`unified-connectors-content/connectors/<slug>/`. The migration created the five
structural YAMLs (`connector`, `capabilities`, `connection`, `configurations`,
`summary`) but without human-facing docs. This skill authors them.

Design of record: `plans/connector-documentation-skill-design.md`.

## Topology / cwd (read first)

The idex shell cwd is the **PARENT** dir that contains `content/` and
`unified-connectors-content/` as **siblings**. The Python toolkit lives under
`content/connectus/connectus_docs/`. **It requires `ruamel`, which is in the
poetry venv** — run every command via poetry, from `content/`:

```
cd content && poetry run python -m connectus.connectus_docs.<module> ...
```

Do NOT `cd` deeper or the `content/` prefix would resolve to `content/content/...`.

## Pipeline (A → E)

```
A RESOLVE → B GATHER → C AUTHOR → D VALIDATE → E APPLY → state
 (script)    (script)    (YOU)      (script)    (script)  (script)
```

The scripts are deterministic and tested (108 unit tests). **Your only judgment
job is stage C** — authoring `doc-spec.json` from the gathered sources under the
near-verbatim rules below. Everything else is a command.

| # | Stage | Command (run from `content/`) |
|---|-------|-------|
| scope | List candidates from CSV | `poetry run python -m connectus.connectus_docs.doc_state doc-find [<substring>]` (NEVER `ls connectors/`) |
| B | Gather cleaned sources | `poetry run python -m connectus.connectus_docs.gatherers <slug>` → JSON bundle |
| C | Author | YOU write the **staging** doc-spec at `unified-connectors-content/.doc_specs/<slug>.json` (NOT in the connector folder) |
| D | Validate (gate) | `poetry run python connectus/connectus_docs/validate_doc_spec.py <slug>` |
| E | Apply (dry-run) | `poetry run python connectus/connectus_docs/apply_doc_spec.py <slug>` |
| E | Apply (write) | `… apply_doc_spec.py <slug> --apply` (deletes the staging doc-spec on success) |
| state | Mark done | `poetry run python -m connectus.connectus_docs.doc_state set-doc-complete <slug>` |

> **The doc-spec is an INTERMEDIATE artifact, not a deliverable.** Write it to the
> git-ignored `unified-connectors-content/.doc_specs/<slug>.json` staging path
> (validate/apply default to that path when the arg is omitted). After a
> successful `--apply` it is auto-deleted, so it never lingers next to the
> connector's published YAMLs. Never write `doc-spec.json` into the connector folder.

**Pause for user approval before stage E `--apply`** (the only step that writes
the connector YAMLs). Stages B/C/D and the dry-run run straight through.

## Scope: the pipeline CSV is the ONLY source of truth (§3.1)

A connector is a valid documentation candidate **only if it has member rows in
`content/connectus/connectus-migration-pipeline.csv`** (matched on the
`Connector Folder Path` column). The `unified-connectors-content/connectors/`
directory contains folders that are **NOT** in the pipeline (other efforts, or
not-yet-migrated shells without grouped `view_groups[]`); documenting those is
always wrong.

**HARD RULE — never enumerate connectors from the filesystem.** Do NOT use
`ls connectors/`, glob, or directory walks to build a candidate list. To turn a
request like "document all the microsoft ones" into a list, ALWAYS use:

```
poetry run python -m connectus.connectus_docs.doc_state doc-find [<substring>]
```

`doc-find` lists connectors straight from the CSV (optional case-insensitive
substring on slug or Connector ID) with member count and ✅/blank status.
Connectors not in the CSV never appear — that is the guarantee that keeps
non-pipeline folders out. Trust `doc-find` over any directory listing. Defense in
depth: the gatherer also hard-stops (`ResolutionError`) on any slug with zero CSV
member rows.

## Single-connector flow

1. **Gather.** Run the gatherer (stage B). It returns ONE JSON payload per
   connector: cleaned, command-free, conditional-resolved per-member sources
   (`description_md` = PRIMARY, `gapfill` = READMEs), `description_md_len` (the
   length governor), bound `profile_ids` / `config_field_ids`, and
   `view_group_flags`.
   - **If the gatherer prints `{"error": ...}`** (a `ResolutionError`: missing
     connector folder, no CSV member rows, missing integration YML, or a missing
     PRIMARY `<integration>_description.md`) → **STOP and ask the engineer how to
     proceed** (`ask_followup_question`). Do NOT invent missing sources.
   - **If any `view_group_flags[].is_flag` is true** (id/label mismatch, §8.6) →
     surface it and ask the engineer; this often indicates a migration error.

2. **Author the doc-spec** (stage C) using ONLY the gathered payload. Shape:
   `content/connectus/connectus_docs/doc-spec.schema.json`. Apply the rules in
   the next section. Write it to the git-ignored staging path
   `unified-connectors-content/.doc_specs/<slug>.json` — **never** into the
   connector folder.

3. **Validate** (stage D). If it FAILs, fix the doc-spec and re-validate. Never
   apply a failing spec. Resolve every `__FLAG__` (don't paper over it).

4. **Apply dry-run** (stage E, no `--apply`). Review the diff of all 5 YAMLs.

5. **Apply for real** — only after user approval — with `--apply`.

6. **Mark done.** `doc_state set-doc-complete <slug>` marks ✅ on EVERY member
   row of the connector.

## Stage C authoring rules (the judgment)

> The single most important rule (§8.7): **help_text is the `description.md`,
> kept as close to VERBATIM as possible.** Do NOT reshape it into a new
> narrative. Do NOT enumerate YAML fields, invent auth schemes, or add prose.

> **ALWAYS read the README `gapfill` for EVERY member, even when `description_md`
> looks complete (§2.1).** You cannot know it is lacking — fully OR partially —
> until you actually check it. The gatherer ALWAYS includes `gapfill` when a README
> exists; it is never withheld. When gap-filling, merge a README fact ONLY when
> (a) it is crucial for the user to connect/configure AND (b) it is not already
> conveyed by `description_md`. Never bulk-copy the README; reasonably keep within > the length governor. 
> Crucial vendor-side setup (settings, scopes/permissions, an app/token to
> create on the vendor side, an admin toggle) is a prerequisite of authenticating —
> surface it in the CONNECTION help_text for that member/view_group (§8.3).

- **`connector.description`** (§8.1): fuse the overview/product-intro material
  across ALL members into a 1–4 line summary. The "what is this product" intro
  paragraphs from each `description_md` go HERE (not into help tiles). ≥10 chars.
  No usable source anywhere → `"__FLAG__: <why>"`.
- **`capabilities.items[]`** (§8.2): for each top-level capability id present in
  the connector, set `description` from the closed table
  `content/connectus/connectus_docs/capability_descriptions.json`. The apply
  step uses the table value verbatim; an unknown id is a flag.
- **`connection.view_groups[]`** (§8.3, OPTIONAL — §8.3b): help_text =
  the **connection portion** of that member's `description_md`, kept
  near-verbatim. Keep ALL links verbatim (`[text](url)`). Fix only obvious typos
  + invalid Markdown. ALWAYS check the member's `gapfill` (§2.1) even when the
  connection portion looks complete; merge a README fact ONLY when crucial to
  connect AND not already conveyed by `description_md` (minimal, never wholesale).
  - **NEAR-VERBATIM means COPY, NOT SUMMARIZE (§8.3c — HARD, enforced).** Do NOT
    paraphrase, condense, or "tidy up" the connection portion into your own
    shorter prose. Reproduce the source steps, lists, command syntax, and notes
    as written. In particular you MUST preserve, verbatim:
    1. **Every command name** the user runs (`!integration-auth-start`,
       `!CreateCertificate days=<n> password=<pw>`, `!DeleteContext all=yes`,
       `!microsoft-teams-generate-login-url`, …) — with its exact arguments.
       Genericizing ("run the authentication start command") is FORBIDDEN.
       → Enforced by §9.15 (dropped source command name = HARD error).
    2. **Every list** the source gives (e.g. "the following commands require the
       Authorization Code flow: …", a required-permissions/scopes list). Do not
       drop or shorten the items.
    3. **Operational/security notes** (e.g. "remember your password — you'll need
       it to create the instance", "delete the sensitive information by running
       `!DeleteContext all=yes`", required-permissions blocks). These are crucial
       and must NOT be dropped.
    4. **Every source link** (`[text](url)` and bare URLs). → Enforced by §9.10:
       a dropped source link in AUTHORED help_text is now a HARD error.
    When in doubt, keep MORE of the source, not less. The length governor (§2.2)
    soft-warns on bloat, but FIDELITY beats brevity — a faithful longer help_text
    is correct; a shorter summarized one that loses a command/list/note is a bug.
  Crucial vendor-side setup (scopes/permissions/settings, app/token to create,
  admin toggle) belongs HERE, since it is a prerequisite of authenticating.
  **help_text is OPTIONAL for a CLEAN/absent view_group — OMIT it when there is
  no substantive guidance and the view_group currently has no help_text. NEVER
  write boilerplate:** the validator HARD-rejects (§9.13) any help_text that
  equals the view_group label or matches a generic filler template
  ("Configuration[s] settings for X", "Connection[s] settings for X", "Settings
  for X", "X settings", "X configuration", "X configuration settings").
  **If an existing connection/config view_group help_text is boilerplate (§9.13 —
  it restates the label or matches "Connection/Configuration settings for X"), you
  MUST either replace it with substantive help_text or set `"help_text": null` to
  delete it. Omission is NOT allowed for boilerplate (omission leaves the
  migration boilerplate in place).** Removing existing help_text is a
  present→absent transition → show the user the existing text + get permission
  (see the permission matrix below). **The validator now AUDITS the final on-disk
  state (§9.13 audit), so unaddressed boilerplate HARD-fails Stage D even if your
  doc-spec never touched that view_group.**
- **`connection.profiles[]`** (§8.3a, MUST-author for jargon/empty/wrong; keep
  only genuinely clean copy): for EVERY profile in the bundle's
  `members[].profiles[]`, evaluate its CURRENT `title` and `description`.
  **You MUST emit a `connection.profiles[]` entry for EVERY profile whose
  current title/description contains jargon (`passthrough`, `plain`, or the raw
  `type` value e.g. `api_key`), is empty, or is wrong.** Only genuinely clear,
  accurate copy may be kept (omitted) — e.g. a generic-but-accurate `title: API
  Key` with no jargon is KEPT (do NOT restyle or embellish clear copy). Key each
  entry by profile `id`, set ONLY the field(s) you changed (just `title`, just
  `description`, or both), and write clear, to-the-point copy.
  **No invention (§12):** the wording must be derivable from the profile's auth
  type + the owning integration's purpose already in the sources — never a
  fabricated capability. Never reintroduce the banned jargon words. **The
  validator now AUDITS the FINAL on-disk profile state (§9.11c audit): any
  on-disk profile whose effective title/description still leaks jargon — because
  you left it unaddressed — HARD-fails Stage D.** Omit ONLY clean profiles.
  - **Profile `title` MUST be a clean human-readable label (LOCKED, §8.3a).** The
    `title` is what the user sees naming the auth method on the connection page.
    **You MUST emit a `connection.profiles[]` entry rewriting any `title` that is a
    raw field id, snake_case, or a lowercase machine token into proper Title Case
    that NAMES THE AUTH METHOD.** Heuristic the AI applies (judgment, NOT a regex it
    runs): *"If the title reads like a machine identifier — all-lowercase, contains
    underscores, or equals a field id — REWRITE it. If it reads like a label a user
    would recognize, KEEP it."* Concrete before→after rewrites (use these verbatim):

    | BEFORE (machine token) | AFTER (clean label) |
    |---|---|
    | `credentials` | `API Credentials` |
    | `client_credentials` | `OAuth 2.0 Client Credentials` |
    | `hmac_signature` | `HMAC Signature` |
    | `cred_api_key` | `API Key` |
    | `api_key` | `API Key` |

    **KEEP titles that are already clean human labels** (e.g. `API Key`, `Basic
    Auth`) — do NOT churn good copy; omit them from the spec.
  - **Profile `description` is OPTIONAL — OMIT it by default (§8.3a.5).** `title`
    is the profile's label and is always wanted (keep/rewrite per the rule above);
    `description` is extra. **A description that merely restates the credential
    fields / auth-method nouns MUST be omitted or `null`-removed** — e.g. "Connect
    with a user ID and API key." adds nothing when the fields already show **User
    ID** + **API Key**. **KEEP a description ONLY when it adds non-obvious value the
    fields/title don't convey:** (1) WHEN to use this profile vs another, (2) a
    PREREQUISITE, (3) a VENDOR-SIDE setup step, or (4) an OAuth SCOPE. When in
    doubt, OMIT (a missing description is valid connector YAML).
  - **WORKED BEFORE/AFTER — cybelangel (the canonical title-rewrite + redundant-
    description-removal case).** On-disk
    `unified-connectors-content/connectors/cybelangel/connection.yaml` profile
    `passthrough.cybelangel_event_collector` carries:
    - BEFORE: `title: credentials` (a raw field id, not a human label) +
      `description: Enter your CybelAngel API client ID and client secret to authorize the connection.`
    - The bound fields are ALREADY labeled **Client ID** + **Client Secret**, so the
      description only RESTATES them → it is noise; and the title is a raw field id →
      it must be rewritten.
    - AFTER (correct doc-spec entry — rewrite the title AND `null` the description):

      ```jsonc
      "connection": { "profiles": [
        { "id": "passthrough.cybelangel_event_collector", "title": "API Credentials", "description": null }
      ]}
      ```

    - WHY: the **Client ID** / **Client Secret** field labels already convey what to
      enter, so the description adds nothing → remove it; the title `credentials` was
      a raw field id → rewrite to the Title-Case auth-method name `API Credentials`.
      **Permission note:** the description is present→absent (a removal), so the
      §8.3a.5 / help_text permission matrix applies — show the user the EXISTING
      description verbatim and get `ask_followup_question` approval BEFORE nulling it.
  - **MANDATORY per-profile DECISION CHECKLIST — run this for EVERY profile in
    `connection.profiles` (you CANNOT skip it).** For each profile surfaced in the
    bundle, walk these three steps in order:
    1. **TITLE.** Is it a clean human label? If **NO** (a machine token / field id /
       snake_case) → REWRITE it to a Title-Case auth-method name (see the table
       above). If **YES** → KEEP it (omit `title` from the spec entry).
    2. **DESCRIPTION.** Does it add NON-OBVIOUS value beyond the labeled fields /
       the title (when-to-use vs another profile / a prerequisite / a vendor-side
       step / an OAuth scope)? If **NO** → OMIT it, and if one already EXISTS on
       disk, `null`-remove it (permission-gated, §8.3a.5). If **YES** → write/keep a
       concise value-adding description.
    3. **JARGON.** Does the effective title/description contain `passthrough` /
       `plain` / the raw `type` value? If yes it MUST be fixed (already enforced by
       the §9.11c on-disk audit).

    > The §9.11c on-disk audit HARD-fails leftover JARGON at Stage D — but a machine-
    > token TITLE and a REDUNDANT description are NOT caught by any script; they are
    > the AUTHOR's responsibility. This checklist is the safeguard. Run it for every
    > profile, every time.
  - **Three-state + null sentinel for `description` (§8.3a.5):** string = set/
    overwrite; `"description": null` = DELETE the existing description key (removal
    sentinel, idempotent); `description` key ABSENT from the entry = leave the
    existing description untouched. (Same pattern as help_text §8.3b.)
  - **Jargon in a description can be addressed EITHER way.** A `(plain)`/
    `(passthrough)`/raw-type description is a MUST-address case (the §9.11c audit
    hard-fails residual jargon). You may EITHER rewrite it to a value-adding
    sentence OR `null`-remove it (effective `None` passes the audit) — removal is a
    complete fix when no keep-criterion applies.
  - **Permission-gated (mirrors the help_text matrix below):** removing an existing
    description (present → absent via `description: null`) — show the user the
    EXISTING description VERBATIM and get `ask_followup_question` approval first.
    Adding a new description where none existed (absent → present) — get approval.
- **`configurations.view_groups[]`** (§8.4, OPTIONAL — §8.3b): author a config
  help_text ONLY when the member has real configuration content (a config section
  in `description_md`/`gapfill`, or meaningful `config_field_ids` worth
  describing). If there is none, OMIT that view_group — do not force filler. ALWAYS
  check the member's `gapfill` (§2.1): a `description_md` can cover connection but
  omit a crucial CONFIG fact — that gap is invisible until you read the README.
  Merge a README config fact ONLY when crucial AND not already conveyed (minimal).
  Crucial vendor-side setup goes in the CONNECTION help_text (§8.3), not here. The
  same boilerplate ban (§9.13) and the permission matrix below apply. **If a config
  view_group's EXISTING help_text is boilerplate (e.g. "Configurations settings for
  X."), you MUST replace it with substantive help_text or set `"help_text": null`
  to delete it — omission is NOT allowed for boilerplate (it leaves the migration
  filler in place). The §9.13 audit inspects the final on-disk config state and
  HARD-fails unaddressed boilerplate at Stage D.**
- **Removing an existing help_text (§8.3b removal sentinel).** To DELETE a
  help_text that already exists in the connector YAML (connection OR
  configurations), put `"help_text": null` on that view_group entry. OMITTING the
  view_group instead LEAVES the existing help_text untouched. A non-empty string
  SETS/overwrites. Three states: string = set; `null` = delete; absent = untouched.
  Removal is permission-gated — see the matrix below. **The identical three-state +
  null-sentinel + permission-gating applies to a profile `description` (§8.3a.5):
  `"description": null` deletes it, an omitted key leaves it untouched, a string
  sets it.**

### Stage-C help_text permission matrix (interaction policy)

> This is an AUTHORING-TIME policy YOU enforce with `ask_followup_question` — the
> validator does NOT prompt (it only gates structure/boilerplate, §9.13). Applies
> to BOTH connection and configuration help_text, AND to a profile `description`
> (§8.3a.5) — adding a new description or `null`-removing an existing one is gated
> identically. Key on (does the value already exist in the connector YAML?) × (are
> you authoring/removing one in the doc-spec?):

| existing in YAML | you author | transition | what to do |
|---|---|---|---|
| absent | absent (add none) | absent → absent | NO prompt — nothing changes |
| present | `null` removal | present → absent | **PROMPT.** Show the user the EXISTING help_text VERBATIM and get explicit `ask_followup_question` approval BEFORE writing `help_text: null` / before apply |
| absent | new string | absent → present | **PROMPT.** Get explicit `ask_followup_question` approval before adding |
| present | edited string | present → present | PROMPT only for §8.7 fidelity flags. Ordinary near-verbatim fidelity edits (incl. the §2.4 incident→issue terminology fix) do NOT each need a prompt |
- **`summary.metadata.next_steps`** (§8.5): omit/`null` unless the sources
  document post-onboard steps; then source strictly from there (action only).
- **Strip the `## Commands` REFERENCE section — but KEEP inline auth/setup command
  names** (§2.3): the gatherer already stripped the bulky `## Commands` reference
  block (the per-command `### command-name` / `#### Base Command` / `#### Context
  Output` tables). Never reintroduce THAT reference material. **However, command
  names that appear inside connection/configuration SETUP INSTRUCTIONS are NOT the
  command reference and MUST be preserved VERBATIM** — e.g. an auth step like "Run
  the `!integration-auth-start` command, then run `!integration-auth-complete`" or
  "Run the `!integration-auth-test` command to test the connection." The user
  literally types these to onboard, so genericizing them ("run the authentication
  start command") is a fidelity LOSS — keep the exact `!command-name` tokens
  (including any `***...***`/backtick formatting) as written in the source
  `description.md`. The same applies to any **"Required Permissions"** block keyed
  by those command names: it tells the user which API scopes each command needs —
  keep it near-verbatim, do NOT drop it. The validator's no-command check only
  bans the `## Commands`-style section HEADERS, so inline command names pass.
  - **Never backslash-escape the bang** (§2.3a): write a command name as
    `!integration-auth-start` (or `***!integration-auth-start***`), NEVER as
    `\!integration-auth-start`. `!` is not a Markdown special char, so a `\!`
    renders the literal backslash in the tooltip. The validator HARD-fails any
    `\!` in help_text / connector.description / profile title+description
    (§9.14) — so a stray escape is caught at Stage D, but just don't add it.
- **Product names are LEFT AS-IS (§2.1):** do NOT rewrite `Cortex XSOAR` →
  `Cortex XSIAM` (or vice versa). Keep whatever the source `description_md` says
  verbatim. There is no XSOAR→XSIAM rename step and no validator gate for it.
- **Terminology: "incident(s)" → "issue(s)" (§2.4 — enforced):** in HUMAN-FACING
  authored copy (`connector.description`, connection/configurations `help_text`,
  profile title/description), the platform's term is **"issue"**, not "incident".
  Rewrite `incident`→`issue` / `incidents`→`issues` (e.g. **"fetch incidents"** →
  **"fetch issues"**, "Maximum number of incidents" → "Maximum number of issues",
  "Fetches incidents" → "Fetches issues"). Preserve surrounding casing
  (Incident→Issue, INCIDENT→ISSUE).
  - **DO NOT touch machine identifiers** — field `id`s and dynamic-field keys such
    as `incidentType`, `incidentFetchInterval`, `incident-type`,
    `xsoar-<x>_incidentType` are STRUCTURAL; renaming them breaks the connector.
    The rule applies ONLY to prose (titles/descriptions/help_text), never to
    `id:` values or `dynamicField:` keys.
  - **KEEP genuine third-party/vendor product terms** that legitimately use
    "incident" as the vendor's own naming (e.g. a vendor API's "Incidents"
    endpoint, GuardiCore incident types, AWS Security Hub). When in doubt about a
    vendor proper-noun, keep it; the rule targets our platform's generic
    incident→issue wording, not a vendor's product name.
  → Enforced by **§9.17**: the word "incident"/"incidents" appearing in AUTHORED
  copy (help_text / connector.description / profile fields) is a HARD validation
  error, so an unconverted term is caught at Stage D. (Field-level `id`s and
  vendor config-field descriptions are outside the authored surface the validator
  inspects.)
- **Length governor** (§2.2): because help_text ≈ description.md, length tracks
  the source. The validator soft-warns if help_text > ~2× `description_md_len`.

The fixed metadata title/description strings for capabilities/connection/
configurations/summary are NOT authored — the apply step sets them to canonical
values silently (§8.1). Don't put them in the doc-spec or flag them.

### Minimal doc-spec.json shape

```jsonc
{
  "connector_slug": "<slug>",
  "connector_id": "<Connector ID>",
  "members": [
    { "integration_id": "...", "view_group_id": "...",
      "commonfields_name": "...", "description_md_len": 0 }
  ],
  "connector": { "description": "1-4 line fused summary" },
  "capabilities": { "items": [ { "id": "automation-and-remediation", "description": "<from table>" } ] },
  "connection": {
    // help_text states (§8.3b): string = set/overwrite; null = DELETE the
    // existing key (removal sentinel, permission-gated); OMIT the view_group
    // entirely = leave existing help_text untouched. OMIT rather than write filler.
    "view_groups": [
      { "id": "...", "label": "...", "help_text": "MD (near-verbatim)" } ],
    "profiles": [
      /* OPTIONAL, HIGH BAR (§8.3a). ONLY profiles whose current title/description
         has jargon, is empty, or is wrong. Key by id; set only changed field(s).
         description states (§8.3a.5): non-empty string = set/overwrite;
         "description": null = DELETE the existing description (removal sentinel,
         permission-gated); OMIT the description key = leave it untouched. OMIT a
         redundant description that only restates the credential fields. */
      { "id": "passthrough.cortex_xdr_ir",
        "description": "Authenticate to Cortex XDR using an API key and key ID." },
      /* null-remove a jargon-only/redundant description (anomali (plain) case): */
      { "id": "api_key.anomali", "description": null }
    ]
  },
  "configurations": { "view_groups": [
      /* OPTIONAL; omit members with no config. Same §8.3b states apply:
         string = set; "help_text": null = DELETE existing key; omitted = untouched. */
  ] },
  "summary": { "metadata": { "next_steps": null } }
}
```

## Batch flow (context-safe over ~600 connectors)

To avoid blowing up context (§3):

0. **Build the candidate list FROM THE CSV** (§3.1). For "do the next one" use
   `doc_state doc-next [--mine]`. For a scoped request ("document all the
   microsoft ones") use `doc_state doc-find <substring>` — never `ls`. Process
   only the slugs these commands return.
1. `doc_state doc-next [--mine]` → the next connector needing docs.
2. **Document ONE connector per isolated `new_task` subtask** (§3.3). Give the
   subtask just the slug + this skill; it runs A→E for that one connector and
   returns only the doc-spec path + pass/fail + any flags. No cross-connector
   accumulation.
3. After the subtask reports success and you (or it) have applied + marked it,
   loop to the next. `doc_state doc-dashboard` shows overall progress.

## Guardrails (no-invention contract, §12)

- `description.md` is PRIMARY; READMEs are gap-fill only.
- Never add facts from your own knowledge without explicit permission.
- If a source looks wrong, change nothing without permission — raise a flag.
- Missing source for a REQUIRED field → `__FLAG__` (validator hard-stops).
- Apply is deterministic, preserves comments/structure, dry-run before write.
