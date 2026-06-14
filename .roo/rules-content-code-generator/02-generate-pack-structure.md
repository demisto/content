# Step 2: Generate Pack Structure

## Purpose

Create the directory tree with **empty placeholder files**.
The content of each file will be filled in during subsequent steps.

This step supports **three scenarios**:

| Scenario | When | What to Generate |
|----------|------|------------------|
| **A — New Pack** | The pack does NOT exist under `Packs/` | The full pack tree (pack-level files + the integration) |
| **B — Existing Pack, New Integration** | The pack exists, but the integration does NOT | ONLY the new `Integrations/<IntegrationName>/` subtree + a `ReleaseNotes/` entry |
| **C — Existing Integration** | Both the pack AND the integration already exist (adding a collector to it) | NO new integration files — ONLY a `ReleaseNotes/` entry. Downstream steps **MODIFY** the existing files |

## Step 2.1: Detect the Scenario

Before generating anything, check what already exists:

- If `Packs/<PackName>/` does NOT exist → **Scenario A (New Pack)**.
- If `Packs/<PackName>/` exists but `Packs/<PackName>/Integrations/<IntegrationName>/` does NOT → **Scenario B (Existing Pack, New Integration)**.
- If both `Packs/<PackName>/` AND `Packs/<PackName>/Integrations/<IntegrationName>/` exist → **Scenario C (Existing Integration)**.

📋 Announce which scenario was detected and confirm with the user before generating files.

## Step 2.2: Apply the Integration Naming Rule (Scenario B only)

This step materializes the **Integration name** into the filesystem
(`Integrations/<IntegrationName>/` and every file inside it), so the naming rule is enforced
**here**. It is only relevant for **Scenario B (Existing Pack, New Integration)** — Scenario A
has no existing integration to trigger the exception, and Scenario C keeps the existing
integration's fixed name.

**Terminology rule — "Event Collector" in the integration name:**

- **Do NOT use "Event Collector"** in the integration name for new integrations.
- **Exception:** If the pack already has a **Partner/Community-tier** integration → name the
  new one `[Vendor] Event Collector`.

**How to determine the existing integration's tier (deterministic):**

The support tier is recorded in the pack's own files — read them, do not guess:

1. **Pack-level (primary):** read `Packs/<PackName>/pack_metadata.json` and check the
   `support` field. It is one of `xsoar`, `partner`, `community`, or `developer`. If it is
   `partner` or `community` → the exception applies.
2. **Integration-level (override):** open the existing integration's YAML
   (`Packs/<PackName>/Integrations/<ExistingIntegration>/<ExistingIntegration>.yml`) and check
   `supportlevelheader` (`xsoar` | `partner` | `community`). When present, it overrides the
   pack-level `support` for that integration. If absent, the pack's `support` field applies.
3. **Decision:** use `supportlevelheader` when it is set, otherwise the pack's `support`
   field. If the resolved tier is `partner` or `community`, name the new integration
   `[Vendor] Event Collector`. Otherwise (e.g., `xsoar`), keep the base rule and do NOT use
   "Event Collector".
4. If neither field is present or the tier is ambiguous → **ask the user** (Core Rule 1).

If applying the rule would change the Integration name gathered in Step 1, 📋 announce the
corrected name and confirm with the user **before** creating any directories.

## Required Inputs (from Step 1)

- **Pack name** — used for the `Packs/<PackName>/` directory
- **Integration name** — used for file names within `Integrations/`

---

## Scenario A — New Pack

Generate the full directory tree:

```
Packs/<PackName>/
├── .pack-ignore
├── .secrets-ignore
├── pack_metadata.json
├── README.md
└── Integrations/
    └── <IntegrationName>/
        ├── <IntegrationName>.py
        ├── <IntegrationName>.yml
        ├── <IntegrationName>_test.py
        ├── <IntegrationName>_description.md
        ├── <IntegrationName>_image.png      ← user must provide, do NOT generate
        ├── README.md
        ├── command_examples.txt
        └── test_data/
```

---

## Scenario B — Existing Pack, New Integration

**Do NOT overwrite or recreate existing pack-level files** (`pack_metadata.json`,
`README.md`, `.pack-ignore`, `.secrets-ignore`). They already exist and may contain
content from other integrations in the pack.

Generate ONLY the new files:

```
Packs/<PackName>/
├── ReleaseNotes/
│   └── <next_version>.md                     ← new entry (bump from current version)
└── Integrations/
    └── <IntegrationName>/                     ← new integration subtree
        ├── <IntegrationName>.py
        ├── <IntegrationName>.yml
        ├── <IntegrationName>_test.py
        ├── <IntegrationName>_description.md
        ├── <IntegrationName>_image.png      ← user must provide, do NOT generate
        ├── README.md
        ├── command_examples.txt
        └── test_data/
```

Notes for Scenario B:
- If `Integrations/<IntegrationName>/` already exists → this is **Scenario C**, not B. Re-detect.
- Determine `<next_version>` by reading the current `version` in the existing
  `pack_metadata.json`. The actual version bump (updating `version` in `pack_metadata.json`)
  is handled in Step 5 (Generate Pack Metadata), and the ReleaseNotes content is handled in
  Step 6 (Generate Release Notes).

---

## Scenario C — Existing Integration

The integration already exists. We are **adding a collector** (fetch-events / get-events, or
fetch-incidents / get-incidents) to it. Adding command-based (Automation) capabilities to an
existing integration is **NOT supported yet** — only the collector part.

**Do NOT generate any new integration files and do NOT overwrite existing files.**
The existing `<IntegrationName>.py`, `<IntegrationName>.yml`, `<IntegrationName>_test.py`,
`<IntegrationName>_description.md`, `README.md`, `command_examples.txt`, `test_data/`, and all
pack-level files already exist and must be preserved.

Generate ONLY the new file:

```
Packs/<PackName>/
└── ReleaseNotes/
    └── <next_version>.md                     ← new entry (bump from current version)
```

**Downstream steps MODIFY existing files — they do NOT create them.** Record this so later
steps add the collector capability into the existing files instead of generating new ones.
The table below maps each later step's behavior in Scenario C:

| Step | File | Scenario C behavior |
|------|------|---------------------|
| 3 | `_description.md` | Update only if the collector adds setup notes the help text needs; otherwise skip. |
| 4 | `.yml` | **MODIFY** — add the collector config + commands (e.g., `isfetchevents: true` / `isfetch: true`, `get-events` / `get-incidents`, fetch params) to the existing YAML. Preserve all existing config and commands. |
| 5 | `pack_metadata.json` | **MODIFY** — bump `version` only. Do NOT recreate. |
| 6 | `ReleaseNotes/<version>.md` | Create the entry (the only file created in this step for Scenario C). |
| 7 | `<Integration>.py` | **MODIFY** — add fetch-events/get-events (or fetch-incidents/get-incidents) logic + the `main()` command routing for the new commands. Preserve all existing code. |
| 8 | `test_data/` | Add ONLY the new fixtures the collector tests need. |
| 9 | `_test.py` | **MODIFY** — add ONLY new tests for the collector. Preserve existing tests. |
| 10 | `.secrets-ignore` | Update only if the collector introduces new secret-like strings; otherwise skip. |
| 11 | `command_examples.txt` | **MODIFY** — add an example for the new `get-events` / `get-incidents` command. |
| 12 | integration `README.md` | **MODIFY** — re-generate/append docs for the new command. |
| 13 | pack-level `README.md` | Update only if pack-level docs reference the integration's capabilities; otherwise skip. |
| 14 | Validate & Format | Run as usual on the modified integration. |

Notes for Scenario C:
- **Read each existing file before modifying it** and make surgical, additive edits — never
  overwrite the whole file.
- If the existing integration already has the collector capability you were asked to add →
  STOP and ask the user how to proceed.
- Determine `<next_version>` by reading the current `version` in the existing
  `pack_metadata.json` (version bump handled in Step 5, ReleaseNotes content in Step 6).

---

In Scenarios A and B, all generated files are created **empty** in this step. Content is filled
in subsequent steps as specified in the Router table in `schema.md`. In Scenario C, only the
`ReleaseNotes/` entry is created here; downstream steps modify the existing files.

## After Generation

Present a summary confirming which files were created (per the detected scenario).
- Scenarios A and B: remind the user to provide `<IntegrationName>_image.png`.
- Scenario C: note that downstream steps will **MODIFY** the existing integration files
  (not create new ones) — see the Scenario C step-behavior table above.

Ask if they are ready to proceed to Step 3 (Generate `_description.md`).
