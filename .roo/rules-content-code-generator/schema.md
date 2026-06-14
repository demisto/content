# 🏭 Content Code Generator — Index & Core Rules

## 📚 Router

Read this file first, then load the step file you need (all files are in the same directory).
**Each step generates at most one file** and lives in its own rules file.

| Step | Name | File |
|------|------|------|
| 1 | Gather Requirements | `01-gather-requirements.md` |
| 2 | Generate Pack Structure | `02-generate-pack-structure.md` |
| 3 | Generate `_description.md` | `03-generate-description.md` |
| 4 | Generate `.yml` | `04-generate-yaml.md` |
| 5 | Generate `pack_metadata.json` | `05-generate-pack-metadata.md` |
| 6 | Generate `ReleaseNotes/<version>.md` (if needed) | `06-generate-release-notes.md` |
| 7 | Generate `<Integration>.py` | `07-generate-python.md` |
| 8 | Generate `test_data/` fixtures | `08-generate-test-data.md` |
| 9 | Generate `_test.py` | `09-generate-unit-tests.md` |
| 10 | Generate `.secrets-ignore` | `10-generate-secrets-ignore.md` |
| 11 | Generate `command_examples.txt` | `11-generate-command-examples.md` |
| 12 | Generate integration `README.md` | `12-generate-integration-readme.md` |
| 13 | Generate pack-level `README.md` | `13-generate-pack-readme.md` |
| 14 | Validate & Format | `14-validate-format.md` |

---

## 📐 Content Types

This mode classifies the design into one of these cases. The full detection logic lives in
Step 1.4 (`01-gather-requirements.md`); this is the quick reference.

| Type | Fetch mechanism | Key signals | Supported? |
|------|-----------------|-------------|------------|
| **Collector — Fetch Events** | `fetch-events` + `<prefix>-get-events` | `isfetchevents: true`; events → dataset; time → `_time` | ✅ |
| **Collector — Fetch Incidents** | `fetch-incidents` + `<prefix>-get-incidents` | `isfetch: true`; incidents → queue; time → `occurred` | ✅ |
| **Mixed** (collector + custom commands) | a fetch mechanism *and* custom commands | both fetch + custom commands present | ✅ Treat as a collector; ignore the custom commands |
| **Automation** | none (custom commands only) | list/get/update/delete commands, no fetch | 🚫 Not yet — gate in Step 1.4 |

---

## ⚠️ Core Rules (ALWAYS Apply)

1. **Never guess.** If any detail is missing from the design — ask before proceeding. No matter how small the detail.
2. **Steps can run standalone, but Step 1 is always a prerequisite.** Any file-generation step (3–13) may be run on its own when the user asks for just that file (e.g., "only generate the `.yml`"). But you can never generate a file without the design inputs, so **Step 1 (Gather Requirements) is a prerequisite for every file-generation step** — for a single-file request, gather requirements first (Step 1), then generate the requested file. If you start the full flow from Step 1, execute steps 1 → 14 in order — do NOT skip steps or proceed without user confirmation between them.
3. **No missing inputs = hard stop.** NEVER advance to the next step while any required input for the current one is missing. List every missing item, ask the user to supply the values, and **wait until they are actually provided** — user approval alone is NOT enough to proceed past blanks. Resume only once every required item has a concrete value.
4. **One file per step — no exceptions.** Each step generates exactly ONE file (or none, for non-generation steps). After a step, present that single file and get user confirmation before starting the next step. NEVER generate, bundle, or present more than one file in a single step — even if a single command (e.g., `demisto-sdk generate-docs`) happens to output multiple files; in that case, present and confirm one file at a time across the relevant steps.
5. **Always announce.** Before any autonomous action: _"📋 [Action]..."_
6. **Use only the files you are told to.** The single source of truth is the design document plus the specific rule/guideline files this mode references (`schema.md`, the step file you are executing, and any file it explicitly points to). Do NOT read, recall, or apply rules from any other file — even if it appears in your context, was loaded for a different mode, or you remember it from elsewhere. If a rule is not in the design or in a file this mode explicitly references, it does NOT apply here. When unsure whether a rule applies, ask the user rather than pulling in outside guidance.
7. **Icon file.** Never generate `_image.png` — ask the user to provide it.
8. **Naming.** Use the product's official name exactly as branded. Do NOT normalize.

---

## 📐 Workflow Overview

A single linear sequence of steps (see the Router table above). Steps 3–13 each generate
exactly one file; steps 1, 2, and 14 are non-file-generation steps. Get user confirmation
between steps.

Each file-generation step can also be run on its own when the user asks for just that file —
but Step 1 (Gather Requirements) must run first, since no file can be generated without the
design inputs. If you begin the full flow at Step 1, follow the sequence in order without
skipping (see Core Rule 2).

> Note on docs ordering: `demisto-sdk generate-docs` reads `command_examples.txt` to build the
> integration `README.md`. That is why `command_examples.txt` (step 11) comes before the
> integration `README.md` (step 12) — each presented and confirmed as its own file.

---

## 📐 Reference Architecture

When generating code, always read these references first to ensure structural alignment:
- **HelloWorldV2**: `Packs/HelloWorld/Integrations/HelloWorldV2/`
- **AGENTS.md**: Root-level file with project-wide coding standards
- **Confluence — XSIAM Collector Development Process**: https://confluence-dc.paloaltonetworks.com/pages/viewpage.action?pageId=646407377&spaceKey=DemistoContent&title=XSIAM%2BCollector%2BDevelopment%2BProcess

> **Per-file guidelines:** Each file-generation step (3–13) has a matching AI-Reviewer
> guideline in `guidelines/` that the step reads at generation time. Those references are
> owned by their step files (not listed here) to keep this router lean and avoid drift — read
> the guideline from the step file you're executing.
