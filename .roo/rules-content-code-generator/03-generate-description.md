# Step 3: Generate `_description.md`

## Purpose

Generate the integration's **description file** (`<IntegrationName>_description.md`).

The description file is the **"Help" panel** shown on the right-hand side of the instance
configuration window. It walks a user from zero to a working instance.

**Core principle:** The description content comes **directly from the design's Help /
Prerequisites section** — we take it as-is. We do NOT author product overviews, marketing
copy, or invent setup steps.

This step generates **exactly one file** (Core Rule 4). After generating it, present it and
get user confirmation before moving on.

---

## Required Inputs (from Step 1)

| Input | Where it came from (Step 1) | Used for |
|-------|------------------------------|----------|
| Integration name / ID | Step 1, item 2 | The `<IntegrationName>_description.md` file name + the `## <Name>` heading |
| Help / Prerequisites content | Step 1, section F (item 24) | The body of the description (used as-is) |

**🚫 Hard gate (Core Rule 3):** If the design has **no Help / Prerequisites content**
(Step 1, item 24), you cannot write a meaningful description. **Ask the user** for the help
content (e.g., how the user obtains the API key, what role/permission is required). Do NOT
guess or fabricate setup steps. Wait until it is actually provided.

---

## Step 3.1: Handle the Scenario (New vs. Existing Integration)

The scenario was detected in Step 2. Behave accordingly:

| Scenario | Action |
|----------|--------|
| **A — New Pack** | Generate the description file from the design's Help section. |
| **B — Existing Pack, New Integration** | Generate the description file from the design's Help section (this integration is new). |
| **C — Existing Integration (adding a collector)** | **ASK THE USER what to do** — see below. Do NOT overwrite the existing file. |

### Scenario C — Existing Integration: Ask the User

When adding a collector to an **existing** integration, a `_description.md` already exists.
Adding a collector usually does NOT change the setup help (same URL, same credentials).

1. **Read the existing `_description.md` first.**
2. Present the existing content to the user and ask how to proceed. Offer these options:
   - **Keep as-is (skip)** — the collector adds no new setup requirements. _(Most common.)_
   - **Append collector setup notes** — only if the collector needs an extra parameter,
     permission, or scope the existing help does not mention. Make a **surgical, additive**
     edit — never rewrite the whole file.
   - **Rewrite** — only if the user explicitly asks for it.
3. Do NOT proceed until the user chooses. If they choose "skip", record it and move on to
   Step 4 without touching the file.

**Never rename the existing description file** — the `<IntegrationName>_description.md` name
is fixed for existing integrations. If the integration ID/name appears to be changing, flag
it as a potential breaking change instead.

---

## Step 3.2: Build the Description Content

Take the design's **Help / Prerequisites** section (Step 1, item 24) and use it as the body
of the description file, with a leading `## <Integration Name>` heading.

### Precedence: Content vs. Formatting

The description file is produced by two distinct inputs that must never be confused:

| Source | Owns | May do | May NOT do |
|--------|------|--------|------------|
| **The design's Help section** | **All content** — every sentence, fact, step, value, permission, and credential instruction | Be the sole origin of what the file *says* | — |
| **The guidelines** (`guidelines/description_xsoar_guidelines.md`) | **Formatting & structure only** | Add the `## <Integration Name>` heading; shape the design's existing steps into numbered/bulleted lists; split the design's existing topics under `###` sub-sections; fix markdown structure | Add any new sentence, fact, sub-heading topic, intro line, or marketing copy that is not already in the design's Help section |

**The rule — content precedence:**

- **Every fact and sentence must trace back to the design's Help section.** The guidelines
  may *re-shape* that content (headings, lists, sub-sections) but may **NEVER** introduce new
  information.
- **Do NOT invent intro sentences** (e.g., "This section explains how to configure…") unless
  that text exists in the design.
- **Do NOT invent `###` sub-heading topics.** You may group the design's *existing* topics
  under sub-headings, but only when the design itself already separates those topics — name
  them from the design's wording, not from a generic template.
- If applying a guideline would require content the design does not provide, **ask the user** —
  do not fabricate it (Core Rule 1, 3).

In short: **structure comes from the guidelines; every word comes from the design.**

> **Read the guidelines fresh:** `guidelines/description_xsoar_guidelines.md` is the single
> source of truth and may evolve independently. Open and apply its **current** content at
> generation time — never rely on a copied or summarized version of its rules.

### Mapping the JumpCloud example (illustration)

Given the design's Help / Prerequisites section:

> Authenticates with a JumpCloud **admin API key** (`x-api-key` header). Only administrator
> roles can access the API. To obtain the key: Admin Portal → username drop-down (top-right)
> → **API Settings** → copy the API key. Treat it as a secret; **Generate New API Key**
> revokes the previous one. MSP/multi-tenant (optional): set `Organization ID` to a client
> org's ID to send the `x-org-id` header. Leave empty for single-org tenants.

This becomes the description file. The **only** changes are formatting (the `## <Name>`
heading and turning the existing "obtain the key" sentence into numbered steps). Every word
still comes from the design's Help text — nothing was added:

```markdown
## JumpCloud Directory Insights

Authenticates with a JumpCloud **admin API key** (`x-api-key` header). Only administrator
roles can access the API.

To obtain the key:

1. Open the **Admin Portal**.
2. Click the username drop-down (top-right) → **API Settings**.
3. Copy the API key.

Treat it as a secret; **Generate New API Key** revokes the previous one.

MSP/multi-tenant (optional): set `Organization ID` to a client org's ID to send the
`x-org-id` header. Leave empty for single-org tenants.
```

Note what did **and did not** happen:
- ✅ Allowed (formatting only): added the `## JumpCloud Directory Insights` heading; split the
  design's "Admin Portal → … → copy the API key" sentence into numbered steps.
- 🚫 NOT done (would violate the precedence rule): no invented intro line like "This section
  explains how to configure…"; no invented `### Generate an API Key` / `### Permissions` /
  `### MSP` sub-heading topics — the design's Help section is three short paragraphs and does
  not separate those topics into headed sections, so neither does the output. Every sentence
  traces back to the design's Help text.

---

## Step 3.3: Write the File

- **Scenario A / B:** Write the content to
  `Packs/<PackName>/Integrations/<IntegrationName>/<IntegrationName>_description.md`.
- **Scenario C:** Only modify the existing file if the user chose "append" / "rewrite" in
  Step 3.1 — otherwise skip.

The description guidelines from Step 3.2 (`guidelines/description_xsoar_guidelines.md`) must be
applied to the file content before writing.

📋 Announce before writing: _"📋 Generating the description file from the design's Help
section..."_

## After Generation

1. Present the **full content** of the generated description file to the user.
2. State that it was built from the design's Help/Prerequisites section and that the
   description guidelines were applied.
3. Ask the user to confirm the content is correct before proceeding to **Step 4 (Generate
   `.yml`)**.

**🚫 Do NOT proceed to Step 4 without user confirmation of this file** (Core Rule 4).

## Important Rules (recap)

- **One file per step** — generate only `_description.md` here (Core Rule 4).
- **Never guess** — missing Help content = ask the user (Core Rule 1, 3).
- **Source is the design's Help section** — use it as-is; do not author overviews or marketing.
- **Scenario C** — ask the user before touching an existing description file; never rename it.
