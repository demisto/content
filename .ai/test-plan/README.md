# Connectus Test Plan — Google Sheets Generator

This folder holds a two-file Google Apps Script project that generates a complete, formatted Google Sheets test plan for the Connectus derived-packs feature (Jira **CIAC-17084**, **CIAC-17085**, **CIAC-17086**, **CIAC-17274**). `data.gs` is the **data layer** — the dropdown vocabularies (`CONFIG_LISTS`), the Jira base URL (`JIRA_BASE_URL`), the build preconditions (`SETUPS`) and the 42 test cases (`TEST_CASES`). `build.gs` is the **presentation layer** — `buildWorkbook()` turns that data into a 12-tab workbook with banners, dropdowns, conditional formatting, live KPI formulas, coverage matrices and read-only views, plus a `🧪 Test Plan` custom menu for day-to-day operations.

---

## Two builders: Full vs. Lite

Pick a builder **before** you install anything — they produce two very different workbooks.

| | `build.gs` (Full) | `build_lite.gs` (Lite) |
|---|---|---|
| Sheets | 12 | 3 visible + 1 hidden `⚙️ Config` |
| Columns in the tests sheet | 26 | 8 |
| Run history | Yes — `▶️ Runs` sheet, multiple `RUN-n` cycles | No — one editable `Status` cell per test |
| Bug tracking | `🐞 Bugs` sheet | `Notes / Evidence` free-text column |
| Layout | One long table with block banners | Tests split into colored, collapsible blocks |
| Best for | Formal, repeated regression cycles | Fast, readable, single-pass execution |

Both builders read the **same `data.gs`** (`CONFIG_LISTS`, `SETUPS`, `TEST_CASES`), and you install only one of them — see the `onOpen` warning below.

> ⚠️ **Keep only one builder in an Apps Script project.** A project may declare `onOpen()` exactly once, and `build.gs` already does. `build_lite.gs` therefore exposes `liteOnOpen()` instead and, as a safety net, `buildLiteWorkbook()` also installs the Lite menu itself. If you keep both files anyway, either call `liteOnOpen()` from `build.gs`'s `onOpen()`, or accept that the Lite menu only shows up once `buildLiteWorkbook()` has been run in the session. Nothing else collides: every Lite name is prefixed (`LITE_` constants, `lite*` functions, `LT_` named ranges).

Sections 1–9 below describe the **Full** builder; for the Lite one jump to [§8.5](#85-lite-version).

---

## 1. Quick start — installation

1. Create a new Google Sheet (e.g. `Connectus Test Plan`).
2. Open **Extensions → Apps Script**.
3. In the script editor, create two script files and paste the contents of the repo files into them:
   - **File → New → Script** → name it `data.gs` → paste `.ai/test-plan/data.gs`.
   - **File → New → Script** → name it `build.gs` → paste `.ai/test-plan/build.gs`.
   - Delete the default `Code.gs` (or leave it empty — it is harmless).
4. Save the project (`Ctrl/Cmd + S`).
5. In the function dropdown at the top of the editor, select **`buildWorkbook`** and click **▶ Run**.
6. Authorize the script when prompted:
   - **Review permissions** → pick your account.
   - Google will warn that the app is not verified (expected — this is a personal, unpublished script).
   - Click **Advanced** → **Go to `<project name>` (unsafe)** → **Allow**.
   - The script only needs access to the spreadsheet it is bound to.
7. Go back to the spreadsheet tab and **reload the page**. The `🧪 Test Plan` menu appears next to `Help`.

> Re-running `buildWorkbook()` is **safe**: `▶️ Runs` and `🐞 Bugs` keep the data you already entered (see [§9](#9-keeping-the-repo-and-the-sheet-in-sync) for the one important exception — the `🧪 TestCases` sheet).

### Alternative: push with `clasp`

```bash
npm install -g @google/clasp
clasp login
# scriptId is visible in Apps Script under Project Settings
clasp clone <scriptId>
cp .ai/test-plan/data.gs .ai/test-plan/build.gs .
clasp push
```

Then open the sheet and run `🧪 Test Plan ▸ 🏗️ Rebuild Workbook`.

---

## 2. Workbook map

12 sheets, created in this left-to-right order (`SHEET_ORDER` in `build.gs`):

| # | Sheet | Source | Purpose |
|---|-------|--------|---------|
| 1 | `📖 README` | auto-generated | In-sheet cover page: purpose, tab guide, ID prefixes, golden rules, status legend. |
| 2 | `⚙️ Config` | auto-generated from `CONFIG_LISTS` | One column per dropdown category (18 columns). Each column is exposed as the named range `List_<Key>` covering rows **2:200**. |
| 3 | `🧱 Setup` | auto-generated from `SETUPS` | The 7 builds / PRs the tests depend on. Columns `A:H` come from `data.gs`; `I` (`# Tests`) and `J` (`Blocked Tests`) are live `COUNTIF`/`COUNTIFS` formulas. |
| 4 | `🧪 TestCases` | auto-generated from `TEST_CASES` | **The main sheet.** 26 columns, two header rows (block banners in row 1, real headers in row 2), data starts on **row 3**. |
| 5 | `▶️ Runs` | **hand-edited** (seeded once) | One row per *(test, run)*. This is where testers record `Status` and `Evidence Link`. Seeded with `RUN-1` + one row per test on the first build. |
| 6 | `🐞 Bugs` | **hand-edited** | Bugs found while executing runs. Column `B` is a pre-filled Jira `HYPERLINK` formula for rows 2:200. |
| 7 | `📊 Dashboard` | auto-generated (all formulas) | KPI block (`A3:B10`), *By Ticket* and *By Tenant* breakdowns with sparklines, and a live *Failed & Blocked* `QUERY` list. |
| 8 | `🎯 Coverage` | auto-generated (all formulas) | Two `COUNTIFS` matrices with a white→green gradient: **Pack Type × Phase** and **Feature × Tenant**. White cells are coverage gaps. |
| 9 | `👁️ Marketplace` | auto-generated (read-only) | `QUERY` view: `Tenant = Marketplace` or `Tenant Scope` contains `Marketplace`. |
| 10 | `👁️ Managed` | auto-generated (read-only) | `QUERY` view: `Tenant = Managed` or `Tenant Scope` contains `Managed`. |
| 11 | `👁️ Connectus` | auto-generated (read-only) | `QUERY` view: `Tenant = Connectus` or `Tenant Scope` contains `Connectus`. |
| 12 | `👁️ CI` | auto-generated (read-only) | `QUERY` view: `Tenant = CI`. |

Each `👁️` view selects `A,B,D,I,K,L,N,R,S,X` (ID, Ticket, Title, Phase, Pack Type, Coupling, Priority, Preconditions, Steps, Latest Status) and carries a red read-only warning in cell `M1`.

---

## 3. The `🧪 TestCases` schema

Row 1 = merged coloured block banners. Row 2 = column headers. Row 3 = first data row (`TC_FIRST_ROW`). Validation and conditional formatting are applied down to row **500** (`TC_LAST_ROW`). Frozen: 2 rows, 2 columns.

| Col | Header | Block | Entry | Allowed values |
|-----|--------|-------|-------|----------------|
| `A` | ID | Identity | manual | `<PREFIX>-nnn`, zero-padded to 3 digits (see [§4](#4-id-conventions)) |
| `B` | Ticket | Identity | dropdown | `⚙️ Config` → `List_Ticket` |
| `C` | Jira | Identity | **formula** | `=IF($B<row>="","",HYPERLINK(JIRA_BASE_URL&$B<row>,$B<row>))` |
| `D` | Title | Identity | manual | free text (one short sentence) |
| `E` | Active | Identity | dropdown | `List_Active` — `Active`, `Deprecated` |
| `F` | Feature | Identity | dropdown | `List_Feature` — `Derived Packs`, `Release Notes`, `Notification Center`, `CSP BC Validation`, `Common-Base` |
| `G` | Tenant | Classification | dropdown | `List_Tenant` — `Marketplace`, `Managed`, `Connectus`, `Multi`, `CI` |
| `H` | Tenant Scope | Classification | manual | free text; fill only when `Tenant = Multi` (e.g. `Marketplace + Managed`) |
| `I` | Phase | Classification | dropdown | `List_Phase` — `Pre-Optin`, `During-Optin`, `Post-Optin`, `Post-Optin + New Version`, `N-A` |
| `J` | Pack State | Classification | dropdown | `List_PackState` — `Installed+Instance`, `Installed-NoInstance`, `Not-Installed`, `N-A` |
| `K` | Pack Type | Classification | dropdown | `List_PackType` — `Regular`, `Partner`, `Tightly-Only`, `Loosely-Only`, `COOC`, `Agentix`, `Autonomous`, `Base`, `Any`, `N-A` |
| `L` | Coupling | Classification | dropdown | `List_Coupling` — `Tightly`, `Loosely`, `Both`, `N-A` |
| `M` | Test Type | Classification | dropdown | `List_TestType` — `Functional`, `UI`, `Regression`, `Negative`, `Infra-CI` |
| `N` | Priority | Classification | dropdown | `List_Priority` — `P0`, `P1`, `P2` (`P0` renders bold red) |
| `O` | Suite | Classification | dropdown | `List_Suite` — `Smoke`, `Full` |
| `P` | Automatable | Classification | dropdown | `List_Automatable` — `Yes`, `No`, `Partial` |
| `Q` | Setup Ref | Execution | dropdown | Range validation on `🧱 Setup!$A$2:$A$100` (`SETUP-01` … `SETUP-07`) |
| `R` | Preconditions | Execution | manual | free text; empty when the setup is enough |
| `S` | Steps | Execution | manual | numbered, newline-separated (`Alt+Enter` in the sheet, `\n` in `data.gs`) |
| `T` | Expected Result | Execution | manual | free text |
| `U` | Verification | Execution | dropdown | `List_VerificationMethod` — `UI`, `Tenant Logs`, `API`, `Build Artifact`, `Bucket` |
| `V` | Test Data / Packs | Execution | manual | free text (pack names, sample data) |
| `W` | Owner | Execution | manual | free text; intentionally left blank by the builder |
| `X` | Latest Status | Status (auto) | **formula** | Status of the newest `▶️ Runs` row for this ID; `Not Run` when no run exists |
| `Y` | Latest Run | Status (auto) | **formula** | `Run ID` of that newest run; empty when none |
| `Z` | Open Bug | Status (auto) | **formula** | Comma-joined `🐞 Bugs` IDs for this test whose `Status` is not `Fixed`/`Verified` |

Block banners (row 1): **Identity** `A:F` (slate) · **Classification** `G:P` (blue) · **Execution** `Q:W` (purple) · **Status (auto)** `X:Z` (green).
Columns `X:Z` are protected with a *warning-only* protection — Sheets will ask for confirmation before you overwrite them.

---

## 4. ID conventions

| Prefix | Feature | Ticket | Example |
|--------|---------|--------|---------|
| `DP` | Derived Packs (opt-in flow) | CIAC-17084 | `DP-001` … `DP-016` |
| `CMN` | Common-Base | CIAC-17084 | `CMN-001` … `CMN-004` |
| `RN` | Release Notes | CIAC-17085 | `RN-001` … `RN-006` |
| `NC` | Notification Center | CIAC-17086 | `NC-001` … `NC-009` |
| `CSP` | CSP BC validation | CIAC-17274 | `CSP-001` … `CSP-007` |
| `SETUP-nn` | Build / PR precondition on `🧱 Setup` | — | `SETUP-01` … `SETUP-07` (2-digit) |
| `RUN-n` | Execution cycle on `▶️ Runs` | — | `RUN-1`, `RUN-2`, … (not padded) |

Rules:

- Test IDs are `<PREFIX>-nnn`, **zero-padded to 3 digits** (`nextTestId_()` enforces this).
- The allowed prefixes are exactly `DP`, `CMN`, `RN`, `NC`, `CSP` (`ID_PREFIXES` in `build.gs`).
- **IDs are never reused and never renumbered.** A new test always takes `max(existing) + 1` for its prefix, even if lower numbers are deprecated. IDs are referenced from `▶️ Runs`, `🐞 Bugs` and every formula — renumbering silently breaks them.

---

## 5. Golden rules

- **Never delete a test row.** Set `Active = Deprecated` (column `E`) — the row renders grey, italic and struck through, and `🔄 Start New Run` skips it.
- **Never reuse an ID.** Not even the number of a deprecated test.
- **Never hand-edit the green Status block** (`X`, `Y`, `Z`) — they are recomputed from `▶️ Runs` and `🐞 Bugs`.
- **Never type a free value into a dropdown column.** Add the value in `⚙️ Config` instead; validation rejects invalid values (`setAllowInvalid(false)`).
- **The `👁️` view sheets are read-only.** They contain a single `QUERY` formula in `A1`; edit `🧪 TestCases` and the views follow.
- **Anything you want to survive a rebuild belongs in `data.gs`.**

---

## 6. Common workflows

### 6.1 Adding a new test

**Via the menu (recommended):**

1. `🧪 Test Plan ▸ ➕ Add Test Row`.
2. Type the ID prefix when prompted: `DP` / `CMN` / `RN` / `NC` / `CSP`.
3. The script appends a row after the last one, assigns the next free ID in `A`, sets `E = Active`, and writes the `C`, `X`, `Y`, `Z` formulas. Validation and formatting are copied down from the row above. The cursor lands on `B` (Ticket).
4. Fill `B`, `D`, `F`–`V`. Leave `C` and `X:Z` alone.

**Manually:** select the last data row, `Ctrl/Cmd + C`, paste into the next row, clear the pasted content, then type the new ID and re-enter the values. This is only worth doing when adding several rows at once — the menu item is safer because it computes the ID for you.

**Then back-port it into `data.gs`** — append the row to `TEST_CASES` in the 21-column order documented at the top of that file. See [§9](#9-keeping-the-repo-and-the-sheet-in-sync).

### 6.2 Adding a value to an existing category

1. Open `⚙️ Config`.
2. Find the column whose header matches the `CONFIG_LISTS` key (e.g. `PackType`).
3. Type the new value in the first empty cell of that column.

The named range `List_<Key>` covers rows **2:200**, so every dropdown bound to it picks up the new value **immediately** — no rebuild needed.

4. Mirror the change in `data.gs` → `CONFIG_LISTS.<Key>`, otherwise the next `buildWorkbook()` will wipe it (the `⚙️ Config` sheet is fully regenerated).

### 6.3 Adding a brand-new category column

1. On `🧪 TestCases`, insert the new column **before the green `Status (auto)` block** (i.e. at or before column `X`), so `X:Z` stay the last three columns.
2. Add a matching entry to `CONFIG_LISTS` in `data.gs`, e.g. `Environment: ['Prod', 'Staging']` — the builder creates the named range `List_Environment` from the key.
3. In `build.gs`:
   - append the header to `TC_HEADERS`,
   - extend the affected entry of `TC_BLOCKS` (the block boundaries are column indexes),
   - add `<newColumnIndex>: 'Environment'` to `TC_VALIDATION`,
   - add a width to `applyTestCaseWidths_()`,
   - map the value in `testCaseRowToSheetRow_()` and extend the row shape in `TEST_CASES`.
4. Run `🧪 Test Plan ▸ 🏗️ Rebuild Workbook`.

> Adding the column by hand in the sheet only survives until the next rebuild. **Putting it in `data.gs` + `build.gs` is what makes it permanent**, because `buildTestCasesSheet_()` regenerates the sheet from those constants.

### 6.4 Adding a new ticket

1. Append the Jira key to `CONFIG_LISTS.Ticket` in `data.gs` (and/or to the `Ticket` column of `⚙️ Config` for immediate use).
2. Choose an ID prefix: reuse an existing one when the ticket covers the same feature, or add a new prefix to `ID_PREFIXES` in `build.gs` when it is a new area.
3. Add the tests (`§6.1`).
4. Run `🏗️ Rebuild Workbook` — the *By Ticket* table on `📊 Dashboard` is generated from `CONFIG_LISTS.Ticket`, so the new row appears only after a rebuild.

The `C` (Jira) column links to `https://jira-hq.paloaltonetworks.local/browse/<key>` via `JIRA_BASE_URL`.

### 6.5 Adding a new Setup / build precondition

1. Append an 8-column row to `SETUPS` in `data.gs`: `Setup ID`, `Title`, `Type`, `Description`, `Deployment Config`, `Depends On`, `Build/Bucket`, `Status`.
2. Use the next free `SETUP-nn` (2-digit, no reuse). `Type` ∈ `Build` / `PR` / `Code+Build` / `Manual`; `Status` ∈ `Pending` / `In Progress` / `Done` / `Failed`.
3. Run `🏗️ Rebuild Workbook`. The `# Tests` and `Blocked Tests` formulas are added automatically, and the new ID becomes selectable in `🧪 TestCases!Q`.
4. During execution, fill `Build/Bucket` (`G`) and flip `Status` (`H`) directly in the sheet — but remember the sheet is regenerated on rebuild, so mirror the values into `data.gs` if they matter.

### 6.6 Executing a test run

1. `🧪 Test Plan ▸ 🔄 Start New Run`.
2. Enter an optional label (build / bucket) when prompted. The script computes the next `RUN-n` and appends one `▶️ Runs` row per **non-deprecated** test, with `Status = Not Run`.
3. For each row, fill:
   - `E Tester`, `F Date` (validated date, `yyyy-mm-dd`), `D Tenant URL`,
   - `G Status` → dropdown `List_RunStatus`,
   - `H Evidence Link` → screenshot / log / artifact URL,
   - `I Bug ID` and `J Notes` when relevant.
4. Nothing else needs to be updated by hand: `🧪 TestCases!X` (`Latest Status`) and `Y` (`Latest Run`) pick up the **last matching row** in `▶️ Runs`, and `📊 Dashboard` + `🎯 Coverage` + the `👁️` views recompute automatically.

Runs validation and colouring cover rows 2–2000.

### 6.7 Filing a bug

1. Open `🐞 Bugs` and add a row:
   - `A Bug ID` → the Jira key (`B` renders the link automatically),
   - `C Test ID` → dropdown of `🧪 TestCases!$A$3:$A$500`,
   - `D Title`, `E Severity` (`Critical`/`High`/`Medium`/`Low`), `F Status` (`Open`/`In Progress`/`Fixed`/`Verified`/`Won't Fix`), `G Found In Run`, `H Owner`, `I Notes`.
2. The bug ID appears in `🧪 TestCases!Z` (`Open Bug`) for that test and is counted in the Dashboard `Open Bugs` KPI **until** `Status` becomes `Fixed` or `Verified`.
3. Also record the `Bug ID` in the corresponding `▶️ Runs` row (`I`) so the failure is traceable to a specific run.

---

## 7. Status legend

`CONFIG_LISTS.RunStatus`, used in `▶️ Runs!G` and mirrored into `🧪 TestCases!X`:

| Status | Meaning | Formatting |
|--------|---------|------------|
| `Not Run` | Row exists in the run, nobody executed it yet. Default seeded value. | none (default row) |
| `In Progress` | Currently being executed. | none (default row) |
| `Pass` | Expected result observed. | light green background `#E8F5E9` |
| `Fail` | Expected result not observed — file a bug. | light red background `#FFEBEE`, bold dark red text `#B71C1C` |
| `Blocked` | Cannot execute: the setup/build/PR is not ready or a prior bug blocks it. | light orange background `#FFF3E0` |
| `Skipped` | Deliberately not executed in this cycle. | grey text `#9E9E9E` |
| `N-A` | Not applicable to this build/tenant combination. | grey text `#9E9E9E` |

Related non-run formatting: a test with `Active = Deprecated` renders grey `#EEEEEE`, italic and struck through; `Priority = P0` renders bold red in column `N`.

---

## 8. Keeping the repo and the sheet in sync

`data.gs` in this repo is the **versioned source of truth for the test *definitions*** — vocabularies, setups and the 42 test cases. **Run results are not versioned**: they live only in the spreadsheet (`▶️ Runs`, `🐞 Bugs`, and the `Owner` / `Build/Bucket` / `Setup Status` cells filled during execution).

### ⚠️ What `buildWorkbook()` actually overwrites

Read `buildTestCasesSheet_()` before assuming anything: it calls `resetSheet_()`, which **clears the entire `🧪 TestCases` sheet in place** (values, notes, conditional formats, filters, merges) and then rewrites rows 3+ from `TEST_CASES`.

> **Any test row added directly in the sheet — including rows created by `➕ Add Test Row` — is permanently lost on the next `🏗️ Rebuild Workbook` unless it has been back-ported into `TEST_CASES` in `data.gs`.**

The same applies to `⚙️ Config`, `🧱 Setup`, `📊 Dashboard`, `🎯 Coverage`, the four `👁️` views and `📖 README`: all are `resetSheet_()`-based and fully regenerated.

The exceptions are `▶️ Runs` and `🐞 Bugs`. Both are preserved when the sheet already holds **more than one data row** (`dataRowCount_(sheet, 1) > 1`); only the header row and formatting are refreshed. With zero or one data row the builder treats the sheet as unseeded and clears it — so a `▶️ Runs` sheet holding a single result row is *not* protected.

### Recommended loop

1. Add or edit tests in `data.gs` first, commit, then rebuild the sheet.
2. If a test was created in the sheet under time pressure, **back-port it into `TEST_CASES` before the next rebuild** (21 columns, order documented at the top of `data.gs`).
3. Never rebuild right before or during an execution cycle without checking that `data.gs` and the sheet agree.
4. Prefer `🎨 Reapply Formatting` over `🏗️ Rebuild Workbook` when you only need to fix styling — it touches formatting, validation and conditional formats only, never data.

### 8.5 Lite version

The lightweight alternative built by `build_lite.gs`. Same `data.gs`, much smaller workbook.

**Install:** create the Apps Script project, paste `data.gs` + `build_lite.gs` (instead of `build.gs`), save, then run **`buildLiteWorkbook`**. The `🧪 Test Plan (Lite)` menu is installed by the builder itself, so it appears without reloading the tab.

**The 3 sheets** (plus the hidden `⚙️ Config`: one column per `CONFIG_LISTS` key, exposed as `LT_<Key>` named ranges over rows 2:200):

| Sheet | Contents |
|-------|----------|
| `📋 Overview` | Six KPI boxes (`Total`, `Pass`, `Fail`, `Blocked`, `Not Run`, `% Done`), a per-ticket progress table with a `SPARKLINE` bar per ticket, and a legend covering both the statuses and the per-ticket block colors. |
| `🧪 Tests` | The working sheet: a title strip plus one colored mini-table per block. |
| `🧱 Setup` | Flat 6-column table from `SETUPS`: `Setup ID`, `Title`, `Type`, `Description` (the deployment note is folded in), `Depends On`, `Status`. |

**The 8 columns of `🧪 Tests`** (`LITE_TEST_HEADERS` / `LITE_TEST_WIDTHS`):

| Col | Header | Width | Meaning |
|-----|--------|-------|---------|
| `A` | ID | 85 | Test ID from `data.gs` (`DP-001`, `CMN-001`, …). |
| `B` | What We Test | 420 | The test `Title`; wrapped. |
| `C` | Expected Result | 520 | The `Expected Result` from `data.gs`; wrapped. |
| `D` | Where | 130 | `Tenant`, or `Tenant Scope` when `Tenant = Multi` (the scope says more than "Multi"). |
| `E` | Setup | 105 | The `Setup Ref` (`SETUP-01` … `SETUP-07`). |
| `F` | Priority | 95 | `P0` / `P1` / `P2`; `P0` renders bold red. |
| `G` | Status | 125 | **The one cell you edit.** A plain value with a dropdown bound to `LT_RunStatus`, seeded `Not Run`. Drives every conditional format and every Overview KPI. |
| `H` | Notes / Evidence | 340 | Free text — links, screenshots, bug keys. Replaces the Full builder's `🐞 Bugs` sheet; wrapped. |

**Blocks are derived, never hardcoded** (`liteDeriveBlocks_()`): rows are grouped on the composite key **`Ticket + Feature + Phase + Pack State + Setup Ref`**, and blocks keep the order in which their key first appears in `TEST_CASES`. A new row in `data.gs` therefore lands in the matching block automatically, and a brand-new combination produces a brand-new block. **The current `data.gs` (42 tests) produces 15 blocks** — verified against `TEST_CASES`.

**Colors and collapsing:** each ticket gets its own color family — `CIAC-17084` blue, `CIAC-17085` orange, `CIAC-17086` green, `CIAC-17274` red, and `Common-Base` purple so it stays visually distinct inside `CIAC-17084` (`LITE_FAMILY_BY_KEY`). Consecutive blocks of the same family alternate between the base and the `alt` shade. Every block's data rows form a row group, so blocks are collapsible from the outline handles in the left margin; they are built expanded.

**Menu:** `🧪 Test Plan (Lite)` → `🏗️ Rebuild` (`buildLiteWorkbook`) and `🔄 Reset Statuses` (`liteResetStatuses`).

**⚠️ Two caveats:**

1. **A rebuild wipes what you typed.** `🏗️ Rebuild` runs `liteBuildTestsSheet_()`, which calls `liteResetSheet_()` on `🧪 Tests`: the sheet is cleared in place and re-rendered from `data.gs`, with every `Status` written back as `Not Run` and every `Notes / Evidence` cell written back empty. **Manually entered statuses and notes are lost on rebuild.** Only rebuild when there is nothing in the sheet you need to keep — or duplicate the tab first.
2. **There is no run history.** One `Status` cell per test means one cycle at a time. `🔄 Reset Statuses` sets every status back to `Not Run` (it keeps `Notes / Evidence` and skips the per-block column-header rows), which silently discards the previous cycle's results. If you need to compare cycles, use the Full builder's `▶️ Runs` sheet.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `#REF!` across formulas | A referenced sheet was deleted or renamed. Cross-sheet references become permanent `#REF!` — this is why `resetSheet_()` wipes sheets instead of deleting them. | Restore the exact sheet name from `SHEETS` in `build.gs`, then run `🏗️ Rebuild Workbook`. If the `#REF!` persists, undo the rename or restore an earlier version via **File → Version history**. |
| `#N/A` or `Not Run` in `Latest Status` (`X`) | No `▶️ Runs` row matches the test ID, or the ID in `Runs!B` does not match `TestCases!A` exactly (trailing space, wrong padding such as `DP-1` vs `DP-001`). | Check `▶️ Runs!B` against `🧪 TestCases!A`. Re-pick the ID from the dropdown rather than typing it. `Not Run` with no runs at all is the intended fallback, not an error. |
| "You are trying to edit a protected cell or range" | You are editing `🧪 TestCases!X:Z`, which is protected *warning-only*. | Don't — those cells are computed. If a formula was already overwritten, run `🏗️ Rebuild Workbook` (or copy the formula down from a healthy row). |
| Duplicate / stale named range error | `List_<Key>` already exists pointing at an old range, e.g. after manually renaming a `⚙️ Config` column. | `createConfigNamedRanges_()` removes and recreates every `List_<Key>` it owns — just rebuild. For orphaned names from a removed key, delete them in **Data → Named ranges**. |
| "Exceeded maximum execution time" / script timeout | Apps Script caps a run at ~6 minutes; a very large `TEST_CASES` or a `▶️ Runs` sheet with thousands of rows can hit it. | Re-run — most builders are idempotent and the completed sheets stay. If it keeps failing, trim `TC_LAST_ROW` / `RUNS_LAST_ROW`, archive old runs to another spreadsheet, or run the individual `build*Sheet_()` functions one at a time from the editor. |
| `🧪 Test Plan` menu missing | `onOpen()` runs only when the spreadsheet is opened. | Reload the browser tab. If it is still missing, run `onOpen` once manually from the Apps Script editor. |
| Dropdown rejects a valid-looking value | The value is not in the `⚙️ Config` column, or it sits below row 200 (outside `List_<Key>`). | Add it within rows 2:200 of the right column, and mirror it into `CONFIG_LISTS`. |

---

## 10. Test inventory

42 test cases across 4 tickets (verified against `TEST_CASES` in `data.gs`):

| Ticket | Feature | ID range | Count |
|--------|---------|----------|-------|
| CIAC-17084 | Derived Packs | `DP-001` … `DP-016` | 16 |
| CIAC-17084 | Common-Base | `CMN-001` … `CMN-004` | 4 |
| CIAC-17085 | Release Notes | `RN-001` … `RN-006` | 6 |
| CIAC-17086 | Notification Center | `NC-001` … `NC-009` | 9 |
| CIAC-17274 | CSP BC Validation | `CSP-001` … `CSP-007` | 7 |
| **Total** | | | **42** |

Supporting data: **18** dropdown categories in `CONFIG_LISTS`, **7** setups (`SETUP-01` … `SETUP-07`) in `SETUPS`.
