# Step 1: Gather Requirements — Handle Ticket and Design Ingestion

## Purpose

Collect all necessary information from the user's design document to enable subsequent
generation steps. The design document is the single source of truth for the collector's
specification.

## Input Methods

The user can provide the design in one of these ways:

| Method | How to handle |
|--------|---------------|
| **Jira ticket key** (e.g., `CIAC-15359`) | Fetch the ticket → find the Design field → extract the design URL → read the design |
| **Google Docs URL** | Read the document content using the Google Docs skill |
| **Local file path** (e.g., `path/to/design.md`) | Read the file using `read_file` |
| **Direct copy-paste** | User pastes the design content directly in chat |
| **Attached file** | Download from Jira attachments if referenced |

## Step-by-Step Workflow

### Step 1.1: Identify the Input

When the user activates this mode, determine which input method they're using:
- If they provide a Jira ticket key → go to Step 1.2
- If they provide a Google Docs URL → go to Step 1.3
- If they provide a local file path → read it with `read_file` → go to Step 1.4
- If they reference a file attached to a Jira ticket → download it from the ticket's attachments (see Step 1.2) → go to Step 1.4
- If they paste text content → go to Step 1.4
- If unclear → ask the user what they're providing

### Step 1.2: Fetch Jira Ticket

1. Use `jira_get_issue` with `fields: '*all'` to fetch the full ticket.
2. Search through all fields in the response for a field whose name contains "Design"
   (case-insensitive). Do NOT hardcode a specific custom field ID — the field ID may change.
3. Extract the design URL from that field.
4. If the Design field contains a Google Docs URL → go to Step 1.3.
5. If the Design field is empty or missing → check the ticket's attachments for `.md` files.
6. If no design is found anywhere → ask the user to provide the design document directly.

**Additional data to extract from the Jira ticket** (if available):
- Ticket summary (may contain the product name)
- Description (may contain event types, DoD)
- Labels
- Comments (may contain design decisions, clarifications)

### Step 1.3: Read Google Docs

1. If the Google Docs skill is available, use it to read the document content.
   - This requires `gcloud auth` to be set up. If authentication fails, ask the user
     to run: `gcloud auth login --enable-gdrive-access --update-adc`
2. If the Google Docs skill is NOT available, ask the user to either:
   - Install the Google Docs skill (recommended), OR
   - Copy-paste the design content directly into chat, OR
   - Export the Google Doc as `.md` or `.txt` and provide the file path
3. Proceed to Step 1.4 with the extracted content.

### Step 1.4: Parse the Design Content

**⚠️ Gate first — is this a collector, and which sub-type?**

Before doing any detailed parsing, do a quick scan to classify the design:

| Result | Signal in the design | Action |
|--------|----------------------|--------|
| **Collector — Fetch Events** | `fetch-events` / events → dataset (`isfetchevents: true`); commands `fetch-events` + `<prefix>-get-events`; time field maps to `_time` | Parse the tables below. |
| **Collector — Fetch Incidents** | `fetch-incidents` / incidents → queue (`isfetch: true`); commands `fetch-incidents` + `<prefix>-get-incidents`; time field maps to `occurred` | Parse the tables below. |
| **Mixed** (collector + custom commands) | Has a fetch mechanism *and* custom commands | Treat as a collector; ignore the custom commands. Determine the collector sub-type as above. |
| **Automation only** | Only custom commands (list/get/update/delete), **no** fetch mechanism | **STOP. Do not parse the tables below.** Show the gate message and end Step 1. |
| **Unclear** | — | Ask the user explicitly before proceeding. |

**🚫 Automation gate message:**

> "⚠️ Automation integrations are not yet supported by the Content Code Generator.
> This feature is planned for a future release. Please create automation integrations
> manually for now."

Store the collector sub-type (Events vs. Incidents) — it is used in every subsequent step.

> The detailed tables (A–F) below are **collector-specific** (endpoints, fetch behavior,
> pagination, time mapping). Only parse them once the design is confirmed to be a collector.

---

Once confirmed as a collector, read the design **in full** and extract all relevant
information. The tables below list the **minimum required items**, grouped by concern — but
also capture any additional details from the design that may be useful for generation (e.g.,
API response schemas, error handling notes, extra field mappings).

For any item that is NOT explicitly stated in the design — **ask the user**. Do NOT guess.

The **Example** column below shows what each item looks like in practice, using a real
JumpCloud Directory Insights design for illustration.

#### A. Identity & Metadata

| # | Information | Where to look | Example |
|---|-------------|---------------|---------|
| 1 | Pack name | Title / "Pack (NEW):" line | `JumpCloud` |
| 2 | Integration display name | Title / "Integration (NEW):" line | `JumpCloud Directory Insights` |
| 3 | Vendor (dataset config) | Vendor/product section (`vendor:`) | `jumpcloud` |
| 4 | Product (dataset config) | Vendor/product section (`product:`) | `directory_insights` |
| 5 | Dataset name | Description / "Dataset Name:" | `jumpcloud_directory_insights_raw` |
| 6 | Category | Header / metadata | `Analytics & SIEM` |
| 7 | Command prefix | Derived from product — confirm with user | `jumpcloud` |

#### B. Connection & Authentication

| # | Information | Where to look | Example |
|---|-------------|---------------|---------|
| 8 | API base URL (+ default) | API section / parameters table | (e.g. JumpCloud Directory Insights base URL) |
| 9 | Authentication method | Authorization Information section | API Key (header) |
| 10 | Auth header name(s) | Headers block | `x-api-key`; optional `x-org-id` |
| 11 | Other required headers | Headers block | `Content-Type: application/json` |

#### C. Fetch & API Behavior

| # | Information | Where to look | Example |
|---|-------------|---------------|---------|
| 12 | API endpoint + HTTP method | APIs section | `POST /insights/directory/v1/events` |
| 13 | Request body / query params | "Body Params" / "Query Params" | `service`, `start_time`, `end_time`, `limit`, `sort`, `search_after` |
| 14 | Event types — the param name AND its **complete** list of valid values (capture every value verbatim; these become the YML multi-select options). If the design truncates the list, get the full list from the API docs or ask the user. | Body Param value list (e.g. the `service` param) | param `service`; values: `access_management`, `alert`, `all`, `directory`, `ldap`, `mdm`, `notifications`, `object_storage`, `password_manager`, `radius`, `reports`, `saas_app_management`, `software`, `sso`, `systems`, `asset_management`, `genai`, `aigw`, `di_events` (default `all`) |
| 15 | Time-range filtering support + time format | API params (start/end time) | Yes — `start_time` (req), `end_time` (opt), RFC3339 UTC |
| 16 | Sort order — supported values + the one to use | API params | `sort`: values `ASC` / `DESC`; use `ASC` (chronological ingestion) |
| 17 | Pagination style | Pagination section | Cursor-based (via `search_after`) |
| 18 | Pagination mechanics — capture exactly *where* each value lives (request body field vs. response header) and the loop logic | Pagination section | **Request body field:** `search_after` (cursor). **Response headers:** `X-Search_after` (next cursor value), `X-Result-Count` (rows returned), `X-Limit` (page size). **Loop:** send the query → read the 3 headers → if `X-Result-Count == X-Limit`, re-send the identical query with body `search_after` set to the latest `X-Search_after` → repeat → stop when `X-Result-Count < X-Limit`. |
| 19 | Page size (per single API call) + API max | API params (`limit`) | default 1000, max 10,000 → collector uses 10,000 |
| 20 | Max events per entire fetch run (total) | Parameters / pagination | 10,000 × 10 = 100,000 |
| 21 | Rate limits | APIs "Rate Limit" note | Not documented (result-size limits only) |

#### D. Field Mappings (per event)

| # | Information | Where to look | Example |
|---|-------------|---------------|---------|
| 22 | Time field → `_time` (events) / `occurred` (incidents) | "`_TIME` field mapping" / field table | `timestamp` |
| 23 | `source_log_type` field | "`source_log_type`" note | per-event `service` (e.g. `directory`, `radius`, `sso`) |

#### E. Full Parameters Table (UI configuration)

This is the **complete list of every instance parameter** the user sees in the UI — the one
that becomes the YML `configuration` section in Step 4 (Generate YAML). Go through the design's parameters
table and record **all attributes for every parameter** (not just the connection ones from
section B). The row below shows the attributes to capture, illustrated with one example
parameter.

| Attribute to capture | Where to look | Example (the `Organization ID` parameter) |
|----------------------|---------------|-------------------------------------------|
| Display name | Parameters table | `Organization ID` |
| YAML name / alias | "(YAML: …)" note | `org_id` |
| Required | Parameters table | No |
| Default value | Parameters table | (empty) |
| Section (Connect/Collect) | Parameters table | Connect – advanced settings |
| Type / widget | Parameters table | text |
| Note / behavior | Parameters table | sent as `x-org-id` header when set |

#### F. Documentation

| # | Information | Where to look | Example |
|---|-------------|---------------|---------|
| 24 | Description / Help content | "Prerequisites / Help" section | API-key creation steps + MSP `org_id` note |

**Note:** Each subsequent step (3–14) defines its own specific requirements. If a later
step discovers something missing that wasn't captured here, it will ask the user at that
point. Step 1 focuses on capturing the design content — not on validating completeness
for every step.

### Step 1.5: Present Summary and Confirm

After extracting all information, present a **summary table** to the user showing what was
found and what's missing. Ask for confirmation before proceeding to Step 2.

Format:
```
📋 Design Summary for [Product Name]

| # | Item | Value | Source |
|---|------|-------|--------|
| 1 | Collector type | Events / Incidents | Jira ticket / Design doc |
| 2 | Pack name | MyProduct | Design doc |
| 3 | Integration name | MyProduct | Design doc |
| ... | ... | ... | ... |

⚠️ Missing information (need your input):
- [list any items not found in the design]

[If nothing is missing:]   Does this look correct? Ready to proceed to Step 2?
[If items are missing:]     Please provide the values for the missing items above so I can continue.
```

**🚫 Hard gate — do NOT proceed to Step 2 while anything is missing (Core Rule 3):**

- If the "Missing information" list is **non-empty**, you are **blocked**. Ask the user to
  provide the missing values and **wait**.
- **User approval is not enough.** Even if the user says "looks good / proceed", do NOT
  advance while any required item is still blank — the actual values must be supplied first.
- Re-present the updated summary after the user fills in values; only when **every** required
  item has a concrete value may you proceed to Step 2.

## Important Rules

- **Jira MCP tools are native function calls** — use `jira_get_issue` directly, never via
  curl or execute_command.
- **Google Docs access** uses the Google Docs skill — requires `gcloud auth` setup.
- **Never hardcode custom field IDs** — always search by field name.
- **The design document is the source of truth** — do not override its content with assumptions.
- **If the design is incomplete** — ask the user for the missing pieces. Do not proceed
  with gaps.
