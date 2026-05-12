# Microsoft Sentinel Integration — Lookback Mechanism Analysis

## 1. Current Fetch Mechanism (How It Works Today)

The fetch flow is: `fetch_incidents_command()` → `fetch_incidents()` → `list_incidents_command()` → `process_incidents()`

- [`fetch_incidents_command()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:1555) — Entry point, reads params, calls `fetch_incidents()`, sets last run
- [`fetch_incidents()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:1478) — Core logic: builds OData filter, calls API, dedup, returns incidents
- [`list_incidents_command()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:994) — Executes the HTTP GET to Azure Sentinel API
- [`process_incidents()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:1575) — Converts raw incidents to XSOAR format, builds `next_run`

### Two Fetch Paths

The integration has **two distinct query strategies**:

1. **Timestamp-based** (first run, or when `last_incident_number` is missing):
   - Filters: `properties/createdTimeUtc ge {time} + severity_filter + status_filter`
   - Orders by: `properties/createdTimeUtc asc`

2. **Incident-number-based** (steady-state, subsequent runs):
   - Filters: `properties/incidentNumber gt {last_number} + severity_filter + status_filter`
   - Orders by: `properties/incidentNumber asc`

### The Core Problem

Both paths apply the **severity filter at query time**. If an incident is created as `Low` severity, it is **excluded by the OData filter** and never fetched. If it later escalates to `High`, the integration never sees it because:
- The `createdTimeUtc` has already passed the fetch window
- The `incidentNumber` is already below `last_incident_number`

---

## 2. Important Arguments & Parameters

### Current Fetch Parameters (from [`AzureSentinel.yml`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.yml:9))

| Parameter | YAML Name | Type | Default | Purpose |
|---|---|---|---|---|
| Max incidents per fetch | `limit` | Short Text (0) | `20` | Capped at `FETCH_MAX_LIMIT = 20` |
| First fetch time | `fetch_time` | Short Text (0) | `3 days` | How far back to look on first run |
| Minimum severity | `min_severity` | Single Select (15) | `Informational` | Options: Informational, Low, Medium, High |
| Incident statuses | `statuses_to_fetch` | Multi Select (16) | All | Options: New, Active, Closed |
| Additional info | `fetch_additional_info` | Multi Select (16) | None | Alerts, Entities, Comments, Relations |
| Fetch interval | `incidentFetchInterval` | Number (19) | `1` minute | How often fetch runs |

### Current `last_run` Object Structure

```python
{
    "last_fetch_time": "2026-05-09T10:00:00Z",      # latest createdTimeUtc seen
    "last_fetch_ids": ["id1", "id2"],                 # IDs from last batch (dedup)
    "last_incident_number": 1234                      # highest incidentNumber seen
}
```

### Key Helper Functions

| Function | Location | Purpose |
|---|---|---|
| [`severity_filter()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:578) | Line 578 | Builds OData `and (severity eq 'X' or ...)` clause |
| [`status_filter()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:591) | Line 591 | Builds OData `and (status eq 'X' or ...)` clause |
| [`severity_to_level()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:563) | Line 563 | Maps severity string → numeric (Informational=0.5, Low=1, Medium=2, High=3) |
| [`process_incidents()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:1575) | Line 1575 | Converts raw → XSOAR format, updates `next_run` |
| [`incident_data_to_xsoar_format()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:324) | Line 324 | Extracts `properties/*` into flat dict, includes `LastModifiedTimeUTC` |

---

## 3. Reference Lookback Implementations

### CommonServerPython Built-in Helpers (Recommended Approach)

The platform provides three ready-made functions in [`CommonServerPython.py`](../Packs/AzureSentinel/Integrations/AzureSentinel/CommonServerPython.py:11549):

| Function | Line | What It Does |
|---|---|---|
| [`get_fetch_run_time_range()`](../Packs/AzureSentinel/Integrations/AzureSentinel/CommonServerPython.py:11549) | 11549 | Calculates `(start_time, end_time)` — if `look_back > 0`, pushes `start_time` back by N minutes from `now` |
| [`filter_incidents_by_duplicates_and_limit()`](../Packs/AzureSentinel/Integrations/AzureSentinel/CommonServerPython.py:11631) | 11631 | Removes already-fetched IDs using `found_incident_ids` in `last_run` |
| [`update_last_run_object()`](../Packs/AzureSentinel/Integrations/AzureSentinel/CommonServerPython.py:11855) | 11855 | Updates `last_run` with new time, limit, and `found_incident_ids` |

### How ServiceNow Uses Them (Pattern to Follow)

From [`ServiceNowv2.py`](../Packs/ServiceNow/Integrations/ServiceNowv2/ServiceNowv2.py:2625):

```python
# 1. Get time range with lookback
start_time, end_time = get_fetch_run_time_range(
    last_run=last_run, first_fetch=first_fetch,
    look_back=look_back, date_format=DATE_FORMAT
)

# 2. Query API with start_time (pushed back by lookback)
tickets = api_call(query=f"timestamp > {start_time}")

# 3. Filter out already-fetched duplicates
tickets = filter_incidents_by_duplicates_and_limit(
    incidents_res=tickets, last_run=last_run,
    fetch_limit=limit, id_field="sys_id"
)

# 4. Update last_run with dedup tracking
last_run = update_last_run_object(
    last_run=last_run, incidents=incidents, fetch_limit=limit,
    start_fetch_time=start_time, end_fetch_time=end_time,
    look_back=look_back, created_time_field="occurred",
    id_field="sys_id", date_format=DATE_FORMAT
)
```

---

## 4. Implementation Steps for the Lookback Feature

### Step 1 — Add YAML Parameter

Add a `look_back` parameter to [`AzureSentinel.yml`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.yml:9) (in the `Collect` section, near the other fetch params):

```yaml
- name: look_back
  display: Lookback Time (minutes)
  type: 0
  section: Collect
  advanced: true
  required: false
  defaultvalue: '0'
  additionalinfo: >
    Time in minutes to look back when fetching incidents.
    Use this to catch incidents whose severity escalated after initial creation.
    When set to 0, lookback is disabled (default behavior).
```

### Step 2 — Change the Query Strategy (Critical Change)

When `look_back > 0`, you must:

1. **Query by `lastModifiedTimeUtc`** instead of `createdTimeUtc` — this catches incidents that were modified (severity changed) within the lookback window
2. **Remove the severity filter from the OData query** — fetch ALL incidents in the time window
3. **Apply severity filtering in Python** after fetching — so you catch incidents that escalated

### Step 3 — Use CommonServerPython Helpers

Replace the custom dedup logic (`last_fetch_ids`) with the standard [`filter_incidents_by_duplicates_and_limit()`](../Packs/AzureSentinel/Integrations/AzureSentinel/CommonServerPython.py:11631) and [`update_last_run_object()`](../Packs/AzureSentinel/Integrations/AzureSentinel/CommonServerPython.py:11855).

### Step 4 — Update `last_run` Structure

The `last_run` object needs to change to match what the CSP helpers expect:

```python
# New last_run structure (when lookback enabled):
{
    "time": "2026-05-09T10:00:00Z",           # managed by update_last_run_object
    "found_incident_ids": {"id1": "", ...},    # managed by update_last_run_object
    "limit": 20,                                # managed by update_last_run_object
    "last_incident_number": 1234                # keep for backward compat
}
```

### Step 5 — Modify [`fetch_incidents()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:1478)

The function signature needs a new `look_back` parameter. The core logic change:

```python
def fetch_incidents(client, last_run, first_fetch_time, min_severity,
                    statuses_to_fetch=[], look_back=0):
    if look_back > 0:
        # Use CSP helper for time range with lookback
        start_time, end_time = get_fetch_run_time_range(
            last_run=last_run, first_fetch=first_fetch_time,
            look_back=look_back, date_format=DATE_FORMAT
        )
        # Query by lastModifiedTimeUtc WITHOUT severity filter
        command_args = {
            "filter": f"properties/lastModifiedTimeUtc ge {start_time}"
                      f" {status_filter(statuses_to_fetch)}".strip(),
            "orderby": "properties/lastModifiedTimeUtc asc",
            "limit": limit,
        }
        raw_incidents = list_incidents_command(client, command_args, is_fetch_incidents=True).outputs
        # Dedup using CSP helper
        raw_incidents = filter_incidents_by_duplicates_and_limit(
            raw_incidents, last_run, limit, id_field="ID"
        )
        # Post-filter severity in Python
        raw_incidents = [inc for inc in raw_incidents
                         if severity_to_level(inc.get("Severity")) >= severity_to_level(min_severity)]
    else:
        # ... existing logic unchanged ...
```

### Step 6 — Update [`fetch_incidents_command()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:1555)

```python
def fetch_incidents_command(client, params):
    first_fetch_time = params.get("fetch_time", "3 days").strip()
    min_severity = params.get("min_severity", "Informational")
    statuses_to_fetch = argToList(params.get("statuses_to_fetch", []))
    look_back = arg_to_number(params.get("look_back")) or 0  # NEW
    # ... pass look_back to fetch_incidents() ...
```

### Step 7 — Update [`process_incidents()`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel.py:1575)

When lookback is enabled, use [`update_last_run_object()`](../Packs/AzureSentinel/Integrations/AzureSentinel/CommonServerPython.py:11855) instead of the manual `next_run` construction.

### Step 8 — Tests & Release Notes

- Add tests in [`AzureSentinel_test.py`](../Packs/AzureSentinel/Integrations/AzureSentinel/AzureSentinel_test.py:27) covering:
  - `look_back=0` (backward compatibility, existing behavior)
  - `look_back>0` with severity escalation scenario
  - Dedup: same incident not re-ingested if severity hasn't changed
  - Dedup: incident IS re-ingested if severity escalated to match filter
- Create a new release note in `Packs/AzureSentinel/ReleaseNotes/`

---

## 5. Key Considerations & Gotchas

| Concern | Detail |
|---|---|
| **API rate limits** | Lookback re-queries the same time window each cycle. With `look_back=60` and `incidentFetchInterval=1`, you query the same 60-min window every minute. Keep `limit` reasonable. |
| **`lastModifiedTimeUtc` vs `createdTimeUtc`** | You MUST switch to `lastModifiedTimeUtc` for the lookback query. `createdTimeUtc` won't catch severity changes. |
| **Backward compatibility** | When `look_back=0` (default), the existing behavior must be preserved exactly. The `last_run` format changes, so handle migration from old format. |
| **`last_run` migration** | On first run after upgrade, `last_run` will have old keys (`last_fetch_time`, `last_fetch_ids`). Detect and migrate to new format (`time`, `found_incident_ids`). |
| **Incident-number path** | The steady-state path (line 1528-1541) queries by `incidentNumber gt X`. With lookback, this path should be bypassed — always use the time-based path. |
| **Severity post-filtering** | When lookback is on, you fetch MORE incidents (no severity filter in OData) and filter in Python. This means more API data transfer per cycle. |
| **`FETCH_MAX_LIMIT = 20`** | The current hard cap is 20 incidents per fetch. With lookback re-querying, the effective throughput may need to increase. Consider whether to raise this. |
