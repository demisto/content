import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import csv
import io
import traceback
from datetime import datetime, timezone

ACTION_COLUMNS = ["alert_id", "keep_id", "victim_id", "victim_name", "victim_owner", "victim_close_reason"]
INLINE_SAMPLE = 50

# The fetched incidents are classified into these subtypes; querying the bare
# parent type alone (or a quoted wildcard) does not reliably match them.
DOPPEL_INCIDENT_TYPES = [
    "Doppel Alert",
    "Doppel Alert Domains",
    "Doppel Alert Social_Media",
    "Doppel Alert Mobile_Apps",
    "Doppel Alert Ecommerce",
    "Doppel Alert Email",
    "Doppel Alert Crypto",
    "Doppel Alert Paid_Ads",
]
DEFAULT_QUERY = " or ".join(f'type:"{t}"' for t in DOPPEL_INCIDENT_TYPES)


def _to_dt(value: Any) -> datetime | None:
    """Parse a timestamp into a timezone-aware datetime, or None if it can't be parsed."""
    if not value:
        return None
    try:
        return arg_to_datetime(str(value))
    except (ValueError, TypeError):
        return None


def _alert_key(incident: dict) -> str:
    """Returns the Doppel alert id used to group duplicates."""
    key = incident.get("dbotMirrorId")
    if key:
        return str(key)
    custom_fields = incident.get("CustomFields") or {}
    for name in ("alertid", "doppelalertid", "alertID", "doppelalertID"):
        if custom_fields.get(name):
            return str(custom_fields.get(name))
    return ""


def _ranked(group: list) -> list:
    """Sort a group deterministically: oldest created first, then lowest incident id."""

    def sort_key(inc):
        created = _to_dt(inc.get("created")) or datetime.max.replace(tzinfo=timezone.utc)
        try:
            inc_id = int(inc.get("id"))
        except (ValueError, TypeError):
            inc_id = float("inf")
        return (created, inc_id)

    return sorted(group, key=sort_key)


def _is_closed(incident: dict) -> bool:
    """True if the incident is already closed, so we never touch or overwrite it."""
    status = incident.get("status")
    if status in (IncidentStatus.DONE, str(int(IncidentStatus.DONE))):  # XSOAR "Closed" status
        return True
    if str(incident.get("closeReason") or "").strip():
        return True
    closed = str(incident.get("closed") or "")
    if closed and not closed.startswith("0001"):  # default empty timestamp is year 0001
        return True
    return False


def plan_dedupe(incidents: list) -> dict:
    """Group incidents by Doppel alert id; keep one OPEN survivor, action the rest.

    Only OPEN incidents are ever acted on. Already-closed incidents (any reason -
    Duplicate, False Positive, Resolved, ...) are left completely untouched, so an
    analyst's disposition is never overwritten and re-runs are idempotent.

    The survivor is the oldest OPEN incident that has an owner (analyst work in
    progress), or the oldest OPEN incident if none are owned.

    Returns 'actions' (open duplicates to close/delete), 'flagged' (a subset that
    have an owner and warrant a human glance), 'group_count', and 'skipped_closed'.
    """
    groups = {}
    for inc in incidents:
        key = _alert_key(inc)
        if not key:
            continue
        groups.setdefault(key, []).append(inc)

    actions = []
    flagged = []
    group_count = 0
    skipped_closed = 0
    for key, group in groups.items():
        if len(group) < 2:
            continue
        open_incidents = [inc for inc in group if not _is_closed(inc)]
        skipped_closed += len(group) - len(open_incidents)
        # Need at least two OPEN incidents to have a redundant one to consolidate.
        if len(open_incidents) < 2:
            continue
        group_count += 1
        ordered = _ranked(open_incidents)
        # Prefer keeping an open incident an analyst is actively working: the
        # oldest open one that has an owner. If none are owned, fall back to the
        # oldest open incident. Owner is used only to break the tie (never as a
        # hard "don't close" gate), so auto-assignment can't block consolidation.
        owned = [inc for inc in ordered if str(inc.get("owner") or "").strip()]
        survivor = owned[0] if owned else ordered[0]
        for victim in ordered:
            if victim is survivor:
                continue
            owner = str(victim.get("owner") or "").strip()
            close_reason = str(victim.get("closeReason") or "").strip()
            entry = {
                "alert_id": key,
                "keep_id": survivor.get("id"),
                "victim_id": victim.get("id"),
                "victim_name": victim.get("name"),
                "victim_owner": owner,
                "victim_close_reason": close_reason,
            }
            actions.append(entry)
            if owner or close_reason:
                flagged.append(entry)
    return {"actions": actions, "flagged": flagged, "group_count": group_count, "skipped_closed": skipped_closed}


_SLIM_CUSTOM_FIELDS = ("alertid", "doppelalertid", "alertID", "doppelalertID")


def _slim(inc: dict) -> dict:
    """Keep only the fields the dedupe logic needs.

    getIncidents returns the full incident object (~69 fields incl. SLA blocks,
    labels, etc.). Holding tens of thousands of those in memory is what makes a
    large scan slow and memory-heavy, so we project down to the handful of
    fields used by _alert_key / _ranked / _is_closed / plan_dedupe.
    """
    custom = inc.get("CustomFields") or {}
    return {
        "id": inc.get("id"),
        "name": inc.get("name"),
        "created": inc.get("created"),
        "owner": inc.get("owner"),
        "status": inc.get("status"),
        "closeReason": inc.get("closeReason"),
        "closed": inc.get("closed"),
        "dbotMirrorId": inc.get("dbotMirrorId"),
        "CustomFields": {k: custom.get(k) for k in _SLIM_CUSTOM_FIELDS if custom.get(k)},
    }


def search_incidents(query: str, page_size: int, max_pages: int) -> list:
    """Page through getIncidents until a short/empty page (or the page ceiling).

    We deliberately do NOT trust the 'total' field: some XSOAR versions return
    total=0 even when data is present, which would stop the scan after one page
    and silently miss most incidents. Instead we page until a page returns fewer
    than page_size results (the last page) or returns nothing.

    Each incident is trimmed to the fields we actually use (see _slim) so the
    scan stays light enough to finish within the automation timeout at 38k+.
    """
    incidents = []
    seen_ids = set()
    page = 0
    while page < max_pages:
        res = demisto.executeCommand("getIncidents", {"query": query, "page": page, "size": page_size})
        if is_error(res):
            raise DemistoException(f"getIncidents failed: {get_error(res)}")
        if not res or not isinstance(res, list):
            break
        contents = res[0].get("Contents") or {}
        if not isinstance(contents, dict):
            break
        batch = contents.get("data") or []
        if not batch:
            break
        for inc in batch:
            inc_id = str(inc.get("id"))
            if inc_id not in seen_ids:
                seen_ids.add(inc_id)
                incidents.append(_slim(inc))
        page += 1
        # A page smaller than the requested size means we've reached the end.
        if len(batch) < page_size:
            break
    return incidents


def _actions_csv(rows: list) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=ACTION_COLUMNS)
    writer.writeheader()
    for row in rows:
        writer.writerow({col: row.get(col, "") for col in ACTION_COLUMNS})
    return buf.getvalue()


def close_incident(victim_id: Any, keep_id: Any, alert_id: str) -> None:
    res = demisto.executeCommand(
        "closeInvestigation",
        {
            "id": str(victim_id),
            "closeReason": "Duplicate",
            "closeNotes": f"Consolidated by DoppelDedupeIncidents - redundant incident for Doppel alert "
            f"{alert_id}; canonical incident: {keep_id}.",
        },
    )
    if is_error(res):
        raise DemistoException(f"Failed to close incident {victim_id}: {get_error(res)}")


def delete_incident(victim_id: Any) -> None:
    res = demisto.executeCommand("deleteIncidents", {"ids": str(victim_id), "force": "true"})
    if is_error(res):
        raise DemistoException(f"Failed to delete incident {victim_id}: {get_error(res)}")


def main() -> None:
    args = demisto.args()
    action = (args.get("action") or "close").lower()
    dry_run = argToBoolean(args.get("dry_run", "true"))
    query = args.get("query") or DEFAULT_QUERY
    page_size = arg_to_number(args.get("page_size")) or 100
    max_pages = arg_to_number(args.get("max_pages")) or 1000
    limit = arg_to_number(args.get("limit")) or 0

    try:
        incidents = search_incidents(query, page_size, max_pages)
        plan = plan_dedupe(incidents)
        actions = plan["actions"]
        flagged = plan["flagged"]

        # Apply the per-run cap (0 = no limit) so a large backlog can be drained
        # in safe batches. Already-closed incidents are skipped on the next scan,
        # so re-running naturally continues where this run stopped.
        batch = actions if limit <= 0 else actions[:limit]

        performed = []
        if not dry_run:
            for act in batch:
                if action == "delete":
                    delete_incident(act["victim_id"])
                else:
                    close_incident(act["victim_id"], act["keep_id"], act["alert_id"])
                performed.append(act)

        # "Remaining" is what this run did not act on: planned actions beyond the
        # batch (dry run) or planned actions not yet performed (real run).
        if dry_run:
            remaining = max(len(actions) - len(batch), 0)
        else:
            remaining = max(len(actions) - len(performed), 0)

        md = "# Doppel Dedupe Report\n"
        md += f"- Mode: **{'DRY RUN (no changes made)' if dry_run else action.upper()}**\n"
        md += f"- Incidents scanned: **{len(incidents)}**\n"
        md += f"- Duplicate groups with open redundant incidents: **{plan['group_count']}**\n"
        md += f"- Open duplicate incidents to {action} (total): **{len(actions)}**\n"
        md += f"- Of those, with an owner (review suggested): **{len(flagged)}**\n"
        md += f"- Already-closed incidents left untouched: **{plan['skipped_closed']}**\n"
        if limit > 0:
            md += f"- Per-run limit: **{limit}**\n"
        if not dry_run:
            md += f"- {action.capitalize()}d this run: **{len(performed)}**\n"
            md += f"- Remaining (re-run to continue): **{remaining}**\n"
        elif limit > 0 and actions:
            runs_needed = -(-len(actions) // limit)  # ceil division
            md += f"- With this limit it will take about **{runs_needed}** run(s) to finish.\n"
        md += "\n"

        sample_source = performed if not dry_run else actions
        if sample_source:
            shown = min(INLINE_SAMPLE, len(sample_source))
            verb = "Completed actions" if not dry_run else "Planned actions"
            title = f"{verb} (showing first {shown} of {len(sample_source)}; full list in the attached CSV)"
            md += tableToMarkdown(title, sample_source[:INLINE_SAMPLE])
        else:
            md += "_No duplicate incidents to act on._\n"
        if flagged:
            md += "\n" + tableToMarkdown("Open duplicates with an owner (review before non-dry run)", flagged)

        results = [
            CommandResults(
                readable_output=md,
                outputs_prefix="Doppel.Dedupe",
                outputs={
                    "scanned": len(incidents),
                    "dry_run": dry_run,
                    "action": action,
                    "limit": limit,
                    "duplicate_groups": plan["group_count"],
                    "skipped_closed": plan["skipped_closed"],
                    "total_actions": len(actions),
                    "remaining": remaining,
                    "actions": actions,
                    "flagged": flagged,
                    "performed": performed,
                },
            )
        ]
        # Attach the full plan (dry run) or the completed actions (real run) as a
        # downloadable CSV, so the 30k-scale list is reviewable outside the War Room.
        csv_rows = actions if dry_run else performed
        if csv_rows:
            csv_name = "doppel_dedupe_plan.csv" if dry_run else f"doppel_dedupe_{action}d.csv"
            results.append(fileResult(csv_name, _actions_csv(csv_rows)))

        return_results(results)
    except Exception as e:  # noqa: BLE001
        demisto.error(traceback.format_exc())
        return_error(f"DoppelDedupeIncidents failed: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
