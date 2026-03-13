# Script name: displayTMV1ProcessFile_FromAlertDetails
# Purpose: Render a Process & File view using VisionOne Alert Details already in context OR from mapped fields.
# Notes:
#  - No external calls; reads what's already in context / incident custom fields.
#  - Works with correlation-rule output where indicators are stored as JSON string.
#  - Matched Process Events require the full alert object (matched_rules) to exist in context.

import json
import demistomock as demisto
from CommonServerPython import *
from collections import defaultdict

# -------------------- tiny helpers --------------------
def md_out(text):
    demisto.results({"Type": 1, "ContentsFormat": "markdown", "Contents": text})

def esc(s):
    if s is None:
        return ""
    if not isinstance(s, str):
        try:
            s = json.dumps(s, ensure_ascii=False)
        except Exception:
            s = str(s)
    return s.replace("`", "\\`")

def flat_join(seq, sep=", "):
    if not seq:
        return ""
    return sep.join(str(x) for x in seq if x not in (None, ""))

def safe_json_loads(maybe_json):
    if maybe_json is None:
        return None
    if isinstance(maybe_json, (list, dict)):
        return maybe_json
    if isinstance(maybe_json, str):
        s = maybe_json.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception:
            return None
    return None

# -------------------- alert discovery (old path) --------------------
def looks_like_alert_obj(obj: dict) -> bool:
    if not isinstance(obj, dict):
        return False
    if not obj.get("id"):
        return False
    if obj.get("indicators"):
        return True
    iscope = obj.get("impact_scope") or {}
    if isinstance(iscope, dict) and isinstance(iscope.get("entities"), list):
        return True
    return False

def find_alert_in_context(ctx):
    seen = set()

    def _walk(node):
        nid = id(node)
        if nid in seen:
            return None
        seen.add(nid)

        if isinstance(node, dict):
            if "alert" in node and looks_like_alert_obj(node["alert"]):
                return node["alert"]
            if looks_like_alert_obj(node):
                return node
            for v in node.values():
                found = _walk(v)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for it in node:
                found = _walk(it)
                if found is not None:
                    return found
        return None

    return _walk(ctx)

# -------------------- indicators discovery (new rule path) --------------------
def find_indicators_payload(ctx):
    """
    Preferred for correlation-rule output:
      incident.CustomFields.trendmicrovisiononexdrindicatorsjson
      incident.CustomFields.trendmicrovisiononexdrindicators
      incident.CustomFields.indicators_json
    """
    try:
        inc = demisto.incident() or {}
        cf = inc.get("CustomFields") or {}
        for k in ("trendmicrovisiononexdrindicatorsjson", "trendmicrovisiononexdrindicators", "indicators_json"):
            if cf.get(k):
                parsed = safe_json_loads(cf.get(k))
                if isinstance(parsed, list):
                    return parsed, f"incident.CustomFields.{k}"
    except Exception:
        pass

    # fallback: scan context for any of these keys
    wanted = {"trendmicrovisiononexdrindicatorsjson", "trendmicrovisiononexdrindicators", "indicators_json"}
    seen = set()

    def _walk(node):
        nid = id(node)
        if nid in seen:
            return None
        seen.add(nid)

        if isinstance(node, dict):
            for k in wanted:
                if node.get(k):
                    parsed = safe_json_loads(node.get(k))
                    if isinstance(parsed, list):
                        return parsed, f"context.{k}"
            for v in node.values():
                found = _walk(v)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for it in node:
                found = _walk(it)
                if found is not None:
                    return found
        return None

    found = _walk(ctx)
    if found:
        return found[0], found[1]

    return None, None

# -------------------- rendering helpers --------------------
def make_table(headers, rows):
    if not rows:
        return "_none_\n"
    md = "|" + "|".join(headers) + "|\n"
    md += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for r in rows:
        md += "|" + "|".join(str(r.get(h, "")) for h in headers) + "|\n"
    return md

def normalize_indicator(ind):
    row = {
        "ID": ind.get("id"),
        "Type": ind.get("type"),
        "Field": ind.get("field") or "",
        "Value": "",
        "Related Entities": "",
        "Provenance": "",
        "Filter IDs": "",
    }

    val = ind.get("value")
    if isinstance(val, dict):
        name = val.get("name")
        ips = flat_join(val.get("ips"))
        guid = val.get("guid")
        parts = []
        if name:
            parts.append(f"name={name}")
        if ips:
            parts.append(f"ips=[{ips}]")
        if guid:
            parts.append(f"guid={guid}")
        row["Value"] = ", ".join(parts) if parts else esc(val)
    else:
        row["Value"] = esc(val)

    row["Related Entities"] = flat_join(ind.get("related_entities"))
    row["Provenance"] = flat_join(ind.get("provenance"))
    row["Filter IDs"] = flat_join(ind.get("filter_ids"))

    for k in list(row.keys()):
        row[k] = esc(row[k])
    return row

def extract_matched_process_events(alert):
    """
    Only works if full alert object exists and includes matched_rules[*].matched_filters[*].matched_events[*]
    """
    rows = []
    rules = alert.get("matched_rules") or []
    if not isinstance(rules, list):
        return rows

    for r in rules:
        rule_name = r.get("name") or r.get("id") or ""
        mfs = r.get("matched_filters") or []
        for f in mfs:
            filter_name = f.get("name") or f.get("id") or ""
            events = f.get("matched_events") or []
            for ev in events:
                ev_type = ev.get("type") or ""
                if "PROCESS" in ev_type.upper():
                    rows.append({
                        "Time": esc(ev.get("matched_date_time") or ""),
                        "Type": esc(ev_type),
                        "UUID": esc(ev.get("uuid") or ""),
                        "Filter": esc(filter_name),
                        "Rule": esc(rule_name),
                    })
    return rows

# -------------------- main --------------------
def main():
    ctx = demisto.context() or {}

    alert = find_alert_in_context(ctx)
    source = None
    wb_id = "—"

    if isinstance(alert, dict):
        wb_id = alert.get("id") or "—"
        indicators = alert.get("indicators") or []
        source = "context.alert.indicators"
    else:
        indicators, source = find_indicators_payload(ctx)
        if indicators is None:
            md_out(
                "### Trend Micro Vision One — Process & File\n"
                "❌ Couldn’t locate a Vision One alert object in context, and couldn’t find mapped indicators JSON "
                "(trendmicrovisiononexdrindicatorsjson / trendmicrovisiononexdrindicators / indicators_json)."
            )
            return

    if not isinstance(indicators, list):
        indicators = []

    # Normalize & bucket
    buckets = defaultdict(list)
    for ind in indicators:
        if not isinstance(ind, dict):
            continue
        row = normalize_indicator(ind)
        t = (row.get("Type") or "").lower()
        buckets[t].append(row)

    # Additional “file path” bucket: VisionOne often uses fields (processFilePath/objectRegistryData/etc.)
    file_path_rows = []
    for t, rows in buckets.items():
        for r in rows:
            f = (r.get("Field") or "").lower()
            if f in ("processfilepath", "objectregistrydata", "fullpath", "filename", "parentfilepath"):
                file_path_rows.append(r)

    md = []
    md.append("### Trend Micro Vision One — Process & File")
    md.append(f"**Workbench ID:** `{wb_id}`  ")
    md.append(f"**Source:** `{esc(source or '—')}`  \n")

    # ---- Process section ----
    md.append("#### Process")

    cmd_headers = ["ID", "Field", "Value", "Related Entities", "Provenance", "Filter IDs"]
    cmd_rows = [{k: r.get(k, "") for k in cmd_headers} for r in buckets.get("command_line", [])]
    md.append("**Command Lines**")
    md.append(make_table(cmd_headers, cmd_rows))

    proc_evt_headers = ["Time", "Type", "UUID", "Filter", "Rule"]
    if isinstance(alert, dict) and alert.get("matched_rules"):
        proc_evt_rows = extract_matched_process_events(alert)
        md.append("**Matched Process Events**")
        md.append(make_table(proc_evt_headers, proc_evt_rows))
    else:
        md.append("**Matched Process Events**")
        md.append("_none (matched_rules not available in correlation-rule output)_\n")

    # ---- File section ----
    md.append("#### File")

    path_headers = ["ID", "Type", "Field", "Value", "Related Entities", "Provenance", "Filter IDs"]
    path_rows = [{k: r.get(k, "") for k in path_headers} for r in file_path_rows]
    md.append("**File Paths**")
    md.append(make_table(path_headers, path_rows))

    hash_headers = ["ID", "Type", "Value", "Related Entities", "Provenance", "Filter IDs"]
    hash_rows = []
    for t in ("file_sha256", "file_sha1", "file_md5"):
        for r in buckets.get(t, []):
            hash_rows.append({
                "ID": r.get("ID", ""),
                "Type": r.get("Type", ""),
                "Value": r.get("Value", ""),
                "Related Entities": r.get("Related Entities", ""),
                "Provenance": r.get("Provenance", ""),
                "Filter IDs": r.get("Filter IDs", ""),
            })
    md.append("**File Hashes**")
    md.append(make_table(hash_headers, hash_rows))

    md_out("\n".join(md))

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
