# Script name: displayTMV1Indicators_FromAlertDetails
# Purpose: Read indicators from VisionOne Alert Details already in *any* context path OR from mapped fields
#          (trendmicrovisiononexdrindicatorsjson / trendmicrovisiononexdrindicators) and render them nicely.

import demistomock as demisto
from CommonServerPython import *
import json
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
    """
    Best-effort parse:
      - list/dict => returned as-is
      - string => json.loads (handles array/object JSON)
      - anything else => None
    """
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

# -------------------- detect & extract sources --------------------
def looks_like_alert_obj(obj: dict) -> bool:
    """Heuristics to identify a Vision One alert object."""
    if not isinstance(obj, dict):
        return False
    if not obj.get("id"):
        return False
    # Must have either indicators or an impact_scope with entities
    if obj.get("indicators"):
        return True
    iscope = obj.get("impact_scope") or {}
    if isinstance(iscope, dict) and isinstance(iscope.get("entities"), list):
        return True
    return False

def find_alert_in_context(ctx):
    """
    Recursively walk the entire context dict/list to find the first Vision One alert object.
    Handles keys like 'VisionOne.Alert_Details(val.etag && val.etag == obj.etag)' and more.
    """
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

def find_indicators_payload(ctx):
    """
    NEW RULES PATH:
    Indicators are usually mapped into incident custom fields:
      - trendmicrovisiononexdrindicatorsjson
      - trendmicrovisiononexdrindicators
    Sometimes they may appear in context as:
      - indicators_json
      - IndicatorsJSON, etc.

    Return: (indicators_list, source_label)
    """
    # 1) Incident custom fields (most reliable for correlation rule output)
    try:
        inc = demisto.incident() or {}
        cf = inc.get("CustomFields") or {}

        for k in (
                "trendmicrovisiononexdrindicatorsjson",
                "trendmicrovisiononexdrindicators",
                "indicators_json",
        ):
            if k in cf and cf.get(k):
                parsed = safe_json_loads(cf.get(k))
                if isinstance(parsed, list):
                    return parsed, f"incident.CustomFields.{k}"

        # Some environments don’t nest under CustomFields (rare), so check top-level too
        for k in (
                "trendmicrovisiononexdrindicatorsjson",
                "trendmicrovisiononexdrindicators",
                "indicators_json",
        ):
            if k in inc and inc.get(k):
                parsed = safe_json_loads(inc.get(k))
                if isinstance(parsed, list):
                    return parsed, f"incident.{k}"
    except Exception:
        pass

    # 2) Context sweep for a direct indicators_json / mapped field value
    def _walk_for_key(node, wanted_keys):
        seen = set()

        def _walk(n):
            nid = id(n)
            if nid in seen:
                return None
            seen.add(nid)

            if isinstance(n, dict):
                for wk in wanted_keys:
                    if wk in n and n.get(wk):
                        parsed = safe_json_loads(n.get(wk))
                        if isinstance(parsed, list):
                            return parsed, f"context.{wk}"
                for v in n.values():
                    found = _walk(v)
                    if found is not None:
                        return found
            elif isinstance(n, list):
                for it in n:
                    found = _walk(it)
                    if found is not None:
                        return found
            return None

        return _walk(node)

    found = _walk_for_key(ctx, {"trendmicrovisiononexdrindicatorsjson", "trendmicrovisiononexdrindicators", "indicators_json"})
    if found:
        return found[0], found[1]

    return None, None

# -------------------- formatting --------------------
def normalize_indicator(ind):
    """
    Return a flat dict for table rendering.
    Expected fields:
      id, type, value, related_entities, provenance, field, filter_ids
    """
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

def make_table(headers, rows):
    if not rows:
        return "_none_\n"
    md = "|" + "|".join(headers) + "|\n"
    md += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for r in rows:
        md += "|" + "|".join(str(r.get(h, "")) for h in headers) + "|\n"
    return md

# -------------------- main --------------------
def main():
    ctx = demisto.context() or {}

    # Prefer new-rule source: the mapped indicators JSON string -> list
    indicators, source = find_indicators_payload(ctx)

    wb_id = "—"
    if indicators is None:
        # Fallback: old behavior (find alert object somewhere in context)
        alert = find_alert_in_context(ctx)
        if not isinstance(alert, dict):
            md_out(
                "### Trend Micro Vision One — Indicators\n"
                "❌ Couldn’t locate indicators (mapped fields) or a Vision One alert object anywhere in context."
            )
            return

        wb_id = alert.get("id") or "—"
        indicators = alert.get("indicators") or []
        source = "context.alert.indicators"
    else:
        # Try to populate workbench id from incident/custom fields if available
        try:
            inc = demisto.incident() or {}
            cf = inc.get("CustomFields") or {}
            # Your rule maps originalalertid -> id, but that’s not necessarily stored as a custom field.
            # If you *do* have it in CF, grab it; otherwise leave wb_id as "—".
            wb_id = cf.get("originalalertid") or cf.get("id") or wb_id
        except Exception:
            pass

    if not isinstance(indicators, list) or not indicators:
        md_out(
            "### Trend Micro Vision One — Indicators\n"
            f"**Workbench ID:** `{wb_id}`  \n"
            f"**Source:** `{esc(source or '—')}`  \n"
            "_No indicators were returned on this alert._"
        )
        return

    # Bucket by indicator type for cleaner sections
    buckets = defaultdict(list)
    for ind in indicators:
        if not isinstance(ind, dict):
            continue
        row = normalize_indicator(ind)
        buckets[(row.get("Type") or "").lower()].append(row)

    total = len([x for x in indicators if isinstance(x, dict)])
    types_summary = ", ".join(f"{t or 'unknown'}: {len(rows)}" for t, rows in buckets.items())

    md = []
    md.append("### Trend Micro Vision One — Indicators")
    md.append(f"**Workbench ID:** `{wb_id}`  ")
    md.append(f"**Source:** `{esc(source or '—')}`  ")
    md.append(f"**Total Indicators:** {total}  ")
    md.append(f"**By Type:** {esc(types_summary)}\n")

    headers = ["ID", "Type", "Field", "Value", "Related Entities", "Provenance", "Filter IDs"]
    preferred = ["command_line", "file_sha256", "file_md5", "domain", "fullpath", "host", "ip"]
    emitted = set()

    for t in preferred:
        rows = buckets.get(t, [])
        if rows:
            md.append(f"#### {t.replace('_',' ').title()}")
            md.append(make_table(headers, rows))
            emitted.add(t)

    for t, rows in buckets.items():
        if t in emitted:
            continue
        title = (t or "unknown").replace("_", " ").title()
        md.append(f"#### {title}")
        md.append(make_table(headers, rows))

    md_out("\n".join(md))

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
