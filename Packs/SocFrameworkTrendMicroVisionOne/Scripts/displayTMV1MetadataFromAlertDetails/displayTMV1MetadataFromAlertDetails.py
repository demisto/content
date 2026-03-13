# Script name: displayTMV1Metadata_FromAlertDetails
# Purpose: Render Vision One "Metadata" from Alert Details already in context OR from rule-mapped fields.
# Notes:
#  - No external calls.
#  - Prefers full VisionOne alert object in context (matched_rules / impact_scope available).
#  - Falls back to correlation-rule mapped incident custom fields when alert object isn't present.
#  - Degrades gracefully when impact_scope / matched_rules aren't available.

import json
import demistomock as demisto
from CommonServerPython import *

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
    if obj.get("impact_scope") or obj.get("indicators"):
        return True
    return False

def find_alert_and_meta_in_context(ctx):
    seen = set()

    def _walk(node):
        nid = id(node)
        if nid in seen:
            return (None, None)
        seen.add(nid)

        if isinstance(node, dict):
            if "alert" in node and looks_like_alert_obj(node["alert"]):
                meta = {}
                if "etag" in node and isinstance(node["etag"], (str, int)):
                    meta["etag"] = node["etag"]
                return (node["alert"], meta)

            if looks_like_alert_obj(node):
                return (node, {})

            for v in node.values():
                a, m = _walk(v)
                if a is not None:
                    if not m and "etag" in node:
                        m = {"etag": node.get("etag")}
                    return (a, m)

        elif isinstance(node, list):
            for it in node:
                a, m = _walk(it)
                if a is not None:
                    return (a, m)

        return (None, None)

    return _walk(ctx)

# -------------------- markdown table helpers --------------------
def make_kv_table(pairs):
    rows = [(k, v) for (k, v) in pairs if v not in (None, "", [], {})]
    if not rows:
        return "_none_\n"
    md = "|Key|Value|\n|---|---|\n"
    for k, v in rows:
        md += f"|{esc(k)}|{esc(v)}|\n"
    return md

def make_table(headers, rows):
    if not rows:
        return "_none_\n"
    md = "|" + "|".join(headers) + "|\n"
    md += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for r in rows:
        md += "|" + "|".join(esc(str(r.get(h, ""))) for h in headers) + "|\n"
    return md

# -------------------- summary helpers (old path only) --------------------
def summarize_impact_scope(iscope):
    if not isinstance(iscope, dict):
        return None, None
    counts = []
    for key in ("desktop_count", "server_count", "account_count", "email_address_count",
                "container_count", "cloud_identity_count"):
        if key in iscope:
            counts.append((key.replace("_", " ").title(), iscope.get(key)))
    entities = iscope.get("entities") or []
    return counts, entities

def summarize_matched_rules(alert):
    out = []
    rules = alert.get("matched_rules") or []
    if not isinstance(rules, list):
        return out
    for r in rules:
        rule_name = r.get("name") or r.get("id") or ""
        mfs = r.get("matched_filters") or []
        if not isinstance(mfs, list):
            continue
        for f in mfs:
            filt_name = f.get("name") or f.get("id") or ""
            when = ""
            evs = f.get("matched_events") or []
            if isinstance(evs, list) and evs:
                when = evs[0].get("matched_date_time") or ""
            techniques = flat_join(f.get("mitre_technique_ids"))
            out.append({
                "Rule": rule_name,
                "Filter": filt_name,
                "When": when,
                "MITRE": techniques,
            })
    return out

# -------------------- new rule fallback (incident fields) --------------------
def get_incident_cf():
    inc = demisto.incident() or {}
    return inc.get("CustomFields") or {}

def get_first_nonempty(*vals):
    for v in vals:
        if v not in (None, "", [], {}):
            return v
    return ""

def count_indicators_from_cf(cf):
    for k in ("trendmicrovisiononexdrindicatorsjson", "trendmicrovisiononexdrindicators", "indicators_json"):
        if cf.get(k):
            parsed = safe_json_loads(cf.get(k))
            if isinstance(parsed, list):
                return len(parsed)
    return 0

# -------------------- main --------------------
def main():
    ctx = demisto.context() or {}
    alert, meta = find_alert_and_meta_in_context(ctx)

    cf = get_incident_cf()

    # If full alert exists, use it (old rich mode). Otherwise use rule-mapped fields (fallback mode).
    mode = "context-alert" if isinstance(alert, dict) else "rule-mapped"

    if isinstance(alert, dict):
        wb_id = alert.get("id") or "—"
        workbench_link = alert.get("workbench_link") or ""
        provider = alert.get("alert_provider") or alert.get("provider") or ""
        model = alert.get("model") or ""
        model_type = alert.get("model_type") or ""
        model_id = alert.get("model_id") or ""
        severity = alert.get("severity") or ""
        score = alert.get("score")
        schema_version = alert.get("schema_version") or ""
        incident_id = alert.get("incident_id") or ""
        case_id = alert.get("case_id") or ""
        owner_ids = alert.get("owner_ids")
        owner_txt = flat_join(owner_ids) if isinstance(owner_ids, list) else (owner_ids or "")

        status = alert.get("status") or ""
        inv_status = alert.get("investigation_status") or ""
        inv_result = alert.get("investigation_result") or ""

        t_created = alert.get("created_date_time") or ""
        t_updated = alert.get("updated_date_time") or ""
        t_first_investigated = alert.get("first_investigated_date_time") or ""

        counts, _entities = summarize_impact_scope(alert.get("impact_scope") or {})
        mr_rows = summarize_matched_rules(alert)

        indicators = alert.get("indicators") or []
        ind_count = len(indicators) if isinstance(indicators, list) else 0

        etag = meta.get("etag") if isinstance(meta, dict) else None

    else:
        # ---- Fallback to rule-mapped fields ----
        # These are based on your correlation-rule mappings:
        # - originalalertid, externallink/external_pivot_url, externalstatus
        # - trendmicrovisiononexdrpriorityscore, trendmicrovisiononexdrinvestigationstatus
        # - source_insert_ts, severity
        wb_id = get_first_nonempty(cf.get("originalalertid"), "—")
        workbench_link = get_first_nonempty(cf.get("externallink"), cf.get("external_pivot_url"), "")
        provider = get_first_nonempty(cf.get("originalalertsource"), "Trend Micro Vision One")
        model = get_first_nonempty(cf.get("originalalertname"), "")
        model_type = ""
        model_id = ""
        severity = get_first_nonempty(cf.get("severity"), "")
        score = get_first_nonempty(cf.get("trendmicrovisiononexdrpriorityscore"), "")
        schema_version = ""
        incident_id = ""
        case_id = ""
        owner_txt = ""

        status = get_first_nonempty(cf.get("externalstatus"), "")
        inv_status = get_first_nonempty(cf.get("trendmicrovisiononexdrinvestigationstatus"), "")
        inv_result = ""  # not mapped in your rule output unless you add it

        t_created = get_first_nonempty(cf.get("source_insert_ts"), "")
        t_updated = ""
        t_first_investigated = ""

        counts = None
        mr_rows = []  # not available without matched_rules
        ind_count = count_indicators_from_cf(cf)
        etag = None

    # ----- Compose Markdown -----
    md = []
    md.append("### Trend Micro Vision One — Metadata")
    md.append(f"**Mode:** `{esc(mode)}`  ")
    md.append(f"**Workbench ID:** `{esc(wb_id)}`  ")
    if workbench_link:
        md.append(f"**Workbench Link:** {esc(workbench_link)}  ")
    md.append("")

    core_pairs = [
        ("Provider", provider),
        ("Model", model),
        ("Model Type", model_type),
        ("Model ID", model_id),
        ("Severity", severity),
        ("Score", score),
        ("Schema Version", schema_version),
        ("Incident ID", incident_id),
        ("Case ID", case_id),
        ("Owner IDs", owner_txt),
        ("Indicators (count)", ind_count),
        ("ETag", etag),
    ]
    md.append("#### Core")
    md.append(make_kv_table(core_pairs))

    status_pairs = [
        ("Status", status),
        ("Investigation Status", inv_status),
        ("Investigation Result", inv_result),
    ]
    md.append("#### Status")
    md.append(make_kv_table(status_pairs))

    time_pairs = [
        ("Created", t_created),
        ("Updated", t_updated),
        ("First Investigated", t_first_investigated),
    ]
    md.append("#### Timestamps")
    md.append(make_kv_table(time_pairs))

    md.append("#### Impact Scope")
    if counts:
        md.append(make_kv_table(counts))
    else:
        md.append("_none (impact_scope not available in rule-mapped mode)_\n")

    md.append("#### Matched Rules")
    if mr_rows:
        md.append(make_table(["Rule", "Filter", "When", "MITRE"], mr_rows))
    else:
        md.append("_none (matched_rules not available in rule-mapped mode)_\n")

    md_out("\n".join(md))

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
