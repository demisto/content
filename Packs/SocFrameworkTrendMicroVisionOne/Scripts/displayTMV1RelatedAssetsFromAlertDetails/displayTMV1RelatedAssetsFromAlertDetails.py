# Script name: displayTMV1RelatedAssets_FromAlertDetails
# Purpose: Render "Related Assets" from VisionOne Alert Details in context OR from rule-mapped fields.
# Notes:
#  - No external calls.
#  - Prefers alert.impact_scope.entities[] when present.
#  - Falls back to incident CustomFields (rule-mapped) when not present.
#  - Fallback is best-effort; it will not include full entity graphs/relationships.

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

# -------------------- alert discovery (old path) --------------------
def looks_like_alert_obj(obj: dict) -> bool:
    if not isinstance(obj, dict):
        return False
    if not obj.get("id"):
        return False
    iscope = obj.get("impact_scope") or {}
    if isinstance(iscope, dict) and isinstance(iscope.get("entities"), list):
        return True
    if obj.get("indicators"):
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

def make_table(headers, rows):
    if not rows:
        return "_none_\n"
    md = "|" + "|".join(headers) + "|\n"
    md += "|" + "|".join(["---"] * len(headers)) + "|\n"
    for r in rows:
        md += "|" + "|".join(str(r.get(h, "")) for h in headers) + "|\n"
    return md

# -------------------- normalization (old path entities[]) --------------------
def norm_host_entity(e):
    ev = e.get("entity_value") or {}
    name = ev.get("name") or ""
    ips = flat_join(ev.get("ips"))
    guid = ev.get("guid") or ""
    prov = flat_join(e.get("provenance"))
    rel = flat_join(e.get("related_entities"))
    return {
        "GUID": esc(guid),
        "Name": esc(name),
        "IPs": esc(ips),
        "Provenance": esc(prov),
        "Related Entities": esc(rel),
    }

def norm_account_entity(e):
    val = e.get("entity_value")
    prov = flat_join(e.get("provenance"))
    rel = flat_join(e.get("related_entities"))
    return {
        "Account": esc(val),
        "Provenance": esc(prov),
        "Related Entities": esc(rel),
    }

def norm_generic_entity(e):
    ev = e.get("entity_value")
    if isinstance(ev, dict):
        pretty = []
        for k in ("name", "address", "id", "guid", "resource", "namespace"):
            if ev.get(k):
                v = ev.get(k)
                if isinstance(v, list):
                    v = "[" + flat_join(v) + "]"
                pretty.append(f"{k}={v}")
        val_str = ", ".join(pretty) if pretty else esc(ev)
    else:
        val_str = esc(ev)
    prov = flat_join(e.get("provenance"))
    rel = flat_join(e.get("related_entities"))
    return {
        "Entity ID": esc(e.get("entity_id") or ""),
        "Value": val_str,
        "Provenance": esc(prov),
        "Related Entities": esc(rel),
    }

def build_relationship_map(entities):
    host_index = {}
    for e in entities:
        if e.get("entity_type") == "host":
            ev = e.get("entity_value") or {}
            disp = ev.get("name") or ev.get("guid") or e.get("entity_id") or "host"
            host_index[e.get("entity_id")] = disp
            if ev.get("guid"):
                host_index[ev.get("guid")] = disp

    lines = []
    for e in entities:
        etype = e.get("entity_type")
        if not e.get("related_entities"):
            continue
        if etype == "account":
            src_label = f"account {e.get('entity_value')}"
        elif etype == "host":
            ev = e.get("entity_value") or {}
            src_label = f"host {ev.get('name') or ev.get('guid') or e.get('entity_id')}"
        else:
            src_label = f"{etype} {e.get('entity_id') or ''}".strip()

        for target in e.get("related_entities") or []:
            tgt = host_index.get(target, target)
            if tgt:
                lines.append(f"- {esc(src_label)} → **{esc(str(tgt))}**")
    return lines

# -------------------- fallback (rule-mapped CustomFields) --------------------
def get_incident_cf():
    inc = demisto.incident() or {}
    return inc.get("CustomFields") or {}

def first_nonempty(*vals):
    for v in vals:
        if v not in (None, "", [], {}):
            return v
    return ""

def build_fallback_assets_from_cf(cf):
    """
    Best-effort assets based on your rule mappings.
    Returns:
      hosts_rows, accounts_rows, misc_rows (list of dicts)
    """
    hosts = []
    accounts = []
    misc = []

    # Host (agent_id / agent_hostname / action_local_ip / mac)
    host_guid = first_nonempty(cf.get("agent_id"), cf.get("agentid"))
    host_name = first_nonempty(cf.get("agent_hostname"), cf.get("agenthostname"))
    local_ip  = first_nonempty(cf.get("action_local_ip"), cf.get("prenatsourceip"))
    mac       = first_nonempty(cf.get("mac"), cf.get("mac_address"))

    if host_guid or host_name or local_ip or mac:
        hosts.append({
            "GUID": esc(host_guid),
            "Name": esc(host_name),
            "IPs": esc(local_ip),  # single value in rule-mapped mode
            "Provenance": esc("Correlation Rule"),
            "Related Entities": esc(""),
        })
        if mac:
            misc.append({
                "Key": "MAC",
                "Value": esc(mac),
            })

    # Account (actor_effective_username / userid)
    uname = first_nonempty(cf.get("actor_effective_username"), cf.get("username"), cf.get("user_name"))
    uid   = first_nonempty(cf.get("userid"), cf.get("user_id"))

    if uname or uid:
        acct_val = uname if uname else "—"
        if uid:
            acct_val = f"{acct_val} (id={uid})"
        accounts.append({
            "Account": esc(acct_val),
            "Provenance": esc("Correlation Rule"),
            "Related Entities": esc(""),
        })

    # Domain (agent_device_domain)
    dom = first_nonempty(cf.get("agent_device_domain"), cf.get("domain"))
    if dom:
        misc.append({"Key": "Domain", "Value": esc(dom)})

    # Remote IP (action_remote_ip)
    rip = first_nonempty(cf.get("action_remote_ip"), cf.get("remote_ip_str"))
    if rip:
        misc.append({"Key": "Remote IP", "Value": esc(rip)})

    return hosts, accounts, misc

# -------------------- main --------------------
def main():
    ctx = demisto.context() or {}
    alert = find_alert_in_context(ctx)

    if isinstance(alert, dict):
        # ---- Old rich mode ----
        wb_id = alert.get("id") or "—"
        entities = (alert.get("impact_scope", {}) or {}).get("entities", []) or []

        if not entities:
            md_out(
                "### Trend Micro Vision One — Related Assets\n"
                f"**Mode:** `context-alert`\n"
                f"**Workbench ID:** `{esc(wb_id)}`  \n"
                "_No related assets present in impact scope._"
            )
            return

        by_type = defaultdict(list)
        for e in entities:
            et = (e.get("entity_type") or "").lower()
            by_type[et].append(e)

        counts = ", ".join(f"{t}: {len(v)}" for t, v in by_type.items())
        md = []
        md.append("### Trend Micro Vision One — Related Assets")
        md.append("**Mode:** `context-alert`  ")
        md.append(f"**Workbench ID:** `{esc(wb_id)}`  ")
        md.append(f"**By Type:** {esc(counts)}\n")

        host_rows = [norm_host_entity(e) for e in by_type.get("host", [])]
        md.append("#### Hosts")
        md.append(make_table(["GUID", "Name", "IPs", "Provenance", "Related Entities"], host_rows))

        acct_rows = [norm_account_entity(e) for e in by_type.get("account", [])]
        md.append("#### Accounts")
        md.append(make_table(["Account", "Provenance", "Related Entities"], acct_rows))

        for t, items in sorted(by_type.items()):
            if t in ("host", "account"):
                continue
            rows = [norm_generic_entity(e) for e in items]
            md.append(f"#### {t.replace('_',' ').title()}")
            md.append(make_table(["Entity ID", "Value", "Provenance", "Related Entities"], rows))

        rel_lines = build_relationship_map(entities)
        if rel_lines:
            md.append("#### Relationships")
            md.extend(rel_lines)

        md_out("\n".join(md))
        return

    # ---- Fallback rule-mapped mode ----
    cf = get_incident_cf()
    wb_id = first_nonempty(cf.get("originalalertid"), "—")

    hosts, accounts, misc = build_fallback_assets_from_cf(cf)

    md = []
    md.append("### Trend Micro Vision One — Related Assets")
    md.append("**Mode:** `rule-mapped`  ")
    md.append(f"**Workbench ID:** `{esc(wb_id)}`  ")
    md.append("_Note: impact_scope/entities not available; this is best-effort from correlation rule fields._\n")

    md.append("#### Hosts")
    md.append(make_table(["GUID", "Name", "IPs", "Provenance", "Related Entities"], hosts))

    md.append("#### Accounts")
    md.append(make_table(["Account", "Provenance", "Related Entities"], accounts))

    if misc:
        md.append("#### Other")
        md.append(make_table(["Key", "Value"], misc))
    else:
        md.append("#### Other")
        md.append("_none_\n")

    md_out("\n".join(md))

if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
