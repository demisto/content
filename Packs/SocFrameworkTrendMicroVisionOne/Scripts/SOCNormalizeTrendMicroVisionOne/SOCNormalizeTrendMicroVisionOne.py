import demistomock as demisto
from CommonServerPython import *

def get_incident_cf():
    inc = demisto.incident() or {}
    return inc.get("CustomFields") or {}

def first_nonempty_str(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str):
            s = v.strip()
            if s:
                return s
        else:
            # allow non-strings if they are meaningful
            if v not in ("", [], {}, ()):
                return v
    return None

def find_alert_anywhere(ctx):
    """
    Best-effort: use VisionOne.Alert_Details.alert if present, otherwise walk context for an alert-like object.
    """
    # your current explicit path
    v = (ctx.get('VisionOne') or {})
    ad = (v.get('Alert_Details') or {})
    alert = (ad.get('alert') or {})
    if isinstance(alert, dict) and alert.get("id"):
        return alert

    # optional: if you want the robust walker like your other scripts, drop it in here.
    return None

def build_alert_from_rule_fields(cf):
    """
    Build a minimal 'alert-like' object from correlation-rule mapped fields.
    Enough to populate Normalized[] with host/user/ip/hashes/process.
    """
    # These keys align to what you've been mapping in the YAML
    host_guid = first_nonempty_str(cf.get("agent_id"))
    host_name = first_nonempty_str(cf.get("agent_hostname"))
    local_ip  = first_nonempty_str(cf.get("action_local_ip"), cf.get("prenatsourceip"))
    user_name = first_nonempty_str(cf.get("actor_effective_username"))
    user_id   = first_nonempty_str(cf.get("userid"))
    sha256    = first_nonempty_str(cf.get("action_file_sha256"), cf.get("filehash"))
    md5       = first_nonempty_str(cf.get("action_file_md5"), cf.get("processmd5"))
    cmdline   = first_nonempty_str(cf.get("actor_process_command_line"), cf.get("processcmd"))
    image_path = first_nonempty_str(cf.get("actor_process_image_path"), cf.get("action_file_path"))
    image_name = first_nonempty_str(cf.get("actor_process_image_name"))

    # remote ip + domain are useful for ips list / context
    remote_ip = first_nonempty_str(cf.get("action_remote_ip"))
    domain    = first_nonempty_str(cf.get("agent_device_domain"))

    # Create an "alert-like" dict in the same shape your normalizer expects
    alert = {
        "id": first_nonempty_str(cf.get("originalalertid"), "—"),
        "workbench_link": first_nonempty_str(cf.get("externallink"), cf.get("external_pivot_url")),
        "description": first_nonempty_str(cf.get("alert_description")),
        "impact_scope": {
            "entities": []
        },
        "indicators": []
    }

    # Entities (host/account) – match VisionOne shapes your code already supports
    if host_guid or host_name or local_ip:
        host_ev = {"guid": host_guid, "name": host_name, "ips": [x for x in [local_ip] if x]}
        alert["impact_scope"]["entities"].append({
            "entity_type": "host",
            "entity_value": host_ev
        })

    if user_name:
        alert["impact_scope"]["entities"].append({
            "entity_type": "account",
            "entity_value": user_name
        })

    # Indicators – keep types consistent with your existing indicator parsing
    if sha256:
        alert["indicators"].append({"type": "file_sha256", "value": sha256})
    if md5:
        alert["indicators"].append({"type": "file_md5", "value": md5})
    if cmdline:
        alert["indicators"].append({"type": "command_line", "value": cmdline})
    if image_path:
        alert["indicators"].append({"type": "fullpath", "value": image_path})
    if remote_ip:
        alert["indicators"].append({"type": "ip", "value": remote_ip})
    if domain:
        alert["indicators"].append({"type": "domain", "value": domain})

    # If you have image_name but no path, still let it show up in process
    if image_name and not image_path:
        alert["indicators"].append({"type": "filename", "value": image_name})

    return alert
