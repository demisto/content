import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Hardened host status renderer for "[BETA] CrowdStrike Endpoint Alert Layout]".
# Reads agent id from alert CustomFields and queries cs-falcon-search-device.
# If extraction fails, surfaces a concise debug summary (toggle DEBUG_MODE).

import json
import html

DEBUG_MODE = False  # set True to see shapes/keys when extraction fails

STATUS_MAP = {
    "normal": "🟢 Online",
    "containment_pending": "🟡 Pending Containment",
    "lift_containment_pending": "🟡 Lifting Containment",
    "contained": "🔴 Contained",
}

def _fmt_status(s):
    return STATUS_MAP.get((s or "").lower(), "🟤 Unknown or Offline")

def _safe_get(d, key, default="unknown"):
    try:
        v = d.get(key)
        if v is None or v == "":
            return default
        return str(v)
    except Exception:
        return default

def _maybe_json(s):
    if isinstance(s, str):
        t = s.strip()
        if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
            try:
                return json.loads(t)
            except Exception:
                return s
    return s

def _first_nonempty_list(*candidates):
    for c in candidates:
        if isinstance(c, list) and c:
            return c
    return []

def _summarize(obj, depth=0):
    """Small, safe shape summarizer for DEBUG_MODE."""
    if depth > 2:
        return type(obj).__name__
    if isinstance(obj, dict):
        keys = list(obj.keys())
        return {"__type__": "dict", "keys": keys[:20]}
    if isinstance(obj, list):
        return {"__type__": f"list[{len(obj)}]", "first": _summarize(obj[0], depth+1) if obj else "empty"}
    return type(obj).__name__

def _extract_resources(res):
    """
    Return a list of CrowdStrike 'resources' dicts from many possible result shapes.
    """
    if not res:
        return [], "empty result"

    # Common: list of entry dicts
    if isinstance(res, list):
        # Try each item until we find resources
        for item in res:
            if isinstance(item, dict):
                contents = item.get('Contents') or item.get('contents') or item.get('Context') or item.get('EntryContext') or item.get('Body') or item.get('body') or item.get('result')
                # 1) Contents is dict with resources
                if isinstance(contents, dict) and isinstance(contents.get('resources'), list):
                    return contents.get('resources') or [], "resources from Contents"
                # 2) Item itself has resources
                if isinstance(item.get('resources'), list):
                    return item.get('resources') or [], "resources from item"
                # 3) Contents is stringified JSON
                if isinstance(contents, str):
                    parsed = _maybe_json(contents)
                    if isinstance(parsed, dict) and isinstance(parsed.get('resources'), list):
                        return parsed.get('resources') or [], "resources from JSON string in Contents"
                # 4) Some integrations nest under 'body'/'result'
                for k in ('body', 'result'):
                    maybe = item.get(k)
                    if isinstance(maybe, dict) and isinstance(maybe.get('resources'), list):
                        return maybe.get('resources') or [], f"resources from {k}"
        # Fallback: first item might be a raw JSON string
        first = res[0]
        if isinstance(first, str):
            parsed = _maybe_json(first)
            if isinstance(parsed, dict) and isinstance(parsed.get('resources'), list):
                return parsed.get('resources') or [], "resources from first string element"
        return [], f"no resources in list; first={_summarize(res[0]) if res else 'none'}"

    # Dict
    if isinstance(res, dict):
        # Direct dict with resources
        if isinstance(res.get('resources'), list):
            return res.get('resources') or [], "resources from top-level dict"
        # Look under known containers
        for key in ('Contents', 'contents', 'Context', 'EntryContext', 'Body', 'body', 'result'):
            cont = res.get(key)
            if isinstance(cont, dict) and isinstance(cont.get('resources'), list):
                return cont.get('resources') or [], f"resources from {key}"
            if isinstance(cont, str):
                parsed = _maybe_json(cont)
                if isinstance(parsed, dict) and isinstance(parsed.get('resources'), list):
                    return parsed.get('resources') or [], f"resources from JSON string in {key}"
        return [], f"no resources in dict; keys={list(res.keys())[:20]}"

    # String (maybe JSON)
    if isinstance(res, str):
        parsed = _maybe_json(res)
        if isinstance(parsed, dict) and isinstance(parsed.get('resources'), list):
            return parsed.get('resources') or [], "resources from raw JSON string"
        return [], "string result without resources"

    # Anything else
    return [], f"unsupported type: {type(res).__name__}"

def _extract_error_message(res):
    """
    Try to surface a meaningful error returned by the integration without raising.
    """
    try:
        # List of entries
        if isinstance(res, list):
            for item in res:
                if isinstance(item, dict):
                    # Standard XSOAR error entry
                    if item.get('Type') == EntryType.ERROR:
                        return str(item.get('Contents') or item.get('HumanReadable') or "Unknown error")
                    # Some integrations return errors in Contents/body
                    for key in ('Contents', 'contents', 'Body', 'body', 'result'):
                        v = item.get(key)
                        v = _maybe_json(v)
                        if isinstance(v, dict):
                            if v.get('errors'):
                                return json.dumps(v.get('errors'))
                            if v.get('error'):
                                return str(v.get('error'))
            return None
        # Dict
        if isinstance(res, dict):
            if res.get('Type') == EntryType.ERROR:
                return str(res.get('Contents') or res.get('HumanReadable') or "Unknown error")
            for key in ('Contents', 'contents', 'Body', 'body', 'result'):
                v = res.get(key)
                v = _maybe_json(v)
                if isinstance(v, dict):
                    if v.get('errors'):
                        return json.dumps(v.get('errors'))
                    if v.get('error'):
                        return str(v.get('error'))
        # String
        if isinstance(res, str):
            v = _maybe_json(res)
            if isinstance(v, dict):
                if v.get('errors'):
                    return json.dumps(v.get('errors'))
                if v.get('error'):
                    return str(v.get('error'))
        return None
    except Exception:
        return None

def main():
    try:
        ctx = demisto.alert() or {}
        c = ctx.get('CustomFields') or {}
        agent_id = c.get('agentid') or c.get('agent_id') or c.get('agentId')

        if not agent_id:
            return_results("🟤 Missing agent id on the alert (CustomFields.agentid).")
            return

        res = execute_command('cs-falcon-search-device', {'ids': agent_id})

        # If integration returned an explicit error, show it (without KeyErrors)
        err_msg = _extract_error_message(res)
        if err_msg:
            return_results(f"🔴 Error from cs-falcon-search-device: {err_msg}")
            return

        resources, how = _extract_resources(res)
        if not resources:
            debug_note = ""
            if DEBUG_MODE:
                shape = _summarize(res)
                debug_note = f"\n\n[DEBUG] result shape: {json.dumps(shape)}"
            return_results("🟤 No host resource found for the provided agent id." + debug_note)
            return

        host = resources[0] if isinstance(resources[0], dict) else {}

        host_name = _safe_get(host, 'hostname', 'unknown')
        host_status = _fmt_status(_safe_get(host, 'status', 'unknown'))
        host_local_ip = _safe_get(host, 'local_ip', 'not-available')
        host_external_ip = _safe_get(host, 'external_ip', 'not-available')

        host_os = _safe_get(host, 'os_product_name', None)
        if host_os in (None, "unknown"):
            host_os = _safe_get(host, 'os_version', 'unknown')

        last_user = _safe_get(host, 'last_login_user', None)
        if last_user in (None, "not-available", "unknown"):
            last_user = _safe_get(host, 'last_logged_on_user', 'not-available')

        snippet = (
            f"Hostname: {host_name}\n"
            f"Status: {host_status}\n"
            f"Current Local IP: {host_local_ip}\n"
            f"Current External IP: {host_external_ip}\n"
            f"OS: {host_os}\n"
            f"Last Logged In User: {last_user}"
        )
        return_results(snippet)

    except Exception as e:
        msg = (
            "🔴 There has been an issue gathering host status. "
            "Please ensure the CrowdStrike Falcon automation integration is enabled."
            f"\n\nException thrown: {str(e)}"
        )
        return_results(msg)

if __name__ in ("builtins", "__builtin__", "__main__"):
    main()

