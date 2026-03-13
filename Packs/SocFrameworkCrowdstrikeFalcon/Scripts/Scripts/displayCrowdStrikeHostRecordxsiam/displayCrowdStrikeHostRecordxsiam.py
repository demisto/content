import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Renders the current CrowdStrike host record as an HTML table for the layout.
# Hardened to avoid 'Type' KeyErrors and odd result shapes.

import json
import html

DEBUG_MODE = False  # set True to return a shape summary if extraction fails

STATUS_MAP = {
    "normal": "🟢 Online",
    "containment_pending": "🟡 Pending Containment",
    "lift_containment_pending": "🟡 Lifting Containment",
    "contained": "🔴 Contained",
}

def _fmt_status(s):
    return STATUS_MAP.get((s or "").lower(), "🟤 Unknown or Offline")

def _maybe_json(s):
    if isinstance(s, str):
        t = s.strip()
        if (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]")):
            try:
                return json.loads(t)
            except Exception:
                return s
    return s

def _summarize(obj, depth=0):
    if depth > 2:
        return type(obj).__name__
    if isinstance(obj, dict):
        return {"__type__": "dict", "keys": list(obj.keys())[:20]}
    if isinstance(obj, list):
        return {"__type__": f"list[{len(obj)}]", "first": _summarize(obj[0], depth+1) if obj else "empty"}
    return type(obj).__name__

def _extract_error_message(res):
    try:
        if isinstance(res, list):
            for item in res:
                if isinstance(item, dict):
                    if item.get('Type') == EntryType.ERROR:
                        return str(item.get('Contents') or item.get('HumanReadable') or "Unknown error")
                    for key in ('Contents', 'contents', 'Body', 'body', 'result'):
                        v = _maybe_json(item.get(key))
                        if isinstance(v, dict):
                            if v.get('errors'): return json.dumps(v.get('errors'))
                            if v.get('error'):  return str(v.get('error'))
            return None
        if isinstance(res, dict):
            if res.get('Type') == EntryType.ERROR:
                return str(res.get('Contents') or res.get('HumanReadable') or "Unknown error")
            for key in ('Contents', 'contents', 'Body', 'body', 'result'):
                v = _maybe_json(res.get(key))
                if isinstance(v, dict):
                    if v.get('errors'): return json.dumps(v.get('errors'))
                    if v.get('error'):  return str(v.get('error'))
        if isinstance(res, str):
            v = _maybe_json(res)
            if isinstance(v, dict):
                if v.get('errors'): return json.dumps(v.get('errors'))
                if v.get('error'):  return str(v.get('error'))
        return None
    except Exception:
        return None

def _extract_resources(res):
    if not res:
        return [], "empty result"

    if isinstance(res, list):
        for item in res:
            if isinstance(item, dict):
                contents = item.get('Contents') or item.get('contents') or item.get('Context') or item.get('EntryContext') or item.get('Body') or item.get('body') or item.get('result')
                if isinstance(contents, dict) and isinstance(contents.get('resources'), list):
                    return contents.get('resources') or [], "resources from Contents"
                if isinstance(item.get('resources'), list):
                    return item.get('resources') or [], "resources from item"
                if isinstance(contents, str):
                    parsed = _maybe_json(contents)
                    if isinstance(parsed, dict) and isinstance(parsed.get('resources'), list):
                        return parsed.get('resources') or [], "resources from JSON string in Contents"
                for k in ('body', 'result'):
                    maybe = item.get(k)
                    if isinstance(maybe, dict) and isinstance(maybe.get('resources'), list):
                        return maybe.get('resources') or [], f"resources from {k}"
        first = res[0]
        if isinstance(first, str):
            parsed = _maybe_json(first)
            if isinstance(parsed, dict) and isinstance(parsed.get('resources'), list):
                return parsed.get('resources') or [], "resources from first string element"
        return [], f"no resources in list; first={_summarize(res[0]) if res else 'none'}"

    if isinstance(res, dict):
        if isinstance(res.get('resources'), list):
            return res.get('resources') or [], "resources from top-level dict"
        for key in ('Contents', 'contents', 'Context', 'EntryContext', 'Body', 'body', 'result'):
            cont = res.get(key)
            if isinstance(cont, dict) and isinstance(cont.get('resources'), list):
                return cont.get('resources') or [], f"resources from {key}"
            if isinstance(cont, str):
                parsed = _maybe_json(cont)
                if isinstance(parsed, dict) and isinstance(parsed.get('resources'), list):
                    return parsed.get('resources') or [], f"resources from JSON string in {key}"
        return [], f"no resources in dict; keys={list(res.keys())[:20]}"

    if isinstance(res, str):
        parsed = _maybe_json(res)
        if isinstance(parsed, dict) and isinstance(parsed.get('resources'), list):
            return parsed.get('resources') or [], "resources from raw JSON string"
        return [], "string result without resources"

    return [], f"unsupported type: {type(res).__name__}"

def _host_with_derived_fields(host):
    # non-destructive copy
    h = dict(host) if isinstance(host, dict) else {}
    h["status_pretty"] = _fmt_status(h.get("status"))
    return h

def _to_html_value(value):
    value = _maybe_json(value)

    if isinstance(value, dict):
        parts = [f"<b>{html.escape(str(k))}</b>: {_to_html_value(v)}" for k, v in value.items()]
        return "<br>".join(parts)

    if isinstance(value, list):
        rendered = []
        for item in value:
            if isinstance(item, dict):
                inner = ", ".join(f"{html.escape(str(k))}: {html.escape(str(v))}" for k, v in item.items())
                rendered.append("{" + inner + "}")
            else:
                rendered.append(html.escape(str(item)))
        return ", ".join(rendered)

    if value is None:
        return "<i>none</i>"

    return html.escape(str(value))

def _dict_to_html_table(d):
    table = (
        "<table style='border-collapse: collapse; width: 100%;'>"
        "<tr style='background-color: #01cc66;'>"
        "<td style='text-align: center; vertical-align: top; width: 20%;'><b>Field</b></td>"
        "<td style='text-align: center; width: 80%;'><b>Value</b></td>"
        "</tr>"
    )
    for key, value in d.items():
        key_html = (
            f"<span style='text-align: right; display: inline-block; font-weight: bold; vertical-align: top;'>"
            f"{html.escape(str(key))}:&nbsp;</span>"
        )
        val_html = f"<span style='display: inline-block;'>{_to_html_value(value)}</span>"
        table += f"<tr><td style='text-align: right; vertical-align: top;'>{key_html}</td><td>{val_html}</td></tr>"
    table += "</table>"
    return table

def main():
    try:
        ctx = demisto.alert() or {}
        custom = ctx.get('CustomFields') or {}
        agent_id = custom.get('agentid') or custom.get('agent_id') or custom.get('agentId')
        if not agent_id:
            return_results("🟤 Missing agent id on the alert (CustomFields.agentid).")
            return

        res = execute_command('cs-falcon-search-device', {'ids': agent_id})

        # show explicit integration error if present (without KeyError)
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
        host_prepped = _host_with_derived_fields(host)

        html_record = _dict_to_html_table(host_prepped)

        return_results({
            'ContentsFormat': EntryFormat.HTML,
            'Type': EntryType.NOTE,
            'Contents': html_record,
        })

    except Exception as e:
        return_results(
            "🔴 There has been an issue gathering host information. Please ensure the CrowdStrike Falcon automation integration is enabled."
            f"\n\n\n Exception thrown: {str(e)}"
        )

if __name__ in ("builtins", "__builtin__", "__main__"):
    main()

