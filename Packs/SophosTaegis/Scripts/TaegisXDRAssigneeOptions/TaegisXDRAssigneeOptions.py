"""
Field display script for Taegis XDR Assignee (taegisxdrassignee).

Reads options from the incident field taegisxdrassigneeoptionsdata (JSON with
options list and label_to_id map), which is set by the TaegisXDRv3 integration
when incidents are fetched. Falls back to @customer, @secureworks, and @sophos when
the data is not present (e.g. incident created manually or before this feature).
"""

STATIC_OPTIONS = ["@customer", "@secureworks", "@sophos"]
FIELD_KEY = "taegisxdrassigneeoptionsdata"
try:
    _STRING_TYPES = (str, unicode)  # Python 2
except NameError:
    _STRING_TYPES = (str,)  # Python 3


def _get_raw(d):
    """Get options data from dict (taegisxdrassigneeoptionsdata)."""
    if not isinstance(d, dict):
        return None
    return d.get(FIELD_KEY)


def _decode_options_data(raw):
    """Decode value that may be 'taegis_users:' + base64 (avoids indicator extraction)."""
    if not raw or not isinstance(raw, _STRING_TYPES) or not (raw.strip() if isinstance(raw, _STRING_TYPES) else True):
        return raw
    s = raw.strip() if isinstance(raw, _STRING_TYPES) else raw
    if isinstance(s, _STRING_TYPES) and s.startswith("taegis_users:"):
        import base64
        try:
            b = base64.b64decode(s[len("taegis_users:"):])
            return b.decode("utf-8") if isinstance(b, bytes) else b
        except Exception:
            return None
    return raw


def main():
    options = list(STATIC_OPTIONS)
    try:
        inc_full = demisto.incident() or {}
        incident = inc_full
        if isinstance(incident, dict) and "incident" in incident and isinstance(incident.get("incident"), dict):
            incident = incident["incident"]
        elif isinstance(incident, dict) and "Incident" in incident and isinstance(incident.get("Incident"), dict):
            incident = incident["Incident"]
        raw = None
        if isinstance(incident, dict):
            raw = _get_raw(incident)
            if not raw and isinstance(incident.get("CustomFields"), dict):
                raw = _get_raw(incident.get("CustomFields"))
            if not raw and isinstance(incident.get("customFields"), dict):
                raw = _get_raw(incident.get("customFields"))
        if raw is not None:
            import json
            raw = _decode_options_data(raw)
            if raw and (isinstance(raw, _STRING_TYPES) and raw.strip()):
                try:
                    data = json.loads(raw)
                except (ValueError, TypeError):
                    data = None
            else:
                data = raw if isinstance(raw, dict) else None
            if isinstance(data, dict) and "options" in data and isinstance(data["options"], list):
                options = [str(o) for o in data["options"] if o is not None]
        if options == STATIC_OPTIONS:
            raw_json = None
            for _inc in (incident, inc_full):
                if isinstance(_inc, dict):
                    raw_json = _inc.get("rawJSON") or _inc.get("raw_json")
                    if isinstance(raw_json, _STRING_TYPES) and raw_json.strip():
                        break
            if raw_json and isinstance(raw_json, _STRING_TYPES) and raw_json.strip():
                try:
                    parsed = __import__("json").loads(raw_json)
                    if isinstance(parsed, dict):
                        raw = parsed.get(FIELD_KEY)
                        raw = _decode_options_data(raw) if raw else raw
                        if isinstance(raw, _STRING_TYPES) and raw.strip():
                            data = __import__("json").loads(raw)
                        elif isinstance(raw, dict):
                            data = raw
                        else:
                            data = None
                        if isinstance(data, dict) and "options" in data and isinstance(data["options"], list):
                            options = [str(o) for o in data["options"] if o is not None]
                except (ValueError, TypeError, KeyError):
                    pass
    except Exception as e:
        demisto.debug("TaegisXDRAssigneeOptions: could not read options data: {}".format(e))
    # Prepend placeholder for "Update in Taegis" requested field so user can reset after push
    PLACEHOLDER = "Select Assignee"
    if not options:
        options = [PLACEHOLDER]
    elif options[0] != PLACEHOLDER:
        options = [PLACEHOLDER] + [o for o in options if o != PLACEHOLDER]
    demisto.results({"hidden": False, "options": options})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
