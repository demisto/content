import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def strip_brackets(name: str) -> str:
    name = (name or "").strip()
    if name.startswith("[") and name.endswith("]"):
        return name[1:-1]
    return name


def get_all_apps() -> list:
    res = demisto.executeCommand("netskopev2-list-private-apps", {})
    if is_error(res):
        raise DemistoException(f"Failed to list private apps: {get_error(res)}")

    # Confirmed against the live API: when a command sets both outputs and raw_response on its
    # CommandResults (netskopev2-list-private-apps does), executeCommand()'s "Contents" reflects
    # raw_response, not outputs - the structured data lives in "EntryContext" instead, keyed by
    # outputs_prefix (with a DT merge-key suffix appended when outputs_key_field is set, hence the
    # prefix match rather than an exact key match).
    apps: list = []
    for entry in res:
        entry_context = entry.get("EntryContext") or {}
        for key, value in entry_context.items():
            if not key.startswith("Netskope.PrivateApp"):
                continue
            if isinstance(value, list):
                apps.extend(value)
            elif isinstance(value, dict):
                apps.append(value)
    return apps


def find_by_name(apps: list, app_name: str) -> list:
    target = app_name.strip().lower()
    matches = []
    for app in apps:
        # Netskope wraps app_name in brackets (e.g. "[test server]") in the list response - a
        # "name" alias field (unwrapped) is only present on create/update responses, not list, so
        # check both to be safe.
        candidates = {strip_brackets(app.get("app_name", "")).lower(), (app.get("name") or "").strip().lower()}
        if target in candidates:
            matches.append(app)
    return matches


def main():
    args = demisto.args()
    app_id = args.get("app_id")
    app_name = args.get("app_name")

    if app_id:
        outputs = {"app_id": str(app_id), "resolved_by": "app_id", "error": ""}
        readable_output = f'Using the provided app_id "{app_id}" directly.'
    elif app_name:
        matches = find_by_name(get_all_apps(), app_name)
        if not matches:
            outputs = {"app_id": "", "resolved_by": "app_name", "error": f'No private app found named "{app_name}".'}
            readable_output = outputs["error"]
        elif len(matches) > 1:
            ids = ", ".join(str(m.get("app_id") or m.get("id")) for m in matches)
            outputs = {
                "app_id": "",
                "resolved_by": "app_name",
                "error": f'Multiple private apps named "{app_name}" found (IDs: {ids}) - provide AppID directly instead.',
            }
            readable_output = outputs["error"]
        else:
            resolved_id = matches[0].get("app_id") or matches[0].get("id")
            outputs = {"app_id": str(resolved_id), "resolved_by": "app_name", "error": ""}
            readable_output = f'Resolved app_name "{app_name}" to app_id "{resolved_id}".'
    else:
        outputs = {"app_id": "", "resolved_by": "none", "error": "Either AppID or AppName must be provided."}
        readable_output = outputs["error"]

    return_results(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="ResolvedAppId",
            outputs=outputs,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
