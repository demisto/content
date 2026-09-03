import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def get_all_publishers() -> list:
    # Restrict to just the two fields needed - a publisher can have many connected app segments,
    # and the full unrestricted response can be large enough that XSOAR strips it from context
    # and attaches it as a file instead, silently returning nothing usable here.
    res = demisto.executeCommand("netskopev2-list-publishers", {"fields": "publisher_id,publisher_name"})
    if is_error(res):
        raise DemistoException(f"Failed to list publishers: {get_error(res)}")

    # Confirmed against the live API: when a command sets both outputs and raw_response on its
    # CommandResults (netskopev2-list-publishers does), executeCommand()'s "Contents" reflects
    # raw_response, not outputs - the structured data lives in "EntryContext" instead, keyed by
    # outputs_prefix (with a DT merge-key suffix appended when outputs_key_field is set, hence the
    # prefix match rather than an exact key match).
    publishers: list = []
    for entry in res:
        entry_context = entry.get("EntryContext") or {}
        for key, value in entry_context.items():
            if not key.startswith("Netskope.Publisher"):
                continue
            if isinstance(value, list):
                publishers.extend(value)
            elif isinstance(value, dict):
                publishers.append(value)
    return publishers


def resolve_publishers(names: list, all_publishers: list) -> tuple:
    by_name: dict = {}
    for pub in all_publishers:
        key = (pub.get("publisher_name") or "").strip().lower()
        by_name.setdefault(key, []).append(pub)

    resolved = []
    errors = []
    for name in names:
        matches = by_name.get(name.lower(), [])
        if not matches:
            errors.append(f'No publisher found named "{name}".')
        elif len(matches) > 1:
            ids = ", ".join(str(m.get("publisher_id")) for m in matches)
            errors.append(f'Multiple publishers named "{name}" found (IDs: {ids}) - resolve manually.')
        else:
            pub = matches[0]
            # netskopev2-list-publishers returns publisher_id as an int, but the write API
            # (create/update/replace private app) declares publisher_id as a string - confirmed
            # against the live API: sending it back as an int causes the whole write to silently
            # no-op, same failure mode as the protocol read-shape/write-shape mismatch.
            resolved.append({"publisher_id": str(pub.get("publisher_id")), "publisher_name": pub.get("publisher_name")})
    return resolved, errors


def main():
    args = demisto.args()
    names = [n.strip() for n in argToList(args.get("publisher_names")) if n.strip()]
    if not names:
        outputs = {"publishers_json": "", "error": "publisher_names must not be empty."}
        return_results(CommandResults(readable_output=outputs["error"], outputs_prefix="ResolvedPublishers", outputs=outputs))
        return

    resolved, errors = resolve_publishers(names, get_all_publishers())

    if errors:
        outputs = {"publishers_json": "", "error": "; ".join(errors)}
        readable_output = outputs["error"]
    else:
        outputs = {"publishers_json": json.dumps(resolved), "error": ""}
        readable_output = f"Resolved publisher(s) {', '.join(names)} to {outputs['publishers_json']}."

    return_results(
        CommandResults(
            readable_output=readable_output,
            outputs_prefix="ResolvedPublishers",
            outputs=outputs,
        )
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
