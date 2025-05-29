import demistomock as demisto  # noqa: F401


def main():  # pragma: no cover
    incident = demisto.incidents()[0]
    incident_type = incident.get("type")
    mirror_id = incident.get("dbotMirrorId")

    if not incident_type or not mirror_id:
        demisto.results(True)  # Keep it if missing either value
        return

    if incident_type not in ["Asimily Anomaly", "Asimily CVE", "Asimily Asset"]:
        demisto.results(True)
        return

    query = f'dbotMirrorId:"{mirror_id}" and type:"{incident_type}"'
    result = demisto.executeCommand("getIncidents", {"query": query, "size": 1})

    incidents = result[0].get("Contents", {}).get("data", []) if result and isinstance(result, list) else []

    if incidents:
        demisto.results(False)  # Drop
    else:
        demisto.results(True)  # Keep


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
