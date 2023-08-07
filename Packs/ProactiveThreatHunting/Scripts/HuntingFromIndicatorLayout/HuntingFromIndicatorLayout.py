import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    dArgs = demisto.args()
    if "indicator" in dArgs:
        sdo = dArgs.get("indicator").get("value")
    else:
        sdo = dArgs.get("sdo")
    try:
        results = demisto.executeCommand("createNewIncident", {"name": f"Threat Hunting Session - {sdo}",
                                                               "sdoname": f"{sdo}",
                                                               "type": "Proactive Threat Hunting"})
    except Exception:
        return_results("Error - Please install Proactive Threat Hunting pack to support this feature")

    result = CommandResults(
        readable_output=f"Proactive Threat Hunting Incident Created: Threat Hunting Session - {sdo}"
    )

    return_results(result)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
