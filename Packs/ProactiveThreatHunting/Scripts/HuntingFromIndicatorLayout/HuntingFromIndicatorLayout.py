import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def hunting_from_indicator_layout(sdo):
    try:
        results = demisto.executeCommand("createNewIncident", {"name": f"Threat Hunting Session - {sdo}",
                                                               "sdoname": f"{sdo}",
                                                               "type": "Proactive Threat Hunting"})
    except Exception as e:
        raise DemistoException(f'Failed to create hunting session: {str(e)}')

    return CommandResults(
        readable_output=f"Proactive Threat Hunting Incident Created: Threat Hunting Session - {sdo}"
    )


def main() -> None:  # pragma: no cover
    args = demisto.args()
    if "indicator" not in args:
        raise DemistoException("error")
    return_results(hunting_from_indicator_layout(args.get("indicator", "").get("value")))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
