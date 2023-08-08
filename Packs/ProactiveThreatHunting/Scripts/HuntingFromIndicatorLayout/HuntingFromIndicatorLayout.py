import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def hunting_from_indicator_layout(sdo: str):
    """
    Creating an incident from the indicator layout with the following parameters:
        Name: Threat Hunting Session - <Indicator Value>
        Type: Proactive Threat Hunting
        sdoname: <Indicator Value>
    Args:
        - sdo: The indicator value.
    Returns:
        - CommandResults: A CommandResults object with a readable output indicating that the incident was created.

    Raises:
        - ValueError: If the indicator value is not part of Demisto args,
          a ValueError is raised with a message indicating that the automation was not executed from the indicator layout.
       """
    try:
        demisto.executeCommand("createNewIncident", {"name": f"Threat Hunting Session - {sdo}",
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
        raise DemistoException("The automation was not executed from indicator layout")
    try:
        return_results(hunting_from_indicator_layout(args.get("indicator", "").get("value")))

    except Exception as e:
        return_error(f'Failed to create hunting session: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
