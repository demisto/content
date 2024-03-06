import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateutil.parser


def get_incident_ids() -> list | None:
    """
    Gets all the campaign incident ids.

    Returns:
        List of all the ids.
    """
    incidents = demisto.get(demisto.context(), "EmailCampaign.incidents")
    return [incident['id'] for incident in incidents] if incidents else None


def get_last_incident_occurred(incident_ids: list[str]) -> str:
    """
    Gets the campaign last incident occurred date.

    Args:
        incident_ids: All the campaign incident ids.

    Returns:
        The date of the last incident occurred.
    """
    res = demisto.executeCommand(
        'GetIncidentsByQuery', {'query': f"id:({' '.join(incident_ids)})"}
    )

    if isError(res):
        return_error(f'Error occurred while trying to get incidents by query: {get_error(res)}')

    incidents_from_query = json.loads(res[0]['Contents'])

    if not incidents_from_query:
        return incidents_from_query

    incident_created = max([dateutil.parser.parse(incident['created']) for incident in incidents_from_query])

    return incident_created.strftime("%B %d, %Y")


def main():

    try:
        if (
            (incident_ids := get_incident_ids())
            and (last_incident_occurred := get_last_incident_occurred(incident_ids))
        ):
            last_incident_occurred = get_last_incident_occurred(incident_ids)
            html_readable_output = last_incident_occurred

        else:
            html_readable_output = "No last incident occurred found."

        return_results(CommandResults(
            content_format='html',
            raw_response=(
                "<div style='text-align:center; font-size:17px; padding: 15px;'>"
                "Last Incident Occurred</br> <div style='font-size:24px;'> "
                f"{html_readable_output} </div></div>")
        ))

    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
