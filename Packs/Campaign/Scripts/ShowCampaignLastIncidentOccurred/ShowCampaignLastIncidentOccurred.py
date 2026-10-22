import traceback
from datetime import timezone

import dateutil.parser
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# XSOAR represents an unset time value as the zero time (year 1), which is not a real occurrence date.
ZERO_TIME_YEAR = 1


def get_campaign_incidents() -> list:
    """
    Gets all the campaign incidents from the context.

    Returns:
        List of all the campaign incidents, an empty list if no incidents were found.
    """
    return argToList(demisto.get(demisto.context(), "EmailCampaign.incidents"))


def get_occurred_dates(incidents: list) -> list:
    """
    Extracts the occurred dates of the campaign incidents.

    Incidents without a parsable occurred value are skipped, so a single malformed incident
    cannot break the whole dynamic section.

    Args:
        incidents: The campaign incidents taken from the context.

    Returns:
        List of the parsed occurred dates, as timezone aware datetimes.
    """
    occurred_dates = []

    for incident in incidents:
        occurred = incident.get("occurred")

        if not occurred:
            demisto.debug(f"Skipping incident {incident.get('id')} - no occurred value was found.")
            continue

        try:
            parsed_occurred = dateutil.parser.parse(occurred)
        except (ValueError, OverflowError, TypeError) as err:
            demisto.debug(
                f"Skipping incident {incident.get('id')} - could not parse occurred value {occurred}: {err}\n"
                f"{traceback.format_exc()}"
            )
            continue

        if parsed_occurred.year <= ZERO_TIME_YEAR:
            demisto.debug(f"Skipping incident {incident.get('id')} - occurred value {occurred} is the zero time.")
            continue

        if parsed_occurred.tzinfo is None:
            # Assume UTC for naive values, otherwise comparing them with aware values raises a TypeError.
            parsed_occurred = parsed_occurred.replace(tzinfo=timezone.utc)  # noqa: UP017

        occurred_dates.append(parsed_occurred)

    return occurred_dates


def get_last_incident_occurred(occurred_dates: list) -> str:
    """
    Gets the campaign last incident occurred date.

    Args:
        occurred_dates: The parsed occurred dates of the campaign incidents.

    Returns:
        The date of the last incident occurred.
    """
    return max(occurred_dates).strftime("%B %d, %Y")


def main():
    try:
        incidents = get_campaign_incidents()
        occurred_dates = get_occurred_dates(incidents)

        if occurred_dates:
            html_readable_output = get_last_incident_occurred(occurred_dates)

        else:
            html_readable_output = "No last incident occurred found."

        return_results(
            CommandResults(
                content_format="html",
                raw_response=(
                    "<div style='text-align:center; font-size:17px; padding: 8px;'>"
                    "Last Incident Occurred"
                    f"<div style='font-size:24px;'>{html_readable_output}</div></div>"
                ),
            )
        )

    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute ShowCampaignLastIncidentOccurred. Error: {err}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
