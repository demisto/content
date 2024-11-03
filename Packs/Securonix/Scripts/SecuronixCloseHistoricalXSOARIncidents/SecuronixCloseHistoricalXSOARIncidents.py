import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Script which closes the existing XSOAR incident whose respective Securonix incident is closed."""

import json
import traceback
from datetime import datetime
from typing import Any

close_xsoar_incident_ids = []


def get_securonix_incident_id(incident: dict[str, Any]) -> str | None:
    """Return Securonix incident id.

    Args:
        incident: Incident data.

    Returns:
        Optional[str]: Securonix incident ID if found.
    """
    incident_labels = incident.get("labels", [])

    for label in incident_labels:
        if label["type"] == "incidentId":
            return label["value"]
    return None


def is_incident_closed_on_securonix(activity_data: list[dict[str, Any]], close_states_of_securonix: list[str]) -> bool:
    """Check whether the incident is closed on the Securonix.

    Args:
        activity_data: A list of activity data from which to determine whether the incident is closed or not.
        close_states_of_securonix: A list of Securonix states which defines the close state for XSOAR.

    Returns:
        bool: Indicating whether the incident is closed on Securonix or not.
    """
    if not isinstance(activity_data, list):
        return False

    for activity in reversed(activity_data):
        current_status = activity.get("status", "").strip().lower()
        last_status = activity.get("lastStatus", "").strip().lower()

        if current_status in close_states_of_securonix and last_status not in close_states_of_securonix:
            return True

    return False


def extract_closing_comments(activity_data: list[dict[str, Any]], close_states_of_securonix: list[str]) -> str:
    """Extract the contents of the closing comments from activity data provided from Securonix.

    Args:
        activity_data: A list of activity data from which to extract the closing comments.
        close_states_of_securonix: A list of Securonix states which defines the close state for XSOAR.

    Returns:
        str: A string representing closing comments.
    """
    closing_comments = []

    if not isinstance(activity_data, list):
        return ""

    for activity in activity_data:
        current_status = activity.get("status", "").strip().lower()
        last_status = activity.get("lastStatus", "").strip().lower()

        if current_status in close_states_of_securonix and last_status not in close_states_of_securonix:
            comments_list = activity.get("comment", [])

            for _comment in comments_list:
                closing_comments.append(_comment.get("Comments", ""))

    if not closing_comments:
        closing_comments.append('Closing the XSOAR incident as Securonix incident is closed.')

    return " | ".join(closing_comments)


def close_xsoar_incident(xsoar_incident_id: str, sx_incident_id: str, close_states_of_securonix: list[str]) -> bool:
    """Close the existing XSOAR incident whose respective Securonix incident is closed.

    Args:
        xsoar_incident_id: XSOAR incident ID.
        sx_incident_id: Securonix incident ID.
        close_states_of_securonix: Close state of Securonix which can be considered as closed state of XSOAR.

    Returns:
        bool: True if the XSOAR incident is close, False otherwise.
    """
    demisto.debug(f"Getting update for XSOAR Incident: {xsoar_incident_id} from the respective "
                  f"Securonix Incident: {sx_incident_id}")

    incident_activity_history_args = {"incident_id": sx_incident_id}
    incident_activity_history_resp = demisto.executeCommand("securonix-incident-activity-history-get",
                                                            args=incident_activity_history_args)

    try:
        incident_activity_history = incident_activity_history_resp[0]["Contents"]
    except KeyError as exception:
        demisto.error(str(exception))
        return False

    if is_incident_closed_on_securonix(incident_activity_history, close_states_of_securonix):
        demisto.info(f"Closing the XSOAR incident {xsoar_incident_id} as its respective securonix incident is closed.")
        closing_comments = extract_closing_comments(incident_activity_history, close_states_of_securonix)

        close_investigation_args = {
            "id": xsoar_incident_id,
            "closeNotes": closing_comments or "Incident closed using script SecuronixCloseHistoricalXSOARIncidents.",
            "closeReason": "Resolved",
        }
        demisto.executeCommand("closeInvestigation", close_investigation_args)
        return True

    demisto.info(f"The XSOAR Incident: {xsoar_incident_id} is not closed."
                 f"Respective Securonix Incident: {sx_incident_id}.")
    return False


def main():
    """Entrypoint."""
    try:
        script_args = demisto.args()
        from_time = script_args.get("from", "").strip()
        to_time = script_args.get("to", "").strip()

        close_states_of_securonix = argToList(script_args.get("close_states", "").strip())
        close_states_of_securonix = [s.lower() for s in close_states_of_securonix]

        timestamp_format = "%Y-%m-%d %H:%M:%S.%f"

        if from_time:
            from_time = datetime.strftime(arg_to_datetime(from_time), timestamp_format)  # type: ignore[arg-type]
        if to_time:
            to_time = datetime.strftime(arg_to_datetime(to_time), timestamp_format)  # type: ignore[arg-type]

        xsoar_query = 'sourceBrand:Securonix and -type:"Securonix Incident" and -status:closed'

        page_num = 0
        number_of_incidents_closed = 0

        get_incidents_args = {
            "query": xsoar_query,
            "fromdate": from_time,
            "todate": to_time,
            "size": 100,
            "page": page_num
        }
        remove_nulls_from_dictionary(get_incidents_args)
        demisto.debug(f"getIncidents command arguments: {json.dumps(get_incidents_args)}")

        get_incidents_resp = demisto.executeCommand("getIncidents", get_incidents_args)
        xsoar_incidents = get_incidents_resp[0]["Contents"]["data"] or []
        total_xsoar_incidents = get_incidents_resp[0]["Contents"]["total"]

        demisto.info(f"Total number of incidents matched by the XSOAR query: {total_xsoar_incidents}")

        while True:
            if not xsoar_incidents:
                demisto.info('Completing the execution as no more incidents found!')
                break

            demisto.info(f"Starting to close {len(xsoar_incidents)} number of incidents.")

            for incident in xsoar_incidents:
                xsoar_incident_id = incident.get("id")
                sx_incident_id = get_securonix_incident_id(incident=incident)
                is_closed = close_xsoar_incident(xsoar_incident_id,
                                                 sx_incident_id, close_states_of_securonix)  # type: ignore

                if is_closed:
                    close_xsoar_incident_ids.append(xsoar_incident_id)
                    number_of_incidents_closed += 1

            get_incidents_args["page"] = get_incidents_args["page"] + 1
            demisto.debug(f"getIncidents command arguments: {json.dumps(get_incidents_args)}")

            get_incidents_resp = demisto.executeCommand("getIncidents", get_incidents_args)
            xsoar_incidents = get_incidents_resp[0]["Contents"]["data"] or []

        return_results(
            CommandResults(
                readable_output=f"Successfully closed {number_of_incidents_closed} XSOAR incidents!",
                outputs_prefix="Securonix.CloseHistoricalXSOARIncidents",
                outputs_key_field='IncidentIDs',
                outputs=remove_empty_elements({'IncidentIDs': close_xsoar_incident_ids})
            )
        )

    except Exception as exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute SecuronixCloseHistoricalXSOARIncidents. Error: {str(exception)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
