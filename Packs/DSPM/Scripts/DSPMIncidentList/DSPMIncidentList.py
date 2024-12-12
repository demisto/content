import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Script Name: DSPMIncidentList
Description:
This automation script manages incidents in a list by adding or deleting incidents based on the provided action.
For incidents older than the configured time limit (default is 48 hours), the script performs a cleanup by removing
the incident from the list. Additionally, the script supports adding new incidents to the list if they do not already exist.
"""

from datetime import datetime

""" STANDALONE FUNCTION """


def get_incident_time(incident_list, incident_id):
    """
    Fetches the creation time of an incident from a list of incidents.

    Args:
        incident_list (list): The list of incidents.
        incident_id (str): The ID of the incident to search for.

    Returns:
        str: The creation time of the incident, if found; otherwise, an empty string.
    """
    incident_time = ""
    for incident in incident_list:
        if incident.get("incident_id") == incident_id:
            incident_time = incident.get("incident_created")
    return incident_time


def timeDifferenceInHours(incident_time, rerun_time):
    """
    Calculates the difference in hours between the current time and the incident's creation time.
    If the difference exceeds the configured threshold (default 48 hours), it returns True.

    Args:
        incident_time (str): The creation time of the incident in the format "%Y-%m-%d %H:%M:%S.%f".
        rerun_time (str): The rerun time of the incident.

    Returns:
        bool: True if the time difference exceeds the threshold, False otherwise.
    """
    given_time = datetime.strptime(incident_time, "%Y-%m-%d %H:%M:%S.%f")
    current_time = datetime.now()
    difference = current_time - given_time
    hours_difference = difference.total_seconds() / 3600
    if hours_difference >= float(rerun_time):
        return True
    return False


def get_incident_list(incident_object):
    """
    Retrieves the list of incidents from the external source ("INCIDENT_LIST2").

    Args:
        incident_object (dict): The incident data passed to the script.

    Returns:
        str: The incident list as a string or an empty string if no list is found.
    """
    incident_list = ""
    incident_data = demisto.executeCommand("getList", {"listName": "INCIDENT_LIST2"})
    if (
        incident_data[0].get("Contents") == "null"
        or incident_data[0].get("Contents") is None
        or "Item not found" in incident_data[0].get("Contents")
        or not incident_data[0].get("Contents")
    ):
        return incident_list
    else:
        incident_list = incident_data[0].get("Contents")
        return incident_list


def delete_incident_list(args):
    """
    Deletes an incident from the incident list if its time difference exceeds the threshold.
    If the incident does not exist in the list or the time limit is not exceeded, no action is taken.

    Args:
        incident_object (dict): The incident data containing the incident ID.

    Returns:
        str: A status message indicating the result of the delete operation.
    """
    rerun_time = args.get("rerun_time")
    incident_object = args.get("incident_data")
    if isinstance(incident_object, list):
        incident_object = incident_object[0]
    incident_id = incident_object.get("id")
    status = f"Incident data with incident id {incident_id} does not exist in the list"
    incident_list = args.get("incident_list")
    incident_list = "[" + incident_list + "]"
    incident_list = json.loads(incident_list)
    # Check if the value exists in any dictionary
    incident_time = get_incident_time(incident_list, incident_id)
    if incident_time:
        differenceInHours = timeDifferenceInHours(incident_time, rerun_time)
        if differenceInHours:
            # Remove the incident_data with the incident_id
            incident_list = [incident for incident in incident_list if incident["incident_id"] != incident_id]
            # delete_incident = demisto.executeCommand("setList", {"listName": "INCIDENT_LIST2", "listData": incident_list})
            status = f"Delete incident data with incident id {incident_id} from the list."
        else:
            status = "Re-run time limit is not exceeded"
    return status


def add_incident_list(args):
    """
    Adds a new incident to the incident list if it does not already exist.

    Args:
        incident_object (dict): The incident data containing the incident ID and creation time.

    Returns:
        str: A status message indicating the result of the add operation.
    """
    status = ""
    incident_object = args.get("incident_data")
    if isinstance(incident_object, list):
        incident_object = incident_object[0]
    incident_id = incident_object.get("id")
    incident_data = {
        "incident_id": incident_id,
        "incident_created": incident_object.get("incidentCreated"),  # Update the create time field after testing
    }
    incident_list = args.get("incident_list")
    incident_list = "[" + incident_list + "]"
    incident_list = json.loads(incident_list)
    incident_time = get_incident_time(incident_list, incident_id)
    if incident_time:
        status = "Incident data already exist in the list."
    else:
        incident_list.append(incident_data)
        # add_incident = demisto.executeCommand("createList", {"listName": "INCIDENT_LIST2", "listData": incident_list})
        status = f"Successfully added incident data with incident id {incident_id} in the list."
    return status


""" MAIN FUNCTION """


def main():
    """
    Main function that handles the script's logic. It decides whether to add or delete an incident
    from the list based on the `action` argument passed to the script.
    """
    action = demisto.args().get("action")
    if action == "delete":
        status = delete_incident_list(demisto.args())
    else:
        demisto.setContext("User.Action", "no_response")
        status = add_incident_list(demisto.args())
    return_results(
        CommandResults(
            readable_output=status,
            outputs_prefix="listStatus",
            outputs=status,
        )
    )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
