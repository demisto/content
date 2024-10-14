
from CommonServerPython import *
from GetIncidentsApiModule import *
DEFAULT_LIMIT = 500
DEFAULT_PAGE_SIZE = 100
DEFAULT_TIME_FIELD = "created"
MAX_BULK_SIZE_ALLOWED = 10

# HELPER FUNCTIONS


def get_playbooks_dict():
    """
    Fetches the playbook ID-to-name mapping and stores it in a global variable.

    Raises:
        DemistoException: If the response is in an invalid format or if no playbooks are found.
    """
    response = demisto.executeCommand("core-api-get", {"uri": "/playbooks/idToNameMap"})
    if not response:
        raise DemistoException("Invalid response format while searching for playbooks.")

    playbooks_dict = response[0].get("Contents", {}).get("response", {})
    if not playbooks_dict:
        raise DemistoException("No playbooks found. Please ensure that playbooks are available and try again.")

    return playbooks_dict


def get_playbook_id(playbook_id: str, playbook_name: str, playbooks_dict: dict):
    """
    Retrieve the playbook ID based on the given playbook ID or name.

    Args:
        playbook_id (str): The ID of the playbook.
        playbook_name (str): The name of the playbook.

    Raises:
        DemistoException: If both `playbook_id` and `playbook_name` are provided,
                          or if the playbook is not found.

    Returns:
        str: The corresponding playbook ID if found.
    """
    if playbook_id and playbook_name:
        raise DemistoException("Please provide only a playbook ID or a playbook name, not both.")

    if playbook_name:
        for key_id, value_name in playbooks_dict.items():
            if value_name == playbook_name:
                return key_id

    elif playbook_id and playbook_id in playbooks_dict:
        return playbook_id

    raise DemistoException(f"Playbook '{playbook_name or playbook_id}' wasn't found. Please check the name and try again.")


def handle_results(command_results: dict, playbook_id: str, alert_ids: list) -> str:
    """Extract and format the relevant info from the result dict.

    Args:
        command_results (dict): The results from the API call.
        playbook_id (str): The playbook id for info.
        alert_ids (list): A list of alert Ids for info.

    Returns:
        str: A summary of the operation status, indicating either success or the error log.
    """
    if not command_results:
        return "No results found for this query."

    try:
        result_dict = command_results[0].get('Contents', {}).get('response', {})

        if not result_dict:
            return f"Playbook ID '{playbook_id}' was set successfully for alerts: {alert_ids}."

        failed_ids = list(result_dict.keys())
        succeeded_ids = list(set(alert_ids) - set(failed_ids))

        message = (
            f"Playbook ID '{playbook_id}' could not be executed for alerts {failed_ids} "
            "due to failure in creating an investigation playbook."
        )

        if succeeded_ids:
            message += (
                f"\nPlaybook ID '{playbook_id}' was set successfully for alerts: {succeeded_ids}."
            )

        return message.strip()

    except Exception as e:
        return f"Unexpected error occurred: {str(e)}. Response: {command_results[0]}"


def open_investigation(alert_ids: list) -> None:
    """
    Reopens investigations for the given alert IDs.

    Args:
        alert_ids (list): List of alert IDs for which the investigations need to be reopened.
    """
    for alert in alert_ids:
        demisto.executeCommand("core-api-post", {"uri": "/investigation/:id/reopen", "body": {"id": alert, "version": -1}})


def set_playbook_on_alerts(playbook_id: str, alert_ids: list, playbooks_dict: dict) -> str:
    """Using an API call, create a new investigation Playbook with a given playbook ID and alerts ID

    Args:
        playbook_id (str): The playbook id to set.
        alert_ids (list): A list of alert Ids. limited to 10 at a time.

    Returns:
        dict: The command results.
    """
    if playbook_id not in playbooks_dict:
        return f"Playbook ID '{playbook_id}' was not found for alerts {alert_ids}."

    command_results = demisto.executeCommand(
        "core-api-post", {"uri": "/xsoar/inv-playbook/new", "body":
                          {"playbookId": playbook_id, "alertIds": alert_ids, "version": -1}})
    return handle_results(command_results, playbook_id, alert_ids)


def loop_on_alerts(incidents: list[dict], playbook_id: str, limit: int, reopen_closed_inv: bool, playbooks_dict: dict):
    """
    Loops through alerts and applies the specified playbook in batches.

    Args:
        incidents (list[dict]): The list of incidents.
        playbook_id (str): The playbook ID to assign.
        limit (int): The maximum number of alerts to process in this run.
        reopen_closed_inv (bool): Whether to reopen closed investigations.

    Returns:
        tuple: A string indicating operation status and a list of reopened alerts.
    """
    if not incidents:
        return "Couldn't find any alerts"

    alert_inv_status: dict[str, list] = {
        "close_ids": [],
        "open_ids": [],
        "all_ids": []
    }

    for inc in incidents[:limit]:
        alert_inv_status["all_ids"].append(inc["id"])
        if inc["closeReason"] != "":
            alert_inv_status["close_ids"].append(inc["id"])
        else:
            alert_inv_status["open_ids"].append(inc["id"])

    alert_closed_bulks = [
        alert_inv_status["close_ids"][i:i + MAX_BULK_SIZE_ALLOWED]
        for i in range(0, len(alert_inv_status["close_ids"]), MAX_BULK_SIZE_ALLOWED)
    ]
    alert_open_bulks = [
        alert_inv_status["open_ids"][i:i + MAX_BULK_SIZE_ALLOWED]
        for i in range(0, len(alert_inv_status["open_ids"]), MAX_BULK_SIZE_ALLOWED)
    ]
    alert_all_ids_bulks = [
        alert_inv_status["all_ids"][i:i + MAX_BULK_SIZE_ALLOWED]
        for i in range(0, len(alert_inv_status["all_ids"]), MAX_BULK_SIZE_ALLOWED)
    ]

    message_response = []
    reopened_alerts = []
    if reopen_closed_inv and alert_closed_bulks:
        if reopened_alerts := alert_inv_status['close_ids']:
            message_response.append(f"Alerts {reopened_alerts} have been reopened.")
            
        for bulk in alert_closed_bulks:
            open_investigation(alert_ids=bulk)

        message_response += [
            set_playbook_on_alerts(playbook_id=playbook_id, alert_ids=bulk, playbooks_dict=playbooks_dict)
            for bulk in alert_all_ids_bulks
        ]
    else:
        message_response += [
            set_playbook_on_alerts(playbook_id=playbook_id, alert_ids=bulk, playbooks_dict=playbooks_dict)
            for bulk in alert_open_bulks
        ]

    return '\n'.join(message_response)


def split_by_playbooks(incidents: list[dict], limit: int, reopen_closed_inv: bool, playbooks_dict: dict) -> str:
    """
    Splits incidents by their playbook ID and processes them accordingly.

    Args:
        incidents (list[dict]): The list of incidents to process.
        limit (int): The maximum number of incidents to process.
        reopen_closed_inv (bool): Whether to reopen closed investigations.

    Returns:
        str: A message summarizing the playbook execution results.
    """
    playbook_map: dict[str, list] = {}
    missing_playbook_alerts = []

    for inc in incidents[:limit]:
        playbook_id = inc.get("playbookId", "")
        if playbook_id:
            if playbook_id in playbook_map:
                playbook_map[playbook_id].append(inc)
            else:
                playbook_map[playbook_id] = [inc]

        else:
            missing_playbook_alerts.append(inc["id"])

    message_response = []

    if missing_playbook_alerts:
        message_response.append(f"Could not find an attached playbook for alerts {missing_playbook_alerts}.")

    for playbook_id, playbook_incidents in playbook_map.items():
        message_response.append(loop_on_alerts(playbook_incidents, playbook_id, limit, reopen_closed_inv, playbooks_dict))

    return "\n".join(message_response)


def main():
    try:
        args = demisto.args()
        incidents = get_incidents_by_query(args)
        limit = int(args.get("limit", "500"))
        reopen_closed_inv = argToBoolean(args.get("reopen_closed_inv"))
        playbook_id = args.get("playbook_id", "")
        playbook_name = args.get("playbook_name", "")
        playbooks_dict = get_playbooks_dict()
        if playbook_id or playbook_name:
            playbook_id = get_playbook_id(playbook_id, playbook_name, playbooks_dict)

        if not playbook_id:
            # we will try to rerun each alert's assigned playbook
            results = split_by_playbooks(incidents, limit, reopen_closed_inv, playbooks_dict)
        else:
            results = loop_on_alerts(incidents, playbook_id, limit, reopen_closed_inv, playbooks_dict)

        return_results(results)

    except Exception as e:
        return_error(str(e))


if __name__ in ["builtins", "__main__"]:
    main()
