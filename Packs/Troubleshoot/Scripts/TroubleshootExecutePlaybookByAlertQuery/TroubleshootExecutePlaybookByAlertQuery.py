
from CommonServerPython import *
from GetIncidentsApiModule import *
DEFAULT_LIMIT = 500
DEFAULT_PAGE_SIZE = 100
DEFAULT_TIME_FIELD = "created"
MAX_BULK_SIZE_ALLOWED = 10


class ResultsSummary:
    def __init__(self, playbooks_dict):
        self.playbooks_dict = playbooks_dict
        self.results_summary: dict = {
            "success": {},
            "failure_create": {},
            "failure_set": {},
            "reopened": [],
            "others": []
        }

    def update_success(self, playbook_id: str, alert_ids: str | list):
        """Update the 'success' dictionary with alert IDs for the given playbook ID."""
        alert_ids = [alert_ids] if isinstance(alert_ids, str) else alert_ids
        if playbook_id in self.results_summary["success"]:
            self.results_summary["success"][playbook_id].extend(alert_ids)
        else:
            self.results_summary["success"][playbook_id] = alert_ids

    def update_failure_create(self, playbook_id: str, failed_ids: str | list):
        """Update the 'failure_create' dictionary with failed IDs for the given playbook ID."""
        failed_ids = [failed_ids] if isinstance(failed_ids, str) else failed_ids
        if playbook_id in self.results_summary["failure_create"]:
            self.results_summary["failure_create"][playbook_id].extend(failed_ids)
        else:
            self.results_summary["failure_create"][playbook_id] = failed_ids

    def update_failure_set(self, playbook_id: str, alert_ids: list):
        """Update the 'failure_set' dictionary with alert IDs for the given playbook ID."""
        if playbook_id in self.results_summary["failure_set"]:
            self.results_summary["failure_set"][playbook_id].extend(alert_ids)
        else:
            self.results_summary["failure_set"][playbook_id] = alert_ids

    def update_reopened(self, reopened_alerts: list):
        """Update the 'reopened' list with alerts from the provided alert_inv_status."""
        self.results_summary["reopened"].extend(reopened_alerts)

    def append_to_others(self, message: str):
        """Append a message to the 'others' list for missing playbook alerts."""
        self.results_summary["others"].append(message)

    def generate_summary(self):
        """Generate a summary message based on the results_summary."""
        final_message = []

        if self.results_summary["success"]:
            for playbook_success, alerts_success in self.results_summary["success"].items():
                playbook_info = get_playbook_info(playbook_success, self.playbooks_dict)
                final_message.append(
                    f"Playbook {playbook_info} was set successfully for alerts: {sorted(alerts_success)}.")

        if self.results_summary["failure_create"]:
            for playbook_failure_create, alerts_fail in self.results_summary["failure_create"].items():
                playbook_info = get_playbook_info(playbook_failure_create, self.playbooks_dict)
                final_message.append(
                    f"Playbook {playbook_info} could not be executed for alerts: "
                    f"{sorted(alerts_fail)}.")

        if self.results_summary["failure_set"]:
            for playbook_failure_set, alerts_fail_set in self.results_summary["failure_set"].items():
                playbook_info = get_playbook_info(playbook_failure_set, self.playbooks_dict)
                final_message.append(
                    f"Playbook {playbook_info} "
                    f"was not found for alerts: {sorted(alerts_fail_set)}.")

        if reopened_alerts := self.results_summary["reopened"]:
            final_message.append(f"Alerts {sorted(reopened_alerts)} have been reopened.")

        final_message.extend(self.results_summary["others"])
        demisto.debug('\n'.join(final_message))
        return '\n'.join(final_message)


def get_playbook_info(playbook_id: str, playbook_dict: dict) -> str:
    """
    Retrieves the playbook information based on the provided playbook ID.

    Args:
        playbook_id (str): The playbook ID to look up.
        playbook_dict (dict): A dictionary mapping playbook IDs to their names.

    Returns:
        str: A string containing the playbook name and ID if the ID exists; otherwise, a string with just the ID.
    """
    playbook_name = ""
    if playbook_id in playbook_dict:
        playbook_name = playbook_dict[playbook_id]
    playbook_info = (
        f"{playbook_name} with ID {playbook_id}" if playbook_name else f"with ID {playbook_id}"
    )
    return playbook_info


def get_playbooks_dict() -> dict:
    """
    Fetches the mapping of playbook IDs to names by executing a command to retrieve the data.

    This function stores the mapping in a local dictionary and raises an exception if the response is invalid
    or no playbooks are found.

    Returns:
        dict: A dictionary containing the playbook ID-to-name mapping.

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


def get_playbook_id(playbook_id: str, playbook_name: str, playbooks_dict: dict) -> str:
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


def handle_results(command_results: dict, playbook_id: str, alert_ids: str | list, results_summary: ResultsSummary):
    """
    Processes API call results and updates the results summary with success or failure details.

    Args:
        command_results (dict): The results from the API call, including contents and response details.
        playbook_id (str): The identifier of the playbook associated with the operation.
        alert_ids (str | list): The alert ID(s) being processed.
        results_summary (ResultsSummary): An object for tracking success and failure summaries.

    Returns:
        Returns an error message string if an exception occurs during processing.
    """
    if not command_results:
        return None

    try:
        result_dict = command_results[0].get('Contents', {})
        if isinstance(alert_ids, str):
            if type(result_dict) is str:
                results_summary.update_failure_create(playbook_id, alert_ids)
                return None

            results_summary.update_success(playbook_id, alert_ids)

        elif isinstance(alert_ids, list):
            if "The request requires the right permissions" in command_results[0].get('Contents'):
                return_error("Request Failed: Insufficient permissions. Ensure the API key has the appropriate access rights.")

            result_dict = result_dict.get('response', {})

            if not result_dict:
                results_summary.update_success(playbook_id, alert_ids)
                return None

            failed_ids = list(result_dict.keys())
            succeeded_ids = list(set(alert_ids) - set(failed_ids))

            results_summary.update_failure_create(playbook_id, failed_ids)

            if succeeded_ids:
                results_summary.update_success(playbook_id, succeeded_ids)

    except Exception as e:
        return f"Unexpected error occurred: {str(e)}. Response: {command_results[0]}"


def open_investigation(results_summary: ResultsSummary, alert_ids: list) -> None:
    """
    Reopens investigations for the given alert IDs.

    Args:
        alert_ids (list): List of alert IDs for which the investigations need to be reopened.
    """
    for alert in alert_ids:
        results = demisto.executeCommand("core-api-post", {"uri": "/investigation/:id/reopen", "body": {"id": alert,
                                                                                                        "version": -1}})
        demisto.debug(f"Reopened alert {alert} with the following results: {results}.")

    results_summary.update_reopened(alert_ids)


def set_playbook_on_alerts(playbook_id: str, alert_ids: list, playbooks_dict: dict, results_summary: ResultsSummary,
                           flag_pending_idle: bool):
    """Using an API call, create a new investigation Playbook with a given playbook ID and alerts ID

    Args:
        playbook_id (str): The playbook id to set.
        alert_ids (list): A list of alert Ids. limited to 10 at a time.
        flag_pending_idle (bool): Indicates whether the playbook's status is pending or idle.
                If true, bulk API calls are used; otherwise, an alternative API call is utilized.
    Returns:
        dict: The command results.
    """
    if playbook_id not in playbooks_dict:
        results_summary.update_failure_set(playbook_id, alert_ids)
        return

    demisto.debug(f"Start setting playbook {playbook_id} on alerts {alert_ids}.")
    if flag_pending_idle:
        command_results = demisto.executeCommand(
            "core-api-post", {"uri": "/xsoar/inv-playbook/new", "body":
                              {"playbookId": playbook_id, "alertIds": alert_ids, "version": -1}})

        demisto.debug(f"Results of setting playbook {playbook_id} on alerts {alert_ids}:\n{command_results}")
        handle_results(command_results, playbook_id, alert_ids, results_summary)
    else:
        for alert_id in alert_ids:
            command_result = demisto.executeCommand(
                "core-api-post", {"uri": f"/xsoar/inv-playbook/new/{playbook_id}/{alert_id}"})
            demisto.debug(f"Results of setting playbook {playbook_id} on alert {alert_id}:\n{command_result}")
            handle_results(command_result, playbook_id, alert_id, results_summary)


def split_alert_ids_into_bulks(alert_inv_status: dict[str, list]) -> tuple[list, list, list]:
    """
    Splits alert IDs into bulks based on the maximum allowed size.

    Args:
        alert_inv_status (dict[str, list]): Dictionary containing 'close_ids', 'open_ids', and 'all_ids'.
        max_bulk_size (int): Maximum allowed size for each bulk.

    Returns:
        tuple[list, list, list]: Bulked lists for closed, open, and all alert IDs.
    """
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
    return alert_closed_bulks, alert_open_bulks, alert_all_ids_bulks


def loop_on_alerts(incidents: list[dict], playbook_id: str, limit: int, reopen_closed_inv: bool, playbooks_dict: dict,
                   results_summary: ResultsSummary, flag_pending_idle: bool):
    """
    Loops through alerts, processes them in batches, and assigns a specified playbook to the alerts.
    Optionally reopens closed investigations based on the provided flag.

    Args:
        incidents (list[dict]): The list of incident dictionaries containing alert details.
        playbook_id (str): The playbook ID to be assigned to the alerts.
        limit (int): The maximum number of alerts to process in this run.
        reopen_closed_inv (bool): Flag indicating whether to reopen closed investigations.
        If True, closed alerts will be reopened.
        playbooks_dict (dict): A dictionary mapping playbook IDs to their corresponding playbook names.
        results_summary (ResultsSummary): An object for summarizing the results, including tracking reopened alerts.
        flag_pending_idle (bool): Indicates whether the playbook's status is pending or idle.
    """
    demisto.debug(f"Calling loop_on_alerts with {len(incidents)=}, {playbook_id=}.")
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

    alert_closed_bulks, alert_open_bulks, alert_all_ids_bulks = split_alert_ids_into_bulks(
        alert_inv_status
    )

    demisto.debug(
        f'{MAX_BULK_SIZE_ALLOWED=}, all ids: {len(alert_inv_status["all_ids"])}, closed ids:{len(alert_inv_status["close_ids"])},'
        f' open_ids: {len(alert_inv_status["open_ids"])}')

    if reopen_closed_inv and alert_closed_bulks:
        alert_bulks_to_set = alert_all_ids_bulks
        for bulk in alert_closed_bulks:
            open_investigation(results_summary=results_summary, alert_ids=bulk)

    else:
        alert_bulks_to_set = alert_open_bulks

    for bulk in alert_bulks_to_set:
        set_playbook_on_alerts(
            playbook_id=playbook_id,
            alert_ids=bulk,
            playbooks_dict=playbooks_dict,
            results_summary=results_summary,
            flag_pending_idle=flag_pending_idle
        )


def split_by_playbooks(incidents: list[dict], limit: int, reopen_closed_inv: bool, playbooks_dict: dict,
                       results_summary: ResultsSummary, flag_pending_idle: bool) -> None:
    """
    Groups incidents by their assigned playbook ID and processes each group.
    If an incident does not have an assigned playbook, it is tracked and reported separately.

    Args:
        incidents (list[dict]): The list of incident dictionaries to process.
        limit (int): The maximum number of incidents to process in this run.
        reopen_closed_inv (bool): Flag indicating whether to reopen closed investigations for applicable incidents.
        playbooks_dict (dict): A dictionary mapping playbook IDs to their respective names, used for validation and logging.
        results_summary (ResultsSummary): An object for tracking the processing results, including alerts missing playbooks.
        flag_pending_idle (bool): Indicates whether the playbook's status is pending or idle.
    Raises:
        DemistoException: If a required attribute is missing in an incident or if processing fails.
    """
    demisto.debug("Split by playbooks.")
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

    if missing_playbook_alerts:
        results_summary.append_to_others(f"Could not find an attached playbook for alerts: {missing_playbook_alerts}.")

    for playbook_id, playbook_incidents in playbook_map.items():
        loop_on_alerts(playbook_incidents, playbook_id, limit, reopen_closed_inv,
                       playbooks_dict, results_summary, flag_pending_idle)


def main():
    try:
        args = demisto.args()
        original_query = args.get("query", "runStatus:Pending")
        # Filters incidents to retrieve only open ones when the client chooses not to reopen closed investigations.
        if not argToBoolean(args.get("reopen_closed_inv")):
            updated_query = f"-status:closed AND {original_query}"
            args.update({"query": updated_query})

        if from_date := arg_to_datetime(args.get("fromDate")):
            demisto.debug(f"Fetching alerts {from_date=}")

        incidents: list[dict] = get_incidents_by_query(args)
        if not incidents:
            return return_results("No alerts were found for the provided query and filter arguments.")

        limit = int(args.get("limit", "500"))
        incidents_ids = [incident.get("id") for incident in incidents]
        demisto.debug(f"Found the following incidents: {incidents_ids}")
        reopen_closed_inv = argToBoolean(args.get("reopen_closed_inv"))
        playbook_id = args.get("playbook_id", "")
        playbook_name = args.get("playbook_name", "")
        playbooks_dict = get_playbooks_dict()
        if playbook_id or playbook_name:
            playbook_id = get_playbook_id(playbook_id, playbook_name, playbooks_dict)

        flag_pending_idle = False
        if "pending" in original_query or "idle" in original_query:
            demisto.debug("The query includes runStatus of pending or idle. Setting flag_pending_idle true.")
            flag_pending_idle = True

        results_summary = ResultsSummary(playbooks_dict)
        if not playbook_id:
            split_by_playbooks(incidents, limit, reopen_closed_inv, playbooks_dict, results_summary, flag_pending_idle)
        else:
            loop_on_alerts(incidents, playbook_id, limit, reopen_closed_inv, playbooks_dict, results_summary, flag_pending_idle)

        results_message = results_summary.generate_summary()
        script_results = CommandResults(
            outputs_prefix="ReopenedAlerts.IDs",
            outputs=results_summary.results_summary["reopened"],
            readable_output=results_message
        )
        return_results(script_results)

    except Exception as e:
        return_error(str(e))


if __name__ in ["builtins", "__main__"]:
    main()
