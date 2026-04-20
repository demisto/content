import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


DEFAULT_MAX_ALERTS = 500
DEFAULT_GROUP_SIZE = 10
DEFAULT_SLEEP_TIME = 10
PAGE_SIZE = 100


def get_alerts_with_errors(max_alerts: int) -> list[dict]:
    """
    Queries all non-closed alerts and returns them.

    Args:
        max_alerts: Maximum number of alerts to retrieve.

    Returns:
        A list of alert/incident dictionaries.
    """
    demisto.debug(f"Querying up to {max_alerts} non-closed alerts.")
    result = demisto.executeCommand(
        "getIncidents",
        {
            "query": "-status:closed",
            "size": max_alerts,
        },
    )

    if is_error(result):
        raise DemistoException(f"Failed to query alerts: {get_error(result)}")

    incidents_data = result[0].get("Contents", {}).get("data")
    alerts = incidents_data if incidents_data else []
    demisto.debug(f"Found {len(alerts)} non-closed alerts.")
    return alerts


def get_failed_tasks_for_alert(alert_id: str) -> list[dict]:
    """
    Retrieves all tasks in Error state for a given alert by fetching the full playbook
    via GET inv-playbook/{id} and filtering tasks client-side.

    Falls back to core-api-get if internalHttpRequest is not available.

    Args:
        alert_id: The alert/incident ID.

    Returns:
        A list of failed task dictionaries.
    """
    allowed_types = {"regular", "condition", "collection"}
    uri = f"inv-playbook/{alert_id}"

    try:
        response = demisto.internalHttpRequest(
            method="GET",
            uri=uri,
        )

        if response and response.get("statusCode") == 200:
            playbook = json.loads(response.get("body", "{}"))
            return _extract_failed_tasks(playbook, allowed_types)

        demisto.debug(f"Internal HTTP request failed for alert {alert_id}: {response}")
        return []

    except (ValueError, Exception) as e:
        demisto.debug(f"Internal HTTP request not available for alert {alert_id}: {e}. Falling back to core-api-get.")
        return get_failed_tasks_via_api(alert_id, allowed_types)


def get_failed_tasks_via_api(alert_id: str, allowed_types: set[str]) -> list[dict]:
    """
    Retrieves failed tasks using core-api-get as a fallback.

    Args:
        alert_id: The alert/incident ID.
        allowed_types: Set of allowed task types to include.

    Returns:
        A list of failed task dictionaries.
    """
    uri = f"inv-playbook/{alert_id}"
    response = demisto.executeCommand(
        "core-api-get",
        {"uri": uri},
    )

    if is_error(response):
        demisto.debug(f"Failed to get playbook for alert {alert_id}: {get_error(response)}")
        return []

    playbook = response[0].get("Contents", {}).get("response", {})
    return _extract_failed_tasks(playbook, allowed_types)


def _extract_failed_tasks(playbook: dict, allowed_types: set[str]) -> list[dict]:
    """
    Extracts tasks in Error state from a playbook object.

    Args:
        playbook: The full playbook dictionary returned by inv-playbook/{id}.
        allowed_types: Set of task types to include (e.g., {"regular", "condition", "collection"}).

    Returns:
        A filtered list of failed task dictionaries.
    """
    if not playbook or not isinstance(playbook, dict):
        return []

    tasks = playbook.get("tasks", {})
    if not isinstance(tasks, dict):
        return []

    failed_tasks = [
        task_data for task_data in tasks.values() if task_data.get("state") == "Error" and task_data.get("type") in allowed_types
    ]

    return filter_playbook_failures(failed_tasks) if failed_tasks else []


def filter_playbook_failures(response: list) -> list:
    """
    Filters out tasks of type 'playbook' from the response if their name appears
    in the ancestors of any other task in the list. This prevents duplicate errors
    when the real failure is in an internal task of the playbook.

    Args:
        response: List of failure tasks.

    Returns:
        The filtered list of tasks.
    """
    ancestors = set()
    for task in response:
        ancestors.update(task.get("ancestors", []))

    filtered_response = [
        task for task in response if not (task.get("type") == "playbook" and task.get("task", {}).get("name") in ancestors)
    ]
    return filtered_response


def restart_task(task_id: str, incident_id: str) -> dict:
    """
    Reopens a failed task and re-executes it.

    Args:
        task_id: The task ID to restart.
        incident_id: The incident/alert ID containing the task.

    Returns:
        A dict with the result: {"success": True/False, "error": "..."}.
    """
    # Step 1: Reopen the task
    reopen_result = demisto.executeCommand("taskReopen", {"id": task_id, "incidentId": incident_id})
    if is_error(reopen_result):
        error_msg = get_error(reopen_result)
        demisto.debug(f"Failed to reopen task {task_id} on alert {incident_id}: {error_msg}")
        return {"success": False, "error": f"Failed to reopen: {error_msg}"}

    # Step 2: Re-execute the task
    body: dict = {"invId": incident_id, "inTaskID": task_id}

    if is_demisto_version_ge("6.2"):
        body = {"taskinfo": body}

    try:
        response = demisto.internalHttpRequest(
            method="POST",
            uri="inv-playbook/task/execute",
            body=json.dumps(body),
        )

        if response and response.get("statusCode") == 200:
            demisto.debug(f"Successfully restarted task {task_id} on alert {incident_id}.")
            return {"success": True, "error": ""}

        error_msg = f"Status {response.get('statusCode')}: {response.get('body', '')}"
        demisto.debug(f"Failed to execute task {task_id} on alert {incident_id}: {error_msg}")
        return {"success": False, "error": f"Failed to execute: {error_msg}"}

    except Exception as e:
        demisto.debug(f"internalHttpRequest failed for task {task_id} on alert {incident_id}: {e}")
        return {"success": False, "error": f"Failed to execute: {e}"}


def restart_all_failed_tasks(
    alerts: list[dict],
    group_size: int,
    sleep_time: int,
) -> tuple[list[dict], list[dict]]:
    """
    Iterates over all alerts, finds failed tasks, and restarts them with throttling.

    Args:
        alerts: List of alert/incident dictionaries.
        group_size: Number of tasks to restart before sleeping.
        sleep_time: Seconds to sleep between groups.

    Returns:
        A tuple of (restarted_tasks, failed_to_restart) lists.
    """
    restarted_tasks = []
    failed_to_restart = []
    total_restarted = 0

    for alert in alerts:
        alert_id = str(alert.get("id", ""))
        if not alert_id:
            continue

        failed_tasks = get_failed_tasks_for_alert(alert_id)
        if not failed_tasks:
            continue

        demisto.debug(f"Found {len(failed_tasks)} failed tasks for alert {alert_id}.")

        for task in failed_tasks:
            task_id = task.get("id", "")
            task_name = task.get("task", {}).get("name", "Unknown")
            playbook_name = task.get("ancestors", [""])[0] if task.get("ancestors") else ""

            if not task_id:
                continue

            demisto.info(f"Restarting task '{task_name}' (ID: {task_id}) on alert {alert_id}")
            result = restart_task(task_id, alert_id)

            if result["success"]:
                restarted_tasks.append(
                    {
                        "IncidentID": alert_id,
                        "TaskID": task_id,
                        "TaskName": task_name,
                        "PlaybookName": playbook_name,
                    }
                )
            else:
                failed_to_restart.append(
                    {
                        "IncidentID": alert_id,
                        "TaskID": task_id,
                        "TaskName": task_name,
                        "PlaybookName": playbook_name,
                        "Error": result["error"],
                    }
                )

            total_restarted += 1

            # Throttle: sleep after every group_size tasks
            if total_restarted % group_size == 0:
                demisto.debug(f"Reached group size {group_size}, sleeping for {sleep_time} seconds.")
                time.sleep(sleep_time)  # pylint: disable=E9003

    return restarted_tasks, failed_to_restart


def main() -> None:
    try:
        args = demisto.args()
        max_alerts = int(args.get("max_alerts", DEFAULT_MAX_ALERTS))
        group_size = int(args.get("group_size", DEFAULT_GROUP_SIZE))
        sleep_time = int(args.get("sleep_time", DEFAULT_SLEEP_TIME))

        if group_size < 1:
            raise DemistoException("The group_size argument must be 1 or higher.")

        # Step 1: Get all non-closed alerts
        alerts = get_alerts_with_errors(max_alerts)
        if not alerts:
            return return_results("No non-closed alerts were found.")

        # Step 2: Restart all failed tasks across all alerts
        restarted_tasks, failed_to_restart = restart_all_failed_tasks(alerts, group_size, sleep_time)

        if not restarted_tasks and not failed_to_restart:
            return return_results("No failed tasks were found across the queried alerts.")

        # Step 3: Build output
        readable_parts = []

        if restarted_tasks:
            readable_parts.append(
                tableToMarkdown(
                    f"Successfully Restarted Tasks ({len(restarted_tasks)})",
                    restarted_tasks,
                    headers=["IncidentID", "PlaybookName", "TaskName", "TaskID"],
                    headerTransform=pascalToSpace,
                )
            )

        if failed_to_restart:
            readable_parts.append(
                tableToMarkdown(
                    f"Failed to Restart Tasks ({len(failed_to_restart)})",
                    failed_to_restart,
                    headers=["IncidentID", "PlaybookName", "TaskName", "TaskID", "Error"],
                    headerTransform=pascalToSpace,
                )
            )

        readable_output = "\n".join(readable_parts)

        outputs = {
            "TotalRestarted": len(restarted_tasks),
            "TotalFailed": len(failed_to_restart),
            "TotalAlerts": len(alerts),
            "RestartedTask": restarted_tasks,
            "FailedToRestart": failed_to_restart,
        }

        return_results(
            CommandResults(
                outputs_prefix="TroubleshootRestartFailedPlaybooks",
                outputs=outputs,
                readable_output=readable_output,
            )
        )

    except Exception as e:
        return_error(f"Failed to restart failed playbooks: {e}")


if __name__ in ["builtins", "__main__"]:
    main()
