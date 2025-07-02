import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *

from typing import Any


""" STANDALONE FUNCTION """


def get_playbook_tasks(tasks: list) -> list:
    """Get the tasks of a playbook recursively

    Args:
        tasks (list): the tasks of the playbook

    Returns:
        list: the tasks fo the playbook including all sub-playbook tasks
    """
    ready_tasks = []
    for task in tasks:
        if task.get("type") == "playbook" and task.get("subPlaybook"):
            sub_playbook_tasks = task.get("subPlaybook", {}).get("tasks", {}).values()
            ready_tasks.extend(get_playbook_tasks(list(sub_playbook_tasks)))
        ready_tasks.append(task)

    return ready_tasks


def get_ask_tasks(inc_id: str) -> List[dict]:
    """_summary_

    Args:
        inc_id (str): the id of the incident to fetch the tasks

    Returns:
        List[dict]: List of ask tasks from the given incident
    """
    res = demisto.executeCommand("core-api-get", {"uri": f"/investigation/{inc_id}/workplan"})
    if not res:
        raise DemistoException(f"No work plan found for the incident with id: {inc_id}")
    if isError(res[0]):
        raise DemistoException(f"Error occurred while fetching work plan for incident with id: {inc_id}. Error: {res}")
    tasks: list = list(dict_safe_get(res[0], ["Contents", "response", "invPlaybook", "tasks"], {}).values())
    if tasks:
        tasks = get_playbook_tasks(tasks)

    ask_tasks = []
    for task in tasks:
        if task.get("type") == "condition":
            options = dict_safe_get(task, ["message", "replyOptions"])
            if not options:
                continue

            ask_task = {
                "id": task.get("id"),
                "options": options,
                "name": dict_safe_get(task, ["task", "name"], ""),
                "state": task.get("state"),
            }
            ask_tasks.append(ask_task)

    return ask_tasks


def encode(value: str) -> str:
    """Returns the input value encoded as a HEX representation of the Base64 Encoded string bytes
    :type value: ``str``
    :param value: string to encoded
    :return: value encoded in Hex Representation of the Base64 bytes
    :rtype: ``str``
    """
    b64 = base64.b64encode(bytes(value, "utf-8"))
    return b64.hex()


def generate_ask_link(server: str, task_id: int, investigation_id: str, email: str, option: str) -> dict[str, Any]:
    """Returns a dictionary with information about the generated link"""
    inv_task = encode(f"{investigation_id}@{task_id}")
    link = urljoin(server, f"/#/external/ask/{inv_task}/{encode(email)}/{encode(option)}")
    return {"link": link, "option": option, "taskID": task_id}


""" COMMAND FUNCTION """


def get_ask_links_command(args: dict[str, Any]) -> CommandResults:
    """_summary_

    Args:
        args (dict[str, Any]): The arguments given to the command

    Raises:
        ValueError: No matching task found for the given name

    Returns:
        CommandResults: command result for the given task
    """
    server = demisto.demistoUrls().get("server", "")
    email: str = "ask@xsoar"
    investigation = args.get("inc_id", demisto.investigation()["id"])
    name = args["task_name"]  # pylint: disable=W9019

    available_tasks = get_ask_tasks(investigation)
    matching_task = None
    for t in available_tasks:
        if t["name"] == name:
            matching_task = t
            break

    if not matching_task:
        raise ValueError(f'no matching Ask task found for "{name}"')

    options = matching_task["options"]
    links = []
    for option in options:
        link = generate_ask_link(server, matching_task["id"], investigation, email, option)
        link["taskName"] = name
        links.append(link)

    return CommandResults(
        outputs_prefix="Ask.Links",
        outputs_key_field=["option", "taskID"],
        outputs=links,
        ignore_auto_extract=True,
        readable_output=tableToMarkdown(
            f'External ask links for task "{matching_task["name"]}" in investigation {investigation}',
            t=links,
            headers=["link", "option", "taskID"],
        ),
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(get_ask_links_command(demisto.args()))
    except Exception as ex:
        return_error(f"Failed to execute GenerateAskLink. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
