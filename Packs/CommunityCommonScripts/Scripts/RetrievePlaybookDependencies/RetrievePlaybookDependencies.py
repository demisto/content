import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any
import traceback
import re
from json import dumps

""" STANDALONE FUNCTION """


def perform_rest_call(method: str, endpoint: str, body=None):
    """
    Perform a REST Call
    :param endpoint:
    :param body: `dict` representing the HTTP body
    :param method: `get` or `post`
    :return: The contents from the API Call
    """
    args = {
        "uri": endpoint,
    }
    if body:
        args["body"] = dumps(body)

    result = demisto.executeCommand(f"core-api-{method}", args)
    if len(result) < 1 or "Contents" not in result[0] or "response" not in result[0].get("Contents"):
        raise Exception(f"Error with REST call to endpoint {endpoint}")

    return result[0]["Contents"]["response"]


def get_tasks_list(tasks):
    # {'1':{'id': '1'}, ...} -> [{'id':'1'}, ...]
    tasks_list = []
    for task_number in tasks:
        tasks_list.append(tasks[task_number])
    return tasks_list


def append_commands(commands, subplaybook_name, subplaybook_json):
    for t in get_tasks_list(subplaybook_json):
        # commands not using-brand
        task = t.get("task", {})
        if task.get("isCommand") and task.get("scriptId", "").startswith("|"):
            key = task.get("scriptId", "").replace("|||", "")
            # These are base commands and should be excluded from brandless list
            if key not in ["domain", "file", "ip", "url"]:
                if key in commands:
                    if subplaybook_name not in commands[key]:
                        commands[key].append(subplaybook_name)
                else:
                    commands.update({key: [subplaybook_name]})
    return commands


def append_to_playbooks_and_integrations(playbooks, integrations, script_ids, commands, playbook_json):
    playbook_name = playbook_json.get("name")
    if playbook_name and playbook_name not in playbooks:
        playbooks.append(playbook_name)
    for b in argToList(playbook_json.get("brands")):
        if b and b != "Builtin" and b not in integrations:
            integrations.append(b)
    for script_id in playbook_json.get("scriptIds"):
        script_ids.append(script_id)
    commands = append_commands(commands, playbook_name, playbook_json.get("tasks"))

    return playbooks, integrations, script_ids, commands


def get_subplaybook_tasks(playbooks, integrations, script_ids, commands, lists, task):
    # recursively go through all subplaybook tasks and append to playbooks and integrations
    _task = task.get("task", {})
    try:
        subplaybook_json = perform_rest_call("get", f"playbook/{_task.get('playbookId')}")
    except Exception:
        raise Exception(f"Playbook {_task.get('name')} not found")
    playbooks, integrations, script_ids, commands = append_to_playbooks_and_integrations(
        playbooks, integrations, script_ids, commands, subplaybook_json
    )
    for t in get_tasks_list(subplaybook_json.get("tasks")):
        if t.get("type") == "regular":
            lists = get_xsoar_list_name(t, lists)
        elif t.get("type") == "playbook" and t.get("task", {}).get("playbookId"):
            # playbookId does not exist if the playbook the task references is missing
            playbooks, integrations, script_ids, commands, lists = get_subplaybook_tasks(
                playbooks, integrations, script_ids, commands, lists, t
            )
    return playbooks, integrations, script_ids, commands, lists


def create_markdown_list(
    incident_types,
    layouts,
    incident_fields,
    indicator_fields,
    jobs,
    lists,
    mappers,
    pre_process_rules,
    scripts,
    integrations,
    playbooks,
    parent_playbook,
):
    markdown_string = "## XSOAR Objects\n"
    markdown_string += (
        "* Incident Types\n  * None\n"
        if len(incident_types) == 0
        else "* Incident Types\n  * " + "\n  * ".join(incident_types) + "\n"
    )
    markdown_string += "* Layouts\n  * None\n" if len(layouts) == 0 else "* Layouts\n  * " + "\n  * ".join(layouts) + "\n"
    markdown_string += (
        "* Incident Fields\n  * None\n"
        if len(incident_fields) == 0
        else "* Incident Fields\n  * " + "\n  * ".join(incident_fields) + "\n"
    )
    markdown_string += (
        "* Indicator Fields\n  * None\n"
        if len(indicator_fields) == 0
        else "* Indicator Fields\n  * " + "\n  * ".join(indicator_fields) + "\n"
    )
    markdown_string += "* Jobs\n  * None\n" if len(jobs) == 0 else "* Jobs\n  * " + "\n  * ".join(jobs) + "\n"
    markdown_string += "* Lists\n  * None\n" if len(lists) == 0 else "* Lists\n  * " + "\n  * ".join(lists) + "\n"
    markdown_string += "* Mappers\n  * None\n" if len(mappers) == 0 else "* Mappers\n  * " + "\n  * ".join(mappers) + "\n"
    markdown_string += (
        "* Pre-Process Rules\n  * None\n"
        if len(pre_process_rules) == 0
        else "* Pre-Process Rules\n  * " + "\n  * ".join(pre_process_rules) + "\n"
    )
    markdown_string += "* Parent Playbook: " + parent_playbook + "\n"
    markdown_string += (
        "* Custom Automations\n  * None\n" if len(scripts) == 0 else "* Custom Automations\n  * " + "\n  * ".join(scripts) + "\n"
    )
    markdown_string += (
        "* Integrations\n  * None\n" if len(integrations) == 0 else "* Integrations\n  * " + "\n  * ".join(integrations) + "\n"
    )
    markdown_string += "* Playbooks\n  * None\n" if len(playbooks) == 0 else "* Playbooks\n  * " + "\n  * ".join(playbooks) + "\n"
    return markdown_string


def create_html_list(
    incident_types,
    layouts,
    incident_fields,
    indicator_fields,
    jobs,
    lists,
    mappers,
    pre_process_rules,
    scripts,
    integrations,
    playbooks,
    parent_playbook,
):
    html_string = "<h2>XSOAR Objects</h2><ul>"
    html_string += (
        "<li>Incident Types</li><ul><li>None</li></ul>"
        if len(incident_types) == 0
        else "<li>Incident Types</li><ul><li>" + "</li><li>".join(incident_types) + "</li></ul>"
    )
    html_string += (
        "<li>Layouts</li><ul><li>None</li></ul>"
        if len(layouts) == 0
        else "<li>Layouts</li><ul><li>" + "</li><li>".join(layouts) + "</li></ul>"
    )
    html_string += (
        "<li>Incident Fields</li><ul><li>None</li></ul>"
        if len(incident_fields) == 0
        else "<li>Incident Fields</li><ul><li>" + "</li><li>".join(incident_fields) + "</li></ul>"
    )
    html_string += (
        "<li>Indicator Fields</li><ul><li>None</li></ul>"
        if len(indicator_fields) == 0
        else "<li>Indicator Fields</li><ul><li>" + "</li><li>".join(indicator_fields) + "</li></ul>"
    )
    html_string += (
        "<li>Jobs</li><ul><li>None</li></ul>"
        if len(jobs) == 0
        else "<li>Jobs</li><ul><li>" + "</li><li>".join(jobs) + "</li></ul>"
    )
    html_string += (
        "<li>Lists</li><ul><li>None</li></ul>"
        if len(lists) == 0
        else "<li>Lists</li><ul><li>" + "</li><li>".join(lists) + "</li></ul>"
    )
    html_string += (
        "<li>Mappers</li><ul><li>None</li></ul>"
        if len(mappers) == 0
        else "<li>Mappers</li><ul><li>" + "</li><li>".join(mappers) + "</li></ul>"
    )
    html_string += (
        "<li>Pre-Process Rules</li><ul><li>None</li></ul>"
        if len(pre_process_rules) == 0
        else "<li>Pre-Process Rules</li><ul><li>" + "</li><li>".join(pre_process_rules) + "</li></ul>"
    )
    html_string += "<li>Parent Playbook: " + parent_playbook + "</li>"
    html_string += (
        "<li>Custom Automations</li><ul><li>None</li></ul>"
        if len(scripts) == 0
        else "<li>Custom Automations</li><ul><li>" + "</li><li>".join(scripts) + "</li></ul>"
    )
    html_string += (
        "<li>Integrations</li><ul><li>None</li></ul>"
        if len(integrations) == 0
        else "<li>Integrations</li><ul><li>" + "</li><li>".join(integrations) + "</li></ul>"
    )
    html_string += (
        "<li>Playbooks</li><ul><li>None</li></ul>"
        if len(playbooks) == 0
        else "<li>Playbooks</li><ul><li>" + "</li><li>".join(playbooks) + "</li></ul></ul>"
    )
    return html_string


def get_xsoar_list_name(task, lists):
    # Search for lists in tasks
    if "scriptArguments" in task:
        script_arguments = task.get("scriptArguments")
        # Check if the complex argument is a list
        try:
            if (
                script_arguments["value"]["complex"]["accessor"] not in lists
                and script_arguments["value"]["complex"]["root"] == "lists"
            ):
                lists.append(script_arguments["value"]["complex"]["accessor"])
        except KeyError:
            pass
        r = re.findall(r"['\{]lists\.(.*?)?[.'\}]", str(script_arguments))
        if r:
            for list_name in r:
                if list_name not in lists:
                    lists.append(list_name)
    return lists


""" COMMAND FUNCTION """


def retrieve_playbook_dependencies(args: dict[str, Any]) -> CommandResults:
    playbooks: list[str] = []
    integrations: list[str] = []
    script_ids: list[str] = []
    commands: dict[str, Any] = {}  # commands not using brand
    lists: list[str] = []  # XSOAR List names

    parent_playbook = args.get("playbook_name") or ""
    # Call parent playbook's data, then recursivley call all subplaybooks' data
    playbooks_json = perform_rest_call("post", "playbook/search", {"query": f'''name:"{parent_playbook}"'''})

    match_found = False
    if playbooks_json.get("playbooks"):
        for playbook_json in playbooks_json.get("playbooks"):
            if playbook_json.get("name") == parent_playbook:
                match_found = True
                break
    if not match_found:
        raise Exception(f"""Playbook '{parent_playbook}' not found""")

    playbooks, integrations, script_ids, commands = append_to_playbooks_and_integrations(
        playbooks, integrations, script_ids, commands, playbook_json
    )

    for task in get_tasks_list(playbook_json.get("tasks")):
        if task.get("type") == "regular":
            lists = get_xsoar_list_name(task, lists)
        elif task.get("type") == "playbook":
            playbooks, integrations, script_ids, commands, lists = get_subplaybook_tasks(
                playbooks, integrations, script_ids, commands, lists, task
            )

    # Sort scripts into base scripts and custom scripts, and get the displayname for custom scripts
    script_ids = list(set(script_ids))
    custom_scripts: list[str] = []
    base_scripts: list[str] = []
    for script_id in script_ids:
        if "-" in script_id:
            custom_scripts.append(perform_rest_call("post", f"automation/load/{script_id}").get("name"))
        else:
            base_scripts.append(perform_rest_call("post", f"automation/load/{script_id}").get("name"))

    # Dedup
    integrations = list(set(integrations))
    playbooks = list(set(playbooks))

    # Format results for output
    base_scripts.sort()
    custom_scripts.sort()
    integrations.sort()
    lists.sort()
    playbooks.sort()

    # Sort, format and display brandless commands' possible integrations and the playbooks they were located in
    if len(commands) > 0:
        integration_result = perform_rest_call("get", "settings/integration-commands")
        integration_commands: dict[str, list[str]] = {}
        # Find the integrations connected to brand-less commands
        for integration in integration_result:
            for command in integration.get("commands", []):
                if command.get("name") and command.get("name") in commands:
                    integration_commands.setdefault(integration.get("display"), []).append(command.get("name"))
        if len(integration_commands) > 0:
            # Format into markdown table displaying integration, command, and playbook it was found in
            integration_commands_str = "## Warning\n\n"
            integration_commands_str += "Commands found with no clear integration connected to them. "
            integration_commands_str += "These integrations have been included in the main markdown list uncritically, "
            integration_commands_str += "but are listed below in case revisions are needed:\n"
            integration_commands_str += "Recommended Action: Locate command calls in playbooks and confirm tasks are using "
            integration_commands_str += "branded commands. EXAMPLE:\n\n"
            integration_commands_str += "  UNBRANDED:  'command_name'\n  BRANDED:    'command_name (Integration Name)'\n"

            integration_commands_str += "| Integration | Brandless Command | Located in Playbook(s) |\n"
            integration_commands_str += "|---|---|---|"

            for key in integration_commands:
                integrations.append(key)
                for command in integration_commands.get(key, []):
                    command_playbooks = (", ").join(commands.get(command))
                    integration_commands_str += f"\n| {key} | {command} | {command_playbooks} |"

            return_results(CommandResults(readable_output=integration_commands_str))

    # Create final markdown and html for documentation
    # Possible opportunities for automating these as well
    incident_types = argToList(args.get("incident_types")) if args.get("incident_types") else []
    layouts = argToList(args.get("layouts")) if args.get("layouts") else []
    incident_fields = argToList(args.get("incident_fields")) if args.get("incident_fields") else []
    indicator_fields = argToList(args.get("indicator_fields")) if args.get("indicator_fields") else []
    jobs = argToList(args.get("jobs")) if args.get("jobs") else []
    mappers = argToList(args.get("mappers")) if args.get("mappers") else []
    pre_process_rules = argToList(args.get("pre_process_rules")) if args.get("pre_process_rules") else []

    markdown_string = create_markdown_list(
        incident_types,
        layouts,
        incident_fields,
        indicator_fields,
        jobs,
        lists,
        mappers,
        pre_process_rules,
        custom_scripts,
        integrations,
        playbooks,
        parent_playbook,
    )
    if args.get("Markdown") == "true":
        demisto.results(markdown_string)
    html_string = create_html_list(
        incident_types,
        layouts,
        incident_fields,
        indicator_fields,
        jobs,
        lists,
        mappers,
        pre_process_rules,
        custom_scripts,
        integrations,
        playbooks,
        parent_playbook,
    )
    if args.get("HTML") == "true":
        demisto.results(html_string)

    dependencies = {
        "Parent Playbook": args.get("playbook_name"),
        "Playbooks": playbooks,
        "Integrations": integrations,
        "Automations": {"CustomScripts": custom_scripts, "BaseScripts": base_scripts},
        "Commands": commands,
        "Lists": lists,
        "MarkdownString": markdown_string,
        "HTMLString": html_string,
    }

    parent_playbook = parent_playbook.replace(" ", "_")

    outputs = {f"{parent_playbook}": dependencies}

    return CommandResults(
        readable_output=f'''Retrieved Dependencies for Playbook "{parent_playbook}"''',
        outputs_prefix="RetrievePlaybookDependencies",
        outputs_key_field="",
        outputs=outputs,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(retrieve_playbook_dependencies(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute RetrievePlaybookDependencies. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
