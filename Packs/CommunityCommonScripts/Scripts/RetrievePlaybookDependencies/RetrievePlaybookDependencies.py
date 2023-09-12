import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import List, Dict, Any
import traceback
import re
from json import dumps


''' STANDALONE FUNCTION '''


def perform_rest_call(method: str, endpoint: str, body=None):
    """
    Perform a REST Call
    :param endpoint:
    :param body: `dict` representing the HTTP body
    :param method: `get` or `post`
    :return: The contents from the API Call
    """
    args = {
        'uri': endpoint,
    }
    if body:
        args['body'] = dumps(body)

    result = demisto.executeCommand(f"demisto-api-{method}", args)
    if len(result) < 1 or 'Contents' not in result[0] or 'response' not in result[0].get('Contents'):
        raise Exception(f"Error with REST call to endpoint {endpoint}")

    return result[0]['Contents']['response']


def get_tasks_list(tasks):
    # {'1':{'id': '1'}, ...} -> [{'id':'1'}, ...]
    tasks_list = []
    for task_number in tasks.keys():
        tasks_list.append(tasks[task_number])
    return tasks_list


def append_commands(commands, subplaybook_name, subplaybook_json):
    for t in get_tasks_list(subplaybook_json):
        # commands not using-brand
        if t['task'].get('isCommand') and t['task']['scriptId'].startswith('|'):
            key = t['task']['scriptId'].replace('|||', '')
            # These are base commands and should be excluded from brandless list
            if key not in ["domain", "file", "ip", "url"]:
                if key in commands.keys():
                    if subplaybook_name not in commands[key]:
                        commands[key].append(subplaybook_name)
                else:
                    commands.update({
                        key: [subplaybook_name]
                    })
    return commands


def append_to_playbooks_and_integrations(playbooks, integrations, script_ids, commands, playbook_json):
    if playbook_json['name'] not in playbooks:
        playbooks.append(playbook_json['name'])
    for b in argToList(playbook_json['brands']):
        if b and b != 'Builtin' and b not in integrations:
            integrations.append(b)
    for script_id in playbook_json['scriptIds']:
        script_ids.append(script_id)
    commands = append_commands(commands, playbook_json['name'], playbook_json['tasks'])

    return playbooks, integrations, script_ids, commands


def get_subplaybook_tasks(playbooks, integrations, script_ids, commands, lists, task):
    # recursively go through all subplaybook tasks and append to playbooks and integrations
    try:
        subplaybook_json = perform_rest_call('get', f"playbook/{task['task']['playbookId']}")
    except:
        raise Exception(f"Playbook {task['task']['name']} not found")
    playbooks, integrations, script_ids, commands = append_to_playbooks_and_integrations(
        playbooks, integrations, script_ids, commands, subplaybook_json)
    for t in get_tasks_list(subplaybook_json['tasks']):
        if t['type'] == 'regular':
            lists.extend(get_xsoar_list_name(task))
        elif t['type'] == 'playbook' and t['task'].get('playbookId'):
            # playbookId does not exist if the playbook the task references is missing
            playbooks, integrations, script_ids, commands, lists = get_subplaybook_tasks(
                playbooks, integrations, script_ids, commands, lists, t)
    return playbooks, integrations, script_ids, commands, lists


def create_markdown_list(lists, scripts, integrations, playbooks, parent_playbook):
    markdown_lists = '* Lists\n  * None\n' if len(lists) == 0 else '* Lists\n  * ' + '\n  * '.join(lists) + '\n'
    markdown_automations = '* Automations\n  * None\n' if len(
        scripts) == 0 else '* Automations\n  * ' + '\n  * '.join(scripts) + '\n'
    markdown_integrations = '* Integrations\n  * None\n' if len(
        integrations) == 0 else '* Integrations\n  * ' + '\n  * '.join(integrations) + '\n'
    markdown_playbooks = '* Playbooks\n  * None\n' if len(playbooks) == 0 else '* Playbooks\n  * ' + \
        '\n  * '.join(playbooks) + '\n'

    markdown_string = 'Markdown List Generated: \n\n## XSOAR Objects\n* Incident Types\n  *\n* Layouts\n  *\n* Incident Fields\n  *\n* Indicator Fields\n  *\n* Jobs\n  *\n' + \
        markdown_lists + '* Mappers\n  *\n* Pre-Process Rules\n  *\n' + '* Parent Playbook: ' + \
        parent_playbook + '\n' + markdown_automations + markdown_integrations + markdown_playbooks

    return markdown_string


def get_xsoar_list_name(task):
    # Search for lists in tasks
    if 'scriptArguments' in task.keys():
        r = re.search(r'\${lists\.(.*?)(\..*?)?}', str(task['scriptArguments']))
        if r:
            xsoar_list_name = r.group(1)
            return [xsoar_list_name]
    return []


''' COMMAND FUNCTION '''


def retrieve_playbooks_and_integrations(args: Dict[str, Any]) -> CommandResults:
    playbooks: List[str] = []
    integrations: List[str] = []
    script_ids: List[str] = []
    commands = Dict[str, Any]   # commands not using brand
    lists: List[str] = []       # XSOAR List names

    # Call parent playbook's data, then recursivley call all subplaybooks' data
    playbooks_json = perform_rest_call('post', 'playbook/search', {'query': f'''name:"{args['playbook_name']}"'''})

    match_found = False
    if playbooks_json['playbooks']:
        for playbook_json in playbooks_json['playbooks']:
            if playbook_json['name'] == args['playbook_name']:
                match_found = True
                break
    if not match_found:
        raise Exception(f'''Playbook '{args["playbook_name"]}' not found''')

    playbooks, integrations, script_ids, commands = append_to_playbooks_and_integrations(
        playbooks, integrations, script_ids, commands, playbook_json)

    lists = []
    for task in get_tasks_list(playbook_json['tasks']):
        if task['type'] == 'regular':
            lists.extend(get_xsoar_list_name(task))
        elif task['type'] == 'playbook':
            playbooks, integrations, script_ids, commands, lists = get_subplaybook_tasks(
                playbooks, integrations, script_ids, commands, lists, task)

    # Sort scripts into base scripts and custom scripts, and get the displayname for custom scripts
    script_ids = list(set(script_ids))
    custom_scripts: List[str] = []
    base_scripts: List[str] = []
    for script_id in script_ids:
        if '-' in script_id:
            custom_scripts.append(perform_rest_call('post', f'automation/load/{script_id}')['name'])
        else:
            base_scripts.append(perform_rest_call('post', f'automation/load/{script_id}')['name'])

    # Sort, format and display brandless commands' possible integrations and the playbooks they were located in
    if len(commands) > 0:
        integration_result = perform_rest_call('get', "settings/integration-commands")
        integration_commands = {}
        # Find the integrations connected to brand-less commands
        for integration in integration_result:
            for command in integration.get('commands', []):
                if command['name'] in commands.keys():
                    integration_commands.setdefault(integration['display'], []).append(command['name'])

        # Format into markdown table displaying integration, command, and playbook it was found in
        integration_commands_str = '## Warning\n\n'
        integration_commands_str += 'Commands found with no clear integration connected to them. These integrations have been included in the main markdown list uncritically, but are listed below in case revisions are needed:\n'
        integration_commands_str += 'Recommended Action: Locate command calls in playbooks and confirm tasks are using branded commands. EXAMPLE:\n\n'
        integration_commands_str += "  UNBRANDED:  'command_name'\n  BRANDED:    'command_name (Integration Name)'\n"

        integration_commands_str += '| Integration | Brandless Command | Located in Playbook(s) |\n|---|---|---|'

        for key in integration_commands:
            integrations.append(key)
            for command in integration_commands.get(key, []):
                command_playbooks = (', ').join(commands[command])
                integration_commands_str += f'\n| {key} | {command} | {command_playbooks} |'

        return_results(
            CommandResults(
                readable_output=integration_commands_str
            )
        )

    # Create final markdown for documentation
    markdown_string = create_markdown_list(lists, custom_scripts, integrations, playbooks, args.get('playbook_name'))

    # Format results for output
    integrations = sorted(list(set(integrations)))
    lists = sorted(list(set(lists)))
    playbooks.sort()
    custom_scripts.sort()
    base_scripts.sort()

    dependencies = {
        'Parent Playbook': args["playbook_name"],
        'Playbooks': playbooks,
        'Integrations': integrations,
        'Automations': {'CustomScripts': custom_scripts, 'BaseScripts': base_scripts},
        'Commands': commands,
        'Lists': lists,
        'MarkdownString': markdown_string
    }

    outputs = {
        f'{args["playbook_name"]}': dependencies
    }

    return CommandResults(
        readable_output=f'''Retrieved Dependencies for Playbook "{args['playbook_name']}"''',
        outputs_prefix='RetrievePlaybookDependencies',
        outputs_key_field='',
        outputs=outputs,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(retrieve_playbooks_and_integrations(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute RetrievePlaybookDependencies. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
