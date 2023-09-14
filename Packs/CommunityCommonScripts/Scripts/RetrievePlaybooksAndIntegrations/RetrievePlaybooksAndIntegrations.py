import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
from typing import Any, Dict


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
        args['body'] = json.dumps(body)

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


def append_to_playbooks_and_integrations(playbooks, integrations, playbook_name, brands):
    if playbook_name not in playbooks:
        playbooks.append(playbook_name)
    for b in brands:
        if b and b != 'Builtin' and b not in integrations:
            integrations.append(b)
    return playbooks, integrations


def get_subplaybook_tasks(playbooks, integrations, task):
    # recursively go through all subplaybook tasks and append to playbooks and integrations
    subplaybook_json = perform_rest_call('get', f"playbook/{task['task']['playbookId']}")
    playbooks, integrations = append_to_playbooks_and_integrations(
        playbooks, integrations, subplaybook_json['name'], subplaybook_json['brands'])
    tasks = get_tasks_list(subplaybook_json['tasks'])
    for t in tasks:
        if t['type'] == 'playbook' and t['task'].get('playbookId'):
            # playbookId does not exist if the playbook the task references is missing
            playbooks, integrations = get_subplaybook_tasks(playbooks, integrations, t)
    return playbooks, integrations


''' COMMAND FUNCTION '''


def retrieve_playbooks_and_integrations(args: Dict[str, Any]) -> CommandResults:
    playbooks: List[str] = []
    integrations: List[str] = []
    query = f'''name:"{args['playbook_name']}"'''
    body = {
        'query': query
    }
    playbooks_json = perform_rest_call('post', 'playbook/search', body)
    for playbook_json in playbooks_json['playbooks']:
        if playbook_json['name'] == args['playbook_name']:
            break
    playbooks, integrations = append_to_playbooks_and_integrations(
        playbooks, integrations, playbook_json['name'], playbook_json['brands'])

    tasks = get_tasks_list(playbook_json['tasks'])
    for task in tasks:
        if task['type'] == 'playbook':
            playbooks, integrations = get_subplaybook_tasks(playbooks, integrations, task)

    outputs = {
        'Playbooks': playbooks,
        'Integrations': integrations
    }

    return CommandResults(
        readable_output=f'''Retrieved Playbooks and Integrations for Playbook "{playbook_json['name']}"''',
        outputs_prefix='RetrievePlaybooksAndIntegrations',
        outputs_key_field='',
        outputs=outputs,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(retrieve_playbooks_and_integrations(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
