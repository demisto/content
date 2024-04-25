import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
CLOUD_URL_STRUCTURE = 'https://api.atlassian.com/jsm/assets/workspace/'
ON_PREM_URL_STRUCTURE = 'https://{}/rest/assets/1.0/'
GETֹֹֹֹ_WORKSPACE_URL_STRUCTURE = 'https://{}.atlassian.net/rest/servicedeskapi/assets/workspace'
INTEGRATION_OUTPUTS_BASE_PATH = 'JiraAsset'
''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {'Authorization': f'Bearer {api_key}', 'Accept': 'application/json'}
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_object_schema_list(self):
        return self._http_request(
            method='GET',
            url_suffix='objectschema/list'
        )

    def get_workspace(self, jsm_premium_site_name) -> Dict[str, Any]:
        return self._http_request(
            auth=(),
            method='GET',
            full_url=GETֹֹֹֹ_WORKSPACE_URL_STRUCTURE.format(jsm_premium_site_name),
            headers={}
        )


''' HELPER FUNCTIONS '''


def pascal_case(s: str) -> str:
    """ Convert a string to PascalCase. """
    words = s.split('_')
    return ''.join(word[:1].upper() + word[1:] for word in words)


def convert_keys_to_pascal(objects: List[Dict[str, Any]], key_mapping: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
    """
    Convert keys of objects in a list to PascalCase, with optional key mapping.

    Args:
        objects (list): List of dictionaries (objects) whose keys need conversion.
        key_mapping (dict): Dictionary containing original keys and expected output keys.

    Returns:
        list: List of dictionaries with keys converted to PascalCase or as per key_mapping.
    """
    if not key_mapping:
        key_mapping = {}

    converted_objects = []

    for obj in objects:
        converted_obj = {}
        for key, value in obj.items():
            if key in key_mapping:
                new_key = key_mapping[key]
            else:
                new_key = pascal_case(key)
            converted_obj[new_key] = value
        converted_objects.append(converted_obj)

    return converted_objects


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        client.get_object_schema_list()
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def jira_asset_get_workspace_command(args: Dict[str, Any], params: Dict[str, Any]) -> CommandResults:
    verify_certificate = not params.get('insecure', True)
    proxy = params.get('proxy', False)
    api_key = params.get('credentials')
    jsm_premium_site_name = args.get('jira_site_name', None)
    client = Client(base_url='dummy.url', verify=verify_certificate, proxy=proxy, api_key=api_key)
    result = client.get_workspace(jsm_premium_site_name)
    outputs = {'ID': result.get('values')[0].get('workspaceId')}
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Workspace',
        outputs_key_field='ID',
        outputs=outputs,
    )


def jira_asset_object_schema_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    page = args.get('page')
    page_size = int(args.get('page_size', 50))
    limit = args.get('limit')
    res = client.get_object_schema_list()
    object_schemas = res.get('objectschemas', [])
    key_mapping = {'id': 'ID', 'objectSchemaKey': 'Key'}

    if page:
        page = int(page)
        if page < 1 or (page - 1) * page_size >= len(object_schemas):
            raise ValueError("Invalid page_number. Page does not exist.")
        start_index = (page - 1) * page_size
        end_index = min(start_index + page_size, len(object_schemas))

        # Retrieve elements for the specified page
        object_schemas = object_schemas[start_index:end_index]

    if limit:
        limit = int(limit)
        object_schemas = object_schemas[:limit]

    outputs = convert_keys_to_pascal(object_schemas, key_mapping)
    readable_outputs = [
        {k: v for k, v in output.items() if
         k != 'Updated' and
         k != 'ObjectCount' and
         k != 'ObjectTypeCount'} for output in outputs]
    hr_headers = ['ID', 'Name', 'Key', 'Status', 'Description', 'Created']
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Schema',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object Schemas', readable_outputs, headers=hr_headers)
    )


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()
    api_key = params.get('credentials', {}).get('password', '')
    workspace_id = params.get('workspace_id', None)
    server_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    base_url = server_url

    try:
        if server_url == CLOUD_URL_STRUCTURE and workspace_id:
            base_url = server_url + workspace_id + '/v1/'
        elif server_url != CLOUD_URL_STRUCTURE:
            base_url = ON_PREM_URL_STRUCTURE.format(server_url)
        else:
            if command == 'jira-asset-get-workspace':
                return_results(jira_asset_get_workspace_command(args, params))
            else:
                raise DemistoException(
                    'Cloud Jira Asset users must specify workspace id. Please run the jira-asset-get-workspace '
                    'command to get your workspace id')

        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, api_key=api_key)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        if command == 'jira-asset-object-schema-list':
            result = jira_asset_object_schema_list_command(client, args)
            return_results(result)
        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    except Exception as e:
        demisto.debug(f"The integration context_data is {get_integration_context()}")
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}\nException is: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
