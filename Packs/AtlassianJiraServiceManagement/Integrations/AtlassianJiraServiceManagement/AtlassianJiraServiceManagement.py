import json

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
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
CLOUD_URL_STRUCTURE = 'https://api.atlassian.com/jsm/assets/workspace/'
ON_PREM_URL_STRUCTURE = '{}/rest/assets/1.0/'
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

    def http_get(self, url_suffix, params=None):
        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params
        )

    def create_object(self, json_data):
        return self._http_request(
            method='POST',
            url_suffix='/object/create',
            json_data=json_data
        )

    def http_post(self, url_suffix, json_data):
        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=json_data
        )

    def update_object(self, object_id: str, json_data: Dict[str, Any]):
        return self._http_request(
            method='PUT',
            url_suffix=f'/object/{object_id}',
            json_data=json_data
        )

    def delete_object(self, object_id: str):
        return self._http_request(
            method='DELETE',
            url_suffix=f'/object/{object_id}'
        )

    def get_workspace(self, jsm_premium_site_name) -> dict[str, Any]:
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


def convert_keys_to_pascal(objects: List[dict[str, Any]], key_mapping: Optional[dict[str, str]] = None) -> List[dict[str, Any]]:
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


def get_object_attribute_string_type(attribute: Dict[str, Any]) -> str:
    match attribute['Type']:
        case 0:
            return attribute['DefaultType']['name']
        case 1:
            return 'Object Reference'
        case 2:
            return 'User'
        case 4:
            return 'Group'
        case 6:
            return 'Project'
        case 7:
            return 'Status'
        case 8:
            return 'Bitbucket Repository'


def get_object_outputs(objects: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    outputs = []
    readable_outputs = []
    for obj in objects:
        obj_type = obj['ObjectType']['name']
        output = {k: v for k, v in obj.items() if k != 'ObjectType' and k != 'Avatar'}
        readable_output = {**output, "Type": obj_type}
        outputs.append(output)
        readable_outputs.append(readable_output)
    return outputs, readable_outputs


def clean_object_attributes(attributes: List[Dict[str, any]]) -> List[Dict[str, any]]:
    pascal_attributes = convert_keys_to_pascal(attributes, {'id': 'ID'})
    string_typed_attributes = [{
        **attribute,
        'Type': get_object_attribute_string_type(attribute)}
        for attribute in pascal_attributes
    ]
    return [{k: v for k, v in attribute.items() if k != 'ObjectType'} for attribute in string_typed_attributes]


def convert_attributes(attributes: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    result = []
    for attribute_id, values in attributes.items():
        attribute_dict = {
            "objectTypeAttributeId": attribute_id,
            "objectAttributeValues": [{"value": value} for value in values]
        }
        result.append(attribute_dict)
    return result


def get_json_data(object_type_id: str, attributes: str = None, attributes_json: str = None) -> Dict[str, Any]:

    if not attributes and not attributes_json:
        raise ValueError('Either attributes or attributes_json must be provided.')
    elif attributes and attributes_json:
        raise ValueError('Only one of attributes or attributes_json must be provided.')

    if attributes:
        converted_attributes = convert_attributes(json.loads(attributes))
    else:
        converted_attributes = json.loads(attributes_json).get('attributes')

    return {
        'objectTypeId': object_type_id,
        'attributes': converted_attributes
    }


def parse_object_results(res: Dict[str, any]) -> Dict[str, Any]:
    pascal_res = convert_keys_to_pascal([res], {'id': 'ID'})
    outputs = [{k: v for k, v in obj_field.items() if k != 'ObjectType'} for obj_field in pascal_res]
    object_id = res.get('id')
    return {'outputs': outputs, 'objectId': object_id}


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
        client.http_get('objectschema/list')
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def jira_asset_get_workspace_command(args: dict[str, Any], params: dict[str, Any]) -> CommandResults:
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


def jira_asset_object_schema_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    limit = args.get('limit', 50)
    all_results = args.get('all_results', False)
    res = client.http_get('objectschema/list')
    object_schemas = res.get('objectschemas', [])
    key_mapping = {'id': 'ID', 'objectSchemaKey': 'Key'}

    if not all_results:
        limit = int(limit)
        object_schemas = object_schemas[:limit]

    outputs = convert_keys_to_pascal(object_schemas, key_mapping)
    hr_headers = ['ID', 'Name', 'Key', 'Status', 'Description', 'Created']
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Schema',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object Schemas', outputs, headers=hr_headers)
    )


def jira_asset_object_type_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    schema_id = args.get('schema_id')
    query = args.get('query')
    exclude = args.get('exclude')
    limit = args.get('limit', 50)
    all_results = args.get('all_results', False)
    url_suffix = f'objectschema/{schema_id}/objecttypes/flat'

    # build request params
    params = {}
    if query:
        params['query'] = query
    if exclude:
        params['exclude'] = exclude

    # build outputs
    res = client.http_get(url_suffix, params)
    object_types = convert_keys_to_pascal(list(res), {'id': 'ID', 'parentObjectTypeId': 'ParentTypeID'})
    if not all_results:
        limit = int(limit)
        object_types = object_types[:limit]
    outputs = [{k: v for k, v in ot.items() if k != 'Icon'} for ot in object_types]

    # build readable outputs
    hr_headers = ['ID', 'Name', 'ParentTypeID', 'AbstractObjectType']

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.ObjectType',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object Types', outputs, headers=hr_headers)
    )


def jira_asset_object_type_attribute_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    object_type_id = args.get('object_type_id')
    limit = args.get('limit', 50)
    all_results = args.get('all_results', False)
    url_suffix = f'objecttype/{object_type_id}/attributes'

    # build request params
    params = {
        'onlyValueEditable': args.get('is_editable', False),
        'orderByName': args.get('order_by_name', False),
        'query': args.get('query'),
        'includeValueExist': args.get('include_value_exist', False),
        'excludeParentAttributes': args.get('exclude_parent_attributes', False),
        'includeChildren': args.get('include_children', False),
        'orderByRequired': args.get('order_by_required', False)
    }

    # build outputs
    res = client.http_get(url_suffix, params)
    outputs = clean_object_attributes(list(res))

    if not all_results:
        limit = int(limit)
        outputs = outputs[:limit]

    hr_headers = ['ID', 'Name', 'Type', 'Description', 'MinimumCardinality', 'Editable']
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Attribute',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object Types', outputs, headers=hr_headers)
    )


def jira_asset_object_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    object_type_id = args.get('object_type_id')
    attributes = args.get('attributes')
    attributes_json = args.get('attributes_json')

    json_data = get_json_data(object_type_id, attributes, attributes_json)
    res = client.create_object(json_data)
    outputs, object_id = parse_object_results(res).values()

    return CommandResults(
        outputs=outputs,
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Object',
        readable_output=f'Object created successfully with ID: {object_id}'
    )


def jira_asset_object_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    attributes = args.get('attributes')
    attributes_json = args.get('attributes_json')
    object_id = args.get('object_id')

    jira_object = client.http_get(f'/object/{object_id}')
    object_type_id = jira_object.get('objectType').get('id')
    json_data = get_json_data(object_type_id, attributes, attributes_json)
    res = client.update_object(object_id, json_data)
    _, object_id = parse_object_results(res).values()

    return CommandResults(readable_output=f'Object {object_id} updated successfully')


def jira_asset_object_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    object_id = args.get('object_id')

    try:
        client.delete_object(object_id)
    except DemistoException as e:
        if e.res.status_code == 404:
            return CommandResults(readable_output=f'Object with id: {object_id} does not exist')
        else:
            raise e

    return CommandResults(readable_output=f'Object with id: {object_id} was deleted successfully')


def jira_asset_object_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    object_id = args.get('object_id')

    try:
        res = client.http_get(f'/object/{object_id}')
        pascal_res = convert_keys_to_pascal([res], {'id': 'ID'})
        hr_headers = ['ID', 'Label', 'Type', 'Created']
        outputs, readable_output = get_object_outputs(pascal_res)
    except DemistoException as e:
        if e.res.status_code == 404:
            return CommandResults(readable_output=f'Object with id: {object_id} does not exist')
        else:
            raise e

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Object',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object', readable_output, headers=hr_headers)
    )


def jira_asset_object_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    ql_query = args.get('ql_query')
    include_attributes = bool(args.get('include_attributes', False))
    page = int(args.get('page', 1))
    page_size = int(args.get('page_size', 50))
    limit = args.get('limit')
    params = {
        'qlQuery': ql_query,
        'includeAttributes': include_attributes,
        'page': page,
        'resultsPerPage': limit if limit else page_size
    }

    res = client.http_get(url_suffix='/aql/objects', params=params)
    pascal_res = convert_keys_to_pascal(res['objectEntries'], {'id': 'ID'})
    hr_headers = ['ID', 'Label', 'Type', 'ObjectKey']
    outputs, readable_output = get_object_outputs(pascal_res)
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Object',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object', readable_output, headers=hr_headers)
    )


def jira_asset_attribute_json_create_command(client: Client, args: Dict[str, Any]):
    object_type_id = args.get('object_type_id')
    url_suffix = f'objecttype/{object_type_id}/attributes'

    params = {'onlyValueEditable': args.get('is_editable', False)}
    res = client.http_get(url_suffix, params)
    if args.get('is_required'):
        res = [attribute for attribute in res if attribute.get('minimumCardinality') > 0]
    outputs = {'attributes': [{
        "objectTypeAttributeId": attribute.get("id"),
        "objectAttributeValues": [{"value": ''}]
    } for attribute in res]}

    return CommandResults()


def jira_asset_comment_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    object_id = args.get('object_id')
    comment = args.get('comment')
    res = client.http_post('/comment/create', {'objectId': object_id, 'comment': comment})
    outputs = convert_keys_to_pascal([res], {'id': 'ID'})

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Comment',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=f'Comment was added successfully to object with id: {object_id}'
    )

def jira_asset_comment_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    object_id = args.get('object_id')
    res = client.http_get(f'/comment/object/{object_id}')
    outputs = convert_keys_to_pascal([res], {'id': 'ID'})
    outputs = [{k: v} for k, v in outputs.items() if k != 'Actor']


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

        elif command == 'jira-asset-object-schema-list':
            result = jira_asset_object_schema_list_command(client, args)
            return_results(result)

        elif command == 'jira-asset-object-type-list':
            result = jira_asset_object_type_list_command(client, args)
            return_results(result)

        elif command == 'jira-asset-object-type-attribute-list':
            result = jira_asset_object_type_attribute_list_command(client, args)
            return_results(result)

        elif command == 'jira-asset-object-create':
            result = jira_asset_object_create_command(client, args)
            return_results(result)

        elif command == 'jira-asset-object-update':
            result = jira_asset_object_update_command(client, args)
            return_results(result)

        elif command == 'jira-asset-object-delete':
            result = jira_asset_object_delete_command(client, args)
            return_results(result)

        elif command == 'jira-asset-object-get':
            result = jira_asset_object_get_command(client, args)
            return_results(result)

        elif command == 'jira-asset-object-search':
            result = jira_asset_object_search_command(client, args)
            return_results(result)

        elif command == 'jira-asset-attribute-json-create':
            result = jira_asset_attribute_json_create_command(client, args)
            return_results(result)

        elif command == 'jira-asset-comment-create':
            result = jira_asset_comment_create_command(client, args)
            return_results(result)

        elif command == 'jira-asset-comment-list':
            result = jira_asset_comment_list_command(client, args)
            return_results(result)

        else:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

    except Exception as e:
        demisto.debug(f"The integration context_data is {get_integration_context()}")
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}\nException is: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
