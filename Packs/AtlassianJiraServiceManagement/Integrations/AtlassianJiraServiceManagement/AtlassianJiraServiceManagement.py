import json
import os
import io
import zipfile

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
ON_PREM_URL_STRUCTURE = '{}/rest/assets/1.0/'
INTEGRATION_OUTPUTS_BASE_PATH = 'JiraAsset'
''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, api_key: str, verify: bool, proxy: bool):
        headers = {'Authorization': f'Bearer {api_key}', 'Accept': 'application/json'}
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers, ok_codes=(200, 201, 204, 404))

    def get_schema_list(self):
        return self._http_request(
            method='GET',
            url_suffix='/objectschema/list'
        )

    def get_object_type_list(self, schema_id: str, exclude):
        url_suffix = f'objectschema/{schema_id}/objecttypes/flat'

        # build request params
        params = {'exclude': exclude} if exclude else {}

        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_object_type_attributes(
        self,
        object_type_id: str,
        is_editable: bool = False,
        order_by_name: bool = False,
        query: str = None,
        include_value_exist: bool = False,
        exclude_parent_attributes: bool = False,
        include_children: bool = False,
        order_by_required: bool = False
    ):
        url_suffix = f'objecttype/{object_type_id}/attributes'

        # build request params
        params = {
            'onlyValueEditable': is_editable,
            'orderByName': order_by_name,
            'query': query,
            'includeValueExist': include_value_exist,
            'excludeParentAttributes': exclude_parent_attributes,
            'includeChildren': include_children,
            'orderByRequired': order_by_required
        }

        return self._http_request(method='GET', url_suffix=url_suffix, params=params)

    def get_object(self, object_id):
        """
        hr_headers = ['ID', 'Label', 'Type', 'Created']
        readable_output = get_object_readable_outputs([res])
        outputs = {k: v for k, v in res.items() if k != 'objectType' and k != 'avatar'}
        """
        res = self._http_request(method='GET', url_suffix=f'/object/{object_id}', resp_type='response')
        if res.status_code == 404:
            return None
        return res.json()

    def search_objects(self, ql_query: str, include_attributes: bool, page: int, page_size: int, limit: int = None):
        params = {
            'qlQuery': ql_query,
            'includeAttributes': include_attributes,
            'page': page,
            'resultsPerPage': limit if limit else page_size
        }

        return self._http_request(
            method='GET',
            url_suffix='/aql/objects',
            params=params
        )

    def get_comment_list(self, object_id: str):
        return self._http_request(method='GET', url_suffix=f'/comment/object/{object_id}')

    def get_object_connected_tickets(self, object_id: str):
        return self._http_request(method='GET', url_suffix=f'/objectconnectedtickets/{object_id}/tickets')

    def get_object_attachment_list(self, object_id):
        res = self._http_request(method='GET', url_suffix=f'/attachments/object/{object_id}', resp_type='response')
        if res.status_code == 404:
            return None
        return res.json()

    def get_file(self, file_url):
        return self._http_request(
            method='GET',
            full_url=file_url,
            resp_type='response'
        )

    def create_object(self, json_data):
        return self._http_request(
            method='POST',
            url_suffix='/object/create',
            json_data=json_data
        )

    def create_comment(self, object_id, comment):
        url_suffix = '/comment/create'
        json_data = {
            'objectId': object_id,
            'comment': comment
        }
        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=json_data
        )

    def send_file(self, object_id, file_path):
        return self._http_request(
            method='POST',
            url_suffix=f'/attachments/object/{object_id}',
            files={'file': (file_path, open(file_path, 'rb'))}
        )

    def update_object(self, object_id: str, json_data: Dict[str, Any]):
        return self._http_request(
            method='PUT',
            url_suffix=f'/object/{object_id}',
            json_data=json_data
        )

    def delete_object(self, object_id: str):
        res = self._http_request(
            method='DELETE',
            url_suffix=f'/object/{object_id}',
            resp_type='response'
        )
        if res.status_code == 404:
            return None
        return res.json()

    def remove_file(self, attachment_id):
        return self._http_request(
            method='DELETE',
            url_suffix=f'/attachments/{attachment_id}'
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
    match attribute['type']:
        case 0:
            return attribute['defaultType']['name']
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
    return 'Default'


def get_object_readable_outputs(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pascal_objects = convert_keys_to_pascal(objects, {'id': 'ID'})
    readable_outputs = []
    for obj in pascal_objects:
        obj_type = obj['ObjectType']['name']
        output = {k: v for k, v in obj.items() if k not in ('ObjectType', 'Avatar')}
        readable_output = {**output, "Type": obj_type}
        readable_outputs.append(readable_output)
    return readable_outputs


def clean_object_attributes(attributes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    string_typed_attributes = [{
        **attribute,
        'type': get_object_attribute_string_type(attribute)}
        for attribute in attributes
    ]
    return [{k: v for k, v in attribute.items() if k != 'objectType'} for attribute in string_typed_attributes]


def convert_attributes(attributes: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    result = []
    for attribute_id, values in attributes.items():
        values = argToList(values)
        attribute_dict = {
            "objectTypeAttributeId": attribute_id,
            "objectAttributeValues": [{"value": value} for value in values]
        }
        result.append(attribute_dict)
    return result


def get_attributes_json_data(
    object_type_id: str,
    attributes: dict[str, Any] = None,
    attributes_json: str = None
) -> Dict[str, Any]:

    if not attributes and not attributes_json:
        raise ValueError('Either attributes or attributes_json must be provided.')
    elif attributes and attributes_json:
        raise ValueError('Only one of attributes or attributes_json must be provided.')

    if attributes:
        converted_attributes = convert_attributes(attributes)
    else:
        # cast is necessary for pre-commit. mypy isn't smart enough to know that by that point, attributes_json must be defined
        converted_attributes = json.loads(str(attributes_json)).get('attributes')

    return {
        'objectTypeId': object_type_id,
        'attributes': converted_attributes
    }


def parse_object_results(res: Dict[str, Any]) -> Dict[str, Any]:
    outputs = [{k: v for k, v in res.items() if k != 'objectType'}]
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
        client.get_schema_list()
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def jira_asset_object_schema_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves a list of Jira asset object schemas with an option to limit the number of results returned.

    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'limit': The maximum number of object schemas to return. Defaults to 50.
        - 'all_results': A boolean indicating whether to return all results or to respect the limit. Defaults to False.
    :return: A CommandResults object containing the list of object schemas as output, and a human-readable markdown table.
    """
    limit = args.get('limit', 50)
    all_results = argToBoolean(args.get('all_results', False))
    res = client.get_schema_list()
    object_schemas = res.get('objectschemas', [])
    key_mapping = {'id': 'ID', 'objectSchemaKey': 'Key'}

    if not all_results:
        limit = int(limit)
        object_schemas = object_schemas[:limit]

    readable_outputs = convert_keys_to_pascal(object_schemas, key_mapping)
    hr_headers = ['ID', 'Name', 'Key', 'Status', 'Description', 'Created']
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Schema',
        outputs_key_field='ID',
        outputs=object_schemas,
        readable_output=tableToMarkdown('Object Schemas', readable_outputs, headers=hr_headers, removeNull=True)
    )


def jira_asset_object_type_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves a list of Jira asset object types based on provided arguments.

    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'schema_id': The ID of the schema to retrieve object types from.
        - 'exclude': A string to specify object types that should be excluded from the results.
        - 'limit': The maximum number of object types to return. Defaults to 50.
        - 'all_results': A boolean indicating whether to return all results or to respect the limit. Defaults to False.
    :return: A CommandResults object containing the list of object types as output, and a human-readable markdown table.
    """
    schema_id = args.get('schema_id', '')
    exclude = args.get('exclude')
    limit = args.get('limit', 50)
    all_results = argToBoolean(args.get('all_results', False))

    if not schema_id:
        raise ValueError("schema_id is a required argument")

    # build outputs
    res = client.get_object_type_list(schema_id, exclude)
    outputs = [{k: v for k, v in ot.items() if k != 'icon'} for ot in res]
    if not all_results:
        limit = int(limit)
        outputs = outputs[:limit]

    readable_outputs = convert_keys_to_pascal(list(outputs), {'id': 'ID', 'parentObjectTypeId': 'ParentTypeID'})

    # build readable outputs
    hr_headers = ['ID', 'Name', 'ParentTypeID', 'AbstractObjectType']

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.ObjectType',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object Types', readable_outputs, headers=hr_headers, removeNull=True)
    )


def jira_asset_object_type_attribute_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
        Retrieves a list of attributes for a specific Jira asset object type with various filtering and sorting options.

        :param client: Client object for performing API requests.
        :param args: A dictionary of command arguments:
            - 'object_type_id': The ID of the object type to retrieve attributes for.
            - 'limit': The maximum number of attributes to return. Defaults to 50.
            - 'all_results': A boolean indicating whether to return all results or to respect the limit. Defaults to False.
            - Additional boolean arguments for filtering and sorting:
                * 'order_by_name'
                * 'include_value_exist'
                * 'exclude_parent_attributes'
                * 'include_children'
                * 'order_by_required'
        :return: A CommandResults object containing the list of attributes as output, and a human-readable markdown table.
    """
    object_type_id = args.get('object_type_id', '')
    limit = args.get('limit', 50)
    all_results = args.get('all_results', False)

    if not object_type_id:
        raise ValueError('object_type_id is a required argument')

    # build outputs
    res = client.get_object_type_attributes(
        object_type_id=object_type_id,
        order_by_name=argToBoolean(args.get('order_by_name', False)),
        query=args.get('query'),
        include_value_exist=argToBoolean(args.get('include_value_exist', False)),
        exclude_parent_attributes=argToBoolean(args.get('exclude_parent_attributes', False)),
        include_children=argToBoolean(args.get('include_children', False)),
        order_by_required=argToBoolean(args.get('order_by_required', False))
    )

    outputs = clean_object_attributes(list(res))

    if not all_results:
        limit = int(limit)
        outputs = outputs[:limit]

    hr_headers = ['ID', 'Name', 'Type', 'Description', 'MinimumCardinality', 'Editable']
    readable_outputs = convert_keys_to_pascal(list(res), {'id': 'ID'})
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Attribute',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object Types', readable_outputs, headers=hr_headers, removeNull=True)
    )


def jira_asset_object_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates a new Jira asset object.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_type_id': The ID of the object type to create the object for.
        - 'attributes': A list of attribute names and values to set for the object.
        - 'attributes_json': A JSON string of attributes to set for the object.
    :return: A CommandResults object containing the created object as output, and a human-readable markdown table.
    """
    object_type_id = args.get('object_type_id', '')
    attributes = args.get('attributes')
    attributes_json = args.get('attributes_json')

    if not object_type_id:
        raise ValueError('object_type_id is a required argument')

    json_data = get_attributes_json_data(object_type_id, attributes, attributes_json)
    res = client.create_object(json_data)
    outputs, object_id = parse_object_results(res).values()

    return CommandResults(
        outputs=outputs,
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Object',
        readable_output=f'Object created successfully with ID: {object_id}'
    )


def jira_asset_object_update_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Updates an existing Jira asset object.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_id': The ID of the object to update.
        - 'attributes': A list of attribute names and values to set for the object.
        - 'attributes_json': A JSON string of attributes to set for the object.
    :return: A CommandResults object containing the updated object as output, and a human-readable markdown table.
    """
    attributes = args.get('attributes')
    attributes_json = args.get('attributes_json')
    object_id = args.get('object_id', '')

    if not object_id:
        raise ValueError('object_id is a required argument')

    jira_object = client.get_object(object_id)

    if not jira_object:
        return CommandResults(readable_output=f'Object with id: {object_id} does not exist')

    object_type_id = jira_object.get('objectType').get('id')
    json_data = get_attributes_json_data(object_type_id, attributes, attributes_json)
    res = client.update_object(object_id, json_data)
    _, object_id = parse_object_results(res).values()

    return CommandResults(readable_output=f'Object {object_id} updated successfully')


def jira_asset_object_delete_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Deletes an existing Jira asset object.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_id': The ID of the object to delete.
    :return: A CommandResults object containing a human-readable message.
    """
    object_id = args.get('object_id', '')
    if not object_id:
        raise ValueError('object_id is a required argument')

    res = client.delete_object(object_id)
    if not res:
        return CommandResults(readable_output=f'Object with id: {object_id} does not exist')

    return CommandResults(readable_output=f'Object with id: {object_id} was deleted successfully')


def jira_asset_object_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves an existing Jira asset object.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_id': The ID of the object to retrieve.
    :return: A CommandResults object containing the object as output, and a human-readable markdown table.
    """
    object_id = args.get('object_id', '')

    if not object_id:
        raise ValueError('object_id is a required argument')

    res = client.get_object(object_id)
    if not res:
        return CommandResults(readable_output=f'Object with id: {object_id} does not exist')
    hr_headers = ['ID', 'Label', 'Type', 'Created']
    readable_output = get_object_readable_outputs([res])
    outputs = {k: v for k, v in res.items() if k != 'objectType' and k != 'avatar'}

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Object',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object', readable_output, headers=hr_headers, removeNull=True)
    )


def jira_asset_object_search_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Searches for Jira asset objects.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'ql_query': The query string to search for.
        - 'include_attributes': Whether to include the object's attributes in the response.
        - 'page': The page number to retrieve.
        - 'page_size': The number of objects to retrieve per page.
        - 'limit': The maximum number of objects to retrieve.
    :return: A CommandResults object containing the objects as output, and a human-readable markdown table.
    """
    # build request params
    ql_query = args.get('ql_query', '')
    include_attributes = argToBoolean(args.get('include_attributes', False))
    page = int(args.get('page', 1))
    page_size = int(args.get('page_size', 50))
    limit = args.get('limit')

    if not ql_query:
        raise ValueError('ql_query is a required argument')

    # build outputs
    res = client.search_objects(ql_query, include_attributes, page, page_size, limit)
    objects = res['objectEntries']
    hr_headers = ['ID', 'Label', 'Type', 'ObjectKey']
    readable_output = get_object_readable_outputs(objects)
    outputs = [{k: v for k, v in obj.items() if k != 'objectType' and k != 'avatar'} for obj in objects]
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Object',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Object', readable_output, headers=hr_headers, removeNull=True)
    )


def jira_asset_attribute_json_create_command(client: Client, args: Dict[str, Any]) -> tuple[dict, CommandResults]:
    """
    Creates a Jira asset attribute JSON object.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_type_id': The ID of the object type to create the attribute JSON for.
        - 'is_required': Whether to include only required attributes in the response.
        - 'is_editable': Whether to include only editable attributes in the response.
    :return: A CommandResults object containing the attribute JSON as a file entry, and a human-readable json string.
    """
    # build request params
    object_type_id = args.get('object_type_id', '')
    is_editable = args.get('is_editable', False)

    if not object_type_id:
        raise ValueError('object_type_id is a required argument')

    # build outputs
    res = client.get_object_type_attributes(object_type_id=object_type_id, is_editable=is_editable)
    if args.get('is_required'):
        res = [attribute for attribute in res if int(attribute.get('minimumCardinality')) > 0]

    outputs = {'attributes': [{
        "objectTypeAttributeId": attribute.get("id"),
        "objectAttributeValues": [{"value": ''}]
    } for attribute in res]}

    hr_command_results = CommandResults(readable_output=json.dumps(outputs))
    file_entry = fileResult(filename='attributes.json', data=json.dumps(outputs, indent=2), file_type=EntryType.ENTRY_INFO_FILE)
    return file_entry, hr_command_results


def jira_asset_comment_create_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Creates a Jira asset comment.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_id': The ID of the object to create the comment for.
        - 'comment': The comment to add to the object.
    :return: A CommandResults object containing the comment as output, and a confirmation message.
    """
    object_id = args.get('object_id')
    comment = args.get('comment')
    res = client.create_comment(object_id, comment)

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Comment',
        outputs_key_field='ID',
        outputs=res,
        readable_output=f'Comment was added successfully to object with id: {object_id}'
    )


def jira_asset_comment_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Lists Jira asset comments.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_id': The ID of the object to retrieve comments for.
    :return: A CommandResults object containing the comments as output, and a human-readable markdown table.
    """
    object_id = args.get('object_id', '')
    if not object_id:
        raise ValueError('object_id is a required argument')

    res = client.get_comment_list(object_id)
    readable_outputs = convert_keys_to_pascal(list(res), {'id': 'ID'})
    outputs = [{k: v for k, v in output.items() if k != 'actor'} for output in res]
    hr_headers = ['ID', 'Comment']

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Comment',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Comments', readable_outputs, headers=hr_headers, removeNull=True)
    )


def jira_asset_connected_ticket_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Lists Jira asset connected tickets.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_id': The ID of the object to retrieve connected tickets for.
    :return: A CommandResults object containing the connected tickets as output, and a human-readable markdown table.
    """
    object_id = args.get('object_id', '')
    if not object_id:
        raise ValueError('object_id is a required argument')
    res = client.get_object_connected_tickets(object_id)
    outputs = list(res.get('tickets'))
    hr_headers = ['ID', 'Title', 'Status', 'Type']
    readable_output = [{'Status': output.get('status', {}).get('name'), 'Type': output.get('type', {}).get('name'),
                        'Title': output.get('title', {})} for output in outputs]
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.ConnectedTicket',
        outputs_key_field='ID',
        outputs=outputs,
        readable_output=tableToMarkdown('Connected Tickets', readable_output, headers=hr_headers, removeNull=True)
    )


def jira_asset_attachment_add_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Adds a Jira asset attachment to a specific object.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_id': The ID of the object to add the attachment to.
        - 'entry_id': The entry ID of the file to add as an attachment.
    :return: A CommandResults object containing the attachment as output, and a confirmation message.
    """
    object_id = args.get('object_id')
    entry_id = args.get('entry_id')
    file_path = demisto.getFilePath(entry_id)
    demisto.debug(f'File path: {file_path}')
    res = client.send_file(object_id=object_id, file_path=file_path.get('path'))
    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Attachment',
        outputs_key_field='ID',
        outputs=res,
        readable_output=f'Attachment was added successfully to object with id: {object_id}'
    )


def jira_asset_attachment_list_command(client: Client, args: dict[str, Any]) -> List[CommandResults | dict] | CommandResults:
    """
    Lists Jira asset attachments for a specific object.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'object_id': The ID of the object to retrieve attachments for.
        - 'download_file': Whether to download the attachments.
    :return: A CommandResults object containing the attachments as output, and a human-readable markdown table if download_file is
        False. If download_file is True, a list of CommandResults objects containing the attachments as output, and a fileResult
        object.
    """
    object_id = args.get('object_id')
    download_file = argToBoolean(args.get('download_file', False))
    res = client.get_object_attachment_list(f'/attachments/object/{object_id}')
    if not res:
        return CommandResults(readable_output='No attachments found.')
    readable_outputs = convert_keys_to_pascal(list(res), {'id': 'ID'})
    hr_header = ['ID', 'Filename', 'Filesize', 'Comment']

    command_results = CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Attachment',
        outputs_key_field='ID',
        outputs=res,
        readable_output=tableToMarkdown('Attachments', readable_outputs, headers=hr_header, removeNull=True)
    )

    if not download_file:
        return command_results

    files = []
    for attachment in res:
        attachment_url = attachment.get('url')
        file_response = client.get_file(attachment_url)
        file_name = attachment_url.split('/')[-1]
        i = 1
        while file_name in files:
            name, ext = file_name.split('.')
            file_name = f"{name}_{i}.{ext}"
            i += 1
        with open(file_name, 'wb') as file:
            file.write(file_response.content)
            files.append(file.name)
    zip_data_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_data_buffer, 'w') as zipf:
        for curr_file_name in files:
            zipf.write(curr_file_name)
            os.remove(curr_file_name)

    data = zip_data_buffer.getvalue()
    file_result = fileResult('ObjectAttachments.zip', data, EntryType.ENTRY_INFO_FILE)
    return [file_result, command_results]


def jira_asset_attachment_remove_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Removes a Jira asset attachment.
    :param client: Client object for performing API requests.
    :param args: A dictionary of command arguments:
        - 'id': The ID of the attachment to remove.
    :return: A CommandResults object containing the attachment as output, and a confirmation message.
    """
    attachment_id = args.get('id')

    try:
        res = client.remove_file(attachment_id)
    except DemistoException as e:
        if e.res.status_code == 404:
            return CommandResults(readable_output=f'Attachment with id: {attachment_id} does not exist')
        else:
            raise e

    return CommandResults(
        outputs_prefix=f'{INTEGRATION_OUTPUTS_BASE_PATH}.Attachment',
        outputs_key_field='ID',
        outputs=res,
        readable_output=f'Attachment with id {res.get("id")} was successfully deleted'
    )


''' MAIN FUNCTION '''

commands = {
    'jira-asset-object-schema-list': jira_asset_object_schema_list_command,
    'jira-asset-object-type-list': jira_asset_object_type_list_command,
    'jira-asset-object-type-attribute-list': jira_asset_object_type_attribute_list_command,
    'jira-asset-object-create': jira_asset_object_create_command,
    'jira-asset-object-update': jira_asset_object_update_command,
    'jira-asset-object-delete': jira_asset_object_delete_command,
    'jira-asset-object-get': jira_asset_object_get_command,
    'jira-asset-object-search': jira_asset_object_search_command,
    'jira-asset-attribute-json-create': jira_asset_attribute_json_create_command,
    'jira-asset-comment-create': jira_asset_comment_create_command,
    'jira-asset-comment-list': jira_asset_comment_list_command,
    'jira-asset-connected-ticket-list': jira_asset_connected_ticket_list_command,
    'jira-asset-attachment-add': jira_asset_attachment_add_command,
    'jira-asset-attachment-remove': jira_asset_attachment_remove_command,
    'jira-asset-attachment-list': jira_asset_attachment_list_command
}


def main() -> None:
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()
    api_key = params.get('credentials', {}).get('password', '')
    server_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    try:
        base_url = ON_PREM_URL_STRUCTURE.format(server_url)
        client = Client(base_url=base_url, verify=verify_certificate, proxy=proxy, api_key=api_key)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_result = test_module(client)
            return_results(test_result)

        command_func = commands.get(command)
        if not command_func:
            raise NotImplementedError(f'''Command '{command}' is not implemented.''')

        result = command_func(client, args)
        return_results(result)

    except Exception as e:
        demisto.debug(f"The integration context_data is {get_integration_context()}")
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}\nException is: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
