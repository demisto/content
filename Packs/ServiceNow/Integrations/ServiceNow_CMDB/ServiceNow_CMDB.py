import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast
from _collections import defaultdict
import ast
from operator import itemgetter

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
API_VERSION = '/api/now/cmdb/instance/'
SYSPARMS = {
    'query': 'sysparm_query',
    'limit': 'sysparm_limit',
    'offset': 'sysparm_offset',
    'fields': 'sysparm_fields',
    'relation_limit': 'sysparm_relation_limit',
    'relation_offset': 'sysparm_relation_offset'
}
RECORDS_LIST_PARAMS = ['query', 'limit', 'offset']
RECORD_PARAMS = ['fields', 'relation_limit', 'relation_offset']
CREAT_RECORD_DATA_FIELDS = ['attributes', 'inbound_relations', 'outbound_relations', 'source']
UPDATE_RECORD_DATA_FIELDS = ['attributes', 'source']
ADD_RELATION_DATA_FIELDS = ['inbound_relations', 'outbound_relations', 'source']
RESULT_FIELDS = ['attributes', 'inbound_relations', 'outbound_relations']
FIELD_TO_OUTPUT = {
    'inbound_relations': 'Inbound Relations',
    'outbound_relations': 'Outbound Relations'
}


class Client:
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """
    def __init__(self, params):
        params['headers'] = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self._snow_client: ServiceNowClient = ServiceNowClient(params=params)

    def records_list(self, class_name, params=None):
        return self._snow_client.http_request(method='GET', url_suffix=class_name, params=params)

    def get_record(self, class_name, sys_id, params=None):
        url_suffix = f'{class_name}/{sys_id}'
        return self._snow_client.http_request(method='GET', url_suffix=url_suffix, params=params)

    def create_record(self, class_name, data, params=None):
        return self._snow_client.http_request(method='POST', url_suffix=class_name, params=params, data=data)

    def update_record(self, class_name, sys_id, data, params=None):
        url_suffix = f'{class_name}/{sys_id}'
        return self._snow_client.http_request(method='PATCH', url_suffix=url_suffix, params=params, data=data)

    def add_relation(self, class_name, sys_id, data, params=None):
        url_suffix = f'{class_name}/{sys_id}/relation'
        return self._snow_client.http_request(method='POST', url_suffix=url_suffix, params=params, data=data)

    def delete_relation(self, class_name, sys_id, rel_sys_id, params=None):
        url_suffix = f'{class_name}/{sys_id}/relation/{rel_sys_id}'
        return self._snow_client.http_request(method='DELETE', url_suffix=url_suffix, params=params)


''' HELPER FUNCTIONS '''


def handle_sysparms(sys_parms: List, args: dict) -> dict:
    """
    This function converts the query parameters given by the user to the format required for the http request.

    Args:
        sys_parms: A list with the sysparms that should be added to the query.
        args: The arguments that were filled by the user.

    Returns:
        A dictionary representing the url params that should be sent in the http request.
    """
    params = {}
    for parm in sys_parms:
        val = args.get(parm)
        if val:
            params[SYSPARMS.get(parm)] = val

    # If the user defined the fields param, verify that sys_id and name were added so they can be shown in the output
    if params.get('sysparm_fields'):
        if 'sys_id' not in params.get('sysparm_fields'):
            params['sysparm_fields'] += ',sys_id'
        if 'name' not in params.get('sysparm_fields'):
            params['sysparm_fields'] += ',name'
    return params


def create_request_data(data_fields: List, args: dict) -> dict:
    """
    This function converts the input given by the user when creating a new record to a data dict that should be passed
    in the http request.

    Args:
        data_fields: A list with the fields that should be added to the data.
        args: The arguments that were filled by the user.

    Returns:
        A dictionary representing the data parameter that should be sent in the http request.
    """
    data = {}
    for field in data_fields:
        if field == 'source':
            data[field] = args.get(field)
        elif field == 'attributes':  # 'attributes' input should be of the form key1=value1,key2=value2...
            val = args.get(field)
            if val:
                try:
                    attributes_dict = {}
                    attributes_input = val.split(',')
                    for attribute in attributes_input:
                        pair = attribute.split('=')
                        attributes_dict[pair[0]] = pair[1]
                    data[field] = attributes_dict
                except Exception:
                    raise Exception('Illegal input. Input format should be "key=value". Multiple values can be filled, '
                                    'separated by a comma.')
        else:  # other fields should be converted to dict/list
            val = args.get(field)
            if val:
                try:
                    data[field] = ast.literal_eval(val)
                except Exception:
                    raise Exception('Illegal input. Please see the argument description for the correct input format.')
    return data


def create_record_context(class_name: str, sys_id: str, result: dict) -> dict:
    """
    Create the context output for commands that operate on a single record.

    Args:
        class_name: The class name of the record used.
        sys_id: The id of the record.
        result: The raw response from the http request.

    Return:
        A dictionary representing the context output for the record.
    """
    context = {
        'ServiceNowCMDB.Record(val.ID===obj.ID)': {
            'Class': class_name,
            'SysID': sys_id,
            'Attributes': result.get('attributes', {}),
            'InboundRelations': result.get('inbound_relations', []),
            'OutboundRelations': result.get('outbound_relations', []),
        }
    }
    return context


def create_human_readable(title: str, result: dict) -> str:
    """
    Create the human readable output for commands.

    Args:
        title: The title of the human readable output.
        result: The raw response from the http request consisting of the attributes, inbound_relations and
                outbound_relations fields.

    Return:
        A string representing the markdown output that should be displayed in the war room.
    """
    md = f'{title}\n'
    attributes_outputs = {
        'SysID': result.get('attributes').get('sys_id'),
        'Name': result.get('attributes').get('name')
    }
    md += tableToMarkdown('Attributes', t=attributes_outputs, removeNull=True)

    for relation_type in ['inbound_relations', 'outbound_relations']:
        relations = result.get(relation_type)
        if relations:
            relation_output = {
                'SysID': list(map(itemgetter('sys_id'), relations)),
                'Target Display Value': list(
                    map(itemgetter('display_value'), list(map(itemgetter('target'), result.get(relation_type))))),
                'Type Display Value': list(
                    map(itemgetter('display_value'), list(map(itemgetter('type'), result.get(relation_type))))),
            }
            md += f' {tableToMarkdown(FIELD_TO_OUTPUT.get(relation_type), t=relation_output)}'
    return md


''' COMMAND FUNCTIONS '''


def records_list_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Query a CMDB table using the class name to receive all records in the class.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    context: dict = defaultdict(list)
    class_name = args.get('class')
    params = handle_sysparms(RECORDS_LIST_PARAMS, args)

    outputs = {
        'Class': class_name
    }

    response = client.records_list(class_name=class_name, params=params)
    result = response.get('result', {})
    if result:
        outputs['Records'] = result
        human_readable = tableToMarkdown(f'Found {len(result)} records for class {class_name}:', t=result)
    else:
        human_readable = f'Found no records for class {class_name}.'
    context['ServiceNowCMDB(val.ID===obj.ID)'] = outputs

    return human_readable, context, response


def get_record_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Query attributes and relationship information for a specific record.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    context: dict = defaultdict(list)
    class_name = args.get('class')
    sys_id = args.get('sys_id')
    params = handle_sysparms(RECORD_PARAMS, args)

    response = client.get_record(class_name=class_name, sys_id=sys_id, params=params)
    result = response.get('result')
    if result:
        context['ServiceNowCMDB.Record(val.ID===obj.ID)'] = {
            'Class': class_name,
            'SysID': sys_id,
            'Attributes': result.get('attributes', {}),
            'InboundRelations': result.get('inbound_relations', []),
            'OutboundRelations': result.get('outbound_relations', []),
        }
        hr_title = f'### Found the following attributes and relations for record {sys_id}:'
        human_readable = create_human_readable(hr_title, result)
    else:
        context['ServiceNowCMDB.Record(val.ID===obj.ID)'] = {
            'Class': class_name,
            'SysID': sys_id
        }
        human_readable = f'Found no attributes and relations for record {sys_id}.'

    return human_readable, context, response


def create_record_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Create a record with associated relations.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    context: dict = defaultdict(list)
    class_name = args.get('class')
    params = handle_sysparms(RECORD_PARAMS, args)

    data = create_request_data(CREAT_RECORD_DATA_FIELDS, args)
    print(data)

    response = client.create_record(class_name=class_name, params=params, data=str(data))
    result = response.get('result')
    if result:
        sys_id = result.get('attributes', {}).get('sys_id')
        context = create_record_context(class_name, sys_id, result)
        hr_title = f'### Record {sys_id} was created successfully.'
        human_readable = create_human_readable(hr_title, result)
    else:
        human_readable = 'Failed to create a new record.'

    return human_readable, context, response


def update_record_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Update a record with attributes given by the user.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    context: dict = defaultdict(list)
    class_name = args.get('class')
    sys_id = args.get('sys_id')

    params = handle_sysparms(RECORD_PARAMS, args)

    data = create_request_data(UPDATE_RECORD_DATA_FIELDS, args)

    response = client.update_record(class_name=class_name, sys_id=sys_id, data=str(data), params=params)
    result = response.get('result')
    if result:
        context = create_record_context(class_name, sys_id, result)
        hr_title = f'### Updated record {sys_id} successfully.'
        human_readable = create_human_readable(hr_title, result)
    else:
        human_readable = f'Failed to update record {sys_id}.'

    return human_readable, context, response


def add_relation_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Add new relations to an existing record.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    context: dict = defaultdict(list)
    class_name = args.get('class')
    sys_id = args.get('sys_id')

    params = handle_sysparms(RECORD_PARAMS, args)

    data = create_request_data(ADD_RELATION_DATA_FIELDS, args)

    response = client.add_relation(class_name=class_name, sys_id=sys_id, data=str(data), params=params)
    result = response.get('result')
    if result:
        context = create_record_context(class_name, sys_id, result)
        hr_title = f'### New relations were added to {sys_id} record successfully.'
        human_readable = create_human_readable(hr_title, result)
    else:
        human_readable = f'Failed to add new relations to record {sys_id}.'

    return human_readable, context, response


def delete_relation_command(client: Client, args: dict) -> Tuple[str, dict, Any]:
    """
    Delete relations for an existing record.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Demisto Outputs.
    """
    context: dict = defaultdict(list)
    class_name = args.get('class')
    sys_id = args.get('sys_id')
    rel_sys_id = args.get('relation_sys_id')

    params = handle_sysparms(RECORD_PARAMS, args)

    response = client.delete_relation(class_name=class_name, sys_id=sys_id, rel_sys_id=rel_sys_id, params=params)
    result = response.get('result')
    if result:
        context = create_record_context(class_name, sys_id, result)
        hr_title = f'### Deleted relation {rel_sys_id} successfully from {sys_id} record.'
        human_readable = create_human_readable(hr_title, result)
    else:
        human_readable = f'Failed to delete relation {rel_sys_id} from record {sys_id}.'

    return human_readable, context, response


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: ServiceNow CMDB client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        client.records_list(class_name='cmdb_ci_linux_server')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    params = demisto.params()
    params['url'] = urljoin(params.get('url'), API_VERSION)
    client = Client(params=params)

    commands = {
        'servicenow-cmdb-records-list': records_list_command,
        'servicenow-cmdb-record-get-by-id': get_record_command,
        'servicenow-cmdb-record-create': create_record_command,
        'servicenow-cmdb-record-update': update_record_command,
        'servicenow-cmdb-record-add-relations': add_relation_command,
        'servicenow-cmdb-record-delete-relations': delete_relation_command
    }

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            return_error('Command not found.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# from Packs.ApiModules.Scripts.ServiceNowApiModule.ServiceNowApiModule import ServiceNowClient  # noqa: E402
from ServiceNowApiModule import *

''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
