from CommonServerPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, Union
import urllib3

"""Example for Analytics and SIEM integration
"""
# Disable insecure warnings
urllib3.disable_warnings()

'''GLOBALS/PARAMS'''

INTEGRATION_NAME = 'cisco-fp'
# lowercase with `-` dividers
INTEGRATION_COMMAND_NAME = 'cisco-fp'
# No dividers
INTEGRATION_CONTEXT_NAME = 'cisco-fp'


class Client(BaseClient):

    def login(self):
        """update the X-auth-access-token in the client.
        """
        self._headers['X-auth-access-token'] = self._http_request(
            'POST',
            url_suffix='api/fmc_platform/v1/auth/generatetoken',
            resp_type='response'
        ).headers['X-auth-access-token']
        if self._headers['X-auth-access-token'] == '':
            return_error('No valid access token')
        return

    def cisco_fp_list_zones(self, limit, offset) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones' \
                 f'?expanded=true&limit={limit}&offset={offset}'
        return self._http_request('GET', suffix)

    def cisco_fp_list_ports(self, limit, offset) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ports' \
                 f'?expanded=true&limit={limit}&offset={offset}'
        return self._http_request('GET', suffix)

    def cisco_fp_list_url_categories(self, limit, offset) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/urlcategories' \
                 f'?expanded=true&limit={limit}&offset={offset}'
        return self._http_request('GET', suffix)

    def cisco_fp_get_network_objects(self, limit, offset, object_type, object_id) -> Dict:
        end_suffix = '/' + object_id if object_id else '?expanded=true&limit=' + limit + '&offset=' + offset
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/{object_type}{end_suffix}'
        return self._http_request('GET', suffix)

    def cisco_fp_create_network_objects(self, data, object_type) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/{object_type}'
        return self._http_request('POST', suffix, json_data=data)

    def cisco_fp_update_network_objects(self, data, object_type, object_id) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/{object_type}/{object_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def cisco_fp_delete_network_objects(self, object_type, object_id) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/{object_type}/{object_id}'
        return self._http_request('DELETE', suffix)

    def cisco_fp_get_network_groups_objects(self, limit, offset, object_id) -> Dict:
        end_suffix = '/' + object_id if object_id else '?expanded=true&limit=' + limit + '&offset=' + offset
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups{end_suffix}'
        return self._http_request('GET', suffix)

    def cisco_fp_create_network_groups_objects(self, data) -> Dict:
        suffix = 'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups'
        return self._http_request('POST', suffix, json_data=data)

    def cisco_fp_update_network_groups_objects(self, data) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/{data["id"]}'
        return self._http_request('PUT', suffix, json_data=data)

    def cisco_fp_delete_network_groups_objects(self, object_id) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/{object_id}'
        return self._http_request('DELETE', suffix)

    def cisco_fp_get_access_policy(self, limit, offset, policy_id) -> Dict:
        end_suffix = '/' + policy_id if policy_id else '?expanded=true&limit=' + limit + '&offset=' + offset
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies{end_suffix}'
        return self._http_request('GET', suffix)

    def cisco_fp_create_access_policy(self, data) -> Dict:
        suffix = 'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies'
        return self._http_request('POST', suffix, json_data=data)

    def cisco_fp_update_access_policy(self, data) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/{data["id"]}'
        return self._http_request('PUT', suffix, json_data=data)

    def cisco_fp_delete_access_policy(self, policy_id) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/{policy_id}'
        return self._http_request('DELETE', suffix)

    def cisco_fp_get_list(self, suffix) -> Dict:
        return self._http_request('GET', suffix)

    def cisco_fp_create_policy_assignments(self, data) -> Dict:
        suffix = 'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments'
        return self._http_request('POST', suffix, json_data=data)

    def cisco_fp_update_policy_assignments(self, data, pol_id) -> Dict:
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments/{pol_id}'
        return self._http_request('POST', suffix, json_data=data)

    def cisco_get_access_rules(self, args) -> Dict:
        limit = args.get('limit', 50)
        offset = args.get('offset', 0)
        policy_id = args.get('policy_id')
        rule_id = f'?expanded=true&limit={limit}&offset={offset}' if args.get('rule_id', '') == '' \
            else '/' + args.get('rule_id', '')
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/' \
                 f'{policy_id}/accessrules{rule_id}'
        return self._http_request('GET', suffix)

    def cisco_fp_create_access_rules(self, args) -> Dict:
        policy_id = args.get('policy_id')
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/' \
                 f'{policy_id}/accessrules'
        del args['policy_id']
        return self._http_request('POST', suffix, json_data=args)

    def cisco_fp_delete_access_rules(self, args) -> Dict:
        policy_id = args.get('policy_id')
        rule_id = args.get('rule_id')
        suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies/' \
                 f'{policy_id}/accessrules{rule_id}'
        return self._http_request('DELETE', suffix)

    def cisco_fp_deploy_to_devices(self, data) -> Dict:
        suffix = 'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests'
        return self._http_request('POST', suffix, json_data=data)


''' HELPER FUNCTIONS '''


def raw_response_to_context(list_key, items):
    if isinstance(items, list):
        return [raw_response_to_context(list_key, item) for item in items]
    list_to_output = {}
    for key in list_key:
        if type(list_key[key]) == dict:
            if key in items:
                list_to_output[key] = raw_response_to_context(list_key[key], items[key])
        elif type(list_key[key]) == list:
            in_list = list_key[key]
            list_to_output[key] = items[in_list[0]][in_list[1]]
        else:
            list_to_output[key] = items.get(list_key[key], '')
    return list_to_output


def switch_list_to_list_counter(data: Union[Dict, List]) -> Union[Dict, List]:
    if isinstance(data, list):
        return [switch_list_to_list_counter(dat) for dat in data]
    new_data = {}
    for item in data:
        if type(data[item]) == list:
            new_data[item] = len(data[item])
        elif type(data[item]) == dict:
            counter = 0
            for in_item in data[item]:
                if type(data[item][in_item]) == list:
                    counter += len(data[item][in_item])
            new_data[item] = counter if counter > 0 else 1
        else:
            new_data[item] = data[item]
    return new_data


def creates_list_of_dictionary(value: str, type_name: str, value_key: str):
    id_list = argToList(value)
    objects = []
    for current_id in id_list:
        if value_key == '':
            objects.append(current_id)
        elif type_name == '':
            objects.append({value_key: current_id})
        else:
            objects.append({value_key: current_id, 'type': type_name})
    return objects


def raw_response_to_context_ruls(items):
    list_to_output = {
        'ID': 'id',
        'Name': 'name',
        'Action': 'action',
        'Enabled': 'enabled',
        'SendEventsToFMC': 'sendEventsToFMC',
        'RuleIndex': ['metadata', 'ruleIndex'],
        'Section': ['metadata', 'section'],
        'Category': ['metadata', 'category'],
        'urls': {
            'literals': {'URL': 'url'},
            'objects': {'Name': 'name', 'ID': 'id'}},
        'vlanTags': {
            'objects': {'Name': 'name', 'ID': 'id', 'Type': 'type'},
            'literals': {'EndTag': 'endTag', 'StartTag': 'startTag'}},
        'sourceZones': {'objects': {'Name': 'name', 'ID': 'id', 'Type': 'type'}},
        'applications': {'applications': {'Name': 'name', 'ID': 'id'}},
        'destinationZones': {'objects': {'Name': 'name', 'ID': 'id', 'Type': 'type'}},
        'sourceNetworks': {
            'objects': {'Name': 'name', 'ID': 'id', 'Type': 'type'},
            'literals': {'Type': 'type', 'Value': 'value'}},
        'destinationNetworks': {
            'objects': {'Name': 'name', 'ID': 'id', 'Type': 'type'},
            'literals': {'Type': 'type', 'Value': 'value'}},
        'sourcePorts': {
            'objects': {'Name': 'name', 'ID': 'id', 'Type': 'type', 'Protocol': 'protocol'},
            'literals': {'Port': 'port', 'Protocol': 'protocol'}},
        'destinationPorts': {
            'objects': {'Name': 'name', 'ID': 'id', 'Type': 'type', 'Protocol': 'protocol'},
            'literals': {'Port': 'port', 'Protocol': 'protocol'}},
        'sourceSecurityGroupTags': {'objects': {'Name': 'name', 'ID': 'id', 'Type': 'type'}}
    }
    return raw_response_to_context(list_to_output, items)


''' COMMANDS '''
@logger
def test_module_command(client: Client, *_) -> Tuple[str, None, None]:
    return 'ok', None, None


@logger
def list_zones_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.cisco_fp_list_zones(limit, offset)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List zones:'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'InterFaceMode': 'interfaceMode',
            'interfaces': {'Name': 'name', 'ID': 'id'}
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Zone(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'interfaceMode', 'interfaces']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any zone.', {}, {}


def list_ports_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.cisco_fp_list_ports(limit, offset)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List ports:'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Protocol': 'protocol',
            'Port': 'port'
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Port(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any port.', {}, {}


def list_url_categories_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.cisco_fp_list_url_categories(limit, offset)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List url categories:'
        list_to_output = {
            'ID': 'id',
            'Name': 'name'
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Category(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any category.', {}, {}


def get_network_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    object_type = args.get('type', 'networks')
    object_id = args.get('object_id', '')
    type_to_output = 'Networks' if object_type == 'networks' else 'Hosts'

    raw_response = client.cisco_fp_get_network_objects(limit, offset, object_type, object_id)
    items = raw_response.get('items')
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List {object_type} objects:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - get {object_type} object {object_id}'
            items = raw_response
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Value': 'value',
            'Overridable': 'overridable',
            'Description': 'description'
        }
        print('hh')
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.{type_to_output}(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any object.', {}, {}


def get_host_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    args['type'] = 'hosts'
    return get_network_objects_command(client, args)


def create_network_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    if 'name' in args and 'value' in args:
        object_type = args.get('type', 'networks')
        type_to_output = 'Networks' if object_type == 'networks' else 'Hosts'

        data_to_post = {}
        for key in args:
            data_to_post[key] = args.get(key)

        if type in data_to_post:
            del data_to_post['type']
        raw_response = client.cisco_fp_create_network_objects(data_to_post, object_type)
        title = f'{INTEGRATION_NAME} - {object_type} object has been created.'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Value': 'value',
            'Overridable': 'overridable',
            'Description': 'description'
        }
        context_entry = raw_response_to_context(list_to_output, raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.{type_to_output}(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not create new object.')


def create_host_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    args['type'] = 'hosts'
    return create_network_objects_command(client, args)


def update_network_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    if 'name' in args and 'value' in args and 'id' in args:
        object_type = args.get('type', 'networks')
        type_to_output = 'Networks' if object_type == 'networks' else 'Hosts'

        object_id = args.get('id')
        data_to_post = {}
        for key in args:
            data_to_post[key] = args.get(key)
        if type in data_to_post:
            del data_to_post['type']

        raw_response = client.cisco_fp_update_network_objects(data_to_post, object_type, object_id)
        title = f'{INTEGRATION_NAME} - {object_type} object has been updated.'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Value': 'value',
            'Overridable': 'overridable',
            'Description': 'description'
        }
        context_entry = raw_response_to_context(list_to_output, raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.{type_to_output}(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not update the object.')


def update_host_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    args['type'] = 'hosts'
    return update_network_objects_command(client, args)


def delete_network_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    if 'id' in args:
        object_type = args.get('type', 'networks')
        object_id = args.get('id')
        type_to_output = 'Networks' if object_type == 'networks' else 'Hosts'
        raw_response = client.cisco_fp_delete_network_objects(object_type, object_id)
        title = f'{INTEGRATION_NAME} - {object_type} object has been deleted.'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Value': 'value',
            'Overridable': 'overridable',
            'Description': 'description'
        }
        context_entry = raw_response_to_context(list_to_output, raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.{type_to_output}(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not delete the object.')


def delete_host_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    args['type'] = 'hosts'
    return delete_network_objects_command(client, args)


def get_network_groups_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    object_id = args.get('id', '')
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    raw_response = client.cisco_fp_get_network_groups_objects(limit, offset, object_id)
    items = raw_response.get('items')
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List of network groups object:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - network group object:'
            items = raw_response
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Overridable': 'overridable',
            'Description': 'description',
            'objects': {'Type': 'type', 'Name': 'name', 'ID': 'id'},
            'literals': {'Type': 'type', 'Value': 'value'}
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'literals', 'objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not delete the object.')


def create_network_groups_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    if 'name' in args and 'id_list' or 'value_list':
        data_to_post = {'name': args.get('name')}
        ids = args.get('id_list', '')
        values = args.get('value_list', '')
        if ids:
            data_to_post['objects'] = creates_list_of_dictionary(ids, '', 'id')
        if values:
            data_to_post['literals'] = creates_list_of_dictionary(values, '', 'value')

        raw_response = client.cisco_fp_create_network_groups_objects(data_to_post)
        title = f'{INTEGRATION_NAME} - network group has been created.'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Overridable': 'overridable',
            'Description': 'description',
            'objects': {'Type': 'type', 'Name': 'name', 'ID': 'id'},
            'literals': {'Type': 'type', 'Value': 'value'}
        }
        context_entry = raw_response_to_context(list_to_output, raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'literals', 'objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not create new group.')


def update_network_groups_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    if 'name' in args and 'id_list' or 'value_list':
        data_to_post = {'name': args.get('name'), 'id': args.get('id')}
        ids = args.get('id_list', '')
        values = args.get('value_list', '')
        if ids:
            data_to_post['objects'] = creates_list_of_dictionary(ids, '', 'id')
        if values:
            data_to_post['literals'] = creates_list_of_dictionary(values, '', 'value')

        raw_response = client.cisco_fp_update_network_groups_objects(data_to_post)
        title = f'{INTEGRATION_NAME} - network group has been updated.'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Overridable': 'overridable',
            'Description': 'description',
            'objects': {'Type': 'type', 'Name': 'name', 'ID': 'id'},
            'literals': {'Type': 'type', 'Value': 'value'}
        }
        context_entry = raw_response_to_context(list_to_output, raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'literals', 'objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not update the group.')


def delete_network_groups_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    if 'id' in args:
        object_id = args['id']
        raw_response = client.cisco_fp_delete_network_groups_objects(object_id)
        title = f'{INTEGRATION_NAME} - network group - {object_id} - has been delete.'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Overridable': 'overridable',
            'Description': 'description',
            'objects': {'Type': 'type', 'Name': 'name', 'ID': 'id'},
            'literals': {'Type': 'type', 'Value': 'value'}
        }
        context_entry = raw_response_to_context(list_to_output, raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'literals', 'objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not delete the group.')


def get_access_policy_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    policy_id = args.get('id', '')
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    raw_response = client.cisco_fp_get_access_policy(limit, offset, policy_id)
    items = raw_response.get('items')
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List access policy:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - get access policy'
            items = raw_response
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'DefaultActionID': ['defaultAction', 'id'],
            'Action': ['defaultAction', 'action']
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any access policy.', {}, {}


def create_access_policy_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    data_to_post = {
        'name': args.get('name'),
        'defaultAction': {
            'action': args.get('action')
        }}
    raw_response = client.cisco_fp_create_access_policy(data_to_post)
    title = f'{INTEGRATION_NAME} - access policy has been created.'
    list_to_output = {
        'ID': 'id',
        'Name': 'name',
        'DefaultActionID': ['defaultAction', 'id'],
        'Action': ['defaultAction', 'action']
    }
    context_entry = raw_response_to_context(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    human_readable = tableToMarkdown(title, context_entry)
    return human_readable, context, raw_response


def update_access_policy_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    data_to_post = {
        'name': args.get('name'),
        'id': args.get('id'),
        'defaultAction': {
            'action': args.get('action'),
            'id': args.get('default_action_id')
        }}
    raw_response = client.cisco_fp_update_access_policy(data_to_post)
    title = f'{INTEGRATION_NAME} - access policy has been updated.'
    list_to_output = {
        'ID': 'id',
        'Name': 'name',
        'DefaultActionID': ['defaultAction', 'id'],
        'Action': ['defaultAction', 'action']
    }
    context_entry = raw_response_to_context(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    human_readable = tableToMarkdown(title, context_entry)
    return human_readable, context, raw_response


def delete_access_policy_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    policy_id = args.get('id')
    raw_response = client.cisco_fp_delete_access_policy(policy_id)
    title = f'{INTEGRATION_NAME} - access policy deleted.'
    list_to_output = {
        'ID': 'id',
        'Name': 'name',
        'DefaultActionID': ['defaultAction', 'id'],
        'Action': ['defaultAction', 'action']
    }
    context_entry = raw_response_to_context(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    human_readable = tableToMarkdown(title, context_entry)
    return human_readable, context, raw_response


def list_security_group_tags_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    ise = args.get('ise', '')
    suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/{ise}securitygrouptags' \
             f'?expanded=true&limit={limit}&offset={offset}'
    raw_response = client.cisco_fp_get_list(suffix)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List {ise}security group tags:'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Tag': 'tag'
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.{ise}SecurityGroupTags(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any {ise}security group tags.', {}, {}


def list_ise_security_group_tags_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    args['ise'] = 'ise'
    return list_security_group_tags_command(client, args)


def list_vlan_tags_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/vlantags' \
             f'?expanded=true&limit={limit}&offset={offset}'
    raw_response = client.cisco_fp_get_list(suffix)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List vlan tags:'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Overridable': 'overridable',
            'Description': 'description',
            'StartTag': ['data', 'startTag'],
            'EndTag': ['data', 'endTag']
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.VlanTags(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any vlan tags.', {}, {}


def list_vlan_tags_group_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/vlangrouptags' \
             f'?expanded=true&limit={limit}&offset={offset}'
    raw_response = client.cisco_fp_get_list(suffix)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of vlan tags groups objects:'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'Overridable': 'overridable',
            'Description': 'description',
            'objects': {
                'ID': 'id',
                'Name': 'name',
                'Overridable': 'overridable',
                'Description': 'description',
                'StartTag': ['data', 'startTag'],
                'EndTag': ['data', 'endTag']
            }
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.VlanTags_group(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'objects']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any vlan tags group.', {}, {}


def list_applications_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/applications' \
             f'?expanded=true&limit={limit}&offset={offset}'
    raw_response = client.cisco_fp_get_list(suffix)
    items = raw_response.get('items')
    if items:
        list_to_output = {
            'applicationTypes': {'applicationTypes': 'name'},
            'appCategories': {'Name': 'name', 'ID': 'id', 'Count': ['metadata', 'count']},
            'Name': 'name',
            'ID': 'id',
            'Risk': ['risk', 'name'],
            'AppProductivity': ['appProductivity', 'name']
        }
        title = f'{INTEGRATION_NAME} - List of applications objects:'
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Applications(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any applications.', {}, {}


def get_access_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    raw_response = client.cisco_get_access_rules(args)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of access rules:'
    elif 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - access rule:'
        items = raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any access rule.', {}, {}
    context_entry = raw_response_to_context_ruls(items)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    human_readable = tableToMarkdown(title, entry_white_list_count)
    return human_readable, context, raw_response


def create_access_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:

    data_to_post = {}
    if 'source_zone_object_ids' in args:
        data_to_post['sourceZones'] = {
            'objects': creates_list_of_dictionary(args['source_zone_object_ids'], 'SecurityZone', 'id')}
    if 'destination_zone_object_ids' in args:
        data_to_post['destinationZones'] = {
            'objects': creates_list_of_dictionary(args['destination_zone_object_ids'], 'SecurityZone', 'id')}
    if 'vlan_tag_object_ids' in args:
        data_to_post['vlanTags'] = {
            'objects': creates_list_of_dictionary(args['vlan_tag_object_ids'], 'vlanTags', 'id')}
    if 'source_network_object_ids' in args:
        data_to_post['sourceNetworks'] = {
            'objects': creates_list_of_dictionary(args['source_network_object_ids'], 'NetworkGroup', 'id')}
    if 'source_network_addresses' in args:
        if 'sourceNetworks' in data_to_post:
            data_to_post['sourceNetworks']['literals'] = \
                creates_list_of_dictionary(args['source_network_addresses'], 'Host', 'value')
        else:
            data_to_post['sourceNetworks'] = {
                'literals': creates_list_of_dictionary(args['source_network_addresses'], 'Host', 'value')}
    if 'destination_network_object_ids' in args:
        data_to_post['destinationNetworks'] = {
            'objects': creates_list_of_dictionary(args['destination_network_object_ids'], 'NetworkGroup', 'id')}
    if 'destination_network_addresses' in args:
        if 'destinationNetworks' in data_to_post:
            data_to_post['destinationNetworks']['literals'] = \
                creates_list_of_dictionary(args['destination_network_addresses'], 'Host', 'value')
        else:
            data_to_post['destinationNetworks'] = {
                'literals': creates_list_of_dictionary(args['destination_network_addresses'], 'Host', 'value')}
    if 'source_port_object_ids' in args:
        data_to_post['sourcePorts'] = {
            'objects': creates_list_of_dictionary(args['source_port_object_ids'], 'ProtocolPortObject', 'id')}
    if 'destination_port_object_ids' in args:
        data_to_post['destinationPorts'] = {
            'objects': creates_list_of_dictionary(args['destination_port_object_ids'], 'ProtocolPortObject', 'id')}
    if 'source_security_group_tag_object_ids' in args:
        data_to_post['sourceSecurityGroupTags'] = {
            'objects':
                creates_list_of_dictionary(args['source_security_group_tag_object_ids'], 'SecurityGroupTag', 'id')}
    if 'application_object_ids' in args:
        data_to_post['applications'] = {
            'applications': creates_list_of_dictionary(args['application_object_ids'], 'Application', 'id')}
    if 'url_object_ids' in args:
        data_to_post['urls'] = {'objects': creates_list_of_dictionary(args['url_object_ids'], 'Url', 'id')}
    if 'url_addresses' in args:
        if 'urls' in data_to_post:
            data_to_post['urls']['literals'] = creates_list_of_dictionary(args['url_addresses'], 'Url', 'url')
        else:
            data_to_post['urls'] = {'literals': creates_list_of_dictionary(args['url_addresses'], 'Url', 'url')}
    if 'enabled' in args:
        data_to_post['enabled'] = args['enabled']

    data_to_post['name'] = args['rule_name']
    data_to_post['policy_id'] = args['policy_id']
    data_to_post['action'] = args['action']

    print(data_to_post)
    raw_response = client.cisco_fp_create_access_rules(data_to_post)
    title = f'{INTEGRATION_NAME} - the new access rule:'
    context_entry = raw_response_to_context_ruls(raw_response)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    human_readable = tableToMarkdown(title, entry_white_list_count)
    return human_readable, context, raw_response


def delete_access_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    raw_response = client.cisco_fp_delete_access_rules(args)
    title = f'{INTEGRATION_NAME} - deleted access rule:'
    context_entry = raw_response_to_context_ruls(raw_response)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    human_readable = tableToMarkdown(title, entry_white_list_count)
    return human_readable, context, raw_response


def list_policy_assignments_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/assignment/policyassignments' \
             f'?expanded=true&limit={limit}&offset={offset}'
    raw_response = client.cisco_fp_get_list(suffix)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of policy assignments:'
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'PolicyName': ['policy', 'name'],
            'PolicyID': ['policy', 'id'],
            'PolicyDescription': ['policy', 'description'],
            'targets': {
                'ID': 'id',
                'Name': 'name',
                'Type': 'type'
            }
        }
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any policy assignments.', {}, {}


def create_policy_assignments_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    data_to_post = {}
    if 'device_ids' in args:
        data_to_post['targets'] = creates_list_of_dictionary(args['device_ids'], 'Device', 'id')
    if 'device_group_ids' in args:
        if 'targets' in data_to_post:
            data_to_post['targets'].extend(creates_list_of_dictionary(args['device_group_ids'], 'DeviceGroup', 'id'))
        else:
            data_to_post['targets'] = creates_list_of_dictionary(args['device_group_ids'], 'DeviceGroup', 'id')
    data_to_post['policy'] = {'id': args.get('policy_id')}
    data_to_post['type'] = 'PolicyAssignment'

    print(data_to_post)
    raw_response = client.cisco_fp_create_policy_assignments(data_to_post)
    title = f'{INTEGRATION_NAME} - Policy assignments has been done.'
    list_to_output = {
        'ID': 'id',
        'Name': 'name',
        'PolicyName': ['policy', 'name'],
        'PolicyID': ['policy', 'id'],
        'targets': {
            'ID': 'id',
            'Name': 'name',
            'Type': 'type'
        }
    }
    context_entry = raw_response_to_context(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
    }
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    human_readable = tableToMarkdown(title, entry_white_list_count)
    return human_readable, context, raw_response


def update_policy_assignments_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    data_to_post = {}
    policy_id = args.get('policy_id')
    if 'device_ids' in args:
        data_to_post['targets'] = creates_list_of_dictionary(args['device_ids'], 'Device', 'id')
    if 'device_group_ids' in args:
        if 'targets' in data_to_post:
            data_to_post['targets'].extend(creates_list_of_dictionary(args['device_group_ids'], 'DeviceGroup', 'id'))
        else:
            data_to_post['targets'] = creates_list_of_dictionary(args['device_group_ids'], 'DeviceGroup', 'id')
    data_to_post['policy'] = {'id': args.get('policy_id')}
    data_to_post['type'] = 'PolicyAssignment'

    print(data_to_post)
    raw_response = client.cisco_fp_update_policy_assignments(data_to_post, policy_id)
    title = f'{INTEGRATION_NAME} - policy update has been done.'
    list_to_output = {
        'ID': 'id',
        'Name': 'name',
        'PolicyName': ['policy', 'name'],
        'PolicyID': ['policy', 'id'],
        'targets': {
            'ID': 'id',
            'Name': 'name',
            'Type': 'type'
        }
    }
    context_entry = raw_response_to_context(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
    }
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    human_readable = tableToMarkdown(title, entry_white_list_count)
    return human_readable, context, raw_response


def get_deployable_devices_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deployabledevices' \
             f'?expanded=true&limit={limit}&offset={offset}'
    raw_response = client.cisco_fp_get_list(suffix)
    items = raw_response.get('items')
    if items:
        list_to_output = {
            'CanBeDeployed': 'canBeDeployed',
            'UpToDate': 'upToDate',
            'DeviceId': ['device', 'id'],
            'DeviceName': ['device', 'name'],
            'DeviceType': ['device', 'type'],
            'Version': 'version'
        }
        title = f'{INTEGRATION_NAME} - List of deployable devices:'
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.DeployableDevices(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any deployable devices.', {}, {}


def get_device_records_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords' \
             f'?expanded=true&limit={limit}&offset={offset}'
    raw_response = client.cisco_fp_get_list(suffix)
    items = raw_response.get('items')
    if items:
        list_to_output = {
            'ID': 'id',
            'Name': 'name',
            'HostName': 'hostName',
            'Type': 'type',
            'deviceGroup': {'id': 'id'}
        }
        title = f'{INTEGRATION_NAME} - List of device records:'
        context_entry = raw_response_to_context(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.DeviceRecords(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any device records.', {}, {}


def deploy_to_devices_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    data_to_post = {}
    if 'device_ids' in args:
        data_to_post['deviceList'] = creates_list_of_dictionary(args['device_ids'], '', '')
    data_to_post['forceDeploy'] = args.get('force_deploy')
    data_to_post['ignoreWarning'] = args.get('ignore_warning')
    data_to_post['version'] = args.get('version')

    print(data_to_post)
    raw_response = client.cisco_fp_deploy_to_devices(data_to_post)
    title = f'{INTEGRATION_NAME} - devices requests to deploy.'
    context_entry = {
        'TaskID': raw_response.get('metadata', {}).get('task', {}).get('id', ''),
        'ForceDeploy': raw_response.get('forceDeploy'),
        'IgnoreWarning': raw_response.get('ignoreWarning'),
        'Version': raw_response.get('version'),
        'DeviceList': raw_response.get('deviceList')
    }
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Deploy(val.ID && val.ID === obj.ID)': context_entry
    }
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    human_readable = tableToMarkdown(title, entry_white_list_count)
    return human_readable, context, raw_response


def get_task_status_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    task_id = args.get('task_id')
    suffix = f'api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/job/taskstatuses/{task_id}'
    raw_response = client.cisco_fp_get_list(suffix)
    if 'status' in raw_response:
        context_entry = {
            'Status': raw_response.get('status')
        }
        title = f'{INTEGRATION_NAME} - {task_id} status:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.TaskStatus(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any status.', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = urljoin(params.get('url'))
    username = params['username']
    password = params['password']
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    headers = {'X-auth-access-token': ''}
    client = Client(base_url=base_url, verify=verify_ssl, proxy=proxy, auth=(username, password), headers=headers)

    client.login()

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-list-zones': list_zones_command,
        f'{INTEGRATION_COMMAND_NAME}-list-ports': list_ports_command,
        f'{INTEGRATION_COMMAND_NAME}-list-url-categories': list_url_categories_command,

        f'{INTEGRATION_COMMAND_NAME}-get-network-object': get_network_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-create-network-object': create_network_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-update-network-object': update_network_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-network-object': delete_network_objects_command,

        f'{INTEGRATION_COMMAND_NAME}-get-host-object': get_host_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-create-host-object': create_host_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-update-host-object': update_host_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-host-object': delete_host_objects_command,

        f'{INTEGRATION_COMMAND_NAME}-get-network-groups-object': get_network_groups_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-create-network-groups-objects': create_network_groups_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-update-network-groups-objects': update_network_groups_objects_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-network-groups-objects': delete_network_groups_objects_command,

        f'{INTEGRATION_COMMAND_NAME}-get-access-policy': get_access_policy_command,
        f'{INTEGRATION_COMMAND_NAME}-create-access-policy': create_access_policy_command,
        f'{INTEGRATION_COMMAND_NAME}-update-access-policy': update_access_policy_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-access-policy': delete_access_policy_command,

        f'{INTEGRATION_COMMAND_NAME}-list-security-group-tags': list_security_group_tags_command,
        f'{INTEGRATION_COMMAND_NAME}-list-ise-security-group-tags': list_ise_security_group_tags_command,
        f'{INTEGRATION_COMMAND_NAME}-list-vlan-tags': list_vlan_tags_command,
        f'{INTEGRATION_COMMAND_NAME}-list-vlan-tags-group': list_vlan_tags_group_command,
        f'{INTEGRATION_COMMAND_NAME}-list-applications': list_applications_command,

        f'{INTEGRATION_COMMAND_NAME}-get-access-rules': get_access_rules_command,
        f'{INTEGRATION_COMMAND_NAME}-create-access-rules': create_access_rules_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-access-rules': delete_access_rules_command,

        f'{INTEGRATION_COMMAND_NAME}-list-policy-assignments': list_policy_assignments_command,
        f'{INTEGRATION_COMMAND_NAME}-create-policy-assignments': create_policy_assignments_command,
        f'{INTEGRATION_COMMAND_NAME}-update-policy-assignments': update_policy_assignments_command,

        f'{INTEGRATION_COMMAND_NAME}-get-deployable-devices': get_deployable_devices_command,
        f'{INTEGRATION_COMMAND_NAME}-get-device-records': get_device_records_command,
        f'{INTEGRATION_COMMAND_NAME}-deploy-to-devices': deploy_to_devices_command,
        f'{INTEGRATION_COMMAND_NAME}-get-task-status': get_task_status_command

    }
    try:

        if command in commands:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)

    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':  # pragma: no cover
    main()
