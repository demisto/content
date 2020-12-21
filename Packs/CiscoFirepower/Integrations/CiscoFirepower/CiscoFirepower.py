from CommonServerPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, Union
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

'''GLOBALS/PARAMS'''

INTEGRATION_NAME = 'Cisco Firepower'

INTEGRATION_CONTEXT_NAME = 'CiscoFP'

OUTPUT_KEYS_DICTIONARY = {
    'id': 'ID'
}


class Client(BaseClient):
    def login(self):
        """update the X-auth-access-token in the client.
        """
        new_headers = self._http_request(
            'POST',
            url_suffix='/api/fmc_platform/v1/auth/generatetoken',
            resp_type='response'
        ).headers
        self._headers = {'X-auth-access-token': new_headers.get('X-auth-access-token')}
        self._base_url += f'/api/fmc_config/v1/domain/{new_headers.get("DOMAIN_UUID")}/'
        if self._headers['X-auth-access-token'] == '':
            return_error('No valid access token')

    def get_list(self, limit: int, offset: int, object_path: str) -> Dict:
        params = {'expanded': 'true', 'limit': limit, 'offset': offset}
        suffix = f'object/{object_path}'
        return self._http_request('GET', suffix, params=params)

    def list_policy_assignments(self, limit: int, offset: int) -> Dict:
        params = {'expanded': 'true', 'limit': limit, 'offset': offset}
        suffix = 'assignment/policyassignments'
        return self._http_request('GET', suffix, params=params)

    def get_deployable_devices(self, limit: int, offset: int) -> Dict:
        params = {'expanded': 'true', 'limit': limit, 'offset': offset}
        suffix = 'deployment/deployabledevices'
        return self._http_request('GET', suffix, params=params)

    def get_device_records(self, limit: int, offset: int) -> Dict:
        params = {'expanded': 'true', 'limit': limit, 'offset': offset}
        suffix = 'devices/devicerecords'
        return self._http_request('GET', suffix, params=params)

    def get_network_objects(self, limit: int, offset: int, object_id: str) -> Dict:
        end_suffix = f'/{object_id}' if object_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'object/networks{end_suffix}'
        return self._http_request('GET', suffix)

    def get_hosts_objects(self, limit: int, offset: int, object_id: str) -> Dict:
        end_suffix = f'/{object_id}' if object_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'object/hosts{end_suffix}'
        return self._http_request('GET', suffix)

    def create_network_objects(self, name: str, value: str, description: str, overridable: bool) -> Dict:
        data = {'name': name, 'value': value, 'description': description, 'overridable': overridable}
        suffix = 'object/networks'
        return self._http_request('POST', suffix, json_data=data)

    def create_host_objects(self, name: str, value: str, description: str, overridable: bool) -> Dict:
        data = {'name': name, 'value': value, 'description': description, 'overridable': overridable}
        suffix = 'object/hosts'
        return self._http_request('POST', suffix, json_data=data)

    def update_network_objects(
            self, name: str, value: str, description: str, overridable: bool, object_id: str) -> Dict:
        data = assign_params(id=object_id, name=name, value=value, description=description, overridable=overridable)
        suffix = f'object/networks/{object_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def update_host_objects(self, name: str, value: str, description: str, overridable: bool, object_id: str) -> Dict:
        data = assign_params(id=object_id, name=name, value=value, description=description, overridable=overridable)
        suffix = f'object/hosts/{object_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def delete_network_objects(self, object_id: str) -> Dict:
        suffix = f'object/networks/{object_id}'
        return self._http_request('DELETE', suffix)

    def delete_host_objects(self, object_id: str) -> Dict:
        suffix = f'object/hosts/{object_id}'
        return self._http_request('DELETE', suffix)

    def get_network_groups_objects(self, limit: int, offset: int, object_id: str) -> Dict:
        end_suffix = f'/{object_id}' if object_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'object/networkgroups{end_suffix}'
        return self._http_request('GET', suffix)

    def create_network_groups_objects(
            self, name: str, ids: str, values: str, description: str, overridable: bool) -> Dict:
        objects = [{'id': curr_id} for curr_id in argToList(ids)]
        values = [{'value': curr_value} for curr_value in argToList(values)]
        data = assign_params(
            name=name, objects=objects, literals=values, description=description, overridable=overridable)
        suffix = 'object/networkgroups'
        return self._http_request('POST', suffix, json_data=data)

    def update_network_groups_objects(
            self, name: str, ids: str, values: str, group_id: str, description: str, overridable: bool) -> Dict:
        objects = [{'id': curr_id} for curr_id in argToList(ids)]
        values = [{'value': curr_value} for curr_value in argToList(values)]
        data = assign_params(name=name, id=group_id, objects=objects, literals=values,
                             description=description, overridable=overridable)
        suffix = f'object/networkgroups/{group_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def delete_network_groups_objects(self, object_id: str) -> Dict:
        suffix = f'object/networkgroups/{object_id}'
        return self._http_request('DELETE', suffix)

    def get_access_policy(self, limit: int, offset: int, policy_id: str) -> Dict:
        end_suffix = f'/{policy_id}' if policy_id else f'?expanded=true&limit={limit}&offset={offset}'
        suffix = f'policy/accesspolicies{end_suffix}'
        return self._http_request('GET', suffix)

    def create_access_policy(self, name: str, action: str) -> Dict:
        data = {'name': name, 'defaultAction': {'action': action}}
        suffix = 'policy/accesspolicies'
        return self._http_request('POST', suffix, json_data=data)

    def update_access_policy(self, name: str, policy_id: str, action: str, action_id: str) -> Dict:
        data = {
            'name': name,
            'id': policy_id,
            'defaultAction': {
                'action': action,
                'id': action_id
            }}
        suffix = f'policy/accesspolicies/{policy_id}'
        return self._http_request('PUT', suffix, json_data=data)

    def delete_access_policy(self, policy_id: str) -> Dict:
        suffix = f'policy/accesspolicies/{policy_id}'
        return self._http_request('DELETE', suffix)

    def get_task_status(self, task_id: str) -> Dict:
        suffix = f'job/taskstatuses/{task_id}'
        return self._http_request('GET', suffix)

    def create_policy_assignments(self, policy_id: str, device_ids: str, device_group_ids: str) -> Dict:
        targets = [{'id': curr_id, 'type': 'Device'} for curr_id in argToList(device_ids)]
        targets.extend([{'id': curr_id, 'type': 'DeviceGroup'} for curr_id in argToList(device_group_ids)])
        data_to_post = assign_params(policy={'id': policy_id}, type='PolicyAssignment', targets=targets)
        suffix = 'assignment/policyassignments'
        return self._http_request('POST', suffix, json_data=data_to_post)

    def update_policy_assignments(self, policy_id: str, device_ids: str, device_group_ids: str) -> Dict:
        targets = [{'id': curr_id, 'type': 'Device'} for curr_id in argToList(device_ids)]
        targets.extend([{'id': curr_id, 'type': 'DeviceGroup'} for curr_id in argToList(device_group_ids)])
        data_to_post = assign_params(policy={'id': policy_id}, type='PolicyAssignment', targets=targets)
        suffix = f'assignment/policyassignments/{policy_id}'
        return self._http_request('POST', suffix, json_data=data_to_post)

    def get_access_rules(self, limit: int, offset: int, policy_id: str, rule_id: str) -> Dict:
        end_suffix = f'?expanded=true&limit={limit}&offset={offset}' if rule_id == '' else '/' + rule_id
        suffix = f'policy/accesspolicies/{policy_id}/accessrules{end_suffix}'
        return self._http_request('GET', suffix)

    def create_access_rules(
            self,
            source_zone_object_ids: str,
            destination_zone_object_ids: str,
            vlan_tag_object_ids: str,
            source_network_object_ids: str,
            source_network_addresses: str,
            destination_network_object_ids: str,
            destination_network_addresses: str,
            source_port_object_ids: str,
            destination_port_object_ids: str,
            source_security_group_tag_object_ids: str,
            application_object_ids: str,
            url_object_ids: str,
            url_addresses: str,
            enabled: bool,
            name: str,
            policy_id: str,
            action: str
    ) -> Dict:
        sourceZones = {'objects': [{'id': curr_id, 'type': 'SecurityZone'
                                    } for curr_id in argToList(source_zone_object_ids)]}
        destinationZones = {'objects': [{'id': curr_id, 'type': 'SecurityZone'
                                         } for curr_id in argToList(destination_zone_object_ids)]}
        vlanTags = {'objects': [{'id': curr_id, 'type': 'vlanTags'} for curr_id in argToList(vlan_tag_object_ids)]}
        sourceNetworks = assign_params(
            objects=[{'id': curr_id, 'type': 'NetworkGroup'} for curr_id in argToList(source_network_object_ids)],
            literals=[{'value': curr_id, 'type': 'Host'} for curr_id in argToList(source_network_addresses)])
        destinationNetworks = assign_params(
            objects=[{'id': curr_id, 'type': 'NetworkGroup'} for curr_id in argToList(destination_network_object_ids)],
            literals=[{'value': curr_id, 'type': 'Host'} for curr_id in argToList(destination_network_addresses)])
        sourcePorts = {'objects': [{'id': curr_id, 'type': 'ProtocolPortObject'
                                    } for curr_id in argToList(source_port_object_ids)]}
        destinationPorts = {'objects': [{'id': curr_id, 'type': 'ProtocolPortObject'
                                         } for curr_id in argToList(destination_port_object_ids)]}
        sourceSecurityGroupTags = {'objects': [{'id': curr_id, 'type': 'SecurityGroupTag'
                                                } for curr_id in argToList(source_security_group_tag_object_ids)]}
        applications = {'applications': [{'id': curr_id, 'type': 'Application'
                                          } for curr_id in argToList(application_object_ids)]}
        urls = assign_params(
            objects=[{'id': curr_id, 'type': 'Url'} for curr_id in argToList(url_object_ids)],
            literals=[{'url': curr_id, 'type': 'Url'} for curr_id in argToList(url_addresses)])
        data = assign_params(name=name, action=action, enabled=enabled, sourceZones=sourceZones,
                             destinationZones=destinationZones, vlanTags=vlanTags, sourceNetworks=sourceNetworks,
                             destinationNetworks=destinationNetworks, sourcePorts=sourcePorts,
                             destinationPorts=destinationPorts, sourceSecurityGroupTags=sourceSecurityGroupTags,
                             applications=applications, urls=urls)
        suffix = f'policy/accesspolicies/{policy_id}/accessrules'
        return self._http_request('POST', suffix, json_data=data)

    def update_access_rules(
            self,
            update_strategy: str,
            source_zone_object_ids: str,
            destination_zone_object_ids: str,
            vlan_tag_object_ids: str,
            source_network_object_ids: str,
            source_network_addresses: str,
            destination_network_object_ids: str,
            destination_network_addresses: str,
            source_port_object_ids: str,
            destination_port_object_ids: str,
            source_security_group_tag_object_ids: str,
            application_object_ids: str,
            url_object_ids: str,
            url_addresses: str,
            enabled: bool,
            name: str,
            policy_id: str,
            action: str,
            rule_id: str
    ) -> Dict:

        suffix = f'policy/accesspolicies/{policy_id}/accessrules/{rule_id}'

        sourceZones = assign_params(
            objects=[{'id': curr_id, 'type': 'SecurityZone'} for curr_id in argToList(source_zone_object_ids)])
        destinationZones = assign_params(
            objects=[{'id': curr_id, 'type': 'SecurityZone'} for curr_id in argToList(destination_zone_object_ids)])
        vlanTags = assign_params(
            objects=[{'id': curr_id, 'type': 'vlanTags'} for curr_id in argToList(vlan_tag_object_ids)])
        sourceNetworks = assign_params(
            objects=[{'id': curr_id, 'type': 'NetworkGroup'} for curr_id in argToList(source_network_object_ids)],
            literals=[{'value': curr_id, 'type': 'Host'} for curr_id in argToList(source_network_addresses)])
        destinationNetworks = assign_params(
            objects=[{'id': curr_id, 'type': 'NetworkGroup'} for curr_id in argToList(destination_network_object_ids)],
            literals=[{'value': curr_id, 'type': 'Host'} for curr_id in argToList(destination_network_addresses)])
        sourcePorts = assign_params(
            objects=[{'id': curr_id, 'type': 'ProtocolPortObject'} for curr_id in argToList(source_port_object_ids)])
        destinationPorts = assign_params(
            objects=[{'id': curr_id, 'type': 'ProtocolPortObject'} for curr_id in
                     argToList(destination_port_object_ids)])
        sourceSecurityGroupTags = assign_params(objects=[{'id': curr_id, 'type': 'SecurityGroupTag'} for curr_id in
                                                         argToList(source_security_group_tag_object_ids)])
        applications = assign_params(
            applications=[{'id': curr_id, 'type': 'Application'} for curr_id in argToList(application_object_ids)])
        urls = assign_params(
            objects=[{'id': curr_id, 'type': 'Url'} for curr_id in argToList(url_object_ids)],
            literals=[{'url': curr_id, 'type': 'Url'} for curr_id in argToList(url_addresses)])
        data = assign_params(name=name, action=action, id=rule_id, enabled=enabled, sourceZones=sourceZones,
                             destinationZones=destinationZones, vlanTags=vlanTags, sourceNetworks=sourceNetworks,
                             destinationNetworks=destinationNetworks, sourcePorts=sourcePorts,
                             destinationPorts=destinationPorts, sourceSecurityGroupTags=sourceSecurityGroupTags,
                             applications=applications, urls=urls)

        data_from_get = self.get_access_rules(0, 0, rule_id=rule_id, policy_id=policy_id)
        if update_strategy == 'override':
            if 'name' not in data:
                data['name'] = data_from_get.get('name')
            if 'action' not in data:
                data['action'] = data_from_get.get('action')
            return self._http_request('PUT', suffix, json_data=data)
        else:
            for key, value in data.items():
                if type(value) == dict:
                    for in_key in value:
                        if in_key in data_from_get[key]:
                            data_from_get[key][in_key].extend(value[in_key])
                        else:
                            data_from_get[key][in_key] = value[in_key]
                else:
                    data_from_get[key] = value
            del data_from_get['metadata']
            del data_from_get['links']
            return self._http_request('PUT', suffix, json_data=data_from_get)

    def delete_access_rules(self, policy_id, rule_id) -> Dict:
        suffix = f'policy/accesspolicies/{policy_id}/accessrules/{rule_id}'
        return self._http_request('DELETE', suffix)

    def deploy_to_devices(self, force_deploy, ignore_warning, version, device_ids) -> Dict:
        data_to_post = assign_params(forceDeploy=force_deploy, ignoreWarning=ignore_warning, version=version,
                                     deviceList=argToList(device_ids), type="DeploymentRequest")
        suffix = 'deployment/deploymentrequests'
        return self._http_request('POST', suffix, json_data=data_to_post)


''' HELPER FUNCTIONS '''


def switch_list_to_list_counter(data: Union[Dict, List]) -> Union[Dict, List]:
    """Receives a list of dictionaries or a dictionary,
    and if one of the keys contains a list or dictionary with lists,
    returns the size of the lists
        Examples:
        >>> switch_list_to_list_counter({'name': 'n', 'type': 't', 'devices': [1, 2, 3]})
        {'name': 'name', 'type': 'type', 'devices': 3}

        >>> switch_list_to_list_counter({'name': 'n', 'type': 't', 'devices': {'new': [1, 2, 3], 'old': [1, 2, 3]}}
        {'name': 'name', 'type': 'type', 'devices': 6}

        >>> switch_list_to_list_counter({'name': 'n', 'type': 't', 'devices': {'new': 'my new'}
        {'name': 'name', 'type': 'type', 'devices': 1}

    :type data: ``list`` or ``dict``
    :param data:  context entry

    :return: ``list`` or ``dict``
    :rtype: context entry for human readable`
    """
    if isinstance(data, list):
        return [switch_list_to_list_counter(dat) for dat in data]
    new_data = {}
    for item in data:
        if type(data[item]) == list:
            new_data[item] = len(data[item])
        elif data[item] and type(data[item]) == dict:
            counter = 0
            for in_item in data[item]:
                if type(data[item][in_item]) == list:
                    counter += len(data[item][in_item])
                elif data[item][in_item]:
                    counter = 1 if counter == 0 else counter
            new_data[item] = counter
        else:
            new_data[item] = data[item]
    return new_data


def raw_response_to_context_list(list_key: List, items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives a dictionary or list of dictionaries and returns only the keys that exist in the list_key
    and changes the keys by Context Standards

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :type list_key: ``list``
    :keyword list_key: Selected keys to copy on context_entry
    """
    if isinstance(items, list):
        return [raw_response_to_context_list(list_key, item) for item in items]

    list_to_output = {OUTPUT_KEYS_DICTIONARY.get(key, key.capitalize()): items.get(key, '') for key in list_key}
    return list_to_output


def raw_response_to_context_network_groups(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to network groups command

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_network_groups(item) for item in items]
    return {
        'Name': items.get('name'),
        'ID': items.get('id'),
        'Overridable': items.get('overridable'),
        'Description': items.get('description'),
        'Objects': [
            {
                'Name': obj.get('name'),
                'ID': obj.get('id'),
                'Type': obj.get('type')
            } for obj in items.get('objects', [])
        ],
        'Addresses': [
            {
                'Value': obj.get('value'),
                'Type': obj.get('type')
            } for obj in items.get('literals', [])
        ]
    }


def raw_response_to_context_policy_assignment(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to policy assignment command

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_policy_assignment(item) for item in items]
    return {
        'Name': items.get('name'),
        'ID': items.get('id'),
        'PolicyName': items.get('policy', {}).get('name', ''),
        'PolicyID': items.get('policy', {}).get('id', ''),
        'PolicyDescription': items.get('policy', {}).get('description', ''),
        'Targets': [
            {
                'Name': obj.get('name'),
                'ID': obj.get('id'),
                'Type': obj.get('type')
            } for obj in items.get('targets', [])
        ]
    }


def raw_response_to_context_access_policy(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to access policy command

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_access_policy(item) for item in items]
    return {
        'Name': items.get('name'),
        'ID': items.get('id'),
        'DefaultActionID': items.get('defaultAction', {}).get('id', '')
    }


def raw_response_to_context_rules(items: Union[Dict, List]) -> Union[Dict, List]:
    """Receives raw response and returns Context entry to rules command

    :type items: ``list`` or ``dict``
    :param items:  list of dict or dict of data from http request

    :return: ``list`` or ``dict``
    :rtype: context entry`
    """
    if isinstance(items, list):
        return [raw_response_to_context_rules(item) for item in items]
    return {
        'ID': items.get('id'),
        'Name': items.get('name'),
        'Action': items.get('action'),
        'Enabled': items.get('enabled'),
        'SendEventsToFMC': items.get('sendEventsToFMC'),
        'RuleIndex': items.get('metadata', {}).get('ruleIndex', ''),
        'Section': items.get('metadata', {}).get('section', ''),
        'Category': items.get('metadata', {}).get('category', ''),
        'Urls': {
            'Addresses': [{
                'URL': obj.get('url', '')
            } for obj in items.get('urls', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', '')
            } for obj in items.get('urls', {}).get('objects', [])
            ]
        },
        'VlanTags': {
            'Numbers': [{
                'EndTag': obj.get('endTag', ''),
                'StartTag': obj.get('startTag', '')
            } for obj in items.get('vlanTags', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('vlanTags', {}).get('objects', [])
            ]
        },
        'SourceZones': {
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('sourceZones', {}).get('objects', [])
            ]
        },
        'Applications': [{
            'Name': obj.get('name', ''),
            'ID': obj.get('id', '')
        } for obj in items.get('applications', {}).get('applications', [])
        ],
        'DestinationZones': {
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('destinationZones', {}).get('objects', [])
            ]
        },
        'SourceNetworks': {
            'Addresses': [{
                'Type': obj.get('type', ''),
                'Value': obj.get('value', '')
            } for obj in items.get('sourceNetworks', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('sourceNetworks', {}).get('objects', [])
            ]
        },
        'DestinationNetworks': {
            'Addresses': [{
                'Type': obj.get('type', ''),
                'Value': obj.get('value', '')
            } for obj in items.get('destinationNetworks', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('destinationNetworks', {}).get('objects', [])
            ]
        },
        'SourcePorts': {
            'Addresses': [{
                'Port': obj.get('port', ''),
                'Protocol': obj.get('protocol', '')
            } for obj in items.get('sourcePorts', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', ''),
                'Protocol': obj.get('protocol', '')
            } for obj in items.get('sourcePorts', {}).get('objects', [])
            ]
        },
        'DestinationPorts': {
            'Addresses': [{
                'Port': obj.get('port', ''),
                'Protocol': obj.get('protocol', '')
            } for obj in items.get('destinationPorts', {}).get('literals', [])
            ],
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', ''),
                'Protocol': obj.get('protocol', '')
            } for obj in items.get('destinationPorts', {}).get('objects', [])
            ]
        },
        'SourceSecurityGroupTags': {
            'Objects': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id', ''),
                'Type': obj.get('type', '')
            } for obj in items.get('sourceSecurityGroupTags', {}).get('objects', [])
            ]
        }
    }


''' COMMANDS '''


def list_zones_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'securityzones')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List zones:'
        context_entry = [{
            'ID': item.get('id', ''),
            'Name': item.get('name', ''),
            'InterfaceMode': item.get('interfaceMode', ''),
            'Interfaces': [{
                'Name': obj.get('name', ''),
                'ID': obj.get('id' '')
            } for obj in item.get('interfaces', {})
            ]
        } for item in items
        ]
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Zone(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'InterfaceMode', 'Interfaces']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any zone.', {}, {}


def list_ports_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'ports')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List ports:'
        list_to_output = ['id', 'name', 'protocol', 'port']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Port(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Protocol', 'Port']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any port.', {}, {}


def list_url_categories_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'urlcategories')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List url categories:'
        list_to_output = ['id', 'name']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Category(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any category.', {}, {}


def get_network_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    object_id = args.get('object_id', '')

    raw_response = client.get_network_objects(limit, offset, object_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List network objects:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - get network object {object_id}'
            items = raw_response
        list_to_output = ['id', 'name', 'value', 'overridable', 'description']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Network(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any network object.', {}, {}


def get_host_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    object_id = args.get('object_id', '')

    raw_response = client.get_hosts_objects(limit, offset, object_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List host objects:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - get host object {object_id}'
            items = raw_response
        list_to_output = ['id', 'name', 'value', 'overridable', 'description']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Host(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any host object.', {}, {}


def create_network_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    name: str = args.get('name')    # type:ignore
    value: str = args.get('value')    # type:ignore
    description: str = args.get('description', '')    # type:ignore
    overridable = args.get('overridable', '')
    raw_response = client.create_network_objects(name, value, description, overridable)
    title = f'{INTEGRATION_NAME} - network object has been created.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']
    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Network(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def create_host_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    name: str = args.get('name')    # type:ignore
    value: str = args.get('value')    # type:ignore
    description: str = args.get('description', '')    # type:ignore
    overridable = args.get('overridable', '')
    raw_response = client.create_host_objects(name, value, description, overridable)
    title = f'{INTEGRATION_NAME} - host object has been created.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']
    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Host(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def update_network_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    object_id: str = args.get('id')    # type:ignore
    name: str = args.get('name')    # type:ignore
    value: str = args.get('value')    # type:ignore
    description: str = args.get('description', '')    # type:ignore
    overridable = args.get('overridable', '')
    raw_response = client.update_network_objects(name, value, description, overridable, object_id)
    title = f'{INTEGRATION_NAME} - network object has been updated.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']

    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Network(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def update_host_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    object_id: str = args.get('id')    # type:ignore
    name: str = args.get('name')    # type:ignore
    value: str = args.get('value')    # type:ignore
    description: str = args.get('description', '')    # type:ignore
    overridable = args.get('overridable', '')
    raw_response = client.update_host_objects(name, value, description, overridable, object_id)
    title = f'{INTEGRATION_NAME} - host object has been updated.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']

    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Host(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def delete_network_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    object_id: str = args.get('id')    # type:ignore
    raw_response = client.delete_network_objects(object_id)
    title = f'{INTEGRATION_NAME} - network object has been deleted.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']
    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Network(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def delete_host_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    object_id: str = args.get('id')    # type:ignore
    raw_response = client.delete_host_objects(object_id)
    title = f'{INTEGRATION_NAME} - host object has been deleted.'
    list_to_output = ['id', 'name', 'value', 'overridable', 'description']
    context_entry = raw_response_to_context_list(list_to_output, raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Host(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Value', 'Overridable', 'Description']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def get_network_groups_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    object_id = args.get('id', '')
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    raw_response = client.get_network_groups_objects(limit, offset, object_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List of network groups object:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - network group object:'
            items = raw_response
        context_entry = raw_response_to_context_network_groups(items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not delete the object.')


def create_network_groups_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    name: str = args.get('name')    # type:ignore
    ids = args.get('network_objects_id_list', '')
    values = args.get('network_address_list', '')
    description = args.get('description', '')
    overridable = args.get('overridable', '')
    if ids or values:
        raw_response = client.create_network_groups_objects(name, ids, values, description, overridable)
        title = f'{INTEGRATION_NAME} - network group has been created.'
        context_entry = raw_response_to_context_network_groups(raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not create new group, Missing value or ID.')


def update_network_groups_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    group_id: str = args.get('id')   # type:ignore
    name: str = args.get('name')    # type:ignore
    ids = args.get('network_objects_id_list', '')
    values = args.get('network_address_list', '')
    description = args.get('description', '')
    overridable = args.get('overridable', '')
    if ids or values:
        raw_response = client.update_network_groups_objects(name, ids, values, group_id, description, overridable)
        title = f'{INTEGRATION_NAME} - network group has been updated.'
        context_entry = raw_response_to_context_network_groups(raw_response)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
        }

        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        raise DemistoException(f'{INTEGRATION_NAME} - Could not update the group, Missing value or ID.')


def delete_network_groups_objects_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    object_id = args['id']
    raw_response = client.delete_network_groups_objects(object_id)
    title = f'{INTEGRATION_NAME} - network group - {object_id} - has been delete.'
    context_entry = raw_response_to_context_network_groups(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.NetworkGroups(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Addresses', 'Objects']
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
    return human_readable, context, raw_response


def get_access_policy_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    policy_id = args.get('id', '')
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    raw_response = client.get_access_policy(limit, offset, policy_id)
    items: Union[List, Dict] = raw_response.get('items')    # type:ignore
    if items or 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - List access policy:'
        if 'id' in raw_response:
            title = f'{INTEGRATION_NAME} - get access policy'
            items = raw_response
        context_entry = raw_response_to_context_access_policy(items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'DefaultActionID']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any access policy.', {}, {}


def create_access_policy_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    name: str = args.get('name')    # type:ignore
    action: str = args.get('action')    # type:ignore
    raw_response = client.create_access_policy(name, action)
    title = f'{INTEGRATION_NAME} - access policy has been created.'
    context_entry = raw_response_to_context_access_policy(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'DefaultActionID']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def update_access_policy_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    name: str = args.get('name')    # type:ignore
    policy_id: str = args.get('id')    # type:ignore
    action: str = args.get('action')    # type:ignore
    action_id: str = args.get('default_action_id')    # type:ignore

    raw_response = client.update_access_policy(name, policy_id, action, action_id)
    title = f'{INTEGRATION_NAME} - access policy has been updated.'
    context_entry = raw_response_to_context_access_policy(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'DefaultActionID']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def delete_access_policy_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    policy_id: str = args.get('id')    # type:ignore
    raw_response = client.delete_access_policy(policy_id)
    title = f'{INTEGRATION_NAME} - access policy deleted.'
    context_entry = raw_response_to_context_access_policy(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Policy(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'DefaultActionID']
    human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
    return human_readable, context, raw_response


def list_security_group_tags_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'securitygrouptags')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List security group tags:'
        list_to_output = ['id', 'name', 'tag']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.SecurityGroupTags(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Tag']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any security group tags.', {}, {}


def list_ise_security_group_tags_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'isesecuritygrouptags')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List ise security group tags:'
        list_to_output = ['id', 'name', 'tag']
        context_entry = raw_response_to_context_list(list_to_output, items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.IseSecurityGroupTags(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Tag']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any ise security group tags.', {}, {}


def list_vlan_tags_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'vlantags')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List vlan tags:'
        context_entry = [
            {
                'Name': item.get('name'),
                'ID': item.get('id'),
                'Overridable': item.get('overridable'),
                'Description': item.get('description'),
                'StartTag': item.get('data', {}).get('startTag'),
                'EndTag': item.get('data', {}).get('endTag')
            } for item in items
        ]
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.VlanTags(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'StartTag', 'EndTag']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any vlan tags.', {}, {}


def list_vlan_tags_group_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'vlangrouptags')
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of vlan tags groups objects:'
        context_entry = [
            {
                'Name': item.get('name'),
                'ID': item.get('id'),
                'Overridable': item.get('overridable'),
                'Description': item.get('description'),
                'Objects': [
                    {
                        'Name': obj.get('name'),
                        'ID': obj.get('id'),
                        'Overridable': obj.get('overridable'),
                        'Description': obj.get('description'),
                        'StartTag': obj.get('data', {}).get('startTag'),
                        'EndTag': obj.get('data', {}).get('endTag')
                    } for obj in item.get('object', [])
                ]
            } for item in items
        ]
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.VlanTagsGroup(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'Overridable', 'Description', 'Objects']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any vlan tags group.', {}, {}


def list_applications_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_list(limit, offset, 'applications')
    items = raw_response.get('items')
    if items:
        context_entry = [
            {
                'Name': item.get('name'),
                'ID': item.get('id'),
                'Risk': item.get('risk', {}).get('name', ''),
                'AppProductivity': item.get('appProductivity', {}).get('name', ''),
                'ApplicationTypes': [
                    {
                        'Name': obj.get('name')
                    } for obj in item.get('applicationTypes', [])
                ],
                'AppCategories': [
                    {
                        'Name': obj.get('name'),
                        'ID': obj.get('id'),
                        'Count': obj.get('metadata', {}).get('count', '')
                    } for obj in item.get('appCategories', [])
                ]
            } for item in items
        ]
        title = f'{INTEGRATION_NAME} - List of applications objects:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.Applications(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'Risk', 'AppProductivity', 'ApplicationTypes', 'AppCategories']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any applications.', {}, {}


def get_access_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    policy_id: str = args.get('policy_id')    # type:ignore
    rule_id = args.get('rule_id', '')
    raw_response = client.get_access_rules(limit, offset, policy_id, rule_id)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of access rules:'
    elif 'id' in raw_response:
        title = f'{INTEGRATION_NAME} - access rule:'
        items = raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any access rule.', {}, {}
    context_entry = raw_response_to_context_rules(items)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Action', 'Enabled', 'SendEventsToFMC', 'RuleIndex', 'Section', 'Category',
                        'Urls', 'VlanTags', 'SourceZones', 'Applications', 'DestinationZones', 'SourceNetworks',
                        'DestinationNetworks', 'SourcePorts', 'DestinationPorts', 'SourceSecurityGroupTags']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
    return human_readable, context, raw_response


def create_access_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    source_zone_object_ids = args.get('source_zone_object_ids', '')
    destination_zone_object_ids = args.get('destination_zone_object_ids', '')
    vlan_tag_object_ids = args.get('vlan_tag_object_ids', '')
    source_network_object_ids = args.get('source_network_object_ids', '')
    source_network_addresses = args.get('source_network_addresses', '')
    destination_network_object_ids = args.get('destination_network_object_ids', '')
    destination_network_addresses = args.get('destination_network_addresses', '')
    source_port_object_ids = args.get('source_port_object_ids', '')
    destination_port_object_ids = args.get('destination_port_object_ids', '')
    source_security_group_tag_object_ids = args.get('source_security_group_tag_object_ids', '')
    application_object_ids = args.get('application_object_ids', '')
    url_object_ids = args.get('url_object_ids', '')
    url_addresses = args.get('url_addresses', '')
    enabled = args.get('enabled', '')
    name = args.get('rule_name', '')
    policy_id = args.get('policy_id', '')
    action = args.get('action', '')

    raw_response = client.create_access_rules(source_zone_object_ids,
                                              destination_zone_object_ids,
                                              vlan_tag_object_ids,
                                              source_network_object_ids,
                                              source_network_addresses,
                                              destination_network_object_ids,
                                              destination_network_addresses,
                                              source_port_object_ids,
                                              destination_port_object_ids,
                                              source_security_group_tag_object_ids,
                                              application_object_ids,
                                              url_object_ids,
                                              url_addresses,
                                              enabled,
                                              name,
                                              policy_id,
                                              action)
    title = f'{INTEGRATION_NAME} - the new access rule:'
    context_entry = raw_response_to_context_rules(raw_response)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Action', 'Enabled', 'SendEventsToFMC', 'RuleIndex', 'Section', 'Category',
                        'Urls', 'VlanTags', 'SourceZones', 'Applications', 'DestinationZones', 'SourceNetworks',
                        'DestinationNetworks', 'SourcePorts', 'DestinationPorts', 'SourceSecurityGroupTags']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
    return human_readable, context, raw_response


def update_access_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    update_strategy: str = args.get('update_strategy')     # type:ignore
    source_zone_object_ids = args.get('source_zone_object_ids', '')
    destination_zone_object_ids = args.get('destination_zone_object_ids', '')
    vlan_tag_object_ids = args.get('vlan_tag_object_ids', '')
    source_network_object_ids = args.get('source_network_object_ids', '')
    source_network_addresses = args.get('source_network_addresses', '')
    destination_network_object_ids = args.get('destination_network_object_ids', '')
    destination_network_addresses = args.get('destination_network_addresses', '')
    source_port_object_ids = args.get('source_port_object_ids', '')
    destination_port_object_ids = args.get('destination_port_object_ids', '')
    source_security_group_tag_object_ids = args.get('source_security_group_tag_object_ids', '')
    application_object_ids = args.get('application_object_ids', '')
    url_object_ids = args.get('url_object_ids', '')
    url_addresses = args.get('url_addresses', '')
    enabled = args.get('enabled', '')
    name = args.get('rule_name', '')
    policy_id = args.get('policy_id', '')
    action = args.get('action', '')
    rule_id: str = args.get('rule_id')    # type:ignore

    raw_response = client.update_access_rules(update_strategy,
                                              source_zone_object_ids,
                                              destination_zone_object_ids,
                                              vlan_tag_object_ids,
                                              source_network_object_ids,
                                              source_network_addresses,
                                              destination_network_object_ids,
                                              destination_network_addresses,
                                              source_port_object_ids,
                                              destination_port_object_ids,
                                              source_security_group_tag_object_ids,
                                              application_object_ids,
                                              url_object_ids,
                                              url_addresses,
                                              enabled,
                                              name,
                                              policy_id,
                                              action,
                                              rule_id)
    title = f'{INTEGRATION_NAME} - access rule:'
    context_entry = raw_response_to_context_rules(raw_response)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Action', 'Enabled', 'SendEventsToFMC', 'RuleIndex', 'Section', 'Category',
                        'Urls', 'VlanTags', 'SourceZones', 'Applications', 'DestinationZones', 'SourceNetworks',
                        'DestinationNetworks', 'SourcePorts', 'DestinationPorts', 'SourceSecurityGroupTags']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
    return human_readable, context, raw_response


def delete_access_rules_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    policy_id = args.get('policy_id')
    rule_id = args.get('rule_id')
    raw_response = client.delete_access_rules(policy_id, rule_id)
    title = f'{INTEGRATION_NAME} - deleted access rule:'
    context_entry = raw_response_to_context_rules(raw_response)
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.Rule(val.ID && val.ID === obj.ID)': context_entry
    }
    presented_output = ['ID', 'Name', 'Action', 'Enabled', 'SendEventsToFMC', 'RuleIndex', 'Section', 'Category',
                        'Urls', 'VlanTags', 'SourceZones', 'Applications', 'DestinationZones', 'SourceNetworks',
                        'DestinationNetworks', 'SourcePorts', 'DestinationPorts', 'SourceSecurityGroupTags']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
    return human_readable, context, raw_response


def list_policy_assignments_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.list_policy_assignments(limit, offset)
    items = raw_response.get('items')
    if items:
        title = f'{INTEGRATION_NAME} - List of policy assignments:'
        context_entry = raw_response_to_context_policy_assignment(items)
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
        }
        entry_white_list_count = switch_list_to_list_counter(context_entry)
        presented_output = ['ID', 'Name', 'PolicyName', 'PolicyID', 'PolicyDescription', 'Targets']
        human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any policy assignments.', {}, {}


def create_policy_assignments_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    device_ids: str = args.get('device_ids')    # type:ignore
    device_group_ids: str = args.get('device_group_ids')    # type:ignore
    policy_id: str = args.get('policy_id')    # type:ignore
    raw_response = client.create_policy_assignments(policy_id, device_ids, device_group_ids)
    title = f'{INTEGRATION_NAME} - Policy assignments has been done.'
    context_entry = raw_response_to_context_policy_assignment(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
    }
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    presented_output = ['ID', 'Name', 'PolicyName', 'PolicyID', 'PolicyDescription', 'Targets']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
    return human_readable, context, raw_response


def update_policy_assignments_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    device_ids: str = args.get('device_ids')    # type:ignore
    device_group_ids: str = args.get('device_group_ids')    # type:ignore
    policy_id: str = args.get('policy_id')    # type:ignore
    raw_response = client.update_policy_assignments(policy_id, device_ids, device_group_ids)
    title = f'{INTEGRATION_NAME} - policy update has been done.'
    context_entry = raw_response_to_context_policy_assignment(raw_response)
    context = {
        f'{INTEGRATION_CONTEXT_NAME}.PolicyAssignments(val.ID && val.ID === obj.ID)': context_entry
    }
    entry_white_list_count = switch_list_to_list_counter(context_entry)
    presented_output = ['ID', 'Name', 'PolicyName', 'PolicyID', 'PolicyDescription', 'Targets']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
    return human_readable, context, raw_response


def get_deployable_devices_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_deployable_devices(limit, offset)
    items = raw_response.get('items')
    if items:
        context_entry = [{
            'CanBeDeployed': item.get('canBeDeployed', ''),
            'UpToDate': item.get('upToDate', ''),
            'DeviceID': item.get('device', {}).get('id', ''),
            'DeviceName': item.get('device', {}).get('name', ''),
            'DeviceType': item.get('device', {}).get('type', ''),
            'Version': item.get('version', '')
        } for item in items
        ]
        title = f'{INTEGRATION_NAME} - List of deployable devices:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.DeployableDevices(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['CanBeDeployed', 'UpToDate', 'DeviceID', 'DeviceName', 'DeviceType', 'Version']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any deployable devices.', {}, {}


def get_device_records_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    limit = args.get('limit', 50)
    offset = args.get('offset', 0)
    raw_response = client.get_device_records(limit, offset)
    items = raw_response.get('items')
    if items:
        context_entry = [{
            'ID': item.get('id', ''),
            'Name': item.get('name', ''),
            'HostName': item.get('hostName', ''),
            'Type': item.get('type', ''),
            'DeviceGroupID': item.get('deviceGroup', {}).get('id', '')
        } for item in items
        ]
        title = f'{INTEGRATION_NAME} - List of device records:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.DeviceRecords(val.ID && val.ID === obj.ID)': context_entry
        }
        presented_output = ['ID', 'Name', 'HostName', 'Type', 'DeviceGroupID']
        human_readable = tableToMarkdown(title, context_entry, headers=presented_output)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any device records.', {}, {}


def deploy_to_devices_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    force_deploy = args.get('force_deploy', '')
    ignore_warning = args.get('ignore_warning', '')
    version = args.get('version', '')
    device_list = args.get('device_ids', '')

    raw_response = client.deploy_to_devices(force_deploy, ignore_warning, version, device_list)
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
    presented_output = ['TaskID', 'ForceDeploy', 'IgnoreWarning', 'Version', 'DeviceList']
    human_readable = tableToMarkdown(title, entry_white_list_count, headers=presented_output)
    return human_readable, context, raw_response


def get_task_status_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    task_id: str = args.get('task_id')    # type:ignore
    raw_response = client.get_task_status(task_id)
    if 'status' in raw_response:
        context_entry = {
            'Status': raw_response.get('status')
        }
        title = f'{INTEGRATION_NAME} - {task_id} status:'
        context = {
            f'{INTEGRATION_CONTEXT_NAME}.TaskStatus(val.ID && val.ID === obj.ID)': context_entry
        }
        human_readable = tableToMarkdown(title, context_entry, headers=['Status'])
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any status.', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = params.get('url')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')

    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client = Client(base_url=base_url, verify=verify_ssl, proxy=proxy, auth=(username, password))
    command = demisto.command()
    client.login()

    LOG(f'Command being called is {command}')

    try:
        if demisto.command() == 'test-module':
            return_outputs('ok')
            # Login is performed at the beginning of each flow if the login fails we return an error.
        elif demisto.command() == 'ciscofp-list-zones':
            return_outputs(*list_zones_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-list-ports':
            return_outputs(*list_ports_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-list-url-categories':
            return_outputs(*list_url_categories_command(client, demisto.args()))

        elif demisto.command() == 'ciscofp-get-network-object':
            return_outputs(*get_network_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-create-network-object':
            return_outputs(*create_network_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-update-network-object':
            return_outputs(*update_network_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-delete-network-object':
            return_outputs(*delete_network_objects_command(client, demisto.args()))

        elif demisto.command() == 'ciscofp-get-host-object':
            return_outputs(*get_host_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-create-host-object':
            return_outputs(*create_host_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-update-host-object':
            return_outputs(*update_host_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-delete-host-object':
            return_outputs(*delete_host_objects_command(client, demisto.args()))

        elif demisto.command() == 'ciscofp-get-network-groups-object':
            return_outputs(*get_network_groups_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-create-network-groups-objects':
            return_outputs(*create_network_groups_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-update-network-groups-objects':
            return_outputs(*update_network_groups_objects_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-delete-network-groups-objects':
            return_outputs(*delete_network_groups_objects_command(client, demisto.args()))

        elif demisto.command() == 'ciscofp-get-access-policy':
            return_outputs(*get_access_policy_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-create-access-policy':
            return_outputs(*create_access_policy_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-update-access-policy':
            return_outputs(*update_access_policy_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-delete-access-policy':
            return_outputs(*delete_access_policy_command(client, demisto.args()))

        elif demisto.command() == 'ciscofp-list-security-group-tags':
            return_outputs(*list_security_group_tags_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-list-ise-security-group-tags':
            return_outputs(*list_ise_security_group_tags_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-list-vlan-tags':
            return_outputs(*list_vlan_tags_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-list-vlan-tags-group':
            return_outputs(*list_vlan_tags_group_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-list-applications':
            return_outputs(*list_applications_command(client, demisto.args()))

        elif demisto.command() == 'ciscofp-get-access-rules':
            return_outputs(*get_access_rules_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-create-access-rules':
            return_outputs(*create_access_rules_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-update-access-rules':
            return_outputs(*update_access_rules_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-delete-access-rules':
            return_outputs(*delete_access_rules_command(client, demisto.args()))

        elif demisto.command() == 'ciscofp-list-policy-assignments':
            return_outputs(*list_policy_assignments_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-create-policy-assignments':
            return_outputs(*create_policy_assignments_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-update-policy-assignments':
            return_outputs(*update_policy_assignments_command(client, demisto.args()))

        elif demisto.command() == 'ciscofp-get-deployable-devices':
            return_outputs(*get_deployable_devices_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-get-device-records':
            return_outputs(*get_device_records_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-deploy-to-devices':
            return_outputs(*deploy_to_devices_command(client, demisto.args()))
        elif demisto.command() == 'ciscofp-get-task-status':
            return_outputs(*get_task_status_command(client, demisto.args()))

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':  # pragma: no cover
    main()
