import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import requests
from urllib.parse import urlparse
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''

BASE_URL = re.sub(r"/+$", "", demisto.params().get('serverURL'))
SERVER_PORT = demisto.params().get('serverPort')
SERVER_URL = BASE_URL + ':' + SERVER_PORT
SERVER_ADMIN_URL = BASE_URL

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')

USE_SSL = not demisto.params().get('insecure', False)

DEFAULT_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Connection': 'keep_alive',
}

DEFAULT_ADMIN_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/xml',
    'Connection': 'keep_alive',
}
''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, headers=None, is_admin_api=False):
    params = params if params is not None else {}
    if headers is None:
        headers = DEFAULT_ADMIN_HEADERS if is_admin_api else DEFAULT_HEADERS

    if is_admin_api:
        url = SERVER_ADMIN_URL + url_suffix
    else:
        url = SERVER_URL + url_suffix

    try:
        LOG(f'running {method} request with url={url}')

        response = requests.request(
            method,
            url,
            auth=(USERNAME, PASSWORD),
            headers=headers,
            verify=USE_SSL,
            params=params,
            data=data
        )
    except requests.exceptions.SSLError:
        err_msg = 'Could not connect to Cisco ISE: Could not verify certificate.'
        return_error(err_msg)
    except requests.exceptions.ConnectionError:
        err_msg = 'Connection Error. Verify that the Server URL and port are correct, and that the port is open.'
        return_error(err_msg)

    # handle request failure
    if response.status_code not in {200, 201, 202, 204}:
        message = parse_error_response(response)
        err_msg = f'Error in API call to Cisco ISE Integration [{response.status_code}] - {response.reason}, {message}'
        return_error(err_msg)

    if response.status_code in (201, 204):
        return None

    if is_admin_api:
        return response.content

    try:
        response = response.json()
    except ValueError:
        return_error(response.content)

    return response


def parse_error_response(response):
    try:
        res = response.json()
        msg = res.get('ERSResponse').get('messages')
        err = msg[0].get('title', '')
    except Exception:
        return response.text
    return err


def translate_group_id(group_id):
    """
    Translates group ID to group name
    """

    api_endpoint = f"/ers/config/identitygroup/{group_id}"
    identity_group = http_request('GET', api_endpoint)['IdentityGroup']
    return identity_group['name']


''' COMMANDS FUNCTIONS '''


def get_groups_request():

    api_endpoint = '/ers/config/endpointgroup'
    return http_request('GET', api_endpoint)


def get_groups():
    """
    Retrieve a collection of endpoint identity groups.
    """

    groups_data: dict = get_groups_request().get('SearchResult', {})

    if groups_data.get('total', 0) < 1:
        return 'No groups were found.'

    groups = groups_data.get('resources', [])
    context = []
    humanreadable = []

    for group in groups:
        context_dict = {
            'ID': group.get('id'),
            'Name': group.get('name'),
            'Description': group.get('description')
        }
        hr_dict = dict(context_dict)
        context.append(context_dict)
        humanreadable.append(hr_dict)

    entry_context = {
        'CiscoISE.Group(val.ID === obj.ID)': context
    }

    return_outputs(tableToMarkdown('Cisco ISE Groups', humanreadable, ['ID', 'Name', 'Description'], removeNull=True),
                   entry_context, groups_data)
    return None


def get_endpoint_id(mac_address=None):
    """
    Returns endpoint id by specific mac address
    """

    api_endpoint = f'/ers/config/endpoint?filter=mac.EQ.{mac_address}' if mac_address is not None else ""
    return http_request('GET', api_endpoint, '')


def get_endpoint_id_command():
    """
    corresponds to 'cisco-ise-get-endpoint-id' command. Returns endpoint's id
    """
    mac_address = demisto.args().get('macAddress')

    if not is_mac_address(mac_address):
        return_error('Given MAC address is invalid')

    endpoint_data = get_endpoint_id(mac_address)

    resources = endpoint_data.get('SearchResult', {}).get('resources', [])
    if resources:
        endpoint_id = resources[0].get('id', None)
    else:
        endpoint_id = None

    entry_context = {
        'Endpoint(val.ID === obj.ID)': {
            'ID': endpoint_id,
            'MACAddress': mac_address
        }
    }

    return_outputs(f'The endpoint ID is: {endpoint_id}', entry_context, endpoint_id)


def get_endpoint_details(endpoint_id):
    """
    Gets endpoint details by specific id
    """

    api_endpoint = f'/ers/config/endpoint/{endpoint_id}'
    response = http_request('GET', api_endpoint)
    if response:
        return response
    else:
        return_error('Endpoint was not found.')
        return None


def get_endpoint_details_command():
    """
    corresponds to 'cisco-ise-get-endpoint-details' command. Returns information about a specific endpoint
    """

    endpoint_id = demisto.args().get('endpointID')
    endpoint_mac_address = demisto.args().get('macAddress')

    if endpoint_mac_address and not is_mac_address(endpoint_mac_address):
        return_error('Given MAC address is invalid')

    if not endpoint_id and not endpoint_mac_address:
        return_error('Either endpoint ID or MAC address should be provided')

    if endpoint_mac_address and not endpoint_id:
        resources = get_endpoint_id(endpoint_mac_address).get('SearchResult', {}).get('resources', [])
        if resources:
            endpoint_id = resources[0].get('id', None)

    endpoint_data = get_endpoint_details(endpoint_id)

    endpoint_details = endpoint_data.get('ERSEndPoint')

    if endpoint_details:
        custom_attributes = endpoint_details.get('customAttributes')
        if custom_attributes:
            custom_attributes = custom_attributes.get('customAttributes')
        portal_user = endpoint_details.get('portalUser')
        description = endpoint_details.get('description')
        group_name = translate_group_id(endpoint_details['groupId'])
        hr = {
            'ID': endpoint_details['id'],
            'MACAddress': endpoint_details['mac'],
            'Group': group_name,
            'CustomAttributes': custom_attributes,
            'StaticGroupAssignment': endpoint_details['staticGroupAssignment'],
            'StaticProfileAssignment': endpoint_details['staticProfileAssignment']
        }
        detailed_ec = {
            'ID': endpoint_details['id'],
            'MACAddress': endpoint_details['mac'],
            'Group': group_name,
            'StaticGroupAssignment': endpoint_details['staticGroupAssignment'],
            'StaticProfileAssignment': endpoint_details['staticProfileAssignment']
        }
        if custom_attributes:
            detailed_ec['CustomAttributes'] = {}
            for attribute in custom_attributes:
                detailed_ec['CustomAttributes'][attribute] = custom_attributes[attribute]
        if portal_user:
            hr['User'] = portal_user
            detailed_ec['User'] = portal_user
        if description:
            hr['Description'] = description
            detailed_ec['Description'] = description
        ec = {
            'Endpoint(val.ID === obj.ID)': {
                'ID': endpoint_details['id'],
                'MACAddress': endpoint_details['mac']
            },
            'CiscoISE.Endpoint(val.ID === obj.ID)': detailed_ec
        }

        title = 'Endpoint details - ' + (endpoint_id or endpoint_mac_address)
        return_outputs(tableToMarkdown(title, hr, removeNull=True), ec, endpoint_details)
    else:
        demisto.results('No results found')


def reauthenticate_endpoint(mac_address, psn_address):
    """
    Reauthenticates an endpoint
    """
    api_endpoint = f"/admin/API/mnt/CoA/Reauth/{psn_address}/{mac_address}/1"
    response = http_request('GET', api_endpoint)
    return response


def get_psn_for_mac(mac_address):
    """
    Retrieves psn for an endpoint
    """
    api_endpoint = f"/admin/API/mnt/AuthStatus/MACAddress/{mac_address}/86400/0/0"
    response = http_request('GET', api_endpoint)
    if response:
        return response
    else:
        return_error('Could not reauthenticate the endpoint')
        return None


def reauthenticate_endpoint_command():
    """
    corresponds to 'cisco-ise-reauthenticate-endpoint' command. Reauthenticates an endpoint
    """
    mac_address = demisto.args().get('macAddress').upper()
    if not is_mac_address(mac_address):
        return "Please enter a valid mac address"
    mac_address = mac_address.upper()
    mac_address_psn = get_psn_for_mac(mac_address)
    if not mac_address_psn:
        return "Couldn't find psn address for mac: " + mac_address
    psn_address = json.loads(xml2json(mac_address_psn)).get('restAuthStatusOutputList', {}).get(
        'authStatusList', {}).get('authStatusElements', {})[0].get('acs_server')
    if not psn_address:
        return "Couldn't find psn address for mac: " + mac_address + " response from psn endpoint was: " + json.dumps(
            mac_address_psn)
    activation_result = reauthenticate_endpoint(mac_address, psn_address).text
    json_activation_result = json.loads(xml2json(activation_result)).get('remoteCoA').get('results')
    activation_result_boolean = 'true' in json_activation_result

    entry_context = {
        "CiscoISE.Endpoint(val.MACAddress==obj.MACAddress)": {
            'MACAddress': json_activation_result,
            'reauthenticateResult': activation_result_boolean
        }
    }

    return_outputs('Activation result was : ' + str(activation_result_boolean), entry_context, activation_result)
    return None


def get_endpoints():
    """
    Gets data about existing endpoints
    """

    api_endpoint = "/ers/config/endpoint"
    return http_request('GET', api_endpoint)


def get_endpoints_command(return_bool: bool = False):
    """
    corresponds to 'ise-get-endpoints' command. Get data about the existing endpoints
    """

    endpoints_data = get_endpoints().get('SearchResult', {})

    if endpoints_data.get('total', 0) < 1:
        return 'No endpoints were found.'

    endpoints = endpoints_data.get('resources', [])

    context = []
    hr = []

    for endpoint in endpoints:
        context_dict = {
            'ID': endpoint.get('id'),
            'MACAddress': endpoint.get('name')
        }
        hr_dict = dict(context_dict)
        context.append(context_dict)
        hr.append(hr_dict)
    if return_bool:
        return True
    entry_context = {
        'Endpoint(val.ID == obj.ID)': context,
        'CiscoISE.Endpoint(val.ID == obj.ID)': context
    }

    return_outputs(tableToMarkdown(
        'Cisco ISE Endpoints', hr, ['ID', 'MACAddress'], removeNull=True),
        entry_context,
        endpoints
    )
    return None


def update_endpoint_by_id(endpoint_id, endpoint_details):
    """
    Updates endpoint status
    """
    api_endpoint = f'/ers/config/endpoint/{endpoint_id}'
    response = http_request('PUT', api_endpoint, data=json.dumps(endpoint_details))
    return response


def update_endpoint_custom_attribute_command():
    """
    corresponds to 'cisco-ise-update-endpoint-custom-attribute' command.
    Blocks endpoint using predefined custom fields
    """

    endpoint_id = demisto.args().get('id')
    endpoint_mac_address = demisto.args().get('macAddress')

    if endpoint_mac_address and not is_mac_address(endpoint_mac_address):
        return_error('Please enter a valid mac address')

    if not endpoint_id and not endpoint_mac_address:
        return_error('Please enter either endpoint id or endpoint mac address')

    if endpoint_mac_address and not endpoint_id:
        endpoint_id = get_endpoint_id(endpoint_mac_address).get('SearchResult', {}).get('resources', [])[0].get('id',
                                                                                                                None)

    endpoint_details = get_endpoint_details(endpoint_id)

    if "ERSEndPoint" not in endpoint_details:
        return_error('Failed to get endpoint %s' % endpoint_id)

    attribute_names = demisto.args().get('attributeName').split(',')
    attribute_values = demisto.args().get('attributeValue').split(',')

    attributes_dic = {}
    for couple in zip(attribute_names, attribute_values):
        attributes_dic[couple[0]] = couple[1]
    try:
        del endpoint_details['ERSEndPoint']['link']
        if endpoint_details['ERSEndPoint'].get('customAttributes'):
            endpoint_details['ERSEndPoint']['customAttributes']['customAttributes'] = attributes_dic
        else:
            endpoint_details['ERSEndPoint']['customAttributes'] = {'customAttributes': attributes_dic}

        update_result = update_endpoint_by_id(endpoint_id, endpoint_details)
        if not update_result:
            demisto.results("Update failed for endpoint " + endpoint_id + ". Please check if the custom "
                                                                          "fields are defined in the system. "
                                                                          "Got the following response: "
                            + update_result.get('ERSResponse', {}).get('messages', []))

        updated_fields_dict_list = update_result.get('UpdatedFieldsList', {}).get('updatedField', [])

        if len(updated_fields_dict_list) > 0:
            updated_fields_string = ' the new custom fields are: ' + json.dumps(
                updated_fields_dict_list[0].get('newValue'))
        else:
            updated_fields_string = ", but the fields that you've tried to update already had that specific value " \
                                    "or do not exist"
        demisto.results('Successfully updated endpoint %s' % endpoint_id + updated_fields_string)

    except Exception as e:
        raise Exception(f"Exception: Failed to update endpoint {endpoint_id}: " + str(e))


def update_endpoint_group_command():
    """
    corresponds to 'cisco-ise-update-endpoint-group' command. Updates endpoint status
    """

    endpoint_group_name = demisto.args().get('groupName')
    endpoint_group_id = demisto.args().get('groupId')
    if not endpoint_group_name and not endpoint_group_id:
        return_error('Please enter either group id or group name')

    if endpoint_group_name and not endpoint_group_id:
        endpoint_group_data = get_endpoint_id(endpoint_group_name).get('SearchResult', {})
        if endpoint_group_data.get('total', 0) < 1:
            return_error('No endpoints were found. Please make sure you entered the correct group name')
        else:
            endpoint_group_id = endpoint_group_data.get('resources')[0].get('id')

    endpoint_id = demisto.args().get('id')
    endpoint_mac_address = demisto.args().get('macAddress')

    if endpoint_mac_address and not is_mac_address(endpoint_mac_address):
        return_error('Please enter a valid mac address')

    if not endpoint_id and not endpoint_mac_address:
        return_error('Please enter either endpoint id or endpoint mac address')

    if endpoint_mac_address and not endpoint_id:
        endpoint_id = get_endpoint_id(endpoint_mac_address).get('SearchResult', {}).get('resources', [])[0].get('id',
                                                                                                                None)
    endpoint_details = get_endpoint_details(endpoint_id)

    if "ERSEndPoint" not in endpoint_details:
        return_error('Failed to get endpoint %s' % endpoint_id)

    try:
        updated_endpoint_details = {'ERSEndPoint': {}}  # type: Dict[str, Any]
        updated_endpoint_details['ERSEndPoint']['groupId'] = endpoint_group_id
        updated_endpoint_details['ERSEndPoint']['id'] = endpoint_details.get('ERSEndPoint', {}).get('id')
        updated_endpoint_details['ERSEndPoint']['mac'] = endpoint_details.get('ERSEndPoint', {}).get('mac')
        updated_endpoint_details['ERSEndPoint']['name'] = endpoint_details.get('ERSEndPoint', {}).get('name')

        update_result = update_endpoint_by_id(endpoint_id, updated_endpoint_details)
        if update_result:
            # Create result
            msg = "Endpoint " + endpoint_id + " updated successfully"
        else:
            msg = "Update failed for endpoint " + endpoint_id + ", got the following response: " + update_result.get(
                'ERSResponse', {}).get('messages', [])

    except Exception as e:
        raise Exception(f"Exception: Failed to update endpoint {endpoint_id}: " + str(e))

    demisto.results(msg)


def list_number_of_active_sessions():
    """
    This function is used for test-module to check connectivity
    """
    api_endpoint = "/admin/API/mnt/Session/ActiveCount"

    response = http_request('GET', api_endpoint)

    return response


def get_policies_request():

    api_endpoint = '/ers/config/ancpolicy'

    response = http_request('GET', api_endpoint)

    return response


def get_policies():
    """
    Return all ANC policies
    """
    data = []

    policies_data = get_policies_request().get('SearchResult', {})

    if policies_data.get('total', 0) < 1:
        return 'No policies were found.'

    policies = policies_data.get('resources', [])

    for policy in policies:
        data.append({
            'ID': policy.get('id'),
            'Name': policy.get('name')
        })

    context = {
        'CiscoISE.Policy(val.ID && val.ID === obj.ID)': data
    }

    return_outputs(
        tableToMarkdown('CiscoISE Adaptive Network Control Policies', data, removeNull=True),
        context,
        policies_data
    )
    return None


def get_policy_by_name(policy_name):

    api_endpoint = f'/ers/config/ancpolicy/name/{policy_name}'

    response = http_request('GET', api_endpoint)
    return response


def get_policy():
    """
    Returns: the specific ANC policy
    """

    data = []
    policy_name = demisto.args().get('policy_name')

    if not policy_name:
        return_error('Please enter either policy name or policy id')

    policy_data = get_policy_by_name(policy_name).get('ErsAncPolicy', {}) if policy_name else None

    if policy_data:
        data.append({
            'Name': policy_data.get('name'),
            'Action': policy_data.get('actions')
        })

    context = {
        'CiscoISE.Policy(val.ID && val.ID === obj.ID)': data
    }

    return_outputs(tableToMarkdown('CiscoISE Policy', data, removeNull=True), context, policy_data)


def create_policy_request(data):

    api_endpoint = '/ers/config/ancpolicy'

    http_request('POST', api_endpoint, data=json.dumps(data))


def create_policy():
    """
    Create ANC Policy
    """
    policy_name = demisto.args().get('policy_name')
    policy_actions = demisto.args().get('policy_actions', '')

    data = {
        'ErsAncPolicy': {
            'name': policy_name,
            'actions': [policy_actions]
        }
    }
    create_policy_request(data)
    policy_context = {
        'Name': policy_name,
        'Action': [policy_actions]
    }

    context = {
        'CiscoISE.Policy(val.Name && val.Name === obj.Name)': policy_context
    }

    return_outputs(f'The policy "{policy_name}" has been created successfully', context)


def assign_policy_request(data):

    api_endpoint = '/ers/config/ancendpoint/apply'

    http_request('PUT', api_endpoint, data=json.dumps(data))


def assign_policy_to_endpoint():
    """
    Apply ANC policy to an endpoint
    """

    policy_name = demisto.args().get('policy_name')
    mac_address = demisto.args().get('mac_address')
    if not is_mac_address(mac_address):
        return_error('Please enter a valid mac address')

    data = {
        'OperationAdditionalData': {
            'additionalData': [{
                'name': 'macAddress',
                'value': mac_address
            },
                {
                'name': 'policyName',
                'value': policy_name
            }
            ]
        }
    }
    assign_policy_request(data)

    endpoint_context = {
        'MACAddress': mac_address,
        'PolicyName': policy_name
    }

    context = {
        'CiscoISE.Endpoint(val.ID && val.ID === obj.ID)': endpoint_context
    }

    return_outputs(f'The policy "{policy_name}" has been assigned successfully', context)


def remove_policy_request(data):

    api_endpoint = '/ers/config/ancendpoint/clear'

    http_request('PUT', api_endpoint, data=json.dumps(data))


def remove_policy_from_endpoint():
    """
    Remove ANC policy from an endpoint
    """

    policy_name = demisto.args().get('policy_name')
    mac_address = demisto.args().get('mac_address')
    if not is_mac_address(mac_address):
        return_error('Please enter a valid mac address')

    data = {
        'OperationAdditionalData': {
            'additionalData': [{
                'name': 'macAddress',
                'value': mac_address
            },
                {
                'name': 'policyName',
                'value': policy_name
            }
            ]
        }
    }
    remove_policy_request(data)

    endpoint_context = {
        'MACAddress': mac_address,
        'PolicyName': policy_name
    }

    context = {
        'CiscoISE.Endpoint(val.ID && val.ID === obj.ID)': endpoint_context
    }

    return_outputs(f'The policy "{policy_name}" has been removed successfully', context)


def get_blacklist_group_id():

    api_endpoint = '/ers/config/endpointgroup?filter=name.EQ.Blacklist'

    response = http_request('GET', api_endpoint)

    return response


def get_blacklist_endpoints_request():

    blacklist = get_blacklist_group_id().get('SearchResult', {})

    resources = blacklist.get('resources', [])
    blacklist_id = {}
    if resources:
        blacklist_id = resources[0]
    else:
        return_error('No blacklist endpoint were found.')

    black_id = blacklist_id.get('id')

    api_endpoint = f'/ers/config/endpoint?filter=groupId.EQ.{black_id}'
    blacklist_response = http_request('GET', api_endpoint)

    return blacklist_response


def get_blacklist_endpoints():

    data = []
    blacklist_endpoints = get_blacklist_endpoints_request().get('SearchResult', {})

    if blacklist_endpoints.get('total', 0) < 1:
        demisto.results('No endpoints were found.')

    endpoints = blacklist_endpoints.get('resources', [])

    for endpoint in endpoints:
        data.append({
            'ID': endpoint.get('id'),
            'Name': endpoint.get('name'),
            'GroupName': 'Blacklist'
        })

    context = {
        'CiscoISE.Endpoint(val.ID && val.ID === obj.ID)': data
    }

    return_outputs(tableToMarkdown('CiscoISE Blacklist Endpoints', data, removeNull=True), context, endpoints)


def get_endpoint_id_by_name(mac_address=None):
    """
    Returns endpoint id by specific mac address
    Only compatible with Cisco ISE versions 2.3
    """
    if not is_mac_address(mac_address):
        return_error('Given MAC address is invalid')

    api_endpoint = f'/ers/config/endpoint/name/{mac_address}'
    return http_request('GET', api_endpoint, '')


def get_endpoint_id_by_name_command():

    mac_address = demisto.args().get('mac_address')

    if not is_mac_address(mac_address):
        return_error('Given MAC address is invalid')

    endpoint_data = get_endpoint_id_by_name(mac_address)
    endpoint_id = endpoint_data.get('ERSEndPoint', {}).get('id', None)

    entry_context = {
        'Endpoint(val.ID === obj.ID)': {
            'ID': endpoint_id,
            'MACAddress': mac_address
        }
    }

    return_outputs(f'The endpoint ID is: {endpoint_id}', entry_context, endpoint_id)


def get_node_details(name=None):
    """
    Returns details for the given Cisco ISE node
    """
    if not name:
        return_error('Given Cisco ISE node is invalid')

    api_endpoint = f'/ers/config/node/name/{name}'
    return http_request('GET', api_endpoint, '')


def get_all_nodes_command():
    """
    Returns all nodes in the Cisco ISE Deployment
    Also sets isLocalIstance in the output
    """

    instance_ip = urlparse(BASE_URL).netloc
    try:
        instance_ip = socket.gethostbyname(instance_ip)
    except Exception as e:
        err_msg = (f'Failed to get ip address of configured Cisco ISE instance - {e}')
        raise Exception(err_msg)

    data = []
    api_endpoint = '/ers/config/node'
    response = http_request('GET', api_endpoint)
    results = response.get('SearchResult', {})

    if results.get('total', 0) < 1:
        demisto.results("No Nodes were found")

    node_data = results.get('resources', [])
    for node in node_data:
        is_local_istance = False
        name = node.get('name')
        node_details = get_node_details(name).get('Node', {})
        ip = node_details.get('ipAddress')
        if ip == instance_ip:
            is_local_istance = True

        data.append({
            'Name': name,
            'ip': ip,
            'isLocalIstance': is_local_istance,
            # if false then standalone mode.. ie single node
            'inDeployment': node_details.get('inDeployment'),
            # primary means active node
            'primaryPapNode': node_details.get('primaryPapNode'),
        })

    context = {
        'CiscoISE.NodesData': data
    }

    return_outputs(tableToMarkdown('CiscoISE deployment nodes', data, removeNull=True), context)


def create_new_endpoint_command():
    """
    Creates a new Endpoint in Cisco ISE with the given
    Mac address and Custom attributes
    """

    attr_map = demisto.args().get('attributes_map')
    mac_address = demisto.args().get('mac_address')
    if not is_mac_address(mac_address):
        return_error('Please enter a valid mac address')
    if attr_map is not None:
        attr_map = json.loads(attr_map)
    data = {
        "ERSEndPoint": {
            "mac": mac_address,
            "customAttributes": {
                "customAttributes": attr_map
            }
        }
    }

    api_endpoint = '/ers/config/endpoint'
    http_request('POST', api_endpoint, data=json.dumps(data))
    endpoint_context = {
        'MACAddress': mac_address,
    }

    context = {
        'CiscoISE.Endpoint(val.Name && val.Name === obj.Name)': endpoint_context
    }
    return_outputs(f'Endpoint "{mac_address}" has been created successfully', context)


def get_session_data_by_ip_request(ip):
    ip_address = f'/admin/API/mnt/Session/EndPointIPAddress/{ip}'
    response = http_request('GET', ip_address, is_admin_api=True)
    byte_conversion = str(response, 'utf-8')
    json_data = xml2json(byte_conversion)
    session_data = json.loads(json_data)

    context = {
        'CiscoISE.Endpoint(val.ID && val.ID === obj.ID)': session_data
    }

    return_outputs('The targeted users session xml is being returned.', context)


def get_session_data_by_ip():
    """
    Returns: the session data given an ip address
    """
    ip = demisto.args().get('ip_address')
    if not ip:
        return_error('Please enter the ip')

    get_session_data_by_ip_request(ip)


''' EXECUTION CODE '''


def main():

    LOG('Command being called is %s' % (demisto.command()))
    try:
        handle_proxy()
        if demisto.command() == 'test-module':
            if get_endpoints_command(True):
                demisto.results('ok')
            else:
                demisto.results('test failed')
        elif demisto.command() == 'cisco-ise-get-endpoint-id':
            get_endpoint_id_command()
        elif demisto.command() == 'cisco-ise-get-endpoint-details':
            get_endpoint_details_command()
        elif demisto.command() == 'cisco-ise-reauthenticate-endpoint':
            reauthenticate_endpoint_command()
        elif demisto.command() == 'cisco-ise-get-endpoints':
            get_endpoints_command()
        elif demisto.command() == 'cisco-ise-update-endpoint-custom-attribute':
            update_endpoint_custom_attribute_command()
        elif demisto.command() == 'cisco-ise-update-endpoint-group':
            update_endpoint_group_command()
        elif demisto.command() == 'cisco-ise-get-groups':
            get_groups()
        elif demisto.command() == 'cisco-ise-get-policies':
            get_policies()
        elif demisto.command() == 'cisco-ise-get-policy':
            get_policy()
        elif demisto.command() == 'cisco-ise-create-policy':
            create_policy()
        elif demisto.command() == 'cisco-ise-assign-policy':
            assign_policy_to_endpoint()
        elif demisto.command() == 'cisco-ise-remove-policy':
            remove_policy_from_endpoint()
        elif demisto.command() == 'cisco-ise-get-blacklist-endpoints':
            get_blacklist_endpoints()
        elif demisto.command() == 'cisco-ise-create-endpoint':
            create_new_endpoint_command()
        elif demisto.command() == 'cisco-ise-get-nodes':
            get_all_nodes_command()
        elif demisto.command() == 'cisco-ise-get-endpoint-id-by-name':
            get_endpoint_id_by_name_command()
        elif demisto.command() == 'cisco-ise-get-session-data-by-ip':
            get_session_data_by_ip()

    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
