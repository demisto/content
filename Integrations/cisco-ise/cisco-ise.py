import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import requests
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Handle proxy
proxies = {}
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']
else:
    def get_env_var(key):
        for k in (key.lower(), key.upper()):
            if k in os.environ:
                return os.environ[k]
        return None


    proxies = {
        'http': get_env_var('http_proxy'),
        'https': get_env_var('https_proxy')
    }

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBAL VARS '''

BASE_URL = re.sub("/[\/]+$/", "", demisto.params().get('serverURL'))
SERVER_PORT = demisto.params().get('serverPort')
SERVER_URL = BASE_URL + ':' + SERVER_PORT

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')

USE_SSL = not demisto.params().get('insecure', False)

ISE = requests.session()
ISE.auth = (USERNAME, PASSWORD)
ISE.verify = USE_SSL
ISE.disable_warnings = True
ISE.timeout = 5
ISE.proxies = proxies

''' HELPER FUNCTIONS '''


def is_mac(mac):
    """
    Test for valid mac address
    :param mac: MAC address in the form of AA:BB:CC:00:11:22
    :return: True/False
    """

    if re.search(r'([0-9A-F]{2}[:]){5}([0-9A-F]){2}', mac.upper()) is not None:
        return True
    else:
        return False


def http_request(method, url_suffix, params_dict, data=None, headers={}):
    url = SERVER_URL + url_suffix
    LOG('running %s request with url=%s' % (method, url))
    try:
        if method == 'GET':
            ISE.headers.update(headers)
            result = ISE.get(url, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=USE_SSL)
            if result.status_code == 200:
                return result
            elif result.status_code == 404:
                pass
            else:
                raise Exception("Got status code: " + str(result.status_code) + " For the request to the " + url_suffix
                                + " endpoint. " + result.text.encode('utf8'))
        elif method == 'PUT':
            ISE.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
            result = ISE.put(url, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=USE_SSL, data=json.dumps(data))
            return result

    except Exception as e:
        LOG(e)
        raise Exception(str(e))


def translate_group_id(group_id):
    """
    Translates group ID to group name
    """
    headers = {
        'Accept': 'application/json',
    }
    api_endpoint = "/ers/config/identitygroup/1"
    identity_group = http_request('GET', api_endpoint, {}, {}, headers).json()['IdentityGroup']
    return identity_group['name']


''' COMMANDS FUNCTIONS '''


def get_groups_request():

    headers = {
        'Accept': 'application/json',
        'Connection': 'keep_alive'
    }
    api_endpoint = '/ers/config/endpointgroup'
    return json.loads(http_request('GET', api_endpoint, {}, {}, headers).text)


def get_groups():
    """
    Retrieve a collection of endpoint identity groups.
    """

    groups_data = get_groups_request().get('SearchResult', {})

    if groups_data.get('total', 0) < 1:
        return 'No groups were found.'

    groups = groups_data.get('resources', [])
    context = []
    hr = []

    for group in groups:
        context_dict = {
            'ID': group.get('id'),
            'Name': group.get('name'),
            'Description': group.get('description')
        }
        hr_dict = dict(context_dict)
        link_data = group.get('link')
        if link_data:
            href = link_data.get('href')
            hr_dict['Link'] = '[{0}]({0})'.format(href)
        context.append(context_dict)
        hr.append(hr_dict)

    ec = {
        'CiscoISE.Group(val.ID == obj.ID)': context
    }

    return {
        'Type': entryTypes['note'],
        'Contents': groups,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Cisco pxGrid ISE Groups', hr, ['ID', 'Name', 'Link'],
                                         removeNull=True),
        'EntryContext': ec
    }


def get_endpoint_id(mac_address=None, group_name=None):
    """
    Returns endpoint id by specific mac address
    """
    headers = None
    if mac_address is not None:
        headers = {
            'Accept': 'application/json',
            'Connection': 'keep_alive'
        }
        api_endpoint = "/ers/config/endpoint?filter=mac.EQ.{}".format(mac_address)
    if group_name is not None:
        api_endpoint = "/ers/config/endpointgroup?filter=name.EQ.{}".format(group_name)
        headers = {
            "Content-Type": "application/vnd.com.cisco.ise.identity.endpoint.1.0+xml; charset=utf-8",
            'Accept': 'application/json'
        }
    return json.loads(http_request('GET', api_endpoint, {}, '', headers).text)


def get_endpoint_id_command():
    """
    corresponds to 'cisco-ise-get-endpoint-id' command. Returns endpoint's id
    """
    mac_address = demisto.args().get('macAddress')

    if not is_mac(mac_address):
        return_error('Given MAC address is invalid')

    endpoint_data = get_endpoint_id(mac_address)
    endpoint_id = endpoint_data.get('SearchResult', {}).get('resources', [])[0].get('id', None)

    ec = {
        'Endpoint(val.ID === obj.ID)': {
            'ID': endpoint_id,
            'MACAddress': mac_address
        }
    }

    return {
        'Type': entryTypes['note'],
        'Contents': endpoint_id,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': "The endpoint ID is: " + endpoint_id,
        'EntryContext': ec
    }


def get_endpoint_details(endpoint_id):
    """
    Gets endpoint details by specific id
    """
    headers = {
        'Accept': 'application/json',
        'Connection': 'keep_alive'
    }
    api_endpoint = '/ers/config/endpoint/{}'.format(endpoint_id)
    response = http_request('GET', api_endpoint, {}, {}, headers)
    if response:
        return json.loads(response.text)
    else:
        return_error('Endpoint was not found.')


def get_endpoint_details_command():
    """
    corresponds to 'cisco-ise-get-endpoint-details' command. Returns information about a specific endpoint
    """

    endpoint_id = demisto.args().get('endpointID')
    endpoint_mac_address = demisto.args().get('macAddress')

    if endpoint_mac_address and not is_mac(endpoint_mac_address):
        return_error('Given MAC address is invalid')

    if not endpoint_id and not endpoint_mac_address:
        return_error('Either endpoint ID or MAC address should be provided')

    if endpoint_mac_address and not endpoint_id:
        endpoint_id = get_endpoint_id(endpoint_mac_address).get('SearchResult', {}).get('resources', [])[0].get('id',
                                                                                                                None)

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
            'Link': '[{0}]({0})'.format(endpoint_details['link'].get('href')),
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
        return {
            'Type': entryTypes['note'],
            'Contents': endpoint_details,
            'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown(title, hr, removeNull=True),
            'EntryContext': ec
        }
    else:
        return 'No results found'


def reauthenticate_endpoint(mac_address, psn_address):
    """
    Reauthenticates an endpoint
    """
    api_endpoint = "/admin/API/mnt/CoA/Reauth/{}/{}/1".format(psn_address, mac_address)
    response = http_request('GET', api_endpoint, {}, {}, {})
    return response


def get_psn_for_mac(mac_address):
    """
    Retrieves psn for an endpoint
    """
    api_endpoint = "/admin/API/mnt/AuthStatus/MACAddress/{}/86400/0/0".format(mac_address)
    response = http_request('GET', api_endpoint, {}, {}, {})
    if response:
        return response
    else:
        return_error('Could not reauthenticate the endpoint')


def reauthenticate_endpoint_command():
    """
    corresponds to 'cisco-ise-reauthenticate-endpoint' command. Reauthenticates an endpoint
    """
    mac_address = demisto.args().get('macAddress').upper()
    if not is_mac(mac_address):
        return "Please enter a valid mac address"
    mac_address = (':').join([x.upper() for x in mac_address.split(':')])
    mac_address_psn = get_psn_for_mac(mac_address)
    if not mac_address_psn:
        return "Couldn't find psn address for mac: " + mac_address
    psn_address = \
    json.loads(xml2json(mac_address_psn)).get('restAuthStatusOutputList', {}).get('authStatusList', {}).get(
        'authStatusElements', {})[0].get('acs_server')
    if not psn_address:
        return "Couldn't find psn address for mac: " + mac_address + " response from psn endpoint was: " + json.dumps(
            mac_address_psn)
    activation_result = reauthenticate_endpoint(mac_address, psn_address).text
    json_activation_result = json.loads(xml2json(activation_result)).get('remoteCoA').get('results')
    activation_result_boolean = 'true' in json_activation_result
    return {
        'Type': entryTypes['note'],
        'Contents': activation_result,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Activation result was : ' + activation_result_boolean,
        'EntryContext': {
            "CiscoISE.Endpoint(val.MACAddress==obj.MACAddress)": {
                'MACAddress': json_activation_result,
                'reauthenticateResult': activation_result_boolean
            }
        }
    }


def get_endpoints():
    """
    Gets data about existing endpoints
    """
    headers = {
        'Accept': 'application/json',
        'Connection': 'keep_alive'
    }
    api_endpoint = "/ers/config/endpoint"
    return json.loads(http_request('GET', api_endpoint, {}, {}, headers).text)


def get_endpoints_command():
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
        link_data = endpoint.get('link')
        if link_data:
            href = link_data.get('href')
            hr_dict['Link'] = '[{0}]({0})'.format(href)
        context.append(context_dict)
        hr.append(hr_dict)

    ec = {
        'Endpoint(val.ID == obj.ID)': context,
        'CiscoISE.Endpoint(val.ID == obj.ID)': context
    }

    return {
        'Type': entryTypes['note'],
        'Contents': endpoints,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Cisco pxGrid ISE Endpoints', hr, ['ID', 'MACAddress', 'Link'],
                                         removeNull=True),
        'EntryContext': ec
    }


def update_endpoint_by_id(endpoint_id, endpoint_details):
    """
    Updates endpoint status
    """
    headers = {
        "Content-Type": "application/vnd.com.cisco.ise.identity.endpoint.1.0+xml; charset=utf-8"
    }
    api_endpoint = "/ers/config/endpoint/{}".format(endpoint_id)
    return http_request('PUT', api_endpoint, {}, endpoint_details, headers)


def update_endpoint_custom_attribute_command():
    """
    corresponds to 'cisco-ise-update-endpoint-custom-attribute' command.
    Blocks endpoint using predefined custom fields
    """

    endpoint_id = demisto.args().get('id')
    endpoint_mac_address = demisto.args().get('macAddress')

    if endpoint_mac_address and not is_mac(endpoint_mac_address):
        return "Please enter a valid mac address"

    if not endpoint_id and not endpoint_mac_address:
        return 'Please enter either endpoint id or endpoint mac address'

    if endpoint_mac_address and not endpoint_id:
        endpoint_id = get_endpoint_id(endpoint_mac_address).get('SearchResult', {}).get('resources', [])[0].get('id',
                                                                                                                None)

    endpoint_details = get_endpoint_details(endpoint_id)

    if "ERSEndPoint" not in endpoint_details:
        return 'Failed to get endpoint %s' % endpoint_id

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
        if update_result.status_code != 200:
            return "Update failed for endpoint " + endpoint_id + ". Please check if the custom fields are defined in " \
                                                                 "the system. Got the following response: " + \
                   json.dumps(json.loads(update_result.text).get('ERSResponse', {}).get('messages', []))

        update_json = json.loads(update_result.text)

        updated_fields_dict_list = update_json.get('UpdatedFieldsList', {}).get('updatedField', [])

        if len(updated_fields_dict_list) > 0:
            updated_fields_string = ' the new custom fields are: ' + json.dumps(
                updated_fields_dict_list[0].get('newValue'))
        else:
            updated_fields_string = ", but the fields that you've tried to update already had that specific value " \
                                    "or do not exist"

        return 'Successfully updated endpoint %s' % endpoint_id + updated_fields_string

    except Exception as e:
        raise Exception("Exception: Failed to update endpoint {}: ".format(endpoint_id) + str(e))


def update_endpoint_group_command():
    """
    corresponds to 'cisco-ise-update-endpoint-group' command. Updates endpoint status
    """

    endpoint_group_name = demisto.args().get('groupName')
    endpoint_group_id = demisto.args().get('groupId')

    if not endpoint_group_name and not endpoint_group_id:
        return 'Please enter either group id or group name'

    if endpoint_group_name and not endpoint_group_id:
        endpoint_group_data = get_endpoint_id(None, endpoint_group_name).get('SearchResult', {})
        if endpoint_group_data.get('total', 0) < 1:
            return 'No endpoints were found. Please make sure you entered the correct group name'

        endpoint_group_id = endpoint_group_data.get('resources')[0].get('id')

    endpoint_id = demisto.args().get('id')
    endpoint_mac_address = demisto.args().get('macAddress')

    if endpoint_mac_address and not is_mac(endpoint_mac_address):
        return "Please enter a valid mac address"

    if not endpoint_id and not endpoint_mac_address:
        return 'Please enter either endpoint id or endpoint mac address'

    if endpoint_mac_address and not endpoint_id:
        endpoint_id = get_endpoint_id(endpoint_mac_address).get('SearchResult', {}).get('resources', [])[0].get('id',
                                                                                                                None)

    endpoint_details = get_endpoint_details(endpoint_id)

    if "ERSEndPoint" not in endpoint_details:
        return 'Failed to get endpoint %s' % endpoint_id

    try:
        endpoint_details['ERSEndPoint']['groupId'] = endpoint_group_id
        update_result = update_endpoint_by_id(endpoint_id, endpoint_details)

        # Create result
        msg = "Endpoint " + endpoint_id + " updated successfully" if update_result.status_code == 200 \
            else "Update failed for endpoint " + endpoint_id + ", got the following response: " + \
                 json.dumps(json.loads(update_result.text).get('ERSResponse', {}).get('messages', []))
        result = [{'Update status': msg}]

    except Exception as e:
        raise Exception("Exception: Failed to update endpoint {}: ".format(endpoint_id) + str(e))

    return {
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': msg,
    }


def list_number_of_active_sessions():
    """
    This function is used for test-module to check connectivity
    """
    api_endpoint = "/admin/API/mnt/Session/ActiveCount"

    response = http_request('GET', api_endpoint, {}, {}, {})

    return response


''' EXECUTION CODE '''
try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        if get_endpoints_command():
            demisto.results('ok')
        elif list_number_of_active_sessions():
            demisto.results('ok')
        else:
            demisto.results('test failed')
    elif demisto.command() == 'cisco-ise-get-endpoint-id':
        demisto.results(get_endpoint_id_command())
    elif demisto.command() == 'cisco-ise-get-endpoint-details':
        demisto.results(get_endpoint_details_command())
    elif demisto.command() == 'cisco-ise-reauthenticate-endpoint':
        demisto.results(reauthenticate_endpoint_command())
    elif demisto.command() == 'cisco-ise-get-endpoints':
        demisto.results(get_endpoints_command())
    elif demisto.command() == 'cisco-ise-update-endpoint-custom-attribute':
        demisto.results(update_endpoint_custom_attribute_command())
    elif demisto.command() == 'cisco-ise-update-endpoint-group':
        demisto.results(update_endpoint_group_command())
    elif demisto.command() == 'cisco-ise-get-groups':
        demisto.results(get_groups())

except Exception as e:
    LOG(e.message)
    LOG.print_log()
    raise Exception(str(e))
