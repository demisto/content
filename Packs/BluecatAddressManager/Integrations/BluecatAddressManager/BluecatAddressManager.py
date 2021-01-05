from CommonServerPython import *

""" IMPORTS """
import ipaddress
import requests
import urllib3


# error class for token errors
class TokenException(Exception):
    pass


# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params().get('url')[:-1] \
    if (demisto.params().get('url') and demisto.params().get('url').endswith('/')) else demisto.params().get('url')
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# Service base URL
BASE_URL = f'{SERVER}/Services/REST/v1'

# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
TOKEN_LIFE_TIME_MINUTES = 5
USER_CONF = demisto.params().get('conf_name')
USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')

''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, headers=HEADERS, safe=False):
    """
        A wrapper for requests lib to send our requests and handle requests and responses better.

        :type method: ``str``
        :param method: HTTP method for the request.

        :type url_suffix: ``str``
        :param url_suffix: The suffix of the URL (endpoint)

        :type params: ``dict``
        :param params: The URL params to be passed.

        :type data: ``str``
        :param data: The body data of the request.

        :type headers: ``dict``
        :param headers: Request headers

        :type safe: ``bool``
        :param safe: If set to true will return None in case of http error

        :return: Returns the http request response json
        :rtype: ``dict``
    """
    headers['Authorization'] = get_token()
    url = BASE_URL + url_suffix
    try:
        res = requests.request(method, url, verify=USE_SSL, params=params, data=data, headers=headers)
        # Try to create a new token
        if res.status_code == 401:
            headers['Authorization'] = get_token(new_token=True)
            res = requests.request(method, url, verify=USE_SSL, params=params, data=data, headers=headers)
    except requests.exceptions.RequestException:
        return_error('Error in connection to the server. Please make sure you entered the URL correctly.')
    # Handle error responses gracefully
    if res.status_code not in {200, 201, 202}:
        result_msg = None
        try:
            result_msg = res.json()
        finally:
            reason = result_msg if result_msg else res.reason
            err_msg = f'Error in API call. code:{res.status_code}; reason: {reason}'
            if safe:
                return None
            return_error(err_msg)
    return res.json()


def get_token(new_token=False):
    """
        Retrieves the token from the server if it's expired and updates the global HEADERS to include it

        :param new_token: If set to True will generate a new token regardless of time passed

        :rtype: ``str``
        :return: Token
    """
    now = datetime.now()
    ctx = demisto.getIntegrationContext()
    if ctx and not new_token:
        passed_minutes = get_passed_minutes(now, datetime.fromtimestamp(ctx.get('time')))
        if passed_minutes >= TOKEN_LIFE_TIME_MINUTES:
            # token expired
            auth_token = get_token_request()
            demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
        else:
            # token hasn't expired
            auth_token = ctx.get('auth_token')
    else:
        # generating new token
        auth_token = get_token_request()
        demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
    return auth_token


def get_configuration():
    """
    Gets the chosen configuration to run queries on

    :return: User configuration id, or the first configuration id if no user configuration provided
    """
    user_conf = USER_CONF
    params = {
        'type': 'Configuration',
        'start': 0,
        'count': 100
    }
    confs = http_request('GET', '/getEntities', params)
    if not confs:
        return_error('No configurations could be fetched from the system')
    if user_conf:
        for conf in confs:
            if conf.get('name') == user_conf:
                return conf.get('id')

    return confs[0].get('id')


def get_passed_minutes(start_time, end_time):
    """
        Returns the time passed in minutes
        :param start_time: Start time in datetime
        :param end_time: End time in datetime
        :return: The passed minutes in int
    """
    time_delta = start_time - end_time
    return time_delta.seconds / 60


def properties_to_camelized_dict(properties):
    properties = properties.split('|')
    properties_dict = {}
    for _property in properties:
        if _property:
            key_val_pair = _property.split('=')
            # camelize the key
            key = key_val_pair[0][0].upper() + key_val_pair[0][1:]
            properties_dict[key] = key_val_pair[1]
    return properties_dict


''' COMMANDS + REQUESTS FUNCTIONS '''


def get_token_request():
    url_args = {
        'username': USERNAME,
        'password': PASSWORD
    }
    start_idx = 16
    end_delim = ' <-'
    url = BASE_URL + '/login'
    res = requests.request('GET', url, verify=USE_SSL, params=url_args)
    if res.status_code != 200:
        raise TokenException('Error: Failed to create a new token, please check your credentials')
    res_json = res.json()
    end_idx = res_json.index(end_delim)
    return res_json[start_idx:end_idx]


def test_module():
    """
    Performs basic get request to get item samples
    """
    get_token(new_token=True)
    demisto.results('ok')


def query_ip_command():
    ip = demisto.getArg('ip')
    try:
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
            ip_type = 'IPv6'
            base_ip_raw_res = query_ipv6(ip)
        else:
            ip_type = 'IPv4'
            base_ip_raw_res = query_ipv4(ip)

        # entity with id 0 is root, and CONF is root of parent
        if base_ip_raw_res.get('id') in (None, 0, CONF):
            return_outputs(f'IP: {ip} was not found.', {}, base_ip_raw_res)
        else:
            base_ip_parents = get_entity_parents(base_ip_raw_res.get('id'))
            ip_object = {
                'ID': base_ip_raw_res.get('id'),
                'Name': base_ip_raw_res.get('name'),
                'Parents': base_ip_parents,
                'Type': ip_type
            }
            ip_object.update(properties_to_camelized_dict(base_ip_raw_res.get('properties')))
            ec = {
                'BlueCat.AddressManager.IP(obj.ID === val.ID)': ip_object,
                'IP(val.Address === obj.Address)': {'Address': ip}
            }
            hr = create_human_readable_ip(ip_object, ip)
            return_outputs(hr, ec, base_ip_raw_res)

    except ipaddress.AddressValueError:
        return_error(f'Invalid IP: {ip}')


def query_ipv4(ip):
    params = {
        'containerId': CONF,
        'address': ip
    }
    return http_request('GET', '/getIP4Address', params=params)


def query_ipv6(ip):
    params = {
        'containerId': CONF,
        'address': ip
    }
    return http_request('GET', '/getIP6Address', params=params)


def get_entity_parents(base_id):
    base_ip_parents = []
    entity_parent = get_entity_parent(entity_id=base_id)
    # entity with id 0 is root, and CONF is root of parent
    while entity_parent.get('id') not in (None, 0, CONF):
        parent_obj = {
            'ID': entity_parent.get('id'),
            'Type': entity_parent.get('type'),
            'Name': entity_parent.get('name'),
        }
        parent_obj.update(properties_to_camelized_dict(entity_parent.get('properties')))
        base_ip_parents.append(parent_obj)
        entity_parent = get_entity_parent(entity_id=entity_parent.get('id'))

    return base_ip_parents


def get_entity_parent(entity_id):
    params = {
        'entityId': entity_id
    }
    return http_request('GET', '/getParent', params=params)


def create_human_readable_ip(ip_object, ip_value):
    ip_object_cpy = dict(ip_object)
    reversed_parents = list(reversed(ip_object_cpy['Parents']))
    ip_object_cpy.pop('Parents')
    hr = tblToMd(f'{ip_value} IP Result:', ip_object_cpy, headerTransform=pascalToSpace)
    hr += tblToMd('Parents Details:', reversed_parents, headerTransform=pascalToSpace)
    return hr


def get_range_by_ip_command():
    ip = demisto.getArg('ip')
    try:
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address) or isinstance(ipaddress.ip_address(ip),
                                                                                     ipaddress.IPv4Address):
            range_raw_res = get_range_by_ip(ip)

            if range_raw_res.get('id') in (None, 0, CONF):
                return_outputs(f'IP range was not found for {ip}.', {}, range_raw_res)
            else:
                base_ip_parents = get_entity_parents(range_raw_res.get('id'))

                range_object = {
                    'ID': range_raw_res.get('id'),
                    'Name': range_raw_res.get('name'),
                    'Parents': base_ip_parents,
                    'Type': range_raw_res.get('type')
                }

                range_object.update(properties_to_camelized_dict(range_raw_res.get('properties')))
                ec = {'BlueCat.AddressManager.Range(obj.ID === val.ID)': range_object}
                hr = create_human_readable_range(range_object, ip)
                return_outputs(hr, ec, range_raw_res)

    except ipaddress.AddressValueError:
        return_error(f'Invalid IP: {ip}')


def get_range_by_ip(ip):
    params = {
        'containerId': CONF,
        'type': '',
        'address': ip
    }
    return http_request('GET', '/getIPRangedByIP', params=params)


def create_human_readable_range(range_object, ip_value):
    range_object_cpy = dict(range_object)
    reversed_parents = list(reversed(range_object_cpy['Parents']))
    range_object_cpy.pop('Parents')
    hr = tblToMd(f'{ip_value} Range Result:', range_object_cpy, headerTransform=pascalToSpace)
    hr += tblToMd('Parents Details:', reversed_parents, headerTransform=pascalToSpace)
    return hr


def get_response_policies_command():
    start = demisto.getArg('start')
    count = demisto.getArg('count')
    raw_response_policies = get_response_policies(start, count)
    response_policies, hr = create_response_policies_result(raw_response_policies)
    return_outputs(hr, response_policies, raw_response_policies)


def get_response_policies(start, count):
    params = {
        'parentId': CONF,
        'type': 'ResponsePolicy',
        'start': start,
        'count': count
    }
    return http_request('GET', '/getEntities', params=params)


def create_response_policies_result(raw_response_policies):
    response_policies = []
    if raw_response_policies:
        hr = '## Response Policies:\n'
        for response_policy in raw_response_policies:
            response_policy_obj = {
                'ID': response_policy.get('id'),
                'Name': response_policy.get('name'),
                'Type': response_policy.get('type')
            }
            response_policy_obj.update(properties_to_camelized_dict(response_policy.get('properties')))
            hr += tblToMd(response_policy_obj['Name'], response_policy_obj)
            response_policies.append(response_policy_obj)
        return {'BlueCat.AddressManager.ResponsePolicies(val.ID === obj.ID)': response_policies}, hr
    return {}, 'Could not find any response policy'


def add_domain_response_policy_command():
    policy_id = demisto.getArg('policy_id')
    domain = demisto.getArg('domain')
    raw_response = add_domain_response_policy(policy_id, domain)
    error_msg = f'Failed to add {domain} to response policy {policy_id}, ' \
                f'possibly the domain already exists in the response policy.'
    if raw_response:
        return_outputs(f'Successfully added {domain} to response policy {policy_id}', {}, raw_response)
    else:
        return_outputs(error_msg, {}, raw_response)


def add_domain_response_policy(policy_id, domain):
    params = {
        'policyId': policy_id,
        'itemName': domain
    }
    return http_request('POST', '/addResponsePolicyItem', params=params)


def remove_domain_response_policy_command():
    policy_id = demisto.getArg('policy_id')
    domain = demisto.getArg('domain')
    raw_response = remove_domain_response_policy(policy_id, domain)
    error_msg = f'Failed to remove {domain} from response policy {policy_id}, ' \
                f'possibly the domain doesn\'t exist in the response policy.'
    if raw_response:
        return_outputs(f'Successfully removed {domain} from response policy {policy_id}', {}, raw_response)
    else:
        return_outputs(error_msg, {}, raw_response)


def remove_domain_response_policy(policy_id, domain):
    params = {
        'policyId': policy_id,
        'itemName': domain
    }
    return http_request('DELETE', '/deleteResponsePolicyItem', params=params)


def search_response_policy_by_domain_command():
    domain = demisto.getArg('domain')
    raw_response_policies = search_response_policy_by_domain(domain)
    response_policies, hr = create_response_policies_result(raw_response_policies)
    return_outputs(hr, response_policies, raw_response_policies)


def search_response_policy_by_domain(domain):
    params = {
        'configurationId': CONF,
        'itemName': domain
    }
    return http_request('GET', '/findResponsePoliciesWithItem', params=params)


''' COMMANDS MANAGER / SWITCH PANEL '''

try:
    CONF = get_configuration()
#except TokenException as e:
except Exception as e:
    return_error(str(e))


def main():
    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        if command == 'test-module':
            test_module()
        elif command == 'bluecat-am-query-ip':
            query_ip_command()
        elif command == 'bluecat-am-get-range-by-ip':
            get_range_by_ip_command()
        elif command == 'bluecat-am-get-response-policies':
            get_response_policies_command()
        elif command == 'bluecat-am-search-response-policies-by-domain':
            search_response_policy_by_domain_command()
        elif command == 'bluecat-am-response-policy-add-domain':
            add_domain_response_policy_command()
        elif command == 'bluecat-am-response-policy-remove-domain':
            remove_domain_response_policy_command()

    # Log exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ('__builtin__', 'builtins'):
    main()
