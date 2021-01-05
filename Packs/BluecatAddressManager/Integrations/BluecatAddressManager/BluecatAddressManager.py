from CommonServerPython import *
import ipaddress
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()
TOKEN_LIFE_TIME_MINUTES = 5


class Client:
    def __init__(self, server_url: str, username: str, password: str, use_ssl: bool, user_conf: str):
        self._base_url = server_url
        self._use_ssl = use_ssl
        self._username = username
        self._password = password
        self.user_conf = user_conf
        self._headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.conf = self.get_configuration()

    def get_token_request(self):
        url_args = {
            'username': self._username,
            'password': self._password
        }
        start_idx = 16
        end_delim = ' <-'
        url = f'{self._base_url}/login'
        res = requests.request('GET', url, verify=self._use_ssl, params=url_args)
        if res.status_code != 200:
            raise Exception('Error: Failed to create a new token, please check your credentials')
        res_json = res.json()
        end_idx = res_json.index(end_delim)
        return res_json[start_idx:end_idx]

    def get_token(self, new_token=False):
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
                auth_token = self.get_token_request()
                demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
            else:
                # token hasn't expired
                auth_token = ctx.get('auth_token')
        else:
            # generating new token
            auth_token = self.get_token_request()
            demisto.setIntegrationContext({'auth_token': auth_token, 'time': date_to_timestamp(now) / 1000})
        return auth_token

    def http_request(self, method, url_suffix, params=None, data=None, safe=False):
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
        self._headers['Authorization'] = self.get_token()
        url = f'{self._base_url}{url_suffix}'
        try:
            res = requests.request(method, url, verify=self._use_ssl, params=params, data=data, headers=self._headers)
            # Try to create a new token
            if res.status_code == 401:
                self._headers['Authorization'] = self.get_token(new_token=True)
                res = requests.request(method, url, verify=self._use_ssl, params=params, data=data, headers=self._headers)
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

    def get_configuration(self):
        """
        Gets the chosen configuration to run queries on

        :return: User configuration id, or the first configuration id if no user configuration provided
        """
        user_conf = self.user_conf
        params = {
            'type': 'Configuration',
            'start': 0,
            'count': 100
        }
        confs = self.http_request('GET', '/getEntities', params)
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


def test_module(client):
    """
    Performs basic get request to get item samples
    """
    client.get_token(new_token=True)
    demisto.results('ok')


def query_ip_command(client):
    ip = demisto.getArg('ip')
    try:
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
            ip_type = 'IPv6'
            base_ip_raw_res = query_ipv6(client, ip)
        else:
            ip_type = 'IPv4'
            base_ip_raw_res = query_ipv4(client, ip)

        # entity with id 0 is root, and CONF is root of parent
        if base_ip_raw_res.get('id') in (None, 0, client.conf):
            return_outputs(f'IP: {ip} was not found.', {}, base_ip_raw_res)
        else:
            base_ip_parents = get_entity_parents(client, base_ip_raw_res.get('id'))
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


def query_ipv4(client, ip):
    params = {
        'containerId': client.conf,
        'address': ip
    }
    return client.http_request('GET', '/getIP4Address', params=params)


def query_ipv6(client, ip):
    params = {
        'containerId': client.conf,
        'address': ip
    }
    return client.http_request('GET', '/getIP6Address', params=params)


def get_entity_parents(client, base_id):
    base_ip_parents = []
    entity_parent = get_entity_parent(client, entity_id=base_id)
    # entity with id 0 is root, and CONF is root of parent
    while entity_parent.get('id') not in (None, 0, client.conf):
        parent_obj = {
            'ID': entity_parent.get('id'),
            'Type': entity_parent.get('type'),
            'Name': entity_parent.get('name'),
        }
        parent_obj.update(properties_to_camelized_dict(entity_parent.get('properties')))
        base_ip_parents.append(parent_obj)
        entity_parent = get_entity_parent(client, entity_id=entity_parent.get('id'))

    return base_ip_parents


def get_entity_parent(client, entity_id):
    params = {
        'entityId': entity_id
    }
    return client.http_request('GET', '/getParent', params=params)


def create_human_readable_ip(ip_object, ip_value):
    ip_object_cpy = dict(ip_object)
    reversed_parents = list(reversed(ip_object_cpy['Parents']))
    ip_object_cpy.pop('Parents')
    hr = tblToMd(f'{ip_value} IP Result:', ip_object_cpy, headerTransform=pascalToSpace)
    hr += tblToMd('Parents Details:', reversed_parents, headerTransform=pascalToSpace)
    return hr


def get_range_by_ip_command(client):
    ip = demisto.getArg('ip')
    try:
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address) or isinstance(ipaddress.ip_address(ip),
                                                                                     ipaddress.IPv4Address):
            range_raw_res = get_range_by_ip(client, ip)

            if range_raw_res.get('id') in (None, 0, client.conf):
                return_outputs(f'IP range was not found for {ip}.', {}, range_raw_res)
            else:
                base_ip_parents = get_entity_parents(client, range_raw_res.get('id'))

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


def get_range_by_ip(client, ip):
    params = {
        'containerId': client.conf,
        'type': '',
        'address': ip
    }
    return client.http_request('GET', '/getIPRangedByIP', params=params)


def create_human_readable_range(range_object, ip_value):
    range_object_cpy = dict(range_object)
    reversed_parents = list(reversed(range_object_cpy['Parents']))
    range_object_cpy.pop('Parents')
    hr = tblToMd(f'{ip_value} Range Result:', range_object_cpy, headerTransform=pascalToSpace)
    hr += tblToMd('Parents Details:', reversed_parents, headerTransform=pascalToSpace)
    return hr


def get_response_policies_command(client):
    start = demisto.getArg('start')
    count = demisto.getArg('count')
    raw_response_policies = get_response_policies(client, start, count)
    response_policies, hr = create_response_policies_result(raw_response_policies)
    return_outputs(hr, response_policies, raw_response_policies)


def get_response_policies(client, start, count):
    params = {
        'parentId': client.conf,
        'type': 'ResponsePolicy',
        'start': start,
        'count': count
    }
    return client.http_request('GET', '/getEntities', params=params)


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


def add_domain_response_policy_command(client):
    policy_id = demisto.getArg('policy_id')
    domain = demisto.getArg('domain')
    raw_response = add_domain_response_policy(client, policy_id, domain)
    error_msg = f'Failed to add {domain} to response policy {policy_id}, ' \
                f'possibly the domain already exists in the response policy.'
    if raw_response:
        return_outputs(f'Successfully added {domain} to response policy {policy_id}', {}, raw_response)
    else:
        return_outputs(error_msg, {}, raw_response)


def add_domain_response_policy(client, policy_id, domain):
    params = {
        'policyId': policy_id,
        'itemName': domain
    }
    return client.http_request('POST', '/addResponsePolicyItem', params=params)


def remove_domain_response_policy_command(client):
    policy_id = demisto.getArg('policy_id')
    domain = demisto.getArg('domain')
    raw_response = remove_domain_response_policy(client, policy_id, domain)
    error_msg = f'Failed to remove {domain} from response policy {policy_id}, ' \
                f'possibly the domain doesn\'t exist in the response policy.'
    if raw_response:
        return_outputs(f'Successfully removed {domain} from response policy {policy_id}', {}, raw_response)
    else:
        return_outputs(error_msg, {}, raw_response)


def remove_domain_response_policy(client, policy_id, domain):
    params = {
        'policyId': policy_id,
        'itemName': domain
    }
    return client.http_request('DELETE', '/deleteResponsePolicyItem', params=params)


def search_response_policy_by_domain_command(client):
    domain = demisto.getArg('domain')
    raw_response_policies = search_response_policy_by_domain(client, domain)
    response_policies, hr = create_response_policies_result(raw_response_policies)
    return_outputs(hr, response_policies, raw_response_policies)


def search_response_policy_by_domain(client, domain):
    params = {
        'configurationId': client.conf,
        'itemName': domain
    }
    return client.http_request('GET', '/findResponsePoliciesWithItem', params=params)


def main():
    params = demisto.params()
    url = params.get('url')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    user_conf = params.get('conf_name')

    # Remove trailing slash to prevent wrong URL path to service
    server = url[:-1] if (url and url.endswith('/')) else url
    base_url = f'{server}/Services/REST/v1'
    use_ssl = not params.get('insecure', False)

    handle_proxy()
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:

        client = Client(server_url=base_url, username=username, password=password, use_ssl=use_ssl, user_conf=user_conf)

        if command == 'test-module':
            test_module(client)
        elif command == 'bluecat-am-query-ip':
            query_ip_command(client)
        elif command == 'bluecat-am-get-range-by-ip':
            get_range_by_ip_command(client)
        elif command == 'bluecat-am-get-response-policies':
            get_response_policies_command(client)
        elif command == 'bluecat-am-search-response-policies-by-domain':
            search_response_policy_by_domain_command(client)
        elif command == 'bluecat-am-response-policy-add-domain':
            add_domain_response_policy_command(client)
        elif command == 'bluecat-am-response-policy-remove-domain':
            remove_domain_response_policy_command(client)

    # Log exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
