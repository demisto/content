import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
from typing import Callable

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '1702.1'

RULE = {
    'endpoint_tag': 'SecurityPolicy',
    'table_headers': ['Name', 'Description', 'Status', 'PolicyType', 'IPFamily', 'AttachIdentity',
                      'Action', 'LogTraffic']
}

RULE_GROUP = {
    'endpoint_tag': 'SecurityPolicyGroup',
    'table_headers': ['Name', 'Description', 'SecurityPolicyList', 'SourceZones',
                      'DestinationZones', 'PolicyType']
}

URL_GROUP = {
    'endpoint_tag': 'WebFilterURLGroup',
    'table_headers': ['Name', 'Description', 'URLlist']
}

IP_HOST = {
    'endpoint_tag': 'IPHost',
    'table_headers': ['Name', 'IPFamily', 'HostType']
}

IP_HOST_GROUP = {
    'endpoint_tag': 'IPHostGroup',
    'table_headers': ['Name', 'Description', 'IPFamily', 'HostList']
}

SERVICE = {
    'endpoint_tag': 'Services',
    'table_headers': ['Name', 'Type', 'ServiceDetails']
}

APP_POLICY = {
    'endpoint_tag': 'ApplicationFilterPolicy',
    'table_headers': ['Name', 'Description', 'MicroAppSupport', 'DefaultAction', 'RuleList']
}

APP_CATEGORY = {
    'endpoint_tag': 'ApplicationFilterCategory',
    'table_headers': ['Name', 'Description', 'QoSPolicy', 'ApplicationSettings',
                      'BandwidthUsageType']
}

WEB_FILTER = {
    'endpoint_tag': 'WebFilterPolicy',
    'table_headers': ['Name', 'Description', 'DefaultAction', 'EnableReporting',
                      'DownloadFileSizeRestrictionEnabled', 'DownloadFileSizeRestriction',
                      'RuleList']
}

USER = {
    'endpoint_tag': 'User',
    'table_headers': ['Username', 'Name', 'Description', 'EmailList', 'Group', 'UserType', 'Status']
}


class Client(BaseClient):
    """Sophos XG Firewall Client"""

    def __init__(self, base_url: str, auth: tuple, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, auth=auth, verify=verify, proxy=proxy)

    def request(self, data: tuple, request_method: str, xml_method: str,
                operation: str = None) -> requests.Response:
        response = self._http_request(method=request_method,
                                      url_suffix='/webconsole/APIController',
                                      params=self.request_builder(self._auth, xml_method, data,
                                                                  operation),
                                      resp_type='Response')
        return response

    def get_request(self, data: tuple) -> requests.Response:
        return self.request(data, 'GET', 'get')

    def set_request(self, data: tuple, operation: str) -> requests.Response:
        return self.request(data, 'POST', 'set', operation)

    def delete_request(self, data: tuple) -> requests.Response:
        return self.request(data, 'POST', 'remove')

    def get_item_by_name(self, endpoint_tag: str, name: str) -> requests.Response:
        data = (endpoint_tag, self.request_one_item_builder(name))
        return self.request(data, 'GET', 'get')

    def validate(self, data: tuple = (None, None)) -> requests.Response:
        return self.request(data, 'GET', 'get')

    @staticmethod
    def request_builder(auth: tuple, method: str, data: tuple, operation: str) -> dict:
        """The builder of the basic xml request

        Args:
            auth (tuple): authentication tuple -> (username, password)
            method (str): Get/Set/Remove
            data (tuple): request body
            operation (str): operation for Get method -> add/update

        Returns:
            dict: returned built dictionary
        """
        request_data = {
            'Request': {
                '@APIVersion': API_VERSION,
                'Login': {
                    'Username': auth[0],
                    'Password': auth[1]
                },
                f'{method.title()}': {
                    '@operation': operation if operation else '',
                    data[0]: data[1]
                }
            }
        }
        return {'reqxml': json2xml(json.dumps(request_data))}

    @staticmethod
    def request_one_item_builder(name: str) -> dict:
        """Build a single filter request

        Args:
            name (str): The name of the object to find with the filter

        Returns:
            dict: returned built dictionary
        """
        request_data = {
            'Filter': {
                'key': {
                    '@name': 'Name',
                    '@criteria': '=',
                    '#text': name
                }
            }
        }
        return request_data


def sophos_firewall_rule_list_command(client: Client, start: int, end: int) -> CommandResults:
    """List all the firewall rules.
    Limited by start and end

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **RULE)


def sophos_firewall_rule_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve firewall rule by name.

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the rule to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **RULE)


def sophos_firewall_rule_add_command(client: Client, params: dict) -> CommandResults:
    """Add firewall rule

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): Params for the creation of the firewall rule

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, RULE['endpoint_tag'], params, rule_builder, RULE['table_headers'])


def sophos_firewall_rule_update_command(client: Client, params: dict) -> CommandResults:
    """Update an existing firewall rule

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): Params for updating the firewall rule

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, RULE['endpoint_tag'], params, rule_builder, RULE['table_headers'],
                                True)


def sophos_firewall_rule_delete_command(client: Client, name: str) -> CommandResults:
    """Delete firewall rule

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the rule to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, RULE['endpoint_tag'])


def sophos_firewall_rule_group_list_command(client: Client, start: int, end: int) -> CommandResults:
    """List firewall rule groups with limitation

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **RULE_GROUP)


def sophos_firewall_rule_group_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve firewall rule group by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the rule group to get_request

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **RULE_GROUP)


def sophos_firewall_rule_group_add_command(client: Client, params: dict) -> CommandResults:
    """Add rule group

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params for the creation of the rule group

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, RULE_GROUP['endpoint_tag'], params, rule_group_builder,
                                RULE_GROUP['table_headers'])


def sophos_firewall_rule_group_update_command(client: Client, params: dict) -> CommandResults:
    """Update firewall rule

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): Params for updating the rule group

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, RULE_GROUP['endpoint_tag'], params, rule_group_builder,
                                RULE_GROUP['table_headers'], True)


def sophos_firewall_rule_group_delete_command(client: Client, name: str) -> CommandResults:
    """Delete a rule group by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the rule group to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, RULE_GROUP['endpoint_tag'])


def sophos_firewall_url_group_list_command(client: Client, start: int, end: int) -> CommandResults:
    """List a URL group with limitations

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **URL_GROUP)


def sophos_firewall_url_group_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve URL group by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the URL group to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **URL_GROUP)


def sophos_firewall_url_group_add_command(client: Client, params: dict) -> CommandResults:
    """Add URL group

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params for the creation of the URL group

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, URL_GROUP['endpoint_tag'], params, url_group_builder,
                                URL_GROUP['table_headers'])


def sophos_firewall_url_group_update_command(client: Client, params: dict) -> CommandResults:
    """Update a URL group

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params for the update

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, URL_GROUP['endpoint_tag'], params, url_group_builder,
                                URL_GROUP['table_headers'], True)


def sophos_firewall_url_group_delete_command(client: Client, name: str) -> CommandResults:
    """Delete a URL group by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the rule to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, URL_GROUP['endpoint_tag'])


def sophos_firewall_ip_host_list_command(client: Client, start: int, end: int) -> CommandResults:
    """List IP host objects

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **IP_HOST)


def sophos_firewall_ip_host_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve IP host by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the IP host to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **IP_HOST)


def sophos_firewall_ip_host_add_command(client: Client, params: dict) -> CommandResults:
    """Add IP host

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params for the creation of the IP host

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, IP_HOST['endpoint_tag'], params, ip_host_builder,
                                IP_HOST['table_headers'])


def sophos_firewall_ip_host_update_command(client: Client, params: dict) -> CommandResults:
    """Update IP host

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params for the updating of the IP host

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, IP_HOST['endpoint_tag'], params, ip_host_builder,
                                IP_HOST['table_headers'], True)


def sophos_firewall_ip_host_delete_command(client: Client, name: str) -> CommandResults:
    """Delete IP host by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, IP_HOST['endpoint_tag'])


def sophos_firewall_ip_host_group_list_command(client: Client, start: int,
                                               end: int) -> CommandResults:
    """List IP host group objects

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **IP_HOST_GROUP)


def sophos_firewall_ip_host_group_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve an IP host group object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **IP_HOST_GROUP)


def sophos_firewall_ip_host_group_add_command(client: Client, params: dict) -> CommandResults:
    """Add IP host group

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to create the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, IP_HOST_GROUP['endpoint_tag'], params, ip_host_group_builder,
                                IP_HOST_GROUP['table_headers'])


def sophos_firewall_ip_host_group_update_command(client: Client, params: dict) -> CommandResults:
    """Update an existing IP host group object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to update the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, IP_HOST_GROUP['endpoint_tag'], params, ip_host_group_builder,
                                IP_HOST_GROUP['table_headers'], True)


def sophos_firewall_ip_host_group_delete_command(client: Client, name: str) -> CommandResults:
    """Delete object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, IP_HOST_GROUP['endpoint_tag'])


def sophos_firewall_services_list_command(client: Client, start: int, end: int) -> CommandResults:
    """List services

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **SERVICE)


def sophos_firewall_services_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve an service object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **SERVICE)


def sophos_firewall_services_add_command(client: Client, params: dict) -> CommandResults:
    """Add service object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to create the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, SERVICE['endpoint_tag'], params, service_builder,
                                SERVICE['table_headers'])


def sophos_firewall_services_update_command(client: Client, params: dict) -> CommandResults:
    """Update an existing object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to update the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, SERVICE['endpoint_tag'], params, service_builder,
                                SERVICE['table_headers'], True)


def sophos_firewall_services_delete_command(client: Client, name: str) -> CommandResults:
    """Delete object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, SERVICE['endpoint_tag'])


def sophos_firewall_app_policy_list_command(client: Client, start: int, end: int) -> CommandResults:
    """List app policy objects

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **APP_POLICY)


def sophos_firewall_app_policy_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve an app policy object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **APP_POLICY)


def sophos_firewall_app_policy_add_command(client: Client, params: dict) -> CommandResults:
    """Add app policy object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to create the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, APP_POLICY['endpoint_tag'], params, app_policy_builder,
                                APP_POLICY['table_headers'])


def sophos_firewall_app_policy_update_command(client: Client, params: dict) -> CommandResults:
    """Update an existing object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to update the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, APP_POLICY['endpoint_tag'], params, app_policy_builder,
                                APP_POLICY['table_headers'], True)

def sophos_firewall_app_policy_delete_command(client: Client, name: str) -> CommandResults:
    """Delete object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, APP_POLICY['endpoint_tag'])


def sophos_firewall_app_category_list_command(client: Client, start: int,
                                              end: int) -> CommandResults:
    """List app category objects

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **APP_CATEGORY)


def sophos_firewall_app_category_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve an app category object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **APP_CATEGORY)


def sophos_firewall_app_category_update_command(client: Client, params: dict) -> CommandResults:
    """Update an existing object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to update the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, APP_CATEGORY['endpoint_tag'], params, app_category_builder,
                                APP_CATEGORY['table_headers'])


def sophos_firewall_web_filter_list_command(client: Client, start: int, end: int) -> CommandResults:
    """List web filter objects

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **WEB_FILTER)


def sophos_firewall_web_filter_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve an web filter object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **WEB_FILTER)


def sophos_firewall_web_filter_add_command(client: Client, params: dict) -> CommandResults:
    """Add web filter object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to create the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, WEB_FILTER['endpoint_tag'], params, web_filter_builder,
                                WEB_FILTER['table_headers'])


def sophos_firewall_web_filter_update_command(client: Client, params: dict) -> CommandResults:
    """Update an existing object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to update the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, WEB_FILTER['endpoint_tag'], params, web_filter_builder,
                                WEB_FILTER['table_headers'], True)

def sophos_firewall_web_filter_delete_command(client: Client, name: str) -> CommandResults:
    """Delete object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, WEB_FILTER['endpoint_tag'])


def sophos_firewall_user_list_command(client: Client, start: int, end: int) -> CommandResults:
    """Retrieve a list of users

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects

    Returns:
        CommandResults: Command results object
    """
    return generic_list(client, start, end, **USER)


def sophos_firewall_user_get_command(client: Client, name: str) -> CommandResults:
    """Retrieve an user object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to get

    Returns:
        CommandResults: Command results object
    """
    return generic_get(client, name, **USER)


def sophos_firewall_user_add_command(client: Client, params: dict) -> CommandResults:
    """Add user object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to create the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, USER['endpoint_tag'], params, user_builder, USER['table_headers'])


def sophos_firewall_user_update_command(client: Client, params: dict) -> CommandResults:
    """Update an existing object

    Args:
        client (Client): Sophos XG Firewall Client
        params (dict): params to update the object with

    Returns:
        CommandResults: Command results object
    """
    return generic_save_and_get(client, USER['endpoint_tag'], params, user_builder, USER['table_headers'],
                                True)


def sophos_firewall_user_delete_command(client: Client, name: str) -> CommandResults:
    """Delete object by name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to delete

    Returns:
        CommandResults: Command results object
    """
    return generic_delete(client, name, USER['endpoint_tag'])


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to.

    Args:
        client: Sophos XG Firewall client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        result = client.validate()
        json_result = json.loads(xml2json(result.text))

        status_message = retrieve_dict_item_recursively(json_result, 'status')
        message = ''

        if status_message and 'Successful' in status_message:
            message = 'ok'
        elif status_message and 'Authentication Failure' in status_message:
            message = 'Please check your credentials'

        status_code = dict_safe_get(json_result, ['Response', 'Status', '@code'], 0)
        if status_code and int(status_code) >= 500:
            status_message = retrieve_dict_item_recursively(json_result, '#text')
            if status_message and 'enable the API Configuration' in status_message:
                message = 'Please enable API configuration from the webconsole ' \
                          '(in Backup & firmware)'
            else:
                message = status_message
        return message

    except DemistoException as error:
        return error.message


def generic_delete(client: Client, name: str, endpoint_tag: str) -> CommandResults:
    """A generic deleting object function

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object to delete
        endpoint_tag (str): Tag of the object to delete

    Returns:
        CommandResults: Command results object
    """
    response = client.delete_request((endpoint_tag, {'Name': name}))
    response = json.loads(xml2json(response.text))

    check_error_on_response(response)

    delete_status = retrieve_dict_item_recursively(response, '#text')

    old_context = demisto.dt(demisto.context(), f'SophosFirewall.{endpoint_tag}'
                                                f'(val.Name == \'{name}\')')
    if old_context:
        if isinstance(old_context, list):
            old_context = old_context[0]

    outputs = {
        'Name': name,
        'IsDeleted': False
    }

    # check if there is a previous data about an object that has been deleted before,
    # and if not, update the IsDeleted field by the message that returns from the API
    if delete_status:
        if old_context and old_context.get('IsDeleted'):
            is_deleted = old_context['IsDeleted']
        else:
            is_deleted = True if 'successfully' in delete_status else False
        outputs['IsDeleted'] = is_deleted

    readable_output = tableToMarkdown(f'Deleting {endpoint_tag} Objects Results', outputs,
                                      ['Name', 'IsDeleted'])

    return CommandResults(
        outputs_prefix=f'SophosFirewall.{endpoint_tag}',
        outputs_key_field='Name',
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output
    )


def merge_for_update(client: Client, name: str, data: dict, keys_for_update: dict,
                     endpoint_tag: str) -> dict:
    """This function used when update is needed.
    The steps for updating the object is as the following:
    1. Retrieve the object from the API
    2. Add the specified params in keys_for_update to the new object
    3. return the object with the previous and the new data merged.

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): Name of the object we want to get data from
        data (dict): the new object data
        keys_for_update (dict): keys for update
        endpoint_tag (str): The endpoint_tag of the object we want to get data from

    Returns:
        dict: returned built dictionary
    """
    previous_object = client.get_item_by_name(endpoint_tag, name)
    previous_object = json.loads(xml2json(previous_object.text))

    check_error_on_response(previous_object)

    previous_object = retrieve_dict_item_recursively(previous_object, endpoint_tag)

    # find the related field by keys_for_update and adding it to data
    for key in keys_for_update:
        info = dict_safe_get(previous_object, keys_for_update[key], [])
        if isinstance(info, str):
            data[key].append(info)
        else:
            data[key].extend(info)  # if the previous info is list we extent the current

    # remove duplications
    for item in data:
        data[item] = list(set(data[item]))

    # if there is nothing, makes sure its None so it'll get removed in the end
    for item in data:
        data[item] = None if not data[item] else data[item]

    return data


def prepare_builder_params(client: Client, keys: dict, is_for_update: bool, name: str,
                           endpoint_tag: str, locals_copy: dict) -> dict:
    """prepare the list of objects for the builder - get the params for locals(),
    split it into list, and return the params after the merge with the new
    object was done (if the is_for_update flag is True)

    Args:
        client (Client): Sophos XG Firewall Client
        keys (dict): field to update
        is_for_update (bool): True if this is an update request
        name (str): name of the object we want to update if is_for_update is True
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        locals_copy (dict): the locals() object copy in order to extract the params

    Returns:
        dict: returned built dictionary
    """
    params = {}
    # creates a dict with the variables names from keys, and add the current data that insides
    # the locals() in the function that called this function.
    for key in keys:
        params[key] = locals_copy.get(key)

    # making the params a list
    for param in params:
        params[param] = argToList(params[param])

    # update the params with the previous information of the object if the desired action is update
    if is_for_update:
        params = merge_for_update(client, name, params, keys, endpoint_tag)

    return params


def update_dict_from_params_using_path(keys_to_update: dict, params: dict, data: dict) -> dict:
    """Update a dictionary using a path given in a list [nest1, nest2] and update it.
         For example: some_dict[nest1][nest2] = some_value
    Args:
        keys_to_update (dict): The keys names with the path to update it into
        params (dict): params with the data of the keys name
        data (dict): data of the object to update

    Returns:
        dict: returned built dictionary
    """
    for key in keys_to_update:
        path = keys_to_update[key]
        # check that there is at least 2 fields for adding the data
        if len(path) >= 2:
            data[f'{path[0]}'] = {
                f'{path[1]}': params.get(key)
            }
    return data


def rule_builder(client: Client, is_for_update: bool, endpoint_tag: str, name: str,
                 policy_type: str = None,
                 position: str = None, description: str = None, status: str = None,
                 ip_family: str = None, position_policy_name: str = None,
                 source_zones: str = None, source_networks: str = None, # pylint: disable=unused-argument
                 destination_zones: str = None, destination_networks: str = None, # pylint: disable=unused-argument
                 services: str = None, members: str = None, # pylint: disable=unused-argument
                 log_traffic: str = None, match_identity: str = None,
                 show_captive_portal: str = None, schedule: str = None,
                 action: str = None, dscp_marking: str = None,
                 application_control: str = None, application_based_qos_policy: str = None,
                 web_filter: str = None, web_category_base_qos_policy: str = None,
                 intrusion_prevention: str = None, traffic_shapping_policy: str = None,
                 apply_nat: str = None, override_gateway_default_nat_policy: str = None,
                 scan_http: str = None, scan_https: str = None, sandstorm: str = None,
                 block_quick_quic: str = None, scan_ftp: str = None,
                 source_security_heartbeat: str = None, minimum_source_hb_permitted: str = None,
                 destination_security_heartbeat: str = None, rewrite_source_address: str = None,
                 minimum_destination_hb_permitted: str = None, data_accounting: str = None,
                 application_control_internet_scheme: str = None,
                 web_filter_internet_scheme: str = None, outbound_address: str = None,
                 backup_gateway: str = None, primary_gateway: str = None) -> dict:
    """The builder of the rule object - build the body of the request

    Args:
        client (Client): Sophos XG Firewall Client
        is_for_update (bool): True if the rule should be updated
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        name (str): The name of the object we want to create/update
        policy_type (str, optional): Policy Type information of the rule
        position (str, optional): Position information of the rule
        description (str, optional): Description information of the rule
        status (str, optional): Status information of the rule
        ip_family (str, optional): Ip Family information of the rule
        position_policy_name (str, optional): Position Policy Name information of the rule
        source_zones (str, optional): Source Zones information of the rule
        source_networks (str, optional): Source Networks information of the rule
        destination_zones (str, optional): Destination Zones information of the rule
        destination_networks (str, optional): Destination Networks information of the rule
        services (str, optional): Services information of the rule
        schedule (str, optional): Schedule information of the rule
        log_traffic (str, optional): Log Traffic information of the rule
        match_identity (str, optional): Match Identity information of the rule
        show_captive_portal (str, optional): Show Captive Portal information of the rule
        members (str, optional): Members information of the rule
        action (str, optional): Action information of the rule
        dscp_marking (str, optional): Dscp Marking information of the rule
        application_control (str, optional): Application Control information of the rule
        application_based_qos_policy (str, optional): Application Based Qos Policy information of
        the rule
        web_filter (str, optional): Web Filter information of the rule
        web_category_base_qos_policy (str, optional): Web Category Base Qos Policy information of
        the rule
        intrusion_prevention (str, optional): Intrusion Prevention information of the rule
        traffic_shapping_policy (str, optional): Traffic Shapping Policy information of the rule
        apply_nat (str, optional): Apply Nat information of the rule
        override_gateway_default_nat_policy (str, optional): Override Gateway Default Nat Policy
        information of the rule
        scan_http (str, optional): Scan Http information of the rule
        scan_https (str, optional): Scan Https information of the rule
        sandstorm (str, optional): Sandstorm information of the rule
        block_quick_quic (str, optional): Block Quick Quic information of the rule
        scan_ftp (str, optional): Scan Ftp information of the rule
        source_security_heartbeat (str, optional): Source Security Heartbeat information of the rule
        minimum_source_hb_permitted (str, optional): Minimum Source Hb Permitted information
        of the rule
        destination_security_heartbeat (str, optional): Destination Security Heartbeat information
        of the rule
        rewrite_source_address (str, optional): Rewrite Source Address information of the rule
        minimum_destination_hb_permitted (str, optional): Minimum Destination Hb Permitted
        information of the rule
        data_accounting (str, optional): Data Accounting information of the rule
        application_control_internet_scheme (str, optional): Application Control Internet Scheme
        information of the rule
        web_filter_internet_scheme (str, optional): Web Filter Internet Scheme information
        of the rule
        outbound_address (str, optional): Outbound Address information of the rule
        backup_gateway (str, optional): Backup Gateway information of the rule
        primary_gateway (str, optional): Primary Gateway information of the rule

    Raises:
        Exception: if there is an error with getting the previous rule

    Returns:
        dict: returned built dictionary
    """
    keys_for_update = {
        'members': ['Identity', 'Member'],
        'source_zones': ['SourceZones', 'Zone'],
        'source_networks': ['SourceNetworks', 'Network'],
        'destination_zones': ['DestinationZones', 'Zone'],
        'destination_networks': ['DestinationNetworks', 'Network'],
        'services': ['Services', 'Service'],
    }

    params = prepare_builder_params(client, keys_for_update, is_for_update, name,
                                    endpoint_tag, locals())
    if is_for_update:
        response = client.get_item_by_name(endpoint_tag, name)
        response = json.loads(xml2json(response.text))
        check_error_on_response(response)
        policy_type = retrieve_dict_item_recursively(response, 'PolicyType')

    json_data = {
        'Name': name,
        'Description': description,
        'Status': status,
        'IPFamily': ip_family,
        'PolicyType': policy_type,
        'Position': position,
        'Schedule': schedule,
        'MatchIdentity': match_identity,
        'ShowCaptivePortal': show_captive_portal,
        'Action': action,
        'DSCPMarking': dscp_marking,
        'LogTraffic': log_traffic,
        'ApplyNAT': apply_nat,
        'ScanHTTP': scan_http,
        'ScanHTTPS': scan_https,
        'Sandstorm': sandstorm,
        'BlockQuickQuic': block_quick_quic,
        'ScanFTP': scan_ftp,
        'DataAccounting': data_accounting,
        'PrimaryGateway': primary_gateway,
        'RewriteSourceAddress': rewrite_source_address,
        'ApplicationControl': application_control,
        'ApplicationControlInternetScheme': application_control_internet_scheme,
        'ApplicationBaseQoSPolicy': application_based_qos_policy,
        'WebFilter': web_filter,
        'WebFilterInternetScheme': web_filter_internet_scheme,
        'WebCategoryBaseQoSPolicy': web_category_base_qos_policy,
        'IntrusionPrevention': intrusion_prevention,
        'TrafficShappingPolicy': traffic_shapping_policy,
        'OverrideGatewayDefaultNATPolicy': override_gateway_default_nat_policy,
        'SourceSecurityHeartbeat': source_security_heartbeat,
        'MinimumSourceHBPermitted': minimum_source_hb_permitted,
        'DestSecurityHeartbeat': destination_security_heartbeat,
        'MinimumDestinationHBPermitted': minimum_destination_hb_permitted,
        'OutboundAddress': outbound_address,
        'BackupGateway': backup_gateway
    }
    if (position == 'after' or position == 'before') and not position_policy_name:
        raise Exception('please provide position_policy_name')

    if position == 'after':
        json_data['After'] = {'Name': position_policy_name}

    elif position == 'before':
        json_data['Before'] = {'Name': position_policy_name}

    json_data = update_dict_from_params_using_path(keys_for_update, params, json_data)
    return remove_empty_elements(json_data)


def rule_group_builder(client: Client, is_for_update: bool, endpoint_tag: str, name: str,
                       destination_zones: str = None, source_zones: str = None, rules: str = None,  # pylint: disable=unused-argument
                       policy_type: str = None, description: str = None) -> dict:
    """Rule group object builder.

    Args:
        client (Client): Sophos XG Firewall Client
        is_for_update (bool): True if the object should be updated
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        name (str): The name of the object we want to add/update
        description (str, optional): Description information of the rule group
        policy_type (str, optional): Policy Type information of the rule group
        rules (str, optional): Rules information of the rule group
        source_zones (str, optional): Source Zones information of the rule group
        destination_zones (str, optional): Destination Zones information of the rule group

    Returns:
        dict: returned built dictionary
    """
    keys_for_update = {
        'rules': ['SecurityPolicyList', 'SecurityPolicy'],
        'source_zones': ['SourceZones', 'Zone'],
        'destination_zones': ['DestinationZones', 'Zone'],
    }

    params = prepare_builder_params(client, keys_for_update, is_for_update, name,
                                    endpoint_tag, locals())

    json_data = {
        'Name': name,
        'Description': description,
        'PolicyType': policy_type
    }

    json_data = update_dict_from_params_using_path(keys_for_update, params, json_data)
    return remove_empty_elements(json_data)


def ip_host_builder(client: Client, is_for_update: bool, endpoint_tag: str,
                    name: str, host_type: str = None, ip_address: str = None, start_ip: str = None,
                    end_ip: str = None, ip_addresses: str = None, subnet_mask: str = None,
                    ip_family: str = None, host_group: str = None) -> dict: # pylint: disable=unused-argument
    """Builder for the IP host object - build the body of the request

    Args:
        client (Client): Sophos XG Firewall Client
        is_for_update (bool): True if the object should be updated
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        name (str): The name of the object we want to add/update
        host_type (str, optional): Host Type information of the IP host
        ip_address (str, optional): Ip Address information of the IP host
        start_ip (str, optional): Start Ip information of the IP host
        end_ip (str, optional): End Ip information of the IP host
        ip_addresses (str, optional): Ip Addresses information of the IP host
        subnet_mask (str, optional): Subnet Mask information of the IP host
        ip_family (str, optional): Ip Family information of the IP host
        host_group (str, optional): Host Group information of the IP host

    Raises:
        Exception: Missing IP address
        Exception: Missing IP address and subnet mask
        Exception: Missing start IP and end IP
        Exception: Missing IP addresses

    Returns:
        dict: returned built dictionary
    """
    keys_for_update = {
        'host_group': ['HostGroupList', 'HostGroup'],
    }

    params = prepare_builder_params(client, keys_for_update, is_for_update, name,
                                    endpoint_tag, locals())
    if is_for_update:
        response = client.get_item_by_name(endpoint_tag, name)
        response = json.loads(xml2json(response.text))
        check_error_on_response(response)
        host_type = retrieve_dict_item_recursively(response, 'HostType')

    json_data = {
        'Name': name,
        'IPFamily': ip_family,
        'HostType': host_type,
    }

    if host_type == 'IP':
        if not ip_address:
            raise Exception('Please provide an IP address')
        json_data['IPAddress'] = ip_address

    elif host_type == 'Network':
        if not (ip_address and subnet_mask):
            raise Exception('Please provide an IP address and subnet mask')
        json_data['IPAddress'] = ip_address
        json_data['Subnet'] = subnet_mask

    elif host_type == 'IPRange':
        if not (start_ip and end_ip):
            raise Exception('Please provide start IP and end ip')
        json_data['StartIPAddress'] = start_ip
        json_data['EndIPAddress'] = end_ip

    else:  # host_type == 'IPList'
        if not ip_addresses:
            raise Exception('Please provide an ip_addresses')
        json_data['ListOfIPAddresses'] = ip_addresses

    json_data = update_dict_from_params_using_path(keys_for_update, params, json_data)
    return remove_empty_elements(json_data)


def url_group_builder(client: Client, is_for_update: bool, endpoint_tag: str, name: str,
                      description: str = None, urls: str = None) -> dict:  # pylint: disable=unused-argument
    """Builder for the URL group object - build the body of the request

    Args:
        client (Client): Sophos XG Firewall Client
        is_for_update (bool): True if the object should be updated
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        name (str): The name of the object we want to add/update
        description (str, optional): Description information of the URL group
        urls (str, optional): URLs information of the URL group

    Returns:
        dict: returned built dictionary
    """
    keys_for_update = {
        'urls': ['URLlist', 'URL'],
    }

    params = prepare_builder_params(client, keys_for_update, is_for_update, name,
                                    endpoint_tag, locals())

    json_data = {
        'Name': name,
        'Description': description,
    }

    json_data = update_dict_from_params_using_path(keys_for_update, params, json_data)
    return remove_empty_elements(json_data)


def ip_host_group_builder(client: Client, is_for_update: bool, endpoint_tag: str,
                          name: str, description: str = None, ip_family: str = None,
                          hosts: str = None) -> dict:  # pylint: disable=unused-argument
    """Builder for the IP host group - build the body of the request

    Args:
        client (Client): Sophos XG Firewall Client
        is_for_update (bool): True if the object should be updated
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        name (str): The name of the object we want to add/update
        description (str, optional): Description information of the IP host group
        ip_family (str, optional): Ip Family information of the IP host group
        hosts (str, optional): Hosts information of the IP host group

    Returns:
        dict: returned built dictionary
    """
    keys_for_update = {
        'hosts': ['HostList', 'Host'],
    }

    params = prepare_builder_params(client, keys_for_update, is_for_update, name,
                                    endpoint_tag, locals())

    json_data = {
        'Name': name,
        'IPFamily': ip_family,
        'Description': description,
    }

    json_data = update_dict_from_params_using_path(keys_for_update, params, json_data)
    return remove_empty_elements(json_data)


def service_builder(client: Client, is_for_update: bool, endpoint_tag: str,
                    name: str, service_type: str, protocol: str = None, source_port: int = None,
                    destination_port: int = None, protocol_name: str = None,
                    icmp_type: str = None, icmp_code: str = None,
                    icmp_v6_type: str = None, icmp_v6_code: str = None) -> dict:
    """Builder for the service object - build the body of the request

    Args:
        client (Client): Sophos XG Firewall Client
        is_for_update (bool): True if the object should be updated
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        name (str): The name of the object we want to add/update
        service_type (str, optional): Service Type information of the service
        protocol (str, optional): Protocol information of the service
        source_port (str, optional): Source Port information of the service
        destination_port (str, optional): Destination Port information of the service
        protocol_name (str, optional): Protocol Name information of the service
        icmp_type (str, optional): ICMP Type information of the service
        icmp_code (str, optional): ICMP Code information of the service
        icmp_v6_type (str, optional): ICMP V6 Type information of the service
        icmp_v6_code (str, optional): ICMP V6 Code information of the service

    Raises:
        Exception: Missing protocol, source port and destination port
        Exception: Missing protocol name
        Exception: Missing icmp_type and icmp_code
        Exception: Missing icmp_v6_type and icmp_v6_code

    Returns:
        dict: returned dictionary
    """
    previous_service_details = []
    # if the object need to be updated, merge between old and new information will happen
    if is_for_update:
        previous_object = client.get_item_by_name(endpoint_tag, name)
        previous_object = json.loads(xml2json(previous_object.text))

        check_error_on_response(previous_object)
        service_type = retrieve_dict_item_recursively(previous_object, 'Type')

        previous_service_details = retrieve_dict_item_recursively(previous_object, 'ServiceDetail')
        if not previous_service_details:
            previous_service_details = []
        elif not isinstance(previous_service_details, list):
            previous_service_details = [previous_service_details]

    json_data = {
        'Name': name,
        'Type': service_type,
    }

    if service_type == 'TCPorUDP':
        if not (protocol and source_port and destination_port):
            raise Exception('Please provide protocol, source_port and destination_port')
        service_details = {
            'Protocol': protocol,
            'SourcePort': source_port,
            'DestinationPort': destination_port
        }

    elif service_type == 'IP':
        if not protocol_name:
            raise Exception('Please provide protocol_name')
        service_details = {
            'ProtocolName': protocol_name
        }

    elif service_type == 'ICMP':
        if not (icmp_type and icmp_code):
            raise Exception('Please provide icmp_type and icmp_code')
        service_details = {
            'ICMPType': icmp_type,
            'ICMPCode': icmp_code
        }

    else:  # type == 'ICMPv6'
        if not (icmp_v6_type and icmp_v6_code):
            raise Exception('Please provide icmp_v6_type and icmp_v6_code')
        service_details = {
            'ICMPv6Type': icmp_v6_type,
            'ICMPv6Code': icmp_v6_code
        }

    previous_service_details.append(service_details)
    json_data.update({
        'ServiceDetails': {
            'ServiceDetail': previous_service_details
        }
    })
    return remove_empty_elements(json_data)


def web_filter_builder(client: Client, is_for_update: bool, endpoint_tag: str,
                       name: str, default_action: str = None, description: str = None,
                       download_file_size_restriction_enabled: str = None,
                       download_file_size_restriction: int = None, enable_reporting: str = None,
                       goog_app_domain_list_enabled: str = None, goog_app_domain_list: str = None,
                       youtube_filter_enabled: str = None, youtube_filter_is_strict: str = None,
                       enforce_safe_search: str = None, enforce_image_licensing: str = None,
                       url_group_names: str = None, http_action: str = None,
                       https_action: str = None, schedule: str = None,
                       policy_rule_enabled: str = None, user_names: str = None,
                       ccl_names: str = None, ccl_rule_enabled: str = None,
                       follow_http_action: str = None) -> dict:
    """Builder for web filter object

    Args:
        client (Client): Sophos XG Firewall Client
        is_for_update (bool): True if the object should be updated
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        name (str): The name of the object we want to add/update
        default_action (str, optional): Default Action information of the web filter
        description (str, optional): Description information of the web filter
        download_file_size_restriction_enabled (str, optional): Download File Size Restriction
        Enabled information of the web filter
        download_file_size_restriction (str, optional): Download File Size Restriction information
        of the web filter
        enable_reporting (str, optional): Enable Reporting information of the web filter
        goog_app_domain_list_enabled (str, optional): Goog App Domain List Enabled information of
        the web filter
        goog_app_domain_list (str, optional): Goog App Domain List information of the web filter
        youtube_filter_enabled (str, optional): Youtube Filter Enabled information of the web filter
        youtube_filter_is_strict (str, optional): Youtube Filter Is Strict information
        of the web filter
        enforce_safe_search (str, optional): Enforce Safe Search information of the web filter
        enforce_image_licensing (str, optional): Enforce Image Licensing information
        of the web filter
        url_group_names (str, optional): Url Group Names information of the web filter
        http_action (str, optional): Http Action information of the web filter
        https_action (str, optional): Https Action information of the web filter
        schedule (str, optional): Schedule information of the web filter
        policy_rule_enabled (str, optional): Policy Rule Enabled information of the web filter
        user_names (str, optional): User Names information of the web filter
        ccl_names (str, optional): Ccl Names information of the web filter
        ccl_rule_enabled (str, optional): Ccl Rule Enabled information of the web filter
        follow_http_action (str, optional): Follow Http Action information of the web filter

    Returns:
        dict: returned built dictionary
    """
    previous_rules_details = []
    # if the object need to be updated, merge between old and new information will happen
    if is_for_update:
        previous_object = client.get_item_by_name(endpoint_tag, name)
        previous_object = json.loads(xml2json(previous_object.text))
        check_error_on_response(previous_object)

        previous_rules_details = retrieve_dict_item_recursively(previous_object, 'Rule')
        if not previous_rules_details:
            previous_rules_details = []
        elif not isinstance(previous_rules_details, list):
            previous_rules_details = [previous_rules_details]
    json_data = {
        'Name': name,
        'Description': description,
        'DefaultAction': default_action,
        'EnableReporting': enable_reporting,
        'DownloadFileSizeRestriction': download_file_size_restriction,
        'DownloadFileSizeRestrictionEnabled': download_file_size_restriction_enabled,
        'GoogAppDomainListEnabled': goog_app_domain_list_enabled,
        'GoogAppDomainList': argToList(goog_app_domain_list),
        'YoutubeFilterEnabled': youtube_filter_enabled,
        'YoutubeFilterIsStrict': youtube_filter_is_strict,
        'EnforceSafeSearch': enforce_safe_search,
        'EnforceImageLicensing': enforce_image_licensing,
    }

    categories = [{'ID': name, 'type': 'URLGroup'} for name in argToList(url_group_names)]
    rule_details = {
        'PolicyRuleEnabled': policy_rule_enabled,
        'CCLRuleEnabled': ccl_rule_enabled,
        'FollowHTTPAction': follow_http_action,
        'CategoryList': {
            'Category': categories
        },
        'HTTPAction': http_action,
        'HTTPSAction': https_action,
        'Schedule': schedule,
        'UserList': {
            'User': argToList(user_names)
        },
        'CCLList': {
            'CCL': argToList(ccl_names)
        }
    }

    previous_rules_details.append(rule_details)
    json_data.update({
        'RuleList': {
            'Rule': previous_rules_details
        }
    })
    return remove_empty_elements(json_data)


def app_category_builder(name: str, description: str = None, qos_policy: str = None) -> dict:
    """Builder for app category object

    Args:
        name (str): The name of the object we want to add/update
        description (str, optional): Description information of the app category
        qos_policy (str, optional): Qos Policy information of the app category

    Returns:
        dict: returned built dictionary
    """
    json_data = {
        'Name': name,
        'Description': description,
        'QoSPolicy': qos_policy,
    }
    return remove_empty_elements(json_data)


def app_policy_builder(client: Client, is_for_update: bool, endpoint_tag: str,
                       name: str, description: str = None, micro_app_support: str = None,
                       default_action: str = None, select_all: str = None, categories: str = None,
                       risks: str = None, applications: str = None, characteristics: str = None,
                       technologies: str = None, classifications: str = None,
                       action: str = None, schedule: str = None) -> dict:
    """Builder for the app policy object - build the body of the request

    Args:
        client (Client): Sophos XG Firewall Client
        is_for_update (bool): True if the object should be updated
        endpoint_tag (str): The endpoint_tag of the object we want to get data from
        name (str): The name of the object we want to add/update
        description (str, optional): Description information of the app policy
        micro_app_support (str, optional): Micro App Support information of the app policy
        default_action (str, optional): Default Action information of the app policy
        select_all (str, optional): Select All information of the app policy
        categories (str, optional): Categories information of the app policy
        risks (str, optional): Risks information of the app policy
        applications (str, optional): Applications information of the app policy
        characteristics (str, optional): Characteristics information of the app policy
        technologies (str, optional): Technologies information of the app policy
        classifications (str, optional): Classifications information of the app policy
        action (str, optional): Action information of the app policy
        schedule (str, optional): Schedule information of the app policy

    Returns:
        dict: returned built dictionary
    """
    previous_rules_details = []
    # if the object need to be updated, merge between old and new information will happen
    if is_for_update:
        previous_object = client.get_item_by_name(endpoint_tag, name)
        previous_object = json.loads(xml2json(previous_object.text))
        check_error_on_response(previous_object)

        previous_rules_details = retrieve_dict_item_recursively(previous_object, 'Rule')
        if not previous_rules_details:
            previous_rules_details = []
        elif not isinstance(previous_rules_details, list):
            previous_rules_details = [previous_rules_details]
    json_data = {
        'Name': name,
        'Description': description,
        'MicroAppSupport': micro_app_support,
        'DefaultAction': default_action,
    }

    rule_details = {
        'SelectAllRule': select_all,
        'CategoryList': {
            'Category': argToList(categories)
        },
        'RiskList': {
            'Risk': argToList(risks)
        },
        'CharacteristicsList': {
            'Characteristics': argToList(characteristics)
        },
        'TechnologyList': {
            'Technology': argToList(technologies)
        },
        'ClassificationList': {
            'Classification': argToList(classifications)
        },
        'ApplicationList': {
            'Application': argToList(applications)
        },
        'Action': action,
        'Schedule': schedule,
    }

    previous_rules_details.append(rule_details)
    json_data.update({
        'RuleList': {
            'Rule': previous_rules_details
        }
    })
    return remove_empty_elements(json_data)


def user_builder(name: str, username: str, email: str = None, password: str = None,
                 description: str = None, group: str = None, user_type: str = None,
                 profile: str = None, surfing_quota_policy: str = None,
                 access_time_policy: str = None, ssl_vpn_policy: str = None,
                 clientless_policy: str = None, data_transfer_policy: str = None,
                 simultaneous_logins_global: str = None, schedule_for_appliance_access: str = None,
                 qos_policy: str = None, login_restriction: str = None) -> dict:
    """Builder for the user object - build the body of the request

    Args:
        name (str): The name of the object we want to add/update
        username (str, optional): Username information of the user
        email (str, optional): Email information of the user
        password (str, optional): Password information of the user
        description (str, optional): Description information of the user
        group (str, optional): Group information of the user
        user_type (str, optional): User Type information of the user
        profile (str, optional): Profile information of the user
        surfing_quota_policy (str, optional): Surfing Quota Policy information of the user
        access_time_policy (str, optional): Access Time Policy information of the user
        ssl_vpn_policy (str, optional): Ssl Vpn Policy information of the user
        clientless_policy (str, optional): Clientless Policy information of the user
        data_transfer_policy (str, optional): Data Transfer Policy information of the user
        simultaneous_logins_global (str, optional): Simultaneous Logins Global information
        of the user
        schedule_for_appliance_access (str, optional): Schedule For Appliance Access information
        of the user
        qos_policy (str, optional): Qos Policy information of the user
        login_restriction (str, optional): Login Restriction information of the user

    Raises:
        Exception: if Administrator type was selected and profile was not provided

    Returns:
        dict: returned built dictionary
    """
    if user_type == 'Administrator' and not profile:
        raise Exception('Administrator type was selected. Please provide profile.')
    json_data = {
        'Username': username,
        'Name': name,
        'Password': password,
        'UserType': user_type,
        'Profile': profile,
        'EmailList': {
            'EmailID': email
        },
        'Group': group,
        'Description': description,
        'SurfingQuotaPolicy': surfing_quota_policy,
        'AccessTimePolicy': access_time_policy,
        'SSLVPNPolicy': ssl_vpn_policy,
        'ClientlessPolicy': clientless_policy,
        'DataTransferPolicy': data_transfer_policy,
        'SimultaneousLoginsGlobal': simultaneous_logins_global,
        'ScheduleForApplianceAccess': schedule_for_appliance_access,
        'QoSPolicy': qos_policy,
        'LoginRestriction': login_restriction,
    }
    return remove_empty_elements(json_data)


def check_error_on_response(response: dict) -> None:
    """Check if there is an error on the response

    Args:
        response (dict): the object to check the error on

    Raises:
        Exception: if there if an error in the response
        Exception: if there are no records on list or get
    """
    response_message = retrieve_dict_item_recursively(response, '#text')
    response_code = retrieve_dict_item_recursively(response, '@code')
    response_status = retrieve_dict_item_recursively(response, 'Status')

    if response_message and 'successful' not in response_message:
        if response_code and int(response_code) > 299:
            raise Exception(f'{response_message} (error code: {response_code})')
    if response_status and 'No. of records Zero.' in response_status:
        raise Exception(response_status)


def generic_save_and_get(client: Client, endpoint_tag: str, params: dict, builder: Callable,
                         table_headers: list, to_update: bool = False) -> CommandResults:
    """Generic function for add/update

    Args:
        to_update (bool): True if the object should be updated
        client (Client): Sophos XG Firewall Client
        params (dict): params for the builder
        builder (Callable): the builder to build the object
        endpoint_tag (str): The endpoint_tag of the object
        table_headers (list): table_headers for readable outputs

    Returns:
        CommandResults: Command results object
    """
    funcs_without_extra_args = [user_builder, app_category_builder]
    if builder in funcs_without_extra_args:
        data = builder(**params)
    else:
        data = builder(client, to_update, endpoint_tag, **params)
    operation = 'update' if to_update else 'add'
    response = client.set_request((endpoint_tag, data), operation)
    response = json.loads(xml2json(response.text))

    check_error_on_response(response)
    return generic_get(client, params.get('name'), endpoint_tag, table_headers)


def generic_get(client: Client, name: str, endpoint_tag: str,
                table_headers: list) -> CommandResults:
    """Generic get, returns an object based on the endpoint tag and the name

    Args:
        client (Client): Sophos XG Firewall Client
        name (str): The name of the object to get
        endpoint_tag (str): The endpoint tag of the object
        table_headers (list): table headers for readable outputs

    Returns:
        CommandResults: Command results object
    """
    response = client.get_item_by_name(endpoint_tag, name)
    response = json.loads(xml2json(response.text))

    check_error_on_response(response)

    outputs = retrieve_dict_item_recursively(response, endpoint_tag)
    if outputs:
        outputs.pop('@transactionid')
        outputs['IsDeleted'] = False

    table_title = f'{endpoint_tag} Object details'

    readable_output = tableToMarkdown(table_title, outputs, table_headers, removeNull=True)
    return CommandResults(
        outputs_prefix=f'SophosFirewall.{endpoint_tag}',
        outputs_key_field='Name',
        raw_response=outputs,
        outputs=outputs,
        readable_output=readable_output
    )


def generic_list(client: Client, start: int, end: int, endpoint_tag: str,
                 table_headers: str) -> CommandResults:
    """Generic function for listing objects

    Args:
        client (Client): Sophos XG Firewall Client
        start (int): low limit of returned objects, starts with 0
        end (int): high limit of returned objects
        endpoint_tag (str): The endpoint tag of the objects
        table_headers (list): table headers for readable outputs

    Returns:
        CommandResults: Command results object
    """
    response = client.get_request((endpoint_tag, None))
    response = json.loads(xml2json(response.text))

    outputs = dict_safe_get(response, ['Response', endpoint_tag])

    check_error_on_response(response)

    outputs = outputs if isinstance(outputs, list) else [outputs]
    for output in outputs:
        output.pop('@transactionid')
        output['IsDeleted'] = False

    start, end = int(start), int(end)
    len_outputs = len(outputs)
    if end > len_outputs:
        end = len_outputs
    outputs = outputs[start:end]

    table_title = f'Showing {start} to {end} {endpoint_tag} objects out of {len_outputs}'

    readable_output = tableToMarkdown(table_title, outputs, table_headers, removeNull=True)
    return CommandResults(
        outputs_prefix=f'SophosFirewall.{endpoint_tag}',
        outputs_key_field='Name',
        raw_response=outputs,
        outputs=outputs,
        readable_output=readable_output
    )


def retrieve_dict_item_recursively(obj, key) -> any:
    """Find items in given dictionary by the key

    Args:
        obj (dict): the dict to search in
        key (str): the key to search for

    Returns:
        The item if found
    """
    if key in obj:
        return obj[key]
    for _, value in obj.items():
        if isinstance(value, dict):
            item = retrieve_dict_item_recursively(value, key)
            if item:
                return item
    return None


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')

    server_url = params.get('server_url')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=server_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'sophos-firewall-rule-list':
            return_results(sophos_firewall_rule_list_command(client, **args))

        elif command == 'sophos-firewall-rule-get':
            return_results(sophos_firewall_rule_get_command(client, **args))

        elif command == 'sophos-firewall-rule-add':
            return_results(sophos_firewall_rule_add_command(client, args))

        elif command == 'sophos-firewall-rule-update':
            return_results(sophos_firewall_rule_update_command(client, args))

        elif command == 'sophos-firewall-rule-delete':
            return_results(sophos_firewall_rule_delete_command(client, **args))

        elif command == 'sophos-firewall-rule-group-list':
            return_results(sophos_firewall_rule_group_list_command(client, **args))

        elif command == 'sophos-firewall-rule-group-get':
            return_results(sophos_firewall_rule_group_get_command(client, **args))

        elif command == 'sophos-firewall-rule-group-add':
            return_results(sophos_firewall_rule_group_add_command(client, args))

        elif command == 'sophos-firewall-rule-group-update':
            return_results(sophos_firewall_rule_group_update_command(client, args))

        elif command == 'sophos-firewall-rule-group-delete':
            return_results(sophos_firewall_rule_group_delete_command(client, **args))

        elif command == 'sophos-firewall-url-group-list':
            return_results(sophos_firewall_url_group_list_command(client, **args))

        elif command == 'sophos-firewall-url-group-get':
            return_results(sophos_firewall_url_group_get_command(client, **args))

        elif command == 'sophos-firewall-url-group-add':
            return_results(sophos_firewall_url_group_add_command(client, args))

        elif command == 'sophos-firewall-url-group-update':
            return_results(sophos_firewall_url_group_update_command(client, args))

        elif command == 'sophos-firewall-url-group-delete':
            return_results(sophos_firewall_url_group_delete_command(client, **args))

        elif command == 'sophos-firewall-ip-host-list':
            return_results(sophos_firewall_ip_host_list_command(client, **args))

        elif command == 'sophos-firewall-ip-host-get':
            return_results(sophos_firewall_ip_host_get_command(client, **args))

        elif command == 'sophos-firewall-ip-host-add':
            return_results(sophos_firewall_ip_host_add_command(client, args))

        elif command == 'sophos-firewall-ip-host-update':
            return_results(sophos_firewall_ip_host_update_command(client, args))

        elif command == 'sophos-firewall-ip-host-delete':
            return_results(sophos_firewall_ip_host_delete_command(client, **args))

        elif command == 'sophos-firewall-ip-host-group-list':
            return_results(sophos_firewall_ip_host_group_list_command(client, **args))

        elif command == 'sophos-firewall-ip-host-group-get':
            return_results(sophos_firewall_ip_host_group_get_command(client, **args))

        elif command == 'sophos-firewall-ip-host-group-add':
            return_results(sophos_firewall_ip_host_group_add_command(client, args))

        elif command == 'sophos-firewall-ip-host-group-update':
            return_results(sophos_firewall_ip_host_group_update_command(client, args))

        elif command == 'sophos-firewall-ip-host-group-delete':
            return_results(sophos_firewall_ip_host_group_delete_command(client, **args))

        elif command == 'sophos-firewall-services-list':
            return_results(sophos_firewall_services_list_command(client, **args))

        elif command == 'sophos-firewall-services-get':
            return_results(sophos_firewall_services_get_command(client, **args))

        elif command == 'sophos-firewall-services-add':
            return_results(sophos_firewall_services_add_command(client, args))

        elif command == 'sophos-firewall-services-update':
            return_results(sophos_firewall_services_update_command(client, args))

        elif command == 'sophos-firewall-services-delete':
            return_results(sophos_firewall_services_delete_command(client, **args))

        elif command == 'sophos-firewall-app-policy-list':
            return_results(sophos_firewall_app_policy_list_command(client, **args))

        elif command == 'sophos-firewall-app-policy-get':
            return_results(sophos_firewall_app_policy_get_command(client, **args))

        elif command == 'sophos-firewall-app-policy-add':
            return_results(sophos_firewall_app_policy_add_command(client, args))

        elif command == 'sophos-firewall-app-policy-update':
            return_results(sophos_firewall_app_policy_update_command(client, args))

        elif command == 'sophos-firewall-app-policy-delete':
            return_results(sophos_firewall_app_policy_delete_command(client, **args))

        elif command == 'sophos-firewall-app-category-list':
            return_results(sophos_firewall_app_category_list_command(client, **args))

        elif command == 'sophos-firewall-app-category-get':
            return_results(sophos_firewall_app_category_get_command(client, **args))

        elif command == 'sophos-firewall-app-category-update':
            return_results(
                sophos_firewall_app_category_update_command(client, args))

        elif command == 'sophos-firewall-web-filter-list':
            return_results(sophos_firewall_web_filter_list_command(client, **args))

        elif command == 'sophos-firewall-web-filter-get':
            return_results(sophos_firewall_web_filter_get_command(client, **args))

        elif command == 'sophos-firewall-web-filter-add':
            return_results(sophos_firewall_web_filter_add_command(client, args))

        elif command == 'sophos-firewall-web-filter-update':
            return_results(sophos_firewall_web_filter_update_command(client, args))

        elif command == 'sophos-firewall-web-filter-delete':
            return_results(sophos_firewall_web_filter_delete_command(client, **args))

        elif command == 'sophos-firewall-user-list':
            return_results(sophos_firewall_user_list_command(client, **args))

        elif command == 'sophos-firewall-user-get':
            return_results(sophos_firewall_user_get_command(client, **args))

        elif command == 'sophos-firewall-user-add':
            return_results(sophos_firewall_user_add_command(client, args))

        elif command == 'sophos-firewall-user-update':
            return_results(sophos_firewall_user_update_command(client, args))

        elif command == 'sophos-firewall-user-delete':
            return_results(sophos_firewall_user_delete_command(client, **args))

    # Log exceptions
    except Exception as error:
        message = f'Failed to execute {command} command. Error: {str(error)}'
        return_error(message)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
