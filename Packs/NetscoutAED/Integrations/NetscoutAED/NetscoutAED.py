import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import copy
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


@logger
class Client(BaseClient):
    """
    Client class to interact with the service API
    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, verify, api_token, proxy):
        headers = {'X-Arbux-APIToken': api_token}
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    # countries
    def country_code_list_command(self, args: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/countries/', params=args)

    def outbound_blacklisted_country_list_command(self, args: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/otf/blacklisted-countries/', params=args)

    def inbound_blacklisted_country_list_command(self, args: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/protection-groups/blacklisted-countries/', params=args)

    def outbound_blacklisted_country_add_command(self, body: dict) -> list:
        return list(self._http_request(method='POST', url_suffix='/otf/blacklisted-countries/', params=body))

    def inbound_blacklisted_country_add_command(self, body: dict) -> dict:
        return self._http_request(method='POST', url_suffix='/protection-groups/blacklisted-countries/', params=body)

    def outbound_blacklisted_country_delete_command(self, body: dict) -> requests.Response:
        return self._http_request(method='DELETE', url_suffix='/otf/blacklisted-countries/', params=body,
                                  return_empty_response=True)

    def inbound_blacklisted_country_delete_command(self, body: dict) -> requests.Response:
        return self._http_request(method='DELETE', url_suffix='/protection-groups/blacklisted-countries/', params=body,
                                  return_empty_response=True)

    # host lists handlers

    def outbound_blacklisted_host_list_command(self, body: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/otf/blacklisted-hosts/', params=body)

    def outbound_whitelisted_host_list_command(self, body: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/otf/whitelisted-hosts/', params=body)

    def inbound_blacklisted_host_list_command(self, body: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/protection-groups/blacklisted-hosts/', params=body)

    def inbound_whitelisted_host_list_command(self, body: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/protection-groups/whitelisted-hosts/', params=body)

    # host addition/updates handlers

    def outbound_blacklisted_host_add_update_command(self, body: dict, http_method: str) -> dict:
        return self._http_request(method=http_method, url_suffix='/otf/blacklisted-hosts/', json_data=body,
                                  headers=merge_dicts(self._headers, {'Content-Type': 'application/json'}))

    def outbound_whitelisted_host_add_update_command(self, body: dict, http_method: str) -> dict:
        return self._http_request(method=http_method, url_suffix='/otf/whitelisted-hosts/', json_data=body,
                                  headers=merge_dicts(self._headers, {'Content-Type': 'application/json'}))

    def inbound_blacklisted_host_add_update_command(self, body: dict, http_method: str) -> dict:
        return self._http_request(method=http_method, url_suffix='/protection-groups/blacklisted-hosts/',
                                  json_data=body,
                                  headers=merge_dicts(self._headers, {'Content-Type': 'application/json'}))

    def inbound_whitelisted_host_add_update_command(self, body: dict, http_method: str) -> dict:
        return self._http_request(method=http_method, url_suffix='/protection-groups/whitelisted-hosts/',
                                  json_data=body,
                                  headers=merge_dicts(self._headers, {'Content-Type': 'application/json'}))

    # host deletion handlers

    def outbound_blacklisted_host_remove_command(self, body: dict) -> requests.Response:
        return self._http_request(method='DELETE', url_suffix='/otf/blacklisted-hosts/', params=body,
                                  return_empty_response=True)

    def outbound_whitelisted_host_remove_command(self, body: dict) -> requests.Response:
        return self._http_request(method='DELETE', url_suffix='/otf/whitelisted-hosts/', params=body,
                                  return_empty_response=True)

    def inbound_blacklisted_host_remove_command(self, body: dict) -> requests.Response:
        return self._http_request(method='DELETE', url_suffix='/protection-groups/blacklisted-hosts/', params=body,
                                  return_empty_response=True)

    def inbound_whitelisted_host_remove_command(self, body: dict) -> requests.Response:
        return self._http_request(method='DELETE', url_suffix='/protection-groups/whitelisted-hosts/', params=body,
                                  return_empty_response=True)

    # domain handlers

    def inbound_blacklisted_domain_list_command(self, body: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/protection-groups/blacklisted-domains/', params=body)

    def inbound_blacklisted_domain_add_command(self, body: dict) -> dict:
        return self._http_request(method='POST', url_suffix='/protection-groups/blacklisted-domains/', params=body)

    def inbound_blacklisted_domain_remove_command(self, body: dict) -> requests.Response:
        return self._http_request(method='DELETE', url_suffix='/protection-groups/blacklisted-domains/', params=body,
                                  return_empty_response=True)

    # url handlers

    def inbound_blacklisted_url_list_command(self, body: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/protection-groups/blacklisted-urls/', params=body)

    def inbound_blacklisted_url_add_command(self, body: dict) -> dict:
        return self._http_request(method='POST', url_suffix='/protection-groups/blacklisted-urls/', params=body)

    def inbound_blacklisted_url_remove_command(self, body: dict) -> requests.Response:
        return self._http_request(method='DELETE', url_suffix='/protection-groups/blacklisted-urls/', params=body,
                                  return_empty_response=True)

    # protection group handlers

    def protection_group_list_command(self, body: dict) -> dict:
        return self._http_request(method='GET', url_suffix='/protection-groups/', params=body)

    def protection_group_patch_command(self, body: dict) -> dict:
        return self._http_request(method='PATCH', url_suffix='/protection-groups/', params=body)


''' HELPER FUNCTIONS '''


def merge_dicts(dict1: dict, dict2: dict) -> dict:
    """
       Merges two dictionaries into one dictionary.

       :type dict1: ``dict``
       :param dict1: The first dictionary.

       :type dict2: ``dict``
       :param dict2: The second dictionary.

       :return: The merged dictionary.
       :rtype: ``dict``
    """
    return {**dict1, **dict2}


def handle_args(demisto_args: dict) -> dict:
    """
        Converts the demisto server arguments into arguments which the API accepts.

        :type demisto_args: ``dict``
        :param demisto_args: The Demisto arguments dictionary.

        :return: The arguments dictionary which the API accepts.
        :rtype: ``dict``
    """
    for key in demisto_args:
        val = demisto_args[key]
        if val in ['true', 'false']:
            demisto_args[key] = argToBoolean(val)
    query = demisto_args.pop('query', None)
    if query:
        demisto_args['q'] = query
    limit = demisto_args.pop('limit', None)
    if limit:
        demisto_args['per_page'] = limit
    remove_nulls_from_dictionary(demisto_args)
    return camelize(demisto_args, '_', upper_camel=False)


def init_commands_dict() -> dict:
    """
       Initializes the legal commands dictionary.

       :return: The commands dictionary.
       :rtype: ``dict``
    """

    inbound_blacklisted = {'direction': 'inbound', 'list_color': 'blacklist'}
    inbound_whitelisted = {'direction': 'inbound', 'list_color': 'whitelist'}
    outbound_blacklisted = {'direction': 'outbound', 'list_color': 'blacklist'}
    outbound_whitelisted = {'direction': 'outbound', 'list_color': 'whitelist'}

    return {
        # test module
        'test-module': {'func': test_module},

        # countries code list
        'na-ed-country-code-list': {'func': country_code_list_command},

        # outbound blacklisted countries
        'na-ed-outbound-blacklisted-countries-list': {'func': handle_country_list_commands,
                                                      'meta_data': outbound_blacklisted},
        'na-ed-outbound-blacklisted-countries-add': {'func': handle_country_addition_commands,
                                                     'meta_data': outbound_blacklisted},
        'na-ed-outbound-blacklisted-countries-remove': {'func': handle_country_deletion_commands,
                                                        'meta_data': outbound_blacklisted},

        # inbound blacklisted countries
        'na-ed-inbound-blacklisted-countries-list': {'func': handle_country_list_commands,
                                                     'meta_data': inbound_blacklisted},
        'na-ed-inbound-blacklisted-countries-add': {'func': handle_country_addition_commands,
                                                    'meta_data': inbound_blacklisted},
        'na-ed-inbound-blacklisted-countries-remove': {'func': handle_country_deletion_commands,
                                                       'meta_data': inbound_blacklisted},

        # outbound blacklisted hosts
        'na-ed-outbound-blacklisted-hosts-list': {'func': handle_host_list_commands,
                                                  'meta_data': outbound_blacklisted},
        'na-ed-outbound-blacklisted-hosts-add': {'func': handle_host_addition_and_replacement_commands,
                                                 'meta_data':
                                                     merge_dicts(outbound_blacklisted, {'http_method': 'POST'})},

        'na-ed-outbound-blacklisted-hosts-replace': {'func': handle_host_addition_and_replacement_commands,
                                                     'meta_data':
                                                         merge_dicts(outbound_blacklisted, {'http_method': 'PUT'})},
        'na-ed-outbound-blacklisted-hosts-remove': {'func': handle_host_deletion_commands,
                                                    'meta_data': outbound_blacklisted},

        # inbound blacklisted hosts
        'na-ed-inbound-blacklisted-hosts-list': {'func': handle_host_list_commands,
                                                 'meta_data': inbound_blacklisted},
        'na-ed-inbound-blacklisted-hosts-add': {'func': handle_host_addition_and_replacement_commands,
                                                'meta_data':
                                                    merge_dicts(inbound_blacklisted, {'http_method': 'POST'})},
        'na-ed-inbound-blacklisted-hosts-replace': {'func': handle_host_addition_and_replacement_commands,
                                                    'meta_data':
                                                        merge_dicts(inbound_blacklisted, {'http_method': 'PUT'})},
        'na-ed-inbound-blacklisted-hosts-remove': {'func': handle_host_deletion_commands,
                                                   'meta_data': inbound_blacklisted},

        # outbound whitelisted hosts
        'na-ed-outbound-whitelisted-hosts-list': {'func': handle_host_list_commands,
                                                  'meta_data': outbound_whitelisted},
        'na-ed-outbound-whitelisted-hosts-add': {'func': handle_host_addition_and_replacement_commands,
                                                 'meta_data':
                                                     merge_dicts(outbound_whitelisted, {'http_method': 'POST'})},
        'na-ed-outbound-whitelisted-hosts-replace': {'func': handle_host_addition_and_replacement_commands,
                                                     'meta_data':
                                                         merge_dicts(outbound_whitelisted, {'http_method': 'PUT'})},
        'na-ed-outbound-whitelisted-hosts-remove': {'func': handle_host_deletion_commands,
                                                    'meta_data': outbound_whitelisted},

        # inbound whitelisted hosts
        'na-ed-inbound-whitelisted-hosts-list': {'func': handle_host_list_commands,
                                                 'meta_data': inbound_whitelisted},
        'na-ed-inbound-whitelisted-hosts-add': {'func': handle_host_addition_and_replacement_commands,
                                                'meta_data':
                                                    merge_dicts(inbound_whitelisted, {'http_method': 'POST'})},
        'na-ed-inbound-whitelisted-hosts-replace': {'func': handle_host_addition_and_replacement_commands,
                                                    'meta_data':
                                                        merge_dicts(inbound_whitelisted, {'http_method': 'PUT'})},
        'na-ed-inbound-whitelisted-hosts-remove': {'func': handle_host_deletion_commands,
                                                   'meta_data': inbound_whitelisted},

        # inbound blacklisted domains
        'na-ed-inbound-blacklisted-domains-list': {'func': handle_domain_list_commands},
        'na-ed-inbound-blacklisted-domains-add': {'func': handle_domain_addition_commands},
        'na-ed-inbound-blacklisted-domains-remove': {'func': handle_domain_deletion_commands},

        # inbound blacklisted URLs
        'na-ed-inbound-blacklisted-urls-list': {'func': handle_url_list_commands},
        'na-ed-inbound-blacklisted-urls-add': {'func': handle_url_addition_commands},
        'na-ed-inbound-blacklisted-urls-remove': {'func': handle_url_deletion_commands},

        # protection groups
        'na-ed-protection-groups-list': {'func': handle_protection_groups_list_commands},
        'na-ed-protection-groups-update': {'func': handle_protection_groups_update_commands},

    }


def objects_time_to_readable_time(list_of_objects: list, time_key: str) -> None:
    """

        Gets a list of objects with "time" key and
        Replaces the value of the field with a readable format and
        Convert all keys of a dictionary to snake_case.

       :type list_of_objects: ``list``
       :param list_of_objects: The list of objects to iterate.

       :type time_key: ``str``
       :param time_key: The time key field to change to date.

       :return: No data returned.
       :rtype: ``None``

    """
    for i, item in enumerate(list_of_objects):
        timestamp = item.get(time_key)
        if not timestamp:
            raise DemistoException("'time_key' argument is not valid")
        item[time_key] = timestamp_to_datestring(timestamp * 1000)
        list_of_objects[i] = snakify(item)


def deserialize_protection_groups(list_of_protection_groups: list) -> None:
    """

        Gets a list of objects (which represents the protection groups)
        deserializes them to a more human readable format.

        :type list_of_protection_groups: ``list``
        :param list_of_protection_groups: The list of protection groups to iterate.

        :return: No data returned.
        :rtype: ``None``

    """
    for item in list_of_protection_groups:
        active = item.get('active')
        if active is None:
            continue

        item['active'] = True if active == 1 else False
        protection_level = item.get('protectionLevel')
        if protection_level:
            if protection_level == 1:
                item['protectionLevel'] = 'low'
            elif protection_level == 2:
                item['protectionLevel'] = 'medium'
            elif protection_level == 3:
                item['protectionLevel'] = 'high'


def serialize_protection_groups(protection_group: dict) -> None:
    """

        Gets a protection group
        serializes it to the format which the api expects.

        :type protection_group: ``dict``
        :param protection_group: The protection group to serialize.

        :return: No data returned.
        :rtype: ``None``

    """
    active = protection_group.get('active')
    if active:
        protection_group['active'] = 1 if active else 0
    protection_level = protection_group.get('protectionLevel')
    if protection_level:
        if protection_level == 'low':
            protection_group['protectionLevel'] = 1
        elif protection_level == 'medium':
            protection_group['protectionLevel'] = 2
        elif protection_level == 'high':
            protection_group['protectionLevel'] = 3
    profiling = protection_group.get('profiling')
    if profiling:
        protection_group['profiling'] = 1 if profiling else 0


''' COMMAND FUNCTIONS '''


def test_module(client: Client, demisto_args: dict) -> str:
    """

        Tests API connectivity and authentication'
        Returning 'ok' indicates that the integration works like it is supposed to.
        Raises exceptions if something goes wrong.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: 'ok' if test passed, anything else will fail the test.
        :rtype: ``str``

    """
    try:
        client.country_code_list_command(demisto_args)
    except DemistoException as e:
        demisto.debug(f'Error: {str(e)}')
        if 'UNAUTHORIZED' in str(e) or 'invalidAuthToken' in str(e):
            raise DemistoException('Test failed, make sure API Key is correctly set.', exception=e)
        elif 'Error in API call' in str(e):
            raise DemistoException(f'Test failed, Error in API call [{e.res.status_code}] {e.res.reason}', exception=e)
    except Exception as e:
        demisto.debug(f'Error: {str(e)}')
        raise DemistoException(f'Test failed, Please check your parameters. \n{str(e)}', exception=e)
    return 'ok'


def country_code_list_command(client: Client, demisto_args: dict) -> CommandResults:
    """

        Gets the countries codes and names.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: The command results which contains a dict of the countries codes and names.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    raw_result = client.country_code_list_command(demisto_args)
    countries_list = [{'country_name': item.get('name'), 'iso_code': item.get('country')} for item in
                      raw_result.get('countries', [])]
    readable_output = tableToMarkdown('Netscout AED Countries List',
                                      countries_list,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)
    return CommandResults(
        outputs_prefix='NetscoutAED.Country',
        outputs_key_field='country_name',
        outputs=countries_list,
        raw_response=raw_result,
        readable_output=readable_output,

    )


def handle_country_list_commands(client: Client, demisto_args: dict,
                                 meta_data: dict) -> CommandResults:
    """

        Gets the countries from the inbound/outbound blacklisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :type meta_data: ``dict``
        :param meta_data: The meta data which determines if the countries list is outbound or inbound.

        :return: The command results which contains a dict of the outbound/inbound blacklisted countries.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    direction = meta_data.get('direction')
    if direction == 'outbound':
        raw_result = client.outbound_blacklisted_country_list_command(demisto_args)
    else:  # inbound
        raw_result = client.inbound_blacklisted_country_list_command(demisto_args)

    name = list(raw_result.keys())[0]
    countries_list = copy.deepcopy(raw_result.get(name, []))
    objects_time_to_readable_time(countries_list, 'updateTime')
    table_header = string_to_table_header(name.replace('-', ' '))

    readable_output = tableToMarkdown(table_header, countries_list,
                                      headers=['country', 'update_time', 'annotation', 'pgid', 'cid'],
                                      headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix=f'NetscoutAED.{camelize_string(direction)}BlacklistCountry',
        outputs_key_field='country',
        outputs=countries_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_country_addition_commands(client: Client, demisto_args: dict,
                                     meta_data: dict) -> CommandResults:
    """

        Adds a country to the inbound/outbound blacklisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :type meta_data: ``dict``
        :param meta_data: The meta data which determines if the countries list is outbound or inbound.

        :return: The command results which contains a dict of the added outbound/inbound blacklisted countries.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    direction = meta_data.get('direction')
    countries_to_add = demisto_args.get('country')

    if not countries_to_add:
        raise DemistoException(
            f'A country code must be provided in order to add it to the {direction} blacklisted list.')

    demisto_args['country'] = ','.join(argToList(countries_to_add))

    if direction == 'outbound':
        raw_result: Union[dict, list] = client.outbound_blacklisted_country_add_command(demisto_args)
        countries_list = list(copy.deepcopy(raw_result))

    else:  # inbound
        raw_result = client.inbound_blacklisted_country_add_command(demisto_args)
        countries_list = copy.deepcopy(raw_result.get('countries', [raw_result]))

    objects_time_to_readable_time(countries_list, 'updateTime')

    msg = f'Countries were successfully added to the {direction} blacklisted list.\n'

    readable_output = msg + tableToMarkdown('Added Countries',
                                            countries_list,
                                            headers=['country', 'cid', 'pgid', 'update_time',
                                                     'annotation'],
                                            headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        outputs_prefix=f'NetscoutAED.{camelize_string(direction)}BlacklistCountry',
        outputs_key_field='country',
        outputs=countries_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_country_deletion_commands(client: Client, demisto_args: dict, meta_data: dict) -> str:
    """

        Removes a country from the inbound/outbound blacklistd list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :type meta_data: ``dict``
        :param meta_data: The meta data which determines if the countries list is outbound or inbound.

        :return: A message which says that the countries were successfully deleted from the list.
        :rtype: ``str``

    """
    demisto_args = handle_args(demisto_args)
    direction = meta_data.get('direction')
    countries_to_delete = demisto_args.get('country')
    if not countries_to_delete:
        raise DemistoException(
            f'A country code must be provided in order to add it to the {direction} blacklisted list.')

    demisto_args['country'] = ','.join(argToList(countries_to_delete))

    if direction == 'outbound':
        raw_result = client.outbound_blacklisted_country_delete_command(demisto_args)

    else:  # inbound
        raw_result = client.inbound_blacklisted_country_delete_command(demisto_args)

    if raw_result.status_code != 204:
        raise DemistoException(
            f'Failed to remove the countries from the {direction} blacklisted list [{raw_result.status_code}]')

    return f'Countries were successfully removed from the {direction} blacklisted list.'


def handle_host_list_commands(client: Client, demisto_args: dict,
                              meta_data: dict) -> CommandResults:
    """

        Gets the hosts from the inbound/outbound blacklisted/whitelisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :type meta_data: ``dict``
        :param meta_data: The meta data which determines if the host list is
                          (outbound or inbound) and (blacklisted or whitelisted).

        :return: The command results which contains a dict of the outbound/inbound blacklisted/whitelisted hosts.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    direction = meta_data.get('direction')
    list_color = meta_data.get('list_color')

    if direction == 'outbound':
        if list_color == 'blacklist':
            raw_result = client.outbound_blacklisted_host_list_command(demisto_args)
        else:  # whitelist
            raw_result = client.outbound_whitelisted_host_list_command(demisto_args)

    else:  # inbound
        if list_color == 'blacklist':
            raw_result = client.inbound_blacklisted_host_list_command(demisto_args)
        else:
            raw_result = client.inbound_whitelisted_host_list_command(demisto_args)

    name = list(raw_result.keys())[0]
    hosts_list = copy.deepcopy(raw_result.get(name, []))
    objects_time_to_readable_time(hosts_list, 'updateTime')
    table_header = string_to_table_header(name.replace('-', ' '))
    readable_output = tableToMarkdown(table_header, hosts_list,
                                      headers=['host_address', 'cid', 'pgid', 'update_time', 'annotation'],
                                      headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix=f'NetscoutAED.{camelize_string(direction)}{camelize_string(list_color)}Host',
        outputs_key_field='host_address',
        outputs=hosts_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_host_addition_and_replacement_commands(client: Client,
                                                  demisto_args: dict,
                                                  meta_data: dict) -> CommandResults:
    """

        Adds hosts to the inbound/outbound blacklisted/whitelisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :type meta_data: ``dict``
        :param meta_data: The meta data which determines if the host list is
                          (outbound or inbound) and (blacklist or whitelist).

        :return: The command results which contains a dict of the added/replaced hosts in the
                 outbound/inbound blacklisted/whitelisted list.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    direction = meta_data.get('direction')
    list_color = meta_data.get('list_color')
    http_method = str(meta_data.get('http_method'))

    host_address = demisto_args.get('hostAddress')
    if not host_address:
        raise DemistoException(
            f'A host address must be provided in order to add/update it in the {direction} {list_color} list.')

    demisto_args['hostAddress'] = argToList(host_address)

    if direction == 'outbound':
        if list_color == 'blacklist':
            raw_result = client.outbound_blacklisted_host_add_update_command(demisto_args, http_method)
        else:  # whitelist
            raw_result = client.outbound_whitelisted_host_add_update_command(demisto_args, http_method)

    else:  # inbound
        if list_color == 'blacklist':
            raw_result = client.inbound_blacklisted_host_add_update_command(demisto_args, http_method)
        else:
            raw_result = client.inbound_whitelisted_host_add_update_command(demisto_args, http_method)

    hosts_list = copy.deepcopy(raw_result.get('hosts', [raw_result]))

    msg_method = 'added to' if http_method == 'POST' else 'replaced in'

    msg = f'Hosts were successfully {msg_method} the {direction} {list_color} list\n'

    objects_time_to_readable_time(hosts_list, 'updateTime')

    readable_output = msg + tableToMarkdown('New Hosts',
                                            hosts_list,
                                            headers=['host_address', 'pgid', 'cid', 'update_time',
                                                     'annotation', ],
                                            headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix=f'NetscoutAED.{camelize_string(direction)}{camelize_string(list_color)}Host',
        outputs_key_field='host_address',
        outputs=hosts_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_host_deletion_commands(client: Client, demisto_args: dict,
                                  meta_data: dict) -> str:
    """

        Removes hosts from the inbound/outbound blacklisted/whitelisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :type meta_data: ``dict``
        :param meta_data: The meta data which determines if the host list is
                          (outbound or inbound) and (blacklist or whitelist).

        :return: A message which says that the hosts were successfully deleted from the list.
        :rtype: ``str``

    """
    demisto_args = handle_args(demisto_args)
    direction = meta_data.get('direction')
    list_color = meta_data.get('list_color')
    host_address = demisto_args.get('hostAddress')

    if not host_address:
        raise DemistoException(
            f'A host address must be provided in order to remove it from the {direction} {list_color} list.')

    demisto_args['hostAddress'] = ','.join(argToList(host_address))

    if direction == 'outbound':
        if list_color == 'blacklist':
            raw_result = client.outbound_blacklisted_host_remove_command(demisto_args)
        else:
            raw_result = client.outbound_whitelisted_host_remove_command(demisto_args)

    else:  # inbound
        if list_color == 'blacklist':
            raw_result = client.inbound_blacklisted_host_remove_command(demisto_args)
        else:
            raw_result = client.inbound_whitelisted_host_remove_command(demisto_args)

    if raw_result.status_code != 204:
        raise DemistoException(
            f'Failed to remove the hosts from the {direction} {list_color} list [{raw_result.status_code}]')

    return f'Hosts were successfully removed from the {direction} {list_color} list'


def handle_protection_groups_list_commands(client: Client, demisto_args: dict) -> CommandResults:
    """

        Gets the list of protections groups.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: The command results which contains a list of the protection groups.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    serialize_protection_groups(demisto_args)
    raw_result = client.protection_group_list_command(demisto_args)
    protection_group_list = copy.deepcopy(raw_result.get('protection-groups', []))
    deserialize_protection_groups(protection_group_list)
    objects_time_to_readable_time(protection_group_list, 'timeCreated')

    headers = ['name', 'pgid', 'protection_level', 'active', 'server_name', 'profiling', 'profiling_duration',
               'time_created', 'description']

    readable_output = tableToMarkdown('Protection Groups', protection_group_list, headers=headers,
                                      headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix='NetscoutAED.ProtectionGroup',
        outputs_key_field='pgid',
        outputs=protection_group_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_protection_groups_update_commands(client: Client, demisto_args: dict) -> CommandResults:
    """

        Updates the settings for one or more protection groups (pgid is required).

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: The command results which contains a dict of updated protection groups.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    pgid = demisto_args.get('pgid')
    if not pgid:
        raise DemistoException(
            'A pgid must be provided in order to update the protection group.')
    if demisto_args.get('profiling') and not demisto_args.get('profiling_duration'):
        raise DemistoException(
            'A profiling duration must be provided when profiling is set to true.')

    serialize_protection_groups(demisto_args)
    raw_result = client.protection_group_patch_command(demisto_args)
    protection_groups_list = copy.deepcopy(raw_result.get('protection-groups', [raw_result]))
    deserialize_protection_groups(protection_groups_list)
    objects_time_to_readable_time(protection_groups_list, 'timeCreated')
    headers = ['name', 'pgid', 'protection_level', 'active', 'server_name', 'profiling', 'profiling_duration',
               'time_created', 'description']
    msg = f'Successfully updated the protection group object with protection group id: {pgid}\n'

    readable_output = msg + tableToMarkdown('Protection Groups', protection_groups_list, headers=headers,
                                            headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix='NetscoutAED.ProtectionGroup',
        outputs_key_field='pgid',
        outputs=protection_groups_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_domain_list_commands(client: Client, demisto_args: dict) -> CommandResults:
    """

        Gets the domains from the inbound blacklisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: The command results which contains a list of the inbound blacklisted domains.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    raw_result = client.inbound_blacklisted_domain_list_command(demisto_args)

    domains_list = copy.deepcopy(raw_result.get('blacklisted-domains', []))
    objects_time_to_readable_time(domains_list, 'updateTime')

    readable_output = tableToMarkdown('Blacklisted Domains', domains_list,
                                      headers=['domain', 'pgid', 'cid', 'update_time', 'annotation'],
                                      headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix='NetscoutAED.InboundBlacklistDomain',
        outputs_key_field='domain',
        outputs=domains_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_domain_addition_commands(client: Client, demisto_args: dict) -> CommandResults:
    """

        Adds the domains to the inbound blacklisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: The command results which contains the added domains to the inbound blacklisted list.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    domain = demisto_args.get('domain')
    if not domain:
        raise DemistoException(
            'A domain must be provided in order to add it to the inbound blacklisted list.')

    demisto_args['domain'] = ','.join(argToList(domain))

    raw_result = client.inbound_blacklisted_domain_add_command(demisto_args)
    domains_list = copy.deepcopy(raw_result.get('domains', [raw_result]))

    msg = 'Domains were successfully added to the inbound blacklisted list\n'

    objects_time_to_readable_time(domains_list, 'updateTime')

    readable_output = msg + tableToMarkdown('Added Domains', domains_list,
                                            headers=['domain', 'pgid', 'cid', 'update_time', 'annotation'],
                                            headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix='NetscoutAED.InboundBlacklistDomain',
        outputs_key_field='domain',
        outputs=domains_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_domain_deletion_commands(client: Client, demisto_args: dict) -> str:
    """

        Removes domains from the inbound blacklisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: A message which says that the domains were successfully deleted from the list.
        :rtype: ``str``

    """
    demisto_args = handle_args(demisto_args)
    domain = demisto_args.get('domain')
    if not domain:
        raise DemistoException('A domain must be provided in order to remove it from the inbound blacklisted list.')

    demisto_args['domain'] = ','.join(argToList(domain))

    raw_result = client.inbound_blacklisted_domain_remove_command(demisto_args)
    if raw_result.status_code != 204:
        raise DemistoException(
            f'Failed to remove the Domains from the inbound blacklisted list [{raw_result.status_code}]')

    return 'Domains were successfully removed from the inbound blacklisted list'


def handle_url_list_commands(client: Client, demisto_args: dict) -> CommandResults:
    """

        Gets the URLs from the inbound blacklisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: The command results which contains a list of the inbound blacklisted URLs.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    raw_result = client.inbound_blacklisted_url_list_command(demisto_args)

    urls_list = copy.deepcopy(raw_result.get('blacklisted-urls', []))
    objects_time_to_readable_time(urls_list, 'updateTime')

    readable_output = tableToMarkdown('Blacklisted URLs', urls_list,
                                      headers=['url', 'pgid', 'cid', 'update_time', 'annotation'],
                                      headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix='NetscoutAED.InboundBlacklistUrl',
        outputs_key_field='url',
        outputs=urls_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_url_addition_commands(client: Client, demisto_args: dict) -> CommandResults:
    """

        Adds the URLs to the inbound blacklisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: The command results which contains the added URLs to the inbound blacklisted list.
        :rtype: ``CommandResults``

    """
    demisto_args = handle_args(demisto_args)
    url = demisto_args.get('url')
    if not url:
        raise DemistoException(
            'A URL must be provided in order to add it to the inbound blacklisted list.')

    demisto_args['url'] = ','.join(argToList(url))

    raw_result = client.inbound_blacklisted_url_add_command(demisto_args)
    urls_list = copy.deepcopy(raw_result.get('urls', [raw_result]))
    msg = 'Urls were successfully added to the inbound blacklisted list\n'

    objects_time_to_readable_time(urls_list, 'updateTime')

    readable_output = msg + tableToMarkdown('Added Urls', urls_list,
                                            headers=['url', 'pgid', 'cid', 'update_time', 'annotation'],
                                            headerTransform=string_to_table_header, removeNull=True)

    return CommandResults(
        outputs_prefix='NetscoutAED.InboundBlacklistUrl',
        outputs_key_field='url',
        outputs=urls_list,
        raw_response=raw_result,
        readable_output=readable_output,
    )


def handle_url_deletion_commands(client: Client, demisto_args: dict) -> str:
    """

        Removes URLs from the inbound blacklisted list.

        :type client: ``Client``
        :param client: Client to use.

        :type demisto_args: ``dict``
        :param demisto_args: The demisto arguments.

        :return: A message which says that the URLs were successfully deleted from the list.
        :rtype: ``str``

    """
    demisto_args = handle_args(demisto_args)
    url = demisto_args.get('url')
    if not url:
        raise DemistoException('A URL must be provided in order to remove it from the inbound blacklisted list.')

    demisto_args['url'] = ','.join(argToList(url))
    raw_result = client.inbound_blacklisted_url_remove_command(demisto_args)
    if raw_result.status_code != 204:
        raise DemistoException(
            f'Failed to remove the URLs from the inbound blacklisted list [{raw_result.status_code}]')

    return 'URLs were successfully removed from the inbound blacklisted list'


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    demisto_command = demisto.command()
    demisto_args = demisto.args()
    try:
        base_url: str = urljoin(params.get('base_url', '').rstrip('/'), '/api/aed/v2')
        verify_certificate: bool = not params.get('insecure', False)
        proxy: bool = params.get('proxy', False)
        if not params.get('User') or not (api_token := params.get('User', {}).get('password')):
            raise DemistoException('Missing API Key. Please fill in a valid key in the integration configuration.')
        commands = init_commands_dict()
        handle_proxy()
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            api_token=api_token,
            proxy=proxy)

        if not demisto_command or demisto_command not in commands:
            raise NotImplementedError(f'Command {demisto_command} is not implemented.')

        demisto.debug(f'Command being called is {demisto_command}')
        func_to_execute = dict_safe_get(commands, [demisto_command, 'func'])
        meta_data = dict_safe_get(commands, [demisto_command, 'meta_data'])
        results = func_to_execute(client, demisto_args, meta_data) if meta_data \
            else func_to_execute(client, demisto_args)
        return_results(results)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}', error=e)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
