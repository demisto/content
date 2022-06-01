from datetime import datetime, timedelta
import urllib3
import json
import dateparser
from typing import Any, Dict
from CommonServerPython import *


urllib3.disable_warnings()


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
HELLOWORLD_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']


class Client(BaseClient):

    def get_associated_users(self, devicetype):
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/associated_users/?device_type=%s' % (devicetype),
            resp_type='text'
        ))

    def get_authentication_methods_distribution(self):
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/device_auth_distribution/',
            resp_type='text'
        ))

    def get_authentication_rate_per_device(self):
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/device_auth_rate/',
            resp_type='text'
        ))

    def get_least_active_users(self, sincedate=None, userinformation=False):
        if sincedate is None:
            sincedate = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/inactive_users/?since_date=%s&user_information=%s' % (sincedate, str(userinformation)),
            resp_type='text'
        ))

    def get_licenses_inventory(self):
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/device_inventory/',
            resp_type='text'
        ))

    def get_licenses_usage(self, begindate=None, enddate=None):
        if begindate is None:
            begindate = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")

        if enddate is None:
            enddate = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/licensesusage/?begin_date=%s&end_date=%s' % (begindate, enddate),
            resp_type='text'
        ))

    def get_most_active_users(self, days=10, limit=30, userinformation=False):
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/top_users/?days=%s&limit=%s&user_information=%s' % (str(days), str(limit), str(userinformation)),
            resp_type='text'
        ))

    def get_physical_tokens_inventory(self):
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/physical_tokens_inventory/',
            resp_type='text'
        ))

    def get_registered_devices_distribution(self):
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/device_inventory/?fields=associated_and_registered',
            resp_type='text'
        ))

    def get_registration(self, begindate=None, enddate=None, userinformation=False):
        if begindate is None:
            begindate = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")

        if enddate is None:
            enddate = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/registrations/?begin_date=%s&end_date=%s&user_information=%s' % (
                begindate, enddate, str(userinformation)),
            resp_type='text'
        ))

    def get_users_associations_indicators(self):
        return json.loads(self._http_request(
            method='GET',
            url_suffix='/reports/users/',
            resp_type='text'
        ))

    def list_incidents(self, page, search, locked, query_filter=None) -> Dict[str, Any]:
        if page is None:
            page = 1

        p_search = ""
        if search is not None and search != '':
            p_search = '&search=%s' % search

        p_locked = ""
        if locked is not None and locked:
            p_locked = '&locked=%s' % "true"

        p_query_filter = ""
        if query_filter is not None and search != '':
            p_query_filter = '&q=%s' % query_filter

        return json.loads(self._http_request(
            method='GET',
            url_suffix='/transactionlog/?page=%s%s%s%s' % (page, p_search, p_locked, p_query_filter),
            resp_type='text'
        ))


def get_associated_users(client, args):

    devicetype = args.get('devicetype')
    result_raw = client.get_associated_users(devicetype)
    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Associated Users Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetAssociatedUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_authentication_methods_distribution(client, args):

    result_raw = client.get_authentication_methods_distribution()

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Authentication Methods Distribution Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetAuthenticationMethodsDistribution.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_authentication_rate_per_device(client, args):
    result_raw = client.get_authentication_rate_per_device()

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Authentication Rate Per Device Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetAuthenticationRatePerDevice.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_least_active_users(client, args):
    sincedate = args.get('sincedate')
    userinformation = args.get('userinformation')

    result_raw = client.get_least_active_users(sincedate, userinformation)

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Least Active Users Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLeastActiveUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_licenses_inventory(client, args):

    result_raw = client.get_licenses_inventory()

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Licenses Inventory Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLicensesInventory.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_licenses_usage(client, args):
    begindate = args.get('begindate')
    enddate = args.get('enddate')

    result_raw = client.get_licenses_usage(begindate, enddate)

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Licenses Usage Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLicensesUsage.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_most_active_users(client, args):
    days = args.get('days')
    limit = args.get('limit')
    userinformation = args.get('userinformation')

    result_raw = client.get_most_active_users(days, limit, userinformation)

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Most Active Users Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetMostActiveUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_physical_tokens_inventory(client, args):

    result_raw = client.get_physical_tokens_inventory()

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Physical Tokens Inventory Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetPhysicalTokensInventory.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_registered_devices_distribution(client, args):

    result_raw = client.get_registered_devices_distribution()

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Registered Devices Distribution Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetRegisteredDevicesDistribution.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_registration(client, args):
    begindate = args.get('begindate')
    enddate = args.get('enddate')
    userinformation = args.get('userinformation')

    result_raw = client.get_registration(begindate, enddate, userinformation)

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Registration Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetRegistration.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def get_users_associations_indicators(client, args):

    result_raw = client.get_users_associations_indicators()

    result = remove_empty_elements(result_raw)

    readable_output = tableToMarkdown(
        'Get Users Associations Indicators Results',
        result,
        headers=list(result.keys()),
        headerTransform=string_to_table_header,
    )
    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUsersAssociationsIndicators.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result_raw
    )

    return command_results


def test_module(client, is_fetch, last_run, first_fetch_str, fetch_limit):

    if argToBoolean(is_fetch):
        results, next_run = fetch_incidents(client, last_run, first_fetch_str, fetch_limit)
        if results and len(results) > 0:
            results = results[0].get('rawJSON')
            if results:
                results = json.loads(results)
                if results.get('reason_detail') == 'Invalid credentials':
                    return 'Failed to run test, invalid credentials.'
            else:
                return 'ok'
    else:
        results = client.list_incidents(None, None, None, None)

    if results:
        results = results.get('results')
        if results and len(results) > 0:
            if results[0].get('reason_detail') == 'Invalid credentials':
                return 'Failed to run test, invalid credentials.'
            else:
                return 'ok'
    else:
        return 'Failed to run test.'


def fetch_incidents(client, last_run, first_fetch_str, fetch_limit, query_filter=None):
    incidents = []

    first_fetch_date = dateparser.parse(first_fetch_str)
    assert first_fetch_date is not None, f'could not parse {first_fetch_str}'
    first_fetch = first_fetch_date.strftime(DATE_FORMAT)
    last_run_time = last_run.get('last_run_time', first_fetch)
    next_run_time = last_run_time

    # Last run time must be used to filter transaction log
    results = []
    if query_filter and query_filter:
        q_list = query_filter.split(',')
        for q in q_list:
            if q:
                tmp = client.list_incidents(None, None, None, q).get('results')
                results.extend([element for element in tmp if element not in results])
    else:
        results = client.list_incidents(None, None, None, query_filter).get('results')

    for result in results:
        timestamp_date = dateparser.parse(result.get('timestamp'))
        assert timestamp_date is not None
        incident_time = timestamp_date.strftime(DATE_FORMAT)

        # This condition is temporal
        if incident_time > last_run_time:
            incident = {
                'name': result.get('reason_detail'),
                'occurred': incident_time,
                'rawJSON': json.dumps(result)
            }
            incidents.append(incident)

            if incident_time > next_run_time:
                next_run_time = incident_time

    next_run = {
        'last_run_time': next_run_time
    }

    return incidents[:int(fetch_limit)], next_run


def main():

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    base_url = params.get('url')
    if base_url:
        base_url = base_url + '/api/v1/admin/'
    demisto.info(f'BASE_URL: {base_url}')
    verify_certificate = not params.get('insecure', False)
    auth_access_token = params.get('apikey')
    proxy = params.get('proxy', False)

    is_fetch = params.get('isFetch', False)
    fetch_limit = params.get('max_fetch', 50)
    first_fetch_str = params.get('first_fetch', '0')
    fetch_query_filter = params.get('fetch_query_filter')

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'Authorization': 'Bearer %s' % auth_access_token},
            proxy=proxy)

        if command == 'safewalk-get-associated-users':
            result = get_associated_users(client, args)
            return_results(result)

        if command == 'safewalk-get-authentication-methods-distribution':
            result = get_authentication_methods_distribution(client, args)
            return_results(result)

        if command == 'safewalk-get-authentication-rate-per-device':
            result = get_authentication_rate_per_device(client, args)
            return_results(result)

        if command == 'safewalk-get-least-active-users':
            result = get_least_active_users(client, args)
            return_results(result)

        if command == 'safewalk-get-licenses-inventory':
            result = get_licenses_inventory(client, args)
            return_results(result)

        if command == 'safewalk-get-licenses-usage':
            result = get_licenses_usage(client, args)
            return_results(result)

        if command == 'safewalk-get-most-active-users':
            result = get_most_active_users(client, args)
            return_results(result)

        if command == 'safewalk-get-physical-tokens-inventory':
            result = get_physical_tokens_inventory(client, args)
            return_results(result)

        if command == 'safewalk-get-registered-devices-distribution':
            result = get_registered_devices_distribution(client, args)
            return_results(result)

        if command == 'safewalk-get-registration':
            result = get_registration(client, args)
            return_results(result)

        if command == 'safewalk-get-users-associations-indicators':
            result = get_users_associations_indicators(client, args)
            return_results(result)

        if command == 'test-module':
            result = test_module(client, is_fetch, demisto.getLastRun(), first_fetch_str, fetch_limit)
            return_results(result)

        if command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            incidents, next_run = fetch_incidents(client, last_run, first_fetch_str, fetch_limit, fetch_query_filter)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
