from datetime import datetime, timedelta
import urllib3
import json
import dateparser
from typing import Any, Dict
from CommonServerPython import *


urllib3.disable_warnings()


class Client(BaseClient):

    def get_associated_users(self, devicetype):
        return self._http_request(
            method='GET',
            url_suffix='/reports/associated_users/?device_type=%s' % (devicetype),
            resp_type='text'
        )

    def get_authentication_methods_distribution(self):
        return self._http_request(
            method='GET',
            url_suffix='/reports/device_auth_distribution/',
            resp_type='text'
        )

    def get_authentication_rate_per_device(self):
        return self._http_request(
            method='GET',
            url_suffix='/reports/device_auth_rate/',
            resp_type='text'
        )

    def get_least_active_users(self, sincedate=None, userinformation=False):
        if sincedate is None:
            sincedate = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        return self._http_request(
            method='GET',
            url_suffix='/reports/inactive_users/?since_date=%s&user_information=%s' % (sincedate, str(userinformation)),
            resp_type='text'
        )

    def get_licenses_inventory(self):
        return self._http_request(
            method='GET',
            url_suffix='/reports/device_inventory/',
            resp_type='text'
        )

    def get_licenses_usage(self, begindate=None, enddate=None):
        if begindate is None:
            begindate = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")

        if enddate is None:
            enddate = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        return self._http_request(
            method='GET',
            url_suffix='/reports/licensesusage/?begin_date=%s&end_date=%s' % (begindate, enddate),
            resp_type='text'
        )

    def get_most_active_users(self, days=10, limit=30, userinformation=False):
        return self._http_request(
            method='GET',
            url_suffix='/reports/top_users/?days=%s&limit=%s&user_information=%s' % (str(days), str(limit), str(userinformation)),
            resp_type='text'
        )

    def get_physical_tokens_inventory(self):
        return self._http_request(
            method='GET',
            url_suffix='/reports/physical_tokens_inventory/',
            resp_type='text'
        )

    def get_registered_devices_distribution(self):
        return self._http_request(
            method='GET',
            url_suffix='/reports/device_inventory/?fields=associated_and_registered',
            resp_type='text'
        )

    def get_registration(self, begindate=None, enddate=None, userinformation=False):
        if begindate is None:
            begindate = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")

        if enddate is None:
            enddate = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")

        return self._http_request(
            method='GET',
            url_suffix='/reports/registrations/?begin_date=%s&end_date=%s&user_information=%s' % (begindate, enddate, str(userinformation)),
            resp_type='text'
        )

    def get_users_associations_indicators(self):
        return self._http_request(
            method='GET',
            url_suffix='/reports/users/',
            resp_type='text'
        )

    def list_incidents(self, page, search, locked, query_filter=None) -> Dict[str, Any]:
        if page is None:
            page = 1

        p_search=""
        if search is not None and search != '':
            p_search = '&search=%s' % search

        p_locked = ""
        if locked is not None and locked:
            p_locked = '&locked=%s' % "true"

        p_query_filter = ""
        if query_filter is not None and search != '':
            p_query_filter = '&q=%s' % query_filter

        return self._http_request(
            method='GET',
            url_suffix='/transactionlog/?page=%s%s%s%s' % (page, p_search, p_locked, p_query_filter),
            resp_type = 'text'
        )


def get_associated_users(client, args):

    devicetype = args.get('devicetype')
    result = client.get_associated_users(devicetype)
    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetAssociatedUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_authentication_methods_distribution(client, args):

    result = client.get_authentication_methods_distribution()

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetAuthenticationMethodsDistribution.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_authentication_rate_per_device(client, args):
    result = client.get_authentication_rate_per_device()

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetAuthenticationRatePerDevice.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_least_active_users(client, args):
    sincedate = args.get('sincedate')
    userinformation = args.get('userinformation')

    result = client.get_least_active_users(sincedate, userinformation)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLeastActiveUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_licenses_inventory(client, args):

    result = client.get_licenses_inventory()

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLicensesInventory.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_licenses_usage(client, args):
    begindate = args.get('begindate')
    enddate = args.get('enddate')

    result = client.get_licenses_usage(begindate, enddate)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetLicensesUsage.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_most_active_users(client, args):
    days = args.get('days')
    limit = args.get('limit')
    userinformation = args.get('userinformation')

    result = client.get_most_active_users(days, limit, userinformation)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetMostActiveUsers.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_physical_tokens_inventory(client, args):

    result = client.get_physical_tokens_inventory()

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetPhysicalTokensInventory.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_registered_devices_distribution(client, args):

    result = client.get_registered_devices_distribution()

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetRegisteredDevicesDistribution.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_registration(client, args):
    begindate = args.get('begindate')
    enddate = args.get('enddate')
    userinformation = args.get('userinformation')

    result = client.get_registration(begindate, enddate, userinformation)

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetRegistration.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def get_users_associations_indicators(client, args):

    result = client.get_users_associations_indicators()

    readable_output = f'## {result}'

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='GetUsersAssociationsIndicators.Result',
        outputs_key_field='',
        outputs=result,
        raw_response=result
    )

    return command_results


def test_module(client, args):
    results = json.loads(client.list_incidents(None, None, None, None))['results']

    if results is not None:
        return 'ok'
    else:
        return 'Failed to run the test'


def fetch_incidents(client, last_run, first_fetch_str, fetch_limit, query_filter=None,
                    auto_generate_filter=False, context=None):
    incidents = []

    first_fetch = dateparser.parse(first_fetch_str).strftime(DATE_FORMAT)
    last_run_time = last_run.get('last_run_time', first_fetch)
    next_run_time = last_run_time

    # Last run time must be used to filter transaction log
    results = []
    if query_filter and query_filter:
        q_list = query_filter.split(',')
        for q in q_list:
            if q:
                tmp = json.loads(client.list_incidents(None, None, None, q)).get('results')
                results.extend([element for element in tmp if element not in results])
    else:
        results = json.loads(client.list_incidents(None, None, None, query_filter)).get('results')

    for result in results:
        incident_time = dateparser.parse(result.get('timestamp')).strftime(DATE_FORMAT)

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
    base_url = base_url + '/api/v1/admin/'
    demisto.info(f'BASE_URL: {base_url}')
    verify_certificate = not params.get('insecure', False)
    auth_access_token = params.get('apikey')
    proxy = params.get('proxy', False)

    fetch_limit = (params.get('max_fetch'))
    first_fetch_str = params.get('first_fetch')
    auto_generate_query_filter = params.get('auto_generate_query_filter')
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
            result = test_module(client, args)
            return_results(result)

        if command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            context = demisto.getIntegrationContext()
            incidents, next_run = fetch_incidents(client, last_run, first_fetch_str, fetch_limit, fetch_query_filter,
                                                  auto_generate_query_filter, context)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
