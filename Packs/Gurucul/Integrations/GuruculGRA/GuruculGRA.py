import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import traceback
from typing import Any, Dict, List, Optional, Tuple, cast

import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_INCIDENTS_TO_FETCH = 25

''' CLIENT CLASS '''


class Client(BaseClient):

    def fetch_command_result(self, url_suffix, params):
        incidents: List = list()
        try:
            r = self._http_request(
                method='GET',
                url_suffix=url_suffix,
                params=params
            )
            if len(r) > 0:
                incidents.extend(r)
        except Exception:
            demisto.error("Unable to fetch command result" + traceback.format_exc())
        return incidents

    def validate_api_key(self):
        self._http_request(
            method='GET',
            url_suffix='/validate',
            params={}
        )
        return 'ok'


''' HELPER FUNCTIONS '''


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> Optional[int]:

    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        return int(arg)
    if isinstance(arg, str):
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, (int, float)):
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


''' COMMAND FUNCTIONS '''


def fetch_record_command(client: Client, url_suffix, prefix, key, params):
    incidents: List = list()
    r = client.fetch_command_result(url_suffix, params)
    incidents.extend(r)
    results = CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=incidents
    )
    return results


def fetch_records(client: Client, url_suffix, prefix, key, params):
    results = fetch_record_command(client, url_suffix, prefix, key, params)
    return_results(results)


def fetch_incidents(client: Client, max_results: int, last_run: Dict[str, int],
                    first_fetch_time: Optional[int], command_type: str
                    ) -> Tuple[Dict[str, int], List[dict]]:
    if command_type == 'GraCases':
        return_data = fetch_incidents_open_cases(client, max_results, last_run, first_fetch_time)
    else:
        return_data = fetch_incidents_high_risk_users(client, max_results, last_run, first_fetch_time)
    return return_data


def fetch_incidents_open_cases(client: Client, max_results: int, last_run: Dict[str, int],
                               first_fetch_time: Optional[int]
                               ) -> Tuple[Dict[str, int], List[dict]]:
    last_fetch = last_run.get('last_fetch', None)

    if last_fetch is None:
        last_fetch = first_fetch_time
        case_url = '/cases/OPEN/opendate/' + (datetime.fromtimestamp(cast(int, last_fetch)).strftime('%Y-%m-%d'))
    else:
        last_fetch = int(last_fetch)
        case_url = '/cases/OPEN/opendate/lastminute'
    latest_created_time = cast(int, last_fetch)
    incidents: List[Dict[str, Any]] = []
    page = 1
    isContinue = True
    while isContinue:
        params = {'page': page, 'max': max_results}
        case_data = client.fetch_command_result(case_url, params)
        if len(case_data) < max_results:
            isContinue = False
        else:
            page += 1
        for record in case_data:
            incident_created_time = datetime.now().timestamp()
            incident_created_time_ms = incident_created_time * 1000
            record['incidentType'] = 'GRACase'
            inc = {
                'name': record.get('entity'),
                'occurred': timestamp_to_datestring(incident_created_time_ms),
                'rawJSON': json.dumps(record)
            }
            incidents.append(inc)
            if incident_created_time > latest_created_time:
                latest_created_time = int(incident_created_time)

        next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def fetch_incidents_high_risk_users(client: Client, max_results: int, last_run: Dict[str, int],
                                    first_fetch_time: Optional[int]
                                    ) -> Tuple[Dict[str, int], List[dict]]:
    last_fetch = last_run.get('last_fetch', None)
    if last_fetch is None:
        last_fetch = first_fetch_time
        high_risk_user_url = '/users/highrisk/modifieddate/' \
                             + (datetime.fromtimestamp(cast(int, last_fetch)).strftime('%Y-%m-%d'))
    else:
        last_fetch = int(last_fetch)
        high_risk_user_url = '/users/highrisk/modifieddate/lastminute'
    latest_created_time = cast(int, last_fetch)
    incidents: List[Dict[str, Any]] = []
    page = 1
    isContinue = True
    while isContinue:
        params = {'page': page, 'max': max_results}
        users_data = client.fetch_command_result(high_risk_user_url, params)
        if len(users_data) < max_results:
            isContinue = False
        else:
            page += 1
        for record1 in users_data:
            incident_created_time = datetime.now().timestamp()
            incident_created_time_ms = incident_created_time * 1000
            record1['incidentType'] = 'HighRiskUser'
            inc1 = {
                'name': record1.get('employeeId'),
                'occurred': timestamp_to_datestring(incident_created_time_ms),
                'rawJSON': json.dumps(record1)
            }
            incidents.append(inc1)
            if incident_created_time > latest_created_time:
                latest_created_time = int(incident_created_time)

        next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def test_module_command(client: Client) -> str:
    try:
        client.validate_api_key()
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:
    try:
        api_key = demisto.params().get('apikey')
        base_url = urljoin(demisto.params()['url'], '/api/')
        verify_certificate = not demisto.params().get('insecure', False)
        first_fetch_time = arg_to_timestamp(
            arg=demisto.params().get('first_fetch', '1 days'),
            arg_name='First fetch time',
            required=True
        )
        assert isinstance(first_fetch_time, int)
        proxy = demisto.params().get('proxy', False)
        page = demisto.args().get('page', "1")
        page_count_no = demisto.args().get('max', "25")
        demisto.debug(f'Command being called is {demisto.command()}')
        params = {'page': page, 'max': page_count_no}
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            result = test_module_command(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            fetch_incident_command = demisto.params().get('fetch_incident_command')

            max_results = arg_to_int(
                arg=demisto.params().get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_time,
                command_type=fetch_incident_command
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'gra-fetch-users':
            fetch_records(client, '/users', 'Gra.Users', 'employeeId', params)

        elif demisto.command() == 'gra-fetch-accounts':
            fetch_records(client, '/accounts', 'Gra.Accounts', 'id', params)

        elif demisto.command() == 'gra-fetch-active-resource-accounts':
            active_resource_url = '/resources/' + demisto.args().get('resource_name', 'Windows Security') + '/accounts'
            fetch_records(client, active_resource_url, 'Gra.Active.Resource.Accounts', 'id', params)

        elif demisto.command() == 'gra-fetch-user-accounts':
            user_account_url = '/users/' + demisto.args().get('employee_id') + '/accounts'
            fetch_records(client, user_account_url, 'Gra.User.Accounts', 'id', params)

        elif demisto.command() == 'gra-fetch-resource-highrisk-accounts':
            res_name = demisto.args().get('Resource_name', 'Windows Security')
            high_risk_account_resource_url = '/resources/' + res_name + '/accounts/highrisk'
            fetch_records(client, high_risk_account_resource_url, 'Gra.Resource.Highrisk.Accounts', 'id', params)

        elif demisto.command() == 'gra-fetch-hpa':
            fetch_records(client, '/accounts/highprivileged', 'Gra.Hpa', 'id', params)

        elif demisto.command() == 'gra-fetch-resource-hpa':
            resource_hpa = '/resources/' + demisto.args().get('resource_name', 'Windows Security') + '/accounts/highprivileged'
            fetch_records(client, resource_hpa, 'Gra.Resource.Hpa', 'id', params)

        elif demisto.command() == 'gra-fetch-orphan-accounts':
            fetch_records(client, '/accounts/orphan', 'Gra.Orphan.Accounts', 'id', params)

        elif demisto.command() == 'gra-fetch-resource-orphan-accounts':
            resource_orphan = '/resources/' + demisto.args().get('resource_name', 'Windows Security') + '/accounts/orphan'
            fetch_records(client, resource_orphan, 'Gra.Resource.Orphan.Accounts', 'id', params)

        elif demisto.command() == 'gra-user-activities':
            user_activities_url = '/user/' + demisto.args().get('employee_id') + '/activity'
            fetch_records(client, user_activities_url, 'Gra.User.Activity', 'employee_id', params)

        elif demisto.command() == 'gra-fetch-users-details':
            fetch_records(client, '/users/' + demisto.args().get('employee_id'), 'Gra.User', 'employeeId', params)

        elif demisto.command() == 'gra-highRisk-users':
            fetch_records(client, '/users/highrisk', 'Gra.Highrisk.Users', 'employeeId', params)

        elif demisto.command() == 'gra-cases':
            cases_url = '/cases/' + demisto.args().get('status')
            fetch_records(client, cases_url, 'Gra.Cases', 'caseId', params)

        elif demisto.command() == 'gra-user-anomalies':
            anomaly_url = '/users/' + demisto.args().get('employee_id') + '/anomalies/'
            fetch_records(client, anomaly_url, 'Gra.User.Anomalies', 'anomaly_name', params)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
