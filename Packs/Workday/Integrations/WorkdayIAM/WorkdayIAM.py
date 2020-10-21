import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''
import traceback
from email.mime.text import MIMEText
from smtplib import SMTP
import requests
from datetime import datetime, timedelta


WORKDAY_DATE_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
READ_TIME_OUT_IN_SECONDS = 300


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """
    def __init__(self, base_url: Any, verify: bool, headers: dict, proxy: bool, ok_codes: tuple, auth: Any, report_url: str):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy, ok_codes=ok_codes, auth=auth)
        self._report_url = report_url

    # Getting Workday Full User Report with a given report URL. This uses RaaS
    def get_full_report(self):
        return self._http_request(method="GET", full_url=self._report_url, url_suffix="", timeout=READ_TIME_OUT_IN_SECONDS)


def convert_incident_fields_to_cli_names(data):
    converted_data = {}
    for k, v in data.items():
        key_machine_name = k.lower().replace(' ', '')
        converted_data[key_machine_name] = v
    return converted_data


def get_time_elapsed(fetch_time, last_run):
    now = datetime.now()
    demisto.info("Workday Last Run: " + str(last_run))
    if 'time' in last_run:
        # Get Last run and parse to date format. Workday report will be pulled from last run time to current time
        last_run_time = last_run['time']
        # Convert to date format
        last_run = datetime.strptime(last_run_time, WORKDAY_DATE_TIME_FORMAT)
        time_elapsed_in_minutes = (now - last_run).total_seconds() / 60
    else:
        # If last run time is not set, data will be pulled using fetch_time
        # i.e. last 10min if fetch events is set to 10min
        last_run_time = (now - timedelta(minutes=int(fetch_time))).strftime(
            WORKDAY_DATE_TIME_FORMAT)
        time_elapsed_in_minutes = fetch_time

    return time_elapsed_in_minutes, last_run_time


def fetch_incidents(client, last_run, fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client: Workday client
        last_run: The greatest incident created_time we fetched from last fetch
        fetch_time: The time interval when the function should execute and return events/incidents

    Returns:
        last_run: This will be last_run in the next fetch-incidents
        events: Incidents/Events that will be created in Cortex XSOAR
    """
    start = datetime.now()
    events = []
    from_date_time = '###'
    to_date_time = '$$$'
    try:
        # If there is no fetch time configured, it will be set to 0 and no events will be pulled
        fetch_time = int(fetch_time) if fetch_time else 0
        time_elapsed_in_minutes, last_run_time = get_time_elapsed(fetch_time, last_run)

        from_date_time = last_run_time
        if fetch_time != 0 and time_elapsed_in_minutes >= fetch_time:
            to_date_time = datetime.now().strftime(WORKDAY_DATE_TIME_FORMAT)
            report_data = client.get_full_report()
            report_entries = report_data.get('Report_Entry')
            for entry in report_entries:
                workday_user = demisto.mapObject(entry, 'IAM Sync User - Workday', 'IAM-Sync-User')
                workday_user = convert_incident_fields_to_cli_names(workday_user)
                demisto_user = get_demisto_user(workday_user)
                profile_changed_fields = get_profile_changed_fields(workday_user, demisto_user)
                does_email_exist = does_email_exist_in_xsoar(workday_user.get('email'))

                if (demisto_user and len(profile_changed_fields) == 0) or (not demisto_user and does_email_exist):
                    # either no change in user profile (by employee id), or user profile doesn't exist but the email is already used
                    # in both cases, don't create the incident
                    continue

                # todo: remove condition
                if workday_user.get('email') == 'dcrocker@paloaltonetworks.com':
                    continue

                entry['UserProfile'] = workday_user
                event = {
                    "rawJSON": json.dumps(entry),
                    "details": 'Profile changed. Changed fields: ' + str(profile_changed_fields)
                }
                events.append(event)
            last_run_time = datetime.now().strftime(WORKDAY_DATE_TIME_FORMAT)
            demisto.info(f'Workday Fetch Events Completed. Response Time:'
                         f' {(datetime.now() - start).total_seconds()} seconds')

        last_run = {'time': last_run_time}
    except Exception as e:
        demisto.error(f'Failed to fetch events. From Date = {from_date_time}. To Date = {to_date_time}')
        raise e

    return last_run, events


def get_demisto_user(workday_user):
    employee_id = workday_user.get('employeeid')
    data = demisto.searchIndicators(query=f"type:\"User Profile\" and employeeid:\"{employee_id}\"").get('iocs')
    demisto.info('WORKDAY FETCH: employee - ' + workday_user.get('displayname'))
    demisto.info('WORKDAY FETCH: employee data - ' + str(data))
    if data:
        return data[0]
    return None


def does_email_exist_in_xsoar(email_address):
    data = demisto.searchIndicators(query=f"type:\"User Profile\" and value:\"{email_address}\"").get('iocs')
    does_email_exist = (data and len(data) > 0)
    demisto.info('WORKDAY FETCH: does email exist - ' + str(does_email_exist))
    demisto.info('WORKDAY FETCH: email - ' + str(email_address))
    return does_email_exist


def get_profile_changed_fields(workday_user, demisto_user):
    if not demisto_user:
        return False  # potential new hire
    profile_changed_fields = []
    for user_profile_key in workday_user.keys():
        workday_value = workday_user.get(user_profile_key)
        demisto_value = demisto_user.get('CustomFields', {}).get(user_profile_key)
        if user_profile_key == 'streetaddress' and workday_user.get('displayname') == 'Remy Buxaplenty':
            demisto.info(f'Remy Buxaplenty - workday_user: {workday_value}, demisto_user: {demisto_value}')
        if workday_value and demisto_value and workday_value != demisto_value:
            profile_changed_fields.append(user_profile_key)

    demisto.info('WORKDAY FETCH: display name: ' + str(workday_user.get('displayname')))
    demisto.info('WORKDAY FETCH: CHANGES ' + str(profile_changed_fields))

    return profile_changed_fields


def test_module(client, params):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Anything else will fail the test.
    """
    client.get_full_report()

    if params.get('isFetch'):
        last_run, events = fetch_incidents(
            client=client,
            last_run={},
            fetch_time=params.get('fetch_events_time_minutes')
        )

    return 'ok'


def entry_to_user_profile(entry):
    user_profile = demisto.mapObject(entry, 'IAM Sync User - Workday', 'IAM-Sync-User')
    user_profile = convert_incident_fields_to_cli_names(user_profile)
    return user_profile


def report_to_indicators(report_entries):
    user_profiles = [entry_to_user_profile(e) for e in report_entries]
    indicators = [user_profile_to_indicator(u) for u in user_profiles]
    return indicators


def user_profile_to_indicator(user_profile):
    indicator = {
        'value': user_profile.get('email'),
        'type': 'User Profile',
        'rawJSON': user_profile
    }
    return indicator


def workday_first_run_command(client):
    report_data = client.get_full_report()
    indicators = report_to_indicators(report_data.get('Report_Entry'))
    for b in batch(indicators, batch_size=2000):
        demisto.createIndicators(b)
    demisto.results(indicators[0])


def main():
    command = demisto.command()
    params = demisto.params()

    report_url = params.get('report_url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    workday_username = params.get('credentials', {}).get('identifier')
    workday_password = params.get('credentials', {}).get('password')

    LOG(f'Command being called is {command}')

    client = Client(
        base_url=None,
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        proxy=proxy,
        ok_codes=(200, 204),
        auth=requests.auth.HTTPBasicAuth(workday_username, workday_password),
        report_url=report_url
    )

    try:
        if command == 'test-module':
            return_results(test_module(client, params))

        if command == 'fetch-incidents':
            '''
                Checks if there are events are stored in the integration context.
                If yes, it gets it from there. Else, it makes a call to Workday to get a new report
                Returns the first x events (x being the fetch limit) and stores the remaining in integration context
            '''
            workday_context = demisto.getIntegrationContext()
            events = workday_context.get('events')

            last_run = demisto.getLastRun()
            if not events:
                # Get the events from Workday by making an API call. Last run is updated only when API call is made
                last_run, events = fetch_incidents(
                    client=client,
                    last_run=last_run,
                    fetch_time=params.get('fetch_events_time_minutes'))

            fetch_limit = int(params.get('fetch_limit'))

            demisto.setLastRun(last_run)
            demisto.incidents(events[:fetch_limit])

            # Set the remaining events back to integration context
            workday_context = {'events': events[fetch_limit:]}
            demisto.setIntegrationContext(workday_context)

        if command == 'workday-first-run':
            workday_first_run_command(client)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
