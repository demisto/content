import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''
import traceback
import requests
from datetime import datetime, timedelta

LAST_DAY_OF_WORK_EVENT_FIELD = 'lastdayofwork'
TERMINATION_DATE_EVENT_FIELD = 'terminationdate'
EMPLOYMENT_STATUS_EVENT_FIELD = 'employmentstatus'
HIRE_DATE_EVENT_FIELD = 'hiredate'
EMPLOYEE_ACTIVE_STATUS = 'active'
WORKDAY_DATE_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
WORKDAY_DATE_FORMAT = "%m/%d/%Y"
READ_TIME_OUT_IN_SECONDS = 300
INCIDENT_TYPE = 'IAM - Sync User'
DEFAULT_MAPPER_IN = 'IAM Sync User - Workday'


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """
    # Getting Workday Full User Report with a given report URL. This uses RaaS
    def get_full_report(self, report_url):
        return self._http_request(method="GET", full_url=report_url, url_suffix="",
                                  timeout=READ_TIME_OUT_IN_SECONDS)


def convert_incident_fields_to_cli_names(data):
    converted_data = {}
    for k, v in data.items():
        key_machine_name = k.lower().replace(' ', '')
        converted_data[key_machine_name] = v
    return converted_data


def get_time_elapsed(fetch_time, last_run):
    now = datetime.now()
    demisto.debug("Workday Last Run: " + str(last_run))
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


def fetch_incidents(client, last_run, fetch_time, mapper_in, report_url):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client: Workday client
        last_run: The greatest incident created_time we fetched from last fetch
        fetch_time: The time interval when the function should execute and return events/incidents
        report_url: The report full URL.

    Returns:
        last_run: This will be last_run in the next fetch-incidents
        events: Incidents/Events that will be created in Cortex XSOAR
    """
    start = datetime.now()
    events = []
    from_date_time = '###'
    to_date_time = '$$$'
    try:
        employee_id_to_user_profile, email_to_user_profile = get_all_user_profiles()

        # If there is no fetch time configured, it will be set to 0 and no events will be pulled
        fetch_time = int(fetch_time) if fetch_time else 0
        time_elapsed_in_minutes, last_run_time = get_time_elapsed(fetch_time, last_run)

        from_date_time = last_run_time
        if fetch_time != 0 and time_elapsed_in_minutes >= fetch_time:
            to_date_time = datetime.now().strftime(WORKDAY_DATE_TIME_FORMAT)
            report_data = client.get_full_report(report_url)
            report_entries = report_data.get('Report_Entry')
            for entry in report_entries:
                workday_user = demisto.mapObject(entry, mapper_in, INCIDENT_TYPE)
                workday_user = convert_incident_fields_to_cli_names(workday_user)

                demisto_user = get_demisto_user(employee_id_to_user_profile, workday_user)
                profile_changed_fields = get_profile_changed_fields(workday_user, demisto_user)
                terminate_date_arrived = check_if_user_should_be_terminated(workday_user)
                does_email_exist = does_user_email_exist_in_xsoar(email_to_user_profile, workday_user)

                if ((demisto_user and len(profile_changed_fields) == 0) or (not demisto_user and does_email_exist))\
                        and not terminate_date_arrived:
                    # either no change in user profile or user profile doesn't exist but the email is already used
                    # in both cases, don't create the incident
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

        last_run = {'time': last_run_time, 'synced_users': True}
    except Exception as e:
        demisto.error(f'Failed to fetch events. From Date = {from_date_time}. To Date = {to_date_time}')
        raise e

    return last_run, events


def get_all_user_profiles(batch_size=1000):
    employee_id_to_user_profile = {}
    email_to_user_profile = {}
    query_result = demisto.searchIndicators(query=f"type:\"User Profile\"").get('iocs', [])
    for user_profile in query_result:
        employee_id = user_profile.get('employeeid')
        email = user_profile.get('email')
        employee_id_to_user_profile[employee_id] = user_profile
        email_to_user_profile[email] = user_profile

    return employee_id_to_user_profile, email_to_user_profile


def get_demisto_user(employee_id_to_user_profile, workday_user):
    employee_id = workday_user.get('employeeid')
    if employee_id:
        return employee_id_to_user_profile.get(employee_id)
    return None


def does_user_email_exist_in_xsoar(email_to_user_profile, workday_user):
    email_address = workday_user.get('email')
    if email_address:
        return email_to_user_profile.get(email_address) is not None
    return False


def get_profile_changed_fields(workday_user, demisto_user):
    if not demisto_user:
        return False  # potential new hire
    profile_changed_fields = []
    for user_profile_key in workday_user.keys():
        workday_value = workday_user.get(user_profile_key)
        demisto_value = demisto_user.get('CustomFields', {}).get(user_profile_key)
        if workday_value and demisto_value and workday_value != demisto_value:
            profile_changed_fields.append(user_profile_key)

    return profile_changed_fields


def check_if_user_should_be_terminated(workday_user):
    # check if employee is active and his terminate fay or last day of work arrived
    is_term_event = False
    employment_status = str(workday_user.get(EMPLOYMENT_STATUS_EVENT_FIELD))

    if employment_status.lower() == EMPLOYEE_ACTIVE_STATUS:
        last_day_of_work = workday_user.get(LAST_DAY_OF_WORK_EVENT_FIELD)
        termination_date = workday_user.get(TERMINATION_DATE_EVENT_FIELD)
        if last_day_of_work or termination_date:
            hire_date = workday_user.get(HIRE_DATE_EVENT_FIELD)
            hire_date = datetime.strptime(hire_date, WORKDAY_DATE_FORMAT)
            today = datetime.today()
            # Check if term date is older than the latest hire date. If it is, then it is not a term, its a rehire
            # Also check with current date. If its future date, then it's not a term event
            if last_day_of_work:
                last_day_of_work = datetime.strptime(last_day_of_work, WORKDAY_DATE_FORMAT)
                is_term_event = hire_date <= last_day_of_work <= today
            elif termination_date:
                termination_date = datetime.strptime(termination_date, WORKDAY_DATE_FORMAT)
                is_term_event = hire_date <= termination_date <= today
    return is_term_event


def test_module(client, is_fetch, fetch_events_time_minutes, report_url, mapper_in):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Anything else will fail the test.
    """
    client.get_full_report(report_url)

    if is_fetch:
        fetch_incidents(
            client=client,
            last_run={},
            fetch_time=fetch_events_time_minutes,
            mapper_in=mapper_in,
            report_url=report_url
        )

    return 'ok'


def entry_to_user_profile(entry, mapper_in):
    user_profile = demisto.mapObject(entry, mapper_in, INCIDENT_TYPE)
    user_profile = convert_incident_fields_to_cli_names(user_profile)
    return user_profile


def report_to_indicators(report_entries, mapper_in):
    user_profiles = [entry_to_user_profile(e, mapper_in) for e in report_entries]
    indicators = [user_profile_to_indicator(u) for u in user_profiles]
    return indicators


def user_profile_to_indicator(user_profile):
    indicator = {
        'value': user_profile.get('email'),
        'type': 'User Profile',
        'rawJSON': user_profile
    }
    return indicator


def workday_first_run_command(client, mapper_in, report_url):
    report_data = client.get_full_report(report_url)
    indicators = report_to_indicators(report_data.get('Report_Entry'), mapper_in)
    for b in batch(indicators, batch_size=2000):
        demisto.createIndicators(b)

    last_run_time = datetime.now().strftime(WORKDAY_DATE_TIME_FORMAT)
    last_run = {'synced_users': True, 'time': last_run_time}
    # return_results("Indicators were created successfully.")
    return last_run


def main():
    command = demisto.command()
    params = demisto.params()

    is_fetch = params.get('isFetch')
    fetch_events_time_minutes = params.get('fetch_events_time_minutes')
    report_url = params.get('report_url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    mapper_in = params.get('mapper_in', DEFAULT_MAPPER_IN)
    workday_username = params.get('credentials', {}).get('identifier')
    workday_password = params.get('credentials', {}).get('password')

    demisto.debug(f'Command being called is {command}')

    client = Client(
        base_url='',  # using report_url in _http_request
        verify=verify_certificate,
        headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        proxy=proxy,
        ok_codes=(200, 204),
        auth=requests.auth.HTTPBasicAuth(workday_username, workday_password)
    )

    try:
        if command == 'test-module':
            return_results(test_module(client, is_fetch, fetch_events_time_minutes, report_url, mapper_in))

        if command == 'fetch-incidents':
            '''
                Checks if there are events are stored in the integration context.
                If yes, it gets it from there. Else, it makes a call to Workday to get a new report
                Returns the first x events (x being the fetch limit) and stores the remaining in integration context
            '''
            workday_context = demisto.getIntegrationContext()
            events = workday_context.get('events')
            report_url = params.get('report_url')

            last_run = demisto.getLastRun()
            if not last_run.get('synced_users'):
                last_run = workday_first_run_command(client, mapper_in, report_url)

            elif not events:
                # Get the events from Workday by making an API call. Last run is updated only when API call is made
                last_run, events = fetch_incidents(
                    client=client,
                    last_run=last_run,
                    fetch_time=params.get('fetch_events_time_minutes'),
                    mapper_in=mapper_in,
                    report_url=report_url
                )

            fetch_limit = int(params.get('max_fetch'))

            demisto.setLastRun(last_run)
            demisto.incidents(events[:fetch_limit])

            # Set the remaining events back to integration context
            workday_context = {'events': events[fetch_limit:]}
            demisto.setIntegrationContext(workday_context)

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command, Error: {e}. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
