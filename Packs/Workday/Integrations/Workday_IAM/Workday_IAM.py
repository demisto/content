import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''
import traceback
import requests
from datetime import datetime

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
BATCH_SIZE = 2000


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


def is_user_profile_unchanged(demisto_user, workday_user):
    profile_changed_fields = get_profile_changed_fields(demisto_user, workday_user)
    return (demisto_user and len(profile_changed_fields) == 0), profile_changed_fields


def fetch_samples(client, mapper_in, report_url):
    """
    This function returns a list of (at most) five sample events (used for classification and mapping only).

    Args:
        client: Workday client
        mapper_in: Incoming mapper's name
        report_url: The report full URL

    Returns:
        events: Incidents/events that will be used as samples for classification and mapping.
    """
    events = []
    num_of_samples = 5
    try:
        report_data = client.get_full_report(report_url)
        report_entries = report_data.get('Report_Entry')
        num_of_samples = min(num_of_samples, len(report_entries))
        report_entries = report_entries[:num_of_samples]

        for entry in report_entries:
            workday_user = demisto.mapObject(entry, mapper_in, INCIDENT_TYPE)
            workday_user = convert_incident_fields_to_cli_names(workday_user)
            entry['UserProfile'] = workday_user
            event = {
                "name": f'{workday_user.get("givenname")} {workday_user.get("surname")}',
                "rawJSON": json.dumps(entry),
                "details": 'This is a sample event.'
            }
            events.append(event)
    except Exception as e:
        demisto.error('Failed to fetch events. Reason: ' + str(e))
        raise e

    return events


def fetch_incidents(client, mapper_in, report_url):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client: Workday client
        mapper_in: Incoming mapper's name
        report_url: The report full URL.

    Returns:
        events: Incidents/Events that will be created in Cortex XSOAR
    """
    events = []
    try:
        employee_id_to_user_profile, email_to_user_profile = get_all_user_profiles()

        report_data = client.get_full_report(report_url)
        report_entries = report_data.get('Report_Entry')
        for entry in report_entries:
            workday_user = demisto.mapObject(entry, mapper_in, INCIDENT_TYPE)
            workday_user = convert_incident_fields_to_cli_names(workday_user)

            demisto_user = get_demisto_user(employee_id_to_user_profile, workday_user)
            user_profile_unchanged, changed_fields = is_user_profile_unchanged(demisto_user, workday_user)
            found_potential_termination = detect_potential_termination(demisto_user, workday_user)
            does_email_exist = does_user_email_exist_in_xsoar(email_to_user_profile, workday_user)

            if user_profile_unchanged or (not demisto_user and does_email_exist) \
                    and not found_potential_termination:
                # either no change in user profile or user profile doesn't exist but the email is already used
                # in both cases, don't create the incident
                continue

            entry['UserProfile'] = workday_user
            event = {
                "name": f'{workday_user.get("givenname")} {workday_user.get("surname")}',
                "rawJSON": json.dumps(entry),
                "details": 'Profile changed. Changed fields: ' + str(changed_fields)
            }
            events.append(event)
    except Exception as e:
        demisto.error('Failed to fetch events. Reason: ' + str(e))
        raise e

    return events


def get_all_user_profiles():
    query = 'type:\"User Profile\"'
    employee_id_to_user_profile = {}
    email_to_user_profile = {}

    def handle_batch(user_profiles):
        for user_profile in user_profiles:
            user_profile = user_profile.get('CustomFields', {})
            employee_id = user_profile.get('employeeid')
            email = user_profile.get('email')
            employee_id_to_user_profile[employee_id] = user_profile
            email_to_user_profile[email] = user_profile

    query_result = demisto.searchIndicators(query=query, size=BATCH_SIZE)
    handle_batch(query_result.get('iocs', []))

    while query_result.get('searchAfter') is not None:
        query_result = demisto.searchIndicators(query=query, size=BATCH_SIZE,
                                                searchAfter=query_result.get('searchAfter'))
        handle_batch(query_result.get('iocs', []))

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


def get_profile_changed_fields(demisto_user, workday_user):
    if not demisto_user:
        return []  # potential new hire
    profile_changed_fields = []

    for field, workday_value in workday_user.items():
        if (workday_value and not demisto_user.get(field)) or workday_value != demisto_user.get(field):
            profile_changed_fields.append(field)

    return profile_changed_fields


def detect_potential_termination(demisto_user, workday_user):
    if not demisto_user or not workday_user:
        return False
    # check if employee is active and his terminate day or last day of work arrived
    is_term_event = False
    employment_status = str(demisto_user.get(EMPLOYMENT_STATUS_EVENT_FIELD))

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


def test_module(client, is_fetch, report_url, mapper_in):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Anything else will fail the test.
    """
    client.get_full_report(report_url)

    if is_fetch:
        fetch_incidents(
            client=client,
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
    raw_json = user_profile.copy()
    raw_json['value'] = user_profile.get('email')
    raw_json['type'] = 'User Profile'
    indicator = {
        'value': user_profile.get('email'),
        'type': 'User Profile',
        'rawJSON': raw_json,
        'fields': user_profile
    }
    return indicator


def workday_first_run_command(client, mapper_in, report_url):
    report_data = client.get_full_report(report_url)
    indicators = report_to_indicators(report_data.get('Report_Entry'), mapper_in)
    for b in batch(indicators, batch_size=BATCH_SIZE):
        demisto.createIndicators(b)
    # return_results("Indicators were created successfully.")


def main():
    command = demisto.command()
    params = demisto.params()

    is_fetch = params.get('isFetch')
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
            return_results(test_module(client, is_fetch, report_url, mapper_in))

        if command == 'fetch-incidents':
            '''
                Checks if there are events are stored in the integration context.
                If yes, it gets it from there. Else, it makes a call to Workday to get a new report
                Returns the first x events (x being the fetch limit) and stores the remaining in integration context
            '''
            last_run = demisto.getLastRun()
            events = last_run.get('events', [])
            report_url = params.get('report_url')

            if params.get('fetch_samples'):
                sample_events = fetch_samples(
                    client=client,
                    mapper_in=mapper_in,
                    report_url=report_url
                )
                demisto.incidents(sample_events)

            else:
                if not last_run.get('synced_users') and params.get('first_run'):
                    workday_first_run_command(client, mapper_in, report_url)
                elif not events:
                    # Get the events from Workday by making an API call. Last run is updated only when API call is made
                    events = fetch_incidents(
                        client=client,
                        mapper_in=mapper_in,
                        report_url=report_url
                    )

                fetch_limit = int(params.get('max_fetch'))

                demisto.incidents(events[:fetch_limit])
                demisto.setLastRun({'synced_users': True, 'events': events[fetch_limit:]})

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command, Error: {e}. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
