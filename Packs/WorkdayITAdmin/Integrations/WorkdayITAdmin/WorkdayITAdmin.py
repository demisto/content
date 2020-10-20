import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
''' IMPORTS '''
import traceback
from email.mime.text import MIMEText
from smtplib import SMTP
import requests
from datetime import datetime, timedelta

''' CONSTANTS '''

WORKDAY_DATE_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
FULL_REPORT_TYPE = 'Full-Report'
DELTA_REPORT_TYPE = 'Delta_Report'
READ_TIME_OUT_IN_SECONDS = 300


''' GLOBAL VARIABLES '''

report_type = demisto.params().get('report_type')
report_url = demisto.params().get('report_url')

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    # Getting Workday Full User Report with a given report URL. This uses RaaS
    def get_full_report(self):
        return self._http_request(method="GET", full_url=report_url, url_suffix=None, timeout=READ_TIME_OUT_IN_SECONDS)

    # Getting Workday Delta Report of changes that happened between from and to date.
    def get_delta_report(self, from_date, to_date):
        query_params = {
            'From_Date': from_date,
            'To_Date': to_date
        }
        return self._http_request(method="GET", full_url=report_url, url_suffix=None,
                                  params=query_params, timeout=READ_TIME_OUT_IN_SECONDS)


'''HELPER FUNCTIONS'''


def convert_incident_fields_to_cli_names(data):
    converted_data = {}
    for k, v in data.items():
        key_machine_name = k.lower().replace(' ', '')
        converted_data[key_machine_name] = v
    return converted_data


def send_email(subject, body=''):
    params = demisto.params()
    smtp_server_host = params.get('smtp_server')
    smtp_server_port = params.get('smtp_port')
    from_email = params.get('from_email')
    to_email = params.get('email_notification_ids')

    # Send email if smtp details are configured
    if smtp_server_host and smtp_server_port and from_email and to_email:
        SERVER = SMTP(smtp_server_host, int(smtp_server_port), local_hostname=smtp_server_host)
        SERVER.ehlo()
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email
        SERVER.sendmail(from_email, to_email.split(','), msg.as_string())
        SERVER.quit()


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


def make_user_rehired(workday_user, event):
    if workday_user.get('email') in ['qjipjorrulac@paloaltonetworks.com', 'kgripullon@paloaltonetworks.com']:
        workday_user['prehireflag'] = True
        workday_user['rehiredemployee'] = 'Yes'
        event['Hide_from_GAL'] = True
        event['Rehired_Employee'] = 'Yes'


'''COMMAND FUNCTIONS'''


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
            if report_type == DELTA_REPORT_TYPE:
                report_data = client.get_delta_report(from_date_time, to_date_time)
            else:
                report_data = client.get_full_report()
            report_entries = report_data.get('Report_Entry')
            for entry in report_entries:
                workday_user = demisto.mapObject(entry, 'IAM Sync User - Workday', 'IAM-Sync-User')
                workday_user = convert_incident_fields_to_cli_names(workday_user)
                # make_user_rehired(workday_user, entry)  # todo: remove
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
            demisto.info('Workday Fetch Events Completed for {}. Response Time: {} seconds'.format(report_type,
                                                                                                   (datetime.now() - start).total_seconds()))
            send_email("Success: Workday Fetch Events completed with " + str(len(events)) + " users", " ")

        last_run = {'time': last_run_time}
    except Exception as e:
        demisto.error(f'Failed to fetch events. From Date = {from_date_time}. To Date = {to_date_time}')
        send_email("ERROR: Workday Fetch Events Failed", traceback.format_exc())
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


def get_delta_report_command(client, args):
    from_date = args.get('from_date')
    to_date = args.get('to_date')

    raw_response = client.get_delta_report(from_date, to_date)
    readable_output = tableToMarkdown("Workday Report", raw_response.get('Report_Entry'))
    return (
        readable_output,
        {},
        raw_response
    )


def get_full_report_command(client, args):
    raw_response = client.get_full_report()
    readable_output = tableToMarkdown("Workday Report", raw_response.get('Report_Entry'))
    return (
        readable_output,
        {},
        raw_response
    )


def test_module(client, args, params):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Anything else will fail the test.
    """
    current_date_time = datetime.now().strftime(WORKDAY_DATE_TIME_FORMAT)
    if report_type == FULL_REPORT_TYPE:
        client.get_full_report()

    if params.get('isFetch'):
        last_run, events = fetch_incidents(
            client=client,
            last_run={},
            fetch_time=params.get('fetch_events_time_minutes')
        )

    return 'ok', None, None


def reset_integration_context_command(client, args):
    integration_context = demisto.getIntegrationContext()
    integration_context_key = args.get('integration_context_key')
    if integration_context_key:
        if integration_context_key in integration_context:
            del integration_context[integration_context_key]
    else:
        integration_context = {}

    demisto.setIntegrationContext(integration_context)
    readable_output = f'Integration Context Reset Successfully. Remaining keys in context: {integration_context.keys()}'
    return readable_output, None, None


def get_integration_context_command(client, args):
    integration_context = demisto.getIntegrationContext()
    readable_output = tableToMarkdown("Workday Integration Context", integration_context)
    return readable_output, None, None


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
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    workday_username = params.get('credentials', {}).get('identifier')
    workday_password = params.get('credentials', {}).get('password')

    LOG(f'Command being called is {command}')

    commands = {
        'workday-get-full-user-report': get_full_report_command,
        'workday-get-delta-user-report': get_delta_report_command,
        'workday-reset-integration-context': reset_integration_context_command,
        'workday-get-integration-context': get_integration_context_command
    }

    client = Client(
        base_url=None,
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
        '''EXECUTION CODE'''
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
        if command == 'test-module':
            human_readable, outputs, raw_response = test_module(client, demisto.args(), demisto.params())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
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

    # Log exceptions
    except Exception as e:
        demisto.error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
