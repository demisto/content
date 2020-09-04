''' IMPORTS '''
import demistomock as demisto
from CommonServerPython import *
import traceback
from email.mime.text import MIMEText
from smtplib import SMTP
import requests

''' CONSTANTS '''

WORKDAY_DATE_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
FULL_REPORT_TYPE = 'Full-Report'
DELTA_REPORT_TYPE = 'Delta-Report'
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

    try:
        # If there is no fetch time configured, it will be set to 0 and no events will be pulled
        fetch_time = int(fetch_time) if fetch_time else 0
        time_elapsed_in_minutes, last_run_time = get_time_elapsed(fetch_time, last_run)

        if fetch_time != 0 and time_elapsed_in_minutes >= fetch_time:
            from_date_time = last_run_time
            to_date_time = datetime.now().strftime(WORKDAY_DATE_TIME_FORMAT)
            if report_type == DELTA_REPORT_TYPE:
                report_data = client.get_delta_report(from_date_time, to_date_time)
            else:
                report_data = client.get_full_report()
            report_entries = report_data.get('Report_Entry')
            for entry in report_entries:
                # Set the Raw JSON to the event. Mapping will be done at the classification and mapping
                event = {"rawJSON": json.dumps(entry)}
                events.append(event)
            last_run_time = datetime.now().strftime(WORKDAY_DATE_TIME_FORMAT)
            demisto.info(f'Workday Fetch Events Completed for {report_type}. Response Time: '
                         f'{(datetime.now() - start).total_seconds()} seconds')
            send_email("Success: Workday Fetch Events completed with " + str(len(events)) + " users", " ")

        last_run = {'time': last_run_time}
    except Exception as e:
        demisto.error(f'Failed to fetch events. From Date = {from_date_time}. To Date = {to_date_time}')
        send_email("ERROR: Workday Fetch Events Failed", traceback.format_exc())
        raise e

    return last_run, events


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


def test_module(client, args):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Anything else will fail the test.
    """
    current_date_time = datetime.now().strftime(WORKDAY_DATE_TIME_FORMAT)
    if report_type == DELTA_REPORT_TYPE:
        client.get_delta_report(current_date_time, current_date_time)

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
        'test-module': test_module,
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

    # Log exceptions
    except Exception:
        return_error(f'Failed to execute {demisto.command()} command. Traceback: {traceback.format_exc()}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
