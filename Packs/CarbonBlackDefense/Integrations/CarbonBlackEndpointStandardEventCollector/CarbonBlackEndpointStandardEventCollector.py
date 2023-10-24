import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
from threading import Thread

''' CONSTANTS '''

# Constants used in last_run
LAST_ALERT_TIME = 'last_time'
LAST_ALERT_IDS = 'last_alert_ids'
LAST_AUDIT_IDS = 'last_audit_logs_ids'

# Constants used in fetch-events
MAX_ALERTS = 100000
MAX_AUDITS = 25000

# Constants used by Response Objects
ALERT_TIMESTAMP = 'backend_timestamp'
AUDIT_TIMESTAMP = 'eventTime'
ALERT_ID = 'id'
AUDIT_ID = 'eventId'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'

''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Carbon Black Endpoint Standard Event Collector client class for fetching alerts and audit logs
    """
    def __init__(self, url: str, proxy: bool, insecure: bool, credentials: dict, org_key: str, max_alerts: int,
                 max_audit_logs: int):
        api_id = credentials.get('username')
        api_secret_key = credentials.get('password')
        auth_headers = {'X-Auth-Token': f'{api_secret_key}/{api_id}', 'Content-Type': 'application/json'}
        self.org_key = org_key
        self.max_alerts = max_alerts
        self.max_audit_logs = max_audit_logs
        super().__init__(
            base_url=url,
            verify=not insecure,
            proxy=proxy,
            headers=auth_headers
        )
        # audit_client to use its own session for thread safe behavior
        self.audit_client: BaseClient = BaseClient(
            base_url=url,
            verify=not insecure,
            headers=auth_headers
        )

    def get_alerts(self, start_time: str, start: int|str, max_rows: int|str):
        body = {
            "time_range": {
                "start": start_time,
                "end": datetime.now().strftime(DATE_FORMAT)
            },
            "start": start,
            "rows": max_rows,
            "sort": [
                {
                    "field": "backend_timestamp",
                    "order": "ASC"
                }
            ]
        }
        return self._http_request(method='POST', url_suffix=f'api/alerts/v7/orgs/{self.org_key}/alerts/_search', data=body)

    def get_audit_logs(self):
        return self.audit_client._http_request(method='GET', url_suffix='integrationServices/v3/auditlogs')

''' HELPER FUNCTIONS '''

def is_audit_interval(run, interval):
    # TODO: finish implementation
    return True

def get_alerts_and_audit_logs(client: Client, start_time: str, add_audit_logs: bool, max_rows: int | str) -> (list, list):
    """
    Fetches alerts and audit logs from CarbonBlack server using multi-threading
    """
    audit_logs = []
    t_alerts = Thread(target=client.get_alerts, args=(start_time, 1, max_rows))
    t_alerts.start()
    if add_audit_logs:
        t_audit_logs = Thread(target=client.get_audit_logs)
        t_audit_logs.start()
        audit_logs = t_audit_logs.join()
    alerts = t_alerts.join()
    return alerts, audit_logs


def update_last_run(last_run, alerts, audit_logs):
    """
    Update the last run object with the latest timestamp and IDs fetched
    """
    if alerts:
        last_run[LAST_ALERT_TIME] = last_alert_time = alerts[-1][ALERT_TIMESTAMP]
        last_run[LAST_ALERT_IDS] = [alert[ALERT_ID] for alert in alerts[::-1]
                                    if not stop_for_different_time(alert[ALERT_TIMESTAMP], last_alert_time)]
    if audit_logs:
        last_audit_time = audit_logs[:-1]
        last_run[LAST_AUDIT_IDS] = [audit[AUDIT_ID] for audit in audit_logs[::-1]
                                    if not stop_for_different_time(audit[AUDIT_TIMESTAMP], last_audit_time)]
    return last_run

def stop_for_different_time(first_time: str, second_time: str):
    if first_time != second_time:
        raise StopIteration(f"Time {first_time} is different than {second_time}")

def dedupe_events(alerts, audit_logs, max_audit_logs, last_run):
    """
    Dedupe alerts and audit logs based on IDs fetched in the last run
    """
    if alerts and last_run.get(LAST_ALERT_TIME) == alerts[0][ALERT_TIMESTAMP]:
        last_run_ids = set(last_run[LAST_ALERT_IDS])
        alerts = filter(lambda alert: alert[ALERT_ID] not in last_run_ids, alerts)
    if audit_logs and last_run.get(LAST_AUDIT_IDS):
        last_run_ids = set(last_run[LAST_AUDIT_IDS])
        audit_logs = filter(lambda audit: audit[AUDIT_ID] not in last_run_ids, audit_logs)
    return alerts, audit_logs[:max_audit_logs]

''' COMMAND FUNCTIONS '''


def get_events(client: Client, last_run: dict, max_alerts: int, max_audit_logs: int, add_audit_logs: bool,
               audit_fetch_interval: str):
    add_audit_logs = add_audit_logs and is_audit_interval(last_run, audit_fetch_interval)
    alerts, audit_logs = get_alerts_and_audit_logs(
        client=client,
        start_time=last_run.get('LAST_TIME'),
        max_rows=max_alerts,
        add_audit_logs=add_audit_logs,
    )
    alerts, audit_logs = dedupe_events(alerts, audit_logs, max_audit_logs, last_run)
    last_run = update_last_run(last_run, alerts, audit_logs)
    events = alerts + audit_logs
    return events, last_run


def test_module(client: Client) -> str:
    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

''' MAIN FUNCTION '''

def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    vendor, product = params.get('vendor', 'vmware_carbon_black'), params.get('product', 'cloud')
    support_multithreading()  # audit_logs will be fetched async
    demisto.debug(f'Command being called is {command}')
    try:
        last_run = demisto.getLastRun()
        add_audit_logs = params.get('add_audit_logs')
        max_alerts = min(arg_to_number(params.get('max_alerts') or MAX_ALERTS), MAX_ALERTS)
        max_audit_logs = min(arg_to_number(params.get('max_alerts') or MAX_ALERTS), MAX_AUDITS)
        audit_fetch_interval = params.get('audit_fetch_interval')
        client = Client(
            url=params.get('url'),
            proxy=params.get('proxy'),
            insecure=params.get('insecure'),
            credentials=params.get('credentials', {}),
            org_key=params.get('org_key'),
            max_alerts=max_alerts,
            max_audit_logs=max_audit_logs,
        )
        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-events':
            demisto.debug(f'Sending request with last run {last_run}')
            events, new_last_run = get_events(
                client=client,
                last_run=last_run,
                max_alerts=max_alerts,
                max_audit_logs=max_audit_logs,
                add_audit_logs=add_audit_logs,
                audit_fetch_interval=audit_fetch_interval,
            )
            demisto.debug(f'sending {len(events)} to xsiam')
            send_events_to_xsiam(events=events, vendor=vendor, product=product)
            demisto.debug(f'Handled {len(events)} total events seconds')
            demisto.setLastRun(new_last_run)
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
