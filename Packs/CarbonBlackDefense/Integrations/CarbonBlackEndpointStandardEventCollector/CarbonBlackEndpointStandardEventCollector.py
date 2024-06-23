import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa
import concurrent.futures

''' CONSTANTS '''

# Constants used in last_run
LAST_ALERT_TIME = 'last_time'
LAST_AUDIT_TIME = 'last_audit_time'
LAST_ALERT_IDS = 'last_alert_ids'

# Constants used in fetch-events
MAX_ALERTS_IN_PAGE = 10000
MAX_FETCH_LOOP = 10
MAX_ALERTS = MAX_FETCH_LOOP * MAX_ALERTS_IN_PAGE
MAX_AUDITS = 25000

# Constants used by Response Objects
ALERT_TIMESTAMP = 'backend_timestamp'
ALERT_DETECTION_TIMESTAMP = 'detection_timestamp'
AUDIT_TIMESTAMP = 'eventTime'
ALERT_ID = 'id'
AUDIT_ID = 'eventId'

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.000Z'

''' CLIENT CLASS '''


class Client(BaseClient):  # pragma: no cover
    """
    Carbon Black Endpoint Standard Event Collector client class for fetching alerts and audit logs
    """

    def __init__(self, url: str, org_key: str, credentials: dict, proxy: bool = False, insecure: bool = False,
                 max_alerts: int | None = None, max_audit_logs: int | None = None):
        api_id = credentials.get('identifier')
        api_secret_key = credentials.get('password')
        auth_headers = {'X-Auth-Token': f'{api_secret_key}/{api_id}', 'Content-Type': 'application/json'}
        self.org_key = org_key
        self.max_alerts = max_alerts or MAX_ALERTS
        self.max_audit_logs = max_audit_logs or MAX_AUDITS
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

    def get_alerts(self, start_time: str, start: int | str, max_rows: int | str):
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
        res = self._http_request(method='POST', url_suffix=f'api/alerts/v7/orgs/{self.org_key}/alerts/_search', json_data=body)
        if res and 'results' in res:
            return res['results']
        return res

    def get_audit_logs(self):
        res = self.audit_client._http_request(method='GET', url_suffix='integrationServices/v3/auditlogs')
        if res and 'notifications' in res:
            return res['notifications']
        return res


''' HELPER FUNCTIONS '''


def get_alerts_and_audit_logs(client: Client, add_audit_logs: bool, last_run: dict):
    """
    Fetches alerts and audit logs from CarbonBlack server using multi-threading
    """
    alerts = []
    audit_logs = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        if add_audit_logs:
            audit_logs_future = executor.submit(get_audit_logs_to_limit, client)
        alerts, last_run = get_alerts_to_limit(client, last_run)
        if add_audit_logs:
            try:
                audit_logs = prepare_audit_logs_result(
                    audit_logs_future.result(), last_run.get(LAST_AUDIT_TIME))
            except Exception as e:
                demisto.error(f'Failed getting audit logs. Error: {e}')
    return alerts, audit_logs


def get_alerts_to_limit(client: Client, last_run: dict):
    alerts: list = []
    try:
        for _ in range(MAX_FETCH_LOOP):
            # Fetch next batch of alerts
            start_time = last_run.get(LAST_ALERT_TIME)
            max_rows = min(client.max_alerts - len(alerts), MAX_ALERTS_IN_PAGE)
            next_batch_alerts = client.get_alerts(start_time, 1, max_rows)  # type: ignore
            next_batch_alerts = prepare_alerts_result(next_batch_alerts, last_run)
            if not next_batch_alerts:
                break
            last_run = update_last_run(last_run, alerts=next_batch_alerts)
            alerts.extend(next_batch_alerts)
            if len(alerts) >= client.max_alerts:
                break
    except Exception as e:
        demisto.error(f'Encountered error while fetching alerts - {e}')
    return alerts[:client.max_alerts], last_run


def get_audit_logs_to_limit(client: Client):
    audit_logs: list[dict] = []
    for _ in range(MAX_FETCH_LOOP):
        next_batch_audit_logs = client.get_audit_logs()
        if not next_batch_audit_logs:
            break
        audit_logs.extend(next_batch_audit_logs)
        if len(audit_logs) >= client.max_audit_logs:
            break
    return audit_logs[:client.max_audit_logs]


def update_last_run(last_run, alerts=None, audit_logs=None):
    """
    Update the last run object with the latest timestamp and IDs fetched
    """
    if alerts:
        last_run[LAST_ALERT_TIME] = last_alert_time = alerts[-1][ALERT_TIMESTAMP]
        last_run[LAST_ALERT_IDS] = [alert[ALERT_ID] for alert in alerts if alert[ALERT_TIMESTAMP] == last_alert_time]
    if audit_logs:
        last_run[LAST_AUDIT_TIME] = audit_logs[-1]['_time']
    return last_run


def prepare_audit_logs_result(audit_logs, last_audit_time):
    """
    Filters audit logs to return only new logs since the last run, and add _time field.
    """
    if not audit_logs:
        return audit_logs

    new_audits = []
    for audit in audit_logs:
        audit_time = timestamp_to_datestring(audit[AUDIT_TIMESTAMP], is_utc=True)
        if not last_audit_time or last_audit_time <= audit_time:
            audit['_time'] = audit_time
            new_audits.append(audit)
    audit_logs = new_audits
    return audit_logs


def prepare_alerts_result(alerts, last_run):  # pragma: no cover
    """
    Filters alerts to return only new alerts since the last run, and add _time field.
    """
    if not alerts:
        return alerts

    last_run_ids = set(last_run[LAST_ALERT_IDS])
    new_alerts = []
    for alert in alerts:
        if alert[ALERT_ID] not in last_run_ids:
            alert['_time'] = alert[ALERT_DETECTION_TIMESTAMP]
            new_alerts.append(alert)
    alerts = new_alerts
    return alerts


''' COMMAND FUNCTIONS '''


def get_events(client: Client, last_run: dict, add_audit_logs: bool):
    alerts, audit_logs = get_alerts_and_audit_logs(
        client=client,
        last_run=last_run,
        add_audit_logs=add_audit_logs,
    )
    last_run = update_last_run(last_run, alerts, audit_logs)
    events = alerts + audit_logs
    return events, last_run


def test_module(client: Client) -> str:  # pragma: no cover
    client.get_alerts(datetime.now().strftime(DATE_FORMAT), 1, 1)
    return 'ok'


''' MAIN FUNCTION '''


def init_last_run(last_run: dict) -> dict:
    """ Initializes the last run for first run """
    if not last_run:
        last_run = {
            LAST_ALERT_TIME: datetime.now().strftime(DATE_FORMAT),
            LAST_ALERT_IDS: [],
            LAST_AUDIT_TIME: None,
        }
    return last_run


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    vendor, product = params.get('vendor', 'vmware_carbon_black'), params.get('product', 'cloud')
    support_multithreading()  # audit_logs will be fetched on a separate thread
    demisto.debug(f'Command being called is {command}')
    try:
        last_run = init_last_run(demisto.getLastRun())
        should_push_events = (command == 'fetch-events') or argToBoolean(args.get('should_push_events', False))
        add_audit_logs = params.get('add_audit_logs')
        max_alerts = min(arg_to_number(params.get('max_alerts') or MAX_ALERTS), MAX_ALERTS)  # type: ignore
        max_audit_logs = min(arg_to_number(params.get('max_audit_logs') or MAX_AUDITS), MAX_AUDITS)  # type: ignore

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

        elif command in ('fetch-events', 'carbonblack-endpoint-standard-get-events'):
            demisto.debug(f'Sending request with last run {last_run}')
            events, new_last_run = get_events(
                client=client,
                last_run=last_run,
                add_audit_logs=add_audit_logs,
            )
            demisto.debug(f'sending {len(events)} to xsiam')
            if should_push_events:
                send_events_to_xsiam(events=events, vendor=vendor, product=product)
            demisto.debug(f'Handled {len(events)} total events')
            demisto.setLastRun(new_last_run)
        else:
            raise NotImplementedError(f'{command} not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
