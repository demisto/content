import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time
from typing import Dict

import urllib3

urllib3.disable_warnings()

''' CONSTANTS '''

MAX_EVENTS_PER_REQUEST = 100
VENDOR = 'tenable'
PRODUCT = 'io'
NUM_ASSETS = 5000
DATE_FORMAT = '%Y-%m-%d'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

        This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
        Handles the token retrieval.

        :param base_url (str): Saas Security server url.
        :param client_id (str): client ID.
        :param client_secret (str): client secret.
        :param verify (bool): specifies whether to verify the SSL certificate or not.
        :param proxy (bool): specifies if to use XSOAR proxy settings.
        """

    @staticmethod
    def add_query(query, param_to_add):
        if query:
            return f'{query}&{param_to_add}'
        return f'?{param_to_add}'

    def get_audit_logs_request(self, from_date: str = None, to_date: str = None, actor_id: str = None,
                               target_id: str = None, limit: int = None):
        """

        Args:
            limit: limit number of audit logs to get.
            from_date: date to fetch audit logs from.
            to_date: date which until to fetch audit logs.
            actor_id: fetch audit logs with matching actor id.
            target_id:fetch audit logs with matching target id.

        Returns:
            audit logs fetched from the API.
        """
        query = ''
        if from_date:
            query = self.add_query(query, f'f=date.gt:{from_date}')
        if to_date:
            query = self.add_query(query, f'f=date.lt:{to_date}')
        if actor_id:
            query = self.add_query(query, f'f=actor_id.match:{actor_id}')
        if target_id:
            query = self.add_query(query, f'f=target_id.match:{target_id}')
        if limit:
            query = self.add_query(query, f'limit={limit}')
        else:
            query = self.add_query(query, 'limit=5000')
        res = self._http_request(method='GET', url_suffix=f'/audit-log/v1/events{query}', headers=self._headers)
        return res.get('events', [])

    def get_export_uuid(self, num_assets: int, last_found: Optional[float], severity: List[str]):
        """

        Args:
            num_assets: number of assets used to chunk the vulnerabilities.
            last_found: vulnerabilities that were last found between the specified date (in Unix time) and now.
            severity: severity of the vulnerabilities to include in the export.

        Returns: The UUID of the vulnerabilities export job.

        """
        payload: Dict[str, Union[Any]] = {
            "filters":
                {
                    "severity": severity
                },
            "num_assets": num_assets
        }
        if last_found:
            payload['filters'].update({"last_found": last_found})

        res = self._http_request(method='POST', url_suffix='/vulns/export', headers=self._headers, json_data=payload)
        return res.get('export_uuid', '')

    def get_export_status(self, export_uuid: str):
        """

        Args:
            export_uuid: The UUID of the vulnerabilities export job.

        Returns: The status of the job, and number of chunks available if succeeded.

        """
        res = self._http_request(method='GET', url_suffix=f'/vulns/export/{export_uuid}/status',
                                 headers=self._headers)
        status = res.get('status')
        chunks_available = res.get('chunks_available', [])
        return status, chunks_available

    def download_vulnerabilities_chunk(self, export_uuid: str, chunk_id: int):
        """

        Args:
            export_uuid: The UUID of the vulnerabilities export job.
            chunk_id: The ID of the chunk you want to export.

        Returns: Chunk of vulnerabilities from API.

        """
        return self._http_request(method='GET', url_suffix=f'/vulns/export/{export_uuid}/chunks/{chunk_id}',
                                  headers=self._headers)


''' HELPER FUNCTIONS '''


def try_get_chunks(client: Client, export_uuid: str):
    """
    If job has succeeded (status FINISHED) get all information from all chunks available.
    Args:
        client: Client class object.
        export_uuid: The UUID of the vulnerabilities export job.

    Returns: All information from all chunks available.

    """
    vulnerabilities = []
    status, chunks_available = client.get_export_status(export_uuid=export_uuid)
    demisto.info(f'Report status is {status}, and number of available chunks is {chunks_available}')
    if status == 'FINISHED':
        for chunk_id in chunks_available:
            vulnerabilities.extend(client.download_vulnerabilities_chunk(export_uuid=export_uuid, chunk_id=chunk_id))
    return vulnerabilities, status


def generate_export_uuid(client: Client, first_fetch: datetime, last_run: Dict[str, str | float | None],
                         severity: List[str]):
    """
    Generate a job export uuid in order to fetch vulnerabilities.

    Args:
        client: Client class object.
        first_fetch: time to first fetch from.
        last_run: last run object.
        severity: severity of the vulnerabilities to include in the export.

    """
    demisto.info("Getting export uuid for report.")
    last_fetch = last_run.get('last_fetch_vuln')
    last_found: float = time.mktime(
        first_fetch.timetuple()) if not last_fetch and first_fetch else last_fetch  # type: ignore
    export_uuid = client.get_export_uuid(num_assets=NUM_ASSETS, last_found=last_found, severity=severity)

    next_run_vuln = time.mktime(datetime.now(tz=timezone.utc).timetuple())
    demisto.info(f'export uuid is {export_uuid}')
    last_run.update({'last_found_use': last_found, 'last_fetch_vuln': next_run_vuln, 'export_uuid': export_uuid})


def run_vulnerabilities_fetch(last_run, first_fetch: datetime,
                              vuln_fetch_interval: int):
    """

    Args:
        last_run: last run object.
        first_fetch: time to first fetch from.
        vuln_fetch_interval: vulnerabilities fetch interval.

    Returns: True if fetch vulnerabilities interval time has passed since last time that fetch run.

    """
    if not last_run.get('last_fetch_vuln'):
        time_to_check: float = time.mktime(first_fetch.timetuple())
    else:
        time_to_check = last_run['last_fetch_vuln']
    return time.time() - time_to_check > vuln_fetch_interval and not last_run.get('export_uuid')


def insert_type_to_logs(audit_logs: list, vulnerabilities: list):
    """
    In order for the user to get easy access to events in the system based on their type, the type of the event is added
    manually.

    Args:
        audit_logs: audit logs to add xsiam type to.
        vulnerabilities: vulnerabilities to add xsiam type to.

    """
    for log in audit_logs:
        log.update({'xsiam_type': 'audit_log'})
    for log in vulnerabilities:
        log.update({'xsiam_type': 'vulnerability'})


def call_send_events_to_xsiam(events, vulnerabilities, should_push_events=False):
    """Enhanced and sends events and vulnerabilities to XSIAM"""
    insert_type_to_logs(audit_logs=events, vulnerabilities=vulnerabilities)
    if should_push_events:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
        send_events_to_xsiam(vulnerabilities, vendor=VENDOR, product=PRODUCT)


''' COMMAND FUNCTIONS '''


def get_audit_logs_command(client: Client, from_date: Optional[str] = None, to_date: Optional[str] = None,
                           actor_id: Optional[str] = None, target_id: Optional[str] = None,
                           limit: Optional[int] = None):
    """

    Args:
        client: Client class object.
        from_date: date to fetch audit logs from.
        to_date: date which until to fetch audit logs.
        actor_id: fetch audit logs with matching actor id.
        target_id:fetch audit logs with matching target id.
        limit: limit number of audit logs to get.

    Returns: CommandResults of audit logs from API.

    """
    audit_logs = client.get_audit_logs_request(from_date=from_date,
                                               to_date=to_date,
                                               actor_id=actor_id,
                                               target_id=target_id,
                                               limit=limit)

    readable_output = tableToMarkdown('Audit Logs List:', audit_logs,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    results = CommandResults(readable_output=readable_output,
                             raw_response=audit_logs)
    return results, audit_logs


@polling_function('tenable-get-vulnerabilities', requires_polling_arg=False)
def get_vulnerabilities_command(args: Dict[str, Any], client: Client) -> CommandResults | PollResult:
    """
    Getting vulnerabilities from Tenable. Polling as long as the report is not ready (status FINISHED or failed)
    Args:
        args: arguments from user (last_found, severity and num_assets)
        client: Client class object.

    Returns: Vulnerabilities from API.

    """
    vulnerabilities = []
    last_found = arg_to_number(args.get('last_found'))
    num_assets = arg_to_number(args.get('num_assets')) or 5000
    severity = argToList(args.get('severity'))
    export_uuid = args.get('export_uuid')
    if not export_uuid:
        export_uuid = client.get_export_uuid(num_assets=num_assets, last_found=last_found,
                                             severity=severity)  # type: ignore

    status, chunks_available = client.get_export_status(export_uuid=export_uuid)
    if status == 'FINISHED':
        for chunk_id in chunks_available:
            vulnerabilities.extend(client.download_vulnerabilities_chunk(export_uuid=export_uuid, chunk_id=chunk_id))
        readable_output = tableToMarkdown('Vulnerabilities List:', vulnerabilities,
                                          removeNull=True,
                                          headerTransform=string_to_table_header)

        results = CommandResults(readable_output=readable_output,
                                 raw_response=vulnerabilities)
        return PollResult(response=results)
    elif status in ['CANCELLED', 'ERROR']:
        results = CommandResults(readable_output='Export job failed',
                                 entry_type=entryTypes['error'])
        return PollResult(response=results)
    else:
        results = CommandResults(readable_output='Export job failed',
                                 entry_type=entryTypes['error'])
        return PollResult(continue_to_poll=True, args_for_next_run={"export_uuid": export_uuid, **args},
                          response=results)


''' FETCH COMMANDS '''


def fetch_vulnerabilities(client: Client, last_run: dict, severity: List[str]):
    """
    Fetches vulnerabilities if job has succeeded.
    Args:
        last_run: last run object.
        severity: severity of the vulnerabilities to include in the export.
        client: Client class object.

    Returns:
        Vulnerabilities fetched from the API.
    """
    vulnerabilities = []
    export_uuid = last_run.get('export_uuid')
    last_found_use = last_run.get('last_found_use')  # last run fetch time
    if export_uuid:
        demisto.info(f'Got export uuid from API {export_uuid}')
        vulnerabilities, status = try_get_chunks(client=client, export_uuid=export_uuid)
        # set params for next run
        if status == 'FINISHED':
            last_run.update({'export_uuid': None})
        elif status in ['CANCELLED', 'ERROR'] and last_found_use:
            export_uuid = client.get_export_uuid(num_assets=5000, last_found=last_found_use, severity=severity)
            last_run.update({'export_uuid': export_uuid})

    demisto.info(f'Done fetching {len(vulnerabilities)} vulnerabilities, {last_run=}.')
    return vulnerabilities


def fetch_events_command(client: Client, first_fetch: datetime, last_run: dict, limit: int = 1000):
    """
    Fetches audit logs.
    Args:
        client: Client class object.
        first_fetch: time to first fetch from.
        last_run: last run object.
        limit: number of audit logs to max fetch.

    Returns: vulnerabilities, audit logs and updated last run object

    """

    last_fetch = last_run.get('last_fetch_time')
    last_index_fetched = last_run.get('index_audit_logs', 0)
    if not last_fetch:
        start_date = first_fetch.strftime(DATE_FORMAT)
    else:
        start_date = last_fetch  # type: ignore

    audit_logs: List[Dict] = []
    audit_logs_from_api = client.get_audit_logs_request(from_date=start_date)

    if last_index_fetched < len(audit_logs_from_api):
        audit_logs.extend(audit_logs_from_api[last_index_fetched:last_index_fetched + limit])

    next_run: str = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)
    last_run.update({'index_audit_logs': len(audit_logs) + last_index_fetched if audit_logs else last_index_fetched,
                     'last_fetch_time': next_run})
    demisto.info(f'Done fetching {len(audit_logs)} audit logs, Setting {last_run=}.')
    return audit_logs, last_run


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.get_audit_logs_request(limit=10)
    return 'ok'


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    """
    args = demisto.args()
    command = demisto.command()
    params = demisto.params()
    events = []
    vulnerabilities: list = []

    access_key = params.get('credentials', {}).get('identifier', '')
    secret_key = params.get('credentials', {}).get('password', '')
    url = params.get('url')
    vuln_fetch_interval = arg_to_number(params.get('vuln_fetch_interval', 240)) * 60  # type: ignore
    severity = argToList(params.get('severity'))

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000

    # transform minutes to seconds
    first_fetch: datetime = arg_to_datetime(params.get('first_fetch', '3 days'))  # type: ignore

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
                   "Accept": "application/json"}
        client = Client(
            base_url=url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'tenable-get-audit-logs':
            results, events = get_audit_logs_command(client,
                                                     from_date=args.get('from_date'),
                                                     to_date=args.get('to_date'),
                                                     actor_id=args.get('actor_id'),
                                                     target_id=args.get('target_id'),
                                                     limit=args.get('limit'))
            return_results(results)

            call_send_events_to_xsiam(events=events, vulnerabilities=vulnerabilities,
                                      should_push_events=argToBoolean(args.get('should_push_events', 'true')))

        elif command == 'tenable-get-vulnerabilities':
            results = get_vulnerabilities_command(args, client)
            if isinstance(results, CommandResults):
                if results.raw_response:
                    vulnerabilities = results.raw_response  # type: ignore
            return_results(results)

            call_send_events_to_xsiam(events=events, vulnerabilities=vulnerabilities,
                                      should_push_events=argToBoolean(args.get('should_push_events', 'true')))

        elif command == 'fetch-events':
            last_run = demisto.getLastRun()
            if run_vulnerabilities_fetch(last_run=last_run, first_fetch=first_fetch,
                                         vuln_fetch_interval=vuln_fetch_interval):
                generate_export_uuid(client, first_fetch, last_run, severity)

            vulnerabilities = fetch_vulnerabilities(client, last_run, severity)
            events, new_last_run = fetch_events_command(client, first_fetch, last_run, max_fetch)

            call_send_events_to_xsiam(events=events, vulnerabilities=vulnerabilities, should_push_events=True)

            demisto.debug(f'Setting new last_run to {new_last_run}')
            demisto.setLastRun(new_last_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
