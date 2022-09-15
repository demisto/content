import time

import requests

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from typing import Dict, Any, Tuple
from enum import Enum

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

MAX_EVENTS_PER_REQUEST = 100
VENDOR = 'tenable'
PRODUCT = 'io'

DATE_FORMAT = '%Y-%m-%d'
BASE_URL = 'https://cloud.tenable.com'

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

    def __init__(self, verify: bool, proxy: bool, headers: dict, **kwargs):
        super().__init__(base_url=BASE_URL, verify=verify, proxy=proxy, headers=headers, **kwargs)

    @staticmethod
    def add_query(query, param_to_add):
        if query:
            return f'{query}&{param_to_add}'
        return f'?{param_to_add}'

    def get_audit_logs_request(self, from_date: str = None, to_date: str = None, actor_id: str = None,
                               target_id: str = None, limit: int = None):
        """

        Args:
            limit:
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
        res = super()._http_request(method='GET', url_suffix=f'/audit-log/v1/events{query}', headers=self._headers)
        return res.get('events', [])

    def get_export_uuid(self, num_assets: int, last_found: int, severity: List[str]):
        payload = {
            "filters":
                {
                    "severity": severity,
                    "last_found": last_found
                },
            "num_assets": num_assets
        }
        res = super()._http_request(method='POST', url_suffix='/vulns/export', headers=self._headers, json_data=payload)
        return res.get('export_uuid', '')

    def get_export_status(self, export_uuid: str):
        res = super()._http_request(method='GET', url_suffix=f'/vulns/export/{export_uuid}/status',
                                    headers=self._headers)
        status = res.get('status')
        chunks_available = res.get('chunks_available', [])
        return status, chunks_available

    def download_vulnerabilities_chunk(self, export_uuid: str, chunk_id: int):
        return super()._http_request(method='GET', url_suffix=f'/vulns/export/{export_uuid}/chunks/{chunk_id}',
                                     headers=self._headers)


''' COMMAND FUNCTIONS '''


def get_audit_logs_command(client: Client, from_date: Optional[str], to_date: Optional[str], actor_id: Optional[str],
                           target_id: Optional[str], limit: Optional[int] = None) -> List[Any] | Any:  # pragma: no cover
    """

    Args:
        client:
        from_date:
        to_date:
        actor_id:
        target_id:
        limit:

    Returns:

    """
    audit_logs = client.get_audit_logs_request(from_date=from_date,
                                               to_date=to_date,
                                               actor_id=actor_id,
                                               target_id=target_id,
                                               limit=limit)

    readable_output = tableToMarkdown('Audit Logs List:', audit_logs,
                                      removeNull=True,
                                      headerTransform=string_to_table_header)

    results = CommandResults(outputs_prefix='Tenable.AuditLogs',
                             outputs_key_field='id',
                             outputs=audit_logs,
                             readable_output=readable_output,
                             raw_response=audit_logs)
    return results, audit_logs


def fetch_audit_logs_command(client: Client, first_fetch: str, last_run: dict, limit: int = 1000) -> Tuple[list, dict]:
    """

    Args:
        client:
        first_fetch:
        last_run:
        limit:

    Returns:

    """

    last_fetch = last_run.get('next_fetch')
    last_id_fetched = last_run.get('last_id')
    vulnerabilities = []
    index = 0
    if not last_fetch and first_fetch:
        start_date = first_fetch.strftime(DATE_FORMAT)
    else:
        start_date = last_fetch.strftime(DATE_FORMAT)

    audit_logs: List[Dict] = []
    audit_logs_from_api = client.get_audit_logs_request(from_date=start_date)
    if last_id_fetched:
        index = 1
        for log in audit_logs_from_api:
            if log.get('id') == last_id_fetched:
                break
            index += 1

    last_log_to_fetch = min(len(audit_logs_from_api), limit)
    audit_logs.extend(audit_logs_from_api[index:last_log_to_fetch])

    # trying to fetch vulnerabilities
    integration_context = get_integration_context()
    export_uuid = integration_context.get('export_uuid')
    if export_uuid:
        vulnerabilities, finished_fetching = try_get_chunks(client=client, export_uuid=export_uuid)
        # set params for next run
        if finished_fetching:
            set_integration_context({'export_uuid': None})
            next_run = time.mktime(datetime.now(tz=timezone.utc).timetuple())
            new_last_run = {'next_fetch_vunl': next_run}

    next_run = datetime.now(tz=timezone.utc).strftime(DATE_FORMAT)
    new_last_run.update({'last_id': audit_logs[-1].get('id'),
                         'next_fetch': next_run})

    demisto.info(f'Done fetching {len(audit_logs)} audit logs, Setting {new_last_run=}.')
    return vulnerabilities, audit_logs, new_last_run


def try_get_chunks(client: Client, export_uuid: str):
    vulnerabilities = []
    status, chunks_available = client.get_export_status(export_uuid=export_uuid)
    if status == 'FINISHED':
        for chunk_id in chunks_available:
            vulnerabilities.extend(client.download_vulnerabilities_chunk(export_uuid=export_uuid, chunk_id=chunk_id))
        return vulnerabilities, True
    elif status in ['QUEUED', 'PROCESSING']:
        return vulnerabilities, False
    return vulnerabilities, True


def fetch_vulnerabilities_command(client: Client, first_fetch: datetime, last_run: dict, severity: List[str]):
    """
    
    Args:
        client: 
        first_fetch: 
        last_run: 
        num_assets: 

    Returns:

    """
    demisto.debug("Getting export uuid for report.")
    last_fetch = last_run.get('next_fetch_vunl')
    last_found = time.mktime(first_fetch.timetuple()) if not last_fetch and first_fetch else last_fetch

    export_uuid = client.get_export_uuid(num_assets=5000, last_found=last_found, severity=severity)
    set_integration_context({'export_uuid': export_uuid})


def run_vulnerabilities_fetch(last_run: dict, first_fetch: datetime, vuln_fetch_interval: int):
    if not last_run.get('next_fetch_vunl'):
        time_to_check = time.mktime(first_fetch.timetuple())
    else:
        time_to_check = last_run.get('next_fetch_vunl')
    if time.time() - time_to_check > vuln_fetch_interval:
        return True
    return False


def test_module(client: Client, first_fetch=None) -> str:
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

    access_key = params.get('access_key', {}).get('password')
    secret_key = params.get('secret_key', {}).get('password')
    vuln_fetch_interval = arg_to_number(params.get('vuln_fetch_interval')) * 60
    severity = argToList(params.get('severity'))

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get('max_fetch')) or 1000

    # transform minutes to seconds
    first_fetch = arg_to_datetime(params.get('first_fetch'))

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
                   "Accept": "application/json"}
        client = Client(
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if command == 'test-module':
            return_results(test_module(client, max_fetch, first_fetch))

        elif command in ('tenable-get-events', 'fetch-events'):

            if command == 'tenable-get-events':
                results, events = get_audit_logs_command(client,
                                                         from_date=args.get('from_date'),
                                                         to_date=args.get('to_date'),
                                                         actor_id=args.get('actor_id'),
                                                         target_id=args.get('target_id'),
                                                         limit=args.get('target_id'))
                return_results(results)

            else:  # command == 'fetch-events':
                last_run = demisto.getLastRun()
                if run_vulnerabilities_fetch(last_run=last_run, first_fetch=first_fetch,
                                             vuln_fetch_interval=vuln_fetch_interval):
                    fetch_vulnerabilities_command(client, first_fetch, last_run, severity)

                vulnerabilities, events, last_run = fetch_audit_logs_command(client, first_fetch, last_run, max_fetch)
                demisto.setLastRun(last_run)

            if argToBoolean(args.get('should_push_events', 'true')):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
                send_events_to_xsiam(vulnerabilities, vendor=VENDOR, product=PRODUCT)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
