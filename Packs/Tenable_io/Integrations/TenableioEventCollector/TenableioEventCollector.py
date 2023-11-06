import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time
from typing import Dict, Union

import urllib3

urllib3.disable_warnings()

''' CONSTANTS '''

MAX_EVENTS_PER_REQUEST = 100
VENDOR = 'tenable'
PRODUCT = 'io'
NUM_ASSETS = 5000
DATE_FORMAT = '%Y-%m-%d'
MAX_CHUNK_SIZE = 5000
MAX_CHUNKS_PER_FETCH = 10

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

    def export_assets_request(self, chunk_size: int, fetch_from):
        """

        Args:
            chunk_size: maximum number of assets in one chunk.
            fetch_from: the last asset that was fetched previously.

        Returns: The UUID of the assets export job.

        """
        payload = {
            'chunk_size': chunk_size,
            "filters": {
                "created_at": fetch_from
            }
        }
        demisto.debug(f"my payload is: {payload}")
        res = self._http_request(method='POST', url_suffix='assets/export', json_data=payload,
                                 headers=self._headers)
        return res.get('export_uuid')

    def get_export_assets_status(self, export_uuid):
        """
        Args:
                export_uuid: The UUID of the assets export job.

        Returns: The assets' chunk id.

        """
        res = self._http_request(method='GET', url_suffix=f'assets/export/{export_uuid}/status', headers=self._headers)
        return res.get('status'), res.get('chunks_available')

    def download_assets_chunk(self, export_uuid: str, chunk_id: int):
        """

        Args:
            export_uuid: The UUID of the assets export job.
            chunk_id: The ID of the chunk you want to export.

        Returns: Chunk of assets from API.

        """
        return self._http_request(method='GET', url_suffix=f'/assets/export/{export_uuid}/chunks/{chunk_id}',
                                  headers=self._headers)


''' HELPER FUNCTIONS '''


def get_timestamp(timestamp):
    return time.mktime(timestamp.timetuple())


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


def handle_assets(assets_last_run, assets):
    last_asset_id = assets_last_run.get('asset_id')
    last_fetch = assets_last_run.get('last_fetch')
    if last_asset_id:
        assets = list(filter(lambda asset: asset.get('id') != last_asset_id, assets))
    assets_last_run.pop('export_uuid', None)  # if the polling is over and we can start a new fetch
    assets_last_run.pop('nextTrigger', None)
    assets_last_run.pop('type', None)
    assets_last_run.pop('available_chunks')
    for asset in assets:
        created_at = round(get_timestamp(arg_to_datetime(asset.get('created_at'))))
        if created_at > last_fetch:
            last_fetch = created_at
            assets_last_run.update({"asset_id": asset.get("id")})
    assets_last_run.update({'last_fetch': last_fetch})

    return assets, assets_last_run


def handle_assets_chunks(client: Client, assets_last_run):
    stored_chunks = assets_last_run.get('available_chunks', [])
    updated_stored_chunks = stored_chunks.copy()
    export_uuid = assets_last_run.get('export_uuid')
    assets = []
    for chunk_id in stored_chunks[:MAX_CHUNKS_PER_FETCH]:
        assets.extend(client.download_assets_chunk(export_uuid=export_uuid, chunk_id=chunk_id))
        updated_stored_chunks.remove(chunk_id)
    if updated_stored_chunks:
        assets_last_run.update({'available_chunks': updated_stored_chunks,
                                'nextTrigger': '0', "type": 1})
    else:
        assets_last_run.pop('nextTrigger', None)
        assets_last_run.pop('type', None)
        assets_last_run.pop('available_chunks', None)
        assets_last_run.pop('export_uuid', None)
    return handle_assets(assets_last_run, assets)
    # todo: add function to return assets and update last fetch in lastrun
    # return assets, assets_last_run


def try_get_assets_chunks(client: Client, export_uuid: str, assets_last_run):
    """
    If job has succeeded (status FINISHED) get all information from all chunks available.
    Args:
        client: Client class object.
        export_uuid: The UUID of the assets export job.

    Returns: All information from all chunks available.

    """
    status, chunks_available = client.get_export_assets_status(export_uuid=export_uuid)
    demisto.info(f'Report status is {status}, and number of available chunks is {chunks_available}')
    if status == 'FINISHED':
        assets_last_run.update({'available_chunks': chunks_available})
        # for chunk_id in chunks_available:
        #     assets.extend(client.download_assets_chunk(export_uuid=export_uuid, chunk_id=chunk_id))
    return status


def generate_export_uuid(client: Client, first_fetch: datetime, last_run: Dict[str, Union[str, float, None]],
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
    last_found: float = last_fetch or get_timestamp(first_fetch)

    export_uuid = client.get_export_uuid(num_assets=NUM_ASSETS, last_found=last_found, severity=severity)

    next_run_vuln = get_timestamp(datetime.now(tz=timezone.utc))
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
        time_to_check: float = get_timestamp(first_fetch)
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
def get_vulnerabilities_command(args: Dict[str, Any], client: Client) -> Union[CommandResults, PollResult]:
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


@polling_function('tenable-export-assets', requires_polling_arg=False)
def get_assets_command(args: Dict[str, Any], client: Client):
    """
    Getting assets from Tenable. Polling as long as the report is not ready (status FINISHED or failed)
    Args:
        args: arguments from user (last_found, severity and num_assets)
        client: Client class object.

    Returns: assets from API.

    """
    fetch_from = arg_to_number(args.get('last_fetch'))
    max_fetch = arg_to_number(args.get('chunk_size')) or MAX_CHUNK_SIZE
    export_uuid = args.get('export_uuid')
    assets = []
    if not export_uuid:
        export_uuid = client.export_assets_request(chunk_size=MAX_CHUNK_SIZE, fetch_from=fetch_from)

    status, chunks_available = client.get_export_assets_status(export_uuid=export_uuid)

    # if getting chunks from API has finished, or we reached the max amount required
    if status == 'FINISHED' or MAX_CHUNK_SIZE * len(chunks_available) < max_fetch:
        for chunk_id in chunks_available:
            assets.extend(client.download_assets_chunk(export_uuid=export_uuid, chunk_id=chunk_id))
        readable_output = tableToMarkdown('Assets List:', assets,
                                          removeNull=True,
                                          headerTransform=string_to_table_header)

        results = CommandResults(readable_output=readable_output,
                                 raw_response=assets)
        return PollResult(response=results)
    elif status in ['CANCELLED', 'ERROR']:
        results = CommandResults(readable_output='Assets export job failed',
                                 entry_type=entryTypes['error'])
        return PollResult(response=results)
    else:
        return PollResult(continue_to_poll=True, args_for_next_run={"export_uuid": export_uuid, **args},
                          response=None, partial_result=CommandResults(readable_output="still processing pulling the assets..."))


def generate_assets_export_uuid(client: Client, first_fetch: datetime, assets_last_run: Dict[str, Union[str, float, None]]):
    """
    Generate a job export uuid in order to fetch assets.

    Args:
        client: Client class object.
        first_fetch: time to first fetch assets from.
        assets_last_run: assets last run object.

    """

    demisto.info("Getting export uuid.")

    last_fetch: int = assets_last_run.get('last_fetch') or round(get_timestamp(first_fetch))
    export_uuid = client.export_assets_request(chunk_size=MAX_CHUNK_SIZE, fetch_from=last_fetch)    # todo: to keep chunk size as 5000 max?
    demisto.debug(f'assets export uuid is {export_uuid}')

    assets_last_run.update({'last_fetch': last_fetch, 'export_uuid': export_uuid})


''' FETCH COMMANDS '''


def fetch_assets_command(client: Client, assets_last_run, max_fetch):
    """
    Fetches assets.
    Args:
        assets_last_run: last run object.
        client: Client class object.

    Returns:
        assets fetched from the API.
    """
    assets = []
    export_uuid = assets_last_run.get('export_uuid')    # if already in assets_last_run meaning its still polling chunks from api
    last_fetch = assets_last_run.get('last_fetch')  # assets last run fetch time
    available_chunks = assets_last_run.get('available_chunks', [])
    if available_chunks:
        assets, assets_last_run = handle_assets_chunks(client, assets_last_run)
    elif export_uuid:
        demisto.info(f'Got export uuid from API {export_uuid}')
        status = try_get_assets_chunks(client=client, export_uuid=export_uuid, assets_last_run=assets_last_run)

        if status in ['PROCESSING', 'QUEUED']:
            demisto.debug("status is in progress, merit test")
            assets_last_run.update({'nextTrigger': '30', "type": 1})
        # set params for next run
        if status == 'FINISHED':
            assets, assets_last_run = handle_assets_chunks(client, assets_last_run)
            # assets, assets_last_run = handle_finished_status(assets_last_run, assets)
            # assets = assets[:max_fetch]
        elif status in ['CANCELLED', 'ERROR'] and last_fetch:
            export_uuid = client.export_assets_request(chunk_size=MAX_CHUNK_SIZE, fetch_from=last_fetch)
            assets_last_run.update({'export_uuid': export_uuid})
            assets_last_run.update({'nextTrigger': '30', "type": 1})

    demisto.info(f'merit, Done fetching {len(assets)} assets, {assets_last_run=}.')
    return assets, assets_last_run


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
    max_assets_fetch = arg_to_number(params.get("max_assets_fetch"))  # todo: how to use it? and how much is the max?

    # transform minutes to seconds
    first_fetch: datetime = arg_to_datetime(params.get('first_fetch', '3 days'))  # type: ignore
    first_assets_fetch: datetime = arg_to_datetime(params.get("first_fetch_time_assets", "10 years"))

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
            demisto.debug("meritfetchevents")
            last_run = demisto.getLastRun()
            demisto.debug(f"saved lastrun events: {last_run}")
            new_last_run = {"testing": "events lastrun"}
            demisto.debug(f"new lastrun events: {new_last_run}")
            demisto.setLastRun(new_last_run)
            # last_run = demisto.getLastRun()
            # if run_vulnerabilities_fetch(last_run=last_run, first_fetch=first_fetch,
            #                              vuln_fetch_interval=vuln_fetch_interval):
            #     generate_export_uuid(client, first_fetch, last_run, severity)
            #
            # vulnerabilities = fetch_vulnerabilities(client, last_run, severity)
            # events, new_last_run = fetch_events_command(client, first_fetch, last_run, max_fetch)
            #
            # call_send_events_to_xsiam(events=events, vulnerabilities=vulnerabilities, should_push_events=True)
            #
            # demisto.setLastRun(new_last_run)

        elif command == 'fetch-assets':
            assets_last_run = demisto.getAssetsLastRun()
            demisto.debug(f"saved lastrun assets: {assets_last_run}")

            # if assets_last_run.get('available_chunks'):
            #     assets, new_assets_last_run = handle_assets_chunks(client, assets_last_run)
            # else:

            # starting new fetch for assets, not polling from prev call
            if not assets_last_run.get('export_uuid'):
                generate_assets_export_uuid(client, first_assets_fetch, assets_last_run)

            assets, new_assets_last_run = fetch_assets_command(client, assets_last_run, max_fetch)
            demisto.debug(f"new lastrun assets: {new_assets_last_run}")
            demisto.setAssetsLastRun(new_assets_last_run)

            send_events_to_xsiam(assets, product=PRODUCT, vendor=VENDOR)
            demisto.debug(f"done sending {len(assets)} assets to xsiam")

            # todo: to be implemented in CSP once we have the api endpoint from xdr
            demisto.updateModuleHealth({'assetsPulled': len(assets)})
            # send_data_to_xsiam(assets, vendor=VENDOR, product=PRODUCT, data_type=ASSETS)

        elif command == 'tenable-export-assets':
            results = get_assets_command(args, client)
            return_results(results)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
