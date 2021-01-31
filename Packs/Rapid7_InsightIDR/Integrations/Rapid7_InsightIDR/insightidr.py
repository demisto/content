import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
from datetime import datetime, timedelta
from typing import Dict, Tuple
from requests import Response

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

INVESTIGATIONS_FIELDS = ['title', 'id', 'status', 'created_time', 'source', 'assignee', 'alerts']
THREATS_FIELDS = ['name', 'note', 'indicator_count', 'published']
LOGS_FIELDS = ['name', 'id']
EVENTS_FIELDS = ['log_id', 'message', 'timestamp']


class Client(BaseClient):
    """Client for Rapid7 InsightIDR REST API."""

    def __init__(self, base_url: str, headers: dict, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_investigations(self, params: dict) -> dict:
        return self._http_request(method='GET',
                                  url_suffix='idr/v1/investigations',
                                  params=params)

    def bulk_close_investigations(self, body: dict) -> dict:
        return self._http_request(method='POST',
                                  url_suffix='idr/v1/investigations/bulk_close',
                                  headers=self._headers,
                                  json_data=body)

    def assign_user(self, investigation_id: str, body: dict) -> dict:
        return self._http_request(method='PUT',
                                  url_suffix=f'idr/v1/investigations/{investigation_id}/assignee',
                                  headers=self._headers,
                                  json_data=body)

    def set_status(self, investigation_id: str, status: str) -> dict:
        return self._http_request(method='PUT',
                                  url_suffix=f'idr/v1/investigations/{investigation_id}'
                                             f'/status/{status}',
                                  headers=self._headers)

    def add_threat_indicators(self, key: str, body: dict) -> dict:
        return self._http_request(method='POST',
                                  url_suffix=f'idr/v1/customthreats/key/{key}/indicators/add',
                                  headers=self._headers,
                                  params={"format": "json"},
                                  json_data=body)

    def replace_threat_indicators(self, key: str, body: dict) -> dict:
        return self._http_request(method='POST',
                                  url_suffix=f'idr/v1/customthreats/key/{key}/indicators/replace',
                                  headers=self._headers,
                                  params={"format": "json"},
                                  json_data=body)

    def list_logs(self) -> dict:
        return self._http_request(method='GET',
                                  url_suffix='log_search/management/logs',
                                  headers=self._headers)

    def list_log_sets(self) -> dict:
        return self._http_request(method='GET',
                                  url_suffix='log_search/management/logsets',
                                  headers=self._headers)

    def download_logs(self, log_ids: str, params: dict) -> Response:
        headers = self._headers.copy()
        headers['Accept-Encoding'] = ''
        return self._http_request(method='GET',
                                  url_suffix=f'log_search/download/logs/{log_ids}',
                                  headers=headers,
                                  params=params,
                                  resp_type='response')

    def query_log(self, log_id: str, params: dict) -> Response:
        return self._http_request(method='GET',
                                  url_suffix=f'log_search/query/logs/{log_id}',
                                  headers=self._headers,
                                  params=params,
                                  resp_type='response')

    def query_log_set(self, log_set_id: str, params: dict) -> Response:
        return self._http_request(method='GET',
                                  url_suffix=f'log_search/query/logsets/{log_set_id}',
                                  headers=self._headers,
                                  params=params,
                                  resp_type='response')

    def query_log_callback(self, url: str) -> dict:
        return self._http_request(method='GET',
                                  url_suffix='',
                                  full_url=url,
                                  headers=self._headers)

    def validate(self) -> Response:
        """
        Validate API using list-investigations method.

        Returns:
            response(Response): API response from InsightIDR
        """
        params = {'size': 1}
        return self._http_request(method='GET',
                                  url_suffix='idr/v1/investigations',
                                  params=params,
                                  resp_type='response')


def insight_idr_list_investigations_command(client: Client, statuses: str = None,
                                            time_range: str = None,
                                            start_time: str = None, end_time: str = None,
                                            index: int = 0, page_size: int = 20) -> CommandResults:
    """
    List investigations according to received parameters.

    Args:
        client(Client): Rapid7 client
        statuses(str): An optional comma separated set of investigation statuses
        time_range(str): An optional relative time range in a readable format.
        start_time(str): An optional ISO formatted timestamp
        end_time(str): An optional ISO formatted timestamp
        index(int): The optional 0 based index of the page to retrieve
        page_size(int): The optional size of the page to retrieve

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    # start_time and end_time can come in "last 1 day" format, so we parse it
    if time_range:
        start_time, end_time = parse_date_range(time_range, date_format=DATE_FORMAT)

    params = {
        'statuses': statuses,
        'start_time': start_time,
        'end_time': end_time,
        'index': index,
        'size': page_size
    }

    results = client.list_investigations(remove_empty_elements(params))

    data_for_output = results.get('data', [])
    readable_output = tableToMarkdown('Requested Investigations',
                                      data_for_output,
                                      headers=INVESTIGATIONS_FIELDS,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Investigation',
        outputs_key_field='id',
        raw_response=results,
        outputs=data_for_output,
        readable_output=readable_output
    )
    return command_results


def insight_idr_get_investigation_command(client: Client, investigation_id: str) -> CommandResults:
    """
        List investigations according to received parameters.

        Args:
            client(Client): Rapid7 client
            investigation_id(str): Investigation ID

        Returns:
            CommandResults with raw_response, readable_output and outputs.
        """
    results = client.list_investigations({})

    data_for_output = results.get('data', [])
    investigation_data = {}

    for investigation in data_for_output:
        if investigation.get('id') == investigation_id:
            investigation_data = investigation

    if not investigation_data:
        return CommandResults(raw_response=None)

    readable_output = tableToMarkdown(f'Investigation Information (id: {investigation_id})',
                                      investigation_data,
                                      headers=INVESTIGATIONS_FIELDS,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Investigation',
        outputs_key_field='id',
        raw_response=investigation_data,
        outputs=investigation_data,
        readable_output=readable_output
    )
    return command_results


def insight_idr_close_investigations_command(client: Client, start_time: str, end_time: str,
                                             source: str, max_investigations_to_close: int = None,
                                             alert_type: str = None) -> CommandResults:
    """
    Close investigations by start_time, end_time and source.

    Args:
        client(Client): Rapid7 client
        start_time(str): An ISO formatted timestamp.
        end_time(str): An ISO formatted timestamp.
        source(str): The name of an investigation source
        max_investigations_to_close(int): An optional maximum number of alerts to close
        alert_type(str): The category of alerts that should be closed

    Returns:
        CommandResults with raw_response, readable_output and outputs.

    """
    body = {
        'from': start_time,
        'to': end_time,
        'source': source,
        'max_investigations_to_close': max_investigations_to_close,
        'alert_type': alert_type
    }

    results = client.bulk_close_investigations(remove_empty_elements(body))

    ids = {
        'id': results.get('ids')
    }

    data_for_outputs = []
    for current_id in results.get('ids', []):
        data_for_outputs.append({
            'id': current_id,
            'status': 'CLOSED'
        })

    readable_output = tableToMarkdown('Closed Investigations IDs', ids, headers=['id'],
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Investigation',
        outputs_key_field='id',
        raw_response=results,
        outputs=data_for_outputs,
        readable_output=readable_output
    )
    return command_results


def insight_idr_assign_user_command(client: Client, investigation_id: str,
                                    user_email_address: str):
    """
    Assigning user, by email, to investigation or investigations.

    Args:
        client(Client): Rapid7 client
        investigation_id(str): Investigation IDs, One or XSOAR list (str separated by commas)
        user_email_address(str): The email address of the user to assign

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    results = []
    data_for_readable_output = []

    for investigation in argToList(investigation_id):
        body = {
            'user_email_address': user_email_address
        }

        result = client.assign_user(investigation, body)
        results.append(result)

        data_for_readable_output.append(result)
        time.sleep(0.01)

    readable_output = tableToMarkdown(f'Investigation Information (id: {investigation_id})',
                                      data_for_readable_output,
                                      headers=INVESTIGATIONS_FIELDS,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Investigation',
        outputs_key_field='id',
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output
    )
    return command_results


def insight_idr_set_status_command(client: Client, investigation_id: str, status: str):
    """
    Change the status of investigation or investigations to OPEN/CLOSED.

        Args:
            client(Client): Rapid7 client
            investigation_id(str): Investigation IDs, One or XSOAR list (str separated by commas)
            status(str): The new status for the investigation (open/closed)

        Returns:
            CommandResults with raw_response, readable_output and outputs.
        """

    results = []
    data_for_readable_output = []
    for investigation in argToList(investigation_id):
        result = client.set_status(investigation, status)
        results.append(result)

        data_for_readable_output.append(result)
        time.sleep(0.01)

    readable_output = tableToMarkdown(f'Investigation Information (id: {investigation_id})',
                                      data_for_readable_output,
                                      headers=INVESTIGATIONS_FIELDS,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Investigation',
        outputs_key_field='id',
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output
    )
    return command_results


def insight_idr_add_threat_indicators_command(client: Client, key: str,
                                              ip_addresses: str = None,
                                              hashes: str = None,
                                              domain_names: str = None,
                                              url: str = None) -> CommandResults:
    """
    Adding threat indicators to threat (or threats) by key.

    Args:
        client(Client): Rapid7 client
        key(str): Threat key (Threat IDs), One or XSOAR list (str separated by commas)
        ip_addresses(str): IPs addresses, One or XSOAR list (str separated by commas)
        hashes(str): Hashes, One or XSOAR list (str separated by commas)
        domain_names(str): Domain names, One or XSOAR list (str separated by commas)
        url(str): URLs, One or XSOAR list (str separated by commas)

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    body = {
        'ips': argToList(ip_addresses),
        'hashes': argToList(hashes),
        'domain_names': argToList(domain_names),
        'urls': argToList(url)
    }
    body = remove_empty_elements(body)

    results = []
    data_for_readable_output = []

    for threat in argToList(key):
        result = client.add_threat_indicators(threat, body)
        results.append(result)

        data_for_readable_output.append(result.get('threat'))
        time.sleep(0.01)

    readable_output = tableToMarkdown(f'Threat Information (key: {key})', data_for_readable_output,
                                      headers=THREATS_FIELDS, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Threat',
        outputs_key_field='name',
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output
    )
    return command_results


def insight_idr_replace_threat_indicators_command(client: Client, key: str,
                                                  ip_addresses: str = None, hashes: str = None,
                                                  domain_names: str = None,
                                                  url: str = None) -> CommandResults:
    """
    Replace threat indicators to threat (or threats) by key.

    Args:
        client(Client): Rapid7 Client
        key(str): Threat key (threat ID), One or XSOAR list (str separated by commas)
        ip_addresses(str/List[str]): IPs addresses, One or XSOAR list (str separated by commas)
        hashes(str/List[str]): hashes, One or XSOAR list (str separated by commas)
        domain_names(str/List[str]): DOMAIN NAMEs, One or XSOAR list (str separated by commas)
        url(str/List[str]): URLs, One or XSOAR list (str separated by commas)

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    body = {
        'ips': argToList(ip_addresses),
        'hashes': argToList(hashes),
        'domain_names': argToList(domain_names),
        'urls': argToList(url)
    }
    body = remove_empty_elements(body)

    results = []
    data_for_readable_output = []

    for threat in argToList(key):
        result = client.replace_threat_indicators(threat, body)
        results.append(result)

        data_for_readable_output.append(result.get('threat'))
        time.sleep(0.01)

    readable_output = tableToMarkdown(f'Threat Information (key: {key})', data_for_readable_output,
                                      headers=THREATS_FIELDS, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Threat',
        outputs_key_field='name',
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output
    )
    return command_results


def insight_idr_list_logs_command(client: Client) -> CommandResults:
    """
    List all logs.

    Args:
        client(Client): Rapid7 Client

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    results = client.list_logs()

    logs = results.get('logs', {})
    data_for_readable_output = []

    for log in logs:
        data_for_readable_output.append(log)

    readable_output = tableToMarkdown('List Logs', data_for_readable_output, headers=LOGS_FIELDS,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Log',
        outputs_key_field='id',
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output
    )
    return command_results


def insight_idr_list_log_sets_command(client: Client) -> CommandResults:
    """
    List all log sets.

    Args:
        client(Client): Rapid7 Client

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    results = client.list_log_sets()

    logs = results.get('logsets', {})
    data_for_readable_output = []

    for log in logs:
        data_for_readable_output.append(log)

    readable_output = tableToMarkdown('List Log Sets', data_for_readable_output,
                                      headers=LOGS_FIELDS, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.LogSet',
        outputs_key_field='id',
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output
    )
    return command_results


def insight_idr_download_logs_command(client: Client, log_ids: str, time_range: str = None,
                                      start_time: str = None, end_time: str = None,
                                      query: str = None, limit: str = None):
    """
    Download logs to .log file based on time and query (query - optional)

    Args:
        client(Client): Rapid7 Client
        log_ids(str): Log ids to be downloaded
        time_range(str): human time format 'last 4 days' (can be hours, days, months, years
        start_time(str): UNIX timestamp in milliseconds
        end_time(str): UNIX timestamp in milliseconds
        query(str): LEQL query
        limit(int): max number of logs to download

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    if not (start_time or end_time or time_range):
        time_range = 'Last 3 days'

    params = {
        'from': start_time,
        'to': end_time,
        'time_range': time_range,
        'query': query,
        'limit': limit
    }
    response = client.download_logs(log_ids.replace(',', ':'), remove_empty_elements(params))
    content_disposition = response.headers.get('Content-Disposition')
    try:
        filename = content_disposition.split(';')[1].split('=')[1].replace(' ', '')  # type: ignore
    except AttributeError:
        filename = datetime.now().strftime(DATE_FORMAT) + '.log'

    file_type = entryTypes['entryInfoFile']
    return fileResult(filename, response.content, file_type)


def insight_idr_query_log_command(client: Client, log_id: str, query: str, time_range: str = None,
                                  start_time: str = None, end_time: str = None,
                                  logs_per_page: int = None,
                                  sequence_number: int = None) -> CommandResults:
    """
    Search a log by Query.

    Args:
        client(Client): Rapid7 Client
        log_id(str): Logentries log key
        query(str): A valid LEQL query to run against the log
        time_range(str): An optional relative time range in a readable format
        start_time(str): Lower bound of the time range you want to query against
        end_time(str): Upper bound of the time range you want to query against
        logs_per_page(int): The number of log entries to return per page
        sequence_number(int): The earlier sequence number of a log entry to start searching from

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    if time_range:
        start_time, end_time = parse_date_range(time_range, to_timestamp=True)

    params = {
        'query': query,
        'from': start_time,
        'to': end_time,
        'per_page': logs_per_page,
        'sequence_number': sequence_number
    }

    params = remove_empty_elements(params)

    results = client.query_log(log_id, params)

    data_for_readable_output = []
    new_data = []

    # 202 if there is a callback, and 200 if that's the full response
    if results.status_code == 202:
        for link in results.json().get('links', []):
            url = link.get('href')
            data = client.query_log_callback(url)
            new_data.append(data)
            events = data.get('events', [])
            for event in events:
                data_for_readable_output.append(event)
    else:
        events = results.json().get('events', [])
        for event in events:
            data_for_readable_output.append(event)

    raw_response = new_data if new_data else results.json()

    readable_output = tableToMarkdown('Query Results', data_for_readable_output,
                                      headers=EVENTS_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Event',
        outputs_key_field='message',
        raw_response=raw_response,
        outputs=data_for_readable_output,
        readable_output=readable_output
    )
    return command_results


def insight_idr_query_log_set_command(client: Client, log_set_id: str, query: str,
                                      time_range: str = None,
                                      start_time: str = None, end_time: str = None,
                                      logs_per_page: int = None,
                                      sequence_number: int = None) -> CommandResults:
    """
    Search a log set by Query.

    Args:
        client(Client): Rapid7 Client
        log_set_id(str): log set id
        query(str): A valid LEQL query to run against the log
        time_range(str): An optional relative time range in a readable format
        start_time(str): Lower bound of the time range you want to query against (ISO  format)
        end_time(str): Upper bound of the time range you want to query against (ISO  format)
        logs_per_page(int): The number of log entries to return per page
        sequence_number(int): The earlier sequence number of a log entry to start searching from

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    if time_range:
        start_time, end_time = parse_date_range(time_range, to_timestamp=True)

    params = {
        'query': query,
        'from': start_time,
        'to': end_time,
        'per_page': logs_per_page,
        'sequence_number': sequence_number
    }

    params = remove_empty_elements(params)

    results = client.query_log_set(log_set_id, params)

    data_for_readable_output = []
    new_data = []

    # 202 if there is a callback, and 200 if that's the full response
    if results.status_code == 202:
        for link in results.json().get('links', []):
            url = link.get('href')
            data = client.query_log_callback(url)
            new_data.append(data)
            events = data.get('events', [])
            for event in events:
                data_for_readable_output.append(event)
    else:
        events = results.json().get('events', [])
        for event in events:
            data_for_readable_output.append(event)

    raw_response = new_data if new_data else results.json()

    readable_output = tableToMarkdown('Query Results', data_for_readable_output,
                                      headers=EVENTS_FIELDS, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Rapid7InsightIDR.Event',
        outputs_key_field='message',
        raw_response=raw_response,
        outputs=data_for_readable_output,
        readable_output=readable_output
    )
    return command_results


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to.

    200 - success
    401 - API key not valid
    500 - not account region
    Args:
        client(Client): Rapid7 Client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        response = client.validate()
        status_code = response.status_code
        if status_code == 200:
            return 'ok'

        if status_code == 401:
            return 'API key is not valid.'

        if status_code == 500:
            return 'This isn\'t your account region.'

        return 'Something went wrong...'
    except DemistoException:
        return 'Connection error. Check your region.'


def fetch_incidents(client: Client,
                    last_run: Dict,
                    first_fetch_time: str,
                    max_fetch: str) -> Tuple[Dict[str, int], List[dict]]:
    """
    Fetch incidents (investigations) each minute (by default).

    Args:
        client(Client): Rapid7 Client
        last_run(Dict[str, int]): Dict with last_fetch object,
                                  saving the last fetch time(in millisecond timestamp)
        first_fetch_time: Dict with first fetch time in str (ex: 3 days ago) need to be parsed
        max_fetch(str): Max number of alerts per fetch. Default is 50
    Returns:
        Tuple of next_run (millisecond timestamp) and the incidents list
    """
    last_fetch_timestamp = last_run.get('last_fetch', None)

    if last_fetch_timestamp:
        last_fetch = datetime.fromtimestamp(last_fetch_timestamp / 1000)
    else:
        last_fetch, _ = parse_date_range(first_fetch_time)

    incidents = []
    next_run = last_fetch

    size = int(max_fetch) if max_fetch else 50
    params = {'start_time': last_fetch.strftime(DATE_FORMAT),
              'size': size}

    investigations = client.list_investigations(remove_empty_elements(params))
    for investigation in investigations.get('data', []):
        investigation_created_time = investigation.get('created_time')

        incident = {
            'name': investigation.get('title'),
            'occurred': investigation_created_time,
            'rawJSON': json.dumps(investigation)
        }
        incidents.append(incident)

        created_time = datetime.strptime(investigation_created_time, DATE_FORMAT)
        if created_time > next_run:
            next_run = created_time

    # add 1 millisecond to next_run to prevent duplication
    next_run = next_run + timedelta(milliseconds=1)
    next_run_timestamp = int(datetime.timestamp(next_run) * 1000)

    return {'last_fetch': next_run_timestamp}, incidents


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS"""

    params = demisto.params()
    region = params.get('region', {})
    api_key = params.get('apiKey', {})
    max_fetch = params.get('max_fetch', '50')

    base_url = f'https://{region}.api.insight.rapid7.com/'

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {
        'X-Api-Key': api_key,
        'content-type': 'application/json'
    }

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = params.get('fetch_time', '3 days').strip()

    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy)
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(client=client,
                                                  last_run=demisto.getLastRun(),
                                                  first_fetch_time=first_fetch_time,
                                                  max_fetch=max_fetch)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'rapid7-insight-idr-list-investigations':
            return_results(insight_idr_list_investigations_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-get-investigation':
            return_results(insight_idr_get_investigation_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-close-investigations':
            return_results(insight_idr_close_investigations_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-assign-user':
            return_results(insight_idr_assign_user_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-set-status':
            return_results(insight_idr_set_status_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-add-threat-indicators':
            return_results(insight_idr_add_threat_indicators_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-replace-threat-indicators':
            return_results(insight_idr_replace_threat_indicators_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-list-logs':
            return_results(insight_idr_list_logs_command(client))

        elif command == 'rapid7-insight-idr-list-log-sets':
            return_results(insight_idr_list_log_sets_command(client))

        elif command == 'rapid7-insight-idr-download-logs':
            return_results(insight_idr_download_logs_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-query-log':
            return_results(insight_idr_query_log_command(client, **demisto.args()))

        elif command == 'rapid7-insight-idr-query-log-set':
            return_results(insight_idr_query_log_set_command(client, **demisto.args()))

    # Log exceptions
    except Exception as error:
        return_error(f'Failed to execute {command} command. Error: {str(error)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
