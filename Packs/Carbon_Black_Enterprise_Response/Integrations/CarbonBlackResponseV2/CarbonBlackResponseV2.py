import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, base_url: str, use_ssl: bool, use_proxy: bool):
        super().__init__(base_url, verify=use_ssl, proxy=use_proxy)

    def http_request(self, url, method, params=None, resp_type=None):
        """
        initiates a http request to openphish
        """
        data = self._http_request(
            method=method,
            url_suffix=url,
            params=params,
            resp_type=resp_type,
        )
        return data


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    message: str = ''
    try:

        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def processes_search_command(client: Client, name: str = None, group: str = None, hostname: str = None,
                             parent_process_name: str = None,
                             process_path: str = None, md5: str = None, query: str = None, group_by: str = None,
                             sort: str = None, facet: str = None, facet_field: str = None, rows: str = None,
                             start: str = None):
    # Create query
    current_query = f'({query})' if query else ''

    _query_fields_mapping = {'process_name': name, 'group': group, 'hostname': hostname,
                             'parent_name': parent_process_name,
                             'path': process_path, 'md5': md5}

    for query_field in _query_fields_mapping:
        if _query_fields_mapping[query_field]:
            current_query += f' AND {query}:{_query_fields_mapping[query_field]}'

    if not query:
        raise Exception(
            f'Session search without any filter is not permitted. '
            f'Please add a query or one of the following filters: {_query_fields_mapping.keys()}')

    res = client.http_request(url='/api/v1/process', method='GET',
                              params={'q': current_query, 'rows': rows, 'start': start, 'sort': sort, 'facet': facet,
                                      'facet.field': facet_field, 'cb.group': group_by})



''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_token = demisto.params().get('apitoken')
    base_url = urljoin(demisto.params()['url'], '/api')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:

        headers: Dict = {}

        client = Client(
            base_url=base_url,
            use_ssl=verify_certificate,
            use_proxy=proxy)
        commands = {'cb-edr-processes-search', 'cb-edr-process-get', 'cb-edr-process-segments-get',
                    'cb-edr-process-events-list', 'cb-edr-binary-search', 'cb-edr-binary-download',
                    'cb-edr-binary-summary', 'cb-edr-alert-search', 'cb-edr-alert-update', 'cb-edr-binary-bans-list',
                    'cb-edr-binary-ban', 'cb-edr-watchlists-list', 'cb-edr-watchlist-create', 'cb-edr-watchlist-update',
                    'cb-edr-watchlist-delete', 'cb-edr-sensors-list', 'cb-edr-quarantine-device',
                    'cb-edr-unquarantine-device', 'cb-edr-sensor-installer-download'}

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'fetch-incidents':
            return
            # return_results(baseintegration_dummy_command(client, demisto.args()))
        elif command in commands:
            return_results(commands[command](client, **demisto.args()))
        else:
            raise NotImplementedError(f'command {command} was not implemented in this integration.')
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
    return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
