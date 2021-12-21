import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_INCIDENTS_TO_FETCH = 50

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, urls, api_key, search_engine_id, search_file_types, keywords, **kwargs):
        super().__init__(**kwargs)
        self._urls = urls
        self._cx = search_engine_id
        self._api_key = api_key
        self._search_file_types = search_file_types
        self._keywords = keywords

    def search(self, q) -> Union[dict, list]:
        params = assign_params(
            cx=self._cx,
            key=self._api_key,
            q=q,
            filter=1,
            sort='date'
        )
        response = self._http_request('GET', params=params)
        return response

    def query_builder(self) -> str:
        query = ' OR '.join(list(map(lambda x: f'filetype:{x}', self._search_file_types)))
        if self._keywords:
            query += ' '
            query += ' OR '.join(list(map(lambda x: f'allintext:{x}', self._keywords)))
        if self._urls:
            query += ' '
            query += ' OR '.join(list(map(lambda x: f'site:{x}', self._urls)))
        return query


def test_module(client) -> str:
    return 'ok'


def google_search_with_params_command(client) -> CommandResults:
    query = client.query_builder()
    return client.search(query)


def google_search_command(client, query) -> CommandResults:
    return client.search(query)


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    search_engine_id = params.get('apiKey').get('identifier')
    api_key = params.get('apiKey').get('password')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    search_urls = argToList(params.get('urls'))
    search_file_types = argToList(params.get('file_types'))
    keywords = argToList(params.get('keywords'))
    # first_fetch_time = arg_to_datetime(
    #     arg=demisto.params().get('first_fetch', '3 days'),
    #     arg_name='First fetch time',
    #     required=True
    # )
    # first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url='https://customsearch.googleapis.com/customsearch/v1',
            verify=verify_certificate,
            proxy=proxy,
            urls=search_urls,
            api_key=api_key,
            search_engine_id=search_engine_id,
            search_file_types=search_file_types,
            keywords=keywords)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'google-search':
            return_results(google_search_command(client, **args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
