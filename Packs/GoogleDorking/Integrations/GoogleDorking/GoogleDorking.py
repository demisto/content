import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
import dateparser
import traceback
import json
import math
from os import path
from typing import Optional, Union, Callable

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_INCIDENTS_TO_FETCH = 100
MAX_RESULTS_PER_PAGE = 10
LAST_RUN_TIME_KEY = 'last_date'
GOOGLE_TIME_FORMAT = '%Y-%m-%d'

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, urls, api_key, search_engine_id, search_file_types, keywords, max_results, **kwargs):
        super().__init__(**kwargs)
        self._urls = urls
        self._cx = search_engine_id
        self._api_key = api_key
        self._search_file_types = search_file_types
        self._keywords = keywords
        self._max_results = max_results
        self._after = None

    @property
    def max_results(self):
        return self._max_results

    @property
    def after(self):
        return self._after

    @after.setter
    def after(self, value):
        self._after = value

    @property
    def urls(self):
        return self._urls

    @urls.setter
    def urls(self, value):
        self._urls = value

    @property
    def file_types(self):
        return self._search_file_types

    @file_types.setter
    def file_types(self, value):
        self._search_file_types = value

    @property
    def keywords(self):
        return self._keywords

    @keywords.setter
    def keywords(self, value):
        self._keywords = value

    def search(self, q, start=0, num=10) -> dict:
        params = assign_params(
            cx=self._cx,
            key=self._api_key,
            q=q,
            filter=1,
            start=start,
            num=num
        )
        response = self._http_request('GET', params=params)
        return response

    def build_query(self) -> str:
        """ Builds a google query in the format of "filetype:...allintext:...site:... after:... " """
        query = ' OR '.join(list(map(lambda x: f'filetype:{x}', self._search_file_types)))
        if self._keywords:
            query += ' ' + ' OR '.join(list(map(lambda x: f'allintext:{x}', self._keywords)))
        if self._urls:
            query += ' ' + ' OR '.join(list(map(lambda x: f'site:{x}', self._urls)))
        if self.after:
            query += f' after:{self.after}'
        return query


def calculate_page_size(current_page: int, max_results: int) -> int:
    results_so_far = current_page * MAX_RESULTS_PER_PAGE
    if (results_diff := max_results - results_so_far) < MAX_RESULTS_PER_PAGE:
        return results_diff
    return MAX_RESULTS_PER_PAGE


def get_search_results(client: Client, parser: Callable) -> Union[list, str]:
    """ Searches google and returns a result using the parser"""
    results = []
    query = client.build_query()
    all_pages_found = False
    pages = math.ceil(client.max_results / MAX_RESULTS_PER_PAGE)
    current_page = 0
    start = 0
    while not all_pages_found and current_page < pages:
        results_in_page = calculate_page_size(current_page, client.max_results)
        page = client.search(query, start, results_in_page)
        items = page.get('items')
        if not items:
            break

        for item in items:
            results.extend(parser(client, item))

        # prepare next run
        current_page += 1
        start += results_in_page
        total = int(demisto.get(page, 'searchInformation.totalResults',
                                demisto.get(page, 'queries.request.totalResults', 0)))
        all_pages_found = total <= start
    if not results:
        return "No results found"
    return results


def item_to_incident(client: Client, item: dict) -> list:
    files = []
    if link := item.get('link'):
        try:
            file_result = fileResult(path.basename(link),
                                     client._http_request('GET', full_url=link, resp_type='content'))
            files.append({
                'path': file_result['FileID'],
                'name': file_result['File']
            })
        except Exception as e:
            demisto.debug(f"Failed fetching file from {link}. {str(e)}")
    return [assign_params(
        name=item.get('title', ''),
        attachment=files,
        rawJSON=json.dumps(item)
    )]


def item_to_result(client: Client, item: dict) -> list:
    results = []
    if link := item.get('link'):
        file_result = fileResult(path.basename(link), client._http_request('GET', full_url=link, resp_type='content'))
        results.append(file_result)
    results.append(
        CommandResults(
            outputs_prefix='GoogleDorking',
            outputs=item
        )
    )
    return results


def test_module(client: Client) -> str:
    client.search('hello world')
    return 'ok'


def google_search_command(
        client: Client,
        after: str = None,
        file_types: str = None,
        keywords: str = None,
        urls: str = None,
) -> Union[list, str]:
    if after:
        client.after = after
    if file_types:
        client.file_types = argToList(file_types)
    if keywords:
        client.keywords = argToList(keywords)
    if urls:
        client.urls = argToList(urls)
    return get_search_results(client, item_to_result)


def fetch_incidents(client: Client, last_run: Optional[dict]) -> list:
    now = datetime.now()
    last_run_date = last_run.get(LAST_RUN_TIME_KEY) if last_run else None
    if last_run_date:
        if (now - dateparser.parse(last_run_date)).days > 0:  # type: ignore
            client.after = last_run_date
    incidents = get_search_results(client, item_to_incident)
    if not isinstance(incidents, list):
        demisto.debug(f'Skipping incident creation. Received: {incidents}, expected list.')
        incidents = []

    demisto.setLastRun({
        LAST_RUN_TIME_KEY: (now - timedelta(days=1)).strftime(GOOGLE_TIME_FORMAT)
    })

    return incidents


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
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch'),
        arg_name='First fetch time',
        required=False
    )
    max_fetch = max(arg_to_number(params.get('max_fetch')) or MAX_INCIDENTS_TO_FETCH,
                    MAX_INCIDENTS_TO_FETCH)
    command = demisto.command()
    args = demisto.args()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            base_url='https://customsearch.googleapis.com/customsearch/v1',
            verify=verify_certificate,
            proxy=proxy,
            urls=search_urls,
            api_key=api_key,
            search_engine_id=search_engine_id,
            search_file_types=search_file_types,
            keywords=keywords,
            max_results=max_fetch
        )
        if first_fetch_time:
            client.after = first_fetch_time.strftime(GOOGLE_TIME_FORMAT)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'google-dorking-search':
            return_results(google_search_command(client, **args))

        elif command == 'fetch-incidents':
            demisto.incidents(fetch_incidents(client, demisto.getLastRun()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
