import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3
import dateparser
import traceback
from os import path
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

MAX_INCIDENTS_TO_FETCH = 100
LAST_RUN_TIME_KEY = 'last_date'
GOOGLE_TIME_FORMAT = '%Y-%m-%d'

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, urls, api_key, search_engine_id, search_file_types, keywords, **kwargs):
        super().__init__(**kwargs)
        self._urls = urls
        self._cx = search_engine_id
        self._api_key = api_key
        self._search_file_types = search_file_types
        self._keywords = keywords
        self._after = None

    @property
    def after(self):
        return self._after

    @after.setter
    def after(self, value):
        self._after = value

    def search(self, q, start=0) -> Union[dict, list]:
        params = assign_params(
            cx=self._cx,
            key=self._api_key,
            q=q,
            filter=1,
            start=start
        )
        response = self._http_request('GET', params=params)
        demisto.info('Requests was successful')
        return response

    def build_query(self) -> str:
        query = ' OR '.join(list(map(lambda x: f'filetype:{x}', self._search_file_types)))
        if self._keywords:
            query += ' '
            query += ' OR '.join(list(map(lambda x: f'allintext:{x}', self._keywords)))
        if self._urls:
            query += ' '
            query += ' OR '.join(list(map(lambda x: f'site:{x}', self._urls)))
        if self.after:
            query += f' {self.after}'
        return query


def test_module(client) -> str:
    return 'ok'


def google_search_command(client: Client, query) -> CommandResults:
    res = client.search(query)
    return CommandResults(
        outputs=res
    )


def item_to_incident(client: Client, item: dict) -> dict:
    file = None
    if 'link' in item:
        link = item['link']
        demisto.info(f'accessing {link}')
        file = fileResult(path.basename(link), client._http_request('GET', full_url=link, resp_type='content'))
    demisto.info(f'Creating incident: {item.get("title")}')
    return assign_params(
        name=item.get('title', ''),
        attachment=file,
        rawJSON=item
    )


def fetch_incidents(client: Client, last_run: Optional[dict]) -> list:
    incidents = []
    now = datetime.now()
    last_run_date = last_run.get(LAST_RUN_TIME_KEY) if last_run else None
    if last_run_date:
        if (now - dateparser.parse(last_run_date)).days > 0:
            client.after = f'after:{last_run_date}'
    query = client.build_query()
    all_pages_found = False
    i = 0
    start = 0
    while not all_pages_found and i < 10:
        demisto.info(f'started fetching page {i}')
        page = client.search(query, start)
        items = page.get('items')
        if not items:
            break

        for item in items:
            incidents.append(item_to_incident(client, item))

        # prepare next run
        i += 1
        start += 10  # page size == 10
        total = int(demisto.get(page, 'searchInformation.totalResults',
                                demisto.get(page, 'queries.request.totalResults', 0)))
        all_pages_found = total < start

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
    # first_fetch_time = arg_to_datetime(
    #     arg=demisto.params().get('first_fetch', '3 days'),
    #     arg_name='First fetch time',
    #     required=True
    # )
    # first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
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
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'google-search':
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
