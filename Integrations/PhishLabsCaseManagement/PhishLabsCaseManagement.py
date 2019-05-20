import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from typing import Callable

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' TYPES '''

Response = requests.models.Response


''' GLOBALS/PARAMS '''

USERNAME: str = demisto.params().get('credentials', {}).get('identifier')
PASSWORD: str = demisto.params().get('credentials', {}).get('password')
SERVER: str = (demisto.params().get('url')[:-1]
               if (demisto.params().get('url') and demisto.params().get('url').endswith('/'))
               else demisto.params().get('url'))
USE_SSL: bool = not demisto.params().get('insecure', False)
BASE_URL: str = str(SERVER) + '/v1/'
HEADERS: dict = {
    'Content-Type': 'application/json'
}
NONE_DATE: str = '0001-01-01T00:00:00Z'

FETCH_TIME: str = demisto.params().get('fetch_time', '').strip()
FETCH_LIMIT: str = demisto.params().get('fetch_limit', '10')
RAISE_EXCEPTION_ON_ERROR: bool = False


''' HELPER FUNCTIONS '''


@logger
def http_request(method: str, path: str, params: dict = None, data: dict = None) -> dict:
    """
    Sends an HTTP request using the provided arguments
    :param method: HTTP method
    :param path: URL path
    :param params: URL query params
    :param data: Request body
    :return: JSON response
    """
    params: dict = params if params is not None else {}
    data: dict = data if data is not None else {}

    try:
        res: Response = requests.request(
            method,
            BASE_URL + path,
            auth=(USERNAME, PASSWORD),
            verify=USE_SSL,
            params=params,
            data=json.dumps(data) if data else {},
            headers=HEADERS)
        demisto.log(str(res.url))
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
            requests.exceptions.TooManyRedirects, requests.exceptions.RequestException) as e:
        return return_error('Could not connect to PhishLabs Case API: {}'.format(str(e)))

    if res.status_code < 200 or res.status_code > 300:
        status: int = res.status_code
        message: str = res.reason
        details = ''
        try:
            error_json: dict = res.json()
            message = error_json.get('error', '')
            details = error_json.get('message')
        except Exception:
            pass
        error_message: str = ('Error in API call to PhishLabs Case API, status code: {}'.format(status))
        if status == 401:
            error_message = 'Could not connect to PhishLabs Case API: Wrong credentials'
        if message:
            error_message += ', reason: ' + message
        if details:
            error_message += ', message: ' + details
        if RAISE_EXCEPTION_ON_ERROR:
            raise Exception(error_message)
        else:
            return return_error(error_message)
    try:
        return res.json()
    except Exception:
        error_message = 'Failed parsing the response from PhishLabs Case API: {}'.format(res.content)
        if RAISE_EXCEPTION_ON_ERROR:
            raise Exception(error_message)
        else:
            return return_error(error_message)


def test_module():
    """
    Performs basic get request to get cases
    """
    list_cases_request(limit='1')
    demisto.results('ok')


def list_cases_command():
    """
    Lists the cases in PhishLabs according to provided arguments
    """

    status = argToList(demisto.args().get('status', []))
    case_type = argToList(demisto.args().get('type', []))
    limit = demisto.args().get('limit')
    date_field = demisto.args().get('date_field')
    begin_date = demisto.args().get('begin_date')
    end_date = demisto.args().get('end_date')

    context = {}

    if not date_field and (begin_date or end_date):
        return_error('In order to use the begin_date or end_date filters, a date field must be provided.')

    if status and status[0] == 'Open':
        # Instead of the "open" path
        # TODO: WTF?
        status = ['New', 'Pending Input', 'Assigned']

    response = list_cases_request(status, case_type, limit, date_field, begin_date, end_date)

    cases = response['data'] if response and response.get('data') else []

    if cases:
        if not isinstance(cases, list):
            cases = [cases]

        case_headers: list = ['Title', 'Number', 'Status', 'Description', 'Brand', 'Type', 'CreatedBy', 'CreatedAt',
                              'ModifiedAt', 'ClosedAt', 'ResolutionStatus']

        contents = [{
            'ID': c.get('caseId'),
            'Title': c.get('title'),
            'Status': c.get('caseStatus'),
            'Description': c.get('description'),
            'Number': c.get('caseNumber'),
            'CreatedBy': c.get('createdBy', {}).get('name'),
            'CreatedAt': c.get('dateCreated'),
            'ModifiedAt': c.get('dateModified') if c.get('dateModified', '') != NONE_DATE else '',
            'ClosedAt': c.get('dateClosed') if c.get('dateClosed', '') != NONE_DATE else '',
            'ResolutionStatus': c.get('resolutionStatus'),
            'Brand': c.get('brand'),
            'Type': c.get('caseType')
        } for c in cases]

        human_readable = tableToMarkdown('PhishLabs Cases', contents, headers=case_headers,
                                         headerTransform=pascalToSpace, removeNull=True)
        context = {
            'PhishLabs.Case(val.ID === obj.ID)': createContext(contents, removeNull=True)
        }

    else:
        human_readable = 'No cases found'

    return_outputs(human_readable, context, response)


@logger
def list_cases_request(status=None, case_type=None, limit=None, date_field=None, begin_date=None, end_date=None):
    """
    Sends a request to PhishLabs global feed with the provided arguments
    :param status: Filter by case status
    :param limit: Limit the number of rows to return
    :param case_type: Filter cases by case type
    :param date_field: Field to use with begin_date and end_date parameters.
    :param begin_date: Date query begin date
    :param end_date: Date query end date
    :return: PhishLabs cases
    """
    path: str = 'data/cases'
    params: dict = {}

    if status:
        params['caseStatus'] = ','.join(status)
    if limit:
        params['maxRecords'] = limit
    if case_type:
        params['caseType'] = ','.join(case_type)
    if date_field:
        params['dateField'] = date_field
        if begin_date:
            params['beginDate'] = begin_date
        if end_date:
            params['endDate'] = end_date

    response = http_request('get', path, params)

    return response


@logger
def get_feed_request(since: str = None, limit: str = None, indicator: list = None,
                     remove_protocol: str = None, remove_query: str = None,
                     offset: str = None, sort: bool = False) -> dict:
    """
    Sends a request to PhishLabs user feed with the provided arguments
    :param since: Data updated within this duration of time from now
    :param limit: Limit the number of rows to return
    :param indicator: Indicator type filter
    :param remove_protocol: Removes the protocol part from indicators when the rule can be applied.
    :param remove_query: Removes the query string part from indicators when the rules can be applied.
    :param offset: Number of incidents to skip
    :param sort: If true, the incidents will be sorted by their creation time in ascending order.
    :return: User feed
    """
    path: str = 'feed'
    params: dict = {}

    if since:
        params['since'] = since
    if limit:
        params['limit'] = int(limit)
    if offset:
        params['offset'] = int(offset)
    if indicator:
        params['indicator'] = indicator
    if remove_query:
        params['remove_query'] = remove_query
    if remove_protocol:
        params['remove_protocol'] = remove_protocol

    if sort:
        params['sort'] = 'created_at'
        params['direction'] = 'asc'

    response = http_request('GET', path, params)

    return response


def fetch_incidents():
    """
    Fetches incidents from the PhishLabs user feed.
    :return: Demisto incidents
    """
    last_run: dict = demisto.getLastRun()
    last_fetch: str = last_run.get('time', '') if last_run else ''
    last_offset: str = last_run.get('offset', '0') if last_run else '0'

    incidents: list = []
    count: int = 1
    limit = int(FETCH_LIMIT)
    feed: dict = get_feed_request(limit=FETCH_LIMIT, since=FETCH_TIME, offset=last_offset, sort=True)
    last_fetch_time: datetime = (datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ') if last_fetch
                                 else datetime.strptime(NONE_DATE, '%Y-%m-%dT%H:%M:%SZ'))
    max_time: datetime = last_fetch_time
    results: list = feed.get('data', []) if feed else []

    if results:
        if not isinstance(results, list):
            results = [results]

        for result in results:
            if count > limit:
                break
            incident_time: datetime = datetime.strptime(result.get('createdAt', NONE_DATE), '%Y-%m-%dT%H:%M:%SZ')
            if last_fetch_time and incident_time <= last_fetch_time:
                continue

            incident: dict = {
                'name': 'PhishLabs IOC Incident ' + result.get('referenceId'),
                'occurred': datetime.strftime(incident_time, '%Y-%m-%dT%H:%M:%SZ'),
                'rawJSON': json.dumps(result)
            }
            incidents.append(incident)
            if max_time < incident_time:
                max_time = incident_time
            count += 1

        demisto.incidents(incidents)
        offset = int(last_offset) + count
        demisto.setLastRun({'time': datetime.strftime(max_time, '%Y-%m-%dT%H:%M:%SZ'), 'offset': str(offset)})


''' MAIN'''


def main():
    """
    Main function
    """
    global RAISE_EXCEPTION_ON_ERROR
    LOG('Command being called is {}'.format(demisto.command()))
    handle_proxy()
    command_dict = {
        'test-module': test_module,
        'fetch-incidents': fetch_incidents,
        'phishlabs-list-cases': list_cases_command
    }
    try:
        command_func: Callable = command_dict[demisto.command()]
        if demisto.command() == 'fetch-incidents':
            RAISE_EXCEPTION_ON_ERROR = True
        command_func()

    except Exception as e:
        if RAISE_EXCEPTION_ON_ERROR:
            LOG(str(e))
            LOG.print_log()
            raise
        else:
            return_error(str(e))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
