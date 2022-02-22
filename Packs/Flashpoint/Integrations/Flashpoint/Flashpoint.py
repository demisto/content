from CommonServerPython import *

""" IMPORTS """
import re
import ipaddress
import requests
import urllib.parse
from typing import Dict, Tuple, List, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" CONSTANTS """

FIRST_FETCH = "3 days"
MAX_FETCH = 15
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 1000
MAX_PRODUCT = 10000
DEFAULT_SORT_ORDER = 'asc'
DEFAULT_FETCH_TYPE = 'Compromised Credentials'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
READABLE_DATE_FORMAT = '%b %d, %Y  %H:%M'
BRAND = 'Flashpoint'

IS_FRESH_VALUES = ['true', 'false']
SORT_ORDER_VALUES = ['asc', 'desc']
SORT_DATE_VALUES = ['created_at', 'first_observed_at']
FILTER_DATE_VALUES = ['created_at', 'first_observed_at']

FLASHPOINT_PATHS = {
    'IP': 'Flashpoint.IP.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Url': 'Flashpoint.URL.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Domain': 'Flashpoint.Domain.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Email': 'Flashpoint.Email.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'File': 'Flashpoint.File.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Filename': 'Flashpoint.Filename.Event(val.Fpid && val.Fpid == obj.Fpid)',
    'Event': 'Flashpoint.Event(val.EventId == obj.EventId)',
    'Report': 'Flashpoint.Report(val.ReportId == obj.ReportId)',
    'Forum': 'Flashpoint.Forum(val.ForumId == obj.ForumId)',
    'Room': 'Flashpoint.Forum.Room(val.RoomId == obj.RoomId)',
    'User': 'Flashpoint.Forum.User(val.UserId == obj.UserId)',
    'Post': 'Flashpoint.Forum.Post(val.PostId == obj.PostId)',
    'Site': 'Flashpoint.Forum.Site(val.SiteId == obj.SiteId)',
    'ALERT': 'Flashpoint.Alerts(val.alert_id == obj.alert_id && val.fpid == obj.fpid)',
    'TOKEN': 'Flashpoint.PageToken.Alert(val.name == obj.name)',
}

URL_SUFFIX = {
    'COMPROMISED_CREDENTIALS': '/all/search'
}

URL_SUFFIX_V1 = {
    'ALERTS': '/api/alerting/v1/alerts'
}

MESSAGES = {
    "INVALID_MAX_FETCH": "{} is an invalid value for maximum fetch. Maximum fetch must be between 1 to 100 for alerts "
                         "and between 1 to 1000 for compromised credentials.",
    "INVALID_FIRST_FETCH": "Argument 'First fetch time interval' should be a valid date or relative timestamp such as "
                           "'2 days', '2 months', 'yyyy-mm-dd', 'yyyy-mm-ddTHH:MM:SSZ'",
    "SIZE_ERROR": "{} is an invalid value for size. Size must be between 1 to 100.",
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "PAGE_SIZE_ERROR": "{} is an invalid value for the page size. The page size must be between 1 to {}.",
    "PAGE_NUMBER_ERROR": "{} is an invalid value for the page number. The page number must be greater than 0.",
    "PRODUCT_ERROR": "The multiplication of the page_size and the page_number parameters cannot exceed {}. "
                     "Current multiplication is {}.",
    "START_DATE_ERROR": "Requires the start_date argument along with the end_date argument.",
    "FILTER_DATE_ERROR": "{} is an invalid value for filter date. Filter date value must be of {}.",
    "SORT_DATE_ERROR": "{} is an invalid value for the sort date. The sort date value must be of {}.",
    "SORT_ORDER_ERROR": "{} is an invalid value for the sort order. The sort order value must be of {}.",
    "MISSING_DATE_ERROR": "Requires the argument value for at least the 'start_date' argument.",
    "MISSING_FILTER_DATE_ERROR": "Requires the filter_date argument's value when the start_date or the "
                                 "end_date argument is provided.",
    "MISSING_SORT_DATE_ERROR": "Requires sort_date value when sort_order is provided.",
    "IS_FRESH_ERROR": "{} is an invalid value for is fresh. Is fresh value must be of {}.",
    "MISSING_DATA": "{} response contains incorrect or missing data.",
    "TIME_RANGE_ERROR": "The maximum records to fetch in first fetch can not exceed 10000. Current records are {}. "
                        "Try decreasing the time interval."
}


class Client:
    """
    Client to use in integration with powerful http_request.
    :type api_key: ``str``
    :param api_key: Use to authenticate request in header

    :type url: ``str``
    :param url: Base server address with suffix, for example: https://example.com.

    :type verify: ``Boolean``
    :param verify: Use to indicate secure/insecure http request

    :type proxies: ``dict``
    :param proxies: proxies dict for http request

    :type create_relationships: ``bool``
    :param create_relationships: True if integration will create relationships

    :return response of request
    :rtype ``dict``
    """

    def __init__(self, api_key, url, verify, proxies, create_relationships):
        self.url = url
        self.api_key = api_key
        self.verify = verify
        self.proxies = proxies
        self.create_relationships = create_relationships

    def http_request(self, method, url_suffix, params=None):
        """
        Get http response based on url and given parameters.

        :param method: Specify http methods
        :param url_suffix: url encoded url suffix
        :param params: None
        :return: http response on json
        """
        base_url = self.url + "/api/v4"
        full_url = base_url + url_suffix

        # over writing full URL as we are adding support for v1 endpoints
        if url_suffix in URL_SUFFIX_V1.values():
            full_url = self.url + url_suffix

        headers = {
            'Authorization': self.api_key
        }

        resp = requests.request(
            method,
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            params=params,
            headers=headers
        )

        status_code = resp.status_code

        resp_json = resp.json()

        if status_code != 200:
            if status_code == 400:
                raise ValueError(
                    "Invalid argument value while trying to get information from Flashpoint: " + resp_json.get(
                        'detail', resp_json.get('message', 'N/A')))
            elif status_code == 401:
                raise ValueError(
                    "Encountered error while trying to get information from Flashpoint: Invalid API Key is "
                    "configured")
            elif status_code == 404:
                raise ValueError("No record found for given argument(s): Not Found")
            elif status_code in (521, 403):
                raise ValueError("Test connectivity failed. Please provide valid input parameters.")
            else:
                resp.raise_for_status()

        return resp_json


''' HELPER FUNCTIONS '''


def get_apikey():
    """ Get API Key from the command argument"""
    api_key = demisto.params()["api_key"]

    return api_key


def get_url_suffix(query):
    """
    Create url-suffix using the query value with url encoding

    :param query: value of query param
    :return: url-encoded url-suffix
    """
    return r'/indicators/simple?query=' + urllib.parse.quote(query.encode('utf8'))


def prepare_args_for_fetch_alerts(max_fetch: int, start_time: str, last_run: dict) -> dict:
    """
    Function to prepare arguments for fetching alerts

    :param max_fetch: Maximum number of incidents per fetch
    :param start_time: Date time to start fetching incidents from
    :param last_run: Dictionary containing last run objects

    :return: Dictionary of fetch arguments
    """
    fetch_params: Dict[str, Any] = {}

    if max_fetch < 1 or max_fetch > 100:
        raise ValueError(MESSAGES['INVALID_MAX_FETCH'].format(max_fetch))

    fetch_params['size'] = max_fetch
    fetch_params['since'] = last_run.get('since', start_time)
    fetch_params['scroll_id'] = last_run.get('scroll_id')

    return fetch_params


def prepare_args_for_fetch_compromised_credentials(max_fetch: int, start_time: str, is_fresh: bool,
                                                   last_run: dict) -> dict:
    """
    Function to prepare arguments for fetching compromised credentials

    :param max_fetch: Maximum number of incidents per fetch
    :param start_time: Date time to start fetching incidents from
    :param is_fresh: Boolean value showing whether to fetch the fresh compromised credentials or not
    :param last_run: Dictionary containing last run objects

    :return: Dictionary of fetch arguments
    """
    fetch_params: Dict[str, Any] = {}

    if max_fetch < 1 or max_fetch > MAX_PAGE_SIZE:
        raise ValueError(MESSAGES['INVALID_MAX_FETCH'].format(max_fetch))
    fetch_params['limit'] = max_fetch

    if not last_run.get('fetch_count'):
        last_run['fetch_count'] = 0

    if not last_run.get('fetch_sum'):
        last_run['fetch_sum'] = 0

    fetch_params['skip'] = last_run['fetch_sum']

    total = last_run.get('total')
    if total:
        fetch_sum = fetch_params['limit'] + fetch_params['skip']
        if fetch_sum > total:
            fetch_params['limit'] = total - fetch_params['skip']
    last_run['fetch_sum'] = fetch_params['limit'] + fetch_params['skip']

    start_time = arg_to_datetime(start_time)
    start_time = datetime.timestamp(start_time)  # type: ignore

    if last_run['fetch_count'] == 0:
        end_time = arg_to_datetime('now')
        last_run['end_time'] = end_time.strftime(DATE_FORMAT)  # type: ignore
    else:
        end_time = last_run['end_time']
        end_time = arg_to_datetime(end_time)
    end_time = datetime.timestamp(end_time)  # type: ignore

    query = '+basetypes:(credential-sighting)'
    query += f' +header_.indexed_at: [{int(start_time)} TO {int(end_time)}]'  # type: ignore

    if is_fresh:
        query += ' +is_fresh:true'

    fetch_params['query'] = query
    fetch_params['sort'] = 'header_.indexed_at:asc'

    return fetch_params


def validate_fetch_incidents_params(params: dict, last_run: dict) -> Dict:
    """
    Function to validate the parameter list for fetch incidents

    :param params: Dictionary containing demisto configuration parameters
    :param last_run: last run returned by function demisto.getLastRun

    :return: Dictionary containing validated configuration parameters in proper format.
    """
    fetch_params = {}

    fetch_type = params.get('fetch_type', DEFAULT_FETCH_TYPE)
    if not fetch_type:
        fetch_type = DEFAULT_FETCH_TYPE

    first_fetch = arg_to_datetime(params.get('first_fetch', FIRST_FETCH))
    if first_fetch is None:
        raise ValueError(MESSAGES['INVALID_FIRST_FETCH'])
    start_time = first_fetch.strftime(DATE_FORMAT)

    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')  # type: ignore

    is_fresh = argToBoolean(params.get('is_fresh_compromised_credentials', 'true'))

    max_fetch = arg_to_number(params.get('max_fetch', MAX_FETCH))
    if max_fetch is None:
        raise ValueError(MESSAGES['INVALID_MAX_FETCH'].format(max_fetch))

    if fetch_type == 'Alerts':
        fetch_params = prepare_args_for_fetch_alerts(max_fetch, start_time, last_run)
    elif fetch_type == DEFAULT_FETCH_TYPE:
        fetch_params = prepare_args_for_fetch_compromised_credentials(max_fetch, start_time,
                                                                      is_fresh, last_run)  # type: ignore

    remove_nulls_from_dictionary(fetch_params)

    return {
        'fetch_type': fetch_type,
        'start_time': start_time,
        'fetch_params': fetch_params
    }


def parse_indicator_response(indicators):
    """
    Extract Flashpoint event details and href values from each of the indicator in an indicator list

    :param indicators: list of indicators
    :return: dict containing event details and href
    """
    events = []
    hrefs = []
    attack_ids = []
    for indicator in indicators:
        hrefs.append(indicator.get('Attribute', {}).get('href', ''))

        event = indicator.get('Attribute', {}).get('Event', {})
        attack_ids = event.get('attack_ids', [])
        tags_list = [tag for tag in event['Tags']]
        tags_value = ', '.join(tags_list)

        observed_time = time.strftime(READABLE_DATE_FORMAT, time.gmtime(float(event['timestamp'])))

        events.append({
            'Date Observed (UTC)': observed_time,
            'Name': event.get('info', ''),
            'Tags': tags_value,
        })

    return {'events': events, 'href': hrefs, 'attack_ids': attack_ids}


def parse_event_response(client, event, fpid, href):
    """
    Prepare required event json object from event response

    :param href: reference link of event
    :param fpid: unique id of event. i.e EventId
    :param client: object of client class
    :param event: event indicator from response
    :return: required event json object
    """
    observed_time = time.strftime(READABLE_DATE_FORMAT, time.gmtime(float(event['timestamp'])))
    name = event.get('info', '')
    uuid = event.get('uuid', '')
    if uuid:
        fp_link = client.url + '/home/technical_data/iocs/items/' + uuid
        name_str = '[{}]({})'.format(name, fp_link)
    else:
        name_str = name

    tags_list = [tag['name'] for tag in event.get('Tag', [])]
    tags_value = ', '.join(tags_list)

    event_creator_email = event.get('event_creator_email', '')

    event = {
        'Observed time (UTC)': observed_time,
        'Name': name_str,
        'Tags': tags_value,
        'EventCreatorEmail': event_creator_email,
        'EventId': fpid,
        'Href': href
    }

    return event


def parse_forum_response(resp):
    """
    Prepare forum json object from forum response

    :param resp: forum response
    :return: required forum json object
    """
    name = resp.get('name', '')
    hostname = resp.get('hostname', '')

    tags_list = [tag['name'] for tag in resp['tags']]
    tags_value = ', '.join(tags_list)

    forum_details = {
        'Name': name,
        'Hostname': hostname,
        'Tags': tags_value
    }

    return forum_details


def get_post_context(resp):
    """
    Prepare context data for forum post

    :param resp: forum post api response
    :return: dict object
    """
    post_ec = {
        'PostId': resp['id'],
        'PublishedAt': resp.get('published_at', ''),
        'Url': resp.get('url', ''),
        'PlatformUrl': resp.get('platform_url', ''),
        'Forum': resp['embed']['forum'],
        'Room': resp['embed']['room'],
        'User': resp['embed']['author']
    }

    return post_ec


def reputation_operation_command(client, indicator, func, command_results=False):
    """
    Common method for reputation commands to accept argument as a comma-separated values and converted into list
    and call specific function for all values.

    :param client: object of client class
    :param indicator: comma-separated values or single value
    :param func: reputation command function. i.e file_lookup, domain_lookup etc.
    :param command_results: if the result of the func returns CommandResults object.
    :return: output of all value according to specified function.
    """
    args = argToList(indicator, ',')
    for arg in args:
        if command_results:
            return_results(func(client, arg))
        else:
            return_outputs(*func(client, arg))


def replace_key(dictionary, new_key, old_key):
    """
    This method is used for replace key in dictionary.

    :param dictionary: dictionary object on which we wan to replace key.
    :param new_key: key which will replace in dictionary
    :param old_key: existing key in dictionary
    :return: dict object
    """
    if dictionary.get(old_key):
        dictionary[new_key] = dictionary.pop(old_key)
    return dictionary


def validate_alert_list_args(args: dict) -> dict:
    """
    Validate arguments for flashpoint-alert-list command, raise ValueError on invalid arguments.

    :param args: The command arguments

    :return: Validated dictionary of arguments
    """
    params = {}

    size = arg_to_number(args.get('size', 50))
    if size is None or size < 1 or size > 100:  # type: ignore
        raise ValueError(MESSAGES['SIZE_ERROR'].format(size))
    params['size'] = size

    since = arg_to_datetime(args.get('since'))
    if since:
        params['since'] = since.strftime(DATE_FORMAT)  # type: ignore

    until = arg_to_datetime(args.get('until'))
    if until:
        params['until'] = until.strftime(DATE_FORMAT)  # type: ignore

    params['scroll_id'] = args.get('scroll_id')  # type: ignore

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_alerts(alerts: List) -> str:
    """
    Prepare human readable format for alerts

    :param alerts: List of alerts

    :return: Human readable format of alerts
    """
    table1_hr = []
    table2_hr = []

    for alert in alerts:
        fpid = alert.get('fpid', '')
        keyword_text = alert.get('keyword', {}).get('keyword_text')
        source_created_at = alert.get("source", {}).get("created_at", {}).get('date-time')
        source_last_observed_at = alert.get("source", {}).get("last_observed_at", {}).get('date-time')

        # For Flashpoint Collected sources, created_at or last_observed_at would be present under source.
        if source_created_at or source_last_observed_at:
            source_created_at = arg_to_datetime(source_created_at)
            if source_created_at:
                source_created_at = source_created_at.strftime(READABLE_DATE_FORMAT)

            source_last_observed_at = arg_to_datetime(source_last_observed_at)
            if source_last_observed_at:
                source_last_observed_at = source_last_observed_at.strftime(READABLE_DATE_FORMAT)

            data = {
                'FPID': fpid,
                'Keyword Text': keyword_text,
                'Site Title': alert.get('source', {}).get('site', {}).get('title'),
                'Created Date (UTC)': source_created_at,
                'Last Observed Date (UTC)': source_last_observed_at
            }
            table1_hr.append(data)
        source_file = alert.get("source", {}).get("file")
        source_repo = alert.get("source", {}).get("repo")

        # Flashpoint Alerts with Data exposures expects file or repo under source
        if source_file or source_repo:
            data = {
                'FPID': fpid,
                'Keyword Text': keyword_text,
                'File': alert.get('source', {}).get('file'),
                'Owner': alert.get('source', {}).get('owner'),
                'Repo': alert.get('source', {}).get('repo'),
                'Source': alert.get('source', {}).get('source'),
            }
            table2_hr.append(data)

        elif not source_created_at and not source_last_observed_at and not source_file and not source_repo:
            raise ValueError(MESSAGES['MISSING_DATA'].format('Alerts'))

    headers1 = ['FPID', 'Keyword Text', 'Site Title', 'Created Date (UTC)', 'Last Observed Date (UTC)']
    headers2 = ['FPID', 'Keyword Text', 'File', 'Owner', 'Repo', 'Source']
    table1 = tableToMarkdown("Alerts from Flashpoint collected sources.", table1_hr, headers1, removeNull=True)
    table2 = tableToMarkdown("Alerts with data exposures.", table2_hr, headers2, removeNull=True)
    return table1 + table2


def validate_page_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Function to validate page_size and page_number for flashpoint-compromised-credentials-list command

    :param args: The command arguments
    :param params: Dictionary of parameters

    :return: None
    """
    page_size = arg_to_number(args.get('page_size', DEFAULT_PAGE_SIZE))
    if page_size is None or page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ValueError(MESSAGES['PAGE_SIZE_ERROR'].format(page_size, MAX_PAGE_SIZE))

    page_number = arg_to_number(args.get('page_number', 1))
    if page_number is None or page_number < 1:
        raise ValueError(MESSAGES['PAGE_NUMBER_ERROR'].format(page_number))

    product = page_size * page_number
    if product > MAX_PRODUCT:
        raise ValueError(MESSAGES['PRODUCT_ERROR'].format(MAX_PRODUCT, product))

    params['skip'] = page_size * (page_number - 1)  # type: ignore
    params['limit'] = page_size  # type: ignore


def validate_date_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Function to validate start_date, end_date, and filter_date for flashpoint-compromised-credentials-list command

    :param args: The command arguments
    :param params: Dictionary of parameters

    :return: None
    """
    start_date = arg_to_datetime(args.get('start_date'))
    end_date = arg_to_datetime(args.get('end_date'))

    if end_date and not start_date:
        raise ValueError(MESSAGES['START_DATE_ERROR'])

    if start_date and not end_date:
        end_date = arg_to_datetime('now')

    filter_date = args.get('filter_date')
    if filter_date:
        if filter_date not in FILTER_DATE_VALUES:
            raise ValueError(MESSAGES['FILTER_DATE_ERROR'].format(filter_date, FILTER_DATE_VALUES))
        if not (start_date or end_date):
            raise ValueError(MESSAGES['MISSING_DATE_ERROR'])
        date_query = ' +breach.{}.date-time: [{} TO {}]'.format(filter_date,
                                                                start_date.strftime(DATE_FORMAT),  # type: ignore
                                                                end_date.strftime(DATE_FORMAT))  # type: ignore
        params['query'] += date_query
    elif start_date or end_date:
        raise ValueError(MESSAGES['MISSING_FILTER_DATE_ERROR'])


def validate_sort_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Function to validate sort_order and sort_date for flashpoint-compromised-credentials-list command

    :param args: The command arguments
    :param params: Dictionary of parameters

    :return: None
    """
    sort_order = args.get('sort_order')
    if sort_order and sort_order not in SORT_ORDER_VALUES:
        raise ValueError(MESSAGES['SORT_ORDER_ERROR'].format(sort_order, SORT_ORDER_VALUES))

    sort_date = args.get('sort_date')
    if sort_date:
        if sort_date not in SORT_DATE_VALUES:
            raise ValueError(MESSAGES['SORT_DATE_ERROR'].format(sort_date, SORT_DATE_VALUES))
        if not sort_order:
            sort_order = DEFAULT_SORT_ORDER
        params['sort'] = f'breach.{sort_date}.timestamp:{sort_order}'
    elif sort_order:
        raise ValueError(MESSAGES['MISSING_SORT_DATE_ERROR'])


def validate_compromised_credentials_list_args(args: dict) -> dict:
    """
    Validate arguments for flashpoint-compromised-credentials-list command, raise ValueError on invalid arguments.

    :param args: The command arguments

    :return: Validated dictionary of arguments
    """
    params = {'query': '+basetypes:(credential-sighting)'}

    validate_page_parameters_for_compromised_credentials(args, params)

    validate_date_parameters_for_compromised_credentials(args, params)

    validate_sort_parameters_for_compromised_credentials(args, params)

    is_fresh = args.get('is_fresh')
    if is_fresh:
        if is_fresh not in IS_FRESH_VALUES:
            raise ValueError(MESSAGES['IS_FRESH_ERROR'].format(is_fresh, IS_FRESH_VALUES))
        params['query'] += f' +is_fresh:{is_fresh}'

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_compromised_credentials(hits: list) -> str:
    """
    Prepare human readable format for compromised credentials

    :param hits: List of compromised credentials

    :return: Human readable format of compromised credentials
    """
    hr = []
    for hit in hits:
        source = hit.get('_source', {})
        created_date = source.get('breach', {}).get('created_at', {}).get('date-time')
        created_date = arg_to_datetime(created_date)
        if created_date:
            created_date = created_date.strftime(READABLE_DATE_FORMAT)  # type: ignore

        first_observed_date = source.get('breach', {}).get('first_observed_at', {}).get('date-time')
        first_observed_date = arg_to_datetime(first_observed_date)
        if first_observed_date:
            first_observed_date = first_observed_date.strftime(READABLE_DATE_FORMAT)  # type: ignore

        data = {
            'FPID': source.get('fpid', ''),
            'Email': source.get('email', ''),
            'Breach Source': source.get('breach', {}).get('source'),
            'Breach Source Type': source.get('breach', {}).get('source_type'),
            'Password': source.get('password'),
            'Created Date (UTC)': created_date,
            'First Observed Date (UTC)': first_observed_date
        }
        hr.append(data)

    return tableToMarkdown("Compromised Credential(s)", hr, ['FPID', 'Email', 'Breach Source', 'Breach Source Type',
                                                             'Password', 'Created Date (UTC)',
                                                             'First Observed Date (UTC)'], removeNull=True)


def remove_duplicate_records(records: List, fetch_type: str, next_run: dict) -> List:
    """
    Function to check for duplicate records and remove them from the list

    :param records: List of records
    :param fetch_type: Type of the records
    :param next_run: Dictionary to set in last run

    :return: Updated list of alerts
    """
    last_run_key = ''
    id_key = ''
    if fetch_type == 'Alerts':
        last_run_key = 'alert_ids'
        id_key = 'alert_id'
    elif fetch_type == DEFAULT_FETCH_TYPE:
        last_run_key = 'hit_ids'
        id_key = '_id'

    if next_run.get(last_run_key):
        prev_alert_ids = next_run[last_run_key]
        records = [i for i in records if i[id_key] not in prev_alert_ids]

    return records


def update_alert_body(alert: dict) -> None:
    """
    Function to add highlight to keyword text

    :param alert: The alert object

    :return: None
    """
    keyword = alert.get("keyword", {}).get("keyword_text", "").replace('\"', "")
    body = alert.get("source", {}).get("body", {}).get("text/plain")
    if body:
        alert["source"]["body"]["text/plain"] = re.sub(keyword, f"<mark>{keyword}</mark>", body, flags=re.IGNORECASE)


def prepare_context_from_next_href(links: str) -> Dict:
    """
    Function to prepare context from href

    :param links: Link with the arguments

    :return: Context data made from link
    """
    arg_split = links.split('?')
    context = urllib.parse.parse_qs(arg_split[1])
    return context


def prepare_incidents_from_alerts_data(response: dict, next_run: dict, start_time: str) -> Tuple[dict, list]:
    """
    Function to prepare incidents from the alerts data

    :param response: Response from the alerts API
    :param next_run: Dictionary to set in last run
    :param start_time: Date time saved of the latest alert

    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    incidents = []
    alerts = response.get('data', [])

    alert_ids = [alert['alert_id'] for alert in alerts]
    alerts = remove_duplicate_records(alerts, 'Alerts', next_run)

    for alert in alerts:
        created_timestamp = alert.get("ts")
        if created_timestamp:
            update_alert_body(alert)
            created_at = datetime.utcfromtimestamp(float(created_timestamp))
            created_at = created_at.strftime(DATE_FORMAT)  # type: ignore

            keyword_text = alert.get('keyword', {}).get('keyword_text', 'Flashpoint Alert')

            incidents.append({
                'name': f"{keyword_text}",
                'occurred': created_at,
                'rawJSON': json.dumps(alert)
            })

            if created_at >= start_time:
                start_time = created_at
        else:
            demisto.error("The incident was ignored because it doesn't contain 'ts' timestamp")

    if alerts:
        next_run['start_time'] = start_time
        if not next_run.get('scroll_id'):
            next_run['alert_ids'] = alert_ids

    links = response.get('links', {}).get('next', {}).get('href')
    if links:
        context = prepare_context_from_next_href(links)
        for con in context:
            next_run[con] = context[con][0]
    else:
        # When no more data is present for current request. So, update the start time and make scroll_id as null.
        next_run['scroll_id'] = None
        next_run['since'] = start_time

    return next_run, incidents


def check_value_of_total_records(total: Any, next_run: dict) -> None:
    """
    Function to check if total number of records are more than the limit or not

    :param total: Total number of records
    :param next_run: Dictionary to set in last run

    :return: None
    """
    if total:
        if total > MAX_PRODUCT:  # type: ignore
            raise ValueError(MESSAGES['TIME_RANGE_ERROR'].format(total))
        next_run['total'] = total


def prepare_checkpoint_and_related_objects(hits: List, hit_ids: List, next_run: dict) -> None:
    """
    Function to prepare checkpoint and related objects for incidents of type compromised credentials

    :param hits: List of compromised credentials
    :param hit_ids: List of ids of compromised credentials
    :param next_run: Dictionary to set in last run

    :return: None
    """
    indexed_at = hits[-1].get('_source', {}).get('header_', {}).get('indexed_at')
    indexed_at_date = datetime.utcfromtimestamp(float(indexed_at))
    indexed_at_date = indexed_at_date.strftime(DATE_FORMAT)
    next_run['last_time'] = indexed_at_date

    if next_run.get('last_timestamp'):
        if next_run['last_timestamp'] == indexed_at:
            next_run['hit_ids'] += hit_ids
        else:
            next_run['hit_ids'] = hit_ids
    else:
        next_run['hit_ids'] = hit_ids

    next_run['last_timestamp'] = indexed_at


def prepare_next_run_when_data_is_present(next_run: dict, start_time: str) -> None:
    """
    Function to prepare next run when data is present

    :param next_run: Dictionary to set in last run
    :param start_time:  Date time saved of the last fetch

    :return: None
    """
    next_run['start_time'] = start_time
    next_run['fetch_count'] = next_run['fetch_count'] + 1


def prepare_next_run_when_data_is_empty(next_run: dict, hits: List) -> None:
    """
    Function to prepare next run when data is present

    :param next_run: Dictionary to set in last run
    :param hits: List of compromised credentials

    :return: None
    """
    if hits:
        next_run['start_time'] = next_run['last_time']
    next_run['fetch_count'] = 0
    next_run['fetch_sum'] = 0
    next_run['total'] = None


def prepare_incidents_from_compromised_credentials_data(response: dict, next_run: dict,
                                                        start_time: str) -> Tuple[dict, list]:
    """
    Function to prepare incidents from the compromised credentials data

    :param response: Response from the compromised credentials API
    :param next_run: Dictionary to set in last run
    :param start_time: Date time saved of the last fetch

    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    incidents = []
    total = arg_to_number(response.get('hits', {}).get('total'))
    check_value_of_total_records(total, next_run)

    hits = response.get('hits', {}).get('hits', [])

    hit_ids = [hit['_id'] for hit in hits]
    hits = remove_duplicate_records(hits, DEFAULT_FETCH_TYPE, next_run)

    for hit in hits:
        name = hit.get('_source', {}).get('email')
        if not name:
            name = hit.get('_source', {}).get('fpid', 'Compromised Credential Alert')
        incidents.append({
            'name': name,
            'occurred': hit.get('_source', {}).get('breach', {}).get('created_at', {}).get('date-time'),
            'rawJSON': json.dumps(hit)
        })

    if hits:
        prepare_checkpoint_and_related_objects(hits, hit_ids, next_run)

    if total > next_run['fetch_sum']:
        # If more records are available, then increase the fetch count
        prepare_next_run_when_data_is_present(next_run, start_time)
    else:
        prepare_next_run_when_data_is_empty(next_run, hits)

    return next_run, incidents


''' FUNCTIONS '''


def test_module(client: Client, params: Dict) -> None:
    """
    Tests the Flashpoint instance configuration

    :param: client: Object of Client class
    :param: params: Dictionary containing demisto configuration parameters
    :return: None
    """
    client.http_request(method="GET", url_suffix='/indicators/simple', params={"limit": 1})
    is_fetch = params.get('isFetch')
    if is_fetch:
        fetch_incidents(client, {}, params)


def ip_lookup_command(client, ip):
    """
    'ip' command to lookup a particular ip-address
    This command searches for the ip in Flashpoint's IOC Dataset. If found, mark it as Malicious.
    If not found, lookup in Torrents for matching peer ip. If found, mark it as Suspicious.
    If not found, lookup in Forums for matching ip. If found, mark it as Suspicious.


    :param client: object of client class
    :param ip: ip-address
    :return: command output
    """
    if not is_ip_valid(ip, True):
        raise ValueError("Invalid ip - " + ip)

    query = r'+type:("ip-src","ip-dst") +value.\*:"' + urllib.parse.quote(ip.encode('utf-8')) + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint IP address reputation for ' + ip + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        # Constructing FP Deeplink
        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=ip-dst%2Cip-src&ioc_value=' + ip
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)
        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name=BRAND,
            score=3,
            malicious_description='Found in malicious indicators dataset'

        )
        relationships = []
        if client.create_relationships:
            if events_details.get('attack_ids'):
                for attack_id in events_details.get('attack_ids'):
                    relationships.append(
                        EntityRelationship(name='indicator-of',
                                           entity_a=ip,
                                           entity_a_type=FeedIndicatorType.IP,
                                           entity_b=attack_id,
                                           entity_b_type=FeedIndicatorType.indicator_type_by_server_version(
                                               'STIX Attack Pattern'),
                                           brand=BRAND))

        ip_ioc = Common.IP(ip=ip, dbot_score=dbot_score, relationships=relationships)

        flashpoint_ip_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'Address': ip,
                'EventDetails': indicator.get('Event'),
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_ip_context.append(event)

        command_results = CommandResults(
            outputs_prefix='Flashpoint.IP.Event',
            outputs_key_field='Fpid',
            outputs=flashpoint_ip_context,
            readable_output=hr,
            indicator=ip_ioc,
            raw_response=resp,
            relationships=relationships
        )
        return command_results

    else:
        # Search for IP in torrents
        torrent_search_url_suffix = '/all/search?query=+basetypes:(+torrent) +is_verified:true ' \
                                    '+ip_address:("' + urllib.parse.quote(ip.encode('utf-8')) + \
                                    '")&limit=10&_source_includes=ip_address'
        torrent_resp = client.http_request("GET", url_suffix=torrent_search_url_suffix)
        torrent_result = torrent_resp.get('hits').get('hits', [])

        if torrent_result:
            torrent_search_link = client.url + '/home/search/torrents?ip_address=' + ip

            hr = '### Flashpoint IP address reputation for ' + ip + '\n'
            hr += 'Reputation: Suspicious\n\n'
            hr += 'FP tools link to torrent search: [{}]({})\n'.format(torrent_search_link, torrent_search_link)

            ec = {
                FLASHPOINT_PATHS['IP']: {
                    "Address": ip
                },
                'DBotScore': {
                    'Indicator': ip,
                    'Type': 'ip',
                    'Vendor': 'Flashpoint',
                    'Score': 2
                }
            }
            command_results = CommandResults(
                outputs=ec,
                readable_output=hr,
                raw_response=resp,
            )
        else:
            # Search for IP in Forums
            forum_search_url_suffix = '/forums/visits?ip_address=' + urllib.parse.quote(ip.encode('utf-8'))
            forum_resp = client.http_request("GET", url_suffix=forum_search_url_suffix)
            forum_result = forum_resp.get('data', [])

            if forum_result:
                forum_search_link = client.url + '/home/search/visits?exclude_tor_nodes_and_known_proxies=true' \
                                                 '&ip_address=' + ip

                hr = '### Flashpoint IP address reputation for ' + ip + '\n'
                hr += 'Reputation: Suspicious\n\n'
                hr += 'FP tools link to Forum-visit search: [{}]({})\n'.format(forum_search_link, forum_search_link)

                ec = {
                    FLASHPOINT_PATHS['IP']: {
                        "Address": ip
                    },
                    'DBotScore': {
                        'Indicator': ip,
                        'Type': 'ip',
                        'Vendor': 'Flashpoint',
                        'Score': 2
                    }
                }
                command_results = CommandResults(
                    outputs=ec,
                    readable_output=hr,
                    raw_response=resp,
                )
            else:
                hr = '### Flashpoint IP address reputation for ' + ip + '\n'
                hr += 'Reputation: Unknown\n\n'
                ec = {
                    'DBotScore': {
                        'Indicator': ip,
                        'Type': 'ip',
                        'Vendor': 'Flashpoint',
                        'Score': 0
                    }
                }
                command_results = CommandResults(
                    outputs=ec,
                    readable_output=hr,
                    raw_response=resp,
                )

        return command_results


def domain_lookup_command(client, domain):
    """
    'domain' command to lookup a particular domain

    :param client: object of client class
    :param domain: domain
    :return: command output
    """
    query = r'+type:("domain") +value.\*.keyword:"' + domain + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint Domain reputation for ' + domain + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=domain&ioc_value=' + domain
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=BRAND,
            score=3,
            malicious_description='Found in malicious indicators dataset'

        )
        relationships = []
        if client.create_relationships:
            if events_details.get('attack_ids'):
                for attack_id in events_details.get('attack_ids'):
                    relationships.append(
                        EntityRelationship(name='indicator-of',
                                           entity_a=domain,
                                           entity_a_type=FeedIndicatorType.Domain,
                                           entity_b=attack_id,
                                           entity_b_type=FeedIndicatorType.indicator_type_by_server_version(
                                               'STIX Attack Pattern'),
                                           brand=BRAND))

        domain_ioc = Common.Domain(domain=domain, dbot_score=dbot_score, relationships=relationships)

        flashpoint_domain_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'Domain': domain,
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type'),
                'Uuid': indicator.get('uuid', ''),
                'EventDetails': indicator.get('Event', []),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_domain_context.append(event)

        command_results = CommandResults(
            outputs_prefix='Flashpoint.Domain.Event',
            outputs_key_field='Fpid',
            outputs=flashpoint_domain_context,
            readable_output=hr,
            indicator=domain_ioc,
            raw_response=resp,
            relationships=relationships
        )
        return command_results

    else:
        hr = '### Flashpoint Domain reputation for ' + domain + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore': {
                'Indicator': domain,
                'Type': 'domain',
                'Vendor': 'Flashpoint',
                'Score': 0
            }
        }
        command_results = CommandResults(
            outputs=ec,
            readable_output=hr,
            raw_response=resp,
        )

        return command_results


def filename_lookup_command(client, filename):
    """
    'filename' command to lookup a particular filename

    :param client: object of client class
    :param filename: filename
    :return: command output
    """
    query = r'+type:("filename") +value.\*.keyword:"' + filename.replace('\\', '\\\\') + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint Filename reputation for ' + filename + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=filename&ioc_value=' + urllib.parse.quote(
            filename.replace('\\', '\\\\').encode('utf8'))
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        dbot_context = {
            'Indicator': filename,
            'Type': 'filename',
            'Vendor': 'Flashpoint',
            'Score': 3
        }

        filename_context = {
            'Name': filename,
            'Malicious': {
                'Vendor': 'Flashpoint',
                'Description': 'Found in malicious indicators dataset'
            }

        }

        flashpoint_filename_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'Filename': filename,
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type'),
                'Uuid': indicator.get('uuid', ''),
                'EventDetails': indicator.get('Event', []),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_filename_context.append(event)

        ec = {
            'DBotScore': dbot_context,
            'Filename(val.Name == obj.Name)': filename_context,
            FLASHPOINT_PATHS['Filename']: flashpoint_filename_context
        }

        return hr, ec, resp

    else:
        hr = '### Flashpoint Filename reputation for ' + filename + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore': {
                'Indicator': filename,
                'Type': 'filename',
                'Vendor': 'Flashpoint',
                'Score': 0
            }
        }

        return hr, ec, resp


def url_lookup_command(client, url):
    """
    'url' command to lookup a particular url

    :param client: object of client class
    :param url: url as indicator
    :return: command output
    """
    encoded_url = urllib.parse.quote(url.encode('utf8'))

    query = r'+type:("url") +value.\*.keyword:"' + url + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint URL reputation for ' + url + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=url&ioc_value=' + encoded_url
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name=BRAND,
            score=3,
            malicious_description='Found in malicious indicators dataset'
        )

        relationships = []
        if client.create_relationships:
            if events_details.get('attack_ids'):
                for attack_id in events_details.get('attack_ids'):
                    relationships.append(
                        EntityRelationship(name='indicator-of',
                                           entity_a=url,
                                           entity_a_type=FeedIndicatorType.URL,
                                           entity_b=attack_id,
                                           entity_b_type=FeedIndicatorType.indicator_type_by_server_version(
                                               'STIX Attack Pattern'),
                                           brand=BRAND))

        url_ioc = Common.URL(url=url, dbot_score=dbot_score, relationships=relationships)

        flashpoint_url_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'Fpid': indicator.get('fpid', ''),
                'EventDetails': indicator['Event'],
                'Category': indicator.get('category', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', ''),
                'Url': indicator['value']['url']
            }
            flashpoint_url_context.append(event)

        command_results = CommandResults(
            outputs_prefix='Flashpoint.URL.Event',
            outputs_key_field='Fpid',
            outputs=flashpoint_url_context,
            readable_output=hr,
            indicator=url_ioc,
            raw_response=resp,
            relationships=relationships
        )
        return command_results

    else:
        hr = '### Flashpoint URL reputation for ' + url + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore': {
                'Indicator': url,
                'Type': 'url',
                'Vendor': 'Flashpoint',
                'Score': 0
            }
        }
        command_results = CommandResults(
            outputs=ec,
            readable_output=hr,
            raw_response=resp,
        )

        return command_results


def file_lookup_command(client, file):
    """
    'file' command to lookup a particular file hash (md5, sha1, sha256, sha512)

    :param client: object of client class
    :param file: file as indicator
    :return: command output
    """

    query = r'+type:("md5", "sha1", "sha256", "sha512") +value.\*.keyword:"' + file + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:
        indicator_type = (indicators[0].get('Attribute', {}).get('type')).upper()
        hr = '### Flashpoint File reputation for ' + file + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=md5%2Csha1%2Csha256%2Csha512' \
                               '&ioc_value=' + urllib.parse.quote(file.encode('utf8'))

        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=file,
            indicator_type=DBotScoreType.FILE,
            integration_name=BRAND,
            score=3,
            malicious_description='Found in malicious indicators dataset'
        )

        relationships = []
        if client.create_relationships:
            if events_details.get('attack_ids'):
                for attack_id in events_details.get('attack_ids'):
                    relationships.append(
                        EntityRelationship(name='indicator-of',
                                           entity_a=file,
                                           entity_a_type=DBotScoreType.FILE,
                                           entity_b=attack_id,
                                           entity_b_type=FeedIndicatorType.indicator_type_by_server_version(
                                               'STIX Attack Pattern'),
                                           brand=BRAND))

        hash_type = get_hash_type(file)  # if file_hash found, has to be md5, sha1 or sha256
        if hash_type == 'md5':
            file_ioc = Common.File(md5=file, dbot_score=dbot_score, relationships=relationships)
        elif hash_type == 'sha1':
            file_ioc = Common.File(sha1=file, dbot_score=dbot_score, relationships=relationships)
        else:
            file_ioc = Common.File(sha256=file, dbot_score=dbot_score, relationships=relationships)

        flashpoint_file_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                str(indicator_type).upper(): file,
                'EventDetails': indicator.get('Event'),
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_file_context.append(event)

        command_results = CommandResults(
            outputs_prefix='Flashpoint.File.Event',
            outputs_key_field='Fpid',
            outputs=flashpoint_file_context,
            readable_output=hr,
            indicator=file_ioc,
            raw_response=resp,
            relationships=relationships
        )
        return command_results

    else:
        hr = '### Flashpoint File reputation for ' + file + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore':
                [
                    {
                        'Indicator': file,
                        'Type': 'file',
                        'Vendor': 'Flashpoint',
                        'Score': 0
                    },
                    {
                        'Indicator': file,
                        'Type': 'hash',
                        'Vendor': 'Flashpoint',
                        'Score': 0
                    }

                ]
        }
        command_results = CommandResults(
            outputs=ec,
            readable_output=hr,
            raw_response=resp,
        )
        return command_results


def email_lookup_command(client, email):
    """
    'email' command to lookup a particular email address or subject

    :param client: object of client class
    :param email: email address or subject
    :return: command output
    """
    query = r'+type:("email-dst", "email-src", "email-src-display-name", "email-subject") +value.\*.keyword:"' \
            + email + '" '
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        hr = '### Flashpoint Email reputation for ' + email + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_type=email-dst%2Cemail-src%2Cemail-src' \
                               '-display-name%2Cemail-subject&ioc_value=' + urllib.parse.quote(email.encode('utf8'))
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        email_context = {
            'Name': email,
            'Malicious': {
                'Vendor': 'Flashpoint',
                'Description': 'Found in malicious indicators dataset'
            }
        }

        dbot_context = {
            'Indicator': email,
            'Type': 'email',
            'Vendor': 'Flashpoint',
            'Score': 3
        }

        flashpoint_email_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                'EventDetails': indicator.get('Event', ''),
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', '')
            }
            flashpoint_email_context.append(event)

        ec = {
            'DBotScore': dbot_context,
            outputPaths['email']: email_context,
            FLASHPOINT_PATHS['Email']: flashpoint_email_context
        }

        return hr, ec, resp

    else:
        hr = '### Flashpoint Email reputation for ' + email + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {
            'DBotScore': {
                'Indicator': email,
                'Type': 'email',
                'Vendor': 'Flashpoint',
                'Score': 0
            }
        }

        return hr, ec, resp


def common_lookup_command(client, indicator_value):
    """
    Command to lookup all types of the indicators

    :param client: object of client class
    :param indicator_value: value of the indicator to lookup
    :return: command output
    """
    encoded_value = urllib.parse.quote(indicator_value.encode('utf8'))

    try:
        ipaddress.ip_address(indicator_value)
        query = r'+type:("ip-src","ip-dst") +value.\*:"' + indicator_value + '"'
    except ValueError:
        try:
            ipaddress.IPv6Address(indicator_value)
            query = r'+type:("ip-src","ip-dst") +value.\*:"' + indicator_value + '"'
        except ValueError:
            query = r'+value.\*.keyword:"' + indicator_value + '"'

    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = resp
    else:
        indicators = []

    if len(indicators) > 0:

        indicator_type = indicators[0].get('Attribute', {}).get('type')

        hr = '### Flashpoint reputation for ' + indicator_value + '\n'
        hr += 'Reputation: Malicious\n\n'

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown('Events in which this IOC observed', events_details['events'],
                              ['Date Observed (UTC)', 'Name', 'Tags'])

        fp_link = client.url + '/home/search/iocs?group=indicator&ioc_value=' + encoded_value
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        ec = {'DBotScore': {
            'Indicator': indicator_value,
            'Type': indicator_type,
            'Vendor': 'Flashpoint',
            'Score': 3
        }}

        return hr, ec, resp

    else:
        hr = '### Flashpoint reputation for ' + indicator_value + '\n'
        hr += 'Reputation: Unknown\n\n'
        ec = {}

        return hr, ec, resp


def get_reports_command(client, report_search):
    """
    Get reports matching the given search term or query

    :param client: object of client class
    :param report_search: search term or query
    :return: command output
    """
    url_suffix = '/reports/?query=' + urllib.parse.quote(report_search) + '&limit=5'
    resp = client.http_request("GET", url_suffix=url_suffix)
    reports = resp.get("data", [])

    hr = '### Flashpoint Intelligence reports related to search: ' + report_search + '\n'
    ec: Dict[Any, Any] = {}

    if reports:
        hr += 'Top 5 reports:\n\n'
        report_details = []
        index = 0
        for report in reports:
            title = report.get('title', 'N/A')
            platform_url = report.get('platform_url', '')
            summary = report.get('summary', 'N/A')
            index += 1
            hr += '' + str(index) + ') [{}]({})'.format(title, platform_url) + '\n'
            if report.get('summary'):
                hr += '   Summary: ' + str(summary) + '\n\n\n'
            else:
                hr += '   Summary: N/A\n\n\n'

            report_detail = {
                'ReportId': report.get('id', 'N/A'),
                'UpdatedAt': report.get('updated_at', ''),
                'PostedAt': report.get('posted_at', ''),
                'NotifiedAt': report.get('notified_at', ''),
                'PlatformUrl': platform_url,
                'Title': title,
                'Summary': summary
            }
            report_details.append(report_detail)

        fp_url = client.url + '/home/search/reports?query=' + urllib.parse.quote(report_search)
        hr += 'Link to Report-search on Flashpoint platform: [{}]({})\n'.format(fp_url, fp_url)

        ec[FLASHPOINT_PATHS['Report']] = report_details

    else:
        hr += 'No reports found for the search.'

    return hr, ec, resp


def get_report_by_id_command(client, report_id):
    """
    Get specific report using its fpid

    :param client: object of client class
    :param report_id: report's fpid
    :return: command output
    """
    url_suffix = '/reports/' + urllib.parse.quote(report_id.encode('utf-8'))
    resp = client.http_request("GET", url_suffix=url_suffix)
    report = resp

    hr = '### Flashpoint Intelligence Report details\n'
    ec: Dict[Any, Any] = {}

    if report:

        if report.get('tags') is None:
            raise ValueError("No record found for given argument(s): Not Found")

        timestamp = None
        try:
            time_str = report.get('posted_at', '')[:-10] + 'UTC'
            timestamp = time.strptime(time_str, '%Y-%m-%dT%H:%M:%S%Z')
        except TypeError:
            pass
        except ValueError:
            pass

        tags = report.get('tags', [])
        tag_string = ""
        for tag in tags:
            tag_string += ", " + str(tag)
        if tag_string:
            tag_string = tag_string[2:]

        if timestamp:
            timestamp_str = time.strftime(READABLE_DATE_FORMAT, timestamp)
        else:
            timestamp_str = 'N/A'

        report_details = [{
            'Title': '[{}]({})'.format(report.get('title', 'N/A'), report.get('platform_url', '')),
            'Date Published (UTC)': timestamp_str,
            'Summary': report.get('summary', 'N/A'),
            'Tags': tag_string
        }]

        hr += tableToMarkdown('Below are the details found:', report_details,
                              ['Title', 'Date Published (UTC)', 'Summary', 'Tags'])
        hr += '\n'
        ec[FLASHPOINT_PATHS['Report']] = {
            'ReportId': report.get('id', ''),
            'UpdatedAt': report.get('updated_at', ''),
            'PostedAt': report.get('posted_at', ''),
            'NotifiedAt': report.get('notified_at', ''),
            'PlatformUrl': report.get('platform_url', ''),
            'Title': report.get('title', ''),
            'Summary': report.get('summary', '')
        }

    else:
        hr += 'No report found for the given ID.'

    return hr, ec, resp


def get_related_reports_command(client, report_id):
    """
    Get reports related to given report

    :param report_id: report id which is related to other reports
    :param client: object of client class
    :return: command output
    """
    url_suffix = '/reports/' + urllib.parse.quote(report_id.encode('utf-8')) + '/related?limit=5'
    resp = client.http_request("GET", url_suffix=url_suffix)
    reports = resp.get("data", [])

    hr = '### Flashpoint Intelligence related reports:\n'
    ec: Dict[Any, Any] = {}

    if reports:
        hr += 'Top 5 related reports:\n\n'
        report_details = []
        index = 0
        for report in reports:
            title = report.get('title', 'N/A')
            platform_url = report.get('platform_url', '')
            summary = report.get('summary', 'N/A')
            index += 1
            hr += '' + str(index) + ') [{}]({})'.format(title, platform_url) + '\n'
            hr += '   Summary: ' + str(summary) + '\n\n\n'
            report_detail = {
                'ReportId': report.get('id', 'N/A'),
                'UpdatedAt': report.get('updated_at', ''),
                'PostedAt': report.get('posted_at', ''),
                'NotifiedAt': report.get('notified_at', ''),
                'PlatformUrl': platform_url,
                'Title': title,
                'Summary': summary
            }
            report_details.append(report_detail)

        fp_url = client.url + '/home/intelligence/reports/report/' + report_id + '#detail'
        hr += 'Link to the given Report on Flashpoint platform: [{}]({})\n'.format(fp_url, fp_url)
        ec[FLASHPOINT_PATHS['Report']] = report_details

    else:
        hr += 'No related reports found for the search.'

    return hr, ec, resp


def get_event_by_id_command(client, event_id):
    """
    Get specific event using its event id

    :param client: object of client class
    :param event_id: event's fpid
    :return: command output
    """
    url_suffix = '/indicators/event/' + urllib.parse.quote(event_id.encode('utf-8'))
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint Event details\n'
    ec: Dict[Any, Any] = {}

    if len(resp) <= 0:
        hr += 'No event found for the given ID.'
        return hr, ec, resp

    event = resp[0].get('Event', '')
    fpid = resp[0].get('fpid', '')
    href = resp[0].get('href', '')

    events = []
    if event:
        event = parse_event_response(client, event, fpid, href)
        if resp[0].get('malware_description'):
            event['Malware Description'] = resp[0].get('malware_description', '')
        events.append(event)
        hr += tableToMarkdown('Below are the detail found:', events,
                              ['Observed time (UTC)', 'Name', 'Tags', 'Malware Description'])

        ec[FLASHPOINT_PATHS['Event']] = {
            'EventId': events[0]['EventId'],
            'Name': events[0]['Name'],
            'Tags': events[0]['Tags'],
            'ObservedTime': events[0]['Observed time (UTC)'],
            'EventCreatorEmail': event['EventCreatorEmail'],
            'Href': href
        }
        # if no key `malware_description` is present, it should not be included in context data
        if event.get('Malware Description'):
            ec[FLASHPOINT_PATHS['Event']]['MalwareDescription'] = event['Malware Description']

    return hr, ec, resp


def get_events_command(client, limit, report_fpid, attack_ids, time_period):
    """
    Get events matching the given parameters

    :param client: object of client class
    :param limit: limit of the records
    :param report_fpid: report fpid to fetch events
    :param attack_ids: array of attack ids of event
    :param time_period: time period i.e 2M, 3d etc
    :return: command output
    """
    url_suffix = '/indicators/event?sort_timestamp=desc&'
    getvars = {}
    if limit:
        getvars['limit'] = limit

    if report_fpid:
        getvars['report'] = report_fpid

    if attack_ids:
        getvars['attack_ids'] = attack_ids

    if time_period:
        getvars['time_period'] = time_period

    url_suffix = url_suffix + urllib.parse.urlencode(getvars)

    resp = client.http_request("GET", url_suffix=url_suffix)
    indicators = resp
    hr = ''
    ec: Dict[Any, Any] = {}
    if len(indicators) > 0:
        hr += '### Flashpoint Events\n\n'

        events = []
        for indicator in indicators:
            href = indicator.get('href', '')
            event = indicator.get('Event', {})
            fpid = indicator.get('fpid', '')
            event = parse_event_response(client, event, fpid, href)
            if indicator.get('malware_description'):
                event['Malware Description'] = indicator.get('malware_description')
            events.append(event)

        hr += tableToMarkdown('Below are the detail found:', events,
                              ['Observed time (UTC)', 'Name', 'Tags', 'Malware Description'])

        fp_link = client.url + '/home/search/iocs'
        if attack_ids:
            fp_link = fp_link + '?attack_ids=' + urllib.parse.quote(attack_ids)
        hr += '\nAll events and details (fp-tools): [{}]({})\n'.format(fp_link, fp_link)

        # Replacing the dict keys for ec  to strip any white spaces and special charcters
        for event in events:
            replace_key(event, 'ObservedTime', 'Observed time (UTC)')
            replace_key(event, 'MalwareDescription', 'Malware Description')

        ec[FLASHPOINT_PATHS['Event']] = events

    else:
        hr += 'No event found for the argument.'

    return hr, ec, resp


def get_forum_details_by_id_command(client, forum_id):
    """
    Get specific forum details by its fpid

    :param client: object of client class
    :param forum_id: forum's fpid
    :return: command output
    """
    url_suffix = '/forums/sites/' + urllib.parse.quote(forum_id.encode('utf-8'))
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint Forum details\n'
    ec = {}

    if resp:
        forum_details = parse_forum_response(resp)
        hr += tableToMarkdown('Below are the details found:', forum_details, ['Name', 'Hostname', 'Tags'])
        hr += '\n'

        ec[FLASHPOINT_PATHS['Forum']] = {
            'ForumId': resp['id'],
            'Hostname': resp['hostname'],
            'Description': resp['description'],
            'Name': resp['name'],
            'Stats': resp['stats'],
            'Tags': resp['tags']
        }

    else:
        hr += 'No forum detail found for given forum id.'

    return hr, ec, resp


def get_room_details_by_id_command(client, room_id):
    """
    Get room details by its room id

    :param client: object of client class
    :param room_id: room's fpid
    :return: command output
    """
    url_suffix = '/forums/rooms/' + urllib.parse.quote(room_id.encode('utf-8')) + '?embed=forum'
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint Room details\n'
    ec = {}

    if resp:
        forum_name = resp['embed']['forum']['name']
        url = resp.get('url', '')
        title = resp.get('title', '')

        room_details = {
            'Forum Name': forum_name,
            'Title': title,
            'URL': url
        }

        hr += tableToMarkdown('Below are the detail found:', room_details, ['Forum Name', 'Title', 'URL'])
        hr += '\n'

        ec[FLASHPOINT_PATHS['Room']] = {
            'RoomId': resp['id'],
            'Title': title,
            'Url': url,
            'Forum': resp['embed']['forum']
        }

    else:
        hr += 'No room details found for given room id'

    return hr, ec, resp


def get_user_details_by_id_command(client, user_id):
    """
    Get user details by user's fpid

    :param client: object of client class
    :param user_id: user's fpid
    :return: command output
    """
    url_suffix = '/forums/users/' + urllib.parse.quote(user_id.encode('utf-8')) + '?embed=forum'
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint User details\n'
    ec = {}

    if resp:
        forum_name = resp['embed']['forum']['name']
        url = resp.get('url', '')
        name = resp.get('name', '')

        user_details = {
            'Forum Name': forum_name,
            'Name': name,
            'URL': url
        }

        hr += tableToMarkdown('Below are the detail found:', user_details, ['Forum Name', 'Name', 'URL'])
        hr += '\n'

        ec[FLASHPOINT_PATHS['User']] = {
            'UserId': resp['id'],
            'Name': name,
            'Url': url,
            'PlatformUrl': resp.get('platform_url', ''),
            'Forum': resp['embed']['forum']
        }

    else:
        hr += 'No user details found for given user id'

    return hr, ec, resp


def get_post_details_by_id_command(client, post_id):
    """
    Get forum post details by post's fpid

    :param client: object of client class
    :param post_id: fpid of post
    :return: command output
    """
    url_suffix = '/forums/posts/' + urllib.parse.quote(
        post_id.encode('utf-8')) + '?body_html=stripped&embed=author,room,forum,thread'
    resp = client.http_request("GET", url_suffix=url_suffix)

    hr = '### Flashpoint Post details\n'
    ec = {}

    if resp:
        published_at = resp.get('published_at', '')
        url = resp.get('url', '')
        platform_url = resp.get('platform_url', '')
        forum_name = resp['embed']['forum']['name']
        room_title = resp['embed']['room']['title']
        author_name = resp['embed']['author']['name']
        thread_title = resp['embed']['thread']['title']

        post_details = {
            'Published at': published_at,
            'Forum Name': forum_name,
            'Room Title': room_title,
            'Author Name': author_name,
            'Thread Title': thread_title,
            'URL': url,
            'Platform url': "[{}]({})".format(platform_url, platform_url)
        }

        hr += tableToMarkdown('Below are the detail found:', post_details,
                              ['Published at', 'Forum Name', 'Room Title', 'Author Name', 'Thread Title', 'URL',
                               'Platform url'])
        hr += '\n'
        post_ec = get_post_context(resp)
        ec[FLASHPOINT_PATHS['Post']] = post_ec

    else:
        hr += 'No post details found for given post id'

    return hr, ec, resp


def get_forum_sites_command(client, site_search):
    """
    Get forum sites matching search keyword or query

    :param client: object of client class
    :param site_search: site's keyword or query
    :return: command output
    """
    url_suffix = '/forums/sites/?query=' + urllib.parse.quote(site_search.encode('utf8')) + '&limit=10'
    resp = client.http_request("GET", url_suffix=url_suffix)
    sites = resp.get("data", [])

    hr = '### Flashpoint Forum sites related to search: ' + site_search + '\n'
    ec: Dict[Any, Any] = {}

    if sites:
        hr += 'Top 10 sites:\n\n'
        site_details = []
        for site in sites:
            site_detail = {
                'SiteId': site.get('id', ''),
                'Name': site.get('name', 'N/A'),
                'Hostname': site.get('hostname', 'N/A'),
                'Description': site.get('description', 'N/A'),
                'PlatformUrl': site.get('platform_url', ''),
                'Tags': site.get('tags', [])
            }

            site_details.append(site_detail)

        hr += tableToMarkdown('Below are the detail found:', site_details, ['Name', 'Hostname', 'Description'])
        hr += '\n'

        ec = {
            FLASHPOINT_PATHS['Site']: site_details
        }

    else:
        hr += 'No forum sites found for the search'

    return hr, ec, resp


def get_forum_posts_command(client, post_search):
    """
    Get forum posts details matching given keyword or query

    :param client: object of client class
    :param post_search: keyword or query for search in posts
    :return: command output
    """
    url_suffix = '/forums/posts/?query=' + urllib.parse.quote(
        post_search.encode('utf8')) + '&limit=10&embed=forum,room,author,thread'
    resp = client.http_request("GET", url_suffix=url_suffix)
    posts = resp.get("data", [])

    hr = '### Flashpoint Forum posts related to search: ' + post_search + '\n'
    ec: Dict[Any, Any] = {}

    if posts:
        hr += 'Top 10 posts:\n\n'
        post_details = []
        post_entry_context = []
        for post in posts:
            platform_url = post.get('platform_url', '')
            thread_title = post['embed']['thread']['title']
            post_ec = get_post_context(post)
            post_entry_context.append(post_ec)
            post_detail = {
                'Forum Name': post['embed']['forum']['name'],
                'Thread Title': thread_title[:30] + '....',
                'Room Title': post['embed']['room']['title'],
                'Author Name': post['embed']['author']['name'],
                'Platform URL': '[{}]({})'.format(platform_url[:30] + '...', platform_url)
            }
            post_details.append(post_detail)

        hr += tableToMarkdown('Below are the detail found:', post_details,
                              ['Forum Name', 'Thread Title', 'Room Title', 'Author Name', 'Platform URL'])
        hr += '\n'

        fp_url = client.url + '/home/search/forums?query=' + urllib.parse.quote(post_search.encode('utf8'))
        hr += 'Link to forum post-search on Flashpoint platform: [{}]({})\n'.format(fp_url, fp_url)

        ec[FLASHPOINT_PATHS['Post']] = post_entry_context

    else:
        hr += 'No forum posts found for the search'

    return hr, ec, resp


def flashpoint_alert_list_command(client: Client, args: dict) -> CommandResults:
    """
    List alerts from Flashpoint.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    args = validate_alert_list_args(args)
    response = client.http_request("GET", url_suffix=URL_SUFFIX_V1['ALERTS'], params=args)

    alerts = response.get('data', [])
    if not alerts:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('alerts'))

    readable_output = prepare_hr_for_alerts(alerts)

    token_context = {
        'since': 'N/A',
        'until': 'N/A',
        'size': 'N/A',
        'scroll_id': 'N/A',
        'name': 'flashpoint-alert-list'
    }

    links = response.get('links', {}).get('next', {}).get('href')
    if links:
        token_hr = "To retrieve the next set of result use,"
        context = prepare_context_from_next_href(links)
        for con in context:
            token_context[con] = context[con][0]
            token_hr += "\n" + con + " = " + context[con][0]
        readable_output += token_hr

    for alert in alerts:
        tags = alert.get('tags', {})
        if 'archived' in tags.keys():
            alert['tags']['archived'] = True
        else:
            alert['tags']['archived'] = False

        if 'flagged' in tags.keys():
            alert['tags']['flagged'] = True
        else:
            alert['tags']['flagged'] = False

    outputs = {
        FLASHPOINT_PATHS['ALERT']: alerts,
        FLASHPOINT_PATHS['TOKEN']: token_context
    }

    outputs = remove_empty_elements(outputs)

    return CommandResults(
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response
    )


def flashpoint_compromised_credentials_list_command(client: Client, args: dict) -> CommandResults:
    """
    List compromised credentials from Flashpoint.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    args = validate_compromised_credentials_list_args(args)
    response = client.http_request("GET", url_suffix=URL_SUFFIX['COMPROMISED_CREDENTIALS'], params=args)

    hits = response.get('hits', {}).get('hits', [])
    if not hits:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('compromised credentials'))

    readable_output = ''

    total_records = response.get('hits', {}).get('total')
    if total_records:
        readable_output += f'#### Total number of records found: {total_records}\n\n'

    readable_output += prepare_hr_for_compromised_credentials(hits)

    outputs = remove_empty_elements(hits)

    return CommandResults(
        outputs_prefix="Flashpoint.CompromisedCredential",
        outputs_key_field="_id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response
    )


def fetch_incidents(client: Client, last_run: dict, params: dict) -> Tuple[dict, list]:
    """
    Fetches incidents from Flashpoint.

    :param client: Client object
    :param last_run: Last run returned by function demisto.getLastRun
    :param params: Dictionary of parameters

    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    fetch_params = validate_fetch_incidents_params(params, last_run)
    fetch_type = fetch_params['fetch_type']

    url_suffix = ''
    if fetch_type == 'Alerts':
        url_suffix = URL_SUFFIX_V1['ALERTS']
    elif fetch_type == DEFAULT_FETCH_TYPE:
        url_suffix = URL_SUFFIX['COMPROMISED_CREDENTIALS']

    response = client.http_request("GET", url_suffix=url_suffix, params=fetch_params['fetch_params'])

    incidents: List[Dict[str, Any]] = []
    next_run = last_run
    start_time = fetch_params['start_time']

    if fetch_type == "Alerts":
        next_run, incidents = prepare_incidents_from_alerts_data(response, next_run, start_time)

    elif fetch_type == DEFAULT_FETCH_TYPE:
        next_run, incidents = prepare_incidents_from_compromised_credentials_data(response, next_run, start_time)

    return next_run, incidents


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    api_key = get_apikey()
    url = params["url"]
    verify_certificate = not params.get('insecure', False)
    create_relationships = argToBoolean(params.get('create_relationships', True))
    proxies = handle_proxy()

    args = demisto.args()
    for arg in args:
        if isinstance(args[arg], str):
            args[arg] = args[arg].strip()

    command = demisto.command()
    try:
        client = Client(api_key, url, verify_certificate, proxies, create_relationships)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module(client, params)    # NOSONAR
            demisto.results('ok')

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'ip':
            ip = demisto.args()['ip']
            reputation_operation_command(client, ip, ip_lookup_command, True)

        elif demisto.command() == 'domain':
            domain = demisto.args()['domain']
            reputation_operation_command(client, domain, domain_lookup_command, True)

        elif demisto.command() == 'filename':
            filename = demisto.args()['filename']
            reputation_operation_command(client, filename, filename_lookup_command)

        elif demisto.command() == 'url':
            url = demisto.args()['url']
            reputation_operation_command(client, url, url_lookup_command, True)

        elif demisto.command() == 'file':
            file = demisto.args()['file']
            reputation_operation_command(client, file, file_lookup_command, True)

        elif demisto.command() == 'email':
            email = demisto.args()['email']
            reputation_operation_command(client, email, email_lookup_command)

        elif demisto.command() == 'flashpoint-common-lookup':
            indicator_value = demisto.args()['indicator']
            reputation_operation_command(client, indicator_value, common_lookup_command)

        elif demisto.command() == 'flashpoint-search-intelligence-reports':
            report_search = demisto.args()['report_search']
            return_outputs(*get_reports_command(client, report_search))

        elif demisto.command() == 'flashpoint-get-single-intelligence-report':
            report_id = demisto.args()['report_id']
            return_outputs(*get_report_by_id_command(client, report_id))

        elif demisto.command() == 'flashpoint-get-related-reports':
            report_id = demisto.args()['report_id']
            return_outputs(*get_related_reports_command(client, report_id))

        elif demisto.command() == 'flashpoint-get-single-event':
            event_id = demisto.args()['event_id']
            return_outputs(*get_event_by_id_command(client, event_id))

        elif demisto.command() == 'flashpoint-get-events':
            args = demisto.args()
            limit = args.get('limit', 10)
            report_fpid = args.get('report_fpid')
            attack_ids = args.get('attack_ids')
            time_period = args.get('time_period')
            return_outputs(*get_events_command(client, limit, report_fpid, attack_ids, time_period))

        elif demisto.command() == 'flashpoint-get-forum-details':
            forum_id = demisto.args()['forum_id']
            return_outputs(*get_forum_details_by_id_command(client, forum_id))

        elif demisto.command() == 'flashpoint-get-forum-room-details':
            room_id = demisto.args()['room_id']
            return_outputs(*get_room_details_by_id_command(client, room_id))

        elif demisto.command() == 'flashpoint-get-forum-user-details':
            user_id = demisto.args()['user_id']
            return_outputs(*get_user_details_by_id_command(client, user_id))

        elif demisto.command() == 'flashpoint-get-forum-post-details':
            post_id = demisto.args()['post_id']
            return_outputs(*get_post_details_by_id_command(client, post_id))

        elif demisto.command() == 'flashpoint-search-forum-sites':
            site_search = demisto.args()['site_search']
            return_outputs(*get_forum_sites_command(client, site_search))

        elif demisto.command() == 'flashpoint-search-forum-posts':
            post_search = demisto.args()['post_search']
            return_outputs(*get_forum_posts_command(client, post_search))

        elif command == 'flashpoint-alert-list':
            return_results(flashpoint_alert_list_command(client, args))

        elif command == 'flashpoint-compromised-credentials-list':
            return_results(flashpoint_compromised_credentials_list_command(client, args))

    except requests.exceptions.ConnectionError as c:
        """ Caused mostly when URL is altered."""
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(c)}')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
