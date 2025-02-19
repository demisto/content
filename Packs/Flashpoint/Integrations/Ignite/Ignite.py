"""Ignite Main File."""
from copy import deepcopy
import ipaddress
from typing import Dict, Tuple

import requests
import urllib3

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

urllib3.disable_warnings()

""" CONSTANTS """
INTEGRATION_VERSION = "2.0.4"
INTEGRATION_PLATFORM = "Cortex XSOAR"
DEFAULT_API_PATH = "api.flashpoint.io"
DEFAULT_PLATFORM_PATH = "https://app.flashpoint.io"
DEFAULT_OLD_PLATFORM_PATH = "https://fp.tools"
FIRST_FETCH = "3 days"
DEFAULT_FETCH = 15
DEFAULT_PAGE_SIZE = 50
DEFAULT_LIMIT = 10
DEFAULT_REPORT_LIMIT = 5
DEFAULT_REPUTATION_LIMIT = 5
MAX_PAGE_SIZE = 1000
MAX_FETCH_LIMIT = 200
MAX_PRODUCT = 10000
MAX_ALERTS_LIMIT = 500
DEFAULT_SORT_ORDER = 'asc'
DEFAULT_FETCH_TYPE = 'Compromised Credentials'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
READABLE_DATE_FORMAT = '%b %d, %Y  %H:%M'
TOTAL_RETRIES = 4
STATUS_CODE_TO_RETRY = (429, *(
    status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (400, 401, 403, 404, 521, *(
    status_code for status_code in requests.status_codes._codes if status_code >= 200 and status_code < 300))  # type: ignore
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s, 60s] between retries.
DEFAULT_END_TIME = 'now'
DEFAULT_SEVERITY = 'Unknown'

IS_FRESH_VALUES = ['true', 'false']
SORT_ORDER_VALUES = ['asc', 'desc']
SORT_DATE_VALUES = ['created_at', 'first_observed_at']
FILTER_DATE_VALUES = ['created_at', 'first_observed_at']
ALERT_STATUS_VALUES = ['archived', 'starred', 'sent', 'none']
ALERT_ORIGIN_VALUES = ['searches', 'assets']

DATE_OBSERVED = "Date Observed (UTC)"
STRING_FORMAT = "[{}]({})"
TIME_OBSERVED = "Observed time (UTC)"
QUERY = r'+type:("ip-src","ip-dst","ip-dst|port") +value.\*:"'
HR_TITLE = '### Ignite {} reputation for '
REPUTATION_MALICIOUS = 'Reputation: Malicious\n\n'
TABLE_TITLE = 'Events in which this IOC observed'
ALL_DETAILS_LINK = '\nAll events and details (ignite): [{}]({})\n'
MALICIOUS_DESCRIPTION = 'Found in malicious indicators dataset'
SUSPICIOUS_DESCRIPTION = 'Found in suspicious indicators dataset'
UNKONWN_DESCRIPTION = 'Reputation of this Indicator is Unknown'
STIX_ATTACK_PATTERN = 'STIX Attack Pattern'
REPUTATION_UNKNOWN = 'Reputation: Unknown\n\n'
REPUTATION_SUSPICIOUS = 'Reputation: Suspicious\n\n'
MALICIOUS_REPUTATION_SCORE = 3
UNKNOWN_REPUTATION_SCORE = 0
SUSPICIOUS_REPUTATION_SCORE = 2
FORUM_NAME = 'Forum Name'
ROOM_TITLE = 'Room Title'
AUTHOR_NAME = 'Author Name'
THREAD_TITLE = 'Thread Title'
EMPTY_DATA = 'N/A'
VENDOR_NAME = 'Ignite'
PAGINATION_HR = '#### To retrieve the next set of result use,'
MARKDOWN_CHARS = r"\*_{}[]()#+-!"
X_FP_HIGHLIGHT_TEXT = r'</?x-fp-highlight>'

URL_SUFFIX = {
    'INDICATOR_SEARCH': '/technical-intelligence/v1/simple',
    'REPORT_SEARCH': '/finished-intelligence/v1/reports',
    'COMPROMISED_CREDENTIALS': '/sources/v1/noncommunities/search',
    'GET_REPORT_BY_ID': '/finished-intelligence/v1/reports/{}',
    'RELATED_REPORT_LIST': '/finished-intelligence/v1/reports/{}/related',
    'EVENT_LIST': '/technical-intelligence/v1/event',
    'EVENT_GET': '/technical-intelligence/v1/event/{}',
    'COMMUNITY_SEARCH': '/sources/v2/communities',
    'ALERTS': '/alert-management/v1/notifications',
}

IGNITE_PATHS = {
    'Filename': 'Ignite.Filename.Event(val.Fpid && val.Fpid == obj.Fpid)',
}

HR_SUFFIX = {
    'IOC_EMAIL': '/cti/malware/iocs?sort_date=All%20Time&types=email-dst,email-src,'
                 'email-src-display-name,email-subject,email&query=%22{}%22',
    'IOC_FILENAME': '/cti/malware/iocs?sort_date=All%20Time&types=filename&query=%22{}%22',
    'IOC_URL': '/cti/malware/iocs?sort_date=All%20Time&types=url&query=%22{}%22',
    'IOC_FILE': '/cti/malware/iocs?sort_date=All%20time&types=md5,sha1,sha256,sha512,ssdeep&query=%22{}%22',
    'IOC_IP': '/cti/malware/iocs?query=%22{}%22&sort_date=All%20Time&types=ip-dst,ip-src,ip-dst|port',
    'IOC_SEARCH': '/cti/malware/iocs?query=%22{}%22&sort_date=All%20Time',
    'IOC_DOMAIN': '/cti/malware/iocs?sort_date=All%20Time&types=domain&query=%22{}%22',
    'IOC_ITEM': '/cti/malware/iocs/{}',
    'IOC_LIST': '/cti/malware/iocs',
    'IOC_UUID_LIST': '/cti/malware/iocs?query={}&sort_date=All+Time',
    'REPORT': '/cti/intelligence/report/{}#detail',
    'COMMUNITY_SEARCH': '/search/results/communities?query={}&include.date=all%20time',
}

OUTPUT_PREFIX = {
    'COMPROMISED_CREDENTIALS': 'Ignite.CompromisedCredential',
    'REPORT': 'Ignite.Report',
    'EMAIL': 'Ignite.Email.Event',
    'FILENAME': 'Ignite.Filename.Event',
    'DOMAIN': 'Ignite.Domain.Event',
    'IP': 'Ignite.IP.Event',
    'IP_COMMUNITY_SEARCH': 'Ignite.IP',
    'URL': 'Ignite.URL.Event',
    'FILE': 'Ignite.File.Event',
    'EVENT': 'Ignite.Event',
    'ALERT': 'Ignite.Alert',
    'TOKEN': 'Ignite.PageToken.Alert',
}

OUTPUT_KEY_FIELD = {
    'FPID': 'Fpid',
    'REPORT_ID': 'ReportId',
    'EVENT_ID': 'EventId',
    'COMPROMISED_CREDENTIAL_ID': '_id',

}

ALERT_SOURCES_MAPPING = {
    'Github': 'data_exposure__github',
    'Gitlab': 'data_exposure__gitlab',
    'Bitbucket': 'data_exposure__bitbucket',
    'Communities': 'communities',
    'Images': 'media',
    'Marketplaces': 'marketplaces'
}

ALERT_RESOURCE_URL = {
    'communities': '/search/context/communities/{}',
    'marketplaces': '/search/context/marketplaces/{}',
    'media': '/search/results/media?include.date=all+time&include.media_id={}',
}

ALERT_STATUS_MAPPING = {
    'starred': 'flagged',
}

MESSAGES = {
    "INVALID_MAX_FETCH": "{} is an invalid value for maximum fetch. Maximum fetch must be between 1 to 200.",
    "INVALID_JSON_OBJECT": 'Failed to parse json object from response: {}.',
    "STATUS_CODE": "Error in API call [{}] - {}",
    "INVALID_FETCH_TIME": '{} is invalid value for First Fetch Time. First fetch time should not be in the future.',
    "INVALID_FIRST_FETCH": "Argument 'First fetch time' should be a valid date or relative timestamp such as "
                           "'2 days', '2 months', 'yyyy-mm-dd', 'yyyy-mm-ddTHH:MM:SSZ'",
    "SIZE_ERROR": "{} is an invalid value for size. Size must be between 1 to {}.",
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "PAGE_SIZE_ERROR": "{} is an invalid value for the page size. The page size must be between 1 to {}.",
    "LIMIT_ERROR": "{} is an invalid value for the limit. The limit must be between 1 to {}.",
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
    "TIME_RANGE_ERROR": f"The maximum records to fetch for the given first fetch can not exceed {MAX_PRODUCT}."
                        " Current records are {}. Try decreasing the time interval.",
    "NO_PARAM_PROVIDED": "Please provide the {}.",
    "INVALID_ARGUMENT_RESPONSE": "Invalid argument value while trying to get information from Ignite: ",
    "INVALID_API_KEY": "Encountered error while trying to get information from Ignite: Invalid API Key configured.",
    "NO_RECORD_FOUND": "No record found for given argument(s): Not Found.",
    "TEST_CONNECTIVITY_FAILED": "Test connectivity failed. Please provide valid input parameters.",
    "MISSING_REQUIRED_ARGS": "{} is a required field. Please provide correct input.",
    "INVALID_IP_ADDRESS": "Invalid IP - {}",
    "INVALID_SINGLE_SELECT_PARAM": "{} is an invalid value for {}. Possible values are: {}.",
    "INVALID_TIME_INTERVAL": "{} parameter must be less than {} parameter.({} - {})",
}


class Client(BaseClient):
    """
    Client to use in integration with powerful http_request.
    """

    def __init__(self, url, headers, verify, proxy, create_relationships):
        """Initialize class object.

        :type url: ``str``
        :param url: Base server address with suffix, for example: https://example.com.

        :type headers: ``Dict``
        :param headers: Additional headers to be included in the requests.

        :type verify: ``bool``
        :param verify: Use to indicate secure/insecure http request.

        :type proxy: ``bool``
        :param proxy: The proxy settings to be used.

        :type create_relationships: ``bool``
        :param create_relationships: True if integration will create relationships.
        """
        self.url = url

        if DEFAULT_API_PATH in url:
            self.platform_url = DEFAULT_PLATFORM_PATH
        else:
            self.platform_url = url

        self.headers = headers
        self.verify = verify
        self.proxy = proxy
        self.create_relationships = create_relationships

        super().__init__(base_url=self.url, headers=self.headers, verify=self.verify, proxy=self.proxy)

    def http_request(self, method, url_suffix, params=None, json_data=None):
        """
        Get http response based on url and given parameters.

        :param method: Specify http methods
        :param url_suffix: url encoded url suffix
        :param params: None
        :param json_data: None
        :return: http response on json
        """
        demisto.debug(f"Requesting Ignite with method: {method}, url_suffix: {url_suffix} and params: {params}")
        resp = self._http_request(method=method, url_suffix=url_suffix, params=params, json_data=json_data, retries=TOTAL_RETRIES,
                                  status_list_to_retry=STATUS_CODE_TO_RETRY, backoff_factor=BACKOFF_FACTOR,
                                  raise_on_redirect=False, raise_on_status=False, resp_type='response',
                                  ok_codes=OK_CODES)  # type: ignore

        status_code = resp.status_code

        try:
            resp_json = resp.json()
        except ValueError as exception:
            raise DemistoException(MESSAGES['STATUS_CODE'].format(
                status_code, MESSAGES['INVALID_JSON_OBJECT'].format(resp.text)), exception) from exception

        if status_code != 200:
            if status_code == 400:
                raise DemistoException(MESSAGES['STATUS_CODE'].format(
                    status_code, MESSAGES["INVALID_ARGUMENT_RESPONSE"] + str(resp_json.get(
                        'detail', resp_json.get('message', json.dumps(resp_json))))))
            if status_code == 401:
                raise DemistoException(MESSAGES['STATUS_CODE'].format(status_code, MESSAGES['INVALID_API_KEY']))
            if status_code == 404:
                raise DemistoException(MESSAGES['STATUS_CODE'].format(status_code, MESSAGES["NO_RECORD_FOUND"]))
            if status_code in (521, 403):
                raise DemistoException(MESSAGES['STATUS_CODE'].format(
                    status_code, MESSAGES["TEST_CONNECTIVITY_FAILED"]))
            self.client_error_handler(resp)

        return resp_json


''' HELPER FUNCTIONS '''


def string_escape_markdown(data: Any):
    """
    Escape any chars that might break a markdown string.

    :param data: The data to be modified (required).

    :return: A modified data.
    """
    if isinstance(data, str):
        data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in data])
    elif isinstance(data, list):
        new_data = []
        for sub_data in data:
            if isinstance(sub_data, str):
                sub_data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in sub_data])
            new_data.append(sub_data)
        data = new_data

    return data


def get_url_suffix(query):
    """
    Create url-suffix using the query value with url encoding.

    :param query: value of query param
    :return: url-encoded url-suffix
    """
    return URL_SUFFIX['INDICATOR_SEARCH'] + '?query=' + urllib.parse.quote(query.encode('utf8'))


def remove_space_from_args(args):
    """Remove space from args."""
    for key in args.keys():
        if isinstance(args[key], str):
            args[key] = args[key].strip()
    return args


def validate_params(command: str, params: Dict):
    """
    Validate the parameters.

    :param command: Command name.
    :type command: str

    :param params: Params to validate.
    :type params: Dict
    :return:
    """
    if not params.get('url'):
        raise DemistoException(MESSAGES["NO_PARAM_PROVIDED"].format('Server URL'))
    if not str(params.get('credentials', {}).get('password', '')).strip():
        raise DemistoException(MESSAGES["NO_PARAM_PROVIDED"].format('API Key'))
    if params.get('isFetch'):
        first_fetch = arg_to_datetime(params.get('first_fetch', FIRST_FETCH)).astimezone(timezone.utc)  # type: ignore
        current_time = arg_to_datetime(DEFAULT_END_TIME).astimezone(timezone.utc)  # type: ignore
        if first_fetch > current_time and command == 'test-module':
            raise DemistoException(MESSAGES["INVALID_FETCH_TIME"].format(first_fetch.strftime(DATE_FORMAT)))


def replace_key(dictionary, new_key, old_key):
    """
    Replace key in dictionary.

    :param dictionary: dictionary object on which we wan to replace key.
    :param new_key: key which will replace in dictionary
    :param old_key: existing key in dictionary
    :return: dict object
    """
    if dictionary.get(old_key):
        dictionary[new_key] = dictionary.pop(old_key)
    return dictionary


def parse_event_response(client, event, fpid, href):
    """
    Prepare required event json object from event response.

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
        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_UUID_LIST'].format(uuid))
        name_str = STRING_FORMAT.format(name, fp_link)
    else:
        name_str = name

    tags_list = [tag['name'] for tag in event.get('Tag', [])]
    tags_value = ', '.join(tags_list)

    event_creator_email = event.get('event_creator_email', '')

    event = {
        TIME_OBSERVED: observed_time,
        'Name': name_str,
        'EventName': name,
        'Tags': tags_value,
        'EventCreatorEmail': event_creator_email,
        'EventId': fpid,
        'UUID': uuid,
        'Href': href,
    }

    return event


def validate_fetch_incidents_params(params: dict, last_run: dict) -> Dict:
    """
    Validate the parameter list for fetch incidents.

    :param params: Dictionary containing demisto configuration parameters
    :param last_run: last run returned by function demisto.getLastRun

    :return: Dictionary containing validated configuration parameters in proper format.
    """
    fetch_params = {}

    fetch_type = params.get('fetch_type', DEFAULT_FETCH_TYPE)
    if not fetch_type:
        fetch_type = DEFAULT_FETCH_TYPE

    first_fetch = arg_to_datetime(params.get('first_fetch', FIRST_FETCH))
    start_time = first_fetch.strftime(DATE_FORMAT)  # type: ignore

    if last_run and 'start_time' in last_run:
        start_time = last_run.get('start_time')  # type: ignore

    is_fresh = argToBoolean(params.get('is_fresh_compromised_credentials', 'true'))

    alert_status = params.get('status', '').lower()
    alert_origin = params.get('origin', '').lower()
    alert_sources = argToList(params.get('sources', ''))

    max_fetch = arg_to_number(params.get('max_fetch', DEFAULT_FETCH))

    if fetch_type == DEFAULT_FETCH_TYPE:
        fetch_params = prepare_args_for_fetch_compromised_credentials(max_fetch, start_time, is_fresh, last_run)  # type: ignore

    elif fetch_type == 'Alerts':
        fetch_params = prepare_args_for_fetch_alerts(
            max_fetch, first_fetch, alert_origin, alert_status, alert_sources, last_run)  # type: ignore
        start_time = fetch_params['created_after']

    remove_nulls_from_dictionary(fetch_params)

    return {
        'fetch_type': fetch_type,
        'start_time': start_time,
        'fetch_params': fetch_params
    }


def prepare_args_for_fetch_compromised_credentials(max_fetch: int, start_time: str, is_fresh: bool,
                                                   last_run: dict) -> dict:
    """
    Prepare arguments for fetching compromised credentials.

    :param max_fetch: Maximum number of incidents per fetch
    :param start_time: Date time to start fetching incidents from
    :param is_fresh: Boolean value showing whether to fetch the fresh compromised credentials or not
    :param last_run: Dictionary containing last run objects

    :return: Dictionary of fetch arguments
    """
    fetch_params: Dict[str, Any] = {}

    if max_fetch > MAX_FETCH_LIMIT and demisto.command() == 'fetch-incidents':
        demisto.debug(
            f'The value for the Max Fetch parameter is {max_fetch} which is greater than '
            f'{MAX_FETCH_LIMIT}, so reducing it to {MAX_FETCH_LIMIT}.')
        max_fetch = 200

    if max_fetch < 1 or max_fetch > MAX_FETCH_LIMIT:
        raise DemistoException(MESSAGES['INVALID_MAX_FETCH'].format(max_fetch))
    fetch_params['limit'] = max_fetch

    if not last_run.get('fetch_count'):
        last_run['fetch_count'] = 0

    if not last_run.get('fetch_sum'):
        last_run['fetch_sum'] = 0

    fetch_params['skip'] = last_run['fetch_sum']

    total = last_run.get('total')
    if total:
        # if total is present in record fetch_sum will be max_fetch and previous fetch_sum addition.
        fetch_sum = fetch_params['limit'] + fetch_params['skip']
        if fetch_sum > total:
            # if calculated fetch sum is more than total records than calculate rest records from total value.
            fetch_params['limit'] = total - fetch_params['skip']

    # update fetch_sum in last run is calculated fetch limit and fetched records addition.
    last_run['fetch_sum'] = fetch_params['limit'] + fetch_params['skip']

    start_time = arg_to_datetime(start_time)
    start_time = datetime.timestamp(start_time)  # type: ignore

    if last_run['fetch_count'] == 0:
        # for first time fetch we have to update end_time as current time otherwise update end time as last run end_time.
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


def prepare_args_for_fetch_alerts(max_fetch: int, first_fetch: str, alert_origin: str, alert_status: str,
                                  alert_sources: list, last_run: dict) -> dict:
    """
    Prepare arguments for fetching alerts.

    :param max_fetch: Maximum number of incidents per fetch
    :param first_fetch: Date time to start fetching incidents from
    :param alert_origin: Alert origin
    :param alert_status: Alert status
    :param alert_sources: Alert sources
    :param last_run: Dictionary containing last run objects

    :return: Dictionary of fetch arguments
    """
    fetch_params: Dict[str, Any] = {}
    end_time = arg_to_datetime('now').strftime(DATE_FORMAT)  # type: ignore
    start_time = first_fetch.strftime(DATE_FORMAT)  # type: ignore

    if max_fetch > MAX_FETCH_LIMIT and demisto.command() == 'fetch-incidents':
        demisto.debug(
            f'The value for the Max Fetch parameter is {max_fetch} which is greater than '
            f'{MAX_FETCH_LIMIT}, so reducing it to {MAX_FETCH_LIMIT}.')
        max_fetch = 200

    if max_fetch < 1 or max_fetch > MAX_FETCH_LIMIT:
        raise DemistoException(MESSAGES['INVALID_MAX_FETCH'].format(max_fetch))

    fetch_params['size'] = max_fetch
    fetch_params['created_after'] = last_run.get('after_time', start_time)
    fetch_params['created_before'] = last_run.get('before_time', end_time)
    fetch_params['cursor'] = last_run.get('cursor')

    if alert_status and alert_status not in ALERT_STATUS_VALUES:
        raise ValueError(MESSAGES['INVALID_SINGLE_SELECT_PARAM'].format(alert_status, 'alert_status', ALERT_STATUS_VALUES))

    if alert_origin and alert_origin not in ALERT_ORIGIN_VALUES:
        raise ValueError(MESSAGES['INVALID_SINGLE_SELECT_PARAM'].format(alert_origin, 'alert_origin', ALERT_ORIGIN_VALUES))

    alert_sources = [ALERT_SOURCES_MAPPING.get(key, key) for key in alert_sources]

    fetch_params['status'] = ALERT_STATUS_MAPPING.get(alert_status, alert_status)  # type: ignore
    fetch_params['origin'] = alert_origin  # type: ignore
    fetch_params['sources'] = ','.join(alert_sources)  # type: ignore

    return fetch_params


def remove_duplicate_records(records: List, fetch_type: str, next_run: dict) -> List:
    """
    Check for duplicate records and remove them from the list.

    :param records: List of records
    :param fetch_type: Type of the records
    :param next_run: Dictionary to set in last run

    :return: Updated list of alerts
    """
    last_run_key = ''
    id_key = ''
    if fetch_type == DEFAULT_FETCH_TYPE:
        last_run_key = 'hit_ids'
        id_key = '_id'

    if next_run.get(last_run_key):
        prev_alert_ids = next_run[last_run_key]
        records = [i for i in records if i[id_key] not in prev_alert_ids]

    return records


def prepare_incidents_from_alerts_data(
        response: dict, last_run: dict, fetch_params: dict, platform_url: str) -> Tuple[dict, list]:
    """
    Prepare incidents from the alerts data.

    :param response: Response from the alerts API
    :param last_run: Dictionary to set in last run
    :param fetch_params: Dictionary of fetch parameters
    :param platform_url: Platform URL

    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    incidents = []
    alerts = response.get('items', [])
    alerts = remove_empty_elements(alerts)

    severity = demisto.params().get('severity', DEFAULT_SEVERITY)
    last_found_alert_ids = last_run.get('alert_ids', [])

    for alert in alerts:
        alert_id = alert.get('id')
        if alert_id in last_found_alert_ids:
            demisto.debug('Found existing alert with alert id:{}'.format(alert_id))
            continue

        tags = alert.get('tags', {})
        alert['tag_as_list'] = list(tags.keys())

        origin = alert.get('reason', {}).get('origin')
        source = alert.get('source')
        resource_url = alert.get('resource', {}).get('url')
        if not resource_url and origin == 'searches':
            resource_url = get_resource_url(source, alert.get('resource', {}).get('id'), platform_url)

        alert['resource'].update({'url': resource_url})

        incidents.append({
            'name': alert.get('reason', {}).get('name', '') + ' : ' + str(alert.get('id', '')),
            'severity': IncidentSeverity.__dict__.get(severity.upper()),
            'occurred': alert.get('generated_at'),
            'rawJSON': json.dumps(alert)
        })
        last_found_alert_ids.append(alert_id)

    next_run = {}
    _next = response.get('pagination', {}).get('next')

    if _next:
        parsed_url = urllib.parse.urlparse(_next)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        cursor = query_params.get('cursor')[0]  # type: ignore
        next_run['cursor'] = cursor
        next_run['after_time'] = fetch_params['created_after']
        next_run['before_time'] = fetch_params['created_before']
    else:
        next_run['after_time'] = fetch_params['created_before']

    demisto.debug(f'Set the last Run for notification alerts: {next_run}')
    next_run['alert_ids'] = last_found_alert_ids
    return next_run, incidents


def get_incident_name(hit_source: dict) -> str:
    '''
    Determines the incident name based on available fields in the hit source.
    :param hit_source: The source data from the hit.
    :return: The incident name.
    '''
    for field in ['username', 'email', 'fpid']:
        value = hit_source.get(field)
        if value:
            demisto.debug(f'Setting incident name with {field}: {value}')
            return value
    demisto.debug('Setting incident name with default: Compromised Credential Alert')
    return 'Compromised Credential Alert'


def prepare_incidents_from_compromised_credentials_data(response: dict, next_run: dict,
                                                        start_time: str, is_test: bool) -> Tuple[dict, list]:
    """
    Prepare incidents from the compromised credentials data.

    :param response: Response from the compromised credentials API
    :param next_run: Dictionary to set in last run
    :param start_time: Date time saved of the last fetch

    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    incidents = []
    total = arg_to_number(response.get('hits', {}).get('total'))
    check_value_of_total_records(total, next_run)

    if is_test:
        return {}, []

    hits = response.get('hits', {}).get('hits', [])

    hit_ids = [hit['_id'] for hit in hits]
    hits = remove_duplicate_records(hits, DEFAULT_FETCH_TYPE, next_run)
    severity = demisto.params().get('severity', DEFAULT_SEVERITY)

    for hit in hits:
        hit_source = hit.get('_source', {})
        incidents.append({
            'name': get_incident_name(hit_source),
            'severity': getattr(IncidentSeverity, severity.upper(), None),  # safer access to enum
            'occurred': hit_source.get('breach', {}).get('created_at', {}).get('date-time'),
            'rawJSON': json.dumps(hit)
        })

    if hits:
        prepare_checkpoint_and_related_objects(hits, hit_ids, next_run)

    if total > next_run['fetch_sum']:
        # If more records are available, then increase the fetch count
        prepare_next_run_when_data_is_present(next_run, start_time)
    else:
        prepare_next_run_when_data_is_empty(next_run, hits)

    next_run_without_ids = {k: v for k, v in next_run.items() if k != 'hit_ids'}
    demisto.debug(f"Set the last Run for compromised credentials: {next_run_without_ids}")
    return next_run, incidents


def check_value_of_total_records(total: Any, next_run: dict) -> None:
    """
    Check if total number of records are more than the limit or not.

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
    Prepare checkpoint and related objects for incidents of type compromised credentials.

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
            # last_timestamp is similar as last_record indexed_at time than hit_ids will be appended to list.
            next_run['hit_ids'] += hit_ids
        else:
            # last_timestamp is not similar as last_record indexed_at so for that response hits_ids will be replaced.
            next_run['hit_ids'] = hit_ids
    else:
        next_run['hit_ids'] = hit_ids

    next_run['last_timestamp'] = indexed_at


def prepare_next_run_when_data_is_present(next_run: dict, start_time: str) -> None:
    """
    Prepare next run when data is present.

    :param next_run: Dictionary to set in last run
    :param start_time:  Date time saved of the last fetch

    :return: None
    """
    next_run['start_time'] = start_time
    next_run['fetch_count'] = next_run['fetch_count'] + 1


def prepare_next_run_when_data_is_empty(next_run: dict, hits: List) -> None:
    """
    Prepare next run when data is present.

    :param next_run: Dictionary to set in last run
    :param hits: List of compromised credentials

    :return: None
    """
    if hits:
        next_run['start_time'] = next_run['last_time']
    next_run['fetch_count'] = 0
    next_run['fetch_sum'] = 0
    next_run['total'] = None


def validate_compromised_credentials_list_args(args: dict) -> dict:
    """
    Validate arguments for flashpoint-ignite-compromised-credentials-list command.

    :param args: The command arguments

    :return: Validated dictionary of arguments
    :raises: ValueError on invalid arguments
    """
    params = {'query': '+basetypes:(credential-sighting)'}

    validate_page_parameters_for_compromised_credentials(args, params)

    validate_date_parameters_for_compromised_credentials(args, params)

    validate_sort_parameters_for_compromised_credentials(args, params)

    is_fresh = args.get('is_fresh', '').lower()
    if is_fresh:
        if is_fresh not in IS_FRESH_VALUES:
            raise ValueError(MESSAGES['IS_FRESH_ERROR'].format(is_fresh, IS_FRESH_VALUES))
        params['query'] += f' +is_fresh:{is_fresh}'

    remove_nulls_from_dictionary(params)

    return params


def validate_date_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Validate date params for flashpoint-ignite-compromised-credentials-list command.

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


def validate_page_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Validate page_size and page_number for flashpoint-ignite-compromised-credentials-list command.

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


def validate_sort_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Validate sort_order and sort_date for flashpoint-ignite-compromised-credentials-list command.

    :param args: The command arguments
    :param params: Dictionary of parameters

    :return: None
    """
    sort_order = args.get('sort_order', '').lower()
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


def validate_alert_list_args(args: dict) -> dict:
    """
    Validate arguments for flashpoint-ignite-alert-list command.

    :param args: The command arguments

    :return: Validated dictionary of arguments
    :raises: ValueError for invalid arguments
    """
    params = {}
    size = arg_to_number(args.get('size', DEFAULT_LIMIT))
    if size is None or size < 1 or size > MAX_ALERTS_LIMIT:  # type: ignore
        raise ValueError(MESSAGES['SIZE_ERROR'].format(size, MAX_ALERTS_LIMIT))
    params['size'] = size

    created_after = arg_to_datetime(args.get('created_after'))
    if created_after:
        params['created_after'] = created_after.strftime(DATE_FORMAT)  # type: ignore

    created_before = arg_to_datetime(args.get('created_before'))
    if created_before:
        params['created_before'] = created_before.strftime(DATE_FORMAT)  # type: ignore

    if created_after and created_before and created_after >= created_before:
        raise ValueError(MESSAGES['INVALID_TIME_INTERVAL'].format(
            'created_after', 'created_before', params['created_after'], params['created_before']))

    params['cursor'] = args.get('cursor')  # type: ignore

    status = args.get('status', '').lower()
    if status and status not in ALERT_STATUS_VALUES:
        raise ValueError(MESSAGES['INVALID_SINGLE_SELECT_PARAM'].format(status, 'status', ALERT_STATUS_VALUES))
    params['status'] = ALERT_STATUS_MAPPING.get(status, status)  # type: ignore

    origin = args.get('origin', '').lower()
    if origin and origin not in ALERT_ORIGIN_VALUES:
        raise ValueError(MESSAGES['INVALID_SINGLE_SELECT_PARAM'].format(origin, 'origin', ALERT_ORIGIN_VALUES))
    params['origin'] = origin  # type: ignore

    params['cursor'] = args.get('cursor')  # type: ignore

    tags = argToList(args.get('tags'))
    if tags:
        params['tags'] = ','.join(tags)  # type: ignore

    sources = argToList(args.get('sources', ''))
    if sources:
        sources = [ALERT_SOURCES_MAPPING.get(key, key) for key in sources]
        params['sources'] = ','.join(sources)  # type: ignore

    asset_ids = argToList(args.get('asset_ids'))
    if asset_ids:
        params['asset_ids'] = ','.join(asset_ids)  # type: ignore

    query_ids = argToList(args.get('query_ids'))
    if query_ids:
        params['query_ids'] = ','.join(query_ids)  # type: ignore

    params['asset_type'] = args.get('asset_type')  # type: ignore

    asset_ip = args.get('asset_ip')
    if asset_ip and not is_ip_valid(asset_ip, True):
        raise ValueError(MESSAGES['INVALID_IP_ADDRESS'].format(asset_ip))
    params['asset_ip'] = asset_ip  # type: ignore

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_compromised_credentials(hits: list) -> str:
    """
    Prepare human readable format for compromised credentials.

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
            'Username': source.get('username', ''),
            'Breach Source': source.get('breach', {}).get('source'),
            'Breach Source Type': source.get('breach', {}).get('source_type'),
            'Password': source.get('password'),
            'Created Date (UTC)': created_date,
            'First Observed Date (UTC)': first_observed_date
        }
        hr.append(data)

    return tableToMarkdown("Compromised Credential(s)", hr,
                           ['FPID', 'Email', 'Username', 'Breach Source', 'Breach Source Type',
                            'Password', 'Created Date (UTC)', 'First Observed Date (UTC)'],
                           removeNull=True)


def parse_indicator_response(indicators):
    """
    Extract Ignite event details and href values from each of the indicator in an indicator list.

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
            DATE_OBSERVED: observed_time,
            'Name': event.get('info', ''),
            'Tags': tags_value,
        })

    return {'events': events, 'href': hrefs, 'attack_ids': attack_ids}


def create_relationships_list(client, events_details, ip):
    """Create relationships list from given data."""
    relationships = []
    if client.create_relationships and events_details.get('attack_ids'):
        for attack_id in events_details.get('attack_ids'):
            relationships.append(
                EntityRelationship(name='indicator-of',
                                   entity_a=ip,
                                   entity_a_type=FeedIndicatorType.IP,
                                   entity_b=attack_id,
                                   entity_b_type=FeedIndicatorType.indicator_type_by_server_version(STIX_ATTACK_PATTERN),
                                   brand=VENDOR_NAME))
    return relationships


def create_relationships_list_for_community_search(client, indicators, ip):
    relationships = []
    if client.create_relationships:
        ip_address_data = indicators.get('enrichments', {}).get('ip_address', [])
        for ip_address in ip_address_data:
            if is_ip_valid(ip_address, True):
                relationships.append(
                    EntityRelationship(name='indicator-of',
                                       entity_a=ip,
                                       entity_a_type=FeedIndicatorType.IP,
                                       entity_b=ip_address,
                                       entity_b_type=FeedIndicatorType.indicator_type_by_server_version(STIX_ATTACK_PATTERN),
                                       brand=VENDOR_NAME))

        indicator_data = indicators.get('enrichments', {}).get('url_domains', [])
        indicator_data += indicators.get('enrichments', {}).get('email_addresses', [])
        indicator_data += indicators.get('enrichments', {}).get('cve_ids', [])

        for indicator in indicator_data:
            relationships.append(
                EntityRelationship(name='indicator-of',
                                   entity_a=ip,
                                   entity_a_type=FeedIndicatorType.IP,
                                   entity_b=indicator,
                                   entity_b_type=FeedIndicatorType.indicator_type_by_server_version(STIX_ATTACK_PATTERN),
                                   brand=VENDOR_NAME))

    return relationships


def get_resource_url(source: str, resource_id: str, platform_url: str):
    """
    Generates the resource URL based on the given source and resource ID.

    :param source: The source of the resource.
    :param resource_id: The ID of the resource.
    :param platform_url: The platform URL

    :return: The generated resource URL.
    """
    if not resource_id:
        raise ValueError(MESSAGES['MISSING_DATA'].format('alerts'))

    resource_url = platform_url + ALERT_RESOURCE_URL[source].format(resource_id)

    return resource_url


def prepare_hr_for_alerts(alerts: List, platform_url: str) -> str:
    """
    Prepare human readable format for alerts.

    :param alerts: List of alerts
    :param platform_url: The platform URL

    :return: Human readable format of alerts
    """
    table_data = []
    for alert in alerts:
        _id = alert.get('id')
        keyword_text = alert.get('reason', {}).get('text')
        created_at = arg_to_datetime(alert.get('created_at'))
        if created_at:
            created_at = created_at.strftime(READABLE_DATE_FORMAT)  # type: ignore

        source = alert.get('source')
        repo = alert.get('resource', {}).get('repo')
        owner = alert.get('resource', {}).get('owner')
        origin = alert.get('reason', {}).get('origin')
        resource_url = alert.get('resource', {}).get('url')
        if not resource_url and origin == 'searches':
            resource_url = get_resource_url(source, alert.get('resource', {}).get('id'), platform_url)
        highlight_text = alert.get('highlight_text')
        ports = ', '.join([re.sub(X_FP_HIGHLIGHT_TEXT, '', port) for port in alert.get('highlights', {}).get('ports', [])])
        services = ', '.join([re.sub(X_FP_HIGHLIGHT_TEXT, '', service)
                             for service in alert.get('highlights', {}).get('services', [])])
        site_title = alert.get('resource', {}).get('site', {}).get('title')
        shodan_info = alert.get('resource', {}).get('shodan_host', {})
        if created_at:
            table_data.append({
                'ID': _id,
                'Created at (UTC)': created_at,
                'Query': keyword_text,
                'Highlight Text': string_escape_markdown(highlight_text),
                'Source': source,
                'Repository': repo,
                'Owner': owner,
                'Resource URL': resource_url,
                'Origin': origin,
                'Site Title': site_title,
                'Shodan Host': shodan_info,
                'Ports': ports,
                'Services': services,
            })

    headers = ['ID', 'Created at (UTC)', 'Query', 'Source', 'Resource URL', 'Site Title', 'Shodan Host',
               'Repository', 'Owner', 'Origin', 'Ports', 'Services', 'Highlight Text']

    return tableToMarkdown('Alerts', remove_empty_elements(table_data), headers, removeNull=True,
                           url_keys=['Resource URL', 'shodan_url'], json_transform_mapping={'Shodan Host': JsonTransformer()})


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Test the Ignite instance configuration.

    :param: client: Object of Client class.
    :return: str
    """
    params = demisto.params()
    is_fetch = params.get('isFetch')
    if is_fetch:
        fetch_incidents(client, {}, params, is_test=True)
    else:
        client.http_request(method="GET", url_suffix=URL_SUFFIX["INDICATOR_SEARCH"], params={"limit": 1})

    return 'ok'


def fetch_incidents(client: Client, last_run: dict, params: dict, is_test: bool = False) -> Tuple[dict, list]:
    """
    Fetch incidents from Flashpoint.

    :param client: Client object
    :param last_run: Last run returned by function demisto.getLastRun
    :param params: Dictionary of parameters
    :param is_test:to test test-module using is_test value.
    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    fetch_params = validate_fetch_incidents_params(params, last_run)
    fetch_type = fetch_params['fetch_type']

    url_suffix = ''
    if fetch_type == DEFAULT_FETCH_TYPE:
        url_suffix = URL_SUFFIX['COMPROMISED_CREDENTIALS']
    elif fetch_type == 'Alerts':
        url_suffix = URL_SUFFIX['ALERTS']

    response = client.http_request('GET', url_suffix=url_suffix, params=fetch_params['fetch_params'])

    incidents: List[Dict[str, Any]] = []
    next_run = last_run
    start_time = fetch_params['start_time']

    if fetch_type == DEFAULT_FETCH_TYPE:
        next_run, incidents = prepare_incidents_from_compromised_credentials_data(response, next_run, start_time, is_test)

    elif fetch_type == 'Alerts':
        if is_test:
            return {}, []
        next_run, incidents = prepare_incidents_from_alerts_data(
            response, last_run, fetch_params['fetch_params'], client.platform_url)

    demisto.info(f'Fetched {len(incidents)} incidents for {fetch_type}')
    return next_run, incidents


def email_lookup_command(client: Client, email: str) -> CommandResults:
    """
    Lookup a particular email address or subject.

    :param client: object of client class
    :param email: email address or subject
    :return: command output
    """
    query = (r'+type:("email-dst", "email-src", "email-src-display-name", "email-subject", "email") +value.\*.keyword:"'
             + email + '"')
    demisto.debug(get_url_suffix(query))
    resp = client.http_request('GET', url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = deepcopy(resp)
    else:
        indicators = []

    if len(indicators) > 0:

        hr = HR_TITLE.format('Email') + email + '\n'
        hr += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown(TABLE_TITLE, events_details['events'],
                              [DATE_OBSERVED, 'Name', 'Tags'])

        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_EMAIL'].format(urllib.parse.quote(email.encode('utf-8'))))
        hr += ALL_DETAILS_LINK.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=email,
            indicator_type=DBotScoreType.EMAIL,
            integration_name=VENDOR_NAME,
            score=MALICIOUS_REPUTATION_SCORE,
            reliability=demisto.params().get('integrationReliability')
        )
        dbot_score.integration_name = VENDOR_NAME

        email_ioc = Common.EMAIL(address=email, dbot_score=dbot_score, description=MALICIOUS_DESCRIPTION.strip())

        ignite_email_context = []
        for indicator in resp:
            indicator = indicator.get('Attribute', {})
            event = {
                'Email': email,
                'EventDetails': indicator.get('Event', ''),
                'Category': indicator.get('category', ''),
                'Fpid': indicator.get('fpid', ''),
                'Href': indicator.get('href', ''),
                'Timestamp': indicator.get('timestamp', ''),
                'Type': indicator.get('type', ''),
                'Uuid': indicator.get('uuid', ''),
                'Comment': indicator['value'].get('comment', ''),
            }
            ignite_email_context.append(event)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['EMAIL'],
            outputs_key_field=OUTPUT_KEY_FIELD['FPID'],
            outputs=remove_empty_elements(ignite_email_context),
            readable_output=hr,
            indicator=email_ioc,
            raw_response=resp
        )

    hr = HR_TITLE.format('Email') + email + '\n'
    hr += REPUTATION_UNKNOWN
    dbot_score = Common.DBotScore(
        indicator=email,
        indicator_type=DBotScoreType.EMAIL,
        integration_name=VENDOR_NAME,
        score=UNKNOWN_REPUTATION_SCORE,
        reliability=demisto.params().get('integrationReliability')
    )
    dbot_score.integration_name = VENDOR_NAME

    email_ioc = Common.EMAIL(address=email, dbot_score=dbot_score, description=UNKONWN_DESCRIPTION.strip())
    return CommandResults(
        indicator=email_ioc,
        readable_output=hr,
        raw_response=resp,
    )


def filename_lookup_command(client: Client, filename: str) -> CommandResults:
    """
        Lookup a particular filename.

        :param client: object of client class
        :param filename: filename
        :return: command output
        """
    query = r'+type:("filename") +value.\*.keyword:"' + filename.replace('\\', '\\\\') + '"'
    resp = client.http_request('GET', url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = deepcopy(resp)
    else:
        indicators = []

    if len(indicators) > 0:

        hr = HR_TITLE.format('Filename') + filename + '\n'
        hr += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown(TABLE_TITLE, events_details['events'],
                              [DATE_OBSERVED, 'Name', 'Tags'])

        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_FILENAME'].format(
            urllib.parse.quote(filename.replace('\\', '\\\\').encode('utf-8'))))
        hr += ALL_DETAILS_LINK.format(fp_link, fp_link)

        filename_context = {
            'Name': filename,
            'Malicious': {
                'Vendor': VENDOR_NAME,
                'Description': MALICIOUS_DESCRIPTION
            }

        }

        dbot_context = {
            'Indicator': filename,
            'Type': 'filename',
            'Vendor': VENDOR_NAME,
            'Score': MALICIOUS_REPUTATION_SCORE,
            'Reliability': demisto.params().get('integrationReliability')
        }

        ignite_filename_context = []
        for indicator in resp:
            indicator = indicator.get('Attribute', {})
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
            ignite_filename_context.append(event)

        ec = {
            'DBotScore': dbot_context,
            'Filename(val.Name == obj.Name)': filename_context,
            IGNITE_PATHS['Filename']: ignite_filename_context
        }

        return CommandResults(
            outputs=remove_empty_elements(ec),
            readable_output=hr,
            raw_response=resp,
        )

    hr = HR_TITLE.format('Filename') + filename + '\n'
    hr += REPUTATION_UNKNOWN
    ec = {
        'DBotScore': {
            'Indicator': filename,
            'Type': 'filename',
            'Vendor': VENDOR_NAME,
            'Score': UNKNOWN_REPUTATION_SCORE,
            'Reliability': demisto.params().get('integrationReliability')
        },
        'Filename(val.Name == obj.Name)': {
            'Name': filename,
            'Description': UNKONWN_DESCRIPTION
        }
    }

    return CommandResults(
        outputs=remove_empty_elements(ec),
        readable_output=hr,
        raw_response=resp,
    )


def ip_lookup_command(client: Client, ip: str) -> CommandResults:
    """
    Lookup a particular ip-address.

    This command searches for the ip in Ignite's IOC Dataset. If found, mark it as Malicious.
    If not found, lookup in Community search for matching peer ip. If found, mark it as Suspicious.

    : param client: object of client class
    : param ip: ip-address
    : return: command output
    """
    if not is_ip_valid(ip, True):
        raise ValueError(MESSAGES['INVALID_IP_ADDRESS'].format(ip))

    query = QUERY + urllib.parse.quote(ip.encode('utf-8')) + '"'
    response = client.http_request('GET', url_suffix=get_url_suffix(query))

    indicators = []
    if isinstance(response, list):
        indicators = deepcopy(response)

    if len(indicators) > 0:

        human_readable = HR_TITLE.format('IP Address') + ip + '\n'
        human_readable += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        human_readable += tableToMarkdown(TABLE_TITLE, events_details['events'], [DATE_OBSERVED, 'Name', 'Tags'])

        # Constructing FP Deeplink
        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_IP'].format(ip))
        human_readable += ALL_DETAILS_LINK.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name=VENDOR_NAME,
            score=MALICIOUS_REPUTATION_SCORE,
            malicious_description=MALICIOUS_DESCRIPTION,
            reliability=demisto.params().get('integrationReliability')
        )
        dbot_score.integration_name = VENDOR_NAME

        relationships = create_relationships_list(client, events_details, ip)
        ip_ioc = Common.IP(
            ip=ip,
            dbot_score=dbot_score,
            relationships=relationships
        )

        ignite_ip_context = []
        for indicator in response:
            indicator = indicator.get('Attribute', {})
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
            ignite_ip_context.append(event)

        command_results = CommandResults(
            outputs_prefix=OUTPUT_PREFIX['IP'],
            outputs_key_field='Fpid',
            outputs=ignite_ip_context,
            readable_output=human_readable,
            indicator=ip_ioc,
            raw_response=response,
            relationships=relationships
        )

    else:
        # Search for IP in Communities
        json_data = {
            'query': ip,
            'size': DEFAULT_REPUTATION_LIMIT
        }

        community_response = client.http_request('POST', url_suffix=URL_SUFFIX['COMMUNITY_SEARCH'], json_data=json_data)
        indicators = community_response.get('items', [])

        if indicators:
            community_search_link = urljoin(client.platform_url, HR_SUFFIX['COMMUNITY_SEARCH'].format(ip))

            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name=VENDOR_NAME,
                score=SUSPICIOUS_REPUTATION_SCORE,
                reliability=demisto.params().get('integrationReliability')
            )
            dbot_score.integration_name = VENDOR_NAME

            relationships = []

            hr_data = []
            for indicator in indicators:
                relationship = create_relationships_list_for_community_search(client, indicator, ip)
                filter_enrichments = deepcopy(indicator.get('enrichments', {}))
                filter_enrichments.pop('translation', None)
                filter_enrichments.pop('bins', None)
                hr_indicator = {
                    'Author': indicator.get('author', EMPTY_DATA),
                    'Date (UTC)': arg_to_datetime(indicator.get('date')).strftime(READABLE_DATE_FORMAT),  # type: ignore
                    'First Observed Date (UTC)': arg_to_datetime(
                        indicator.get('first_observed_at')).strftime(READABLE_DATE_FORMAT),  # type: ignore
                    'Last Observed Date (UTC)': arg_to_datetime(
                        indicator.get('last_observed_at')).strftime(READABLE_DATE_FORMAT),  # type: ignore
                    'Title': indicator.get('title', EMPTY_DATA),
                    'Site': indicator.get('site', EMPTY_DATA),
                    'Enrichments': filter_enrichments
                }
                relationships += relationship
                hr_data.append(hr_indicator)

            ip_ioc = Common.IP(
                dbot_score=dbot_score,
                ip=ip,
                relationships=relationships,
                description=SUSPICIOUS_DESCRIPTION.strip()
            )

            title = HR_TITLE.format('IP Address') + ip + '\n' + REPUTATION_SUSPICIOUS
            title = title[4:]
            human_readable = tableToMarkdown(title, hr_data, json_transform_mapping={
                                             'Enrichments': JsonTransformer()}, removeNull=True)
            human_readable += '\nIgnite link to community search: [{}]({})\n'.format(community_search_link, community_search_link)

            command_results = CommandResults(
                outputs_prefix=OUTPUT_PREFIX['IP_COMMUNITY_SEARCH'],
                outputs_key_field='id',
                outputs=remove_empty_elements(indicators),
                readable_output=human_readable,
                indicator=ip_ioc,
                raw_response=community_response,
                relationships=relationships
            )

        else:
            human_readable = HR_TITLE.format('IP Address') + ip + '\n'
            human_readable += REPUTATION_UNKNOWN
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name=VENDOR_NAME,
                score=UNKNOWN_REPUTATION_SCORE,
                reliability=demisto.params().get('integrationReliability')
            )
            dbot_score.integration_name = VENDOR_NAME

            ip_ioc = Common.IP(dbot_score=dbot_score, ip=ip, description=UNKONWN_DESCRIPTION.strip())
            command_results = CommandResults(
                readable_output=human_readable,
                indicator=ip_ioc,
                raw_response=response
            )

    return command_results


def common_lookup_command(client: Client, indicator_value: str) -> CommandResults:
    """
    Lookup all types of the indicators.

    :param client: object of client class
    :param indicator_value: value of the indicator to lookup
    :return: command output
    """

    try:
        ipaddress.ip_address(indicator_value)
        query = QUERY + indicator_value + '"'
    except ValueError:
        query = r'+value.\*.keyword:"' + indicator_value + '"'

    response = client.http_request('GET', url_suffix=get_url_suffix(query))

    if isinstance(response, list):
        indicators = deepcopy(response)
    else:
        indicators = []

    if len(indicators) > 0:
        indicator_type = indicators[0].get('Attribute', {}).get('type')

        human_readable = '### Ignite reputation for ' + indicator_value + '\n'
        human_readable += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        human_readable += tableToMarkdown(TABLE_TITLE, events_details['events'],
                                          [DATE_OBSERVED, 'Name', 'Tags'])

        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_SEARCH'].format(urllib.parse.quote(indicator_value)))
        human_readable += ALL_DETAILS_LINK.format(fp_link, fp_link)

        entry_context = {'DBotScore': {
            'Indicator': indicator_value,
            'Type': indicator_type,
            'Vendor': VENDOR_NAME,
            'Score': MALICIOUS_REPUTATION_SCORE,
            'Reliability': demisto.params().get('integrationReliability')
        }}

    else:
        human_readable = '### Ignite reputation for ' + indicator_value + '\n'
        human_readable += REPUTATION_UNKNOWN
        entry_context = {}

    return CommandResults(
        outputs=remove_empty_elements(entry_context),
        readable_output=human_readable,
        raw_response=response,
    )


def url_lookup_command(client: Client, url: str) -> CommandResults:
    """
    Lookup a particular url.

    :param client: object of client class
    :param url: url as indicator
    :return: command output
    """
    encoded_url = urllib.parse.quote(url.encode('utf8'))

    query = r'+type:("url") +value.\*.keyword:"' + url + '"'
    resp = client.http_request('GET', url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = deepcopy(resp)
    else:
        indicators = []

    if len(indicators) > 0:

        hr = HR_TITLE.format('URL') + url + '\n'
        hr += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown(TABLE_TITLE, events_details['events'],
                              [DATE_OBSERVED, 'Name', 'Tags'])

        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_URL'].format(encoded_url))
        hr += ALL_DETAILS_LINK.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name=VENDOR_NAME,
            score=MALICIOUS_REPUTATION_SCORE,
            malicious_description=MALICIOUS_DESCRIPTION,
            reliability=demisto.params().get('integrationReliability')
        )
        dbot_score.integration_name = VENDOR_NAME

        relationships = []
        if client.create_relationships and events_details.get('attack_ids'):
            for attack_id in events_details.get('attack_ids'):
                relationships.append(
                    EntityRelationship(name='indicator-of',
                                       entity_a=url,
                                       entity_a_type=FeedIndicatorType.URL,
                                       entity_b=attack_id,
                                       entity_b_type=FeedIndicatorType.indicator_type_by_server_version(
                                           STIX_ATTACK_PATTERN),
                                       brand=VENDOR_NAME))

        url_ioc = Common.URL(url=url, dbot_score=dbot_score, relationships=relationships)

        ignite_url_context = []
        for indicator in resp:
            indicator = indicator.get('Attribute', {})
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
            ignite_url_context.append(event)

        command_results = CommandResults(
            outputs_prefix=OUTPUT_PREFIX['URL'],
            outputs_key_field='Fpid',
            outputs=remove_empty_elements(ignite_url_context),
            readable_output=hr,
            indicator=url_ioc,
            raw_response=resp,
            relationships=relationships
        )
        return command_results

    hr = HR_TITLE.format('URL') + url + '\n'
    hr += REPUTATION_UNKNOWN
    dbot_score = Common.DBotScore(
        indicator=url,
        indicator_type=DBotScoreType.URL,
        integration_name=VENDOR_NAME,
        score=UNKNOWN_REPUTATION_SCORE,
        reliability=demisto.params().get('integrationReliability')
    )
    dbot_score.integration_name = VENDOR_NAME

    url_ioc = Common.URL(url=url, dbot_score=dbot_score, description=UNKONWN_DESCRIPTION.strip())
    command_results = CommandResults(
        indicator=url_ioc,
        readable_output=hr,
        raw_response=resp,
    )

    return command_results


def domain_lookup_command(client: Client, domain: str) -> CommandResults:
    """
    Lookup a particular domain.

    :param client: object of client class
    :param domain: domain
    :return: command output
    """

    query = r'+type:("domain") +value.\*.keyword:"' + domain + '"'
    response = client.http_request('GET', url_suffix=get_url_suffix(query))

    indicators = []
    if isinstance(response, list):
        indicators = deepcopy(response)

    if len(indicators) > 0:
        human_readable = HR_TITLE.format('Domain') + domain + '\n'
        human_readable += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        human_readable += tableToMarkdown(TABLE_TITLE, events_details['events'], [DATE_OBSERVED, 'Name', 'Tags'])

        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_DOMAIN'].format(domain))
        human_readable += ALL_DETAILS_LINK.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=VENDOR_NAME,
            score=MALICIOUS_REPUTATION_SCORE,
            malicious_description=MALICIOUS_DESCRIPTION,
            reliability=demisto.params().get('integrationReliability')
        )
        dbot_score.integration_name = VENDOR_NAME

        relationships = []
        if client.create_relationships and events_details.get('attack_ids'):
            for attack_id in events_details.get('attack_ids'):
                relationships.append(
                    EntityRelationship(name='indicator-of',
                                       entity_a=domain,
                                       entity_a_type=FeedIndicatorType.Domain,
                                       entity_b=attack_id,
                                       entity_b_type=FeedIndicatorType.indicator_type_by_server_version(STIX_ATTACK_PATTERN),
                                       brand=VENDOR_NAME))

        domain_ioc = Common.Domain(
            domain=domain,
            dbot_score=dbot_score,
            relationships=relationships
        )
        ignite_domain_context = []
        for indicator in response:
            indicator = indicator.get('Attribute', {})
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
            ignite_domain_context.append(event)

        command_results = CommandResults(
            outputs_prefix=OUTPUT_PREFIX['DOMAIN'],
            outputs_key_field='Fpid',
            outputs=remove_empty_elements(ignite_domain_context),
            readable_output=human_readable,
            indicator=domain_ioc,
            raw_response=response,
            relationships=relationships
        )

    else:
        human_readable = HR_TITLE.format('Domain') + domain + '\n'
        human_readable += REPUTATION_UNKNOWN
        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=VENDOR_NAME,
            score=UNKNOWN_REPUTATION_SCORE,
            reliability=demisto.params().get('integrationReliability')
        )
        dbot_score.integration_name = VENDOR_NAME

        domain_ioc = Common.Domain(domain=domain, dbot_score=dbot_score, description=UNKONWN_DESCRIPTION.strip())

        command_results = CommandResults(
            indicator=domain_ioc,
            readable_output=human_readable,
            raw_response=response
        )

    return command_results


def file_lookup_command(client: Client, file: str) -> CommandResults:
    """
    Lookup a particular file hash (md5, sha1, sha256, sha512, ssdeep).

    :param client: object of client class
    :param file: file as indicator
    :return: command output
    """
    query = r'+type:("md5","sha1","sha256","sha512","ssdeep") +value.\*.keyword:"' + file + '"'
    resp = client.http_request('GET', url_suffix=get_url_suffix(query))

    indicators = []
    if isinstance(resp, list):
        indicators = deepcopy(resp)

    if len(indicators) > 0:
        indicator_type = (indicators[0].get('Attribute', {}).get('type', '')).upper()
        hr = HR_TITLE.format('File') + file + '\n'
        hr += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown(TABLE_TITLE, events_details['events'],
                              [DATE_OBSERVED, 'Name', 'Tags'])

        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_FILE'].format(urllib.parse.quote(file.encode('utf-8'))))
        hr += ALL_DETAILS_LINK.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=file,
            indicator_type=DBotScoreType.FILE,
            integration_name=VENDOR_NAME,
            score=MALICIOUS_REPUTATION_SCORE,
            malicious_description=MALICIOUS_DESCRIPTION,
            reliability=demisto.params().get('integrationReliability')
        )
        dbot_score.integration_name = VENDOR_NAME

        relationships = []
        if client.create_relationships and events_details.get('attack_ids'):
            for attack_id in events_details.get('attack_ids'):
                relationships.append(
                    EntityRelationship(name='indicator-of',
                                       entity_a=file,
                                       entity_a_type=DBotScoreType.FILE,
                                       entity_b=attack_id,
                                       entity_b_type=FeedIndicatorType.indicator_type_by_server_version(
                                           STIX_ATTACK_PATTERN),
                                       brand=VENDOR_NAME))

        hash_type = get_hash_type(file)  # if file_hash found, has to be md5, sha1, sha256, sha512 or ssdeep
        if hash_type == 'md5':
            file_ioc = Common.File(md5=file, dbot_score=dbot_score, relationships=relationships)
        elif hash_type == 'sha1':
            file_ioc = Common.File(sha1=file, dbot_score=dbot_score, relationships=relationships)
        elif hash_type == 'sha256':
            file_ioc = Common.File(sha256=file, dbot_score=dbot_score, relationships=relationships)
        elif hash_type == 'sha512':
            file_ioc = Common.File(sha512=file, dbot_score=dbot_score, relationships=relationships)
        else:
            file_ioc = Common.File(ssdeep=file, dbot_score=dbot_score, relationships=relationships)

        ignite_file_context = []
        for indicator in resp:
            indicator = indicator.get('Attribute', {})
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
            ignite_file_context.append(event)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['FILE'],
            outputs_key_field='Fpid',
            outputs=remove_empty_elements(ignite_file_context),
            readable_output=hr,
            indicator=file_ioc,
            raw_response=resp,
            relationships=relationships
        )

    hr = HR_TITLE.format('File') + file + '\n'
    hr += REPUTATION_UNKNOWN

    dbot_score = Common.DBotScore(
        indicator=file,
        indicator_type=DBotScoreType.FILE,
        integration_name=VENDOR_NAME,
        score=UNKNOWN_REPUTATION_SCORE,
        reliability=demisto.params().get('integrationReliability')
    )
    dbot_score.integration_name = VENDOR_NAME

    file_ioc = Common.File(name=file, dbot_score=dbot_score, description=UNKONWN_DESCRIPTION.strip())

    command_results = CommandResults(
        indicator=file_ioc,
        readable_output=hr,
        raw_response=resp,
    )
    return command_results


def get_reports_command(client, args) -> CommandResults:
    """
    Get reports matching the given search term or query.

    :param client: object of client class
    :param args: demisto args
    :return: command output
    """
    report_search = args.get('report_search')
    if not report_search:
        raise ValueError(MESSAGES['MISSING_REQUIRED_ARGS'].format('report_search'))
    params = {'query': urllib.parse.quote(report_search), 'limit': DEFAULT_REPORT_LIMIT}

    response = client.http_request(method='GET', url_suffix=URL_SUFFIX['REPORT_SEARCH'], params=params)
    reports = deepcopy(response.get('data', []))
    human_readable = '### Ignite Intelligence reports related to search: ' + report_search + '\n'
    report_details: List[Any] = []

    if reports:
        human_readable += 'Top 5 reports:\n\n'

        index = 0
        for report in reports:
            title = report.get('title', EMPTY_DATA)
            platform_url = report.get('platform_url', '')
            if isinstance(platform_url, str) and DEFAULT_OLD_PLATFORM_PATH in platform_url:
                platform_url = platform_url.replace(DEFAULT_OLD_PLATFORM_PATH, DEFAULT_PLATFORM_PATH)
            summary = string_escape_markdown(report.get('summary', EMPTY_DATA))
            index += 1
            human_readable += '' + str(index) + ') [{}]({})'.format(title, platform_url) + '\n'
            if report.get('summary'):
                human_readable += '   Summary: ' + str(summary) + '\n\n\n'
            else:
                human_readable += '   Summary: N/A\n\n\n'

            report_detail = {
                'ReportId': report.get('id', EMPTY_DATA),
                'UpdatedAt': report.get('updated_at', ''),
                'PostedAt': report.get('posted_at', ''),
                'NotifiedAt': report.get('notified_at', ''),
                'PlatformUrl': platform_url,
                'Title': title,
                'Summary': summary
            }
            report_details.append(report_detail)
        report_details = remove_empty_elements(report_details)

        fp_url = urljoin(client.platform_url, '/cti/intelligence/search?sort_date=All Time&query=' + report_search)
        fp_url = urllib.parse.quote(fp_url, safe=':/?&=')
        human_readable += 'Link to Report-search on Ignite platform: [{}]({})\n'.format(fp_url, fp_url)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['REPORT'],
            outputs_key_field=OUTPUT_KEY_FIELD['REPORT_ID'],
            outputs=report_details,
            readable_output=human_readable,
            raw_response=response
        )

    human_readable += 'No reports found for the search.'
    return CommandResults(
        readable_output=human_readable,
        raw_response=response
    )


def flashpoint_ignite_compromised_credentials_list_command(client: Client, args: dict) -> CommandResults:
    """
    List compromised credentials from Flashpoint Ignite platform.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    args = validate_compromised_credentials_list_args(args)
    response = client.http_request('GET', url_suffix=URL_SUFFIX['COMPROMISED_CREDENTIALS'], params=args)

    hits = deepcopy(response.get('hits', {}).get('hits', []))
    if not hits:
        return CommandResults(
            readable_output=MESSAGES['NO_RECORDS_FOUND'].format('compromised credentials'),
            raw_response=response
        )

    readable_output = ''

    total_records = response.get('hits', {}).get('total')
    if total_records:
        readable_output += f'#### Total number of records found: {total_records}\n\n'

    readable_output += prepare_hr_for_compromised_credentials(hits)

    outputs = remove_empty_elements(hits)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['COMPROMISED_CREDENTIALS'],
        outputs_key_field=OUTPUT_KEY_FIELD['COMPROMISED_CREDENTIAL_ID'],
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response
    )


def get_report_by_id_command(client: Client, args: Dict) -> CommandResults:
    """
    Get specific report using its fpid.

    :param client: object of client class
    :param args: demisto args
    :return: command output
    """
    report_id = args.get('report_id')
    if not report_id:
        raise ValueError(MESSAGES['MISSING_REQUIRED_ARGS'].format('report_id'))

    response = client.http_request(
        method='GET', url_suffix=URL_SUFFIX['GET_REPORT_BY_ID'].format(urllib.parse.quote(str(report_id))))
    report = deepcopy(response)

    human_readable = '### Ignite Intelligence Report details\n'

    if report:
        if report.get('tags') is None:
            raise ValueError(MESSAGES['NO_RECORD_FOUND'])

        timestamp = None
        try:
            time_str = report.get('posted_at', '')[:-10] + 'UTC'
            timestamp = time.strptime(time_str, '%Y-%m-%dT%H:%M:%S%Z')
        except (TypeError, ValueError):
            pass

        tags = report.get('tags', [])
        tag_string = ', '.join(tags)

        if timestamp:
            timestamp_str = time.strftime(READABLE_DATE_FORMAT, timestamp)
        else:
            timestamp_str = EMPTY_DATA

        platform_url = report.get('platform_url', '')
        if isinstance(platform_url, str) and DEFAULT_OLD_PLATFORM_PATH in platform_url:
            platform_url = platform_url.replace(DEFAULT_OLD_PLATFORM_PATH, DEFAULT_PLATFORM_PATH)
        report_details = [{
            'Title': STRING_FORMAT.format(report.get('title', EMPTY_DATA), platform_url),
            'Date Published (UTC)': timestamp_str,
            'Summary': string_escape_markdown(report.get('summary', EMPTY_DATA)),
            'Tags': tag_string
        }]

        human_readable += tableToMarkdown('Below are the details found:', report_details,
                                          ['Title', 'Date Published (UTC)', 'Summary', 'Tags'])
        human_readable += '\n'
        entry_context = {
            'ReportId': report.get('id', ''),
            'UpdatedAt': report.get('updated_at', ''),
            'PostedAt': report.get('posted_at', ''),
            'NotifiedAt': report.get('notified_at', ''),
            'PlatformUrl': platform_url,
            'Title': report.get('title', ''),
            'Summary': report.get('summary', ''),
            'Tags': tag_string
        }
        entry_context = remove_empty_elements(entry_context)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['REPORT'],
            outputs_key_field=OUTPUT_KEY_FIELD['REPORT_ID'],
            outputs=entry_context,
            readable_output=human_readable,
            raw_response=response
        )

    human_readable += 'No report found for the given ID.'
    return CommandResults(
        readable_output=human_readable,
        raw_response=response
    )


def related_report_list_command(client: Client, args: Dict) -> CommandResults:
    """
    Get reports related to given report.

    :param args: demisto args
    :param client: object of client class
    :return: command output
    """
    report_id = args.get('report_id')
    if not report_id:
        raise ValueError(MESSAGES['MISSING_REQUIRED_ARGS'].format('report_id'))
    params = {'limit': DEFAULT_REPORT_LIMIT}

    response = client.http_request(
        method='GET', url_suffix=URL_SUFFIX['RELATED_REPORT_LIST'].format(urllib.parse.quote(str(report_id))), params=params)
    reports = deepcopy(response.get('data', []))
    human_readable = '### Ignite Intelligence related reports:\n'
    report_details: List[Any] = []

    if reports:
        human_readable += 'Top 5 related reports:\n\n'
        index = 0
        for report in reports:
            title = report.get('title', EMPTY_DATA)
            platform_url = report.get('platform_url', '')
            if isinstance(platform_url, str) and DEFAULT_OLD_PLATFORM_PATH in platform_url:
                platform_url = platform_url.replace(DEFAULT_OLD_PLATFORM_PATH, DEFAULT_PLATFORM_PATH)
            summary = string_escape_markdown(report.get('summary', EMPTY_DATA))
            index += 1
            human_readable += '' + str(index) + ') [{}]({})'.format(title, platform_url) + '\n'
            human_readable += '   Summary: ' + str(summary) + '\n\n\n'

            report_detail = {
                'ReportId': report.get('id', EMPTY_DATA),
                'UpdatedAt': report.get('updated_at', ''),
                'PostedAt': report.get('posted_at', ''),
                'NotifiedAt': report.get('notified_at', ''),
                'PlatformUrl': platform_url,
                'Title': title,
                'Summary': summary
            }
            report_details.append(report_detail)
        report_details = remove_empty_elements(report_details)

        fp_url = urljoin(client.platform_url, HR_SUFFIX['REPORT'].format(urllib.parse.quote(str(report_id))))
        human_readable += 'Link to the given Report on Ignite platform: [{}]({})\n'.format(fp_url, fp_url)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['REPORT'],
            outputs_key_field=OUTPUT_KEY_FIELD['REPORT_ID'],
            outputs=report_details,
            readable_output=human_readable,
            raw_response=response
        )

    human_readable += 'No reports found for the search.'
    return CommandResults(
        readable_output=human_readable,
        raw_response=response
    )


def event_list_command(client, args) -> CommandResults:
    """
        Get events matching the given parameters.

        :param client: object of client class
        :param args: demisto args
        :return: command output
        """
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT), 'limit')
    report_fpid = args.get('report_fpid')
    attack_ids = args.get('attack_ids')
    time_period = args.get('time_period')
    url_suffix = f'{URL_SUFFIX["EVENT_LIST"]}?sort_timestamp=desc&'
    getvars = {}
    if limit or limit == 0:
        if limit < 1 or limit > MAX_PRODUCT:
            raise DemistoException(MESSAGES['LIMIT_ERROR'].format(limit, MAX_PRODUCT))
        getvars['limit'] = limit

    if report_fpid:
        getvars['report'] = report_fpid

    if attack_ids:
        getvars['attack_ids'] = attack_ids

    if time_period:
        getvars['time_period'] = time_period

    url_suffix = url_suffix + urllib.parse.urlencode(getvars)

    resp = client.http_request("GET", url_suffix=url_suffix)
    indicators = deepcopy(resp)
    hr = ''
    events = []

    if len(indicators) > 0:
        hr += '### Ignite Events\n\n'

        for indicator in indicators:
            href = indicator.get('href', '')
            event = indicator.get('Event', {})
            fpid = indicator.get('fpid', '')
            event = parse_event_response(client, event, fpid, href)
            if indicator.get('malware_description'):
                event['Malware Description'] = indicator.get('malware_description')
            events.append(event)

        hr += tableToMarkdown('Below are the detail found:', events,
                              [TIME_OBSERVED, 'Name', 'Tags', 'Malware Description'])

        fp_link = urljoin(client.platform_url, HR_SUFFIX['IOC_LIST'])
        hr += ALL_DETAILS_LINK.format(fp_link, fp_link)

        # Replacing the dict keys for ec  to strip any white spaces and special characters
        for event in events:
            replace_key(event, 'ObservedTime', TIME_OBSERVED)
            replace_key(event, 'MalwareDescription', 'Malware Description')
            replace_key(event, 'Name', 'EventName')

        events = remove_empty_elements(events)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX['EVENT'],
            outputs_key_field=OUTPUT_KEY_FIELD['EVENT_ID'],
            outputs=events,
            readable_output=hr,
            raw_response=resp
        )

    hr += MESSAGES['NO_RECORDS_FOUND'].format('events')
    return CommandResults(
        readable_output=hr,
        raw_response=resp
    )


def event_get_command(client, args) -> CommandResults:
    """
    Get specific event using its event id.

    :param client: object of client class
    :param args: demisto args
    :return: command output
    """
    event_id = args.get('event_id')
    if not event_id:
        raise DemistoException(MESSAGES['MISSING_REQUIRED_ARGS'].format('event_id'))
    url_suffix = URL_SUFFIX["EVENT_GET"].format(urllib.parse.quote(event_id.encode('utf-8')))
    resp = client.http_request("GET", url_suffix=url_suffix)

    ec: Dict[Any, Any] = {}

    if len(resp) <= 0:
        hr = MESSAGES['NO_RECORDS_FOUND'].format('event')
        return CommandResults(
            readable_output=hr,
            raw_response=resp
        )

    hr = '### Ignite Event details\n'
    indicator = deepcopy(resp[0])
    event = indicator.get('Event', '')
    fpid = indicator.get('fpid', '')
    href = indicator.get('href', '')

    if event:
        event = parse_event_response(client, event, fpid, href)
        if indicator.get('malware_description'):
            event['Malware Description'] = indicator.get('malware_description', '')

        hr += tableToMarkdown('Below are the detail found:', event,
                              [TIME_OBSERVED, 'Name', 'Tags', 'Malware Description'])

        ec = {
            'EventId': event['EventId'],
            'UUID': event['UUID'],
            'Name': event['EventName'],
            'Tags': event['Tags'],
            'ObservedTime': event[TIME_OBSERVED],
            'EventCreatorEmail': event['EventCreatorEmail'],
            'Href': href
        }
        # if no key `malware_description` is present, it should not be included in context data
        if event.get('Malware Description'):
            ec['MalwareDescription'] = event['Malware Description']

    ec = remove_empty_elements(ec)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX['EVENT'],
        outputs_key_field=OUTPUT_KEY_FIELD['EVENT_ID'],
        outputs=ec,
        readable_output=hr,
        raw_response=resp
    )


def alert_list_command(client: Client, args: Dict):
    """
    List alerts notification from Flashpoint Ignite.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    params = validate_alert_list_args(args)

    response = client.http_request('GET', url_suffix=URL_SUFFIX['ALERTS'], params=params)

    alerts = deepcopy(response.get('items', []))
    command_results = []

    if alerts:
        human_readable = prepare_hr_for_alerts(alerts, client.platform_url)

        alert_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX['ALERT'],
            outputs_key_field='id',
            outputs=remove_empty_elements(alerts),
            raw_response=response,
            readable_output=human_readable,
        )
        command_results.append(alert_result)

        _next = response.get('pagination', {}).get('next')
        if _next:
            token_hr = PAGINATION_HR
            parsed_url = urllib.parse.urlparse(_next)
            query_params = urllib.parse.parse_qs(parsed_url.query)

            token_context_keys = ['created_after', 'created_before', 'size', 'cursor']
            token_context = {key: EMPTY_DATA for key in token_context_keys}

            for query in token_context_keys:
                query_value = query_params.get(query)
                if query_value:
                    token_context[query] = query_value[0]
                    token_hr += '\n' + query + ' = ' + token_context[query]

            token_context['name'] = 'flashpoint-ignite-alert-list'
            token_context = remove_empty_elements(token_context)

            token_result = CommandResults(
                outputs_prefix=OUTPUT_PREFIX['TOKEN'],
                outputs_key_field='name',
                outputs=token_context,
                readable_output=token_hr
            )
            command_results.append(token_result)
    else:
        command_results.append(
            CommandResults(
                raw_response=response,
                readable_output=MESSAGES['NO_RECORDS_FOUND'].format('alerts')
            )
        )

    return command_results


def main():
    """main function, parses params and runs command functions"""
    params = remove_space_from_args(demisto.params())
    remove_nulls_from_dictionary(params)

    api_key = str(params.get('credentials', {}).get('password', '')).strip()
    url = params.get('url')

    verify = not argToBoolean(params.get("insecure", False))

    create_relationships = argToBoolean(params.get('create_relationships', True))

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = argToBoolean(params.get("proxy", False))

    args = remove_space_from_args(demisto.args())
    remove_nulls_from_dictionary(args)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}.")

    try:
        headers = {
            'Authorization': f"Bearer {api_key}",
            'X-FP-IntegrationPlatform': INTEGRATION_PLATFORM,
            'X-FP-IntegrationPlatformVersion': get_demisto_version_as_str(),
            'X-FP-IntegrationVersion': INTEGRATION_VERSION
        }
        validate_params(command, params)
        client = Client(url, headers, verify, proxy, create_relationships)

        COMMAND_TO_FUNCTION: Dict = {
            'flashpoint-ignite-intelligence-report-search': get_reports_command,
            'flashpoint-ignite-compromised-credentials-list': flashpoint_ignite_compromised_credentials_list_command,
            'flashpoint-ignite-intelligence-report-get': get_report_by_id_command,
            'flashpoint-ignite-intelligence-related-report-list': related_report_list_command,
            'flashpoint-ignite-event-list': event_list_command,
            'flashpoint-ignite-event-get': event_get_command,
            'flashpoint-ignite-alert-list': alert_list_command,
        }

        REPUTATION_COMMAND_TO_FUNCTION: Dict = {
            'email': email_lookup_command,
            'filename': filename_lookup_command,
            'url': url_lookup_command,
            'domain': domain_lookup_command,
            'file': file_lookup_command,
            'ip': ip_lookup_command
        }

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))  # NOSONAR

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params, False)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'flashpoint-ignite-common-lookup':
            indicator_value = args.get('indicator')
            if not indicator_value:
                raise ValueError(MESSAGES['MISSING_REQUIRED_ARGS'].format('indicator'))
            indicator_list = argToList(indicator_value)
            indicator_list = [indicator.strip() for indicator in indicator_list if indicator.strip()]
            results = []
            if not indicator_list:
                raise ValueError(MESSAGES['MISSING_REQUIRED_ARGS'].format('indicator'))
            for indicator in indicator_list:
                results.append(common_lookup_command(client, indicator))
            return_results(results)

        elif REPUTATION_COMMAND_TO_FUNCTION.get(command):
            if not args.get(command):
                raise ValueError(MESSAGES['MISSING_REQUIRED_ARGS'].format(command))
            indicator_list = argToList(args.get(command))
            indicator_list = [indicator.strip() for indicator in indicator_list if indicator.strip()]
            results = []
            if not indicator_list:
                raise ValueError(MESSAGES['MISSING_REQUIRED_ARGS'].format(command))
            for indicator in indicator_list:
                results.append(REPUTATION_COMMAND_TO_FUNCTION[command](client, indicator))
            return_results(results)

        elif COMMAND_TO_FUNCTION.get(command):
            return_results(COMMAND_TO_FUNCTION[command](client, args))

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except requests.exceptions.ConnectionError as c:
        """ Caused mostly when URL is altered."""
        return_error(f'Failed to execute {command} command. Error: {str(c)}')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
