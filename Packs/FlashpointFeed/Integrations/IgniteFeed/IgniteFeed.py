""" Flashpoint Ignite Feed Integration for Cortex XSOAR (aka Demisto) """

""" IMPORTS """

from typing import Any, Dict, Tuple  # noqa E402

import urllib3  # noqa E402

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
LIMIT = 10
MAX_INDICATORS = 10000
MAX_FETCH = 1000
DEFAULT_FIRST_FETCH = '3 days'
CURRENT_TIME = 'now'
DEFAULT_OFFSET = 0
DEFAULT_SORT_ORDER = 'asc'
DEFAULT_INDICATOR_TYPE = 'Flashpoint Indicator'
FILE_TYPES = ['sha1', 'sha256', 'sha512', 'md5', 'ssdeep']
TIMEOUT = 60
STATUS_LIST_TO_RETRY = (429, *(
    status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (200, 201)
TOTAL_RETRIES = 4
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s, 60s] between retries.
URL_SUFFIX = {
    "ATTRIBUTES": "/technical-intelligence/v1/attribute"
}
MESSAGES = {
    "NO_PARAM_PROVIDED": "Please provide the {}.",
    "LIMIT_ERROR": "{} is an invalid value for limit. Limit must be between 1 and {}.",
    "NO_INDICATORS_FOUND": "No indicators were found for the given argument(s).",
    "TIME_RANGE_ERROR": f"The maximum indicators to fetch for the given first fetch can not exceed {MAX_INDICATORS}."
                        " Current indicators are {}. Try decreasing the time interval."
}
HTTP_ERRORS = {
    400: "Bad request: An error occurred while fetching the data.",
    401: "Authentication error: Please provide valid API Key.",
    403: "Forbidden: Please provide valid API Key.",
    404: "Resource not found: Invalid endpoint was called.",
    500: "Internal server error: Please try again after some time."
}
INTEGRATION_VERSION = "2.0.4"
INTEGRATION_PLATFORM = 'Cortex XSOAR'
DEFAULT_API_PATH = 'api.flashpoint.io'
DEFAULT_PLATFORM_PATH = 'https://app.flashpoint.io'
IGNITE_FEED_EVENT_HREF = 'https://app.flashpoint.io/cti/malware/iocs/'
FLASHPOINT_FEED_MAPPING = {
    "firstseenbysource": {"path": "first_observed_at.date-time", "type": "date"},
    "tags": {"path": "Event.Tag.name", "type": "tags"},
    "flashpointfeedattributeid": {"path": "fpid", "type": "str"},
    "flashpointfeedattributeuuid": {"path": "uuid", "type": "str"},
    "flashpointfeedcategory": {"path": "category", "type": "str"},
    "flashpointfeedeventcreatoremail": {"path": "Event.event_creator_email", "type": "str"},
    "flashpointfeedeventhref": {"path": "Event.uuid", "type": "url"},
    "flashpointfeedeventinformation": {"path": "Event.info", "type": "str"},
    "flashpointfeedeventuuid": {"path": "Event.uuid", "type": "str"},
    "flashpointfeedindicatortype": {"path": "type", "type": "str"},
    "flashpointfeedhtmlmalwaredescription": {"path": "malware_description", "type": "str"},
    "flashpointfeedreport": {"path": "Event.report", "type": "url"},
    "flashpointfeedtimestamp": {"path": "timestamp", "type": "date"}
}
HR_SUFFIX = {
    'IOC_UUID_LIST': '/cti/malware/iocs?query={}&sort_date=All%20Time',
}


class Client(BaseClient):
    """Client class to interact with the service API."""

    def __init__(self, url, headers, verify, proxy):
        """Initialize class object.

        :type url: ``str``
        :param url: Base server address with suffix, for example: https://example.com.

        :type headers: ``Dict``
        :param headers: Additional headers to be included in the requests.

        :type verify: ``bool``
        :param verify: Use to indicate secure/insecure http request.

        :type proxy: ``bool``
        :param proxy: The proxy settings to be used.

        """
        self.url = url

        if DEFAULT_API_PATH in url:
            self.platform_url = DEFAULT_PLATFORM_PATH
        else:
            self.platform_url = url

        self.headers = headers
        self.verify = verify
        self.proxy = proxy

        super().__init__(base_url=self.url, headers=self.headers, verify=self.verify, proxy=self.proxy)

    def http_request(self, url_suffix: str, params: Optional[dict[str, Any]], method: str = 'GET',
                     resp_type: str = 'json') -> Any:
        """
        Get http response based on url and given parameters.

        :param url_suffix: url encoded url suffix.
        :param params: URL parameters to specify the query.
        :param method: Specify http methods.
        :param resp_type: Response type to be returned.

        :return: http response on json.
        """
        resp = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            ok_codes=OK_CODES,
            error_handler=self.handle_errors,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            retries=TOTAL_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            timeout=TIMEOUT,
            resp_type=resp_type,
        )

        return resp

    def check_indicator_type(self, indicator_value: str, default_map: bool) -> str:
        """
        Set the type of the indicator.

        :param indicator_value: Value of the indicator.
        :param default_map: To enable the default mapper setting for the indicator.

        :return: Type of the indicator.
        """
        ind_type = DEFAULT_INDICATOR_TYPE
        if not default_map:
            ind_type = auto_detect_indicator_type(indicator_value)

            if not ind_type:
                ind_type = DEFAULT_INDICATOR_TYPE

        return ind_type

    def create_relationship(self, entity_a: str, entity_a_type: str, tags: list) -> List:
        """
        Create a list of relationships objects from the tags.

        :param entity_a: the entity a of the relation which is the current indicator.
        :param entity_a_type: the entity a type which is the type of the current indicator.
        :param tags: list of tags returned from the API.

        :return: list of EntityRelationship objects containing all the relationships.
        """
        my_tags = [tag for tag in tags if tag.get('is_galaxy')]
        relationships = []
        for tag in my_tags:
            name = tag.get('name')
            if name and 'misp-galaxy:mitre-enterprise-attack' in name:
                # operations for entity_b
                names = name.split('=')
                entity_b_value = names[1].replace('\"', '')
                entity_b_values = entity_b_value.split('-')
                entity_b = entity_b_values[0].strip()

                # operations for entity_b_type
                entity_b_types = names[0].split('misp-galaxy:mitre-enterprise-attack-')
                entity_b_type = ' '.join(w[0].upper() + w[1:] for w in entity_b_types[1].split('-'))
                entity_b_type = entity_b_type.replace(' Of ', ' of ')

                obj = EntityRelationship(
                    name=EntityRelationship.Relationships.INDICATOR_OF,
                    entity_a=entity_a,
                    entity_a_type=entity_a_type,
                    entity_b=entity_b,
                    entity_b_type=entity_b_type
                )
                obj = obj.to_indicator()
                relationships.append(obj)

        return relationships

    def map_indicator_fields(self, resp: dict, indicator_obj: dict) -> None:
        """
        Map fields of indicators from the response.

        :param resp: raw response of indicator.
        :param indicator_obj: created indicator object.

        :return: None.
        """
        for key, value in FLASHPOINT_FEED_MAPPING.items():
            if key == 'tags':
                new_tags = indicator_obj.get('fields', {}).get('tags')
                event_tags = resp.get('Event', {}).get('Tag', {})
                true_value = new_tags + [tag.get('name') for tag in event_tags]
            elif key == 'flashpointfeedeventhref':
                fpid = resp.get('fpid', '')
                true_value = urljoin(IGNITE_FEED_EVENT_HREF, fpid)
            elif key == 'flashpointfeedtimestamp':
                timestamp = int(resp.get('timestamp')) * 1000  # type: ignore
                true_value = timestamp_to_datestring(timestamp, DATE_FORMAT, is_utc=True)
            else:
                path = value.get('path', '')
                paths = path.split('.')
                true_value = resp

                try:
                    for p in paths:
                        true_value = true_value.get(p)
                except AttributeError:
                    true_value = None

            indicator_obj['fields'][key] = true_value

    def create_indicators_from_response(self, response: Any, params: dict) -> List:
        """
        Create indicators from the response.

        :param response: response received from the API.
        :param params: dictionary of parameters.

        :return: List of indicators.
        """
        indicators = []
        feed_tags = argToList(params.get('feedTags'))
        tlp_color = params.get('tlp_color')
        relationship = params.get('createRelationship', False)
        default_map = params.get('defaultMap', False)

        for resp in response:
            source_type = resp.get('type')
            indicator_value = resp.get('value', {}).get(source_type)
            indicator_type = self.check_indicator_type(indicator_value=indicator_value, default_map=default_map)
            indicator_obj = {
                'value': indicator_value,
                'type': indicator_type,
                'rawJSON': resp,
                'fields': {
                    'tags': feed_tags,
                }
            }
            if tlp_color:
                indicator_obj['fields']['trafficlightprotocol'] = tlp_color

            if relationship:
                event_tags = resp.get('Event', {}).get('Tag', '')
                relationships = self.create_relationship(indicator_value, indicator_type, event_tags)  # type: ignore
                indicator_obj['relationships'] = [] if not event_tags else relationships

            self.map_indicator_fields(resp, indicator_obj)

            indicators.append(indicator_obj)

        return indicators

    def fetch_indicators(self, params: dict, resp_type: str = 'json') -> Any:
        """
        Fetch the list of indicators based on specified arguments.

        :param params: Parameters to be sent with API call.
        :param resp_type: Response type to be returned.

        :return: List of indicators.
        """
        response = self.http_request(
            url_suffix=URL_SUFFIX['ATTRIBUTES'],
            params=params,
            method='GET',
            resp_type=resp_type
        )

        return response

    @staticmethod
    def handle_errors(resp) -> None:
        """Handle http errors."""
        status = resp.status_code
        if status in HTTP_ERRORS:
            raise DemistoException(HTTP_ERRORS[status])
        else:
            resp.raise_for_status()


''' HELPER FUNCTIONS '''


def remove_space_from_args(args):
    """
    Remove space from args.

    :param args: Arguments.

    :return: Argument's dictionary without spaces.
    """
    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()
    return args


def check_value_of_total_records(total: Any, next_run: dict) -> None:
    """
    Check if total number of records are more than the limit or not.

    :param total: Total number of records
    :param next_run: Dictionary to set in last run

    :return: None
    """
    if total:
        if total > MAX_INDICATORS:  # type: ignore
            raise ValueError(MESSAGES['TIME_RANGE_ERROR'].format(total))
        next_run['total'] = total


def validate_params(params: dict):
    """
    Validate the parameters.

    :param params: Params to validate.
    """
    if not params.get('url'):
        raise DemistoException(MESSAGES["NO_PARAM_PROVIDED"].format('Server URL'))
    if not str(params.get('credentials', {}).get('password', '')).strip():
        raise DemistoException(MESSAGES["NO_PARAM_PROVIDED"].format('API Key'))


def validate_get_indicators_args(args: dict) -> dict:
    """
    Validate the argument list for get indicators.

    :param args: Dictionary of arguments.

    :return: Updated dictionary of arguments.
    """
    fetch_params = {}

    limit = arg_to_number(args.get('limit', LIMIT))
    if limit < 1 or limit > MAX_FETCH:  # type: ignore
        raise ValueError(MESSAGES['LIMIT_ERROR'].format(limit, MAX_FETCH))
    fetch_params['limit'] = limit

    fetch_params['types'] = args.get('types', '').lower()

    first_fetch = arg_to_datetime(args.get('updated_since', DEFAULT_FIRST_FETCH))

    fetch_params['updated_since'] = first_fetch.strftime(DATE_FORMAT)  # type: ignore
    fetch_params['sort_timestamp'] = DEFAULT_SORT_ORDER  # type: ignore

    remove_nulls_from_dictionary(fetch_params)

    return fetch_params


def prepare_hr_for_indicators(indicators: list, platform_url: str) -> str:
    """
    Prepare human-readable response.

    :param indicators: List of indicators.
    :param platform_url: URL of the platform.

    :return: Indicators in human-readable format.
    """
    hr = []

    for indicator in indicators:
        raw_json = indicator.get('rawJSON')
        indicator_type = raw_json.get('type')

        updated_indicator_type = indicator_type
        if updated_indicator_type in FILE_TYPES:
            updated_indicator_type = 'File'

        event_tags = []
        tags = raw_json.get('Event', {}).get('Tag')
        if tags:
            for tag in tags:
                name = tag.get('name')
                event_tags.append(name)

        timestamp = datetime.utcfromtimestamp(int(raw_json.get('timestamp')))
        timestamp = timestamp.strftime(DATE_FORMAT)

        uuid = raw_json.get('Event', {}).get('uuid')
        fp_link = urljoin(platform_url, HR_SUFFIX['IOC_UUID_LIST'].format(uuid))
        fp_id = '[{}]({})'.format(raw_json.get('fpid'), fp_link)

        report_data = ''
        reports = raw_json.get('reports')
        if reports:
            for report in reports:
                report_data += '\n\nClick to see\n[Intelligence Report]({})'.format(report.get('html'))

        fp_id += report_data

        data = {
            'FPID': fp_id,
            'Indicator Type': updated_indicator_type,
            'Indicator Value': raw_json.get('value', {}).get(indicator_type),
            'Category': raw_json.get('category'),
            'Event Name': raw_json.get('Event', {}).get('info'),
            'Event Tags': event_tags,
            'Created Timestamp (UTC)': timestamp,
            'First Observed Date': raw_json.get('first_observed_at', {}).get('date-time')
        }
        hr.append(data)

    headers = ['FPID', 'Indicator Type', 'Indicator Value', 'Category', 'Event Name', 'Event Tags', 'Created Timestamp (UTC)',
               'First Observed Date']

    return tableToMarkdown(name='Indicator(s)', t=hr, headers=headers, removeNull=True)


def validate_fetch_indicators_params(params: dict, last_run: dict[str, Any]) -> dict:
    """
    Validate the parameter list for fetch indicators.

    :param params: Dictionary of parameters.
    :param last_run: last run object obtained from demisto.getLastRun().

    :return: Updated dictionary of parameters.
    """
    fetch_params = {'limit': MAX_FETCH, 'types': (','.join(params.get('types', ''))).lower()}

    first_fetch = arg_to_datetime(params.get('first_fetch', DEFAULT_FIRST_FETCH)).strftime(DATE_FORMAT)  # type: ignore
    # If available then take updated_since from last_run.
    updated_since = last_run.get('next_updated_since', first_fetch)

    current_time = arg_to_datetime(CURRENT_TIME).strftime(DATE_FORMAT)  # type: ignore
    # If available then take updated_until from last_run.
    updated_until = last_run.get('next_updated_until', current_time)

    offset = last_run.get('offset', DEFAULT_OFFSET)

    fetch_params['skip'] = offset
    fetch_params['updated_since'] = updated_since
    fetch_params['updated_until'] = updated_until
    fetch_params['sort_timestamp'] = DEFAULT_SORT_ORDER  # type: ignore

    remove_nulls_from_dictionary(fetch_params)

    return fetch_params


'''Command functions'''


def test_module(client: Client) -> str:
    """
    Tests the indicators from the feed.

    :param client: Client object.

    :return: 'ok' if test passed, anything else will fail the test.
    """
    params = demisto.params()
    is_fetch = params.get('feed', False)
    if is_fetch:
        fetch_indicators_command(client=client, params=params, last_run={}, is_test=True)
    else:
        client.fetch_indicators(params={'limit': 1})
    return 'ok'


def fetch_indicators_command(client: Client, params: dict, last_run: dict[str, Any], is_test: bool = False) -> tuple[List, dict]:
    """
    Fetch the indicators.

    :param client: Client object.
    :param params: Dictionary of parameters.
    :param last_run: last run object obtained from demisto.getLastRun().
    :param is_test: If test_module called fetch_incident.

    :return: List of indicators and Dict of last run object.
    """
    next_run: dict = {}

    fetch_params = validate_fetch_indicators_params(params=params, last_run=last_run)

    resp = client.fetch_indicators(params=fetch_params, resp_type='response')

    response = remove_empty_elements(resp.json())

    total = int(resp.headers.get('x-fp-total-hits', len(response)))
    check_value_of_total_records(total, next_run)

    if is_test:
        return [], {}

    # Creating new last_run according to response.
    if len(response) < MAX_FETCH:
        # Updating updated_since equal to previous updated_until.
        next_run['next_updated_since'] = last_run.get('next_updated_until', fetch_params['updated_until'])
    else:
        next_run = last_run
        next_run['next_updated_since'] = fetch_params['updated_since']
        next_run['next_updated_until'] = fetch_params['updated_until']
        # Set only offset equal to previous offset + max_fetch.
        next_run['offset'] = next_run.get('offset', DEFAULT_OFFSET) + MAX_FETCH

    indicators = client.create_indicators_from_response(response=response, params=params)

    demisto.debug(f"Set the last Run for indicators: {next_run}")

    return indicators, next_run


def flashpoint_ignite_get_indicators_command(client: Client, params: dict, args: dict) -> CommandResults:
    """
    Get limited number of indicators.

    :param client: Client object.
    :param params: Dictionary of parameters.
    :param args: Dictionary of arguments.

    :return: Standard Command Result.
    """
    fetch_params = validate_get_indicators_args(args=args)

    response = client.fetch_indicators(params=fetch_params)

    response = remove_empty_elements(response)

    indicators = client.create_indicators_from_response(response=response, params=params)

    if not indicators:
        return CommandResults(readable_output=MESSAGES['NO_INDICATORS_FOUND'])

    readable_output = prepare_hr_for_indicators(indicators=indicators, platform_url=client.platform_url)
    return CommandResults(
        readable_output=readable_output,
        raw_response=indicators
    )


'''Main Function'''


def main():
    """Parse params and runs command functions."""
    params = remove_space_from_args(demisto.params())
    remove_nulls_from_dictionary(params)

    # Get the service API url
    base_url = params.get('url', DEFAULT_API_PATH)

    api_key = str(params.get('credentials', {}).get('password', '')).strip()

    # Default configuration parameters for handling proxy and SSL Certificate validation.
    insecure = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()
    demisto.debug(f'[Ignite] Command being called is {command}')

    try:
        validate_params(params=params)
        headers: dict = {
            'Authorization': f'Bearer {api_key}',
            'X-FP-IntegrationPlatform': INTEGRATION_PLATFORM,
            'X-FP-IntegrationPlatformVersion': get_demisto_version_as_str(),
            'X-FP-IntegrationVersion': INTEGRATION_VERSION
        }
        client = Client(
            verify=insecure,
            proxy=proxy,
            url=base_url,
            headers=headers
        )
        args = demisto.args()
        if command == 'test-module':
            return_results(test_module(client=client))
        elif command == 'fetch-indicators':
            last_run = demisto.getLastRun()
            indicators, next_run = fetch_indicators_command(client=client, params=params, last_run=last_run)
            demisto.setLastRun(next_run)
            demisto.createIndicators(indicators)
        elif command == 'flashpoint-ignite-get-indicators':
            return_results(flashpoint_ignite_get_indicators_command(client=client, params=params, args=args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:  # pragma: no cover
    main()
