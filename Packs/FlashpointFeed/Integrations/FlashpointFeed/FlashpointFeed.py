from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
LIMIT = 10
TIMEOUT = 60
MAX_FETCH = 1000
DEFAULT_INDICATOR_TYPE = "Flashpoint Indicator"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_SORT_ORDER = "asc"

URL_SUFFIX = {
    "ATTRIBUTES": "/indicators/attribute"
}

MESSAGES = {
    "LIMIT_ERROR": "{} is an invalid value for limit. Limit must be between 1 and {}.",
    "NO_INDICATORS_FOUND": "No indicators were found for the given argument(s)."
}

HTTP_ERRORS = {
    400: "Bad request: An error occurred while fetching the data.",
    401: "Authentication error: Please provide valid API Key.",
    403: "Forbidden: Please provide valid API Key.",
    404: "Resource not found: Invalid endpoint was called.",
    500: "Internal server error: Please try again after some time."
}

INTEGRATION_VERSION = "v1.0.0"
INTEGRATION_PLATFORM = "XSOAR Cortex"

FILE_TYPES = ['sha1', 'sha256', 'sha512', 'md5']

flashpoint_field_mapping = {
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
    "flashpointfeedmalwaredescription": {"path": "malware_description", "type": "str"},
    "flashpointfeedreport": {"path": "Event.report", "type": "url"},
    "flashpointfeedtimestamp": {"path": "timestamp", "type": "str"}
}


class Client(BaseClient):
    """Client class to interact with the service API"""

    def http_request(self, url_suffix, method="GET", params=None) -> Any:
        """
        Get http response based on url and given parameters.

        :param method: Specify http methods
        :param url_suffix: url encoded url suffix
        :param params: None

        :return: http response on json
        """
        resp = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            ok_codes=(200, 201),
            error_handler=self.handle_errors,
            timeout=TIMEOUT
        )

        return resp

    def check_indicator_type(self, indicator_value: str, default_map: bool) -> str:
        """
        Function to set the type of the indicator.

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
        if not tags:
            return []

        my_tags = [tag for tag in tags if tag.get('is_galaxy')]
        relationships = []
        for tag in my_tags:
            name = tag.get('name')
            if name and 'misp-galaxy:mitre-enterprise-attack' in name:
                # operations for entity_b
                names = name.split("=")
                entity_b_value = names[1].replace('\"', "")
                entity_b_values = entity_b_value.split("-")
                entity_b = entity_b_values[0].strip()

                # operations for entity_b_type
                entity_b_types = names[0].split("misp-galaxy:mitre-enterprise-attack-")
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
        Function to map indicators fields from the response

        :param resp: raw response of indicator
        :param indicator_obj: created indicator object

        :return: None
        """
        for key, value in flashpoint_field_mapping.items():
            if key == "tags":
                new_tags = indicator_obj['fields']['tags']
                event_tags = resp.get('Event', {}).get('Tag')
                true_value = new_tags + [tag.get('name') for tag in event_tags]

            elif key == "flashpointfeedeventhref":
                uuid = resp.get('Event', {}).get('uuid')
                true_value = "https://fp.tools/home/technical_data/iocs/items/" + uuid

            else:
                path = value['path']
                paths = path.split('.')
                true_value = resp

                try:
                    for p in paths:
                        true_value = true_value.get(p)
                except AttributeError:
                    true_value = None

            indicator_obj['fields'][key] = true_value

    def create_indicators_from_response(self, response: Any, last_fetch: str, params: dict, is_get: bool) -> List:
        """
        Function to create indicators from the response

        :param response: response received from the API.
        :param last_fetch: Last fetched time stamp
        :param params: dictionary of parameters
        :param is_get: Whether this request is from flashpoint-get-indicators command or not

        :return: List of indicators
        """
        indicators = []
        fetch_time = last_fetch
        feed_tags = argToList(params.get('feedTags'))
        tlp_color = params.get('tlp_color')
        relationship = params.get('createRelationship', False)
        default_map = params.get('defaultMap', False)

        for resp in response:
            source_type = resp.get('type')
            indicator_value = resp.get('value', {}).get(source_type)
            indicator_type = self.check_indicator_type(indicator_value, default_map)
            indicator_obj = {
                "value": indicator_value,
                "type": indicator_type,
                "rawJSON": resp,
                "fields": {
                    "tags": feed_tags,
                }
            }
            if tlp_color:
                indicator_obj['fields']['trafficlightprotocol'] = tlp_color

            if relationship:
                event_tags = resp.get('Event').get('Tag')
                indicator_obj['relationships'] = self.create_relationship(indicator_value, indicator_type,
                                                                          event_tags)  # type: ignore

            self.map_indicator_fields(resp, indicator_obj)

            indicators.append(indicator_obj)

            ind_date = resp.get('header_', {}).get('indexed_at')
            ind_date = datetime.utcfromtimestamp(int(ind_date)).strftime(DATE_FORMAT)

            if ind_date > fetch_time:
                fetch_time = ind_date

        if indicators and not is_get:
            context = get_integration_context()
            context.update({'last_fetch': fetch_time})
            set_integration_context(context)

        return indicators

    def fetch_indicators(self, params: dict) -> Any:
        """
        Function to fetch the list of indicators based on specified arguments

        :param params: Parameters to be sent with API call

        :return: List of indicators
        """
        response = self.http_request(
            url_suffix=URL_SUFFIX['ATTRIBUTES'],
            params=params
        )

        return response

    @staticmethod
    def handle_errors(resp) -> None:
        """
        Handling http errors
        """
        status = resp.status_code
        if status in HTTP_ERRORS:
            raise DemistoException(HTTP_ERRORS[status])
        else:
            resp.raise_for_status()


''' HELPER FUNCTIONS '''


def prepare_hr_for_indicators(indicators: list) -> str:
    """
    Makes human readable format

    :param indicators: List of indicators

    :return: Indicators in human readable format
    """
    hr = []

    for indicator in indicators:
        raw_json = indicator.get('rawJSON')
        indicator_type = raw_json.get('type')

        updated_indicator_type = indicator_type
        if updated_indicator_type in FILE_TYPES:
            updated_indicator_type = "File"

        event_tags = []
        tags = raw_json.get('Event', {}).get('Tag')
        if tags:
            for tag in tags:
                name = tag.get('name')
                event_tags.append(name)

        timestamp = datetime.utcfromtimestamp(int(raw_json.get('timestamp')))
        timestamp = timestamp.strftime(DATE_FORMAT)
        fp_id = '[{}]({})'.format(raw_json.get('fpid'), raw_json.get('href'))

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

    return tableToMarkdown("Indicator(s)", hr, ['FPID', 'Indicator Type', 'Indicator Value', 'Category', 'Event Name',
                                                'Event Tags', 'Created Timestamp (UTC)', 'First Observed Date'],
                           removeNull=True)


def validate_get_indicators_args(args: dict) -> dict:
    """
    Function to validate the argument list for get indicators

    :param args: Dictionary of arguments

    :return: Updated dictionary of arguments
    """
    fetch_params = {}

    limit = arg_to_number(args.get('limit', LIMIT))
    if limit < 1 or limit > MAX_FETCH:  # type: ignore
        raise ValueError(MESSAGES['LIMIT_ERROR'].format(limit, MAX_FETCH))
    fetch_params['limit'] = limit

    fetch_params['types'] = args.get('types')

    first_fetch = arg_to_datetime(args.get('updated_since', DEFAULT_FIRST_FETCH))

    fetch_params['updated_since'] = first_fetch.strftime(DATE_FORMAT)  # type: ignore
    fetch_params['sort_timestamp'] = DEFAULT_SORT_ORDER  # type: ignore

    fetch_params = remove_empty_elements(fetch_params)

    return fetch_params


def validate_fetch_indicators_params(params: dict) -> dict:
    """
    Function to validate the parameter list for fetch indicators

    :param params: Dictionary of parameters

    :return: Updated dictionary of parameters
    """
    fetch_params = {'limit': MAX_FETCH, 'types': params.get('types')}

    first_fetch = arg_to_datetime(params.get('first_fetch', DEFAULT_FIRST_FETCH))

    fetch_params['updated_since'] = first_fetch.strftime(DATE_FORMAT)  # type: ignore
    fetch_params['sort_timestamp'] = DEFAULT_SORT_ORDER  # type: ignore

    fetch_params = remove_empty_elements(fetch_params)

    return fetch_params


'''Command functions'''


def test_module(client: Client, params: dict) -> str:
    """Tests the indicators from the feed.
    Args:
        client: Client object.
    Returns:
        Outputs.
    """
    client.http_request(url_suffix='/indicators/attribute', params={"limit": 1})
    return 'ok'


def fetch_indicators_command(client: Client, params: dict, args: dict, is_get: bool) -> List:
    """
    Function to fetch the indicators

    :param client: Client object
    :param params: Dictionary of parameters
    :param args: Dictionary of arguments
    :param is_get: Whether this request is from flashpoint-get-indicators command or not

    :return: List of indicators
    """
    if is_get:
        fetch_params = validate_get_indicators_args(args)
    else:
        fetch_params = validate_fetch_indicators_params(params)
        context = get_integration_context()
        if context.get('last_fetch'):
            fetch_params['updated_since'] = context.get('last_fetch')

    response = client.fetch_indicators(fetch_params)
    indicators = client.create_indicators_from_response(response, fetch_params['updated_since'], params, is_get)

    return indicators


def get_indicators_command(client: Client, params: dict, args: dict) -> CommandResults:
    """
    Function to get limited number of indicators

    :param client: Client object
    :param params: Dictionary of parameters
    :param args: Dictionary of arguments

    :return: Standard Command Result
    """
    indicators = fetch_indicators_command(client, params, args, True)
    if not indicators:
        return CommandResults(readable_output=MESSAGES['NO_INDICATORS_FOUND'])

    readable_output = prepare_hr_for_indicators(indicators)
    return CommandResults(
        readable_output=readable_output,
        raw_response=indicators
    )


'''Main Function'''


def main():
    """Main function, parses params and runs command functions
    """
    params = demisto.params()
    args = demisto.args()

    # Get the service API url
    base_url = urljoin(params.get('url'), '/api/v4')
    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_key = params.get('api_key')

    command = demisto.command()
    demisto.debug(f'[Flashpoint] Command being called is {command}')
    headers: Dict = {
        'Authorization': f'Bearer {api_key}',
        'X-FP-IntegrationPlatform': INTEGRATION_PLATFORM,
        'X-FP-IntegrationPlatformVersion': get_demisto_version_as_str(),
        'X-FP-IntegrationVersion': INTEGRATION_VERSION
    }
    try:
        client = Client(
            verify=insecure,
            proxy=proxy,
            base_url=base_url,
            headers=headers
        )

        if command == 'test-module':
            return_results(test_module(client, params))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params, args, False)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif command == 'flashpoint-get-indicators':
            return_results(get_indicators_command(client, params, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
