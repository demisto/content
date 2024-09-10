import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Implementation file for FeedCyCognito."""

from typing import Any
import urllib3
import pycountry

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
HR_DATE_FORMAT = "%d %b %Y, %I:%M %p"
BASE_URL = "https://api.platform.cycognito.com/v1"
AVAILABLE_ASSET_TYPES = ["ip", "domain", "cert", "webapp", "iprange"]
AVAILABLE_HOSTING_TYPES = ["cloud", "owned", "undetermined"]
AVAILABLE_SECURITY_GRADE = ["a", "b", "c", "d", "f"]
AVAILABLE_STATUS_TYPES = ["new", "changed", "normal"]
MAX_PAGE_SIZE = 1000
DEFAULT_FIRST_FETCH = "2 weeks"
DEFAULT_MAX_FETCH = 50
CYCOGNITO_INDICATOR_TYPE = "CyCognito Asset"
INDICATOR_TYPE_MAPPING = {
    "ip": FeedIndicatorType.IP,
    "domain": FeedIndicatorType.Domain,
    "cert": CYCOGNITO_INDICATOR_TYPE,
    "webapp": CYCOGNITO_INDICATOR_TYPE,
    "iprange": CYCOGNITO_INDICATOR_TYPE,
}

ERRORS = {
    "INVALID_PAGE_SIZE": "{} is invalid value for count. Value must be in 1 to 1000.",
    "INVALID_SINGLE_SELECT_PARAM": "{} is an invalid value for {}. Possible values are: {}.",
    "INVALID_MULTI_SELECT_PARAM": "Invalid value for {}. Possible comma separated values are {}.",
    "INVALID_REQUIRED_PARAMETER": "{} is a required parameter. Please provide correct value.",
    "INVALID_COUNTRY_ERROR": "{} is an invalid country name."
}
''' CLIENT CLASS '''


class CyCognitoFeedClient(BaseClient):
    """Client class to interact with the service API."""

    def get_indicators(self, asset_type: str, count: int = None, search: str = None, offset: int = None,
                       sort_param: tuple = None, filters: list[Dict[str, Union[str, list]]] = None) -> Any:
        """Return the list of assets.

        :param asset_type: type of asset
        :param count: number of the assets to fetch
        :param offset: number of pages to skip
        :param search: search string to perform plain text search
        :param sort_param: A tuple of sort_by and sort_order parameter
        :param filters: body parameters passed with request
        :return: response from the api.
        """
        sort_by, sort_order = sort_param if sort_param else (None, None)
        query_params = {
            'count': count, 'q': search, 'offset': offset, 'sort-by': sort_by, 'sort-order': sort_order
        }
        remove_nulls_from_dictionary(query_params)
        demisto.info(f"[+] FeedCyCognito: Fetching assets for type: {asset_type}")
        demisto.info(f"[+] FeedCyCognito: Query parameters for get-indicators: {query_params}")
        demisto.info(f"[+] FeedCyCognito: Body filters for get-indicators: {filters}")
        return self._http_request(method='POST', url_suffix=f'assets/{asset_type}', params=query_params,
                                  json_data=filters)


def trim_spaces_from_args(args):
    """
    Trim spaces from values of the args dict.

    :param args: Dict to trim spaces from
    :type args: dict
    :return:
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def convert_countries_to_alpha_3_codes(countries: list[str]):
    """Convert countries into alpha-3 codes.

    :type countries: List[str]
    :param countries: Countries to be converted into alpha-3 codes.

    :rtype: List[str]
    :returns: List of countries converted into alpha-3 codes.
    """
    if not countries:
        return []

    converted_country_codes = []
    for country in filter(None, countries):
        try:
            converted_country_codes.append(pycountry.countries.search_fuzzy(country)[0].alpha_3)  # type: ignore[attr-defined]
        except LookupError as err:
            demisto.error(f"[+] FeedCyCognito: Error while parsing country name: {country}")
            raise ValueError(ERRORS['INVALID_COUNTRY_ERROR'].format(country)) from err

    return converted_country_codes


def convert_alpha_3_codes_to_country_names(locations: list[str]):
    """Convert alpha-3 code location to country name.

    :type locations: List[str]
    :param locations: Locations to be converted into country name

    :rtype: List[str]
    :returns: List of locations converted into country name.
    """
    converted_locations = []
    for location in filter(None, locations):
        try:
            converted_locations.append(pycountry.countries.search_fuzzy(location)[0].name)  # type: ignore[attr-defined]
        except LookupError as err:
            demisto.error(f"[+] FeedCyCognito: Error while parsing country code: {location}")
            raise ValueError(ERRORS['INVALID_COUNTRY_ERROR'].format(location)) from err

    return converted_locations


def validate_get_indicators_arguments(asset_type: str = None, count: Optional[int] = None,
                                      sort_order: str = None, hosting_type: list[str] = None,
                                      security_grade: list[str] = None, status: list[str] = None) -> None:
    """Validate parameters for get indicators command.

    :param asset_type: type of the asset
    :param count: number of the assets to fetch
    :param sort_order: the order in which to sort the result. possible values are asc and desc
    :param hosting_type: the list of hosting types
    :param security_grade: the list of security grades
    :param status: the list of status

    :raises ValueError: if the parameter is not in a format the command accepts
    """
    if not asset_type:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_type'))

    if asset_type not in AVAILABLE_ASSET_TYPES:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(asset_type, 'asset_type', AVAILABLE_ASSET_TYPES))

    if count and (count < 1 or count > MAX_PAGE_SIZE):
        raise ValueError(ERRORS['INVALID_PAGE_SIZE'].format(count))

    if sort_order and sort_order not in ['asc', 'desc']:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(sort_order, 'sort_order', ["asc", "desc"]))

    if not set(hosting_type).issubset(AVAILABLE_HOSTING_TYPES):  # type: ignore
        raise ValueError(ERRORS['INVALID_MULTI_SELECT_PARAM'].format('hosting_type', AVAILABLE_HOSTING_TYPES))

    if not set(security_grade).issubset(AVAILABLE_SECURITY_GRADE):  # type: ignore
        raise ValueError(ERRORS['INVALID_MULTI_SELECT_PARAM'].format(
            'security_grade', [x.upper() for x in AVAILABLE_SECURITY_GRADE]))

    if not set(status).issubset(AVAILABLE_STATUS_TYPES):  # type: ignore
        raise ValueError(ERRORS['INVALID_MULTI_SELECT_PARAM'].format('status', AVAILABLE_STATUS_TYPES))


def prepare_body_filters_for_get_indicators(asset_type: str = None, organizations: list[str] = None,
                                            hosting_type: list[str] = None, locations: list[str] = None,
                                            tags: list[str] = None, first_seen: str = None,
                                            last_seen: str = None, security_grade: list[str] = None,
                                            status: list[str] = None, only_alive: bool = False) -> list[Dict]:
    """Prepare body filters for get indicator command.

    :param asset_type: the type of the asset
    :param organizations: to retrieve the assets of specific organizations
    :param hosting_type: to retrieve the assets of specific hosting type
    :param locations: to retrieve the assets from specific countries
    :param tags: to retrieve the assets with specific tags
    :param first_seen: to retrieve the assets from a specific first seen time
    :param last_seen: to retrieve the assets from a specific last seen time
    :param security_grade: to retrieve the assets with specific security ratings
    :param status: to retrieve the assets with specific status
    :param only_alive: to fetch only live assets
    :return: returns a dictionary of query params and a list of body params
    """
    req_body = []

    fields_with_in_operator = ['organizations', 'locations', 'security-grade', 'status', 'tags', 'hosting-type']
    values_with_in_operator = [organizations, locations, security_grade, status, tags, hosting_type]

    for field, value in zip(fields_with_in_operator, values_with_in_operator):
        if value:
            req_body.append({
                'field': field,
                'op': 'in',
                'values': value
            })

    if asset_type in ['ip', 'iprange'] and only_alive:
        req_body.append({
            'field': 'alive',
            'op': 'in',
            'values': [True]  # type: ignore
        })

    if first_seen:
        req_body.append({
            'field': 'first-seen',
            'op': 'between',
            'values': [
                [first_seen, arg_to_datetime(time.time()).strftime(DATE_FORMAT)]  # type: ignore
            ]
        })

    if last_seen:
        req_body.append({
            'field': 'last-seen',
            'op': 'between',
            'values': [
                [last_seen, arg_to_datetime(time.time()).strftime(DATE_FORMAT)]  # type: ignore
            ]
        })

    return req_body


def prepare_hr_for_get_indicators(asset_type: str, response: Any) -> str:
    """Prepare human-readable output for get indicators command.

    :param asset_type: type of the asset
    :param response: response from the api
    :return: human-readable output
    """
    hr_outputs = []

    for asset in response:
        first_seen = arg_to_datetime(asset.get('first_seen'), arg_name='first_seen')  # type: ignore
        last_seen = arg_to_datetime(asset.get('last_seen'), arg_name='last_seen')  # type: ignore

        if first_seen:
            first_seen: str = first_seen.strftime(HR_DATE_FORMAT)  # type: ignore

        if last_seen:
            last_seen: str = last_seen.strftime(HR_DATE_FORMAT)  # type: ignore

        hr_outputs.append({
            'Asset ID': asset.get('id', '').split('/', 1)[-1],
            'Security Grade': asset.get('security_grade'),
            'Status': asset.get('status'),
            'Organizations': ", ".join(asset.get('organizations', [])),
            'First Seen': first_seen,
            'Last Seen': last_seen,
            'Locations': ", ".join(convert_alpha_3_codes_to_country_names(asset.get('locations', []))),
            'Hosting Type': asset.get('hosting_type')
        })

    headers = ["Asset ID", "Security Grade", "Status", "Organizations", "First Seen", "Last Seen",
               "Locations", "Hosting Type"]
    title = f"Indicator Detail:\n #### Asset type: {asset_type.title() if asset_type != 'ip' else asset_type.upper()}"
    return tableToMarkdown(title, hr_outputs, headers=headers, removeNull=True)


def build_iterators(response: list[Dict[str, Any]], feed_tags: list[str], tlp_color: str, default_mapping: bool) -> \
        list[Dict[str, Any]]:
    """
    Create indicators from response.

    :param response: response received from API.
    :param feed_tags: feed tags provided in integration configuration.
    :param tlp_color: trafficlightprotocol color provided in integration configuration.
    :param default_mapping: default mapping provided in integration configuration.

    :returns: indicators
    """
    indicators = []

    for asset in response:
        indicator = {
            'value': asset['id'].split('/', 1)[-1],
            'type': INDICATOR_TYPE_MAPPING[asset['type']] if not default_mapping else CYCOGNITO_INDICATOR_TYPE,
            'rawJSON': asset,
            'fields': {
                'tags': feed_tags,
                'feedcycognitoaliveendpoint': asset.get('alive'),
                'feedcycognitocomment': comment.get('content', '') if (comment := asset.get('comment')) else None,
                'feedcycognitoassetid': asset.get('id'),
                'feedcycognitoassettype': asset.get('type'),
                'feedcycognitobusinessunits': asset.get('business_units'),
                'feedcycognitocertificatesignature': asset.get('signature'),
                'feedcycognitoclosedports': asset.get('closed_ports'),
                'creationdate': asset.get('created'),
                'domainname': asset.get('domain'),
                'feedcycognitodomains': asset.get('domains'),
                'feedcycognitoassetdiscoverability': discoverability if (
                    discoverability := asset.get('discoverability')) else "Unknown",
                'feedcycognitoexpiration': asset.get('expiration'),
                'firstseenbysource': asset.get('first_seen'),
                'feedcycognitodynamicallyresolved': dynamically_resolved if (
                    dynamically_resolved := asset.get('dynamically_resolved')) else "",
                'feedcycognitohostingtypes': hosting_types if (hosting_types := asset.get('hosting_type')) else "",
                'feedcycognitoinvestigationstatus': asset.get('investigation_status'),
                'ipaddress': asset.get('ip'),
                'feedcycognitoipaddresses': asset.get('ip_addresses'),
                'feedcycognitoissueralternativenames': asset.get('issuer_alt_names'),
                'feedcycognitoissuercommonname': asset.get('issuer_common_name'),
                'feedcycognitoissuercountry': asset.get('issuer_country'),
                'feedcycognitoissuerlocality': asset.get('issuer_locality'),
                'feedcycognitoissuerorganization': asset.get('issuer_organization'),
                'feedcycognitoissuerorganizationunit': asset.get('issuer_organization_unit'),
                'feedcycognitoissuerstate': asset.get('issuer_state'),
                'feedcycognitoissuescount': asset.get('issues_count'),
                'lastseenbysource': asset.get('last_seen'),
                'feedcycognitolocations': convert_alpha_3_codes_to_country_names(asset.get('locations', [])),
                'feedcycognitoopenports': asset.get('open_ports'),
                'feedcycognitoorganizations': asset.get('organizations'),
                'feedcycognitostatus': status if (status := asset.get('status')) else "",
                'feedcycognitosecuritygrade': grade if (grade := asset.get('security_grade')) else "Unknown",
                'feedcycognitosevereissues': asset.get('severe_issues'),
                'feedcycognitosignaturealgorithm': asset.get('signature_algorithm'),
                'feedcycognitosubdomains': asset.get('sub_domains'),
                'feedcycognitosubjectalternativenames': asset.get('subject_alt_names'),
                'feedcycognitosubjectcommonname': asset.get('subject_common_name'),
                'feedcycognitosubjectcountry': asset.get('subject_country'),
                'feedcycognitosubjectlocality': asset.get('subject_locality'),
                'feedcycognitosubjectorganization': asset.get('subject_organization'),
                'feedcycognitosubjectorganizationunit': asset.get('subject_organization_unit'),
                'feedcycognitosubjectstate': asset.get('subject_state'),
                'feedcycognitotags': asset.get('tags'),
                'feedcycognitoopenportprotocols': [ports['protocol'] for ports in asset.get('open_ports', [])]
            }
        }
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator)

    return indicators


def get_indicators_command(client: CyCognitoFeedClient, args: Dict[str, Any]) -> CommandResults:
    """Command function for cycognito-get-indicators command.

    :param client: client object to be used
    :param args: arguments passed with the command
    :return: standard command results
    """
    asset_type = args.get('asset_type', '').lower()
    count = arg_to_number(args.get('count', 50), arg_name='count')
    offset = max(arg_to_number(args.get('offset', 0), arg_name='offset'), 0)  # type: ignore
    sort_order = args.get('sort_order', '').lower()
    hosting_type = argToList(args.get('hosting_type', '').lower())
    security_grade = argToList(args.get('security_grade', '').lower())
    status = argToList(args.get('status', '').lower())
    search = args.get('search', '')
    sort_by = args.get('sort_by', '').lower()
    organizations = argToList(args.get('organizations', '').lower())
    locations = argToList(args.get('locations', ''))
    tags = argToList(args.get('tags', ''))
    first_seen = args.get('first_seen', '')
    last_seen = args.get('last_seen', '')

    if first_seen:
        first_seen = arg_to_datetime(first_seen, arg_name='first_seen').strftime(DATE_FORMAT)  # type: ignore
    if last_seen:
        last_seen = arg_to_datetime(last_seen, arg_name='last_seen').strftime(DATE_FORMAT)  # type: ignore

    validate_get_indicators_arguments(asset_type=asset_type, count=count, sort_order=sort_order,
                                      hosting_type=hosting_type, security_grade=security_grade, status=status)

    filters = prepare_body_filters_for_get_indicators(asset_type=asset_type, organizations=organizations,
                                                      hosting_type=hosting_type, locations=locations,
                                                      tags=tags, first_seen=first_seen,
                                                      last_seen=last_seen, security_grade=security_grade,
                                                      status=status)

    response = client.get_indicators(asset_type=asset_type, count=count, offset=offset,
                                     sort_param=(sort_by, sort_order), search=search, filters=filters)
    hr_output = prepare_hr_for_get_indicators(asset_type=asset_type, response=response)

    return CommandResults(
        readable_output=hr_output,
        raw_response=response,
    )


def fetch_indicators_command(client: CyCognitoFeedClient, params: Dict[str, Any], last_run: Dict[str, Any],
                             is_test: bool = False) -> tuple[Dict[str, Any], list[Dict[str, Any]]]:
    """Fetch the indicators.

    :param client: client object to be used
    :param params: integration configuration parameters
    :param last_run: last run object obtained from demisto.getLastRun()
    :param is_test: True if the function call is from test_module, False otherwise
    """
    asset_type = params.get('asset_type')
    first_fetch_timestamp = arg_to_datetime(params.get('first_fetch', DEFAULT_FIRST_FETCH),
                                            arg_name='First Fetch Time').strftime(DATE_FORMAT)  # type: ignore
    max_fetch = arg_to_number(params.get('max_fetch', DEFAULT_MAX_FETCH), arg_name="Max Fetch")
    organizations = argToList(params.get('organizations'))
    security_grade = [x.split(':')[0].lower() for x in params.get('security_grade', [])] if params.get(
        'security_grade') else []
    hosting_type = params.get('hosting_type', [])
    locations = convert_countries_to_alpha_3_codes(argToList(params.get('locations')))
    default_mapping = params.get('default_mapping')
    only_alive = params.get('only_alive', True)

    feed_tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')

    validate_get_indicators_arguments(asset_type=asset_type, hosting_type=hosting_type, security_grade=security_grade,
                                      count=max_fetch, status=[])

    start_time = last_run.get('last_fetch', first_fetch_timestamp)
    offset = last_run.get('offset', 0)

    filters = prepare_body_filters_for_get_indicators(asset_type=asset_type, organizations=organizations,
                                                      hosting_type=hosting_type,
                                                      locations=locations, last_seen=start_time,
                                                      security_grade=security_grade,
                                                      only_alive=only_alive)  # type: ignore

    response = client.get_indicators(asset_type=asset_type, count=max_fetch, offset=offset,  # type: ignore
                                     sort_param=('last_seen', 'asc'), filters=filters)

    if is_test:
        return {}, []

    demisto.info(f"[+] FeedCyCognito: Number of indicators fetched: {len(response)}")
    indicators = build_iterators(tlp_color=tlp_color, default_mapping=default_mapping,  # type: ignore
                                 response=response, feed_tags=feed_tags)

    # Update last_run according to the response to retrieve the next set of assets
    if response:
        if len(response) < max_fetch:  # type: ignore
            last_fetch_time = dateparser.parse(response[-1].get('last_seen')) + timedelta(  # type: ignore
                milliseconds=1)
            last_run['last_fetch'] = last_fetch_time.strftime(API_DATE_FORMAT)  # type: ignore
            last_run['offset'] = 0
        else:
            last_run['offset'] = offset + 1
            last_run['last_fetch'] = start_time

    return last_run, indicators


def test_module(client: CyCognitoFeedClient, params) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        client (CyCognitoFeedClient): client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    if params['feed']:
        fetch_indicators_command(client, params, {}, is_test=True)
    else:
        client.get_indicators(asset_type='ip', count=1, filters=[])  # Body is required for this endpoint
    return 'ok'


def main():
    """Parse params and runs command functions."""
    params = demisto.params()

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            "Authorization": params.get('api_key')
        }

        client = CyCognitoFeedClient(
            base_url=BASE_URL,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client, params))
        elif command == 'cycognito-get-indicators':
            args = demisto.args()
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            return_results(get_indicators_command(client, args))
        elif command == 'fetch-indicators':
            last_run = demisto.getLastRun()
            next_run, indicators = fetch_indicators_command(client, params, last_run)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
            demisto.info(f"[+] FeedCyCognito: Last run object to be used for next set of indicators is: {next_run}")
            demisto.setLastRun(next_run)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as err:
        return_error(f'Failed to execute {command} command.\nError:\n{err}', error=err)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
