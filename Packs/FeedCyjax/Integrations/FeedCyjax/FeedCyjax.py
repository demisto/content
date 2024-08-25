import demistomock as demisto
from CommonServerPython import *

import urllib3
import traceback
import dateparser
from datetime import datetime, timezone, timedelta
from typing import Any

import cyjax as cyjax_sdk
from cyjax.exceptions import UnauthorizedException, TooManyRequestsException

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
INDICATORS_LAST_FETCH_KEY = 'last_fetch'
INDICATORS_LIMIT = 50


''' CLIENT CLASS '''


class Client:
    """Client class to interact with the Cyjax API using Cyjax SDK"""

    def __init__(self, base_url, api_key, proxies=None, verify_ssl=True):
        self.__base_url = base_url
        self.__api_key = api_key
        self.__proxies = proxies
        self.__verify_ssl = verify_ssl
        self._set_sdk()

    def _set_sdk(self) -> None:
        """Set Cyjax SDK
        :return: None
        """
        cyjax_sdk.api_key = self.__api_key

        if self.__base_url:
            cyjax_sdk.api_url = self.__base_url

        if self.__proxies:
            cyjax_sdk.proxy_settings = self.__proxies

        if self.__verify_ssl is False:
            cyjax_sdk.verify_ssl = False

    def test_connection(self) -> tuple[bool, str]:
        """Test connection to the Cyjax API using Cyjax SDK. Call indicator list API, and check if it's valid list

        :return: A tuple with connection result and the error message if test failed.
        :rtype: ``Tuple(bool, str)``
        """
        result = False
        error_msg = 'Not responding'

        try:
            indicators = list(cyjax_sdk.IndicatorOfCompromise().list(since=timedelta(minutes=5)))
            if isinstance(indicators, list):
                result = True
        except Exception as e:
            if isinstance(e, UnauthorizedException):
                error_msg = 'Unauthorized'
            elif isinstance(e, TooManyRequestsException):
                error_msg = 'Too many requests'
            else:
                if str(e):
                    error_msg = str(e)

            demisto.debug(f'Error when testing connection to Cyjax API {error_msg}')

        return result, error_msg

    def fetch_indicators(self, since=None, until=None, indicator_type=None, source_type=None, source_id=None,
                         limit=None) -> list:
        """
        Fetch indicators from Cyjax SDK.

        :type since: ``str``
        :param since:  The start date time in ISO 8601 format.

        :type until: ``str``
        :param until:  The end date time in ISO 8601 format

        :type indicator_type: ``str``
        :param indicator_type:  The indicator type. If not specified all indicators are returned

        :type source_type: ``str``
        :param source_type:  The indicators source type. Allowed values are incidnet-report, my-report

        :type source_id: ``int``
        :param source_id:  The indicators source ID

        :type limit: ``int``
        :param limit: The indicators count limit

        :return: The list of indicators
        :rtype: list
        """
        try:
            indicators = cyjax_sdk.IndicatorOfCompromise().list(since=since,
                                                                until=until,
                                                                type=indicator_type,
                                                                source_type=source_type,
                                                                source_id=source_id,
                                                                limit=limit)
        except Exception as e:
            indicators = []
            demisto.debug(f'Error when fetching Indicators from Cyjax SDK {str(e)}')

        return indicators

    def sighting(self, value: str) -> dict | None:
        """
        Get the sighting for an indicator

        :type value: ``str``
        :param value:  The indicator value

        :return: The dict with sighting metadata
        :rtype: Optional[dict]
        """
        try:
            enrichment = cyjax_sdk.IndicatorOfCompromise().enrichment(value)
            enrichment['value'] = value

            # Do not expose geoip enrichment data in sighting method
            if 'geoip' in enrichment:
                del enrichment['geoip']
            if 'asn' in enrichment:
                del enrichment['asn']
        except Exception:
            enrichment = None

        return enrichment


''' HELPER FUNCTIONS '''


def get_indicators_last_fetch_date() -> datetime:
    """Get the last fetch-indicators date. Check if indicators were ever fetched before,
    if not find the date for the first fetch.

    :return: Incidents last fetch date
    :rtype: ``datetime``
    """
    integration_context = demisto.getIntegrationContext()
    last_fetch_timestamp = integration_context.get(INDICATORS_LAST_FETCH_KEY, None)

    # Check if indicators were ever fetched before
    if last_fetch_timestamp is None:
        # How much time before the first fetch to retrieve incidents
        first_fetch_time = arg_to_datetime(
            arg=demisto.params().get('first_fetch', '3 days'),
            arg_name='First fetch time',
            required=True
        )
        if first_fetch_time:
            last_fetch_timestamp = first_fetch_time.timestamp()
        else:
            raise ValueError('Invalid first_fetch date config param')

    date = datetime.utcfromtimestamp(int(last_fetch_timestamp)).replace(tzinfo=timezone.utc)  # noqa: UP017

    return date


def set_indicators_last_fetch_date(timestamp: int) -> None:
    """
    Set the last indicator fetch date to integration context

    :type timestamp: ``int``
    :param timestamp: The last fetch timestamp

    :return: None
    """
    integration_context = demisto.getIntegrationContext()

    if timestamp:
        integration_context[INDICATORS_LAST_FETCH_KEY] = int(timestamp)

    demisto.setIntegrationContext(integration_context)


def map_indicator_type(cyjax_type: str) -> str | None:
    """Map Cyjax indicator type to XSOAR indicator type

    :param cyjax_type: The Cyjax indicator type
    :type cyjax_type: ``str``

    :return: XSOAR indicator type
    :rtype: ``Optional[str]``
    """
    indicator_map = {
        'IPv4': FeedIndicatorType.IP,
        'IPv6': FeedIndicatorType.IPv6,
        'URL': FeedIndicatorType.URL,
        'Email': FeedIndicatorType.Email,
        'Hostname': FeedIndicatorType.Domain,
        'Domain': FeedIndicatorType.Domain,
        'FileHash-SHA1': FeedIndicatorType.File,
        'FileHash-SHA256': FeedIndicatorType.File,
        'FileHash-MD5': FeedIndicatorType.File,
        'FileHash-SSDEEP': FeedIndicatorType.SSDeep
    }

    return indicator_map.get(cyjax_type)


def map_reputation_to_score(reputation: str) -> int:
    """Map reputation as string to it's score as integer representation

    :param reputation: The reputation as str
    :type reputation: ``str``

    :return: the score integer value
    :rtype: ``int``
    """
    reputation_map = {
        'unknown': 0,
        'none': 0,
        'good': 1,
        'suspicious': 2,
        'bad': 3
    }

    return reputation_map.get(reputation.lower(), 0)


def convert_cyjax_indicator(cyjax_indicator: dict, score: int | None = None, tlp: str | None = None,
                            tags: list | None = None) -> dict[str, Any]:
    """Convert Cyjax indicator into XSOAR indicator

    :type cyjax_indicator: ``dict``
    :param cyjax_indicator: The Cyjax indicator dict

    :type score: ``Optional[int]``
    :param score: The score that should be applied to the XSOAR indicator

    :type tlp: ``Optional[str]``
    :param tlp: The score that should be applied to the XSOAR indicator

    :type tags: ``Optional[list]``
    :param tags: A list of tags to add to indicators

    :return: Indicator dict
    :rtype: ``Dict[str, Any]``
    """
    if score is None:
        score = map_reputation_to_score('Suspicious')

    if tlp is None and 'handling_condition' in cyjax_indicator:
        tlp = cyjax_indicator['handling_condition']

    if tags is None:
        tags = []

    indicator_date = dateparser.parse(cyjax_indicator['discovered_at'])
    assert indicator_date is not None

    indicator = {
        'value': cyjax_indicator['value'],
        'type': map_indicator_type(cyjax_indicator['type']),
        'rawJSON': cyjax_indicator,
        'score': score
    }

    # Add additional indicator fields
    fields = {
        'firstseenbysource': indicator_date.strftime(DATE_FORMAT)
    }

    if tlp is not None:
        fields['trafficlightprotocol'] = tlp

    if tags:
        fields['tags'] = tags  # type: ignore

    if 'description' in cyjax_indicator:
        fields['description'] = cyjax_indicator['description']

    if 'source' in cyjax_indicator:
        fields['source'] = cyjax_indicator['source']

    if 'industry_type' in cyjax_indicator:
        fields['cyjaxindustrytypes'] = cyjax_indicator['industry_type']

    if 'ttp' in cyjax_indicator:
        fields['cyjaxtechniquestacticsprocedures'] = cyjax_indicator['ttp']

    if 'asn' in cyjax_indicator and 'asn' in cyjax_indicator['asn']:
        fields['ASN'] = cyjax_indicator['asn']['asn']

    if 'geoip' in cyjax_indicator:
        if 'city_name' in cyjax_indicator['geoip']:
            fields['city'] = cyjax_indicator['geoip']['city_name']
        if 'country_name' in cyjax_indicator['geoip']:
            fields['geocountry'] = cyjax_indicator['geoip']['country_name']
        if 'location' in cyjax_indicator['geoip']:
            fields['geolocation'] = "Lon: {}, Lat: {}".format(
                cyjax_indicator['geoip']['location']['lon'],
                cyjax_indicator['geoip']['location']['lat'])

    indicator['fields'] = fields

    return indicator


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication

    :type client: ``Client``
    :param client: Instance of Client class.

    :return: The test result
    :rtype: ``str``
    """
    (result, error_msg) = client.test_connection()

    if result:
        return 'ok'
    else:
        return f'Could not connect to Cyjax API ({error_msg})'


def fetch_indicators_command(client: Client, last_fetch_date: datetime, reputation: str, tlp: str | None = None,
                             tags: list | None = None) -> tuple[int, list[dict]]:
    """Fetch indicators from Cyjax API.
    This function retrieves new indicators every interval (default is 60 minutes).

    :type client: ``Client``
    :param client: Instance of Client class.

    :type last_fetch_date: ``datetime``
    :param last_fetch_date: The last fetch date run

    :type reputation: ``str``
    :param reputation: The feed reputation as string

    :type tlp: ``Optional[str]``
    :param tlp: TLP to apply to indicators fetched from the feed. If None, use TLP set by Cyjax.

    :type tags: ``Optional[list]``
    :param tags: A list of tags to add to indicators

    :return: A tuple containing two elements:
            last_run_timestamp (``int``): The timestamp that will be used in ``last_run`` on the next fetch.
            indicators (``List[dict]``): List of indicators that will be added to XSOAR
    :rtype: ``Tuple[int, List[dict]]``
    """
    last_run_timestamp = int(last_fetch_date.timestamp())

    # Add one second from last_fetch_timestamp to avoid fetching the same indicators
    since = last_fetch_date + timedelta(seconds=1)

    indicators = []  # type:List
    cyjax_indicators = client.fetch_indicators(since=since.isoformat())   # type:List

    indicators_score = map_reputation_to_score(reputation)  # type: int

    for cyjax_indicator in cyjax_indicators:
        indicator_date = dateparser.parse(cyjax_indicator.get('discovered_at'))
        assert indicator_date is not None
        indicator_timestamp = int(indicator_date.timestamp())

        indicators.append(convert_cyjax_indicator(cyjax_indicator, indicators_score, tlp, tags))

        # Update last run
        if indicator_timestamp > last_run_timestamp:
            last_run_timestamp = indicator_timestamp

    return last_run_timestamp, indicators


def get_indicators_command(client: Client, args: dict[str, Any]) -> dict[str, Any] | None:
    """Get indicators command

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    since = args.get('since', None)
    until = args.get('until', None)
    indicator_type = args.get('type', None)
    source_type = args.get('source_type', None)
    source_id = args.get('source_id', None)
    limit = int(args.get('limit', INDICATORS_LIMIT))

    if since is not None:
        since_date = arg_to_datetime(since, 'since')
        since = since_date.strftime(DATE_FORMAT) if since_date else None

    if until is not None:
        until_date = arg_to_datetime(until, 'until')
        until = until_date.strftime(DATE_FORMAT) if until_date else None

    if source_id is not None:
        source_id = int(source_id)

    cyjax_indicators = client.fetch_indicators(since=since,
                                               until=until,
                                               indicator_type=indicator_type,
                                               source_type=source_type,
                                               source_id=source_id,
                                               limit=limit)

    indicators = [convert_cyjax_indicator(indicator) for indicator in cyjax_indicators]  # type:List

    # Format indicators for human readable table output
    human_readable_indicators = []
    for indicator in indicators:
        human_readable_indicators.append({
            'value': indicator['value'],
            'score': indicator['score'],
            'type': indicator['type'],
            'description': indicator['fields'].get('description'),
            'date': indicator['fields'].get('firstseenbysource')
        })
    human_readable_headers = ['value', 'type', 'score', 'description', 'date']

    return {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': indicators,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Cyjax indicators:', human_readable_indicators, headers=human_readable_headers,
                                         headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.Indicators(val.value && val.value === obj.value)': createContext(indicators, removeNull=True),
        }
    }


def indicator_sighting_command(client: Client, args: dict[str, Any]) -> dict[str, Any] | None:
    """Get sighting of an indicator command

    :type client: ``Client``
    :param Client: The client

    :type args: ``dict``
    :param args: all command arguments, usually passed from ``demisto.args()``.

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    value = args.get('value', None)

    if not value:
        raise ValueError('Value not specified')

    indicator_sighting = client.sighting(value)

    if indicator_sighting is not None:
        sightings_list = indicator_sighting.get('sightings', [])
        description = 'Indicator "{}" sightings. Last seen at: {}'.format(value,
                                                                          indicator_sighting.get('last_seen_timestamp'))
    else:
        sightings_list = []
        description = f'No events found for indicator "{value}"'

    return_object = {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': sightings_list,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown(description, sightings_list, headerTransform=string_to_table_header)
    }

    if indicator_sighting is not None:
        return_object['EntryContext'] = {
            'Cyjax.IndicatorSighting(val.value && val.value === obj.value)':
                createContext(indicator_sighting, removeNull=True),
        }

    return return_object


def unset_indicators_last_fetch_date_command() -> dict[str, Any] | None:
    """Unset the indicators last fetch date

    :return: A dict with result options that is then passed to ``return_results``,
    :rtype: ``dict``
    """
    integration_context = demisto.getIntegrationContext()

    if INDICATORS_LAST_FETCH_KEY in integration_context:
        del integration_context[INDICATORS_LAST_FETCH_KEY]

    demisto.setIntegrationContext(integration_context)

    return {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.TEXT,
        'Contents': 'Indicators feed last fetch date has been unset. Next feed run will use first_fetch param.',
    }


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    api_key = params.get('apikey')
    base_url = params.get('url')
    verify_ssl = not params.get('insecure', False)
    proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
    reputation = params.get('feedReputation', 'Suspicious')
    use_cyjax_tlp = params.get('use_cyjax_tlp', False)
    tlp_color = params.get('tlp_color')
    tlp_to_use = tlp_color if use_cyjax_tlp is False else None  # Whether to use Cyjax TLP or TLP set by the user.
    tags = params.get('feedTags')

    demisto.debug(f'Command being called is {demisto.command()}')

    try:

        client = Client(
            base_url=base_url,
            api_key=api_key,
            proxies=proxies,
            verify_ssl=verify_ssl)

        if demisto.command() == 'test-module':
            return_results(test_module(client))

        elif demisto.command() == 'fetch-indicators':
            last_fetch_date = get_indicators_last_fetch_date()  # type:datetime
            next_run, indicators = fetch_indicators_command(client, last_fetch_date, reputation, tlp_to_use, tags)

            if indicators:
                for b in batch(indicators, batch_size=2000):
                    demisto.createIndicators(b)

                set_indicators_last_fetch_date(next_run)

        elif demisto.command() == 'cyjax-get-indicators':
            return_results(get_indicators_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-indicator-sighting':
            return_results(indicator_sighting_command(client, demisto.args()))

        elif demisto.command() == 'cyjax-unset-indicators-last-fetch-date':
            return_results(unset_indicators_last_fetch_date_command())

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
