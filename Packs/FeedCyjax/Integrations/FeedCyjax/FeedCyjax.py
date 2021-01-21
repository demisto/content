import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import pytz
import urllib3
import traceback
import dateparser
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Tuple, List, Optional, Union, cast

import cyjax as cyjax_sdk

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
INDICATORS_LAST_FETCH_KEY = 'last_fetch'


''' CLIENT CLASS '''


class Client(object):
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

    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to the Cyjax API using Cyjax SDK. Call indicator list API, and check if it's valid list

        :return: A tuple with connection result and the error message if test failed.
        :rtype: ``Tuple(bool, str)``
        """
        result = False
        error_msg = 'Not responding'

        try:
            indicators = list(cyjax_sdk.IndicatorOfCompromise().list(since=timedelta(minutes=5)))
            result = True
        except Exception as e:
            error_msg = str(e)
            demisto.debug('Error when testing connection to Cyjax API {}'.format(error_msg))

        return result, error_msg

    def fetch_indicators(self, since=None, until=None, indicator_type=None, source_type=None, source_id=None) -> list:
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

        :return: The list of indicators
        :rtype: list
        """
        try:
            indicators = cyjax_sdk.IndicatorOfCompromise().list(since=since,
                                                                until=until,
                                                                type=indicator_type,
                                                                source_type=source_type,
                                                                source_id=source_id)
        except Exception as e:
            indicators = []
            demisto.debug('Error when fetching Indicators from Cyjax SDK {}'.format(str(e)))

        return indicators


''' HELPER FUNCTIONS '''


def arg_to_datetime(arg, arg_name=None, is_utc=True, required=False, settings=None):
    # type: (Any, Optional[str], bool, bool, dict) -> Optional[datetime]

    """Converts an XSOAR argument to a datetime

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``datetime``. It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type is_utc: ``bool``
    :param is_utc: if True then date converted as utc timezone, otherwise will convert with local timezone.

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :type settings: ``dict``
    :param settings: If provided, passed to dateparser.parse function.

    :return:
        returns an ``datetime`` if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[datetime]``
    """

    if arg is None:
        if required is True:
            if arg_name:
                raise ValueError('Missing "{}"'.format(arg_name))
            else:
                raise ValueError('Missing required argument')
        return None

    if isinstance(arg, str) and arg.isdigit() or isinstance(arg, (int, float)):
        # timestamp is a str containing digits - we just convert it to int
        ms = float(arg)
        if ms > 2000000000.0:
            # in case timestamp was provided as unix time (in milliseconds)
            ms = ms / 1000.0

        if is_utc:
            return datetime.utcfromtimestamp(ms).replace(tzinfo=timezone.utc)
        else:
            return datetime.fromtimestamp(ms)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        if settings:
            date = dateparser.parse(arg, settings=settings)
        else:
            date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})

        if date is None:
            # if d is None it means dateparser failed to parse it
            if arg_name:
                raise ValueError('Invalid date: "{}"="{}"'.format(arg_name, arg))
            else:
                raise ValueError('"{}" is not a valid date'.format(arg))

        return date

    if arg_name:
        raise ValueError('Invalid date: "{}"="{}"'.format(arg_name, arg))
    else:
        raise ValueError('"{}" is not a valid date'.format(arg))


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
        last_fetch_timestamp = first_fetch_time.timestamp()

    date = datetime.utcfromtimestamp(int(last_fetch_timestamp)).replace(tzinfo=timezone.utc)

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


def map_indicator_type(cyjax_type: str) -> str:
    """Map Cyjax indicator type to XSOAR indicator type

    :param cyjax_type: The Cyjax indicator type
    :type cyjax_type: ``str``

    :return: XSOAR indicator type
    :rtype: ``str``
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


def convert_cyjax_indicator(cyjax_indicator: dict, score: Optional[int] = None, tlp: Optional[str] = None,
                            tags: Optional[list] = None) -> Dict[str, Any]:
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
        tlp = cyjax_indicator.get('handling_condition')

    if tags is None:
        tags = []

    indicator_date = dateparser.parse(cyjax_indicator.get('discovered_at'))

    indicator = {
        'value': cyjax_indicator.get('value'),
        'type': map_indicator_type(cyjax_indicator.get('type')),
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
        fields['tags'] = tags

    if 'description' in cyjax_indicator:
        fields['description'] = cyjax_indicator.get('description')

    if 'source' in cyjax_indicator:
        fields['source'] = cyjax_indicator.get('source')

    if 'industry_type' in cyjax_indicator:
        fields['industrytypes'] = cyjax_indicator.get('industry_type')

    if 'ttp' in cyjax_indicator:
        fields['techniquestacticsprocedures'] = cyjax_indicator.get('ttp')

    if 'asn' in cyjax_indicator and 'asn' in cyjax_indicator.get('asn'):
        fields['ASN'] = cyjax_indicator.get('asn').get('asn')

    if 'geoip' in cyjax_indicator:
        if 'city_name' in cyjax_indicator.get('geoip'):
            fields['city'] = cyjax_indicator.get('geoip').get('city_name')
        if 'country_name' in cyjax_indicator.get('geoip'):
            fields['geocountry'] = cyjax_indicator.get('geoip').get('country_name')
        if 'location' in cyjax_indicator.get('geoip'):
            fields['geolocation'] = "Lon: {}, Lat: {}".format(
                cyjax_indicator.get('geoip').get('location').get('lon'),
                cyjax_indicator.get('geoip').get('location').get('lat'))

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
        return 'Could not connect to Cyjax API ({})'.format(error_msg)


def fetch_indicators_command(client: Client, last_fetch_date: datetime, reputation: str, tlp: Optional[str] = None,
                             tags: Optional[list] = None) -> Tuple[int, List[dict]]:
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
    since = last_fetch_date.isoformat()
    last_run_timestamp = int(last_fetch_date.timestamp())

    indicators = []  # type:List
    cyjax_indicators = client.fetch_indicators(since=since)   # type:List

    indicators_score = map_reputation_to_score(reputation)  # type: int

    for cyjax_indicator in cyjax_indicators:
        indicator_date = dateparser.parse(cyjax_indicator.get('discovered_at'))
        indicator_timestamp = int(indicator_date.timestamp())

        indicators.append(convert_cyjax_indicator(cyjax_indicator, indicators_score, tlp, tags))

        # Update last run
        if indicator_timestamp > last_run_timestamp:
            last_run_timestamp = indicator_timestamp

    return last_run_timestamp, indicators


def get_indicators_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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

    if since is not None:
        since_date = arg_to_datetime(since, 'since')
        since = since_date.strftime(DATE_FORMAT) if since_date else None

    if until is not None:
        until_date = arg_to_datetime(until, 'until')
        until = until_date.strftime(DATE_FORMAT) if until_date else None

    if source_id is not None:
        source_id = int(source_id)

    # Check if any filter is set, if not set since to 30 days ago to prevent to many indicators load
    if not any([since, until, indicator_type, source_type, source_id]):
        month_ago = datetime.now() - timedelta(30)
        since = month_ago.strftime(DATE_FORMAT)

    cyjax_indicators = client.fetch_indicators(since=since,
                                               until=until,
                                               indicator_type=indicator_type,
                                               source_type=source_type,
                                               source_id=source_id)

    indicators = [convert_cyjax_indicator(indicator) for indicator in cyjax_indicators]  # type:List

    return {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': indicators,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Cyjax indicators:', indicators,
                                         headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.Indicators(val.value && val.value === obj.value)': createContext(indicators, removeNull=True),
        }
    }


def indicator_sighting_command(client: Client, args: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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

    indicator_sighting = {'id': 1234, 'name': 'tester', 'abba': 'babba', 'value': value}

    return {
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.JSON,
        'Contents': indicator_sighting,
        'ReadableContentsFormat': EntryFormat.MARKDOWN,
        'HumanReadable': tableToMarkdown('Indicator "{}" sighting'.format(value), indicator_sighting,
                                         headerTransform=pascalToSpace),
        'EntryContext': {
            'Cyjax.IndicatorSighting(val.value && val.value === obj.value)': createContext(indicator_sighting,
                                                                                           removeNull=True),
        }
    }


def unset_indicators_last_fetch_date_command() -> Optional[Dict[str, Any]]:
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
    demisto.info(f' --------- !!±!!!!!!!! ----------- CYJAX ----- Command being called is {demisto.command()}')

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
            demisto.info('-------------- CYJAX fetch-indicators called at {}, use date: {}'.
                         format(datetime.now().isoformat(), last_fetch_date.isoformat()))

            next_run, indicators = fetch_indicators_command(client, last_fetch_date, reputation, tlp_to_use, tags)

            if indicators:
                demisto.info('------------------ CYJAX FOUND INDICATORS count={}'.format(len(indicators)))
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
