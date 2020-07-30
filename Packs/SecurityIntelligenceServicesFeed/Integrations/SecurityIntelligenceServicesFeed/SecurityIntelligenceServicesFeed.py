from CommonServerPython import *

'''IMPORTS'''

from typing import Dict, Any, List, Union, Optional, Tuple
from datetime import timezone
import csv
import gzip
import boto3 as s3
import botocore
import botocore.config as config
import urllib3
import dateparser
from itertools import islice

# Disable insecure warnings
urllib3.disable_warnings()

'''CONSTANTS'''

BUCKETS: Dict[str, str] = {
    'host': 'sis-new-observations',
    'domain': 'sis-new-observations',
    'phish': 'riq-sis-blacklist-phish',
    'malware': 'riq-sis-blacklist-malware',
    'content': 'riq-sis-blacklist-content',
    'scam': 'riq-sis-blacklist-scam'
}

FIELD_NAMES: Dict[str, List[str]] = {
    'host': ['value', 'Timestamp'],
    'domain': ['value', 'Timestamp'],
    'phish': ['value', 'Category', 'MatchType', 'Expiration'],
    'malware': ['value', 'MalwareType', 'MatchType', 'MaliciousExpiration'],
    'content': ['value', 'Category', 'MatchType', 'Expiration'],
    'scam': ['value', 'Category', 'MatchType', 'Expiration']
}

INDICATOR_TYPES: Dict[str, str] = {
    'host': FeedIndicatorType.Host,
    'domain': FeedIndicatorType.Domain,
    'phish': FeedIndicatorType.URL,
    'malware': FeedIndicatorType.URL,
    'content': FeedIndicatorType.URL,
    'scam': FeedIndicatorType.URL
}

REGIONS: Dict[str, Union[str, None]] = {
    'host': 'us-west-1',
    'domain': 'us-west-1',
    'phish': 'us-east-1',
    'malware': 'us-west-1',
    'content': 'us-west-1',
    'scam': 'us-west-1',
}

MESSAGES: Dict[str, str] = {
    'BAD_REQUEST_ERROR': 'API call failed: Bad Request. Error: ',
    'AUTHORIZATION_ERROR': 'Unauthorized. S3 Access Key or S3 Secret Key is invalid. Error: ',
    'NOT_FOUND_ERROR': 'Not found. Error: ',
    'SERVER_ERROR': 'API call failed. Server error received. Error: ',
    'PROXY_ERROR': 'Proxy Error - if the \'Use system proxy\' checkbox in the integration\
                    configuration is selected, try clearing the checkbox. Error: ',
    'HTTP_CLIENT_ERROR': 'API call failed. Check the parameters configured. Error: ',
    'ERROR': 'API call failed. Error: ',
    'INVALID_FEED_TYPE_ERROR': 'Invalid feed type.',
    'REQUIRED_FEED_TYPE_ERROR': 'Argument feedType is mandatory.',
    'INVALID_LIMIT_ERROR': 'Argument limit must be a positive integer between 1 to 1000.',
    'BLANK_PROXY_ERROR': 'https proxy value is empty. Check XSOAR server configuration ',
    'Feed_EXTRACT_ERROR': 'Unable to extract feeds. Error: ',
    'INVALID_FIRST_FETCH_INTERVAL_ERROR': 'First fetch time range must be "number time_unit", '
                                          'examples: (10 days, 6 months, 1 year, etc.)',
    'INVALID_FIRST_FETCH_UNIT_ERROR': 'First fetch time range field\'s unit is invalid. Must be in day(s), '
                                      'month(s) or year(s)',
    'INVALID_MAX_INDICATORS_ERROR': 'Max Indicators Per Interval must be a positive integer.',
    'NO_INDICATORS_FOUND': 'No indicators found for the given argument(s).'
}


class Client:
    """
    Client to use in integration to fetch data from Amazon S3.
    Creates instance of botot3 client and Handles exceptions.
    """

    def __init__(self, access_key: str, secret_key: str, verify: bool, proxy: bool):
        self.access_key = access_key
        self.secret_key = secret_key
        self.verify = verify

        # Set proxy
        if proxy:
            proxies = handle_proxy()

            # Throws a ValueError if Proxy is empty in configuration.
            if not proxies.get('https', True):
                raise ValueError(MESSAGES['BLANK_PROXY_ERROR'] + str(proxies))

            self.config = config.Config(proxies=proxies)
        else:
            self.config = config.Config(proxies={})

        self.s3_client: Any = None

    def set_s3_client(self, region_name: Optional[str]) -> None:
        """
        Create S3 Client instance specific to region.

        :param region_name: Name of the S3 supported region.
        :return: None
        """
        self.s3_client = s3.client('s3', aws_access_key_id=self.access_key,
                                   region_name=region_name,
                                   aws_secret_access_key=self.secret_key, verify=self.verify,
                                   config=self.config)

    def return_error_based_on_status_code(self, status_code: int, error_message: str) -> Optional[None]:
        """
        Return error message based on status code.
        Throws a ValueError based on respected status code.

        :param status_code: HTTP response code.
        :param error_message: Error message.
        :return: return_error
        """
        if status_code == 400:
            raise ValueError(MESSAGES['BAD_REQUEST_ERROR'] + error_message)
        elif status_code == 401 or status_code == 403:
            raise ValueError(MESSAGES['AUTHORIZATION_ERROR'] + error_message)
        elif status_code == 404:
            raise ValueError(MESSAGES['NOT_FOUND_ERROR'] + error_message)
        elif status_code >= 500:
            raise ValueError(MESSAGES['SERVER_ERROR'] + error_message)

    def request_list_objects(self, feed_type: str, max_keys: int = 1000, start_after: str = '', prefix: str = '') -> \
            List[Dict[str, Any]]:
        """
        Makes the API call to Amazon S3 using the boto3 list_objects method to retrieve the keys of objects.

        :param feed_type: Type of the feed. That is map with bucket.
        :param max_keys: Sets the maximum number of keys returned in the response.
        :param start_after: Start_after is where you want Amazon S3 to start listing from. Amazon S3 starts listing
        after this specified key.
        :param prefix: Limits the response to keys that begin with the specified prefix.
        :return: list of keys.
        """
        response = self.s3_client.list_objects_v2(Bucket=BUCKETS.get(feed_type, ''),
                                                  MaxKeys=max_keys,
                                                  StartAfter=start_after,
                                                  Prefix=prefix)
        return response.get('Contents', [])

    def request_select_object_content(self, feed_type: str, key: str, limit: str = None,
                                      search: str = None, delimiter: str = '\t') -> csv.DictReader:
        """
         Makes the API call to Amazon S3 using the boto3 select_objecy_content method to retrieve the feeds.
         Method will execute search and limit records using SQL query provided.
         Used in get-indicators command.

        :param feed_type: Type of the feed. That is map with bucket.
        :param key: Return data of specified key.
        :param limit: Number of records to fetch.
        :param search: To search specific feeds from S3.
        :param delimiter: character to split feed from.
        :return: String of records.
        """
        query = "Select * from S3Object s where s._1 LIKE '%{0}%' ESCAPE '\\' LIMIT {1}" if search \
            else "Select * from S3Object s LIMIT {}"
        response = self.s3_client.select_object_content(
            Bucket=BUCKETS.get(feed_type, ''),
            Key=key,
            ExpressionType='SQL',
            Expression=query.format(search, limit) if search else query.format(limit),
            InputSerialization={
                'CompressionType': 'GZIP',
                'CSV': {
                    'FileHeaderInfo': 'NONE',
                    'RecordDelimiter': '\n',
                    'FieldDelimiter': '\t',
                    'QuoteCharacter': '\t',
                    'AllowQuotedRecordDelimiter': True
                }
            },
            OutputSerialization={
                'CSV': {
                    'RecordDelimiter': '\n',
                    'FieldDelimiter': '\t',
                }
            }
        )
        records: List[bytes] = []
        for event in response.get('Payload', ''):
            if 'Records' in event:
                records.append(event['Records']['Payload'])
            elif 'end' in event:
                return csv.DictReader('')

        response_string = ''.join(r.decode('utf-8') for r in records)
        return csv.DictReader(response_string.splitlines(),
                              fieldnames=FIELD_NAMES.get(feed_type),
                              delimiter=delimiter, quoting=csv.QUOTE_NONE)

    def build_iterator(self, feed_type: str, key: str, start_from: int = 0, limit: str = None, search: str = None,
                       delimiter: str = '\t', max_indicators: int = 30000, is_get_indicators: bool = False) -> Any:
        """
        Retrieves all entries from the streaming response batch wise
        and prepares dictionaries of feeds.
        If any parameter required to get response from S3 is invalid then throws a ValueError.

        :param feed_type: Type of the feed. That is map with bucket.
        :param key: Return data of specified key.
        :param start_from: Integer line number to start reading file from.
        :param limit: Number of records to fetch.
        :param search: To search specific feeds from S3.
        :param delimiter: character to split feed from.
        :param max_indicators: size of feeds batch to return.
        :return: list of feed dictionaries.
        """
        try:

            if is_get_indicators:
                # Request for get-indicators
                return self.request_select_object_content(feed_type, key, limit, search, delimiter)

            # Request for fetch-indicators
            if not start_from:
                self.s3_client.download_file(Bucket=BUCKETS.get(feed_type, ''), Key=key, Filename=feed_type)

            if os.path.exists(feed_type):
                response_feeds = gzip.open(feed_type, 'rt')

                # Creating feeds batch
                feed_batch = list(islice(response_feeds, start_from, start_from + max_indicators))

                if not feed_batch:
                    response_feeds.close()
                    os.remove(feed_type)
                    return []

                return csv.DictReader(feed_batch, fieldnames=FIELD_NAMES.get(feed_type), delimiter=delimiter,
                                      quoting=csv.QUOTE_NONE)
            return []

        except botocore.exceptions.ClientError as exception:
            status_code = exception.response.get('ResponseMetadata', {}).get('HTTPStatusCode', '')
            error_message = exception.response.get('Error', {}).get('Message', '')
            self.return_error_based_on_status_code(status_code, error_message)

        except botocore.exceptions.ProxyConnectionError as exception:
            raise ValueError(MESSAGES['PROXY_ERROR'] + str(exception))

        except botocore.exceptions.HTTPClientError as exception:
            raise ValueError(MESSAGES['HTTP_CLIENT_ERROR'] + str(exception))

        except Exception as exception:
            raise ValueError(MESSAGES['ERROR'] + str(exception))


''' HELPER FUNCTIONS '''


def validate_feeds(feed_types: List[str]) -> None:
    """
    Checks that given feeds are exist or not.
    If feed_types is empty then throws a ValueError.
    If any feed_type is not exist in BUCKET throws a ValueError.

    :param feed_types: Feed types provided.
    :return: True if feeds exist else return error.
    """
    if not feed_types:
        raise ValueError(MESSAGES['REQUIRED_FEED_TYPE_ERROR'])
    for feed in feed_types:
        if feed not in BUCKETS:
            raise ValueError(MESSAGES['INVALID_FEED_TYPE_ERROR'])


def get_last_key_from_integration_context(feed_type: str) -> Tuple[Any, Any]:
    """
    To get last fetched key of feed from integration context.

    :param feed_type: Type of feed to get last fetched key.
    :return: list of S3 object keys.
    """
    feed_context = demisto.getIntegrationContext().get('SISContext', [])
    for cached_feed in feed_context:
        cached_key = cached_feed.get(feed_type, '')
        if cached_key:
            return cached_key, cached_feed.get('start_from', 0)
    return '', 0


def set_last_key_to_integration_context(feed_type: str, key: str, start_from=0) -> None:
    """
    To set last fetched key of feed to integration context.

    :param feed_type: Type of feed to set.
    :param key: Key to set.
    :param start_from: Line number to start from.
    :return: None
    """
    feed_context = demisto.getIntegrationContext().get('SISContext', [])
    for f_type_dict in feed_context:
        if f_type_dict.get(feed_type, ''):
            f_type_dict[feed_type] = key
            f_type_dict['start_from'] = start_from
            demisto.setIntegrationContext({'SISContext': feed_context})
            return
    feed_context.append({feed_type: key, 'start_from': start_from})
    demisto.setIntegrationContext({'SISContext': feed_context})


def validate_limit(limit: str) -> None:
    """
    Validates the limit argument.
    If the limit is 0 >= limit > 1000 or not an integer then throws a ValueError.

    :param limit: Number of feeds to fetch .
    :return: None
    """
    try:
        val = int(limit)
        if val <= 0 or val > 1000:
            raise ValueError
    except ValueError:
        raise ValueError(MESSAGES['INVALID_LIMIT_ERROR'])


def get_max_indicators(params: Dict) -> int:
    """
    Validates the max indicators parameter.
    If the max_indicators is not a positive integer then throws a ValueError.

    :param params: Demisto parameters.
    :return: Integer max indicators to fetch in an interval.
    """
    try:
        max_indicators_int = int(params.get('MaxIndicators', ''))
        if max_indicators_int <= 0:
            raise ValueError
        return max_indicators_int
    except ValueError:
        raise ValueError(MESSAGES['INVALID_MAX_INDICATORS_ERROR'])


def prepare_date_string_for_custom_fields(date_string: str) -> str:
    """
    Prepares date string in iso format and adds timezone if not exist.

    :param date_string: string represent date.
    :return: formatted date string.
    """
    parsed_dt = dateparser.parse(date_string)
    if parsed_dt:
        if parsed_dt.tzinfo is None or parsed_dt.tzinfo.utcoffset(parsed_dt) is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        return parsed_dt.isoformat()
    return ''


def indicator_field_mapping(feed_type: str, indicator: Dict[str, Any]) -> Dict[str, Any]:
    """
    Maps the indicator fields.

    :param feed_type: Type of feed.
    :param indicator: Indicator dictionary.
    :return: Dict of fields.
    """
    fields: Dict[str, Any] = {
        'service': 'Passive Total',
    }

    if feed_type in ['host', 'domain']:
        if indicator.get('Timestamp'):
            fields['firstseenbysource'] = datetime.fromtimestamp(int(indicator.get('Timestamp')),  # type: ignore
                                                                 timezone.utc).isoformat()
    else:
        fields['threattypes'] = [{'threatcategory': feed_type.capitalize() if feed_type != 'phish' else 'Phishing'}]
        if indicator.get('MatchType'):
            fields['sismatchtype'] = indicator['MatchType']

        if feed_type == 'malware':
            if indicator.get('MalwareType'):
                fields['sismalwaretype'] = indicator['MalwareType']

            if indicator.get('MaliciousExpiration'):
                fields['sisexpiration'] = prepare_date_string_for_custom_fields(
                    indicator['MaliciousExpiration'])
        else:
            if indicator.get('Category'):
                fields['siscategory'] = indicator['Category']

            if indicator.get('Expiration'):
                fields['sisexpiration'] = prepare_date_string_for_custom_fields(indicator['Expiration'])
    remove_nulls_from_dictionary(fields)
    return fields


def validate_first_fetch_interval(first_fetch_interval):
    """
    Validating first fetch interval. it should be in form of (<number> <time unit>, e.g., 12 hours, 7 days,
    3 months, 1 year)
    raise value error if validation fails.

    :param first_fetch_interval: first fetch interval
    :return: None
    """
    range_split = first_fetch_interval.split(' ')
    if len(range_split) != 2:
        raise ValueError(MESSAGES['INVALID_FIRST_FETCH_INTERVAL_ERROR'])
    if not range_split[0].isdigit():
        raise ValueError(MESSAGES['INVALID_FIRST_FETCH_INTERVAL_ERROR'])
    if not range_split[1] in ['minute', 'minutes', 'hours', 'hour', 'day', 'days', 'month', 'months', 'year', 'years']:
        raise ValueError(MESSAGES['INVALID_FIRST_FETCH_UNIT_ERROR'])


def get_latest_key(client: Client, feed_type: str, first_fetch_interval: str,
                   is_get_indicators: bool = False) -> Tuple[str, int]:
    """
    Get latest key from bucket of specified feed type.
    :return:
    """
    # Retrieving cached key from integration context.
    cached_key, start_from = get_last_key_from_integration_context(feed_type)
    object_key_list = client.request_list_objects(feed_type=feed_type, start_after=cached_key,
                                                  prefix=feed_type.lower())
    object_key_list = [object_key for object_key in object_key_list if '.gz' in object_key.get('Key', '')]
    object_key_list.sort(key=lambda key_dict: key_dict['LastModified'])

    if is_get_indicators:
        return object_key_list[-1].get('Key', '') if object_key_list else cached_key, 0

    # Parsing first fetch time.
    date_from, now = dateparser.parse(f'{first_fetch_interval} UTC'), datetime.now(timezone.utc)

    # Fetching latest object keys.
    latest_key_list: List[str] = [key_dict.get('Key', '') for key_dict in
                                  object_key_list if
                                  key_dict.get('LastModified', now) >= date_from]

    return latest_key_list[0] if latest_key_list and not start_from else cached_key, start_from


''' REQUESTS FUNCTIONS '''


@logger
def test_module(client: Client, feed_type: str) -> Optional[str]:
    """
    Performs test connectivity by valid response.
    If any parameter required to get response from S3 is invalid then throws a ValueError.

    :param client: boto3 client
    :param feed_type: Type of feed to test.
    :return: 'ok' if test passed, anything else will fail the test.
    """
    try:
        client.set_s3_client(REGIONS[feed_type])
        client.request_list_objects(feed_type=feed_type, max_keys=1)
    except botocore.exceptions.ClientError as exception:
        status_code = exception.response.get('ResponseMetadata', {}).get('HTTPStatusCode', '')
        error_message = exception.response.get('Error', {}).get('Message', '')
        client.return_error_based_on_status_code(status_code, error_message)

    except botocore.exceptions.ProxyConnectionError as exception:
        raise ValueError(MESSAGES['PROXY_ERROR'] + str(exception))

    except botocore.exceptions.HTTPClientError as exception:
        raise ValueError(MESSAGES['HTTP_CLIENT_ERROR'] + str(exception))
    except Exception as exception:
        raise ValueError(MESSAGES['ERROR'] + str(exception))
    return 'ok'


@logger
def fetch_indicators_command(client: Client, feed_types: List[str], first_fetch_interval: str = '7 day',
                             limit: str = None, search: str = None, max_indicators: int = 30000,
                             is_get_indicators: bool = False) -> List[Dict[str, Any]]:
    """
    Fetches indicators from the S3 to the indicators tab.

    :param client: client object.
    :param feed_types: Types of feeds to fetch.
    :param first_fetch_interval: Interval to look back first time to fetch indicators.
    :param search: To search specific feeds from S3.
    :param limit: Number of records to fetch.
    :param max_indicators: Size of the batch to create indicators.
    :param is_get_indicators: return true if get-indicators command called.
    :return: list of indicators.
    """
    indicators = []
    for feed in feed_types:
        client.set_s3_client(region_name=REGIONS[feed])

        latest_key, start_from = get_latest_key(client, feed, first_fetch_interval, is_get_indicators)
        demisto.debug('next file ' + latest_key + ' start_from ' + str(start_from))

        if latest_key:
            feed_dicts = client.build_iterator(feed_type=feed, key=latest_key, limit=limit, search=search,
                                               max_indicators=max_indicators, start_from=start_from,
                                               is_get_indicators=is_get_indicators)
            indicators_count = 0
            # Iterating trough each feed dictionary and creating indicators.
            for feed_dict in feed_dicts:
                value = feed_dict.get('value', '')
                if value:
                    indicator_type = INDICATOR_TYPES.get(feed)
                    feed_dict['type'] = indicator_type
                    remove_nulls_from_dictionary(feed_dict)
                    indicators.append({
                        'value': value,
                        'type': indicator_type,
                        'rawJSON': feed_dict,
                        'fields': indicator_field_mapping(feed, indicator=feed_dict)
                    })
                    indicators_count += 1

            # Setting last key to context.
            if not is_get_indicators:
                # Setting next start_from
                start_from = start_from + indicators_count if indicators_count else 0
                set_last_key_to_integration_context(feed, latest_key, start_from)

    return indicators


@logger
def get_indicators_command(client: Client, args: Dict[str, str]) -> Union[CommandResults, str]:
    """
    Wrapper for retrieving indicators from the feed to the war-room.

    :param client: Client object.
    :param args: demisto arguments.
    :return: CommandResult instance.
    """
    # Retrieving command arguments.
    feed_type = args.get('feed_type', 'domain').lower()
    feed_type = feed_type if feed_type != 'phishing' else 'phish'
    limit = args.get('limit', '50')
    search = args.get('search', '')

    # Validate the provided limit
    validate_limit(limit)

    # Validate the provided feed type.
    validate_feeds([feed_type])

    # Retrieving indicators from fetch indicators command.
    indicators_list: List[Dict[str, Any]] = fetch_indicators_command(client, [feed_type], limit=limit, search=search,
                                                                     is_get_indicators=True)
    # Generating human-readable.
    if not indicators_list:
        return MESSAGES['NO_INDICATORS_FOUND']

    human_readable = '### Total indicators fetched: {}\n'.format(len(indicators_list))
    human_readable += tableToMarkdown('Indicators from Security Intelligence Services feed',
                                      indicators_list, ['value', 'type'], removeNull=True,
                                      headerTransform=lambda header: header.capitalize())

    # Returning command result.
    return CommandResults(readable_output=human_readable, raw_response=indicators_list)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main() -> None:
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # Retrieving parameters.
    params = demisto.params()
    access_key = params.get('accessKey', '')
    secret_key = params.get('secretKey', '')
    verify_certificate = not params.get('insecure', False)
    use_proxy = params.get('proxy', False)
    feed_types = params.get('feedType', [])
    first_fetch_interval = params.get('firstFetchInterval', '1 day')

    try:
        # validate first_fetch_time_interval parameter
        validate_first_fetch_interval(first_fetch_interval)

        # validate and get max_indicators parameter
        max_indicators = get_max_indicators(params)

        # Validate the provided feed types.
        feed_types_lower = [feed_type.lower() if 'phish' not in feed_type.lower() else 'phish' for feed_type in
                            feed_types]
        validate_feeds(feed_types_lower)

        client = Client(
            verify=verify_certificate,
            access_key=access_key,
            secret_key=secret_key,
            proxy=use_proxy
        )

        if demisto.command() == 'test-module':
            demisto.results(test_module(client, feed_types_lower[0]))

        elif demisto.command() == 'fetch-indicators':

            indicators = fetch_indicators_command(client, feed_types=feed_types_lower,
                                                  first_fetch_interval=first_fetch_interval,
                                                  max_indicators=max_indicators)

            for indicators in batch(indicators, 2000):
                demisto.createIndicators(indicators)  # type: ignore

        elif demisto.command() == 'sis-get-indicators':
            return_results(get_indicators_command(client, demisto.args()))
    # Log exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error('Failed to execute {0} command. Error: {1}'.format(demisto.command(), str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
