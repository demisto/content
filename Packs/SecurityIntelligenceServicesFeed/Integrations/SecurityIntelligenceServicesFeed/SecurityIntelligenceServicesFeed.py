from CommonServerPython import *

'''IMPORTS'''

from typing import Dict, Any, List, Generator, Union, Optional
from dateutil.parser import parse
from datetime import timezone
import csv
import gzip
import boto3 as s3
import botocore
import botocore.config as config
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

'''CONSTANTS'''

FETCH_BATCH_SIZE = 2000

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
    'Feed_EXTRACT_ERROR': 'Unable to extract feeds. Error: '
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

    def build_iterator(self, feed_type: str, key: str, limit: str = None, search: str = None, delimiter: str = '\t',
                       batch_size: int = 2000) -> Generator:
        """
        Retrieves all entries from the streaming response batch wise
        and prepares dictionaries of feeds.
        If any parameter required to get response from S3 is invalid then throws a ValueError.

        :param feed_type: Type of the feed. That is map with bucket.
        :param key: Return data of specified key.
        :param limit: Number of records to fetch.
        :param search: To search specific feeds from S3.
        :param delimiter: character to split feed from.
        :param batch_size: size of feeds batch to return.
        :return: list of feed dictionaries.
        """
        try:

            if limit:
                # Request for get-indicators
                yield self.request_select_object_content(feed_type, key, limit, search, delimiter)
            else:
                # Request for fetch-indicators
                self.s3_client.download_file(Bucket=BUCKETS.get(feed_type, ''), Key=key, Filename=feed_type)
                if os.path.exists(feed_type):
                    response_feeds = gzip.open(feed_type, 'rt')
                    while True:
                        # Creating feeds batch
                        feeds_batch = [feed for _, feed in zip(range(batch_size), response_feeds) if feed]
                        if not feeds_batch:
                            response_feeds.close()
                            os.remove(feed_type)
                            return
                        yield csv.DictReader(feeds_batch, fieldnames=FIELD_NAMES.get(feed_type), delimiter=delimiter,
                                             quoting=csv.QUOTE_NONE)
                return
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


def get_last_key_from_integration_context(feed_type: str) -> str:
    """
    To get last fetched key of feed from integration context.

    :param feed_type: Type of feed to get last fetched key.
    :return: list of S3 object keys.
    """
    feed_context = demisto.getIntegrationContext().get('SISContext', [])
    for cached_feed in feed_context:
        cached_key = cached_feed.get(feed_type, '')
        if cached_key:
            return cached_key
    return ''


def set_last_key_to_integration_context(feed_type: str, key: str) -> None:
    """
    To set last fetched key of feed to integration context.

    :param feed_type: Type of feed to set.
    :param key: Key to set.
    :return: None
    """
    feed_context = demisto.getIntegrationContext().get('SISContext', [])
    for f_type_dict in feed_context:
        if f_type_dict.get(feed_type, ''):
            f_type_dict[feed_type] = key
            demisto.setIntegrationContext({'SISContext': feed_context})
            return
    feed_context.append({feed_type: key})
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


def prepare_date_string_for_custom_fields(date_string: str) -> str:
    """
    Prepares date string in iso format and adds timezone if not exist.

    :param date_string: string represent date.
    :return: formatted date string.
    """
    parsed_dt = parse(date_string)
    if parsed_dt.tzinfo is None or parsed_dt.tzinfo.utcoffset(parsed_dt) is None:
        parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
    return parsed_dt.isoformat()


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
    try:
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

    except ValueError as exception:
        raise ValueError(MESSAGES['Feed_EXTRACT_ERROR'] + str(exception))
    return fields


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
                             limit: str = None, search: str = None, batch_size: int = 0) -> Generator:
    """
    Fetches indicators from the S3 to the indicators tab.

    :param client: client object.
    :param feed_types: Types of feeds to fetch.
    :param first_fetch_interval: Interval to look back first time to fetch indicators.
    :param search: To search specific feeds from S3.
    :param limit: Number of records to fetch.
    :param batch_size: Size of the batch to create indicators.
    :return: list of indicators.
    """
    for feed in feed_types:
        client.set_s3_client(region_name=REGIONS[feed])

        # Parsing first fetch time.
        date, _ = parse_date_range('0 day' if first_fetch_interval == 'Today' else first_fetch_interval)
        date_from = date.date()

        # Retrieving cached key from integration context.
        cached_key = get_last_key_from_integration_context(feed)

        # Fetching latest object keys.
        latest_key_list: List[str] = [key_dict.get('Key', '') for key_dict in
                                      client.request_list_objects(feed_type=feed, start_after=cached_key,
                                                                  prefix=feed.lower()) if
                                      key_dict.get('LastModified', datetime.today().date()).date() >= date_from]

        # If get-indicators command called.
        if limit:
            if latest_key_list:
                # Retrieving latest object key for get-indicators.
                latest_key_list = [latest_key_list[-1]]
            elif cached_key:
                # If no latest key found, retrieving key from cache.
                latest_key_list = [cached_key]

        # Iterating through latest objects found.
        for key in latest_key_list:

            # Generator, returning object data specified batch wise.
            feeds_batch = client.build_iterator(feed_type=feed, key=key, limit=limit, search=search,
                                                batch_size=batch_size)
            for feed_dicts in feeds_batch:
                indicators = []

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
                yield indicators

        # Setting last key to context.
        if latest_key_list and not limit:
            set_last_key_to_integration_context(feed, latest_key_list[-1])


@logger
def get_indicators_command(client: Client, args: Dict[str, str]) -> CommandResults:
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
    indicators_list: List[Dict[str, Any]] = []
    for indicators in fetch_indicators_command(client, [feed_type], limit=limit, search=search):
        indicators_list.extend(indicators)

    # Generating human-readable.
    if indicators_list:
        human_readable = '### Total indicators fetched: {}\n'.format(len(indicators_list))
        human_readable += tableToMarkdown('Indicators from Security Intelligence Services feed',
                                          indicators_list, ['value', 'type'], removeNull=True,
                                          headerTransform=lambda header: header.capitalize())
    else:
        human_readable = "No indicators found for the given argument(s)."

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
    first_fetch_interval = params.get('firstFetchInterval', '0 day')

    try:
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
            # Generator, iterating and creating indicators specified batch wise.
            for indicators in fetch_indicators_command(client, feed_types=feed_types_lower,
                                                       first_fetch_interval=first_fetch_interval,
                                                       batch_size=FETCH_BATCH_SIZE):
                demisto.createIndicators(indicators)  # type: ignore

        elif demisto.command() == 'sis-get-indicators':
            return_results(get_indicators_command(client, demisto.args()))
    # Log exceptions
    except Exception as e:
        return_error('Failed to execute {0} command. Error: {1}'.format(demisto.command(), str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
