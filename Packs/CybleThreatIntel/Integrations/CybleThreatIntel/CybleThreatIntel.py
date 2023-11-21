import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import pytz
from cabby import create_client
from urllib.parse import urlparse
from lxml import etree
from stix.core import STIXPackage
from datetime import datetime
from dateutil import parser
from typing import *

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f+00:00"


class Client(object):
    """
    Client will implement the feed service.
    Contatins the requests and return data.
    """

    def __init__(self, params):
        self.params = params
        self.creds = params.get('credentials', {})
        self.username = self.creds.get('identifier', "")
        self.password = self.creds.get('password', "")
        self.collection_name = params.get('collection', "")
        self.discovery_service = params.get('discovery_service', "")
        self.feedReputation = params.get('feedReputation', "")
        self.feedReliability = params.get('feedReliability', "")
        self.tlp_color = params.get('tlp_color', "")
        self.initial_interval = arg_to_number(params.get('initial_interval', '1'))
        self.limit = arg_to_number(params.get('limit', ''))
        self.verify_certificate = not argToBoolean(params.get('insecure', False))
        self.proxy = argToBoolean(params.get('proxy', False))

        self.parsed_url = urlparse(self.discovery_service)
        self.client = create_client(
            self.parsed_url.netloc,
            use_https=True,
            discovery_path=self.parsed_url.path)
        self.client.set_auth(username=self.username, password=self.password, verify_ssl=self.verify_certificate)
        if self.proxy:
            self.client.set_proxies(handle_proxy())

    def fetch(self, begin, end, collection):
        for block in self.client.poll(collection_name=collection, begin_date=begin, end_date=end):
            yield block.content.decode('utf-8')

    def get_recursively(self, search_dict, field):
        """
        Takes a dict with nested lists and dicts,
        and searches all dicts for a key of the field
        provided.
        """
        fields_found = []
        for key, value in iter(search_dict.items()):

            if key == field:
                fields_found.append(value)

            elif isinstance(value, dict):
                results = self.get_recursively(value, field)
                for result in results:
                    fields_found.append(result)

            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        more_results = self.get_recursively(item, field)
                        for another_result in more_results:
                            fields_found.append(another_result)

        return fields_found

    def build_indicators(self, args: Dict[str, Any], data: list):
        indicators = []
        for eachres in data:
            indicator_obj = {
                "service": "Cyble Feed"
            }
            for eachtype in FeedIndicatorType.list_all_supported_indicators():
                if eachtype.lower() in args.get('collection').lower():      # type: ignore
                    indicator_obj['type'] = eachtype
                    break
            multi_data = True
            try:
                data = self.get_recursively(eachres['indicators'][0]['observable'], 'value')
                if not data:
                    data = self.get_recursively(eachres['indicators'][0]['observable'], 'address_value')
            except Exception:
                data = self.get_recursively(eachres['observables']['observables'][0], 'value')

            if multi_data:
                ind_val = {}
                for eachindicator in data:
                    typeval = auto_detect_indicator_type(eachindicator)
                    indicator_obj['type'] = typeval
                    if typeval:
                        ind_val[typeval] = eachindicator

                if len(data) == 1:
                    indicator_obj['value'] = str(data[0])
                elif indicator_obj['type'] in list(ind_val.keys()):
                    indicator_obj['value'] = str(ind_val[indicator_obj['type']])
                elif len(ind_val) != 0:
                    indicator_obj['type'] = list(ind_val.keys())[0]
                    indicator_obj['value'] = ind_val[list(ind_val.keys())[0]]
            #
            if eachres.get('indicators'):
                for eachindicator in eachres.get('indicators'):
                    indicator_obj['title'] = eachindicator.get('title')
                    indicator_obj['time'] = eachindicator.get('timestamp')
            else:
                for eachindicator in eachres.get('ttps').get('ttps'):
                    indicator_obj['title'] = eachindicator.get('title')
                    indicator_obj['time'] = eachindicator.get('timestamp')

            indicator_obj['rawJSON'] = eachres
            indicators.append(indicator_obj)

        return indicators

    def parse_to_json(self, content):
        """
        Parse the feed response to JSON
        :param content: xml data to parse
        """
        if content:
            stix_dict = STIXPackage.from_xml(etree.XML(content)).to_dict()  # parse to dictionary
            return stix_dict
        else:
            return {}

    def get_taxii(self, args: Dict[str, Any]):
        """
        Fetch Taxii events for the given parameters
        :param args: arguments which would be used to fetch feed
        :return:
        """
        taxii_data = []
        save_fetch_time = None
        count = 0
        try:
            for data in self.fetch(args.get('begin'), args.get('end'), args.get('collection')):
                response = self.parse_to_json(data)

                if response.get('indicators') or False:
                    content = response.get('indicators')
                elif response.get('ttps') or False:
                    content = response.get('ttps').get('ttps')
                else:
                    raise ValueError("Last fetch time retrieval failed.")

                for eachone in content:
                    save_fetch_time = parser.parse(eachone['timestamp']).replace(tzinfo=pytz.UTC).strftime(
                        DATETIME_FORMAT)

                taxii_data.append(response)

                count += 1
                if count == arg_to_number(args.get('limit', 1)):
                    break
        except Exception as e:
            demisto.error("Failed to fetch feed details, exception:{}".format(e))
            raise e

        return taxii_data, save_fetch_time

    def get_services(self):
        """
        Fetch the services from the feed
        """
        collection_list = []
        try:
            services = self.client.discover_services()
            if services:
                for service in services:
                    if 'collection' in service.type.lower():
                        for eachone in self.get_collection(service.address):
                            collection_list.append({'name': eachone.name})
                        break
        except Exception as e:
            demisto.error("Failed to fetch collections, exception:{}".format(e))
            raise e

        return collection_list

    def get_collection(self, address):
        """
        Collection names available from the feed
        """
        return self.client.get_collections(uri=address)


def get_test_response(client: Client, args: Dict[str, Any]):
    """
    Test the integration connection state
    :param client: instance of client to communicate with server
    :param args: Parameters
    :return: Test Response Success or Failure
    """
    ret_val = 'Unable to Contact Feed Service, Please Check the parameters.'
    args['begin'] = str((datetime.utcnow() - timedelta(days=1)).replace(tzinfo=pytz.UTC))
    args['end'] = str(datetime.utcnow().replace(tzinfo=pytz.UTC))

    try:
        services = client.get_taxii(args)
    except Exception as e:
        demisto.error(e)
        services = None

    if services:
        ret_val = 'ok'
    return ret_val


def get_feed_collection(client: Client):
    """
    get the collections from taxii feed
    :param client: instance of client to communicate with server
    :return: list of collection names
    """
    collections = client.get_services()
    command_results = CommandResults(
        outputs_prefix='CybleIntel.collection',
        outputs_key_field='names',
        outputs=collections
    )
    return command_results


def cyble_fetch_taxii(client: Client, args: Dict[str, Any]):
    '''
    TAXII feed details will be pulled from server
    :param client: instance of client to communicate with server
    :param args: Parameters for fetching the feed
    :return: TAXII feed details
    '''
    try:
        args['begin'] = str(parser.parse(args.get('begin', '')).replace(tzinfo=pytz.UTC)) if args.get('begin', None) else None
        args['end'] = str(parser.parse(args.get('end', '')).replace(tzinfo=pytz.UTC)) if args.get('end', None) else None
    except Exception as e:
        raise ValueError("Invalid date format received, [{}]".format(e))

    result, time = client.get_taxii(args)
    indicators = client.build_indicators(args, result)

    entry_result = camelize(indicators)
    hr = tableToMarkdown('Indicators', entry_result, headers=['Type', 'Value', 'Title', 'Time', 'Rawjson'])
    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='CybleIntel.Threat',
        outputs_key_field='details',
        outputs=indicators
    )
    return command_results


def fetch_indicators(client: Client):
    '''
    TAXII feed details will be pulled from server
    :param client: instance of client to communicate with server
    :return: TAXII feed details
    '''
    args = {}
    last_run = demisto.getLastRun()
    if isinstance(last_run, dict):
        last_fetch_time = last_run.get('lastRun_{}'.format(client.collection_name), None)

    if last_fetch_time:
        args['begin'] = str(parser.parse(last_fetch_time).replace(tzinfo=pytz.UTC))
    else:
        last_fetch_time = datetime.utcnow() - timedelta(days=client.initial_interval)      # type: ignore
        args['begin'] = str(last_fetch_time.replace(tzinfo=pytz.UTC))

    args['end'] = str(datetime.utcnow().replace(tzinfo=pytz.UTC))

    args['collection'] = client.collection_name
    args['limit'] = client.limit       # type: ignore
    indicator, save_fetch_time = client.get_taxii(args)
    indicators = client.build_indicators(args, indicator)

    if save_fetch_time:
        last_run['lastRun_{}'.format(client.collection_name)] = save_fetch_time
        demisto.setLastRun(last_run)

    return indicators


def validate_input(args: Dict[str, Any]):
    """
    Check if the input params for the command are valid. Return an error if any
    :param args: dictionary of input params
    """
    try:
        # we assume all the params to be non-empty, as cortex ensures it
        if args.get('limit') and int(args.get('limit', '1')) <= 0:
            raise ValueError(f"Limit should be positive, limit: {args.get('limit')}")

        try:
            if args.get('begin', None):
                _start_date = parser.parse(args.get('begin', '')).replace(tzinfo=pytz.UTC)
            if args.get('end', None):
                _end_date = parser.parse(args.get('end', '')).replace(tzinfo=pytz.UTC)
        except Exception as e:
            raise ValueError("Invalid date format received, [{}]".format(e))

        if args.get('begin', None) and _start_date > datetime.now(timezone.utc):
            raise ValueError("Start date must be a date before or equal to current")
        if args.get('end', None) and _end_date > datetime.now(timezone.utc):
            raise ValueError("End date must be a date before or equal to current")
        if args.get('begin', None) and args.get('end', None) and _start_date > _end_date:
            raise ValueError("Start date cannot be after end date")

        if not args.get('collection', False):
            raise ValueError(f"Collection Name should be provided: {arg_to_number(args.get('collection', None))}")

        return None
    except Exception as e:
        demisto.error("Exception with validating inputs [{}]".format(e))
        raise e


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # get the params in format
    params = {key: value for key, value in demisto.params().items() if value is not None}

    LOG(f'Command being called is {demisto.command()}')
    try:
        if params.get('initial_interval') and int(params.get('initial_interval')) > 7:      # type: ignore
            raise ValueError(
                f"Retroactive timeline should be within 7 days, given value: {params.get('initial_interval')}")

        client = Client(params)
        args = demisto.args()

        if demisto.command() == 'test-module':
            if not args.get('collection', False):
                args['collection'] = params.get('collection', '')
            return_results(get_test_response(client, args))

        elif demisto.command() == 'fetch-indicators':
            # fetch indicators using taxii service
            indicators = fetch_indicators(client)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif demisto.command() == 'cyble-vision-fetch-taxii':
            # fetch indicators using taxii service
            validate_input(args)
            return_results(cyble_fetch_taxii(client, args))

        elif demisto.command() == 'cyble-vision-get-collection-names':
            # fetch collections using taxii service
            return_results(get_feed_collection(client))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
