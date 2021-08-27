import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


# IMPORTS

import cabby
import requests
import urllib3
import dateutil
import pytz
import dateutil.parser
from bs4 import BeautifulSoup
from netaddr import IPAddress, iprange_to_cidrs, IPNetwork
from six import string_types
from typing import Dict, List, Optional

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

SOURCE_NAME = "Alien Vault OTX TAXII"

# disable insecure warnings
urllib3.disable_warnings()

EPOCH = datetime.utcfromtimestamp(0).replace(tzinfo=pytz.UTC)

""" Helper Methods """


def package_extract_properties(package):
    """Extracts properties from the STIX package"""
    result: Dict[str, str] = {}

    header = package.find_all('STIX_Header')
    if len(header) == 0:
        return result

    # share level
    mstructures = header[0].find_all('Marking_Structure')
    for ms in mstructures:
        type_ = ms.get('xsi:type')
        if type_ is result:
            continue

        color = ms.get('color')
        if color is result:
            continue

        type_ = type_.lower()
        if 'tlpmarkingstructuretype' not in type_:
            continue

        result['share_level'] = color.lower()  # https://www.us-cert.gov/tlp
        break

    # decode title
    title = next((c for c in header[0] if c.name == 'Title'), None)
    if title is not None:
        result['stix_package_title'] = title.text

    # decode description
    description = next((c for c in header[0] if c.name == 'Description'), None)
    if description is not None:
        result['stix_package_description'] = description.text

    # decode description
    sdescription = next((c for c in header[0] if c.name == 'Short_Description'), None)
    if sdescription is not None:
        result['stix_package_short_description'] = sdescription.text

    # decode identity name from information_source
    information_source = next((c for c in header[0] if c.name == 'Information_Source'), None)
    if information_source is not None:
        identity = next((c for c in information_source if c.name == 'Identity'), None)
        if identity is not None:
            name = next((c for c in identity if c.name == 'Name'))
            if name is not None:
                result['stix_package_information_source'] = name.text

    return result


def observable_extract_properties(observable):
    """Extracts properties from observable"""
    result = {}

    title = next((c for c in observable if c.name == 'Title'), None)
    if title is not None:
        title = title.text
        result['stix_title'] = title

    description = next((c for c in observable if c.name == 'Description'), None)
    if description is not None:
        description = description.text
        result['stix_description'] = description

    return result


""" TAXII STIX DECODE """


class AddressObject(object):
    """
    Implements address object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/AddressObj/AddressObjectType/
    """
    @staticmethod
    def decode(props, **kwargs):
        indicator = props.find('Address_Value')
        if indicator is None:
            return []
        indicator = indicator.string.encode('ascii', 'replace').decode()

        acategory = props.get('category', None)
        if acategory is None:
            try:
                # if ',' in the ip address then we have a range (10.0.0.0,10.0.0.255)
                # and we want to change it to a CIDR object (10.0.0.0/24)
                if ',' in indicator:
                    ips = indicator.split(',')
                    indicator = str(iprange_to_cidrs(ips[0], ips[1])[0].cidr)
                    cidr = IPNetwork(indicator)
                    if cidr.version == 4:
                        type_ = 'CIDR'
                    elif cidr.version == 6:
                        type_ = 'IPv6CIDR'
                    else:
                        LOG('Unknown ip version: {!r}'.format(cidr.version))
                        return []

                else:
                    ip = IPAddress(indicator)
                    if ip.version == 4:
                        type_ = 'IP'
                    elif ip.version == 6:
                        type_ = 'IPv6'
                    else:
                        LOG('Unknown ip version: {!r}'.format(ip.version))
                        return []

            except Exception:
                return []

        elif acategory == 'ipv4-addr':
            # if ',' in the ip address then we have a range (10.0.0.0,10.0.0.255)
            # and we want to change it to a CIDR object (10.0.0.0/24)
            if ',' in indicator:
                ips = indicator.split(',')
                indicator = str(iprange_to_cidrs(ips[0], ips[1])[0].cidr)
                type_ = 'CIDR'

            else:
                type_ = 'IP'

        elif acategory == 'ipv6-addr':
            # Same logic as above just for ipv6
            if ',' in indicator:
                ips = indicator.split(',')
                indicator = str(iprange_to_cidrs(ips[0], ips[1])[0].cidr)
                type_ = 'IPv6CIDR'

            else:
                type_ = 'IPv6'

        elif acategory == 'e-mail':
            type_ = 'Email'

        else:
            LOG('Unknown AddressObjectType category: {!r}'.format(acategory))
            return []

        return [{
            'indicator': indicator,
            'type': type_
        }]


class DomainNameObject(object):
    """
    Implements domain object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/DomainNameObj/DomainNameObjectType/
    """
    @staticmethod
    def decode(props, **kwargs):
        dtype = props.get('type', 'FQDN')
        if dtype != 'FQDN':
            return []

        domain = props.find('Value')
        if domain is None:
            return []

        return [{
            'indicator': domain.string.encode('ascii', 'replace').decode(),
            'type': 'Domain'
        }]


class FileObject(object):
    """
    Implements file object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/FileObj/FileObjectType/
    """
    @staticmethod
    def _decode_basic_props(props):
        result = {}

        name = next((c for c in props if c.name == 'File_Name'), None)
        if name is not None:
            result['stix_file_name'] = name.text

        size = next((c for c in props if c.name == 'File_Size'), None)
        if size is not None:
            result['stix_file_size'] = size.text

        format = next((c for c in props if c.name == 'File_Format'), None)
        if format is not None:
            result['stix_file_format'] = format.text

        return result

    @staticmethod
    def decode(props, **kwargs):
        result = []

        bprops = FileObject._decode_basic_props(props)

        hashes = props.find_all('Hash')
        for h in hashes:
            htype = h.find('Type')
            if htype is None:
                continue
            htype = htype.string.lower()
            if htype not in ['md5', 'sha1', 'sha256', 'ssdeep']:
                continue

            value = h.find('Simple_Hash_Value')
            if value is None:
                continue
            value = value.string.lower()

            result.append({
                'indicator': value,
                'htype': htype,
                'type': 'File'
            })

        for r in result:
            for r2 in result:
                if r['htype'] == r2['htype']:
                    continue

                r['stix_file_{}'.format(r2['htype'])] = r2['indicator']

            r.update(bprops)

        return result


class URIObject(object):
    """
    Implements URI object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/URIObj/URIObjectType/
    """
    @staticmethod
    def decode(props, **kwargs):
        utype = props.get('type', 'URL')
        if utype == 'URL':
            type_ = 'URL'
        elif utype == 'Domain Name':
            type_ = 'Domain'
        else:
            return []

        url = props.find('Value')
        if url is None:
            return []

        return [{
            'indicator': url.string.encode('utf8', 'replace').decode(),
            'type': type_
        }]


class SocketAddressObject(object):
    """
    Implements socket address object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/SocketAddressObj/SocketAddressObjectType/
    """
    @staticmethod
    def decode(props, **kwargs):
        ip = props.get('ip_address', None)
        if ip:
            return AddressObject.decode(ip)
        return []


class LinkObject(object):
    """
    Implements link object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/LinkObj/LinkObjectType/
    """
    @staticmethod
    def decode(props, **kwargs):
        ltype = props.get('type', 'URL')
        if ltype != 'URL':
            LOG('Unhandled LinkObjectType type: {}'.format(ltype))
            return []
        value = props.get('value', None)
        if value is None:
            LOG('no value in observable LinkObject')
            return []
        if not isinstance(value, string_types):
            value = value.get('value', None)
            if value is None:
                LOG('no value in observable LinkObject')
                return []
        return [{
            'indicator': value,
            'type': ltype
        }]


class HTTPSessionObject(object):
    """
    Implements http session object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/HTTPSessionObj/HTTPSessionObjectType/
    """
    @staticmethod
    def decode(props, **kwargs):
        if 'http_request_response' in props.keys():
            tmp = props['http_request_response']

            if len(tmp) == 1:
                item = tmp[0]
                http_client_request = item.get('http_client_request', None)
                if http_client_request is not None:
                    http_request_header = http_client_request.get('http_request_header', None)
                    if http_request_header is not None:
                        raw_header = http_request_header.get('raw_header', None)
                        if raw_header is not None:
                            return [{
                                'indicator': raw_header.split('\n')[0],
                                'type': 'http-session',  # we don't support this type natively in demisto
                                'header': raw_header
                            }]
            else:
                LOG('multiple HTTPSessionObjectTypes not supported')
        return []


class StixDecode(object):
    """
    Decode STIX strings formatted as xml, and extract indicators from them
    """
    DECODERS = {
        'DomainNameObjectType': DomainNameObject.decode,
        'FileObjectType': FileObject.decode,
        'WindowsFileObjectType': FileObject.decode,
        'URIObjectType': URIObject.decode,
        'AddressObjectType': AddressObject.decode,
        'SocketAddressObjectType': SocketAddressObject.decode,
        'LinkObjectType': LinkObject.decode,
        'HTTPSessionObjectType': HTTPSessionObject.decode,
    }

    @staticmethod
    def object_extract_properties(props, kwargs):
        type_ = props.get('xsi:type').rsplit(':')[-1]

        if type_ not in StixDecode.DECODERS:
            LOG('Unhandled cybox Object type: {!r} - {!r}'.format(type_, props))
            return []

        return StixDecode.DECODERS[type_](props, **kwargs)

    @staticmethod
    def _parse_stix_timestamp(stix_timestamp):
        dt = dateutil.parser.parse(stix_timestamp)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=pytz.UTC)
        delta = dt - EPOCH
        return int(delta.total_seconds() * 1000)

    @staticmethod
    def _deduplicate(indicators):
        result = {}

        for iv in indicators:
            result['{}:{}'.format(iv['indicator'], iv['type'])] = iv

        return result.values()

    @staticmethod
    def decode(content, **kwargs):
        result = []

        package = BeautifulSoup(content, 'xml')

        if package.contents[0].name != 'STIX_Package':
            return None, []

        package = package.contents[0]

        timestamp = package.get('timestamp', None)
        if timestamp is not None:
            timestamp = StixDecode._parse_stix_timestamp(timestamp)

        pprops = package_extract_properties(package)

        indicators = package.find_all('Indicator')

        for ind in indicators:
            observables = ind.find_all('Observable')
            for o in observables:
                gprops = observable_extract_properties(o)

                obj = next((ob for ob in o if ob.name == 'Object'), None)
                if obj is None:
                    continue

                # main properties
                properties = next((c for c in obj if c.name == 'Properties'), None)
                if properties is not None:
                    for r in StixDecode.object_extract_properties(properties, kwargs):
                        r.update(gprops)
                        r.update(pprops)
                        r.update({'added_time': ind.get('timestamp') + 'Z'})

                        result.append(r)

                # then related objects
                related = next((c for c in obj if c.name == 'Related_Objects'), None)
                if related is not None:
                    for robj in related:
                        if robj.name != 'Related_Object':
                            continue

                        properties = next((c for c in robj if c.name == 'Properties'), None)
                        if properties is None:
                            continue

                        for r in StixDecode.object_extract_properties(properties, kwargs):
                            r.update(gprops)
                            r.update(pprops)
                            result.append(r)

        return timestamp, StixDecode._deduplicate(result)


""" Alien Vault OTX TAXII Client """


class Client:
    """Client for AlienVault OTX Feed - gets indicator lists from collections using TAXII client

        Attributes:
            api_key(str): The API key for AlienVault OTX.
            collection(str): The collections on which to run the feed.
            insecure(bool): Use SSH on http request.
            proxy(str): Use system proxy.
            all_collections(bool): Whether to run on all active collections.
        """
    def __init__(self, api_key: str, collection: str, insecure: bool = False, proxy: bool = False,
                 all_collections: bool = False, tags: list = [], tlp_color: Optional[str] = None):

        taxii_client = cabby.create_client(discovery_path="https://otx.alienvault.com/taxii/discovery")
        taxii_client.set_auth(username=str(api_key), password="foo", verify_ssl=not insecure)
        if proxy:
            taxii_client.set_proxies(handle_proxy())

        self.taxii_client = taxii_client
        self.tags = tags
        self.tlp_color = tlp_color

        self.all_collections = all_collections
        if all_collections:
            self.collections = self.get_all_collections()

        else:
            if collection is None or collection == '':
                return_error(f"No collection set. Here is a list of all accessible collections: "
                             f"{self.get_all_collections()}")

            self.collections = collection.split(',')

    def get_all_collections(self):
        """Gets a list of all collections listed in the AlienVault OTX instance.

        Returns:
            list. A list of all collection names in AlienVault OTX.
        """
        collections = self.taxii_client.get_collections()
        full_collection_list = []
        for collection in collections:
            full_collection_list.append(collection.name)
        return full_collection_list

    def build_iterator(self, collection, begin_date=None):
        """Returns a list of all XML elements from the given collection.

        Args:
            collection(str): The collection name to fetch the elements from.
            begin_date(datetime): what is the first date to fetch indicators from.

        Returns:
            list. A list of XML elements (strings).
        """
        if not begin_date:
            begin_date, _ = parse_date_range(demisto.params().get('initial_interval'))

        if begin_date.tzinfo is None:
            begin_date = begin_date.replace(tzinfo=pytz.UTC)

        # bring all the indicators created from the last date until now.
        return list(self.taxii_client.poll(collection_name=collection, begin_date=begin_date))

    def decode_indicators(self, response):
        """Decode the XML response given using STIXDecode class.

        Args:
            response(str): An XML response from a collection of AlienVault.

        Returns:
            list. A list of indicators (dicts) decoded from the response.
        """
        return StixDecode.decode(response)


def module_test_command(client: Client, args: Dict):
    """Test module for the integration
    will run on all the collections given and check for a response.
    if all_collections is checked will return an error only in case no collection returned a response.
    if all_collections is not checked will return an error for the collections that did not respond.

    Args:
        client(Client): The AlienVault OTX client.
        args(dict): empty dictionary.

    Returns:
        str,dict,dict. ok if passed - will raise an Exception otherwise.
    """
    passed_collections = []  # type:List
    failed_collections = []  # type:List
    for collection in client.collections:
        try:
            client.build_iterator(collection)
            passed_collections.append(collection)

        except Exception as e:
            if e.__class__ is requests.exceptions.SSLError:
                raise Exception("SSL Connection failed - try marking the Trust Any Certificate checkbox.")
            else:
                if not client.all_collections:
                    failed_collections.append(collection)
                    continue

    if not client.all_collections and len(failed_collections) > 0:
        raise Exception(f"Unable to poll from the collections {str(failed_collections)} check the collection names and "
                        f"configuration on Alien Vault")

    if len(passed_collections) == 0:
        raise Exception("Unable to poll from any collection - please check the configuration on Alien Vault")

    return 'ok', {}, {}


def get_indicators_command(client: Client, args: Dict):
    """Runs fetch indicators and return the indicators.

    Args:
        client(Client): The AlienVault OTX client.
        args(dict): The command arguments

    Returns:
        str,dict,dict. The human readable, and rawJSON from the command - no context created.
    """
    limit = int(args.get('limit', 50))

    if args.get('begin_date'):
        begin_date, _ = parse_date_range(args.get('begin_date'))
    else:
        begin_date = None

    indicator_list, _ = fetch_indicators_command(client, limit=limit, begin_date=begin_date)

    human_readable = tableToMarkdown("Indicators from AlienVault OTX TAXII:", indicator_list, removeNull=True)

    return human_readable, {}, indicator_list


def parse_indicators(sub_indicator_list, full_indicator_list, tags, tlp_color):
    """Gets a decoded indicator list and returns a parsed version of the indicator with accordance with Demisto's
    Feed indicator standards.

    Args:
        tags(list): The tags to add to the indicator.
        sub_indicator_list(list): A list of STIXDecoded indicators
        full_indicator_list(list): A list of all the indicators fetched to this point - used to prevent duplications.
        tlp_color(str): Traffic Light Protocol color.

    Returns:
        list,list. A list of parsed indicators and an updated list of all indicators polled
    """
    parsed_indicator_list = []  # type: List
    for indicator in sub_indicator_list:
        # If the indicator was already seen, skip it.
        if indicator['indicator'] in full_indicator_list:
            continue

        indicator['value'] = indicator['indicator']
        indicator['fields'] = {
            "description": indicator["stix_package_short_description"],
            "tags": tags,
            "firstseenbysource": indicator.get('added_time')
        }
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color

        temp_copy = indicator.copy()

        del indicator['indicator']

        indicator['rawJSON'] = temp_copy
        parsed_indicator_list.append(indicator)
        full_indicator_list.append(indicator['value'])

    return parsed_indicator_list, full_indicator_list


def get_latest_indicator_time(indicators_list):
    if not indicators_list:
        return None

    latest_indicator_time = dateutil.parser.parse(indicators_list[0].get('added_time', '1970-01-01T00:00:00Z'))
    for ind in indicators_list:
        indicator_time = dateutil.parser.parse(ind.get('added_time', '1970-01-01T00:00:00Z'))
        if indicator_time > latest_indicator_time:
            latest_indicator_time = indicator_time

    return latest_indicator_time


def fetch_indicators_command(client: Client, limit=None, begin_date=None):
    """Fetch indicators from AlienVault OTX.

    Args:
        client(Client): The AlienVault OTX client.
        limit(any): How many XML elements to parse, None if all should be parsed.
        begin_date(datetime): what is the first date to fetch indicators from.

    Returns:
        list. A list of indicators.
    """
    indicator_list = []  # type:List
    for collection in client.collections:
        try:
            taxii_iter = client.build_iterator(collection, begin_date=begin_date)

        except Exception as e:
            if not client.all_collections:
                raise Exception(e)

            else:
                continue

        only_indicator_list = []  # type:List
        for raw_response in taxii_iter:
            _, res = client.decode_indicators(raw_response.content)
            # the only_indicator_list is a list containing only the indicators themselves.
            # it is used to prevent duplicated indicators from being created in the system.
            # this is because AlienVault OTX can return the same indicator several times from the same collection.
            parsed_list, only_indicator_list = parse_indicators(res, only_indicator_list, client.tags, client.tlp_color)
            indicator_list.extend(parsed_list)

            if limit is not None and limit <= len(indicator_list):
                indicator_list = indicator_list[:limit]
                break

        latest_indicator_time = get_latest_indicator_time(indicator_list)

    return indicator_list, latest_indicator_time


def main():
    params = demisto.params()
    tags = argToList(params.get('feedTags'))
    tlp_color = params.get('tlp_color')
    client = Client(params.get('api_key'), params.get('collections'), params.get('insecure'), params.get('proxy'),
                    params.get('all_collections'), tags=tags, tlp_color=tlp_color)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': module_test_command,
        'alienvaultotx-get-indicators': get_indicators_command
    }
    try:
        integration_cache = demisto.getIntegrationContext()
        begin_date = integration_cache.get('begin_date')

        if demisto.command() == 'fetch-indicators':
            if not begin_date:
                begin_date = demisto.params().get('initial_interval')
                if begin_date:
                    begin_date, _ = parse_date_range(begin_date)

            else:
                begin_date = dateutil.parser.parse(begin_date)

            indicators, latest_indicator_time = fetch_indicators_command(client, begin_date=begin_date)
            # we submit the indicators in batches
            if indicators:
                # if new indicators were found - submit them in batches, set the next begin_date
                # to the time of the last indicator found
                for b in batch(indicators, batch_size=2000):
                    demisto.createIndicators(b)
                demisto.setIntegrationContext({"begin_date": str(latest_indicator_time)})

            else:
                # if no indicators entered - dont change begin date.
                demisto.setIntegrationContext({"begin_date": str(begin_date)})

        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in {SOURCE_NAME} Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins' or __name__ == "__main__":
    main()
