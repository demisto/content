import demistomock as demisto
from CommonServerPython import *  # noqa: E402
from CommonServerUserPython import *  # noqa: E402


# IMPORTS
import cabby
import requests
import urllib3
import dateutil
import pytz
import dateutil.parser
from bs4 import BeautifulSoup
from netaddr import IPAddress
from six import string_types
from typing import Dict, List
import ssl

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

SOURCE_NAME = "Alien Vault OTX TAXII"


# disable insecure warnings
urllib3.disable_warnings()

EPOCH = datetime.utcfromtimestamp(0).replace(tzinfo=pytz.UTC)


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
            type_ = 'IP'
        elif acategory == 'ipv6-addr':
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

        observables = package.find_all('Observable')
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


class Client():
    def __init__(self, api_key: str, collection: str, insecure: bool = False, proxy: bool = False):
        taxii_client = cabby.create_client(discovery_path="https://otx.alienvault.com/taxii/discovery")
        taxii_client.set_auth(username=str(api_key), password="foo", verify_ssl=not insecure)
        if proxy:
            taxii_client.set_proxies(handle_proxy())

        self.taxii_client = taxii_client
        self.collection = collection

    def build_iterator(self):
        return list(self.taxii_client.poll(collection_name=self.collection))

    def decode_indicators(self, response):
        return StixDecode.decode(response)


def module_test_command(client: Client, args: Dict):
    try:

        client.build_iterator()

    except Exception as e:
        if e.__class__ is requests.exceptions.SSLError:
            raise Exception("SSL Connection failed - try marking the Trust Any Certificate checkbox.")
        else:
            raise Exception(f"Unable to poll from the collection {client.collection} check the collection name and "
                            f"configuration on Alien Vault")

    return 'ok', {}, {}


def get_indicators_command(client: Client, args: Dict):
    limit = int(args.get('limit', 50))
    indicator_list = fetch_indicators_command(client, limit)

    human_readable = tableToMarkdown("Indicators from AlienVault OTX TAXII:", indicator_list,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, indicator_list


def parse_indicators(sub_indicator_list, full_indicator_list):
    parsed_indicator_list = []  # type: List
    for indicator in sub_indicator_list:
        if indicator['indicator'] in full_indicator_list:
            continue

        temp_copy = indicator.copy()
        indicator['value'] = indicator['indicator']
        del indicator['indicator']
        indicator['rawJSON'] = temp_copy
        parsed_indicator_list.append(indicator)
        full_indicator_list.append(indicator['value'])

    return parsed_indicator_list, full_indicator_list


def fetch_indicators_command(client: Client, limit=None):
    taxii_iter = client.build_iterator()
    indicator_list = []  # type:List
    index = 0
    only_indicator_list = []  # type:List
    for raw_response in taxii_iter:
        _, res = client.decode_indicators(raw_response.content)
        parsed_list, only_indicator_list = parse_indicators(res, only_indicator_list)
        indicator_list.extend(parsed_list)
        if limit:
            index = index + 1
            if limit == index:
                break

    return indicator_list


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


def main():
    params = demisto.params()

    client = Client(params.get('api_key'), params.get('collection'), params.get('insecure'), params.get('proxy'))

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    # Switch case
    commands = {
        'test-module': module_test_command,
        'alienvaultotx-get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        raise Exception(f'Error in {SOURCE_NAME} Integration [{e}]')


if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
