from lxml import etree
import demistomock as demisto
from CommonServerPython import *
from bs4 import BeautifulSoup
import dateutil.parser
from netaddr import IPNetwork
from six import string_types
import pytz
import dateutil.parser


EPOCH = datetime.utcfromtimestamp(0).replace(tzinfo=pytz.UTC)
PATTERNS_DICT = {
    "file:": FeedIndicatorType.File,
    "ipv6": FeedIndicatorType.IPv6,
    "ipv4-addr:": FeedIndicatorType.IP,
    "url:": FeedIndicatorType.URL,
    "domain-name:": FeedIndicatorType.Domain,
    "email": FeedIndicatorType.Email,
    "registry-key:key": FeedIndicatorType.Registry,
    "account": FeedIndicatorType.Account,
}
SCRIPT_NAME = 'STIXParserV2'

def convert_to_json(string):
    """Will try to convert given string to json.

    Args:
        string: str of stix/json file. may be xml, then function will fail

    Returns:
        json object if succeed
        False if failed
    """
    try:
        js = json.loads(string)
        return js
    except ValueError:
        return None


def parse_stix2(js_content):
    pass


def create_indicator_entry(
        indicator_type,
        value,
        pkg_id,
        ind_id,
        timestamp,
        source=None,
        score=None,
):
    """Creating a JSON object of given args

    Args:
        indicator_type: (str) indicator type
        value: (str) indicator value
        pkg_id: (str) package id
        ind_id: (str) indicator id
        timestamp: (str) timestamp
        source: (str) source of indicator (custom field)
        score: (str) score of indicator (custom field)

    Returns:
        dict:
            {
                "indicator_type": indicator_type,
                "value": value,
                "CustomFields": {
                    "indicatorId": ind_id,
                    "stixPackageId": pkg_id
                }
                "source": ind_id.split("-")[0] or source if provided
                "score": if source is "DBot" then score should be here.
            }
    """
    entry = dict()
    entry["indicator_type"] = indicator_type
    entry["value"] = value
    entry["CustomFields"] = {"indicatorId": ind_id, "stixPackageId": pkg_id}
    entry["source"] = source if source else ind_id.split("-")[0]
    entry["score"] = score
    # Times
    entry["timestamp"] = timestamp
    return entry


def raise_for_taxii_error(response):
    if response.contents[0].name != 'Status_Message':
        return

    if response.contents[0]['status_type'] == 'SUCCESS':
        return

    raise RuntimeError('{} - error returned by TAXII Server: {}'.format(
        SCRIPT_NAME, response.contents[0]['status_type']
    ))


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

        result['share_level'] = color.lower()  # To keep backward compatibility
        result['TLP'] = color.upper()  # https://www.us-cert.gov/tlp
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
    result: Dict[str, str] = {}

    if id_ref := observable.get('id'):
        result['indicator_ref'] = id_ref

    title = next((c for c in observable if c.name == 'Title'), None)
    if title is not None:
        title = title.text
        result['stix_title'] = title

    description = next((c for c in observable if c.name == 'Description'), None)
    if description is not None:
        description = description.text
        result['stix_description'] = description

    return result


def indicator_extract_properties(indicator) -> Dict[str, Any]:
    """Extracts the Indicator properties

    Args:
        indicator (bs4.element.Tag): The Indicator content in xml.

    Returns:
        dict: The ttp properties in a dict {'property': 'value'}. (The value can be a list)

    """

    result: Dict[str, Any] = {}

    title = next((c for c in indicator if c.name == 'Title'), None)
    if title is not None:
        title = title.text
        result['stix_indicator_name'] = title

    description = next((c for c in indicator if c.name == 'Description'), None)
    if description is not None:
        description = description.text
        result['stix_indicator_description'] = description

    confidence = next((c for c in indicator if c.name == 'Confidence'), None)
    if confidence is not None:
        value = next((c for c in confidence if c.name == 'Value'), None)
        if value is not None:
            value = value.text
            result['confidence'] = value

    if indicated_ttp := indicator.find_all('Indicated_TTP'):
        result['ttp_ref'] = []
        # Each indicator can be related to few ttps
        for ttp_value in indicated_ttp:
            ttp = next((c for c in ttp_value if c.name == 'TTP'), None)
            if ttp is not None:
                value = ttp.get('idref')
                result['ttp_ref'].append(value)

    return result


def ttp_extract_properties(ttp, behavior) -> Dict[str, str]:
    """Extracts the TTP properties

    Args:
        ttp (bs4.element.Tag): The TTP content in xml.
        behavior (str): The TTP behavior ['Malware', 'Attack Pattern'].

    Returns:
        dict: The ttp properties in a dict {'property': 'value'}.

    """

    result = {'type': behavior}

    if behavior == 'Malware':
        type_ = next((c for c in ttp if c.name == 'Type'), None)
        if type_ is not None:
            type_ = type_.text
            result['malware_type'] = type_

        name = next((c for c in ttp if c.name == 'Name'), None)
        if name is not None:
            name = name.text
            result['indicator'] = name

        title = next((c for c in ttp if c.name == 'Title'), None)
        if title is not None:
            title = title.text
            result['title'] = title

    if behavior == 'Attack Pattern':
        id_ref = next((c for c in ttp if c.name == 'idref'), None)
        if id_ref is not None:
            id_ref = id_ref.text
            result['stix_id_ref'] = id_ref

        title = next((c for c in ttp if c.name == 'Title'), None)
        if title is not None:
            title = title.text
            result['indicator'] = title

    description = next((c for c in ttp if c.name == 'Description'), None)
    if description is not None:
        description = description.text
        result['description'] = description

    short_description = next((c for c in ttp if c.name == 'Short_Description'), None)
    if short_description is not None:
        short_description = short_description.text
        result['short_description'] = short_description

    return result


def parse_timestamp_label(timestamp_label):
    try:
        dt = dateutil.parser.parse(timestamp_label)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=pytz.UTC)
        delta = dt - EPOCH
        return int(delta.total_seconds() * 1000)

    except Exception:
        return None


class AddressObject(object):
    """
    Implements address object indicator decoding
    based on: https://stixproject.github.io/data-model/1.2/AddressObj/AddressObjectType/
    """

    @staticmethod
    def decode(props, **kwargs):
        result: List[Dict[str, str]] = []

        indicator = props.find('Address_Value')
        if indicator is None:
            return result

        indicator = indicator.string.encode('ascii', 'replace').decode()
        category = props.get('category', None)
        address_list = indicator.split('##comma##')

        if category == 'e-mail':
            return [{'indicator': address, 'type': 'Email'} for address in address_list]

        try:
            for address in address_list:
                ip = IPNetwork(address)
                if ip.version == 4:
                    if len(address.split('/')) > 1:
                        type_ = 'CIDR'
                    else:
                        type_ = 'IP'
                elif ip.version == 6:
                    if len(address.split('/')) > 1:
                        type_ = 'IPv6CIDR'
                    else:
                        type_ = 'IPv6'
                else:
                    LOG('Unknown ip version: {!r}'.format(ip.version))
                    return []

                result.append({'indicator': address, 'type': type_})

        except Exception:
            return result

        return result


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

        file_format = next((c for c in props if c.name == 'File_Format'), None)
        if file_format is not None:
            result['stix_file_format'] = file_format.text

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

        return list(result.values())

    @staticmethod
    def decode(content, **kwargs):
        observable_result = []
        indicator_result: Dict[str, dict] = {}
        ttp_result: Dict[str, dict] = {}

        package = BeautifulSoup(content, 'xml')

        if package.contents[0].name != 'STIX_Package':
            return None, None, None, None

        package = package.contents[0]

        timestamp = package.get('timestamp', None)
        if timestamp is not None:
            timestamp = StixDecode._parse_stix_timestamp(timestamp)

        # extract the Observable info
        if observables := package.find_all('Observable'):
            pprops = package_extract_properties(package)

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

                        observable_result.append(r)

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
                            observable_result.append(r)

        # extract the Indicator info
        if indicators := package.find_all('Indicator'):

            if observables:
                indicator_ref = observables[0].get('idref')

                if indicator_ref:
                    indicator_info = indicator_extract_properties(indicators[0])
                    indicator_result[indicator_ref] = indicator_info

        # extract the TTP info
        if ttp := package.find_all('TTP'):
            ttp_info: Dict[str, str] = {}

            id_ref = ttp[0].get('id')

            title = next((c for c in ttp[0] if c.name == 'Title'), None)
            if title is not None:
                title = title.text
                ttp_info['stix_ttp_title'] = title

            description = next((c for c in ttp[0] if c.name == 'Description'), None)
            if description is not None:
                description = description.text
                ttp_info['ttp_description'] = description

            if behavior := package.find_all('Behavior'):
                if behavior[0].find_all('Malware'):
                    ttp_info.update(ttp_extract_properties(package.find_all('Malware_Instance')[0], 'Malware'))

                elif behavior[0].find_all('Attack_Patterns'):
                    ttp_info.update(ttp_extract_properties(package.find_all('Attack_Pattern')[0], 'Attack Pattern'))

                ttp_result[id_ref] = ttp_info

        return timestamp, StixDecode._deduplicate(observable_result), indicator_result, ttp_result


def parse_stix(file_name):
    tag_stack = collections.deque()  # type: ignore
    observables = []
    indicators: Dict[str, dict] = {}
    ttps: Dict[str, dict] = {}
    last_stix_package_ts = None
    last_taxii_content_ts = None

    for action, element in etree.iterparse(file_name, events=('start', 'end'), recover=True):
        if action == 'start':
            tag_stack.append(element.tag)

        else:
            last_tag = tag_stack.pop()
            if last_tag != element.tag:
                raise RuntimeError(
                    '{} - error parsing poll response, mismatched tags'.format(SCRIPT_NAME))

        if action == 'end' and element.tag.endswith('Status_Message') and len(tag_stack) == 0:
            raise_for_taxii_error(
                BeautifulSoup(etree.tostring(element, encoding='unicode'), 'xml')
            )
            return

        elif action == 'end' and element.tag.endswith('Poll_Response') and len(tag_stack) == 0:
            result_id = element.get('result_id', None)
            more = element.get('more', None)
            result_part_number = element.get('result_part_number', None)
            if result_part_number is not None:
                result_part_number = int(result_part_number)

        elif action == 'end' and element.tag.endswith('Content_Block') and len(tag_stack) == 1:
            for c in element:
                if c.tag.endswith('Content'):
                    if len(c) == 0:
                        continue

                    content = etree.tostring(c[0], encoding='unicode')
                    timestamp, observable, indicator, ttp = StixDecode.decode(content)
                    if observable:
                        observables.append(observable[0])
                    if indicator:
                        indicators.update(indicator)
                    if ttp:
                        ttps.update(ttp)

                    if timestamp:
                        if last_stix_package_ts is None or timestamp > last_stix_package_ts:
                            last_stix_package_ts = timestamp

                elif c.tag.endswith('Timestamp_Label'):
                    timestamp = parse_timestamp_label(c.text)

                    if timestamp:
                        if last_taxii_content_ts is None or timestamp > last_taxii_content_ts:
                            last_taxii_content_ts = timestamp

            element.clear()

    for observable in observables:

        if indicator_ref := observable.get('indicator_ref'):
            if indicator_info := indicators.get(indicator_ref):
                observable.update(indicator_info)

        ttp_ref = observable.get('ttp_ref', [])
        relationships = []

        for reference in ttp_ref:
            if relationship := ttps.get(reference):
                relationships.append(relationship)
        if relationships:
            observable['relationships'] = relationships

    return observables


def main():
    args = demisto.args()

    indicator_txt = args.get('ioc_txt')
    entry_id = args.get('entry_id')

    if not indicator_txt and not entry_id:
        raise Exception('You must enter ioc_txt or entry_id of the Indicator.')
    elif entry_id:
        file_path = demisto.getFilePath(entry_id).get('path')
        with open(file_path, 'rb') as f:
            content = f.read()
    else:
        content = indicator_txt

    if stix2 := convert_to_json(content):
        indicators = parse_stix2(stix2)
    else:
        with tempfile.NamedTemporaryFile() as temp:
            temp.write(content)
            temp.flush()
            observables = parse_stix(temp.name)
        print(observables)


from TAXII2ApiModule import *

if __name__ in ('__builtin__', 'builtins'):
    main()
