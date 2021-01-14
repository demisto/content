import tempfile
from typing import Dict, Optional

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import collections

import cabby
import requests
from lxml import etree
import dateutil.parser
from bs4 import BeautifulSoup
from netaddr import IPAddress
from six import string_types

# TAXII11 import

import uuid
import dateutil
import pytz

# disable insecure warnings
urllib3.disable_warnings()

EPOCH = datetime.utcfromtimestamp(0).replace(tzinfo=pytz.UTC)
INTEGRATION_NAME = 'TAXII1'


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


class Taxii11(object):
    """
    TAXII 1 client utilities class
    """
    MESSAGE_BINDING = 'urn:taxii.mitre.org:message:xml:1.1'
    SERVICES = 'urn:taxii.mitre.org:services:1.1'
    PROTOCOLS = {
        'http': 'urn:taxii.mitre.org:protocol:http:1.0',
        'https': 'urn:taxii.mitre.org:protocol:https:1.0'
    }
    # 2014-12-19T00:00:00Z
    TAXII_DT_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

    @staticmethod
    def new_message_id():
        return str(uuid.uuid4())

    @staticmethod
    def discovery_request(message_id=None):
        if message_id is None:
            message_id = Taxii11.new_message_id()

        return f'''<Discovery_Request xmlns="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="{message_id}"/>'''

    @staticmethod
    def collection_information_request(message_id=None):
        if message_id is None:
            message_id = Taxii11.new_message_id()

        return '''<taxii_11:Collection_Information_Request xmlns:taxii_11=
        "http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="{}"/>'''.format(
            message_id)

    @staticmethod
    def poll_request(
            collection_name,
            exclusive_begin_timestamp,
            inclusive_end_timestamp,
            message_id=None,
            subscription_id=None):
        if message_id is None:
            message_id = Taxii11.new_message_id()

        exclusive_begin_timestamp = exclusive_begin_timestamp.strftime(Taxii11.TAXII_DT_FORMAT)
        inclusive_end_timestamp = inclusive_end_timestamp.strftime(Taxii11.TAXII_DT_FORMAT)

        result = [
            '<taxii_11:Poll_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"',
            'message_id="{}"'.format(message_id),
            'collection_name="{}"'.format(collection_name)
        ]
        if subscription_id is not None:
            result.append('subscription_id="{}"'.format(subscription_id))
        result.append('>')
        result.append('<taxii_11:Exclusive_Begin_Timestamp>{}</taxii_11:Exclusive_Begin_Timestamp>'.format(
            exclusive_begin_timestamp))
        result.append(
            '<taxii_11:Inclusive_End_Timestamp>{}</taxii_11:Inclusive_End_Timestamp>'.format(inclusive_end_timestamp))

        if subscription_id is None:
            result.append(
                '<taxii_11:Poll_Parameters allow_asynch="false"><taxii_11:Response_Type>'
                'FULL</taxii_11:Response_Type></taxii_11:Poll_Parameters>')

        result.append('</taxii_11:Poll_Request>')

        return '\n'.join(result)

    @staticmethod
    def poll_fulfillment_request(result_id, result_part_number, collection_name, message_id=None):
        if message_id is None:
            message_id = Taxii11.new_message_id()

        return f'''<taxii_11:Poll_Fulfillment xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"
                    message_id="{message_id}" collection_name="{collection_name}" result_id="{result_id}"
                    result_part_number="{result_part_number}"/>'''

    @staticmethod
    def headers(content_type=None, accept=None, services=None, protocol=None):
        if content_type is None:
            content_type = Taxii11.MESSAGE_BINDING

        if accept is None:
            accept = Taxii11.MESSAGE_BINDING

        if services is None:
            services = Taxii11.SERVICES

        if protocol is None:
            protocol = 'urn:taxii.mitre.org:protocol:http:1.0'
        if protocol in Taxii11.PROTOCOLS:
            protocol = Taxii11.PROTOCOLS[protocol]

        return {
            'Content-Type': 'application/xml',
            'X-TAXII-Content-Type': content_type,
            'X-TAXII-Accept': accept,
            'X-TAXII-Services': services,
            'X-TAXII-Protocol': protocol
        }

    @staticmethod
    def parse_timestamp_label(timestamp_label):
        try:
            dt = dateutil.parser.parse(timestamp_label)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=pytz.UTC)
            delta = dt - EPOCH
            return int(delta.total_seconds() * 1000)

        except Exception:
            return None


class TAXIIClient(object):
    def __init__(self, insecure: bool = True, polling_timeout: int = 20, initial_interval: str = '1 day',
                 discovery_service: str = '', poll_service: str = None, collection: str = None,
                 credentials: dict = None, cert_text: str = None, key_text: str = None, tags: str = None,
                 tlp_color: Optional[str] = None, **kwargs):
        """
        TAXII Client
        :param insecure: Set to true to ignore https certificate
        :param polling_timeout: Time before send request timeout
        :param initial_interval: Interval between each read from TAXII server
        :param discovery_service: TAXII server discovery service
        :param poll_service: TAXII poll service
        :param collection: TAXII collection
        :param credentials: Username and password dict for basic auth
        :param cert_text: Certificate File as Text
        :param cert_Key: Key File as Text
        :param kwargs:
        """
        self.discovered_poll_service = None
        self.last_taxii_run = demisto.getLastRun()
        if isinstance(self.last_taxii_run, dict):
            self.last_taxii_run = self.last_taxii_run.get('time')
        self.last_stix_package_ts = None
        self.last_taxii_content_ts = None
        self.verify_cert = not insecure
        self.polling_timeout = polling_timeout
        try:
            self.polling_timeout = int(self.polling_timeout)
        except (ValueError, TypeError):
            raise TypeError('Please provide a valid integer for "Polling Timeout"')
        self.initial_interval = initial_interval
        self.initial_interval = interval_in_sec(self.initial_interval)
        if self.initial_interval is None:
            self.initial_interval = 86400

        self.discovery_service = discovery_service
        self.poll_service = poll_service
        self.collection = collection

        self.api_key = None
        self.api_header = None
        self.username = None
        self.password = None
        self.crt = None
        self.tags = argToList(tags)
        self.tlp_color = tlp_color
        # authentication
        if credentials:
            if '_header:' in credentials.get('identifier', None):
                self.api_header = credentials.get('identifier', None).split('_header:')[1]
                self.api_key = credentials.get('password', None)
            else:
                self.username = credentials.get('identifier', None)
                self.password = credentials.get('password', None)

        if (cert_text and not key_text) or (not cert_text and key_text):
            raise Exception('You can not configure either certificate text or key, both are required.')
        if cert_text and key_text:

            cert_text_list = cert_text.split('-----')
            # replace spaces with newline characters
            cert_text_fixed = '-----'.join(cert_text_list[:2] + [cert_text_list[2].replace(' ', '\n')] + cert_text_list[3:])
            cf = tempfile.NamedTemporaryFile(delete=False)
            cf.write(cert_text_fixed.encode())
            cf.flush()

            key_text_list = key_text.split('-----')
            # replace spaces with newline characters
            key_text_fixed = '-----'.join(key_text_list[:2] + [key_text_list[2].replace(' ', '\n')] + key_text_list[3:])
            kf = tempfile.NamedTemporaryFile(delete=False)
            kf.write(key_text_fixed.encode())
            kf.flush()
            self.crt = (cf.name, kf.name)

        if collection is None or collection == '':
            all_collections = self.get_all_collections()
            return_error(f"No collection set. Here is a list of all accessible collections: "
                         f"{str(all_collections)}")

    def get_all_collections(self, is_raise_error=False):
        """Gets a list of all collections listed in the discovery service instance.

        Args:
            is_raise_error(bool): Whether to raise an error when one occurs.

        Returns:
            list. A list of all collection names in discovery service.
        """
        if self.discovery_service:
            taxii_client = cabby.create_client(discovery_path=self.discovery_service)
            if self.username:
                taxii_client.set_auth(username=str(self.username), password=self.password, verify_ssl=self.verify_cert)
            elif self.api_key:
                taxii_client.set_auth(username=str(self.api_key), verify_ssl=self.verify_cert)
            else:
                taxii_client.set_auth(verify_ssl=self.verify_cert)

            try:
                all_collections = taxii_client.get_collections()
                return [collection.name for collection in all_collections]
            except Exception as e:
                if is_raise_error:
                    raise ConnectionError()
                return_error(f'{INTEGRATION_NAME} - An error occurred when trying to fetch available collections.\n{e}')

        return []

    def _send_request(self, url, headers, data, stream=False):
        if self.api_key is not None and self.api_header is not None:
            headers[self.api_header] = self.api_key

        rkwargs = dict(
            stream=stream,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            headers=headers,
            cert=self.crt,
            data=data
        )

        if self.username is not None and self.password is not None:
            rkwargs['auth'] = (self.username, self.password)

        r = requests.post(
            url,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except Exception:
            demisto.debug(
                '{} - exception in request: {!r} {!r}'.format(INTEGRATION_NAME, r.status_code, r.content)
            )
            raise

        return r

    @staticmethod
    def _raise_for_taxii_error(response):
        if response.contents[0].name != 'Status_Message':
            return

        if response.contents[0]['status_type'] == 'SUCCESS':
            return

        raise RuntimeError('{} - error returned by TAXII Server: {}'.format(
            INTEGRATION_NAME, response.contents[0]['status_type']
        ))

    def _discover_poll_service(self):
        # let's start from discovering the available services
        req = Taxii11.discovery_request()
        reqhdrs = Taxii11.headers(
            protocol=self.discovery_service.split(':', 1)[0]
        )
        result = self._send_request(
            url=self.discovery_service,
            headers=reqhdrs,
            data=req
        )

        result = BeautifulSoup(result.text, 'xml')
        self._raise_for_taxii_error(result)

        # from here we look for a good collection management service
        coll_services = result.find_all(
            'Service_Instance',
            service_type='COLLECTION_MANAGEMENT'
        )
        if len(coll_services) == 0:
            raise RuntimeError('{} - Collection management service not found'.format(INTEGRATION_NAME))

        selected_coll_service = None
        for coll_service in coll_services:
            address = coll_service.find('Address')
            if address is None:
                LOG(
                    '{} - Collection management service with no address: {!r}'.format(
                        INTEGRATION_NAME, coll_service
                    )
                )
                continue
            address = address.string

            if selected_coll_service is None:
                selected_coll_service = address
                continue

            msgbindings = coll_service.find_all('Message_Binding')
            if len(msgbindings) != 0:
                for msgbinding in msgbindings:
                    if msgbinding.string == Taxii11.MESSAGE_BINDING:
                        selected_coll_service = address
                        break

        if selected_coll_service is None:
            raise RuntimeError(
                '{} - Collection management service not found'.format(INTEGRATION_NAME)
            )

        # from here we look for the correct poll service
        req = Taxii11.collection_information_request()
        reqhdrs = Taxii11.headers(
            protocol=selected_coll_service.split(':', 1)[0]
        )
        result = self._send_request(
            url=selected_coll_service,
            headers=reqhdrs,
            data=req
        )

        result = BeautifulSoup(result.text, 'xml')
        self._raise_for_taxii_error(result)

        # from here we look for the collection
        collections_found = result.find_all('Collection', collection_name=self.collection)
        if len(collections_found) == 0:
            raise RuntimeError(f'{INTEGRATION_NAME} - collection {self.collection} not found')

        # and the right poll service
        poll_service = None
        for coll in collections_found:
            pservice = coll.find('Polling_Service')
            if pservice is None:
                LOG('{} - Collection with no Polling_Service: {!r}'.format(INTEGRATION_NAME, coll))
                continue

            address = pservice.find('Address')
            if address is None:
                LOG('{} - Collection with no Address: {!r}'.format(INTEGRATION_NAME, coll))
                continue
            address = address.string

            if poll_service is None:
                poll_service = address
                continue
            msgbindings = coll_service.find_all('Message_Binding')
            if len(msgbindings) != 0:
                for msgbinding in msgbindings:
                    if msgbinding.string == Taxii11.MESSAGE_BINDING:
                        poll_service = address
                        break

        if poll_service is None:
            raise RuntimeError('{} - No valid Polling Service found'.format(INTEGRATION_NAME))

        return poll_service

    def _poll_collection(self, poll_service, begin, end):
        req = Taxii11.poll_request(
            collection_name=self.collection,
            exclusive_begin_timestamp=begin,
            inclusive_end_timestamp=end
        )
        reqhdrs = Taxii11.headers(
            protocol=poll_service.split(':', 1)[0]
        )
        result = self._send_request(
            url=poll_service,
            headers=reqhdrs,
            data=req,
            stream=True
        )
        result.raw.decode_content = True

        while True:
            result_part_number = None
            result_id = None
            more = None
            tag_stack = collections.deque()  # type: ignore
            xml_parser = etree.iterparse(result.raw, events=('start', 'end'), recover=True, dtd_validation=False,
                                         load_dtd=False, encoding='utf-8')

            try:
                for action, element in xml_parser:
                    if action == 'start':
                        tag_stack.append(element.tag)

                    else:
                        last_tag = tag_stack.pop()
                        if last_tag != element.tag:
                            raise RuntimeError(
                                '{} - error parsing poll response, mismatched tags'.format(INTEGRATION_NAME))

                    if action == 'end' and element.tag.endswith('Status_Message') and len(tag_stack) == 0:
                        self._raise_for_taxii_error(
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
                                timestamp, indicators = StixDecode.decode(content)

                                for indicator in indicators:
                                    yield indicator
                                if timestamp:
                                    if self.last_stix_package_ts is None or timestamp > self.last_stix_package_ts:
                                        self.last_stix_package_ts = timestamp

                            elif c.tag.endswith('Timestamp_Label'):
                                timestamp = Taxii11.parse_timestamp_label(c.text)

                                if timestamp:
                                    if self.last_taxii_content_ts is None or timestamp > self.last_taxii_content_ts:
                                        self.last_taxii_content_ts = timestamp

                        element.clear()

            finally:
                result.close()

            if not more or more == '0' or more.lower() == 'false':
                break

            if result_id is None or result_part_number is None:
                break

            req = Taxii11.poll_fulfillment_request(
                collection_name=self.collection,
                result_id=result_id,
                result_part_number=result_part_number + 1
            )
            result = self._send_request(
                url=poll_service,
                headers=reqhdrs,
                data=req,
                stream=True
            )

    def _incremental_poll_collection(self, poll_service, begin, end):
        """Polls collection in increments of 10 days"""
        cbegin = begin
        dt = timedelta(days=10)

        self.last_stix_package_ts = None
        self.last_taxii_content_ts = None

        while cbegin < end:
            cend = min(end, cbegin + dt)

            result = self._poll_collection(
                poll_service=poll_service,
                begin=cbegin,
                end=cend
            )

            for i in result:
                yield i

            if self.last_taxii_content_ts is not None:
                self.last_taxii_run = self.last_taxii_content_ts

            cbegin = cend

    def build_iterator(self, now):
        """Creates an indicator iterator from the TAXII feed"""
        if self.poll_service is not None:
            discovered_poll_service = self.poll_service
        else:
            discovered_poll_service = self._discover_poll_service()

        last_run = self.last_taxii_run

        if last_run is None:
            last_run = now - (self.initial_interval * 1000)
            self.last_taxii_run = last_run

        begin = datetime.utcfromtimestamp(last_run / 1000)
        begin = begin.replace(microsecond=0, tzinfo=pytz.UTC)

        end = datetime.utcfromtimestamp(now / 1000)
        end = end.replace(tzinfo=pytz.UTC)

        # lower time precision - solve issues with certain taxii servers
        end = end.replace(second=0, microsecond=0)
        begin = begin.replace(second=0, microsecond=0)
        return self._incremental_poll_collection(
            discovered_poll_service,
            begin=begin,
            end=end
        )


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


def interval_in_sec(val):
    """Translates interval string to seconds int"""
    if val is None:
        return None
    if isinstance(val, int):
        return val
    else:
        range_split = val.split()
        if len(range_split) != 2:
            raise ValueError('Interval must be "number date_range_unit", examples: (2 hours, 4 minutes,6 months, 1 day.')
        number = int(range_split[0])
        range_unit = range_split[1].lower()
        if range_unit not in ['minute', 'minutes', 'hour', 'hours', 'day', 'days']:
            raise ValueError('The unit of Interval is invalid. Must be minutes, hours or days')

    multipliers = {
        'minute': 60,
        'hour': 3600,
        'day': 86400,
    }
    for m, m_value in multipliers.items():
        if m in range_unit:
            return number * m_value

    return None


def test_module(client, *_):
    try:
        all_collections = client.get_all_collections(is_raise_error=True)
    except ConnectionError:
        all_collections = [client.collection]

    if client.collection not in all_collections:
        return_error(f'Collection could not be found at this time. Here is a list of all accessible collections:'
                     f' {str(all_collections)}')

    client._discover_poll_service()
    return 'ok', {}, {}


def fetch_indicators_command(client):
    iterator = client.build_iterator(date_to_timestamp(datetime.now()))
    indicators = []
    for item in iterator:
        indicator = item.get('indicator')
        if indicator:
            item['value'] = indicator
            indicator_obj = {
                'value': indicator,
                'type': item.get('type'),
                'fields': {
                    'tags': client.tags,
                },
                'rawJSON': item,
            }
            if client.tlp_color:
                indicator_obj['fields']['trafficlightprotocol'] = client.tlp_color

            indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client, args):
    limit = int(args.get('limit', 10))
    client.initial_interval = interval_in_sec(args.get('initial_interval'))
    client.last_taxii_run = None
    indicators_list = fetch_indicators_command(client)
    entry_result = camelize(indicators_list[:limit])
    hr = tableToMarkdown('Indicators', entry_result, headers=['Value', 'Type', 'Rawjson'])
    return hr, {'TAXII.Indicator': entry_result}, indicators_list


def main():
    # Write configure here
    params = {key: value for key, value in demisto.params().items() if value is not None}
    handle_proxy()
    client = TAXIIClient(**params)
    command = demisto.command()
    demisto.info('Command being called is {command}'.format(command=command))
    # Switch case
    commands = {
        'test-module': test_module,
        'get-indicators': get_indicators_command
    }
    try:
        if demisto.command() == 'fetch-indicators':
            indicators = fetch_indicators_command(client)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
            demisto.setLastRun({'time': client.last_taxii_run})
        else:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())  # type: ignore
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        raise Exception(err_msg)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
