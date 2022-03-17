import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
""" IMPORTS """

from typing import Dict, Generator, List, Optional, Tuple, Union

import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
# todo: add all necessary field types
COMMON_FIELD_TYPES = ['trafficlightprotocol']
DATE_FIELDS_LIST = ["creationdate", "firstseenbysource", "lastseenbysource", "gibdatecompromised"]
MAPPING: dict = {
    "compromised/mule": {
        "indicators":
            [
                {
                    "main_field": 'account', "main_field_type": 'GIB Compromised Mule',
                    "add_fields": [
                        'dateAdd', 'sourceType', 'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'creationdate', 'source', 'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc.url', "main_field_type": 'URL',
                    "add_fields": [
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc.domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc.ipv4.ip', "main_field_type": 'IP',
                    "add_fields": [
                        'cnc.ipv4.asn', 'cnc.ipv4.countryName', 'cnc.ipv4.region', 'malware.name',
                        'threatActor.name', 'threatActor.isAPT', 'threatActor.id',
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation', 'gibmalwarename',
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                }
            ]
    },
    "compromised/imei": {
        "indicators":
            [
                {
                    "main_field": 'cnc.url', "main_field_type": 'URL',
                    "add_fields": [
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc.domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc.ipv4.ip', "main_field_type": 'IP',
                    "add_fields": [
                        'cnc.ipv4.asn', 'cnc.ipv4.countryName', 'cnc.ipv4.region',
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'device.imei', "main_field_type": 'GIB Compromised IMEI',
                    "add_fields": [
                        'dateDetected', 'dateCompromised', 'device.model',
                        'client.ipv4.asn', 'client.ipv4.countryName',
                        'client.ipv4.region', 'client.ipv4.ip',
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types":[
                        'creationdate', 'gibdatecompromised', 'devicemodel',
                        'asn', 'geocountry', 'geolocation', 'ipaddress',
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                }
            ]
    },
    "attacks/ddos": {
        "indicators":
            [
                {
                    "main_field": 'cnc.url', "main_field_type": 'URL',
                    "add_fields": [
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc.domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc.ipv4.ip', "main_field_type": 'IP',
                    "add_fields": [
                        'cnc.ipv4.asn', 'cnc.ipv4.countryName', 'cnc.ipv4.region',
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'target.ipv4.ip', "main_field_type": 'GIB Victim IP',
                    "add_fields": [
                        'target.ipv4.asn', 'target.ipv4.countryName', 'target.ipv4.region',
                        'malware.name', 'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id',
                        'dateBegin', 'dateEnd'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                }
            ]
    },
    "attacks/deface": {
        "indicators":
            [
                {
                    "main_field": 'url', "main_field_type": 'URL',
                    "add_fields": ['threatActor.name', 'threatActor.isAPT', 'threatActor.id'],
                    "add_fields_types": ['gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid']
                },
                {
                    "main_field": 'targetDomain', "main_field_type": 'Domain',
                    "add_fields": ['threatActor.name', 'threatActor.isAPT', 'threatActor.id'],
                    "add_fields_types": ['gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid']
                },
                {
                    "main_field": 'targetIp.ip', "main_field_type": 'IP',
                    "add_fields": [
                        'targetIp.asn', 'targetIp.countryName', 'targetIp.region',
                        'threatActor.name', 'threatActor.isAPT', 'threatActor.id'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                }
            ]
    },
    "attacks/phishing": {
        "indicators":
            [
                {
                    "main_field": 'url', "main_field_type": 'URL',
                },
                {
                    "main_field": 'phishingDomain.domain', "main_field_type": 'Domain',
                    "add_fields":
                    [
                        'phishingDomain.dateRegistered', 'dateDetected',
                        'phishingDomain.registrar',
                        'phishingDomain.title', 'targetBrand',
                        'targetCategory', 'targetDomain'
                    ],
                    "add_fields_types":
                    [
                        'creationdate', 'firstseenbysource',
                        'registrarname',
                        'gibphishingtitle', 'gibtargetbrand',
                        'gibtargetcategory', 'gibtargetdomain'
                    ]
                },
                {
                    "main_field": 'ipv4.ip', "main_field_type": 'IP',
                    "add_fields": ['ipv4.asn', 'ipv4.countryName', 'ipv4.region'],
                    "add_fields_types": ['asn', 'geocountry', 'geolocation']
                }
            ]
    },
    "attacks/phishing_kit": {
        "indicators":
            [
                {
                    "main_field": 'emails', "main_field_type": 'Email',
                    "add_fields": ['dateFirstSeen', 'dateLastSeen'],
                    "add_fields_types": ['firstseenbysource', 'lastseenbysource']
                }
            ]
    },
    "apt/threat": {
        "indicators":
            [
                {
                    "main_field": 'indicators.params.ipv4', "main_field_type": 'IP',
                    "add_fields": [
                        'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id',
                        'indicators.dateFirstSeen', 'indicators.dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                },
                {
                    "main_field": 'indicators.params.domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id',
                        'indicators.dateFirstSeen', 'indicators.dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                },
                {
                    "main_field": 'indicators.params.url', "main_field_type": 'URL',
                    "add_fields": [
                        'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id',
                        'indicators.dateFirstSeen', 'indicators.dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                },
                {
                    "main_field": 'indicators.params.hashes.md5', "main_field_type": 'File',
                    "add_fields": [
                        'indicators.params.name', 'indicators.params.hashes.md5',
                        'indicators.params.hashes.sha1',
                        'indicators.params.hashes.sha256', 'indicators.params.size',
                        'threatActor.name', 'threatActor.isAPT', 'threatActor.id',
                        'indicators.dateFirstSeen', 'indicators.dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibfilename', 'md5', 'sha1', 'sha256', 'size',
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                }
            ]
    },
    "hi/threat": {
        "indicators":
            [
                {
                    "main_field": 'indicators.params.ipv4', "main_field_type": 'IP',
                    "add_fields": [
                        'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id',
                        'indicators.dateFirstSeen', 'indicators.dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                },
                {
                    "main_field": 'indicators.params.domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id',
                        'indicators.dateFirstSeen', 'indicators.dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                },
                {
                    "main_field": 'indicators.params.url', "main_field_type": 'URL',
                    "add_fields": [
                        'threatActor.name',
                        'threatActor.isAPT', 'threatActor.id',
                        'indicators.dateFirstSeen', 'indicators.dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                },
                {
                    "main_field": 'indicators.params.hashes.md5', "main_field_type": 'File',
                    "add_fields": [
                        'indicators.params.name', 'indicators.params.hashes.md5',
                        'indicators.params.hashes.sha1',
                        'indicators.params.hashes.sha256', 'indicators.params.size',
                        'threatActor.name', 'threatActor.isAPT', 'threatActor.id',
                        'indicators.dateFirstSeen', 'indicators.dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibfilename', 'md5', 'sha1', 'sha256', 'size',
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                }
            ]
    },
    "suspicious_ip/tor_node": {
        'indicators':
            [
                {
                    "main_field": 'ipv4.ip', "main_field_type": 'IP',
                    "add_fields": ['ipv4.asn', 'ipv4.countryName', 'ipv4.region', 'dateFirstSeen', 'dateLastSeen'],
                    "add_fields_types": ['asn', 'geocountry', 'geolocation', 'firstseenbysource', 'lastseenbysource']
                }
            ]
    },
    "suspicious_ip/open_proxy": {
        'indicators':
            [
                {
                    "main_field": 'ipv4.ip', "main_field_type": 'IP',
                    "add_fields":
                    [
                        'ipv4.asn', 'ipv4.countryName', 'ipv4.region',
                        'port', 'anonymous', 'source',
                        'dateFirstSeen', 'dateDetected'
                    ],
                    "add_fields_types":
                    [
                        'asn', 'geocountry', 'geolocation',
                        'gibproxyport', 'gibproxyanonymous', 'source',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                }
            ]
    },
    "suspicious_ip/socks_proxy": {
        'indicators':
            [
                {
                    "main_field": 'ipv4.ip', "main_field_type": 'IP',
                    "add_fields": ['ipv4.asn', 'ipv4.countryName', 'ipv4.region', 'dateFirstSeen', 'dateLastSeen'],
                    "add_fields_types": ['asn', 'geocountry', 'geolocation', 'firstseenbysource', 'lastseenbysource']
                }
            ]
    },
    "malware/cnc": {
        'indicators':
            [
                {
                    'main_field': 'url', "main_field_type": 'URL',
                    "add_fields": [
                        'threatActor.name', 'threatActor.isAPT', 'threatActor.id',
                        'dateDetected', 'dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                },
                {
                    'main_field': 'domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'threatActor.name', 'threatActor.isAPT', 'threatActor.id',
                        'dateDetected', 'dateLastSeen'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                },
                {
                    "main_field": 'ipv4.ip', "main_field_type": 'IP',
                    "add_fields": [
                        'ipv4.asn', 'ipv4.countryName', 'ipv4.region',
                        'threatActor.name', 'threatActor.isAPT', 'threatActor.id',
                        'dateDetected', 'dateLastSeen'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid',
                        'firstseenbysource', 'lastseenbysource'
                    ]
                }
            ]
    },
    "osi/vulnerability": {
        'indicators':
            [
                {
                    'main_field': 'id', "main_field_type": 'CVE',
                    "add_fields":
                    [
                        'cvss.score', 'cvss.vector', 'softwareMixed',
                        'description', 'dateModified', 'datePublished'
                    ],
                    "add_fields_types":
                    [
                        'cvss', 'gibcvssvector', 'gibsoftwaremixed',
                        'cvedescription', 'cvemodified', 'published'
                    ]
                }
            ]
    },
}


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def create_update_generator(self, collection_name: str, date_from: Optional[str] = None,
                                seq_update: Union[int, str] = None, limit: int = 200) -> Generator:
        """
        Creates generator of lists with feeds class objects for an update session
        (feeds are sorted in ascending order) `collection_name` with set parameters.

        `seq_update` allows you to receive all relevant feeds. Such a request uses the seq_update parameter,
        you will receive a portion of feeds that starts with the next `seq_update` parameter for the current collection.
        For all feeds in the Group IB Intelligence continuous numbering is carried out.
        For example, the `seq_update` equal to 1999998 can be in the `compromised/accounts` collection,
        and a feed with seq_update equal to 1999999 can be in the `attacks/ddos` collection.
        If item updates (for example, if new attacks were associated with existing APT by our specialists
        or tor node has been detected as active again), the item gets a new parameter and it automatically rises
        in the database and "becomes relevant" again.

        :param collection_name: collection to update.
        :param date_from: start date of update session.
        :param seq_update: identification number from which to start the session.
        :param limit: size of portion in iteration.
        """

        while True:
            params = {'df': date_from, 'limit': limit, 'seqUpdate': seq_update}
            params = {key: value for key, value in params.items() if value}
            portion = self._http_request(method="GET", url_suffix=collection_name + '/updated',
                                         params=params, timeout=60.,
                                         retries=4, status_list_to_retry=[429, 500])
            if portion.get("count") == 0:
                break
            seq_update = portion.get("seqUpdate")
            date_from = None
            yield portion.get('items')

    def create_search_generator(self, collection_name: str, date_from: str = None,
                                limit: int = 200) -> Generator:
        """
        Creates generator of lists with feeds for the search session
        (feeds are sorted in descending order) for `collection_name` with set parameters.

        :param collection_name: collection to search.
        :param date_from: start date of search session.
        :param limit: size of portion in iteration.
        """

        result_id = None
        while True:
            params = {'df': date_from, 'limit': limit, 'resultId': result_id}
            params = {key: value for key, value in params.items() if value}
            portion = self._http_request(method="GET", url_suffix=collection_name,
                                         params=params, timeout=60.,
                                         retries=4, status_list_to_retry=[429, 500])
            if len(portion.get('items')) == 0:
                break
            result_id = portion.get("resultId")
            date_from = None
            yield portion.get('items')

    def search_feed_by_id(self, collection_name: str, feed_id: str) -> Dict:
        """
        Searches for feed with `feed_id` in collection with `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        """

        portion = self._http_request(method="GET", url_suffix=collection_name + '/' + feed_id, timeout=60.,
                                     retries=4, status_list_to_retry=[429, 500])
        return portion


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    :param client: GIB_TI&A_Feed client
    :return: 'ok' if test passed, anything else will fail the test.
    """

    generator = client.create_update_generator(collection_name='compromised/mule', limit=10)
    generator.__next__()
    return 'ok'


""" Support functions """


def find_element_by_key(obj, key):
    """
    Recursively finds element or elements in dict.
    """

    path = key.split(".", 1)
    if len(path) == 1:
        if isinstance(obj, list):
            return [i.get(path[0]) for i in obj]
        elif isinstance(obj, dict):
            return obj.get(path[0])
        else:
            return obj
    else:
        if isinstance(obj, list):
            return [find_element_by_key(i.get(path[0]), path[1]) for i in obj]
        elif isinstance(obj, dict):
            return find_element_by_key(obj.get(path[0]), path[1])
        else:
            return obj


def unpack_iocs(iocs, ioc_type, fields, fields_names, collection_name):
    """
    Recursively ties together and transforms indicator data.
    """
    unpacked = []
    if isinstance(iocs, list):
        for i, ioc in enumerate(iocs):
            buf_fields = []
            for field in fields:
                if isinstance(field, list):
                    buf_fields.append(field[i])
                else:
                    buf_fields.append(field)
            unpacked.extend(unpack_iocs(ioc, ioc_type, buf_fields, fields_names, collection_name))
    else:
        if iocs in ['255.255.255.255', '0.0.0.0', '', None]:
            return unpacked

        fields_dict = {fields_names[i]: fields[i] for i in range(len(fields_names)) if fields[i] is not None}

        # Transforming one certain field into a markdown table
        if ioc_type == "CVE" and len(fields_dict["gibsoftwaremixed"]) != 0:
            soft_mixed = fields_dict.get("gibsoftwaremixed", {})
            buffer = ''
            for chunk in soft_mixed:
                software_name = ', '.join(chunk.get('softwareName'))
                software_type = ', '.join(chunk.get('softwareType'))
                software_version = ', '.join(chunk.get('softwareVersion'))
                if len(software_name) != 0 or len(software_type) != 0 or len(software_version) != 0:
                    buffer += '| {0} | {1} | {2} |\n'.format(software_name, software_type,
                                                             software_version.replace('||', ', '))
            if len(buffer) != 0:
                buffer = "| Software Name | Software Type | Software Version |\n" \
                         "| ------------- | ------------- | ---------------- |\n" + buffer
                fields_dict["gibsoftwaremixed"] = buffer
            else:
                del fields_dict["gibsoftwaremixed"]

        # Transforming into correct date format
        for date_field in DATE_FIELDS_LIST:
            if fields_dict.get(date_field):
                fields_dict[date_field] = dateparser.parse(fields_dict.get(date_field)).strftime('%Y-%m-%dT%H:%M:%SZ')

        fields_dict.update({'gibcollection': collection_name})
        unpacked.append({'value': iocs, 'type': ioc_type,
                         'rawJSON': {'value': iocs, 'type': ioc_type, **fields_dict}, 'fields': fields_dict})

    return unpacked


def find_iocs_in_feed(feed: Dict, collection_name: str, common_fields: Dict) -> List:
    """
    Finds IOCs in the feed and transform them to the appropriate format to ingest them into Demisto.

    :param feed: feed from GIB TI&A.
    :param collection_name: which collection this feed belongs to.
    :param common_fields: fields defined by user.
    """

    indicators = []
    indicators_info = MAPPING.get(collection_name, {}).get('indicators', [])
    for i in indicators_info:
        main_field = find_element_by_key(feed, i['main_field'])
        main_field_type = i['main_field_type']
        add_fields = []
        add_fields_list = i.get('add_fields', []) + ['id']
        for j in add_fields_list:
            add_fields.append(find_element_by_key(feed, j))
        add_fields_types = i.get('add_fields_types', []) + ['gibid']
        for field_type in COMMON_FIELD_TYPES:
            if common_fields.get(field_type):
                add_fields.append(common_fields.get(field_type))
                add_fields_types.append(field_type)
        if collection_name in ['apt/threat', 'hi/threat', 'malware/cnc']:
            add_fields.append(', '.join(find_element_by_key(feed, "malwareList.name")))
            add_fields_types = add_fields_types + ['gibmalwarename']
        indicators.extend(unpack_iocs(main_field, main_field_type, add_fields,
                                      add_fields_types, collection_name))
    return indicators


def get_human_readable_feed(indicators: List, type_: str, collection_name: str) -> str:
    headers = ['value', 'type']
    for fields in MAPPING.get(collection_name, {}).get('indicators', {}):
        if fields.get('main_field_type') == type_:
            headers.extend(fields['add_fields_types'])
            break
    if collection_name in ['apt/threat', 'hi/threat', 'malware/cnc']:
        headers.append('gibmalwarename')
    return tableToMarkdown("{0} indicators".format(type_), indicators,
                           removeNull=True, headers=headers)


def format_result_for_manual(indicators: List) -> Dict:
    formatted_indicators: Dict[str, Any] = {}
    for indicator in indicators:
        indicator = indicator.get('rawJSON')
        type_ = indicator.get('type')
        if type_ == 'CVE':
            del indicator["gibsoftwaremixed"]
        if formatted_indicators.get(type_) is None:
            formatted_indicators[type_] = [indicator]
        else:
            formatted_indicators[type_].append(indicator)
    return formatted_indicators


""" Commands """


def fetch_indicators_command(client: Client, last_run: Dict, first_fetch_time: str,
                             indicator_collections: List, requests_count: int,
                             common_fields: Dict) -> Tuple[Dict, List]:
    """
    This function will execute each interval (default is 1 minute).

    :param client: GIB_TI&A_Feed client.
    :param last_run: the greatest sequpdate we fetched from last fetch.
    :param first_fetch_time: if last_run is None then fetch all incidents since first_fetch_time.
    :param indicator_collections: list of collections enabled by client.
    :param requests_count: count of requests to API per collection.
    :param common_fields: fields defined by user.

    :return: next_run will be last_run in the next fetch-indicators; indicators will be created in Demisto.
    """
    indicators = []
    next_run: Dict[str, Dict[str, Union[int, Any]]] = {"last_fetch": {}}
    tags = common_fields.pop("tags", [])
    for collection_name in indicator_collections:
        last_fetch = last_run.get('last_fetch', {}).get(collection_name)

        # Handle first time fetch
        date_from = None
        seq_update = None
        if not last_fetch:
            date_from = dateparser.parse(first_fetch_time)
            if date_from is None:
                raise DemistoException('Inappropriate indicators_first_fetch format, '
                                       'please use something like this: 2020-01-01 or January 1 2020 or 3 days')
            date_from = date_from.strftime('%Y-%m-%d')
        else:
            seq_update = last_fetch

        portions = client.create_update_generator(collection_name=collection_name,
                                                  date_from=date_from, seq_update=seq_update)
        k = 0
        for portion in portions:
            for feed in portion:
                seq_update = feed.get('seqUpdate')
                indicators.extend(find_iocs_in_feed(feed, collection_name, common_fields))
            k += 1
            if k >= requests_count:
                break

        if tags:
            for indicator in indicators:
                indicator["fields"].update({"tags": tags})
                indicator["rawJSON"].update({"tags": tags})

        next_run['last_fetch'][collection_name] = seq_update

    return next_run, indicators


def get_indicators_command(client: Client, args: Dict[str, str]):
    """
    Returns limited portion of indicators to War Room.

    :param client: GIB_TI&A_Feed client.
    :param args: arguments, provided by client.
    """

    id_, collection_name = args.get('id'), args.get('collection', '')
    indicators = []
    raw_json = None
    try:
        limit = int(args.get('limit', '50'))
        if limit > 50:
            raise Exception('A limit should be lower than 50.')
    except ValueError:
        raise Exception('A limit should be a number, not a string.')

    if collection_name not in MAPPING.keys():
        raise Exception('Incorrect collection name. Please, choose one of the displayed options.')

    if not id_:
        portions = client.create_search_generator(collection_name=collection_name, limit=limit)
        for portion in portions:
            for feed in portion:
                indicators.extend(find_iocs_in_feed(feed, collection_name, {}))
                if len(indicators) >= limit:
                    indicators = indicators[:limit]
                    break
            if len(indicators) >= limit:
                break
    else:
        raw_json = client.search_feed_by_id(collection_name=collection_name, feed_id=id_)
        indicators.extend(find_iocs_in_feed(raw_json, collection_name, {}))
        if len(indicators) >= limit:
            indicators = indicators[:limit]

    formatted_indicators = format_result_for_manual(indicators)
    results = []
    for type_, indicator in formatted_indicators.items():
        results.append(CommandResults(
            readable_output=get_human_readable_feed(indicator, type_, collection_name),
            raw_response=raw_json,
            ignore_auto_extract=True
        ))
    return results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    proxy = params.get('proxy', False)
    verify_certificate = not params.get('insecure', False)
    base_url = str(params.get("url"))

    indicator_collections = params.get('indicator_collections', [])
    indicators_first_fetch = params.get('indicators_first_fetch', '3 days').strip()
    requests_count = int(params.get('requests_count', 2))

    args = demisto.args()
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy,
            headers={"Accept": "*/*"})

        commands = {'gibtia-get-indicators': get_indicators_command}

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif command == 'fetch-indicators':
            # Set and define the fetch incidents command to run after activated via integration settings.
            common_fields = {
                'trafficlightprotocol': params.get("tlp_color"),
                'tags': argToList(params.get("feedTags")),
            }
            next_run, indicators = fetch_indicators_command(client=client, last_run=get_integration_context(),
                                                            first_fetch_time=indicators_first_fetch,
                                                            indicator_collections=indicator_collections,
                                                            requests_count=requests_count,
                                                            common_fields=common_fields)
            set_integration_context(next_run)
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        else:
            return_results(commands[command](client, args))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
