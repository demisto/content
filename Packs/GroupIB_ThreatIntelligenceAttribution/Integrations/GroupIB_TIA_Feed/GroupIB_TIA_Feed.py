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
MAPPING: dict = {
    "compromised/mule": {
        "indicators":
            [
                {
                    "main_field": 'account', "main_field_type": 'GIB Compromised Mule',
                    "add_fields": [
                        'dateAdd', 'sourceType', 'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'creationdate', 'source', 'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc_url', "main_field_type": 'URL',
                    "add_fields": [
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc_domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc_ipv4_ip', "main_field_type": 'IP',
                    "add_fields": [
                        'cnc_ipv4_asn', 'cnc_ipv4_countryName', 'cnc_ipv4_region', 'malware_name',
                        'threatActor_name', 'threatActor_isAPT', 'threatActor_id',
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
                    "main_field": 'cnc_url', "main_field_type": 'URL',
                    "add_fields": [
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc_domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc_ipv4_ip', "main_field_type": 'IP',
                    "add_fields": [
                        'cnc_ipv4_asn', 'cnc_ipv4_countryName', 'cnc_ipv4_region',
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'device_imei', "main_field_type": 'GIB Compromised IMEI',
                    "add_fields": [
                        'dateDetected', 'dateCompromised', 'device_model',
                        'client_ipv4_asn', 'client_ipv4_countryName',
                        'client_ipv4_region', 'client_ipv4_ip',
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
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
                    "main_field": 'cnc_url', "main_field_type": 'URL',
                    "add_fields": [
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc_domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'cnc_ipv4_ip', "main_field_type": 'IP',
                    "add_fields": [
                        'cnc_ipv4_asn', 'cnc_ipv4_countryName', 'cnc_ipv4_region',
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'target_ipv4_ip', "main_field_type": 'GIB Victim IP',
                    "add_fields": [
                        'target_ipv4_asn', 'target_ipv4_countryName', 'target_ipv4_region',
                        'malware_name', 'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibmalwarename', 'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                }
            ]
    },
    "attacks/deface": {
        "indicators":
            [
                {
                    "main_field": 'url', "main_field_type": 'URL',
                    "add_fields": ['threatActor_name', 'threatActor_isAPT', 'threatActor_id'],
                    "add_fields_types": ['gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid']
                },
                {
                    "main_field": 'targetDomain', "main_field_type": 'Domain',
                    "add_fields": ['threatActor_name', 'threatActor_isAPT', 'threatActor_id'],
                    "add_fields_types": ['gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid']
                },
                {
                    "main_field": 'targetIp_ip', "main_field_type": 'IP',
                    "add_fields": [
                        'targetIp_asn', 'targetIp_countryName', 'targetIp_region',
                        'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
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
                    "main_field": 'phishingDomain_domain', "main_field_type": 'Domain',
                    "add_fields":
                    [
                        'phishingDomain_dateRegistered', 'phishingDomain_registrar',
                        'phishingDomain_title', 'targetBrand',
                        'targetCategory', 'targetDomain'
                    ],
                    "add_fields_types":
                    [
                        'creationdate', 'registrarname',
                        'gibphishingtitle', 'gibtargetbrand',
                        'gibtargetcategory', 'gibtargetdomain'
                    ]
                },
                {
                    "main_field": 'ipv4_ip', "main_field_type": 'IP',
                    "add_fields": ['ipv4_asn', 'ipv4_countryName', 'ipv4_region'],
                    "add_fields_types": ['asn', 'geocountry', 'geolocation']
                }
            ]
    },
    "attacks/phishing_kit": {
        "indicators":
            [
                {
                    "main_field": 'emails', "main_field_type": 'Email',
                }
            ]
    },
    "apt/threat": {
        "indicators":
            [
                {
                    "main_field": 'indicators_params_ipv4', "main_field_type": 'IP',
                    "add_fields": [
                        'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'indicators_params_domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'indicators_params_url', "main_field_type": 'URL',
                    "add_fields": [
                        'threatActor_name',
                        'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname',
                        'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'indicators_params_hashes_md5', "main_field_type": 'File',
                    "add_fields": [
                        'indicators_params_name', 'indicators_params_hashes_md5',
                        'indicators_params_hashes_sha1',
                        'indicators_params_hashes_sha256', 'indicators_params_size',
                        'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibfilename', 'md5', 'sha1', 'sha256', 'size',
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                }
            ]
    },
    "hi/threat": {
        "indicators":
            [
                 {
                     "main_field": 'indicators_params_ipv4', "main_field_type": 'IP',
                     "add_fields": [
                         'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
                     ],
                     "add_fields_types": [
                         'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                     ]
                 },
                {
                     "main_field": 'indicators_params_domain', "main_field_type": 'Domain',
                     "add_fields": [
                         'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
                     ],
                     "add_fields_types": [
                         'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                     ]
                 },
                {
                     "main_field": 'indicators_params_url', "main_field_type": 'URL',
                     "add_fields": [
                         'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
                     ],
                     "add_fields_types": [
                         'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                     ]
                 },
                {
                     "main_field": 'indicators_params_hashes_md5', "main_field_type": 'File',
                     "add_fields": [
                         'indicators_params_name', 'indicators_params_hashes_md5',
                         'indicators_params_hashes_sha1',
                         'indicators_params_hashes_sha256', 'indicators_params_size',
                         'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
                     ],
                     "add_fields_types": [
                         'gibfilename', 'md5', 'sha1', 'sha256', 'size',
                         'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                     ]
                 }
            ]
    },
    "suspicious_ip/tor_node": {
        'indicators':
            [
                {
                    "main_field": 'ipv4_ip', "main_field_type": 'IP',
                    "add_fields": ['ipv4_asn', 'ipv4_countryName', 'ipv4_region'],
                    "add_fields_types": ['asn', 'geocountry', 'geolocation']
                }
            ]
    },
    "suspicious_ip/open_proxy": {
        'indicators':
            [
                {
                    "main_field": 'ipv4_ip', "main_field_type": 'IP',
                    "add_fields":
                    [
                        'ipv4_asn', 'ipv4_countryName', 'ipv4_region',
                        'port', 'anonymous', 'source'
                    ],
                    "add_fields_types":
                    [
                        'asn', 'geocountry', 'geolocation',
                        'gibproxyport', 'gibproxyanonymous', 'source'
                    ]
                }
            ]
    },
    "suspicious_ip/socks_proxy": {
        'indicators':
            [
                {
                    "main_field": 'ipv4_ip', "main_field_type": 'IP',
                    "add_fields": ['ipv4_asn', 'ipv4_countryName', 'ipv4_region'],
                    "add_fields_types": ['asn', 'geocountry', 'geolocation']
                }
            ]
    },
    "malware/cnc": {
        'indicators':
            [
                {
                    'main_field': 'url', "main_field_type": 'URL',
                    "add_fields": [
                        'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    'main_field': 'domain', "main_field_type": 'Domain',
                    "add_fields": [
                        'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
                    ]
                },
                {
                    "main_field": 'ipv4_ip', "main_field_type": 'IP',
                    "add_fields": [
                        'ipv4_asn', 'ipv4_countryName', 'ipv4_region',
                        'threatActor_name', 'threatActor_isAPT', 'threatActor_id'
                    ],
                    "add_fields_types": [
                        'asn', 'geocountry', 'geolocation',
                        'gibthreatactorname', 'gibthreatactorisapt', 'gibthreatactorid'
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
                        'cvss_score', 'cvss_vector', 'softwareMixed',
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

    path = key.split("_", 1)
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
        return unpacked
    else:
        if iocs in ['255.255.255.255', '0.0.0.0', '', None]:
            return []

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
        if collection_name == 'attacks/phishing':
            if fields_dict.get('creationdate'):
                fields_dict['creationdate'] = \
                    dateparser.parse(fields_dict['creationdate']).strftime('%Y-%m-%dT%H:%M:%SZ')

        fields_dict.update({'gibcollection': collection_name})
        return [{'value': iocs, 'type': ioc_type,
                 'raw_json': {'value': iocs, 'type': ioc_type, **fields_dict}, 'fields': fields_dict}]


def find_iocs_in_feed(feed: Dict, collection_name: str) -> List:
    """
    Finds IOCs in the feed and transform them to the appropriate format to ingest them into Demisto.

    :param feed: feed from GIB TI&A.
    :param collection_name: which collection this feed belongs to.
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
        if collection_name in ['apt/threat', 'hi/threat', 'malware/cnc']:
            add_fields.append(', '.join(find_element_by_key(feed, "malwareList_name")))
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
        indicator = indicator.get('raw_json')
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
                             indicator_collections: List, requests_count: int) -> Tuple[Dict, List]:
    """
    This function will execute each interval (default is 1 minute).

    :param client: GIB_TI&A_Feed client.
    :param last_run: the greatest sequpdate we fetched from last fetch.
    :param first_fetch_time: if last_run is None then fetch all incidents since first_fetch_time.
    :param indicator_collections: list of collections enabled by client.
    :param requests_count: count of requests to API per collection.

    :return: next_run will be last_run in the next fetch-indicators; indicators will be created in Demisto.
    """
    indicators = []
    next_run: Dict[str, Dict[str, Union[int, Any]]] = {"last_fetch": {}}
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
                indicators.extend(find_iocs_in_feed(feed, collection_name))
            k += 1
            if k >= requests_count:
                break

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
                indicators.extend(find_iocs_in_feed(feed, collection_name))
                if len(indicators) >= limit:
                    indicators = indicators[:limit]
                    break
            if len(indicators) >= limit:
                break
    else:
        raw_json = client.search_feed_by_id(collection_name=collection_name, feed_id=id_)
        indicators.extend(find_iocs_in_feed(raw_json, collection_name))
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
            next_run, indicators = fetch_indicators_command(client=client, last_run=get_integration_context(),
                                                            first_fetch_time=indicators_first_fetch,
                                                            indicator_collections=indicator_collections,
                                                            requests_count=requests_count)
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
