# Import std packages

# Import 3-rd party packages
from unittest.mock import MagicMock
import pytest

# Import local packages
from AlienVault_OTX_v2 import \
    calculate_dbot_score, Client, file_command, url_command, domain_command, ip_command, \
    delete_duplicated_entities
from CommonServerPython import *
import demistomock as demisto

# DBot calculation Test
arg_names_dbot = "pulse, score"


arg_values_dbot = [
    ({'false_positive': [{"assessment": "accepted", "assessment_date": "2021-04-01"}]}, 1),
    ({}, 1),
    ({"validation": [1]}, 2),
    ({'pulse_info': {'count': 5}, 'false_positive': [{"assessment": "pending", "assessment_date": "2021-04-01"}]}, 3),
    ({'pulse_info': {'count': 1}}, 2),
    ({'false_positive': [{"assessment": "pending", "assessment_date": "2021-04-01"}], 'pulse_info': {'count': 0}}, 0)]


FILE_GENERAL_RAW_RESPONSE = {'indicator': '6c5360d41bd2b14b1565f5b18e5c203cf512e493',
                             'sections': ['general', 'analysis'],
                             'pulse_info': {'count': 0, 'references': [], 'pulses': []},
                             'base_indicator': {'indicator': '2eb14920c75d5e73264f77cfa273ad2c', 'description': '',
                                                'title': '', 'access_reason': '', 'access_type': 'public',
                                                'content': '',
                                                'type': 'FileHash-MD5', 'id': 2113706547}, 'validation': [],
                             'type': 'sha1', 'type_title': 'FileHash-SHA1'}

FILE_ANALYSIS_RAW_RESPONSE = {'malware': {}, 'page_type': 'PEXE', 'analysis': {
    'info': {'results': {'sha1': '6c5360d41bd2b14b1565f5b18e5c203cf512e493', 'file_class': 'PEXE',
                         'file_type': 'PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows',
                         'filesize': '437760', 'ssdeep': '',
                         'sha256': '4cf9322c49adebf63311a599dc225bbcbf16a253eca59bbe1a02e4ae1d824412',
                         'md5': '2eb14920c75d5e73264f77cfa273ad2c'}},
    'hash': '4cf9322c49adebf63311a599dc225bbcbf16a253eca59bbe1a02e4ae1d824412',
    'has_S3': True, 'plugins': {}, 'datetime_int': '2016-04-14T12:24:43',
    '_id': '570f8d369d7ca60a650c6f8d',
    'analysis_time': 125743941,
    'metadata': {'tlp': 'WHITE'}}}

FILE_EMPTY_ANALYSIS_RAW_RESPONSE = {'malware': {}, 'page_type': 'generic', 'analysis': None}

FILE_EC_WITH_ANALYSIS = {
    'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 ||'
    ' val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 ||'
    ' val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH ||'
    ' val.SSDeep && val.SSDeep == obj.SSDeep)': {
        'MD5': '2eb14920c75d5e73264f77cfa273ad2c', 'SHA1': '6c5360d41bd2b14b1565f5b18e5c203cf512e493',
        'SHA256': '4cf9322c49adebf63311a599dc225bbcbf16a253eca59bbe1a02e4ae1d824412', 'SSDeep': '',
        'Size': '437760', 'Type': 'PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows',
        'Malicious': {'PulseIDs': []}},
    'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&'
    ' val.Vendor == obj.Vendor && val.Type == obj.Type)': [{
        'Indicator': '6c5360d41bd2b14b1565f5b18e5c203cf512e493', 'Type': 'file',
        'Vendor': 'AlienVault OTX v2', 'Score': 0, 'Reliability': 'C - Fairly reliable'
    }]
}

FILE_EC_WITHOUT_ANALYSIS = {
    'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 ||'
    ' val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 ||'
    ' val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH ||'
    ' val.SSDeep && val.SSDeep == obj.SSDeep)': [
        {'SHA1': '6c5360d41bd2b14b1565f5b18e5c203cf512e493',
         'Hashes': [
             {
                 'type': 'SHA1',
                 'value': '6c5360d41bd2b14b1565f5b18e5c203cf512e493'
             }
         ]
         }
    ],
    'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor &&'
    ' val.Type == obj.Type)': [{'Indicator': '6c5360d41bd2b14b1565f5b18e5c203cf512e493', 'Type': 'file',
                                'Vendor': '', 'Score': 0, 'Reliability': 'C - Fairly reliable',
                                'Message': 'No results found.'}]
}

URL_RAW_RESPONSE = {
    "alexa": "http://www.alexa.com/siteinfo/fotoidea.com",
    "base_indicator": {},
    "domain": "fotoidea.com",
    "False_positive": [],
    "hostname": "www.fotoidea.com",
    "indicator": "http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list",
    "pulse_info": {
        "count": 0,
        "pulses": [],
        "references": [],
        "related": {
            "alienvault": {
                "adversary": [],
                "industries": [],
                "malware_families": [],
                "unique_indicators": 0
            },
            "other": {
                "adversary": [],
                "industries": [],
                "malware_families": [],
                "unique_indicators": 0
            }
        }
    },
    "sections": [
        "general",
        "url_list",
        "http_scans",
        "screenshot"
    ],
    "type": "url",
    "type_title": "URL",
    "validation": [],
    "whois": "http://whois.domaintools.com/fotoidea.com"
}

URL_EC = {
    'URL(val.Data && val.Data == obj.Data)': [{
        'Data': {'url': 'http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list'},
        'Relationships': [{
            'Relationship': 'hosted-on',
            'EntityA': {'url': 'http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list'},
            'EntityAType': 'URL', 'EntityB': 'fotoidea.com', 'EntityBType': 'Domain'}]
    }],
    'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor &&'
    ' val.Type == obj.Type)': [{
        'Indicator': {'url': 'http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list'},
        'Type': 'url', 'Vendor': 'AlienVault OTX v2', 'Score': 0, 'Reliability': 'C - Fairly reliable'}],
    'AlienVaultOTX.URL(val.Url && val.Url === obj.Url)': {
        'Url': {'url': 'http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list'},
        'Hostname': 'www.fotoidea.com', 'Domain': 'fotoidea.com',
        'Alexa': 'http://www.alexa.com/siteinfo/fotoidea.com', 'Whois': 'http://whois.domaintools.com/fotoidea.com'}
}

URL_RELATIONSHIPS = [{
    'name': 'hosted-on', 'reverseName': 'hosts', 'type': 'IndicatorToIndicator',
    'entityA': 'http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list',
    'entityAFamily': 'Indicator', 'entityAType': 'URL', 'entityB': 'fotoidea.com', 'entityBFamily': 'Indicator',
    'entityBType': 'Domain', 'fields': {}, 'reliability': 'C - Fairly reliable', 'brand': 'AlienVault OTX v2'
}]

DOMAIN_RAW_RESPONSE = {
    "alexa": "http://www.alexa.com/siteinfo/otx.alienvault.com",
    "base_indicator": {},
    "False_positive": [],
    "indicator": "otx.alienvault.com",
    "pulse_info": {
        "count": 0,
        "pulses": [],
        "references": [],
        "related": {
            "alienvault": {
                "adversary": [],
                "industries": [],
                "malware_families": []
            },
            "other": {
                "adversary": [],
                "industries": [],
                "malware_families": []
            }
        }
    },
    "sections": [
        "general",
        "geo",
        "url_list",
        "passive_dns",
        "malware",
        "whois",
        "http_scans"
    ],
    "type": "domain",
    "type_title": "Domain",
    "validation": [
        {
            "message": "Whitelisted domain alienvault.com",
            "name": "Whitelisted domain",
            "source": "majestic"
        },
        {
            "message": "Whitelisted domain alienvault.com",
            "name": "Whitelisted domain",
            "source": "whitelist"
        }
    ],
    "whois": "http://whois.domaintools.com/otx.alienvault.com"
}

DOMAIN_DNS_RAW_RESPONSE = {'passive_dns': [], 'count': 0}

DOMAIN_HASH_RAW_RESPONSE = {'data': [], 'size': 865426, 'count': 865426}

DOMAIN_URL_RAW_RESPONSE = {'url_list': [], 'page_num': 1, 'limit': 10, 'paged': True, 'has_next': True,
                           'full_size': 5494039, 'actual_size': 5494039}

DOMAIN_EC = {'Domain(val.Name && val.Name == obj.Name)': [{'Name': {'domain': 'otx.alienvault.com'}}],
             'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)':
             [{'Indicator': {'domain': 'otx.alienvault.com'}, 'Type': 'domain', 'Vendor': 'AlienVault OTX v2', 'Score': 1,
               'Reliability': 'C - Fairly reliable'}],
             'AlienVaultOTX.Domain(val.Alexa && val.Alexa === obj.Alexa && val.Whois && val.Whois === obj.Whois)':
             {'Name': 'otx.alienvault.com', 'Alexa': 'http://www.alexa.com/siteinfo/otx.alienvault.com',
              'Whois': 'http://whois.domaintools.com/otx.alienvault.com'}}

IP_404_RAW_RESPONSE = 404

IP_RAW_RESPONSE = {
    "accuracy_radius": 1000,
    "area_code": 0,
    "asn": "AS3356 LEVEL3",
    "base_indicator": {},
    "charset": 0,
    "city": None,
    "city_data": True,
    "continent_code": "NA",
    "country_code": "US",
    "country_code2": "US",
    "country_code3": "USA",
    "country_name": "United States of America",
    "dma_code": 0,
    "False_positive": [],
    "flag_title": "United States of America",
    "flag_url": "/assets/images/flags/us.png",
    "indicator": "8.8.88.8",
    "latitude": 37.751,
    "longitude": -97.822,
    "postal_code": None,
    "pulse_info": {
        "count": 0,
        "pulses": [],
        "references": [],
        "related": {
            "alienvault": {
                "adversary": [],
                "industries": [],
                "malware_families": []
            },
            "other": {
                "adversary": [],
                "industries": [],
                "malware_families": []
            }
        }
    },
    "region": None,
    "reputation": 0,
    "sections": [
        "general",
        "geo",
        "reputation",
        "url_list",
        "passive_dns",
        "malware",
        "nids_list",
        "http_scans"
    ],
    "subdivision": None,
    "type": "IPv4",
    "type_title": "IPv4",
    "validation": [],
    "whois": "http://whois.domaintools.com/8.8.88.8"
}

IP_EC = {
    'IP(val.Address && val.Address == obj.Address)': [{
        'Address': '8.8.88.8', 'ASN': 'AS3356 LEVEL3', 'Geo': {'Location': '37.751:-97.822', 'Country': 'US'}}],
    'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor &&'
    ' val.Type == obj.Type)': [{
        'Indicator': '8.8.88.8', 'Type': 'ip', 'Vendor': 'AlienVault OTX v2', 'Score': 0,
        'Reliability': 'C - Fairly reliable'}],
    'AlienVaultOTX.IP(val.IP && val.IP === obj.IP)': {
        'IP': {'Reputation': 0, 'IP': '8.8.88.8'}}
}

IP_RAW_RESPONSE_WITH_RELATIONSHIPS = {
    "accuracy_radius": 1000,
    "area_code": 0,
    "asn": "AS36647 YAHOO-GQ1",
    "base_indicator": {
        "access_reason": "",
        "access_type": "public",
        "content": "",
        "description": "",
        "id": 2212739426,
        "indicator": "98.136.103.23",
        "title": "",
        "type": "IPv4"
    },
    "charset": 0,
    "city": None,
    "city_data": True,
    "continent_code": "NA",
    "country_code": "US",
    "country_code2": "US",
    "country_code3": "USA",
    "country_name": "United States of America",
    "dma_code": 0,
    "False_positive": [],
    "flag_title": "United States of America",
    "flag_url": "/assets/images/flags/us.png",
    "indicator": "98.136.103.23",
    "latitude": 37.751,
    "longitude": -97.822,
    "postal_code": None,
    "pulse_info": {
        "count": 1,
        "pulses": [
            {
                "TLP": "green",
                "adversary": "",
                "attack_ids": [
                    {
                        "display_name": "T1140 - Deobfuscate/Decode Files or Information",
                        "id": "T1140",
                        "name": "Deobfuscate/Decode Files or Information"
                    },
                    {
                        "display_name": "T1040 - Network Sniffing",
                        "id": "T1040",
                        "name": "Network Sniffing"
                    },
                    {
                        "display_name": "T1053 - Scheduled Task/Job",
                        "id": "T1053",
                        "name": "Scheduled Task/Job"
                    },
                    {
                        "display_name": "T1060 - Registry Run Keys / Startup Folder",
                        "id": "T1060",
                        "name": "Registry Run Keys / Startup Folder"
                    },
                    {
                        "display_name": "T1071 - Application Layer Protocol",
                        "id": "T1071",
                        "name": "Application Layer Protocol"
                    }
                ],
                "author": {
                    "avatar_url": "https://otx20-web-media.s3.amazonaws.com/media/avatars/user_80137/"
                                  "resized/80/avatar_54d0ee2979.png",
                    "id": "80137",
                    "is_following": False,
                    "is_subscribed": False,
                    "username": "dorkingbeauty1"
                },
                "cloned_from": None,
                "comment_count": 0,
                "created": "2020-12-11T23:37:51.039000",
                "description": "Technique ID: T1140 ATTACKID",
                "downvotes_count": 0,
                "export_count": 7,
                "follower_count": 0,
                "groups": [],
                "id": "5fd402cf91a35497c2af3da8",
                "in_group": False,
                "indicator_count": 4323,
                "indicator_type_counts": {
                    "FileHash-MD5": 21,
                    "FileHash-SHA1": 21,
                    "FileHash-SHA256": 253,
                    "URL": 3007,
                    "domain": 309,
                    "hostname": 712
                },
                "industries": [],
                "is_author": False,
                "is_modified": True,
                "is_subscribing": None,
                "locked": False,
                "malware_families": [],
                "modified": "2021-01-10T00:02:05.455000",
                "modified_text": "84 days ago ",
                "name": "4275147930ee7f90e65251218ef84542577ff2a79699dd6634108721ee81be1d",
                "public": 1,
                "pulse_source": "web",
                "references": [
                    "The following is the full set of results for the 2016 Windows World Cup"
                ],
                "related_indicator_is_active": 0,
                "related_indicator_type": "IPv4",
                "subscriber_count": 137,
                "tags": [
                    "pushdo",
                    "activity beacon",
                    "united",
                    "malware beacon",
                    "unknown",
                    "msie",
                    "windows nt",
                    "show",
                    "search",
                    "entries",
                    "malware",
                    "copy",
                    "date",
                    "write",
                    "whitelisted",
                    "as15169 google",
                    "united kingdom",
                    "gmbh",
                    "default"
                ],
                "targeted_countries": [
                    "Finland",
                    "Germany",
                    "France",
                    "Ireland",
                    "United Kingdom of Great Britain and Northern Ireland",
                    "United States of America"
                ],
                "threat_hunter_has_agents": 1,
                "threat_hunter_scannable": True,
                "upvotes_count": 0,
                "validator_count": 0,
                "vote": 0,
                "votes_count": 0
            }
        ],
        "references": [
            "The following is the full set of results for the 2016 Windows World Cup"
        ],
        "related": {
            "alienvault": {
                "adversary": [],
                "industries": [],
                "malware_families": []
            },
            "other": {
                "adversary": [],
                "industries": [],
                "malware_families": []
            }
        }
    },
    "region": None,
    "reputation": 0,
    "sections": [
        "general",
        "geo",
        "reputation",
        "url_list",
        "passive_dns",
        "malware",
        "nids_list",
        "http_scans"
    ],
    "subdivision": None,
    "type": "IPv4",
    "type_title": "IPv4",
    "validation": [
        {
            "message": "contained in whitelisted prefix",
            "name": "Whitelisted IP",
            "source": "whitelist"
        }
    ],
    "whois": "http://whois.domaintools.com/98.136.103.23"
}

IP_EC_WITH_RELATIONSHIPS = {
    'IP(val.Address && val.Address == obj.Address)': [{
        'Address': '98.136.103.23', 'ASN': 'AS36647 YAHOO-GQ1', 'Geo': {'Location': '37.751:-97.822', 'Country': 'US'},
        'Relationships': [{'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP',
                           'EntityB': 'T1140 - Deobfuscate/Decode Files or Information',
                           'EntityBType': 'Attack Pattern'},
                          {'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP',
                           'EntityB': 'T1040 - Network Sniffing', 'EntityBType': 'Attack Pattern'},
                          {'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP',
                           'EntityB': 'T1053 - Scheduled Task/Job', 'EntityBType': 'Attack Pattern'},
                          {'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP',
                           'EntityB': 'T1060 - Registry Run Keys / Startup Folder',
                           'EntityBType': 'Attack Pattern'},
                          {'Relationship': 'indicator-of', 'EntityA': '98.136.103.23', 'EntityAType': 'IP',
                           'EntityB': 'T1071 - Application Layer Protocol', 'EntityBType': 'Attack Pattern'}]
    }],
    'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)': [{
        'Indicator': '98.136.103.23', 'Type': 'ip', 'Vendor': 'AlienVault OTX v2', 'Score': 2,
        'Reliability': 'C - Fairly reliable'}],
    'AlienVaultOTX.IP(val.IP && val.IP === obj.IP)': {'IP': {'Reputation': 0, 'IP': '98.136.103.23'}}
}

IP_URL_RAW_RESPONSE = {'page_num': 1, 'limit': 10, 'paged': True, 'has_next': True, 'full_size': 7855, 'actual_size': 7855}

IP_URL_RAW_RESPONSE_WITH_RELATIONSHIPS = {'url_list': [{'url': 'mojorojorestaurante.com', 'date': '2022-01-03T08:21:31',
                                                        'domain': 'mojorojorestaurante.com',
                                                        'hostname': 'mojorojorestaurante.com',
                                                        'result': {'urlworker': {'ip': '8.8.8.8', 'http_code': 200},
                                                                   'safebrowsing': {'matches': []}},
                                                        'httpcode': 200, 'gsb': [], 'encoded':
                                                        'https%3A//mojorojorestaurante.com'}], 'page_num': 1, 'limit': 10,
                                          'paged': True, 'has_next': True, 'full_size': 7855, 'actual_size': 7855}

IP_FILE_ANALYSIS_RAW_RESPONSE = {'size': 2189582, 'count': 2189582}

IP_FILE_ANALYSIS_RAW_RESPONSE_WITH_RELATIONSHIPS = {'data': [{'datetime_int': 1508608939, 'hash':
                                                    '0b4d4a7c35a185680bc5102bdd98218297e2cdf0a552bde10e377345f3622c1c',
                                                              'detections': {'avast': 'Win32:Sinowal-GB\\ [Trj]', 'avg': None,
                                                                             'clamav': 'Win.Downloader.50691-1',
                                                                             'msdefender': 'Worm:Win32/VB'},
                                                              'date': '2017-10-21T18:02:19'}], 'size': 2189582, 'count': 2189582}

IP_DNS_RAW_RESPONSE_WITH_RELATIONSHIPS = {'passive_dns': [{'address': '8.8.8.8', 'first': '2022-01-04T08:25:39',
                                                           'last': '2022-01-04T08:25:39', 'hostname': 'nguyenhoangai-4g.xyz',
                                                           'record_type': 'A',
                                                           'indicator_link': '/indicator/domain/nguyenhoangai-4g.xyz',
                                                           'flag_url': 'assets/images/flags/us.png',
                                                           'flag_title': 'United States', 'asset_type': 'domain',
                                                           'asn': 'AS15169 GOOGLE'}], 'count': 1}

IP_DNS_RAW_RESPONSE = {'count': 0}

IP_RELATIONSHIPS = [
    {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator',
     'entityA': '98.136.103.23',
     'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': 'T1140 - Deobfuscate/Decode Files or Information',
     'entityBFamily': 'Indicator', 'entityBType': 'Attack Pattern', 'fields': {},
     'reliability': 'C - Fairly reliable',
     'brand': 'AlienVault OTX v2'},
    {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator',
     'entityA': '98.136.103.23', 'entityAFamily': 'Indicator', 'entityAType': 'IP',
     'entityB': 'T1040 - Network Sniffing', 'entityBFamily': 'Indicator', 'entityBType': 'Attack Pattern',
     'fields': {}, 'reliability': 'C - Fairly reliable', 'brand': 'AlienVault OTX v2'},
    {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator', 'entityA': '98.136.103.23',
     'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': 'T1053 - Scheduled Task/Job',
     'entityBFamily': 'Indicator', 'entityBType': 'Attack Pattern', 'fields': {}, 'reliability': 'C - Fairly reliable',
     'brand': 'AlienVault OTX v2'},
    {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator', 'entityA': '98.136.103.23',
     'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': 'T1060 - Registry Run Keys / Startup Folder',
     'entityBFamily': 'Indicator', 'entityBType': 'Attack Pattern', 'fields': {}, 'reliability': 'C - Fairly reliable',
     'brand': 'AlienVault OTX v2'},
    {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator', 'entityA': '98.136.103.23',
     'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': 'T1071 - Application Layer Protocol',
     'entityBFamily': 'Indicator', 'entityBType': 'Attack Pattern', 'fields': {}, 'reliability': 'C - Fairly reliable',
     'brand': 'AlienVault OTX v2'},
    {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator', 'entityA': '98.136.103.23',
     'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': 'mojorojorestaurante.com',
     'entityBFamily': 'Indicator', 'entityBType': 'URL', 'fields': {}, 'reliability': 'C - Fairly reliable',
     'brand': 'AlienVault OTX v2'},
    {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator', 'entityA': '98.136.103.23',
     'entityAFamily': 'Indicator', 'entityAType': 'IP',
     'entityB': '0b4d4a7c35a185680bc5102bdd98218297e2cdf0a552bde10e377345f3622c1c', 'entityBFamily': 'Indicator',
     'entityBType': 'File', 'fields': {}, 'reliability': 'C - Fairly reliable', 'brand': 'AlienVault OTX v2'},
    {'name': 'indicator-of', 'reverseName': 'indicated-by', 'type': 'IndicatorToIndicator', 'entityA': '98.136.103.23',
     'entityAFamily': 'Indicator', 'entityAType': 'IP', 'entityB': 'nguyenhoangai-4g.xyz', 'entityBFamily': 'Indicator',
     'entityBType': 'Domain', 'fields': {}, 'reliability': 'C - Fairly reliable', 'brand': 'AlienVault OTX v2'}]

INTEGRATION_NAME = 'AlienVault OTX v2'

client = Client(
    base_url="base_url",
    headers={'X-OTX-API-KEY': "TOKEN"},
    verify=False,
    proxy=False,
    default_threshold='2',
    max_indicator_relationships=3,
    reliability=DBotScoreReliability.C,
    create_relationships=True
)


@pytest.mark.parametrize(argnames=arg_names_dbot, argvalues=arg_values_dbot)
def test_dbot_score(pulse: dict, score: int):
    """
    Given:
        - Raw Response with fields relevant for Dbot score calculation

    When:
        - Running the calculate dbot score command

    Then:
        - Ensure the score is calculated correctly
    """
    assert calculate_dbot_score(client, pulse) == score, f"Error calculate DBot Score {pulse.get('count')}"


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


@pytest.mark.parametrize('raw_response_general,raw_response_analysis,expected', [
    (FILE_GENERAL_RAW_RESPONSE, FILE_ANALYSIS_RAW_RESPONSE, FILE_EC_WITH_ANALYSIS),
    (FILE_GENERAL_RAW_RESPONSE, FILE_EMPTY_ANALYSIS_RAW_RESPONSE, FILE_EC_WITHOUT_ANALYSIS)
])
def test_file_command(mocker, raw_response_general, raw_response_analysis, expected):
    """
    Given
    - A file hash.

    When
    - Running file_command with the file.

    Then
    - Validate that the File and DBotScore entry context have the proper values.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response_analysis, raw_response_general])
    command_results = file_command(client, file='6c5360d41bd2b14b1565f5b18e5c203cf512e493')
    # results is CommandResults list
    context = command_results[0].to_context()['EntryContext']
    assert expected == context


@pytest.mark.parametrize('raw_response,expected_ec, expected_relationships', [
    (URL_RAW_RESPONSE, URL_EC, URL_RELATIONSHIPS),
])
def test_url_command(mocker, raw_response, expected_ec, expected_relationships):
    """
    Given
    - A URL.

    When
    - Running url_command with the url.

    Then
    - Validate that the URL and DBotScore entry context have the proper values.
    - Validate that the proper relations were created
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    command_results = url_command(client, 'http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list')
    # results is CommandResults list
    all_context = command_results[0].to_context()

    context = all_context['EntryContext']
    assert sorted(expected_ec) == sorted(context)

    relations = all_context['Relationships']
    assert sorted(expected_relationships) == sorted(relations)


def test_url_command_not_found(mocker):
    """
    Given
    - A url with status code 404.

    When
    - Running url_command with the url.

    Then
    - Return no matches for the url.
    """
    url = 'http://url2447.staywell.com/asm/unsubscribe/?user_id=275860%5C%5Cu0026data=LeFzS0ZTdINxJN2UMVFvyPotO31n' \
          'Q1cIqvNrOcRqvlAgWpdtwnHcouXXGS0c64jBnTCVM9X4Cd5n0ZizgP78tXM5VB2w0m0DiwLI_J2sI1s09Mb5WlOYhWuCjJ8-lUjUdQ9' \
          'TyxcDuXhHIapoSlpgOzqCddxTLM3cSCW9zRcHfK5b3yO7P0XOFOqG-kZyFOs9LA75fX-yJ-d-2jHzBzeXrFbc9GxWEw1W9yyTUzvCY8' \
          'cirtcm1_CG8NVhvfc5wnattncML1PF6zctl5JVX3kUHZZJoc2uUHbADiLAJ6K3mEHmH4EbS9oEFs10MF8BvT7n'
    expected_result = 0
    mocker.patch.object(client, 'query', return_value=404)

    command_results = url_command(client, url)

    assert command_results[0].indicator.dbot_score.score == expected_result


def test_url_command_uppercase_protocol(requests_mock):
    """
    Given:
        - URL with uppercase protocol (HTTPS)

    When:
        - Running the url command

    Then:
        - Ensure the protocol is lowercased
    """
    requests_mock.get(
        'base_url/indicators/url/https://www.google.com/general',
        json={
            'alexa': 'http://www.alexa.com/siteinfo/google.com',
        }
    )
    res = url_command(client, 'HTTPS://www.google.com')
    assert res[0].indicator.to_context()['URL(val.Data && val.Data == obj.Data)']['Data'] == 'https://www.google.com'


@pytest.mark.parametrize('raw_response,url_raw_response,file_raw_response,dns_raw_response,expected', [
    (DOMAIN_RAW_RESPONSE, DOMAIN_DNS_RAW_RESPONSE, DOMAIN_HASH_RAW_RESPONSE, DOMAIN_URL_RAW_RESPONSE, DOMAIN_EC)
])
def test_domain_command(mocker, raw_response, url_raw_response, file_raw_response, dns_raw_response, expected):
    """
    Given
    - A domain name.

    When
    - Running domain_command with the domain.

    Then
    - Validate that the Domain and DBotScore entry context have the proper values.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response, url_raw_response, file_raw_response, dns_raw_response])
    command_results = domain_command(client, {'domain': 'otx.alienvault.com'})
    # results is CommandResults list
    context = command_results[0].to_context()['EntryContext']
    assert expected == context


test_ip_command_input = 'ip_,raw_response,url_raw_response,file_raw_response,dns_raw_response,expected_ec,expected_relationships'


@pytest.mark.parametrize(test_ip_command_input, [('8.8.88.8', IP_RAW_RESPONSE, IP_URL_RAW_RESPONSE,
                         IP_FILE_ANALYSIS_RAW_RESPONSE, IP_DNS_RAW_RESPONSE, IP_EC, []), ('98.136.103.23',
                         IP_RAW_RESPONSE_WITH_RELATIONSHIPS, IP_URL_RAW_RESPONSE_WITH_RELATIONSHIPS,
                         IP_FILE_ANALYSIS_RAW_RESPONSE_WITH_RELATIONSHIPS, IP_DNS_RAW_RESPONSE_WITH_RELATIONSHIPS,
                         IP_EC_WITH_RELATIONSHIPS, IP_RELATIONSHIPS)])
def test_ip_command(mocker, ip_, raw_response, url_raw_response, file_raw_response, dns_raw_response,
                    expected_ec, expected_relationships):
    """
    Given
    - An IPv4 address.

    When
    - Running ip_command with the IP.

    Then
    - Validate that the IP and DBotScore entry context have the proper values.
    - Validate that relationships where created if available in the raw response.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response, url_raw_response, file_raw_response, dns_raw_response])
    command_results = ip_command(client, ip_, 'IPv4')
    # results is CommandResults list
    all_context = command_results[0].to_context()

    context = all_context['EntryContext']
    assert sorted(expected_ec) == sorted(context)

    relations = all_context['Relationships']
    assert expected_relationships == relations


@pytest.mark.parametrize('ip_,raw_response,expected', [
    ('8.8.88.8', IP_404_RAW_RESPONSE, 0),
])
def test_ip_command_on_404(mocker, ip_, raw_response, expected):
    """
        Given
        - An IPv4 address.

        When
        - Running ip_command with the IP.

        Then
        - Validate that the CommandResult created correctly when the api returns 404
        """
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    command_results = ip_command(client, ip_, 'IPv4')
    assert command_results[0].indicator.dbot_score.score == expected


@pytest.mark.parametrize('entities_list,field_name,expected_results', [
    ([{'name': 'some_name'}, {'name': 'some_name1'}, {'name': 'some_name2'}, {'name': 'some_name3'}], 'name',
     [{'name': 'some_name'}, {'name': 'some_name1'}, {'name': 'some_name2'}, {'name': 'some_name3'}]),
    ([{'url': 'www.site1.com'}, {'url': 'www.site1.com'}, {'url': 'www.site2.com'}, {'url': 'www.site1.com'}], 'url',
     [{'url': 'www.site1.com'}, {'url': 'www.site2.com'}]),
])
def test_delete_duplicated_entities(entities_list, field_name, expected_results):
    """
    Given
    - Case 1: List containing 4 different entities and their field name.
    - Case 2: List containing 2 different entities where one of them appear 3 times and their field name.

    When
    - Running delete_duplicated_entities on input.

    Then
    - Ensure the duplicated entities were deleted.
    - Case 1: Should return the exact same list.
    - Case 2: Should return a list of length two containing only 1 occurrence of each entity from the input.
    """
    assert delete_duplicated_entities(entities_list, field_name) == expected_results


def test_query_function_return_timeout_error():
    """
    Given
    - A client configured with should_error=True.
    - The client's HTTP request method is mocked to raise a ReadTimeout exception.

    When
    - Calling ip_command with an IP address.

    Then
    - Ensure a ReadTimeout exception is raised.
    """
    client = Client(base_url='aa', headers={}, verify=True, proxy=False, default_threshold='5', max_indicator_relationships='1',
                    reliability='', should_error=True)
    client._http_request = MagicMock()
    client._http_request.side_effect = requests.exceptions.ReadTimeout("Request timed out")
    with pytest.raises(requests.exceptions.ReadTimeout) as e:
        ip_command(client, ip_address='9.9.9.9', ip_version='9.9.9.9')
    assert e.value.args[0] == 'Request timed out'

def test_query_function_return_timeout_warning():
    """
    Given
    - A client configured with should_error=False.
    - The client's HTTP request method is mocked to raise a ReadTimeout exception.

    When
    - Calling ip_command with an IP address.

    Then
    - Ensure the function does not raise an exception.
    - Ensure the returned result contains a readable output indicating "Not found".
    """
    client = Client(base_url='aa', headers={}, verify=True, proxy=False, default_threshold='5', max_indicator_relationships='1',
                    reliability='', should_error=False)
    client._http_request = MagicMock()
    client._http_request.side_effect = requests.exceptions.ReadTimeout("Request timed out")
    result = ip_command(client, ip_address='9.9.9.9', ip_version='9.9.9.9')
    assert result[0].readable_output == '### Results:\n|IP|Result|\n|---|---|\n| 9.9.9.9 | Not found |\n'
        
