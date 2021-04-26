# Import std packages

# Import 3-rd party packages
import pytest

# Import local packages
from AlienVault_OTX_v2 import calculate_dbot_score, Client, file_command, url_command, domain_command, ip_command
from CommonServerPython import *

# DBot calculation Test
arg_names_dbot = "pulse, score"

arg_values_dbot = [
    ({}, 0),
    ({'count': -1}, 0),
    ({'count': 0}, 0),
    ({'count': 1}, 2),
    ({'count': 2}, 3),
    ({'count': 1000}, 3),
    ({'count': 10}, 3),
    ({'count': 10}, 3),
]

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
        'Indicator': {
            'file': '6c5360d41bd2b14b1565f5b18e5c203cf512e493'}, 'Type': 'file',
        'Vendor': 'AlienVault OTX v2', 'Score': 0, 'Reliability': 'C - Fairly reliable'
    }]
}

FILE_EC_WITHOUT_ANALYSIS = {
    'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 ||'
    ' val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 ||'
    ' val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH ||'
    ' val.SSDeep && val.SSDeep == obj.SSDeep)': {
        'MD5': None, 'SHA1': None, 'SHA256': None, 'SSDeep': None, 'Size': None, 'Type': None,
        'Malicious': {'PulseIDs': []}},
    'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor &&'
    ' val.Type == obj.Type)': [{
        'Indicator': {'file': '6c5360d41bd2b14b1565f5b18e5c203cf512e493'}, 'Type': 'file',
        'Vendor': 'AlienVault OTX v2', 'Score': 0, 'Reliability': 'C - Fairly reliable'
    }]
}

URL_RAW_RESPONSE = {
    "alexa": "http://www.alexa.com/siteinfo/fotoidea.com",
    "base_indicator": {},
    "domain": "fotoidea.com",
    "false_positive": [],
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
        'Relations': [{
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
    'entityA': {'url': 'http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list'},
    'entityAFamily': 'Indicator', 'entityAType': 'URL', 'entityB': 'fotoidea.com', 'entityBFamily': 'Indicator',
    'entityBType': 'Domain', 'fields': {}, 'reliability': 'C - Fairly reliable', 'brand': 'AlienVault OTX v2'
}]

DOMAIN_RAW_RESPONSE = {
    "alexa": "http://www.alexa.com/siteinfo/otx.alienvault.com",
    "base_indicator": {},
    "false_positive": [],
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

DOMAIN_EC = {
    'Domain(val.Name && val.Name == obj.Name)': [{
        'Name': {'domain': 'otx.alienvault.com'}}],
    'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor &&'
    ' val.Type == obj.Type)': [{
        'Indicator': {'domain': 'otx.alienvault.com'}, 'Type': 'domain', 'Vendor': 'AlienVault OTX v2', 'Score': 0,
        'Reliability': 'C - Fairly reliable'}],
    'AlienVaultOTX.Domain(val.Alexa && val.Alexa === obj.Alexa && val.Whois && val.Whois === obj.Whois)': {
        'Name': 'otx.alienvault.com', 'Alexa': 'http://www.alexa.com/siteinfo/otx.alienvault.com',
        'Whois': 'http://whois.domaintools.com/otx.alienvault.com'}
}

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
    "false_positive": [],
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

client = Client(
    base_url="base_url",
    headers={'X-OTX-API-KEY': "TOKEN"},
    verify=False,
    proxy=False,
    default_threshold='2',
    reliability=DBotScoreReliability.C,
    create_relationships=True
)


@pytest.mark.parametrize(argnames=arg_names_dbot, argvalues=arg_values_dbot)
def test_dbot_score(pulse: dict, score: int):
    assert calculate_dbot_score(client, pulse) == score, f"Error calculate DBot Score {pulse.get('count')}"


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
    command_results = file_command(client, {'file': '6c5360d41bd2b14b1565f5b18e5c203cf512e493'})
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
    command_results = url_command(client, {
        'url': 'http://www.fotoidea.com/sport/4x4_san_ponso/slides/IMG_0068.html/url_list'})
    # results is CommandResults list
    all_context = command_results[0].to_context()

    context = all_context['EntryContext']
    assert expected_ec == context

    relations = all_context['Relationships']
    assert expected_relationships == relations


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
    expected_result = 'No matches for URL http://url2447.staywell.com/asm/unsubscribe/?user_id=275860%5C%5Cu0026dat' \
                      'a=LeFzS0ZTdINxJN2UMVFvyPotO31nQ1cIqvNrOcRqvlAgWpdtwnHcouXXGS0c64jBnTCVM9X4Cd5n0ZizgP78tXM5VB' \
                      '2w0m0DiwLI_J2sI1s09Mb5WlOYhWuCjJ8-lUjUdQ9TyxcDuXhHIapoSlpgOzqCddxTLM3cSCW9zRcHfK5b3yO7P0XOFO' \
                      'qG-kZyFOs9LA75fX-yJ-d-2jHzBzeXrFbc9GxWEw1W9yyTUzvCY8cirtcm1_CG8NVhvfc5wnattncML1PF6zctl5JVX3' \
                      'kUHZZJoc2uUHbADiLAJ6K3mEHmH4EbS9oEFs10MF8BvT7n'
    mocker.patch.object(client, 'query', return_value=404)

    command_results = url_command(client, url)

    assert command_results[0].to_context()['HumanReadable'] == expected_result


@pytest.mark.parametrize('raw_response,expected', [
    (DOMAIN_RAW_RESPONSE, DOMAIN_EC)
])
def test_domain_command(mocker, raw_response, expected):
    """
    Given
    - A domain name.

    When
    - Running domain_command with the domain.

    Then
    - Validate that the Domain and DBotScore entry context have the proper values.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    command_results = domain_command(client, {'domain': 'otx.alienvault.com'})
    # results is CommandResults list
    context = command_results[0].to_context()['EntryContext']
    assert expected == context


@pytest.mark.parametrize('raw_response,expected', [
    (IP_RAW_RESPONSE, IP_EC)
])
def test_ip_command(mocker, raw_response, expected):
    """
    Given
    - An IPv4 address.

    When
    - Running ip_command with the IP.

    Then
    - Validate that the IP and DBotScore entry context have the proper values.
    """
    mocker.patch.object(client, 'query', side_effect=[raw_response])
    command_results = ip_command(client, '8.8.88.8', 'IPv4')
    # results is CommandResults list
    context = command_results[0].to_context()['EntryContext']
    assert expected == context
