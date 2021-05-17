# Import std packages

# Import 3-rd party packages
import pytest

# Import local packages
from AlienVault_OTX_v2 import calculate_dbot_score, Client, file_command

INTEGRATION_NAME = 'AlienVault OTX v2'

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

GENERAL_RAW_RESPONSE = {'indicator': '6c5360d41bd2b14b1565f5b18e5c203cf512e493',
                        'sections': ['general', 'analysis'],
                        'pulse_info': {'count': 0, 'references': [], 'pulses': []},
                        'base_indicator': {'indicator': '2eb14920c75d5e73264f77cfa273ad2c', 'description': '',
                                           'title': '', 'access_reason': '', 'access_type': 'public', 'content': '',
                                           'type': 'FileHash-MD5', 'id': 2113706547}, 'validation': [],
                        'type': 'sha1', 'type_title': 'FileHash-SHA1'}

ANALYSIS_RAW_RESPONSE = {'malware': {}, 'page_type': 'PEXE', 'analysis': {
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

EMPTY_ANALYSIS_RAW_RESPONSE = {'malware': {}, 'page_type': 'generic', 'analysis': None}

EC_WITH_ANALYSIS = {
    'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256'
    ' || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32'
    ' || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': [
        {'MD5': '2eb14920c75d5e73264f77cfa273ad2c', 'SHA1': '6c5360d41bd2b14b1565f5b18e5c203cf512e493',
         'SHA256': '4cf9322c49adebf63311a599dc225bbcbf16a253eca59bbe1a02e4ae1d824412', 'SSDeep': '', 'Size': '437760',
         'Type': 'PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows',
         'Malicious': {'PulseIDs': []}}], 'DBotScore': [
        {'Indicator': '6c5360d41bd2b14b1565f5b18e5c203cf512e493', 'Score': 0, 'Type': 'file',
         'Vendor': 'AlienVault OTX v2'}]}

EC_WITHOUT_ANALYSIS = {
    'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256'
    ' || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32'
    ' || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': [
        {'MD5': None, 'SHA1': None, 'SHA256': None, 'SSDeep': None, 'Size': None, 'Type': None,
         'Malicious': {'PulseIDs': []}}], 'DBotScore': [
        {'Indicator': '6c5360d41bd2b14b1565f5b18e5c203cf512e493', 'Score': 0, 'Type': 'file',
         'Vendor': 'AlienVault OTX v2'}]}

client = Client(
    base_url="base_url",
    headers={'X-OTX-API-KEY': "TOKEN"},
    verify=False,
    proxy=False
)


@pytest.mark.parametrize(argnames=arg_names_dbot, argvalues=arg_values_dbot)
def test_dbot_score(pulse: dict, score: int):
    assert calculate_dbot_score(pulse) == score, f"Error calculate DBot Score {pulse.get('count')}"


@pytest.mark.parametrize('raw_response_general,raw_response_analysis,expected', [
    (GENERAL_RAW_RESPONSE, ANALYSIS_RAW_RESPONSE, EC_WITH_ANALYSIS),
    (GENERAL_RAW_RESPONSE, EMPTY_ANALYSIS_RAW_RESPONSE, EC_WITHOUT_ANALYSIS)
])
def test_file_command(mocker, raw_response_general, raw_response_analysis, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response_analysis, raw_response_general])
    results = file_command(client, {'file': '6c5360d41bd2b14b1565f5b18e5c203cf512e493'})
    # results is tuple (human_readable, context_entry, raw_response).
    assert expected == results[1]
