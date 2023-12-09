from copy import deepcopy

from ThreatConnect_v2 import calculate_freshness_time, create_context, demisto, \
    associate_indicator_request, get_indicators
from freezegun import freeze_time
import pytest
from requests import Response
from threatconnect import ThreatConnect

data_test_calculate_freshness_time = [
    (0, '2020-04-20'),
    (1, '2020-04-19')
]


@freeze_time('2020-04-20')
@pytest.mark.parametrize('freshness, time_out', data_test_calculate_freshness_time)
def test_calculate_freshness_time(freshness, time_out):
    time_out = f'{time_out}T00:00:00Z'
    output = calculate_freshness_time(freshness)
    assert output == time_out, f'calculate_freshness_time({freshness})\n\treturns: {output}\n\tinstead: {time_out}'


URL_INDICATOR = [{
    'id': 113283093,
    'owner': 'Demisto Inc.',
    'dateAdded': '2020-05-14T09:07:29Z',
    'lastModified': '2020-05-14T09:07:29Z',
    'rating': 0.0,
    'confidence': 0,
    'threatAssessRating': 0.0,
    'threatAssessConfidence': 0.0,
    'webLink': 'https://sandbox.threatconnect.com/auth/indicators/details/url.xhtml?orgid=113283093&owner=Demisto+Inc',
    'text': 'https://www.domain.info',
    'type': 'URL'
}]

URL_CONTEXT = (
    {
        'URL(val.Data && val.Data == obj.Data)': [{
            'Malicious': {
                'Vendor': 'ThreatConnect',
                'Description': ''
            },
            'Data': 'https://www.domain.info'
        }],
        'TC.Indicator(val.ID && val.ID === obj.ID)': [{
            'ID': 113283093,
            'Name': 'https://www.domain.info',
            'Type': 'URL',
            'Owner': 'Demisto Inc.',
            'CreateDate': '2020-05-14T09:07:29Z',
            'LastModified': '2020-05-14T09:07:29Z',
            'Rating': 0,
            'Confidence': 0,
            'WebLink': 'https://sandbox.threatconnect.com/auth/indicators/details/url.xhtml?'
                       'orgid=113283093&owner=Demisto+Inc'
        }]
    },
    [{
        'ID': 113283093,
        'Name': 'https://www.domain.info',
        'Type': 'URL',
        'Owner': 'Demisto Inc.',
        'CreateDate': '2020-05-14T09:07:29Z',
        'LastModified': '2020-05-14T09:07:29Z',
        'Rating': 0,
        'Confidence': 0,
        'WebLink': 'https://sandbox.threatconnect.com/auth/indicators/details/url.xhtml?'
                   'orgid=113283093&owner=Demisto+Inc'
    }]
)

IP_INDICATOR = [{
    'id': 113286420,
    'owner': 'Demisto Inc.',
    'dateAdded': '2020-05-14T13:16:32Z',
    'lastModified': '2020-05-14T13:16:32Z',
    'rating': 2.0,
    'confidence': 50,
    'threatAssessRating': 3.0,
    'threatAssessConfidence': 53.0,
    'webLink': 'https://sandbox.threatconnect.com/auth/indicators/details/address.xhtml?'
               'address=88.88.88.88&owner=Demisto+Inc',
    'ip': '88.88.88.88',
    'type': 'Address'
}]

IP_CONTEXT = (
    {'IP(val.Address && val.Address == obj.Address)': [
        {'Malicious': {'Vendor': 'ThreatConnect', 'Description': ''}, 'Address': '88.88.88.88'}],
        'TC.Indicator(val.ID && val.ID === obj.ID)': [
            {
                'ID': 113286420,
                'Name': '88.88.88.88',
                'Type': 'Address',
                'Owner': 'Demisto Inc.',
                'CreateDate': '2020-05-14T13:16:32Z',
                'LastModified': '2020-05-14T13:16:32Z',
                'Rating': 2,
                'Confidence': 50,
                'WebLink': 'https://sandbox.threatconnect.com/auth/indicators/details/address.xhtml?'
                           'address=88.88.88.88&owner=Demisto+Inc'
            }]},
    [{
        'ID': 113286420,
        'Name': '88.88.88.88',
        'Type': 'Address',
        'Owner': 'Demisto Inc.',
        'CreateDate': '2020-05-14T13:16:32Z',
        'LastModified': '2020-05-14T13:16:32Z',
        'Rating': 2,
        'Confidence': 50,
        'WebLink': 'https://sandbox.threatconnect.com/auth/indicators/details/address.xhtml?'
                   'address=88.88.88.88&owner=Demisto+Inc'
    }]
)

DOMAIN_INDICATOR = [{
    'id': 112618314,
    'owner': 'Demisto Inc.',
    'dateAdded': '2020-04-23T14:42:21Z',
    'lastModified': '2020-05-14T13:24:35Z',
    'rating': 0.0,
    'confidence': 0,
    'threatAssessRating': 0.0,
    'threatAssessConfidence': 0.0,
    'webLink': 'https://sandbox.threatconnect.com/auth/indicators/details/host.xhtml?'
               'host=domain.info&owner=Demisto+Inc',
    'hostName': 'domain.info',
    'dnsActive': 'false',
    'whoisActive': 'false',
    'type': 'Host'
}]

DOMAIN_CONTEXT = (
    {'Domain(val.Name && val.Name == obj.Name)': [
        {'Malicious': {'Vendor': 'ThreatConnect', 'Description': ''},
         'Name': 'domain.info'}],
        'TC.Indicator(val.ID && val.ID === obj.ID)': [
            {'ID': 112618314,
             'Name': 'domain.info',
             'Type': 'Host',
             'Owner': 'Demisto Inc.',
             'CreateDate': '2020-04-23T14:42:21Z',
             'LastModified': '2020-05-14T13:24:35Z',
             'Rating': 0,
             'Confidence': 0,
             'WebLink': 'https://sandbox.threatconnect.com/auth/indicators/details/host.xhtml?'
                        'host=domain.info&owner=Demisto+Inc',
             'Active': 'false'}]},
    [{
        'ID': 112618314,
        'Name': 'domain.info',
        'Type': 'Host',
        'Owner': 'Demisto Inc.',
        'CreateDate': '2020-04-23T14:42:21Z',
        'LastModified': '2020-05-14T13:24:35Z',
        'Rating': 0,
        'Confidence': 0,
        'WebLink': 'https://sandbox.threatconnect.com/auth/indicators/details/host.xhtml?'
                   'host=domain.info&owner=Demisto+Inc',
        'Active': 'false'}])

FILE_INDICATOR = [{
    'id': 113286426,
    'owner': 'Demisto Inc.',
    'dateAdded': '2020-05-14T13:22:49Z',
    'lastModified': '2020-05-14T13:22:49Z',
    'rating': 4.0,
    'confidence': 20,
    'threatAssessRating': 4.0,
    'threatAssessConfidence': 20.0,
    'webLink': 'https://sandbox.threatconnect.com/auth/indicators/details/file.xhtml?file=49456A'  # noqa: W504
               + '40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229&owner=Demisto+Inc.',
    'sha256': '49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229',
    'md5': 'md5test',
    'sha1': 'sha1test',
    'type': 'File'
}]
FILE_CONTEXT = (
    {
        'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': [  # noqa: E501
            {
                'Malicious':
                    {'Vendor': 'ThreatConnect', 'Description': ''},
                'MD5': 'md5test',
                'SHA1': 'sha1test',
                'SHA256': '49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229'
            }
        ],
        'TC.Indicator(val.ID && val.ID === obj.ID)': [
            {'ID': 113286426, 'Name': 'md5test', 'Type': 'File', 'Owner': 'Demisto Inc.',
             'CreateDate': '2020-05-14T13:22:49Z', 'LastModified': '2020-05-14T13:22:49Z', 'Rating': 4,
             'Confidence': 20,
             'WebLink': 'https://sandbox.threatconnect.com/auth/indicators/details/file.xhtml?file=49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229&owner=Demisto+Inc.',  # noqa: E501
             'File': {'MD5': 'md5test', 'SHA1': 'sha1test',
                      'SHA256': '49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229'}}]}, [
        {'ID': 113286426, 'Name': 'md5test', 'Type': 'File', 'Owner': 'Demisto Inc.',
         'CreateDate': '2020-05-14T13:22:49Z', 'LastModified': '2020-05-14T13:22:49Z', 'Rating': 4, 'Confidence': 20,
         'WebLink': 'https://sandbox.threatconnect.com/auth/indicators/details/file.xhtml?file=49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229&owner=Demisto+Inc.',  # noqa: E501
         'File':
             {
                 'MD5': 'md5test',
                 'SHA1': 'sha1test',
                 'SHA256': '49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229'
             }
         }
    ]
)

GET_XINDAPI_OWNER1 = [{'id': 1, 'owner': 'Demisto Inc.', 'dateAdded': '2020-08-26T10:14:55Z',
                       'lastModified': '2020-08-26T10:14:55Z', 'rating': 0.0, 'confidence': 0,
                       'threatAssessRating': 1.29,
                       'threatAssessConfidence': 5.29,
                       'webLink': '',
                       'ip': '127.0.0.1', 'type': 'Address'}]

GET_XINDAPI_OWNER2 = [{'id': 2, 'owner': 'PhishTank', 'dateAdded': '2020-08-26T10:14:55Z',
                       'lastModified': '2020-08-26T10:14:55Z', 'rating': 0.0, 'confidence': 0,
                       'threatAssessRating': 1.29,
                       'threatAssessConfidence': 5.29,
                       'webLink': '',
                       'ip': '127.0.0.1', 'type': 'Address'}]

EXPECTED_INDOCATORS_OUTPUT = [
    {"id": 1, "owner": "Demisto Inc.", "dateAdded": "2020-08-26T10:14:55Z", "lastModified": "2020-08-26T10:14:55Z",
     "rating": 0.0, "confidence": 0, "threatAssessRating": 1.29, "threatAssessConfidence": 5.29, "webLink": "",
     "ip": "127.0.0.1", "type": "Address"},
    {"id": 2, "owner": "PhishTank", "dateAdded": "2020-08-26T10:14:55Z", "lastModified": "2020-08-26T10:14:55Z",
     "rating": 0.0, "confidence": 0, "threatAssessRating": 1.29, "threatAssessConfidence": 5.29, "webLink": "",
     "ip": "127.0.0.1", "type": "Address"}]

PARAMS = {"defaultOrg": "Demisto Inc.", "freshness": 7, "rating": 0, "confidence": 0}
data_test_create_context = [
    ({}, ({}, []), PARAMS),
    (DOMAIN_INDICATOR, DOMAIN_CONTEXT, PARAMS),
    (IP_INDICATOR, IP_CONTEXT, PARAMS),
    (URL_INDICATOR, URL_CONTEXT, PARAMS),
    (FILE_INDICATOR, FILE_CONTEXT, PARAMS),
]


@pytest.mark.parametrize('indicators, expected_output, params', data_test_create_context)
def test_create_context(indicators, expected_output, params, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    output = create_context(indicators)
    assert output == expected_output, f'expected_output({indicators})\n\treturns: ' \
                                      f'{output}\n\tinstead: {expected_output}'


data_test_create_context_debotscore = [
    (
        {"defaultOrg": "Demisto Inc.", "freshness": 7, "rating": 0, "confidence": 0}, 3, 3
    ),
    (
        {"defaultOrg": "Demisto Inc.", "freshness": 7, "rating": 2, "confidence": 0}, 2, 3
    ),
    (
        {"defaultOrg": "Demisto Inc.", "freshness": 7, "rating": 2, "confidence": 0}, 3, 3
    ),
    (
        {"defaultOrg": "Demisto Inc.", "freshness": 7, "rating": 3, "confidence": 60}, 3, 2
    ),
    (
        {"defaultOrg": "Demisto Inc.", "freshness": 7, "rating": 1, "confidence": 100}, 0, 0
    )
]


@pytest.mark.parametrize('params, rate, expected_score', data_test_create_context_debotscore)
def test_create_context_debotscore(params, rate, expected_score, mocker):
    expected_output = {'Indicator': '88.88.88.88', 'Score': expected_score, 'Type': 'ip', 'Vendor': 'ThreatConnect',
                       'Reliability': 'B - Usually reliable'}
    indicator = deepcopy(IP_INDICATOR)
    indicator[0]['rating'] = float(rate)
    mocker.patch.object(demisto, 'params', return_value=params)
    output = create_context(indicator, True)[0].get('DBotScore', [{}])[0]
    assert output == expected_output, f'expected_output({indicator}, True)[0].get(\'DBotScore\')\n\treturns: {output}' \
                                      f'\n\tinstead: {expected_output}'


data_test_associate_indicator_request = [
    ('addresses', '0.0.0.0', 'addresses/0.0.0.0'),
    ('urls', 'http://test.com', 'urls/http%3A%2F%2Ftest.com')
]


@pytest.mark.parametrize('indicator_type, indicator, expected_url', data_test_associate_indicator_request)
def test_associate_indicator_request(indicator_type, indicator, expected_url, mocker):
    mocker.patch.object(Response, 'json', return_value={})
    api_request = mocker.patch.object(ThreatConnect, 'api_request', return_value=Response())
    mocker.patch('ThreatConnect_v2.get_client', return_value=ThreatConnect())
    associate_indicator_request(indicator_type, indicator, 'test', '0')
    url = f'/v2/indicators/{expected_url}/groups/test/0'
    assert api_request.call_args[0][0].request_uri == url


def test_ip_get_indicators_multiple_owners(mocker):
    mocker.patch('ThreatConnect_v2.get_xindapi', side_effect=[GET_XINDAPI_OWNER1, GET_XINDAPI_OWNER2])
    mocker.patch('ThreatConnect_v2.get_client', return_value=ThreatConnect())
    indicators = get_indicators('127.0.0.1', 'Address', 'Demisto Inc.,PhishTank', -1, -1)
    assert indicators == EXPECTED_INDOCATORS_OUTPUT


def test_create_context_debotscore_samilar_indicator(mocker):
    indicator = deepcopy(IP_INDICATOR)
    indicator.extend(deepcopy(IP_INDICATOR))
    indicator[0]['confidence'] = 0
    mocker.patch.object(demisto, 'params', return_value={"defaultOrg": "Demisto Inc.",
                                                         "freshness": 7, "rating": 0, "confidence": 50})

    # passing 2 ip indicators with the same address, one of them should gets the score 2 and the second one the score 3
    context, _ = create_context(indicator, True)
    # validate there is one indicator with the highest score - 3
    assert context
    assert len(context['DBotScore']) == 1
    assert context['DBotScore'][0]['Indicator'] == '88.88.88.88'
    assert context['DBotScore'][0]['Score'] == 3
    assert context['DBotScore'][0]['Reliability'] == 'B - Usually reliable'
