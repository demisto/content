from ThreatConnect_v2 import calculate_freshness_time, create_context
from freezegun import freeze_time
import pytest

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
    'webLink': 'https://sandbox.threatconnect.com/auth/indicators/details/url.xhtml?orgid=113283093&owner=Demisto+Inc.',
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
            'Confidence': 0
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
        'Confidence': 0
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
    'webLink': 'https://sandbox.threatconnect.com/auth/indicators/details/address.xhtml?address=88.88.88.88&owner=Demisto+Inc.',
    'ip': '88.88.88.88',
    'type': 'Address'
}]
IP_CONTEXT = (
    {
        'IP(val.Address && val.Address == obj.Address)': [{
            'Malicious': {
                'Vendor': 'ThreatConnect',
                'Description': ''
            },
            'Address': '88.88.88.88'
        }],
        'TC.Indicator(val.ID && val.ID === obj.ID)': [{
            'ID': 113286420,
            'Name': '88.88.88.88',
            'Type': 'Address',
            'Owner': 'Demisto Inc.',
            'CreateDate': '2020-05-14T13:16:32Z',
            'LastModified': '2020-05-14T13:16:32Z',
            'Rating': 2,
            'Confidence': 50
        }]
    },
    [{
        'ID': 113286420,
        'Name': '88.88.88.88',
        'Type': 'Address',
        'Owner': 'Demisto Inc.',
        'CreateDate': '2020-05-14T13:16:32Z',
        'LastModified': '2020-05-14T13:16:32Z',
        'Rating': 2,
        'Confidence': 50
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
    'webLink': 'https://sandbox.threatconnect.com/auth/indicators/details/host.xhtml?host=domain.info&owner=Demisto+Inc.',
    'hostName': 'domain.info',
    'dnsActive': 'false',
    'whoisActive': 'false',
    'type': 'Host'
}]
DOMAIN_CONTEXT = (
    {
        'Domain(val.Name && val.Name == obj.Name)': [
            {
                'Malicious': {
                    'Vendor': 'ThreatConnect',
                    'Description': ''
                },
                'Name': 'domain.info'
            }
        ],
        'TC.Indicator(val.ID && val.ID === obj.ID)': [
            {
                'ID': 112618314,
                'Name': 'domain.info',
                'Type': 'Host',
                'Owner': 'Demisto Inc.',
                'CreateDate': '2020-04-23T14:42:21Z',
                'LastModified': '2020-05-14T13:24:35Z',
                'Rating': 0,
                'Confidence': 0,
                'Active': 'false'
            }
        ]
    },
    [{
        'ID': 112618314,
        'Name': 'domain.info',
        'Type': 'Host',
        'Owner': 'Demisto Inc.',
        'CreateDate': '2020-04-23T14:42:21Z',
        'LastModified': '2020-05-14T13:24:35Z',
        'Rating': 0,
        'Confidence': 0,
        'Active': 'false'
    }]
)
FILE_INDICATOR = [{
    'id': 113286426,
    'owner': 'Demisto Inc.',
    'dateAdded': '2020-05-14T13:22:49Z',
    'lastModified': '2020-05-14T13:22:49Z',
    'rating': 4.0,
    'confidence': 20,
    'threatAssessRating': 4.0,
    'threatAssessConfidence': 20.0,
    'webLink': 'https://sandbox.threatconnect.com/auth/indicators/details/file.xhtml?file=49456A' +     # noqa: W504
               '40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229&owner=Demisto+Inc.',
    'sha256': '49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229',
    'type': 'File'
}]
FILE_CONTEXT = (
    {
        'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && ' +    # noqa: W504
        'val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && ' +     # noqa: W504
        'val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': [{
            'Malicious': {
                'Vendor': 'ThreatConnect',
                'Description': ''
            },
            'SHA256': '49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229'
        }],
        'TC.Indicator(val.ID && val.ID === obj.ID)': [{
            'ID': 113286426,
            'Type': 'File',
            'Owner': 'Demisto Inc.',
            'CreateDate': '2020-05-14T13:22:49Z',
            'LastModified': '2020-05-14T13:22:49Z',
            'Rating': 4,
            'Confidence': 20,
            'File': {
                'SHA256': '49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229'
            }
        }]
    },
    [{
        'ID': 113286426,
        'Type': 'File',
        'Owner': 'Demisto Inc.',
        'CreateDate': '2020-05-14T13:22:49Z',
        'LastModified': '2020-05-14T13:22:49Z',
        'Rating': 4,
        'Confidence': 20,
        'File': {
            'SHA256': '49456A40536940A1304A506D7278F6B19FC7F71BE545810F7CAFEAA35A086229'
        }
    }]
)

data_test_create_context = [
    ({}, ({}, [])),
    (DOMAIN_INDICATOR, DOMAIN_CONTEXT),
    (IP_INDICATOR, IP_CONTEXT),
    (URL_INDICATOR, URL_CONTEXT),
    (FILE_INDICATOR, FILE_CONTEXT),
]


@ pytest.mark.parametrize('indicators, expected_output', data_test_create_context)
def test_create_context(indicators, expected_output):
    output = create_context(indicators)
    assert output == expected_output, f'expected_output({indicators})\n\treturns: {output}\n\tinstead: {expected_output}'
