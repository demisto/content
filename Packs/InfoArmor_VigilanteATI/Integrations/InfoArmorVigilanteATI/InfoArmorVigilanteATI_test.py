"""
    Tests module for InfoArmor VigilanteATI integration
"""
import demistomock as demisto
import pytest


def test_query_infected_host_data_command(mocker):
    """
        Given:
            - A mock response for the 'query_infected_host_data' function.
        When:
            - Running the 'query_infected_host_data_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import query_infected_host_data_command
    mock_response = {
        'hosts': {
            'c&c': '1.1.1.1',
            'country': 'Asia',
            'domain': 'sancharnet.in',
            'ip': '1.1.1.2',
            'malware': 's_gamarue',
            'timestamp': '2018-12-01T12:57:22'
        },
        're_token': 'test_token'
    }

    expected_context = {
        'VigilanteATI.InfectedHost(val.ip == obj.ip)': {
            'c&c': '1.1.1.1',
            'country': 'Asia',
            'domain': 'sancharnet.in',
            'ip': '1.1.1.2',
            'malware': 's_gamarue',
            'timestamp': '2018-12-01T12:57:22'},
        'VigilanteATI.GetInfectedHostsToken(true==true)': 'test_token'}
    expected_readable_output = '| 1.1.1.1 | Asia | sancharnet.in | 1.1.1.2 | s_gamarue | 2018-12-01T12:57:22 |'

    mocker.patch('InfoArmorVigilanteATI.query_infected_host_data', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    query_infected_host_data_command()
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert expected_readable_output in readable_output


@pytest.mark.parametrize('mock_response, expected_readable_output, expected_context', [
    ({'results': {}}, 'No entries.', {}),
    ({'results': {'test_results': 'test'}}, 'test', {'test_results': 'test'})
])
def test_query_elasticsearch_command(mocker, mock_response, expected_readable_output, expected_context):
    """
        Given:
            - A mock response for the 'query_elasticsearch' function.
             1. query_elasticsearch returned No results
             2. query_elasticsearch returned results
        When:
            - Running the 'query_elasticsearch_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import query_elasticsearch_command

    mocker.patch('InfoArmorVigilanteATI.query_elasticsearch', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    query_elasticsearch_command()
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context.get('VigilanteATI.ElasticsearchResults')
    assert expected_readable_output in readable_output


@pytest.mark.parametrize('mock_response, expected_readable_output, expected_context', [
    ({'results': {}}, 'No entries.', {}),
    ({'results': {'test_results': 'test'}}, 'test', {'test_results': 'test'})
])
def test_search_command(mocker, mock_response, expected_readable_output, expected_context):
    """
        Given:
            - A mock response for the 'search' function.
        When:
            - Running the 'search_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import search_command

    mocker.patch('InfoArmorVigilanteATI.search', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    search_command()
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context.get('SearchResults')
    assert expected_readable_output in readable_output


def test_get_vulnerable_host_data_command(mocker):
    """
        Given:
            - A mock response for the 'get_vulnerable_host_data' function.
        When:
            - Running the 'get_vulnerable_host_data_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import get_vulnerable_host_data_command
    mock_response = {
        'hosts': [
            {
                "geoip": {
                    "postal_code": "11111",
                    "ip": "9.9.9.9",
                    "latitude": 35.994,
                    "longitude": -78.8986,
                    "dma_code": 560,
                    "country_name": "United States",
                    "location": {
                        "lat": 35.994,
                        "lon": -78.8986
                    },
                    "region_name": "North Carolina",
                    "region_code": "NC",
                    "continent_code": "NA",
                    "timezone": "America/New_York",
                    "country_code2": "US",
                    "country_code3": "US",
                    "city_name": "Durham"
                },
                "hostname": [
                    "dns.quad9.net"
                ],
                "ip": "9.9.9.9",
                "port": 53,
                "protocols": "udp",
                "timestamp": "2018-03-27 08:33:42",
                "type": "accessible port 53",
                "url": [
                  "quad9.net"
                ]
            }
        ]
    }

    expected_context = {'Hosts(val.ip === obj.ip)': [
        {
            'geoip': {
                'postal_code': '11111',
                'ip': '9.9.9.9',
                'latitude': 35.994,
                'longitude': -78.8986,
                'dma_code': 560,
                'country_name': 'United States',
                'location': {'lat': 35.994, 'lon': -78.8986},
                'region_name': 'North Carolina',
                'region_code': 'NC',
                'continent_code': 'NA',
                'timezone': 'America/New_York',
                'country_code2': 'US',
                'country_code3': 'US',
                'city_name': 'Durham'
            },
            'hostname': ['dns.quad9.net'],
            'ip': '9.9.9.9',
            'port': 53,
            'protocols': 'udp',
            'timestamp': '2018-03-27 08:33:42',
            'type': 'accessible port 53',
            'url': ['quad9.net']
        }
    ]
    }

    mocker.patch('InfoArmorVigilanteATI.get_vulnerable_host_data', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    get_vulnerable_host_data_command()
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert '9.9.9.9' in readable_output
    assert 'quad9.net' in readable_output


