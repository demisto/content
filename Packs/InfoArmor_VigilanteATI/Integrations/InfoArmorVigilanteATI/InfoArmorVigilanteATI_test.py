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

    query_infected_host_data_command({})
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

    query_elasticsearch_command({})
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

    search_command({})
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
                "url": ["quad9.net"]
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

    get_vulnerable_host_data_command({})
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert '9.9.9.9' in readable_output
    assert 'quad9.net' in readable_output


def test_search_leaks_command(mocker):
    """
        Given:
            - A mock response for the 'search_leaks' function.
        When:
            - Running the 'search_leaks_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import search_leaks_command
    mock_response = {
        'leaks': [
            {
                "leak_id": "aa66573902ed4f4bfb2ae08ebac390c3",
                "password_type": None,
                "description": "part of solenya collection of dumps www.shareapple.com.txt.",
                "source_refs": [],
                "attack_method": "",
                "title": "www.shareapple.com.txt solenya collection leak",
                "import_date": "2018-03-17 00:00:00",
                "breach_date": "",
                "targets": [
                    "www.shareapple.com.txt"
                ],
                "attackers": [],
                "num_entries": 5669,
                "score": 30,
                "num_domains_affected": 5669,
                "leak_type": "Database dump",
                "target_industries": "",
                "password_hash": "",
                "leak_date": "2017-01-01 00:00:00",
                "media_refs": []
            }
        ],
        'token': 'test_token'
    }

    expected_context = {
        'VigilanteATI.LeakInfoToken(true==true)': 'test_token',
        'VigilanteATI.Leaks(val.leak_id === obj.leak_id)': [
            {
                'leak_id': 'aa66573902ed4f4bfb2ae08ebac390c3',
                'password_type': None,
                'description': 'part of solenya collection of dumps www.shareapple.com.txt.',
                'source_refs': [],
                'attack_method': '',
                'title': 'www.shareapple.com.txt solenya collection leak',
                'import_date': '2018-03-17 00:00:00',
                'breach_date': '',
                'targets': ['www.shareapple.com.txt'],
                'attackers': [],
                'num_entries': 5669,
                'score': 30,
                'num_domains_affected': 5669,
                'leak_type': 'Database dump',
                'target_industries': '',
                'password_hash': '',
                'leak_date': '2017-01-01 00:00:00',
                'media_refs': []
            }
        ]
    }

    mocker.patch('InfoArmorVigilanteATI.search_leaks', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    search_leaks_command({})
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert 'aa66573902ed4f4bfb2ae08ebac390c3' in readable_output
    assert 'www.shareapple.com.txt' in readable_output


def test_get_leak_command(mocker):
    """
        Given:
            - A mock response for the 'get_leak' function.
        When:
            - Running the 'get_leak_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import get_leak_command
    mock_response = {
        'accounts': [
            {
                "leak_id": "aa66573902ed4f4bfb2ae08ebac390c3",
                "domain": "hotmail.com",
                "password": "dummypassword",
                "plain": "dummy1@hotmail.com",
                "type_id": 1
            }
        ],
        'token': 'test_token'
    }

    expected_context = {
        'VigilanteATI.Leaks(val.leak_id === obj.leak_id)': {
            'leak_id': 'aa66573902ed4f4bfb2ae08ebac390c3',
            'accounts': [
                {
                    'leak_id': 'aa66573902ed4f4bfb2ae08ebac390c3',
                    'domain': 'hotmail.com',
                    'password': 'dummypassword',
                    'type_id': 1,
                    'email': 'dummy1@hotmail.com'
                }
            ]
        },
        'VigilanteATI.LeakAccountsToken(true==true)': 'test_token'
    }
    expected_readable_output = ('### Accounts related to leak aa66573902ed4f4bfb2ae08ebac390c3\n|email|domain|'
                                'password|type_id|\n|---|---|---|---|\n| dummy1@hotmail.com | hotmail.com |'
                                ' dummypassword | 1 |\n')

    mocker.patch('InfoArmorVigilanteATI.get_leak', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    get_leak_command({'leak_id': 'aa66573902ed4f4bfb2ae08ebac390c3'})
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert expected_readable_output in readable_output


def test_query_ecrime_intelligence_database_command(mocker):
    """
        Given:
            - A mock response for the 'query_ecrime_intelligence_database' function.
        When:
            - Running the 'query_ecrime_intelligence_database_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import query_ecrime_intelligence_database_command
    mock_response = {
        'posts': [
            {
                "author": "fb_official2",
                "date": "2018-12-10",
                "forum": "bcbm4y7yusdxthg3.onion",
                "post": b'PG1hcms+TkVURkxJWDwvbWFyaz4gVE9EQVkKCkFDQ09VTlQ6ICBleGFtcGxlQGdtYWlsLmNvbQpQQVNTOiBUSEVkb25ib'
                        b'25l',
                "thread_url": "http://bcbm4y7yusdxthg3.onion/showthread.php?t=28120",
                "title": b'RlJFRSA8bWFyaz5ORVRGTElYPC9tYXJrPiBBQ0NPVU5UIERBSUxZLi4='
            }
        ],
        're_token': 'test_token'
    }

    expected_context = {
        'VigilanteATI.ECrimePosts': [
            {
                'author': 'fb_official2',
                'date': '2018-12-10',
                'forum': 'bcbm4y7yusdxthg3.onion',
                'post': '<mark>NETFLIX</mark> TODAY\n\nACCOUNT:  example@gmail.com\nPASS: THEdonbone',
                'thread_url': 'http://bcbm4y7yusdxthg3.onion/showthread.php?t=28120',
                'title': 'FREE <mark>NETFLIX</mark> ACCOUNT DAILY..'
            }
        ],
        'VigilanteATI.ECrimeQueryToken(true==true)': 'test_token'
    }

    mocker.patch('InfoArmorVigilanteATI.query_ecrime_intelligence_database', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    query_ecrime_intelligence_database_command({})
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert 'FREE <mark>NETFLIX</mark> ACCOUNT DAILY..' in readable_output
    assert '2018-12-10' in readable_output


def test_query_accounts_command(mocker):
    """
        Given:
            - A mock response for the 'query_accounts' function.
        When:
            - Running the 'query_accounts_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import query_accounts_command
    mock_response = {
        'results': [
            {
                "plain": "16@gmail.com",
                "leak_id": "792b3740220e53017d3d0c16b87b5750",
                "password": "6FQS8sui06wUvI1voAEupvgMip30C+WqGjqQpIh/oC4YJSD2yPv8xpNVgCULgkGPQs6SYcnSrcIT4+qFB0mu/Q==",
                "source_type": 1,
                "type_id": 1
            }
        ]
    }

    expected_context = {
        'VigilanteATI.Account(val.email == obj.email && val.password == obj.password && val.leak_id && obj.leak_id)': [
            {'leak_id': '792b3740220e53017d3d0c16b87b5750',
             'password': '6FQS8sui06wUvI1voAEupvgMip30C+WqGjqQpIh/oC4YJSD2yPv8xpNVgCULgkGPQs6SYcnSrcIT4+qFB0mu/Q==',
             'source_type': 1,
             'type_id': 1,
             'email': '16@gmail.com'
             }
        ]
    }

    expected_readable_output = ('### Leaks related to email accounts \n\n|leak_id|email|password|source_type|type_id|'
                                '\n|---|---|---|---|---|\n| 792b3740220e53017d3d0c16b87b5750 | 16@gmail.com |'
                                ' 6FQS8sui06wUvI1voAEupvgMip30C+WqGjqQpIh/oC4YJSD2yPv8xpNVgCULgkGPQs6SYcnSrcIT4+qFB0mu'
                                '/Q== | 1 | 1 |\n')

    mocker.patch('InfoArmorVigilanteATI.query_accounts', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    query_accounts_command({})
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert expected_readable_output in readable_output


def test_query_domains_command(mocker):
    """
        Given:
            - A mock response for the 'query_domains' function.
        When:
            - Running the 'query_domains_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import query_domains_command
    mock_response = {
        'accounts': [
            {
                "plain": "foo4@yahoo.com",
                "leak_id": "e1c5019aaf21ca585cb9f630d95e2301",
                "password": "//dummypass==",
                "source_type": 1,
                "type_id": 1
            }
        ],
        'domain_identifier': 'domain_id_test',
        'token': 'test_token'
    }

    expected_context = {
        'VigilanteATI.Domain(val.domain == obj.domain)': {
            'domain': 'domain_id_test',
            'accounts': [
                {
                    'leak_id': 'e1c5019aaf21ca585cb9f630d95e2301',
                    'password': '//dummypass==',
                    'source_type': 1,
                    'type_id': 1,
                    'email': 'foo4@yahoo.com'
                }
            ]
        },
        'DomainQueryToken': 'test_token'}

    expected_readable_output = ('### Accounts related to domain: None\n|leak_id|email|password|source_type|type_id|'
                                '\n|---|---|---|---|---|\n| e1c5019aaf21ca585cb9f630d95e2301 | foo4@yahoo.com |'
                                ' //dummypass== | 1 | 1 |\n')

    mocker.patch('InfoArmorVigilanteATI.query_domains', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    query_domains_command({})
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert expected_readable_output in readable_output


def test_watchlist_add_accounts_command(mocker):
    """
        Given:
            - A mock response for the 'watchlist_add_accounts' function.
        When:
            - Running the 'watchlist_add_accounts_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import watchlist_add_accounts_command
    mock_response = {
        'added': ['1', '2'],
        'already on watchlist': ['3', '4'],
        'invalid': ['5', '6']
    }

    expected_content = mock_response

    expected_readable_output = '### Added: 1,2\n\n### Already on watchlist: 3,4### Invalid: 5,6\n'

    mocker.patch('InfoArmorVigilanteATI.watchlist_add_accounts', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    watchlist_add_accounts_command({})
    results = demisto.results
    content = results.call_args[0][0].get('Contents')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_content == content
    assert expected_readable_output in readable_output


def test_watchlist_remove_accounts_command(mocker):
    """
        Given:
            - A mock response for the 'watchlist_remove_accounts' function.
        When:
            - Running the 'watchlist_remove_accounts_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import watchlist_remove_accounts_command
    mock_response = {
        'removed': ['1', '2'],
        'not on watchlist': ['3', '4']
    }

    expected_content = mock_response

    expected_readable_output = '### Removed: 1,2### Not on watchlist: 3,4'

    mocker.patch('InfoArmorVigilanteATI.watchlist_remove_accounts', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    watchlist_remove_accounts_command({})
    results = demisto.results
    content = results.call_args[0][0].get('Contents')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_content == content
    assert expected_readable_output in readable_output


def test_get_watchlist_accounts_command(mocker):
    """
        Given:
            - A mock response for the 'get_watchlist_accounts' function.
        When:
            - Running the 'get_watchlist_accounts_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import get_watchlist_accounts_command
    mock_response = {
        'identifiers': {'id1': '111', 'id2': '222', 'id3': '333'},
        'token': 'test_token'
    }

    expected_context = {
        'VigilanteATI.WatchlistQueryToken(true==true)': 'test_token',
        'VigilanteATI.Watchlist(val.identifier == obj.identifier)': {
            'id1': '111',
            'id2': '222',
            'id3': '333'
        }
    }

    expected_readable_output = '### Watchlist\n|id1|id2|id3|\n|---|---|---|\n| 111 | 222 | 333 |\n'

    mocker.patch('InfoArmorVigilanteATI.get_watchlist_accounts', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    get_watchlist_accounts_command({})
    results = demisto.results
    context = results.call_args[0][0].get('EntryContext')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_context == context
    assert expected_readable_output in readable_output


def test_usage_info_command(mocker):
    """
        Given:
            - A mock response for the 'usage_info' function.
        When:
            - Running the 'usage_info_command'.
        Then:
            - Verify that the command's context and readable output are as expected.
    """
    from InfoArmorVigilanteATI import usage_info_command
    mock_response = {
        'num_queries_left': 1,
        'num_queries_allotted': 2
    }

    expected_content = [{'Number of queries allowed': 2, 'Number of queries left': 1}]

    expected_readable_output = ('### Usage Info\n|Number of queries allowed|Number of queries left|\n|---|---|\n|'
                                ' 2 | 1 |\n')

    mocker.patch('InfoArmorVigilanteATI.usage_info', return_value=mock_response)
    mocker.patch.object(demisto, 'results')

    usage_info_command()
    results = demisto.results
    content = results.call_args[0][0].get('Contents')
    readable_output = results.call_args[0][0].get('HumanReadable')

    assert expected_content == content
    assert expected_readable_output in readable_output


@pytest.mark.parametrize('params_to_test, expected_params', [
    ({'a': 'a', 'b': None, 'c': 'c'}, {'a': 'a', 'c': 'c'}),
    ({'b': None}, {}),
    ({'a': 'a', 'b': 'b', 'c': 'c'}, {'a': 'a', 'b': 'b', 'c': 'c'})
])
def test_remove_none_params(params_to_test, expected_params):
    """
        Given:
            - A parameters dictionary:
                1. with two valid values, and one None value.
                2. with only one pair of key and value, where the value is none.
                3. with 3 pairs of key and value, without None values.
        When:
            - Running the 'remove_none_params' function.
        Then:
            - Verify that the output params dictionary doesn't include key: value pairs of None values.
    """
    from InfoArmorVigilanteATI import remove_none_params

    params_without_none_values = remove_none_params(params_to_test)

    assert params_without_none_values == expected_params
