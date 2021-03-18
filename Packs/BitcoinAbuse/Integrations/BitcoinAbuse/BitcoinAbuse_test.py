"""
Bitcoin Abuse Integration for Cortex XSOAR - Unit Tests file
"""

import io

import pytest

from BitcoinAbuse import BitcoinAbuseClient, bitcoin_abuse_report_address_command, bitcoin_abuse_get_indicators_command, \
    update_indicator_occurrences, READER_CONFIG
from CommonServerPython import DemistoException, Dict, json

SERVER_URL = 'https://www.bitcoinabuse.com/api/'
client = BitcoinAbuseClient(
    base_url=SERVER_URL,
    insecure=True,
    proxy=False,
    api_key='',
    initial_fetch_interval='',
    reader_config=READER_CONFIG,
    have_fetched_first_time=False
)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


bitcoin_responses = util_load_json('test_data/bitcoin_responses.json')
report_address_scenarios = util_load_json('test_data/report_command.json')
successful_bitcoin_report_command_output = 'Bitcoin address 12xfas41 by abuse bitcoin user ' \
                                           'blabla@blabla.net was reported to ' \
                                           'BitcoinAbuse service'
failure_bitcoin_report_command_output = 'bitcoin report address did not succeed: {}'.format(
    bitcoin_responses['failure']['response'])
get_indicators_scenarios = util_load_json('test_data/get_indicators_command.json')


@pytest.mark.parametrize('response, address_report, expected',
                         [(bitcoin_responses['success'],
                           report_address_scenarios['valid'],
                           successful_bitcoin_report_command_output
                           ),
                          (bitcoin_responses['success'],
                           report_address_scenarios['valid_other'],
                           successful_bitcoin_report_command_output)
                          ])
def test_report_address_successful_command(requests_mock, response: Dict, address_report: Dict, expected: str):
    """
        Given:
         - Bitcoin address to report.

        When:
         - Reporting valid address to Bitcoin Abuse service.

        Then:
         - When reporting to the API should return failure - the command fails and the correct output is given.
         - When reporting to the API should success - the command succeeds and the correct output is given.
        """
    requests_mock.post(
        'https://www.bitcoinabuse.com/api/reports/create',
        json=response
    )
    assert bitcoin_abuse_report_address_command(client, address_report).readable_output == expected


@pytest.mark.parametrize('address_report, expected',
                         [(report_address_scenarios['other_type_missing'],
                           'Bitcoin Abuse: abuse_type_other is mandatory when abuse type is other'),
                          (report_address_scenarios['unknown_type'],
                           'Bitcoin Abuse: invalid type of abuse, please insert a correct abuse type')
                          ])
def test_report_address_command_invalid_arguments(address_report: Dict, expected: str):
    """
       Given:
        - Invalid bitcoin address report.

       When:
        - Trying to report the address to Bitcoin Abuse service.

       Then:
        - Ensure the command throws an error.
        - Ensure the expected error with the expected error message is returned.
       """

    with pytest.raises(DemistoException, match=expected):
        bitcoin_abuse_report_address_command(client, address_report)


def test_failure_response_from_bitcoin_abuse(requests_mock):
    """
       Given:
        - bitcoin address report.

       When:
        - Trying to report the address to Bitcoin Abuse Api, and receiving a failure response from Bitcoin Abuse service.

       Then:
        - Ensure the command throws an error.
        - Ensure the expected error with the expected error message is returned.
       """
    requests_mock.post(
        'https://www.bitcoinabuse.com/api/reports/create',
        json=bitcoin_responses['failure']
    )
    with pytest.raises(DemistoException, match=failure_bitcoin_report_command_output):
        bitcoin_abuse_report_address_command(client, report_address_scenarios['valid'])


@pytest.mark.parametrize(
    'initial_fetch_interval, have_fetched_first_time, expected_url_suffix, expected_have_fetched_first_time',
    [('30 Days', False, {'download/30d'}, True),
     ('Forever', False, {'download/forever', 'download/30d'}, True),
     ('30 Days', True, {'download/1d'}, True)
     ])
def test_url_suffixes_builder(initial_fetch_interval, have_fetched_first_time, expected_url_suffix,
                              expected_have_fetched_first_time):
    """
    Given:
     - Request for url to fetch indicators.

    When:
     - Case a: First fetch time is 30 Days, fetching for the first time.
     - Case b: First fetch time is Forever, fetching for first time.
     - Case c: First fetch time is 30 Days, not fetching for first time.

    Then:
     - Case a: Ensure that the monthly download suffix is returned.
     - Case b: Ensure that the monthly and forever download suffix is returned.
     - Case c: Ensure that the daily download suffix is returned.
    """
    client.have_fetched_first_time = have_fetched_first_time
    client.initial_fetch_interval = initial_fetch_interval
    assert client.build_fetch_indicators_url_suffixes() == expected_url_suffix


def test_get_indicators_command(requests_mock):
    """
    Given:
        - params: Demisto params for get-indicators command.
        - args: Demisto args for get-indicators command.
    When:
        - Command `bitcoinabuse-get-indicators` is being called.
    Then:
        - Assert the CommandResults object returned is as expected.
    """
    requests_mock.get(
        'https://www.bitcoinabuse.com/api/download/30d?api_token=123',
        content=get_indicators_scenarios['mock_response'].encode('utf-8')
    )
    client.api_key = '123'
    client.have_fetched_first_time = False
    results = bitcoin_abuse_get_indicators_command(client, args={'limit': 1})
    assert results.raw_response == get_indicators_scenarios['expected']['raw_response']
    assert results.readable_output == get_indicators_scenarios['expected']['readable_output']


def test_update_indicator_occurrences():
    """
    Given:
        - indicator: Indicator fetched from Bitcoin Abuse service.
        - address_to_count_dict: Dict of Bitcoin addresses to count of occurrences.
    When:
        - Update_indicator_occurrences is being called.
    Then:
        - Assert that 'address_to_count_dict' is updated as expected.
    """
    first_ind = {'value': '12345abcde'}
    second_ind = {'value': '67890fghij'}
    address_to_count_dict = dict()
    update_indicator_occurrences(first_ind, address_to_count_dict)
    update_indicator_occurrences(first_ind, address_to_count_dict)
    update_indicator_occurrences(second_ind, address_to_count_dict)
    assert (address_to_count_dict.get('12345abcde')) == 2
    assert (address_to_count_dict.get('67890fghij', 0)) == 1
    assert (address_to_count_dict.get('12bxcas', 0)) == 0
