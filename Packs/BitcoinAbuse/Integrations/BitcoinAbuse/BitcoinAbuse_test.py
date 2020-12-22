"""
Bitcoin Abuse Integration for Cortex XSOAR - Unit Tests file
"""

import io

import pytest

from BitcoinAbuse import *

SERVER_URL = 'https://www.bitcoinabuse.com/api/'

client = BitcoinAbuseClient(
    api_key='',
    params={
        'verify': False,
        'proxy': False,
        'url': SERVER_URL
    }
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
         - Bitcoin address to report

        When:
         - Reporting valid address to Bitcoin Abuse Api

        Then:
         - When reporting to the API should return failure - the command fails and the correct output is given
         - When reporting to the API should success - the command succeeds and the correct output is given
        """
    requests_mock.post(
        'https://www.bitcoinabuse.com/api/reports/create',
        json=response
    )
    assert report_address_command(client, address_report).readable_output == expected


@pytest.mark.parametrize('address_report, expected',
                         [(report_address_scenarios['other_type_missing'],
                           'Bitcoin Abuse: abuse_type_other is mandatory when abuse type is other'),
                          (report_address_scenarios['unknown_type'],
                           'Bitcoin Abuse: invalid type of abuse, please insert a correct abuse type')
                          ])
def test_report_address_command_invalid_arguments(address_report: Dict, expected: str):
    """
       Given:
        - Invalid bitcoin address report

       When:
        - Trying to report the address to Bitcoin Abuse Api

       Then:
        - Ensure the command throws an error
        - Ensure the expected error with the expected error message is returned
       """

    with pytest.raises(DemistoException, match=expected):
        report_address_command(client, address_report)


def test_failure_response_from_bitcoin_abuse(requests_mock):
    """
       Given:
        - bitcoin address report

       When:
        - Trying to report the address to Bitcoin Abuse Api, and receiving a failure response from Bitcoin Abuse service

       Then:
        - Ensure the command throws an error
        - Ensure the expected error with the expected error message is returned
       """
    requests_mock.post(
        'https://www.bitcoinabuse.com/api/reports/create',
        json=bitcoin_responses['failure']
    )
    with pytest.raises(DemistoException, match=failure_bitcoin_report_command_output):
        report_address_command(client, report_address_scenarios['valid'])


@pytest.mark.parametrize('have_fetched_first_time, feed_interval_suffix_url, expected',
                         [(False, '30d', {'download/30d'}),
                          (False, 'forever', {'download/forever', 'download/30d'}),
                          (True, '30d', {'download/1d'})])
def test_url_fetch(have_fetched_first_time: bool, feed_interval_suffix_url: str, expected):
    """
    Given:
     - Request for url to fetch indicators

    When:
     - Trying to fetch indicators

    Then:
     - Ensure on first fetch the feed_interval_suffix_url is returned
     - Ensure on any other fetch the daily download suffix is returned
    """
    assert build_fetch_indicators_url_suffixes(have_fetched_first_time, feed_interval_suffix_url) == expected
