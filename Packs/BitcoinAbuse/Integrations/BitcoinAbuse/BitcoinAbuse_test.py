"""
Bitcoin Abuse Integration for Cortex XSOAR - Unit Tests file
"""

import io

import pytest

from BitcoinAbuse import *

SERVER_URL = 'https://www.bitcoinabuse.com/api/'

client = BitcoinAbuseClient(
    api_key='',
    verify=False,
    proxy=False
)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


bitcoin_responses = util_load_json('test_data/bitcoin_responses.json')
report_address_scenarios = util_load_json('test_data/report_command.json')
successful_bitcoin_report_command_output = 'Bitcoin address 12xfas41 by abuse bitcoin user ' \
                                           'blabla@blabla.net was reported to ' \
                                           'BitcoinAbuse API'
failure_bitcoin_report_command_output = 'bitcoin report address did not succeed: response: {}'.format(
    bitcoin_responses['failure'])


@pytest.mark.parametrize('response, address_report, expected',
                         [(bitcoin_responses['success'],
                           report_address_scenarios['valid'],
                           successful_bitcoin_report_command_output
                           ),
                          (bitcoin_responses['failure'],
                           report_address_scenarios['valid'],
                           failure_bitcoin_report_command_output),
                          (bitcoin_responses['success'],
                           report_address_scenarios['valid_other'],
                           successful_bitcoin_report_command_output)
                          ])
def test_report_address_command(requests_mock, response: Dict, address_report: Dict, expected: str):
    """
        Given:
         - Bitcoin address to report

        When:
         - Reporting the address to Bitcoin Abuse Api

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
def test_report_address_command_error_thrown(address_report: Dict, expected: str):
    """
       Given:
        - Illegal bitcoin address report

       When:
        - Trying to report the address to Bitcoin Abuse Api

       Then:
        - Ensure the command throws an error
        - Ensure the expected error with the expected error message is returned
       """

    try:
        report_address_command(client, address_report)
        raise AssertionError('report address command should fail when type is other and no abuse_type_other was given')
    except DemistoException as error:
        assert error.message == expected


@pytest.mark.parametrize('have_fetched_first_time, feed_interval_suffix_url, expected',
                         [(False, '30d', 'download/30d'),
                          (True, '30d', 'download/1d')])
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
    assert build_fetch_indicators_url_suffix(have_fetched_first_time, feed_interval_suffix_url) == expected
