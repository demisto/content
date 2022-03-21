import datetime

import Whois
import demistomock as demisto
import pytest
import subprocess
import time
import tempfile
import sys

from CommonServerPython import DBotScoreReliability

import json

INTEGRATION_NAME = 'Whois'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def assert_results_ok():
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'ok'


def test_test_command(mocker):
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='test-module')
    Whois.main()
    assert_results_ok()


@pytest.mark.parametrize(
    'query,expected',
    [("app.paloaltonetwork.com", "paloaltonetwork.com"),
     ("test.this.google.co.il", "google.co.il"),
     ("app.XSOAR.test", "app.XSOAR.test")]
)
def test_get_domain_from_query(query, expected):
    from Whois import get_domain_from_query
    assert get_domain_from_query(query) == expected


def test_socks_proxy_fail(mocker):
    mocker.patch.object(demisto, 'params', return_value={'proxy_url': 'socks5://localhost:1180'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    with pytest.raises(SystemExit) as err:
        Whois.main()
    assert err.type == SystemExit
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert "Couldn't connect with the socket-server" in results[0]['Contents']


def test_socks_proxy(mocker, request):
    mocker.patch.object(demisto, 'params', return_value={'proxy_url': 'socks5h://localhost:9980'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    tmp = tempfile.TemporaryFile('w+')
    microsocks = './test_data/microsocks_darwin' if 'darwin' in sys.platform else './test_data/microsocks'
    process = subprocess.Popen([microsocks, "-p", "9980"], stderr=subprocess.STDOUT, stdout=tmp)

    def cleanup():
        process.kill()

    request.addfinalizer(cleanup)
    time.sleep(1)
    Whois.main()
    assert_results_ok()
    tmp.seek(0)
    assert 'connected to' in tmp.read()  # make sure we went through microsocks


TEST_QUERY_RESULT_INPUT = [
    (
        {'contacts': {'admin': None, 'billing': None, 'registrant': None, 'tech': None},
         'raw': ['NOT FOUND\n>>> Last update of WHOIS database: 2020-05-07T13:55:34Z <<<']},
        'rsqupuo.info',
        DBotScoreReliability.B,
        False
    ),
    (
        {'contacts': {'admin': None, 'billing': None, 'registrant': None, 'tech': None},
         'raw': ['No match for "BLABLA43213422342AS.COM".>>> Last update of whois database: 2020-05-20T08:39:17Z <<<']},
        "BLABLA43213422342AS.COM",
        DBotScoreReliability.B, False
    ),
    (
        {'status': ['clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)'],
         'updated_date': [datetime.datetime(2019, 9, 9, 8, 39, 4)],
         'contacts': {'admin': {'country': 'US', 'state': 'CA', 'name': 'Google LLC'},
                      'tech': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'},
                      'registrant': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'}, 'billing': None},
         'nameservers': ['ns1.google.com', 'ns4.google.com', 'ns3.google.com', 'ns2.google.com'],
         'expiration_date': [datetime.datetime(2028, 9, 13, 0, 0), datetime.datetime(2028, 9, 13, 0, 0)],
         'emails': ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'],
         'raw': ['Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN'],
         'creation_date': [datetime.datetime(1997, 9, 15, 0, 0)], 'id': ['2138514_DOMAIN_COM-VRSN']},
        'google.com',
        DBotScoreReliability.B,
        True
    ),
    (
        {'contacts': {'admin': None, 'billing': None, 'registrant': None, 'tech': None}},
        'rsqupuo.info',
        DBotScoreReliability.B,
        False
    ),
    (
        {'status': ['clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)'],
         'updated_date': [datetime.datetime(2019, 9, 9, 8, 39, 4)],
         'contacts': {'admin': {'country': 'US', 'state': 'CA', 'name': 'Google LLC'},
                      'tech': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'},
                      'registrant': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'}, 'billing': None},
         'nameservers': ['ns1.google.com', 'ns4.google.com', 'ns3.google.com', 'ns2.google.com'],
         'expiration_date': [datetime.datetime(2028, 9, 13, 0, 0), datetime.datetime(2028, 9, 13, 0, 0)],
         'emails': ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'],
         'raw': 'Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN',
         'creation_date': [datetime.datetime(1997, 9, 15, 0, 0)], 'id': ['2138514_DOMAIN_COM-VRSN']},
        'google.com',
        DBotScoreReliability.B,
        True
    ),
    (
        {'status': ['clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)'],
         'updated_date': [datetime.datetime(2019, 9, 9, 8, 39, 4)],
         'contacts': {'admin': {'country': 'US', 'state': 'CA', 'name': 'Google LLC'},
                      'tech': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'},
                      'registrant': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'}, 'billing': None},
         'nameservers': ['ns1.google.com', 'ns4.google.com', 'ns3.google.com', 'ns2.google.com'],
         'expiration_date': [datetime.datetime(2028, 9, 13, 0, 0), datetime.datetime(2028, 9, 13, 0, 0)],
         'emails': ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'],
         'raw': {'data': 'Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN'},
         'creation_date': [datetime.datetime(1997, 9, 15, 0, 0)], 'id': ['2138514_DOMAIN_COM-VRSN']},
        'google.com',
        DBotScoreReliability.B,
        True
    ),
    (
        {'contacts': {'admin': None, 'billing': None, 'registrant': None, 'tech': None},
         'raw': {'data': 'Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN'}},
        'rsqupuo.info',
        DBotScoreReliability.B,
        True
    ),
]


@pytest.mark.parametrize('whois_result, domain, reliability, expected', TEST_QUERY_RESULT_INPUT)
def test_query_result(whois_result, domain, reliability, expected):
    from Whois import create_outputs
    md, standard_ec, dbot_score = create_outputs(whois_result, domain, reliability)
    assert standard_ec['Whois']['QueryResult'] == expected
    assert dbot_score.get('DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && '
                          'val.Type == obj.Type)').get('Reliability') == 'B - Usually reliable'


def test_ip_command(mocker):
    """
    Given:
        - IP addresses

    When:
        - running the IP command

    Then:
        - Verify the result is as expected
        - Verify support list of IPs
    """
    from Whois import ip_command
    response = load_test_data('./test_data/ip_output.json')
    mocker.patch.object(Whois, 'get_whois_ip', return_value=response)
    result = ip_command(['4.4.4.4', '4.4.4.4'], DBotScoreReliability.B)
    assert len(result) == 2
    assert result[0].outputs_prefix == 'Whois.IP'
    assert result[0].outputs.get('query') == '4.4.4.4'
    assert result[0].indicator.to_context() == {
        'IP(val.Address && val.Address == obj.Address)': {
            'Organization': {'Name': u'LVLT-STATIC-4-4-16'},
            'FeedRelatedIndicators': [{'type': 'CIDR', 'description': None, 'value': u'4.4.0.0/16'}],
            'ASN': u'3356',
            'Address': '4.4.4.4'},
        'DBotScore('
        'val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)':
            {'Reliability': 'B - Usually reliable',
             'Vendor': 'Whois',
             'Indicator': '4.4.4.4',
             'Score': 0,
             'Type': 'ip'}}


def test_get_whois_ip_proxy_param(mocker):
    """
    Given:
        - proxy address

    When:
        - running the get_whois_ip function

    Then:
        - Verify the function doesn't fail due to type errors
    """
    from Whois import get_whois_ip
    mocker.patch.object(demisto, 'params', return_value={"proxy": True})
    result = get_whois_ip('1.1.1.1')
    assert result


def test_indian_tld():
    """
    Given:
        - indian domain

    When:
        - running the get_root_server function

    Then:
        - Verify the function returns the correct Whois server
    """
    from Whois import get_root_server
    result = get_root_server("google.in")
    assert result == "in.whois-servers.net"


def test_ph_tld():
    """
    Given:
        - A domain that its extension (tld) is '.ph'

    When:
        - running the get_root_server function

    Then:
        - Verify the function returns the correct Whois server
    """
    from Whois import get_root_server
    host = get_root_server("test.com.ph")
    assert host == "whois.iana.org"


def test_parse_raw_whois():
    with open('test_data/EU domains.text', 'r') as f:
        raw_data = f.read()
    result = Whois.parse_raw_whois([raw_data], [], never_query_handles=False, handle_server='whois.eu')
    assert result['registrar'] == ['IONOS SE']


def test_get_raw_response_with_a_refer_server_that_fails(mocker):
    """
    Background:
    get_whois_raw(domain, server) is a recursive function in the Whois integration which in charge of getting the raw
    response from the whois server for the query domain. In some cases the response from the whois server includes
    a name of another whois server, i.e a refer server, that is also used for querying the domain. If the raw response
    include a refer server, the get_whois_raw() function is recursively called this time with the refer server as the
    server argument, and the responses of the recursive calls are concatenating.

    This test simulates a case in which the call to get_whois_raw(domain, server) returns a response that includes a
    refer whois server but the call to the refer server fails with an exception. The purpose of the test is to verify
    that the final response of the get_whois_raw() includes the response of the first server which was queried although
    that the recursive call to the refer server failed.

    Given:
        - A Whois server, a domain to query and a mock response which simulates a Whois server response that includes
          a name of a refer server.
    When:
        - running the Whois.get_whois_raw(domain, server) function

    Then:
        - Verify that the final response of the get_whois_raw() includes the response of the first server which was
          queried although that the recursive call to the refer server failed.
    """
    import socket
    from Whois import get_whois_raw

    def connect_mocker(curr_server):
        """
        This function is a mocker for the function socket.connect() that simulates a case in which the first server of
        the test enables a socket connection, while the second server fails and raises an exception.
        """
        if curr_server[0] == "test_server":
            return None
        else:
            raise Exception

    mock_response = "Domain Name: test.plus\n WHOIS Server: whois.test.com/\n"

    mocker.patch.object(socket.socket, 'connect', side_effect=connect_mocker)
    mocker.patch('Whois.whois_request_get_response', return_value=mock_response)

    server = "test_server"
    domain = "test.plus"
    response = get_whois_raw(domain=domain, server=server)
    assert response == [mock_response]
