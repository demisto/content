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
    mocker.patch("Whois.get_whois_raw", return_value=load_test_data('./test_data/whois_raw_response.json')['result'])
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
    mocker.patch("ipwhois.IPWhois.lookup_rdap", return_value={"raw": None})
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


def test_parse_raw_whois_empty_nameserver():
    with open('test_data/EU domains_empty_nameservers.text', 'r') as f:
        raw_data = f.read()
    result = Whois.parse_raw_whois([raw_data], [], never_query_handles=False, handle_server='whois.eu')
    assert result['nameservers'] == ['ns1060.ui-dns.biz']


@pytest.mark.parametrize('input, expected_result', [(['2024-05-09T00:00:00Z'], datetime.datetime(2024, 5, 9, 0, 0, 0)),
                                                    (['0000-00-00T00:00:00Z'], Whois.InvalidDateHandler(year=0, month=0, day=0)),
                                                    (['0000-01-02T11:22:33Z'], datetime.datetime(2000, 1, 2, 11, 22, 33)),
                                                    (['0000-00-02T00:00:00Z'], Whois.InvalidDateHandler(year=0, month=0, day=2))
                                                    ])
def test_parse_dates_invalid_time(input, expected_result):
    assert type(Whois.parse_dates(input)[0]) == type(expected_result)


@pytest.mark.parametrize('input, expected_result', [(['2024-05-09T00:00:00Z'], datetime.datetime(2024, 5, 9, 0, 0, 0)),
                                                    (['2024-20-09T00:00:00Z'], datetime.datetime(2024, 9, 20, 0, 0, 0))])
def test_swap_month_day_in_parse_dates(input, expected_result):
    assert Whois.parse_dates(input)[0] == expected_result


@pytest.mark.parametrize('updated_date, expected_res',
                         [({'updated_date': [Whois.InvalidDateHandler(0, 0, 0)]}, '0-0-0'),
                          ({'updated_date': [datetime.datetime(2025, 6, 8, 0, 0, 0)]}, '08-06-2025')])
def test_create_outputs_invalid_time(updated_date, expected_res):

    res = Whois.create_outputs(updated_date, 'test_domain', DBotScoreReliability.A)
    assert res[0]['Updated Date'] == expected_res


def test_parse_nic_contact():
    data = ["%%\n%% This is the AFNIC Whois server.\n%%\n%% complete date format : YYYY-MM-DDThh:mm:ssZ\n%% short date "
            "format    : DD/MM\n%% version              : FRNIC-2.5\n%%\n%% Rights restricted by copyright.\n%% See "
            "https://www.afnic.fr/en/products-and-services/services/whois/whois-special-notice/\n%%\n%% Use '-h' option"
            "to obtain more information about this service.\n%%\n%% [1111 REQUEST] >> google.fr\n%%\n%% RL "
            "Net [##########] - RL IP [#########.]\n%%\n\ndomain:      google.fr\nstatus:      ACTIVE\nhold:        "
            "NO\nholder-c:    GIHU100-FRNIC\nadmin-c:     GIHU101-FRNIC\ntech-c:      MI3669-FRNIC\nzone-c:      "
            "NFC1-FRNIC\nnsl-id:      NSL4386-FRNIC\nregistrar:   MARKMONITOR Inc.\nExpiry Date: 2022-12-30T17:16"
            ":48Z\ncreated:     2000-07-26T22:00:00Z\nlast-update: 2022-08-17T16:39:47Z\nsource:      FRNIC\n\nns-list:"
            "    NSL4386-FRNIC\nnserver:     ns1.google.com\nnserver:     ns2.google.com\nnserver:     ns3.google.com\n"
            "nserver:   ns4.google.com\nsource:      FRNIC\n\nregistrar:   MARKMONITOR Inc.\ntype:        Isp Option "
            "\naddress:     2150 S. Bonito Way, Suite 150\naddress:     ID 83642 MERIDIAN\ncountry:     US\n"
            "phone:       +1 208 389 5740\nfax-no:      +1 208 389 5771\ne-mail:      registry.admin@markmonitor.com\n"
            "website:    http://www.markmonitor.com\nanonymous:   NO\nregistered:  2002-01-10T12:00:00Z\nsource:      "
            "FRNIC\n\nnic-hdl:     GIHU100-FRNIC\ntype:        ORGANIZATION\ncontact:     Google Ireland Holdings "
            "Unlimited Company\naddress:     Google Ireland Holdings Unlimited Company\naddress:     70 Sir John "
            "Rogerson's Quay\naddress:     2 Dublin\naddress:     Dublin\ncountry:     IE\nphone:       "
            "+353.14361000\ne-mail:      dns-admin@google.com\nregistrar:   MARKMONITOR Inc.\nchanged:    "
            " 2018-03-02T18:03:31Z nic.fr\nanonymous:   NO\nobsoleted:   NO\neligstatus:  not identified\n"
            "reachstatus: not identified\nsource:      FRNIC\n\nnic-hdl:     GIHU101-FRNIC\ntype:        ORGANIZATION"
            "\ncontact:     Google Ireland Holdings Unlimited Company\naddress:     70 Sir John Rogerson's Quay\n"
            "address:     2 Dublin\ncountry:     IE\nphone:       +353.14361000\ne-mail:      dns-admin@google.com\n"
            "registrar:   MARKMONITOR Inc.\nchanged:     2018-03-02T17:52:06Z nic.fr\nanonymous:   NO\nobsoleted:  "
            " NO\neligstatus:  not identified\nreachmedia:  email\nreachstatus: ok\nreachsource: REGISTRAR\nreachdate: "
            "2018-03-02T17:52:06Z\nsource:      FRNIC\n\nnic-hdl:     MI3669-FRNIC\ntype:        ORGANIZATION\ncontact:"
            "MarkMonitor Inc.\naddress:     2150 S. Bonito Way, Suite 150\naddress:     83642 Meridian\naddress:     "
            "ID\ncountry:     US\nphone:       +1.2083895740\nfax-no:      +1.2083895771\ne-mail:      "
            "ccops@markmonitor"
            ".com\nregistrar:   MARKMONITOR Inc.\nchanged:     2021-10-05T15:17:57Z nic.fr\nanonymous:   NO\n"
            "obsoleted:   NO\neligstatus:  ok\neligsource:  REGISTRAR\neligdate:    2021-10-05T15:17:56Z\nreachmedia: "
            "email\nreachstatus: ok\nreachsource: REGISTRAR\nreachdate:   2021-10-05T15:17:56Z\nsource:      FRNIC\n\n"]

    res = Whois.parse_nic_contact(data)

    expected = [{'handle': 'GIHU100-FRNIC', 'type': 'ORGANIZATION', 'name': 'Google Ireland Holdings Unlimited Company',
                 'street1': 'Google Ireland Holdings Unlimited Company', 'street2': "70 Sir John Rogerson's Quay",
                 'street3': '2 Dublin', 'phone': None, 'fax': None, 'email': None,
                 'changedate': '2018-03-02T18:03:31Z nic.fr'},
                {'handle': 'GIHU101-FRNIC', 'type': 'ORGANIZATION', 'name': 'Google Ireland Holdings Unlimited Company',
                 'street1': "70 Sir John Rogerson's Quay", 'street2': '2 Dublin', 'street3': None, 'phone': None,
                 'fax': None, 'email': None, 'changedate': '2018-03-02T17:52:06Z nic.fr'},
                {'handle': 'MI3669-FRNIC', 'type': 'ORGANIZATION', 'name': 'MarkMonitor Inc.',
                 'street1': '2150 S. Bonito Way, Suite 150', 'street2': '83642 Meridian', 'street3': 'ID',
                 'phone': None, 'fax': None, 'email': None, 'changedate': '2021-10-05T15:17:57Z nic.fr'},
                {'handle': 'GIHU100-FRNIC', 'type': 'ORGANIZATION', 'name': 'Google Ireland Holdings Unlimited Company',
                 'street1': 'Google Ireland Holdings Unlimited Company', 'street2': "70 Sir John Rogerson's Quay",
                 'street3': '2 Dublin', 'street4': 'Dublin', 'country': 'IE', 'phone': '+353.14361000', 'fax': None,
                 'email': 'dns-admin@google.com', 'changedate': '2018-03-02T18:03:31Z nic.fr'},
                {'handle': 'GIHU101-FRNIC', 'type': 'ORGANIZATION', 'name': 'Google Ireland Holdings Unlimited Company',
                 'street1': "70 Sir John Rogerson's Quay", 'street2': '2 Dublin', 'street3': None, 'street4': None,
                 'country': 'IE', 'phone': '+353.14361000', 'fax': None, 'email': 'dns-admin@google.com',
                 'changedate': '2018-03-02T17:52:06Z nic.fr'},
                {'handle': 'MI3669-FRNIC', 'type': 'ORGANIZATION', 'name': 'MarkMonitor Inc.',
                 'street1': '2150 S. Bonito Way, Suite 150', 'street2': '83642 Meridian', 'street3': 'ID',
                 'street4': None, 'country': 'US', 'phone': '+1.2083895740', 'fax': '+1.2083895771',
                 'email': 'ccops@markmonitor.com', 'changedate': '2021-10-05T15:17:57Z nic.fr'}]
    assert res == expected


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


def test_get_raw_response_with_non_recursive_data_query(mocker):
    """
    Given:
        - A domain to query, non-recursive data query and a mock response which simulates a
          Whois server response that includes a name of a refer server.
    When:
        - running the Whois.get_whois_raw(domain, server) function

    Then:
        - Verify that the final response of the get_whois_raw() includes only the response of the first server which was
          queried, without the response of the refer server.
    """
    import socket
    from Whois import get_whois_raw

    def connect_mocker(curr_server):
        """
        This function is a mocker for the function socket.connect()
        """
        return None

    mock_response1 = "Domain Name: test.plus\n WHOIS Server: whois.test.com/\n"
    mock_response2 = "Domain Name: test_refer_server\n"

    mocker.patch.object(socket.socket, 'connect', side_effect=connect_mocker)
    mocker.patch('Whois.whois_request_get_response', side_effect=[mock_response1, mock_response2])

    domain = "test.plus"
    response = get_whois_raw(domain=domain, is_recursive=False)
    assert response == [mock_response1]
