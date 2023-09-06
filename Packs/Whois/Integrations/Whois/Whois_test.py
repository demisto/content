import datetime
import pickle
import Whois
import demistomock as demisto
import pytest
import subprocess
import time
import tempfile
import sys
from typing import Any

from CommonServerPython import DBotScoreReliability, EntryType, ExecutionMetrics, ErrorTypes
from Whois import (
    ipwhois_exception_mapping,
    whois_exception_mapping,
    increment_metric,
    WhoisInvalidDomain,
    whois_command,
    domain_command,
    get_domain_from_query,
    ip_command,
    get_root_server
)
import ipwhois
import socket
from pytest_mock import MockerFixture

import json

INTEGRATION_NAME = 'Whois'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker: MockerFixture):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def assert_results_ok():
    assert demisto.results.call_count == 1  # type: ignore
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]  # type: ignore
    assert len(results) == 1
    assert results[0] == 'ok'


def test_test_command(mocker: MockerFixture):
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch("Whois.get_whois_raw", return_value=load_test_data('./test_data/whois_raw_response.json')['result'])
    Whois.main()
    assert_results_ok()


@pytest.mark.parametrize(
    'query,expected',
    [("app.paloaltonetwork.com", "paloaltonetwork.com"),
     ("test.this.google.co.il", "google.co.il"),
     ("app.XSOAR.test", "app.XSOAR.test")
     ]
)
def test_get_domain_from_query(query, expected):
    assert get_domain_from_query(query) == expected


def test_socks_proxy_fail(mocker: MockerFixture, capfd: pytest.CaptureFixture):
    mocker.patch.object(demisto, 'params', return_value={'proxy_url': 'socks5://localhost:1180'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')

    with capfd.disabled():
        with pytest.raises(SystemExit) as err:
            Whois.main()
        assert err.type == SystemExit
        assert demisto.results.call_count == 1  # type: ignore
        # call_args is tuple (args list, kwargs). we only need the first one
        results = demisto.results.call_args[0]  # type: ignore
        assert len(results) == 1
        assert "Exception thrown calling command" in results[0]['Contents']


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


def test_ip_command(mocker: MockerFixture):
    """
    Given:
        - IP addresses

    When:
        - running the IP command

    Then:
        - Verify the result is as expected
        - Verify support list of IPs
    """
    mocker.patch.object(ExecutionMetrics, 'is_supported', return_value=True)
    response = load_test_data('./test_data/ip_output.json')
    mocker.patch.object(Whois, 'get_whois_ip', return_value=response)
    mocker.patch.object(demisto, 'args', return_value={"ip": "4.4.4.4,8.8.8.8"})
    result = ip_command(
        reliability=DBotScoreReliability.B,
        should_error=False
    )
    assert len(result) == 3
    assert result[0].outputs_prefix == 'Whois.IP'
    assert result[0].outputs.get('query') == '4.4.4.4'  # type: ignore
    assert result[0].indicator.to_context() == {  # type: ignore
        'IP(val.Address && val.Address == obj.Address)': {
            'Organization': {'Name': 'LVLT-STATIC-4-4-16'},
            'FeedRelatedIndicators': [{'type': 'CIDR', 'description': None, 'value': '4.4.0.0/16'}],
            'ASN': '3356',
            'Address': '4.4.4.4'},
        'DBotScore('
        'val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)':
            {'Reliability': 'B - Usually reliable',
             'Vendor': 'Whois',
             'Indicator': '4.4.4.4',
             'Score': 0,
             'Type': 'ip'}}


def test_get_whois_ip_proxy_param(mocker: MockerFixture):
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
    with open('test_data/EU domains.text') as f:
        raw_data = f.read()
    result = Whois.parse_raw_whois([raw_data], [], never_query_handles=False, handle_server='whois.eu')
    assert result['registrar'] == ['IONOS SE']


def test_parse_raw_whois_empty_nameserver():
    with open('test_data/EU domains_empty_nameservers.text') as f:
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


@pytest.mark.parametrize('args, expected_res', [
    ({"query": "cnn.com", "is_recursive": "true", "verbose": "true", "should_error": "false"}, 2),
    ({"query": "cnn.com", "is_recursive": "true", "should_error": "false"}, 2)
])
def test_whois_with_verbose(args, expected_res, mocker: MockerFixture):
    """
    Given:
        - The args for the whois command with or without the verbose arg.
    When:
        - calling the whois command.
    Then:
        - validate that another context path is added for the raw-response if verbose arg is true.
    """
    mocker.patch.object(ExecutionMetrics, 'is_supported', return_value=True)
    mocker.patch.object(demisto, 'command', 'whois')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('Whois.get_domain_from_query', return_value='cnn.com')
    with open('test_data/cnn_pickled', 'rb') as f:
        get_whois_ret_value = pickle.load(f)  # guardrails-disable-line
    mocker.patch('Whois.get_whois', return_value=get_whois_ret_value)

    result = Whois.whois_command(
        reliability='B - Usually reliable'
    )
    assert len(result) == expected_res


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


def test_get_raw_response_with_non_recursive_data_query(mocker: MockerFixture):
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
        return

    mock_response1 = "Domain Name: test.plus\n WHOIS Server: whois.test.com/\n"
    mock_response2 = "Domain Name: test_refer_server\n"

    mocker.patch.object(socket.socket, 'connect', side_effect=connect_mocker)
    mocker.patch('Whois.whois_request_get_response', side_effect=[mock_response1, mock_response2])

    domain = "test.plus"
    response = get_whois_raw(domain=domain, is_recursive=False)
    assert response == [mock_response1]


@pytest.mark.parametrize('param_key, param_value, arg_key, arg_value, expected_res',
                         [
                             ("param_key", "param_value", "arg_key", "arg_value", "param_value"),
                             ("param_key", None, "arg_key", "arg_value", "arg_value"),
                             ("param_key", "param_value", "arg_key", None, "param_value"),
                             ("param_key", None, "arg_key", None, None),
                         ])
def test_get_param_or_arg(param_key, param_value, arg_key, arg_value, expected_res, mocker: MockerFixture):
    """
    Given:
        - Demisto params and args.
    When:
        - Getting a value.
    Then:
        - validate that param override an arg.
    """
    mocker.patch.object(demisto, 'args', return_value={arg_key: arg_value})
    mocker.patch.object(demisto, 'params', return_value={param_key: param_value})

    assert expected_res == Whois.get_param_or_arg(param_key, arg_key)


@pytest.mark.parametrize('args,execution_metrics_supported,expected_entries', [
    ({"query": "google.com"}, True, 2),
    ({"query": "127.0.0.1"}, True, 2),
    ({"query": "google.com,amazon.com"}, True, 3),
    ({"query": "google.com"}, False, 1)
])
def test_execution_metrics_appended(
    args: dict[str, str],
    execution_metrics_supported: bool,
    expected_entries: int,
    mocker: MockerFixture,
    capfd
):
    """
    Test whether the metrics entry is appended to the list of results according to the XSOAR version.
    API Execution Metrics is only supported for 6.8+.

    Given: Arguments passed to the `whois` command.

    When:
        - Case A: 1 valid domain is passed to v > 6.8.0.
        - Case B: 1 invalid domain is passed to v > 6.8.0.
        - Case C: 2 valid domains are passed to v > 6.8.0.
        - Case D: 1 valid domain is passed to v < 6.8.0.

    Then:
        - Case A: 2 entries are expected (1 for query, 1 for execution metrics).
        - Case B: 2 entries are expected (1 for query, 1 for execution metrics).
        - Case C: 3 entries are expected (2 for queries, 1 for execution metrics).
        - Case D: 1 entries are expected (1 for query, no execution metrics since it's not supported).

    """
    mocker.patch.object(demisto, 'command', 'whois')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(ExecutionMetrics, 'is_supported', return_value=execution_metrics_supported)
    mocker.patch.object(Whois, "get_whois_raw", return_value=load_test_data('./test_data/whois_raw_response.json')['result'])
    with capfd.disabled():
        results = whois_command(reliability=DBotScoreReliability.B)
        assert len(results) == expected_entries


@pytest.mark.parametrize('args,entry_type', [
    ({"query": "1.1.1.1", "is_recursive": "true", "with_error": True}, EntryType.ERROR),
    ({"query": "1.1.1.1", "is_recursive": "true", "with_error": False}, EntryType.WARNING)
])
def test_error_entry_type(
    args: dict[str, str],
    entry_type: EntryType,
    mocker: MockerFixture,
    capfd: pytest.CaptureFixture
):

    mocker.patch.object(demisto, 'command', 'whois')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(Whois, "get_whois_raw", return_value=load_test_data('./test_data/whois_raw_response.json')['result'])
    with capfd.disabled(), pytest.raises(Exception) as exc:
        results = Whois.whois_command(reliability=DBotScoreReliability.B)
        assert results[0].entry_type == entry_type
        assert "caught performing whois lookup with domain" in exc.value


@pytest.mark.parametrize(
    'em,mapping,exception_caught,expected',
    [
        (ExecutionMetrics(success=100, general_error=6), ipwhois_exception_mapping, ipwhois.exceptions.WhoisLookupError,
         (ErrorTypes.GENERAL_ERROR, 7)),
        (ExecutionMetrics(service_error=12), ipwhois_exception_mapping, ipwhois.exceptions.BlacklistError,
         (ErrorTypes.SERVICE_ERROR, 13)),
        (ExecutionMetrics(success=100, general_error=6), ipwhois_exception_mapping, ipwhois.exceptions.NetError,
         (ErrorTypes.CONNECTION_ERROR, 1)),
        (ExecutionMetrics(), ipwhois_exception_mapping, BaseException,
         (ErrorTypes.GENERAL_ERROR, 1)),
        (ExecutionMetrics(), whois_exception_mapping, BaseException,
         (ErrorTypes.GENERAL_ERROR, 1)),
        (ExecutionMetrics(success=100, general_error=6), whois_exception_mapping, socket.error,
         (ErrorTypes.CONNECTION_ERROR, 1)),
        (ExecutionMetrics(), whois_exception_mapping, TypeError,
         (ErrorTypes.GENERAL_ERROR, 1)),
        (ExecutionMetrics(), whois_exception_mapping, WhoisInvalidDomain,
         (ErrorTypes.GENERAL_ERROR, 1)),
    ]
)
def test_exception_type_to_metrics(
    em: ExecutionMetrics,
    mapping: dict[type, str],
    exception_caught: type,
    expected: tuple[str, int]
):
    """
    Test whether the caught `ipwhois.exception` type results in the expected API execution metric being incremented.

    Given: The exception type and the expected metric.

    When:
        - Case A:
            - ExecutionMetrics with success and general error set.
            - `ipwhois` exception mapping provided.
            - `WhoisLookupError` exception thrown.
        - Case B:
            - ExecutionMetrics with service error set.
            - `ipwhois` exception mapping provided.
            - `BlacklistError` exception thrown.
        - Case C:
            - ExecutionMetrics with success and general error set.
            - `ipwhois` exception mapping provided.
            - `NetError` exception thrown.
        - Case D:
            - Empty ExecutionMetrics.
            - `ipwhois` exception mapping provided.
            - `BaseException` thrown.
        - Case E:
            - Empty ExecutionMetrics.
            - `whois` exception mapping provided.
            - `BaseException` thrown.
        - Case F:
            - ExecutionMetrics with success and general error set.
            - `whois` exception mapping provided.
            - `socket.error|OSError` thrown.
       - Case G:
            - Empty ExecutionMetrics.
            - `whois` exception mapping provided.
            - `TypeError` thrown.
        - Case H:
            - Empty ExecutionMetrics.
            - `whois` exception mapping provided.
            - `WhoisInvalidDomain` thrown.


    Then:
        - Case A: ErrorTypes.GENERAL_ERROR is incremented and equal to 7.
        - Case B: ErrorTypes.SERVICE_ERROR is incremented and equal to 13.
        - Case C: ErrorTypes.CONNECTION_ERROR is incremented and equal to 1.
        - Cases D/E/G/H: ErrorTypes.GENERAL_ERROR is incremented and equal to 1.
        - Case F: ErrorTypes.CONNECTION_ERROR is incremented and equal to 1.

    """
    actual: ExecutionMetrics = increment_metric(
        execution_metrics=em,
        mapping=mapping,
        caught_exception=exception_caught
    )

    for metrics in actual.metrics.execution_metrics:  # type: ignore
        if (metrics['Type'], metrics['APICallsCount']) == expected:
            actual_type = metrics['Type']
            actual_count = metrics['APICallsCount']
            break

    assert actual_type == expected[0]
    assert actual_count == expected[1]


@pytest.mark.parametrize("domain,expected", [
    ("google.com", "whois.verisign-grs.com")
])
def test_get_root_server(domain: str, expected: str):
    """
    Test to get the root server from the domain. The root server resolution is handled inside
    ``Whois`` by `tlds` and `dble_ext` dictionaries.

    Given: a domain.

    When: The domain is google.com.

    Then: The root server is whois.verisign-grs.com.

    """
    assert expected == get_root_server(domain)


@pytest.mark.parametrize("domain", [
    ("com"),
    ("1.1.1.1"),
])
def test_get_root_server_invalid_domain(domain: str, capfd: pytest.CaptureFixture):
    """
    Test to get the root server from the domain when an invalid domain is supplied.

    Given: a domain.

    When:
        - Case A: An `str` that has no '.' in it.
        - Case B: An IP address.

    Then:
        - `WhoisInvalidDomain` expected

    """
    with capfd.disabled(), pytest.raises(WhoisInvalidDomain):
        get_root_server(domain)


@pytest.mark.parametrize('args, expected_res', [
    ({"domain": "cnn.com", "is_recursive": "true", "verbose": "true", "should_error": "false"}, 2),
    ({"domain": "cnn.com", "is_recursive": "true", "should_error": "false"}, 2)
])
def test_domain_command(args: dict[str, Any], expected_res, mocker: MockerFixture):
    """
    Given:
        - The args for the domain command.
    When:
        - calling the whois command.
    Then:
        - validate that another context path is added for the raw-response if verbose arg is true.
    """
    mocker.patch.object(ExecutionMetrics, 'is_supported', return_value=True)
    mocker.patch.object(demisto, 'command', 'domain')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch('Whois.get_domain_from_query', return_value='cnn.com')
    with open('test_data/cnn_pickled', 'rb') as f:
        get_whois_ret_value = pickle.load(f)  # guardrails-disable-line
    mocker.patch('Whois.get_whois', return_value=get_whois_ret_value)

    result = domain_command(
        reliability='B - Usually reliable'
    )
    assert len(result) == expected_res
