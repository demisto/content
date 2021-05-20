"""Imports"""
import json
import pytest
import requests
import demistomock as demisto
from netaddr import IPAddress
from pathlib import Path
import os
from pytest_mock import MockerFixture
from time import sleep
import subprocess
from typing import Optional

SSL_TEST_KEY = '''-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDd5FcvCKgtXjkY
aiDdqpFAYKw6WxNEpZIGjzD9KhEqr7OZjpPoLeyGh1U6faAcN6XpkQugFA/2Gq+Z
j/pe1abiTCbctdE978FYVjXxbEEAtEn4x28s/bKah/xjjw+RjUyQB9DsioFkV1eN
9iJh5eOOIOjTDMBt7SxY1HivC0HjUKjCaMjdH2WxGu4na9phPOa7zixlgLqZGC8g
E1Ati5j3nOEOlmrNIf1Z/4zdJzEaMprBCymfEvrgMC7ibG9AokDcAj6Sl4xgvTRp
tTczCbUxF1jsnNNbuLyq/RuQ85SWB3mrRKT4OgPtz/ga3sm4l7Uq/YN71Gr/Lxaq
bkwWVMd/AgMBAAECggEBAKnMfacBYejtzJVRSXs3dlWkZMd3QGRsqzUXyG5DDcXz
lGVyxN6Mng5Ia8EJt0dAklcM5q+GCrzSqQPDON3vcviDO83z2H4kBXm65yarJ4cJ
b/3PZ9UvAsjcPRhWtpw0W51wTcFlMCT/7YE2FBOEX0E5D9HJVUwJjcEgPoX9AFuY
xYVpFvr1AoORde/RoJGoe+Z81hIRvcbrzfLHEMCB0pY0wxBuD5tyhEunIwLxG+6v
T1OHtuXDATEGabZQJKuhBfuP00YFRKxHIBLWPtkplQGFAXmBEeD5NIYfo+RBQFUH
GuvDTHoEvecn9ZHF4eOjJ88TXaGuXrFHwa0g0KMDNaECgYEA+ld2bkC4RXNWIzYI
4bOH7UBFrd74nz4zqNd2UZqP9R1al8nLgcESiT6izBbR+6wnNANIon5fXYGFK+wu
NGvKwuL1Xf04Ro/Z/i03QrV5fTgL/F8NX9F0kc6znxli9SrpswSjb1ZUoJmQXCew
ZYkCVavy3Zpgk8uHeeaHOOAI6k8CgYEA4uhC2Jy9Ysq6Eg79hVq0xHtXLl0VWfrU
5mugItrH90LmsCvKK4Qzg33BjhIMbE9vq63yFxW08845weuxUV6LalPSLOclE7D2
6exG5grcdGpqyWKc2qCAXP2uLys68cOfWduJoVUYsdAGbyNdvkI69VcTsI8pV6kR
bjzP+l50c9ECgYA3CVN4GbJpUln1k8OQGzAe8Kpg90whdkNVM0lH13seoD1ycWLU
O+YfVi3kQIAZnFdiD/bAAphkrjzg0yO1Up1ZCxx2dV0R5j4+qyIjAFKdPN0ltp/y
GNJP2+mRaLtguvZ17OchaxFf3WLnX7JgICbrPso9/dqNo4k9O3ku/9H18QKBgQDZ
LaMlfsgJ8a2ssSpYZBwW31LvbmqMR/dUX/jSw4KXmDICtrb3db50gX4rw/yeAl4I
/SF0lPMwU9eWU0fRcOORro7BKa+kLEH4XYzyi7y7tEtnW3p0CyExYCFCxmbRlgJE
WEtf3noXXtt5rmkAPJX/0wtmd3ADli+3yn7pzVQ6sQKBgQDJJITERtov019Cwuux
fCRUIbRyUH/PCN/VvsuKFs+BWbFTnqBXRDQetzTyuUvNKiL7GmWQuR/QpgYjLd9W
jxAayhtcVKeL96dqimK9twmw/NC5DveOVoReXx7io4gicmQi7AGq5WRkm8NUZRVE
1dH1Hhp7kjnPlUOUBvKf8mfFxQ==
-----END PRIVATE KEY-----
'''

SSL_TEST_CRT = '''-----BEGIN CERTIFICATE-----
MIIDeTCCAmGgAwIBAgIUaam3vV40bjLs7mabludFi6dRsxkwDQYJKoZIhvcNAQEL
BQAwTDELMAkGA1UEBhMCSUwxEzARBgNVBAgMClNvbWUtU3RhdGUxEzARBgNVBAoM
ClhTT0FSIFRlc3QxEzARBgNVBAMMCnhzb2FyLXRlc3QwHhcNMjEwNTE2MTQzNDU0
WhcNMzAwODAyMTQzNDU0WjBMMQswCQYDVQQGEwJJTDETMBEGA1UECAwKU29tZS1T
dGF0ZTETMBEGA1UECgwKWFNPQVIgVGVzdDETMBEGA1UEAwwKeHNvYXItdGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN3kVy8IqC1eORhqIN2qkUBg
rDpbE0SlkgaPMP0qESqvs5mOk+gt7IaHVTp9oBw3pemRC6AUD/Yar5mP+l7VpuJM
Jty10T3vwVhWNfFsQQC0SfjHbyz9spqH/GOPD5GNTJAH0OyKgWRXV432ImHl444g
6NMMwG3tLFjUeK8LQeNQqMJoyN0fZbEa7idr2mE85rvOLGWAupkYLyATUC2LmPec
4Q6Was0h/Vn/jN0nMRoymsELKZ8S+uAwLuJsb0CiQNwCPpKXjGC9NGm1NzMJtTEX
WOyc01u4vKr9G5DzlJYHeatEpPg6A+3P+BreybiXtSr9g3vUav8vFqpuTBZUx38C
AwEAAaNTMFEwHQYDVR0OBBYEFJLT/bq2cGAu6buAQSoeusx439YaMB8GA1UdIwQY
MBaAFJLT/bq2cGAu6buAQSoeusx439YaMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI
hvcNAQELBQADggEBACmcsfDI382F64TWtJaEn4pKCTjiJloXfb3curr7qYVfeLUX
jbb6aRha88/PB+6/IC/lR0JjXRWMMQafFFR7rb1290p2YVPE9T5Wc5934M590LxZ
bwa5YsCF+qzBiWPMUs5s/el8AHTnUQdU/CKLMI7ZL2IpyTpfW4PERw2HiOBdgCbl
1DzjH9L1bmCzIhXBR6bUXUn4vjg8VBIQ29uHrLNN1fgDyRB1eAaOs4iuBAZm7IkC
k+cVw239GwbLsYkRg5BpkQF4IC6a4+Iz9fpvpUc/g6jpxtGU0kE2DVWOEAyPOOWC
C/t/GFcoOUze68WuI/BqMAiWhPJ1ioL7RI2ZPvI=
-----END CERTIFICATE-----
'''

IOC_RES_LEN = 38

'''Tests'''


class TestHelperFunctions:
    def test_get_edl_ioc_values_1(self, mocker):
        """Test on_demand"""
        from EDL import get_edl_ioc_values, RequestArguments
        with open('EDL_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            integration_context = {"last_output": iocs_text_dict}
            request_args = RequestArguments(query='', limit=50, offset=0)
            ioc_list = get_edl_ioc_values(
                on_demand=True,
                request_args=request_args,
                edl_cache=integration_context
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    def test_get_edl_ioc_values_2(self, mocker):
        """Test update by not on_demand with no refresh"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383899, 1578383899))
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(edl, 'refresh_edl_context', return_value=iocs_text_dict)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            request_args = edl.RequestArguments(query='', limit=50, offset=0)
            ioc_list = edl.get_edl_ioc_values(
                on_demand=False,
                request_args=request_args,
                edl_cache=iocs_text_dict,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    def test_get_edl_ioc_values_3(self, mocker):
        """Test update by not on_demand with refresh"""
        import CommonServerPython as CSP
        mocker.patch.object(CSP, 'parse_date_range', return_value=(1578383898, 1578383898))
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/iocs_cache_values_text.json', 'r') as iocs_text_values_f:
            iocs_text_dict = json.loads(iocs_text_values_f.read())
            mocker.patch.object(demisto, 'getIntegrationContext', return_value=iocs_text_dict)
            request_args = edl.RequestArguments(query='', limit=50, offset=0)
            mocker.patch.object(demisto, 'getLastRun', return_value={'last_run': 1578383898000})
            ioc_list = edl.get_edl_ioc_values(
                on_demand=False,
                request_args=request_args,
                edl_cache=iocs_text_dict,
                cache_refresh_rate='1 minute'
            )
            for ioc_row in ioc_list:
                assert ioc_row in iocs_text_dict

    def test_list_to_str_1(self):
        """Test invalid"""
        from EDL import list_to_str
        with pytest.raises(AttributeError):
            invalid_list_value = 2
            list_to_str(invalid_list_value)

        with pytest.raises(AttributeError):
            invalid_list_value = {'invalid': 'invalid'}
            list_to_str(invalid_list_value)

    def test_list_to_str_2(self):
        """Test empty"""
        from EDL import list_to_str
        assert list_to_str(None) == ''
        assert list_to_str([]) == ''
        assert list_to_str({}) == ''

    def test_list_to_str_3(self):
        """Test non empty fields"""
        from EDL import list_to_str
        valid_list_value = [1, 2, 3, 4]
        assert list_to_str(valid_list_value) == '1,2,3,4'
        assert list_to_str(valid_list_value, '.') == '1.2.3.4'
        assert list_to_str(valid_list_value, map_func=lambda x: f'{x}a') == '1a,2a,3a,4a'

    def test_get_params_port_1(self):
        """Test invalid"""
        from CommonServerPython import DemistoException
        from EDL import get_params_port
        params = {'longRunningPort': 'invalid'}
        with pytest.raises(DemistoException):
            get_params_port(params)

    def test_get_params_port_2(self):
        """Test empty"""
        from EDL import get_params_port
        params = {'longRunningPort': ''}
        with pytest.raises(ValueError):
            get_params_port(params)

    def test_get_params_port_3(self):
        """Test valid"""
        from EDL import get_params_port
        params = {'longRunningPort': '80'}
        assert get_params_port(params) == 80

    def test_refresh_edl_context_1(self, mocker):
        """Sanity"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            mocker.patch.object(edl, 'find_indicators_to_limit', return_value=iocs_json)
            request_args = edl.RequestArguments(query='', limit=38, url_port_stripping=True)
            edl_vals = edl.refresh_edl_context(request_args)
            for ioc in iocs_json:
                ip = ioc.get('value')
                stripped_ip = edl._PORT_REMOVAL.sub(edl._URL_WITHOUT_PORT, ip)
                if stripped_ip != ip:
                    assert stripped_ip.replace('https://', '') in edl_vals
                else:
                    assert ip in edl_vals

    def test_find_indicators_to_limit_1(self, mocker):
        """Test find indicators limit"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            limit = 30
            mocker.patch.object(edl, 'find_indicators_to_limit_loop', return_value=(iocs_json, 1))
            edl_vals = edl.find_indicators_to_limit(indicator_query='', limit=limit)
            assert len(edl_vals) == limit

    def test_find_indicators_to_limit_and_offset_1(self, mocker):
        """Test find indicators limit and offset"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())
            limit = 30
            offset = 1
            mocker.patch.object(edl, 'find_indicators_to_limit_loop', return_value=(iocs_json, 1))
            edl_vals = edl.find_indicators_to_limit(indicator_query='', limit=limit, offset=offset)
            assert len(edl_vals) == limit
            # check that the first value is the second on the list
            assert edl_vals[0].get('value') == '212.115.110.19'

    def test_find_indicators_to_limit_loop_1(self, mocker):
        """Test find indicators stops when reached last page"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_dict = {'iocs': json.loads(iocs_json_f.read())}
            limit = 50
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_dict)
            edl_vals, nxt_pg = edl.find_indicators_to_limit_loop(indicator_query='', limit=limit)
            assert nxt_pg == 1  # assert entered into loop

    def test_find_indicators_to_limit_loop_2(self, mocker):
        """Test find indicators stops when reached limit"""
        import EDL as edl
        with open('EDL_test/TestHelperFunctions/demisto_iocs.json', 'r') as iocs_json_f:
            iocs_dict = {'iocs': json.loads(iocs_json_f.read())}
            limit = 30
            mocker.patch.object(demisto, 'searchIndicators', return_value=iocs_dict)
            edl.PAGE_SIZE = IOC_RES_LEN
            edl_vals, nxt_pg = edl.find_indicators_to_limit_loop(indicator_query='', limit=limit,
                                                                 last_found_len=IOC_RES_LEN)
            assert nxt_pg == 1  # assert entered into loop

    def test_create_values_for_returned_dict(self):
        from EDL import create_values_for_returned_dict, EDL_VALUES_KEY, RequestArguments
        with open('EDL_test/TestHelperFunctions/demisto_url_iocs.json', 'r') as iocs_json_f:
            iocs_json = json.loads(iocs_json_f.read())

            # strips port numbers
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True)
            returned_dict, num_of_indicators = create_values_for_returned_dict(iocs_json, request_args)
            returned_output = returned_dict.get(EDL_VALUES_KEY)
            assert returned_output == "1.2.3.4/wget\nwww.demisto.com/cool"
            assert num_of_indicators == 2

            # should ignore indicators with port numbers
            request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=False)
            returned_dict, num_of_indicators = create_values_for_returned_dict(iocs_json, request_args)
            returned_output = returned_dict.get(EDL_VALUES_KEY)
            assert returned_output == 'www.demisto.com/cool'
            assert num_of_indicators == 1

            # should not ignore indicators with '*' in them
            request_args = RequestArguments(query='', drop_invalids=False, url_port_stripping=False)
            returned_dict, num_of_indicators = create_values_for_returned_dict(iocs_json, request_args)
            returned_output = returned_dict.get(EDL_VALUES_KEY)
            assert returned_output == 'www.demisto.com/cool\nwww.demisto.com/*'
            assert num_of_indicators == 2

    def test_create_values_for_returned_dict__filters(self):
        from EDL import create_values_for_returned_dict, EDL_VALUES_KEY, RequestArguments
        iocs = [
            {'value': '2603:1006:1400::/40', 'indicator_type': 'IPv6'},
            {'value': '2002:ac8:b8d:0:0:0:0:0', 'indicator_type': 'IPv6'},
            {'value': 'demisto.com:369/rest/of/path', 'indicator_type': 'URL'},
            {'value': 'panw.com/path', 'indicator_type': 'URL'},
            {'value': '*.domain.com', 'indicator_type': 'URL'},
        ]

        request_args = RequestArguments(query='', drop_invalids=True, url_port_stripping=True)
        returned_dict, num_of_indicators = create_values_for_returned_dict(iocs, request_args)
        returned_output = returned_dict.get(EDL_VALUES_KEY, '').split('\n')
        assert '2603:1006:1400::/40' in returned_output
        assert '2002:ac8:b8d:0:0:0:0:0' in returned_output
        assert 'demisto.com/rest/of/path' in returned_output  # port stripping
        assert 'panw.com/path' in returned_output
        assert '*.domain.com' in returned_output
        assert 'domain.com' in returned_output  # PAN-OS URLs
        assert num_of_indicators == 6

    def test_validate_basic_authentication(self):
        """Test Authentication"""
        from EDL import validate_basic_authentication
        data = {
            "empty_auth": {},
            "basic_missing_auth": {
                "Authorization": "missing basic"
            },
            "colon_missing_auth": {
                "Authorization": "Basic bWlzc2luZ19jb2xvbg=="
            },
            "wrong_length_auth": {
                "Authorization": "Basic YTpiOmM="
            },
            "wrong_credentials_auth": {
                "Authorization": "Basic YTpi"
            },
            "right_credentials_auth": {
                "Authorization": "Basic dXNlcjpwd2Q="
            }
        }
        username, password = 'user', 'pwd'
        assert not validate_basic_authentication(data.get('empty_auth'), username, password)
        assert not validate_basic_authentication(data.get('basic_missing_auth'), username, password)
        assert not validate_basic_authentication(data.get('colon_missing_auth'), username, password)
        assert not validate_basic_authentication(data.get('wrong_length_auth'), username, password)
        assert not validate_basic_authentication(data.get('wrong_credentials_auth'), username, password)
        assert validate_basic_authentication(data.get('right_credentials_auth'), username, password)

    def test_ips_to_ranges_range(self):
        from EDL import ips_to_ranges, COLLAPSE_TO_RANGES
        ip_list = [IPAddress("1.1.1.1"), IPAddress("25.24.23.22"), IPAddress("22.21.20.19"),
                   IPAddress("1.1.1.2"), IPAddress("1.2.3.4"), IPAddress("1.1.1.3"), IPAddress("2.2.2.2"),
                   IPAddress("1.2.3.5")]

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_RANGES)
        assert "1.1.1.1-1.1.1.3" in ip_range_list
        assert "1.2.3.4-1.2.3.5" in ip_range_list
        assert "1.1.1.2" not in ip_range_list
        assert "2.2.2.2" in ip_range_list
        assert "25.24.23.22" in ip_range_list

    def test_ips_to_ranges_cidr(self):
        from EDL import ips_to_ranges, COLLAPSE_TO_CIDR
        ip_list = [IPAddress("1.1.1.1"), IPAddress("25.24.23.22"), IPAddress("22.21.20.19"),
                   IPAddress("1.1.1.2"), IPAddress("1.2.3.4"), IPAddress("1.1.1.3"), IPAddress("2.2.2.2"),
                   IPAddress("1.2.3.5")]

        ip_range_list = ips_to_ranges(ip_list, COLLAPSE_TO_CIDR)
        assert "1.1.1.1" in ip_range_list
        assert "1.1.1.2/31" in ip_range_list
        assert "1.2.3.4/31" in ip_range_list
        assert "1.2.3.5" not in ip_range_list
        assert "1.1.1.3" not in ip_range_list
        assert "2.2.2.2" in ip_range_list
        assert "25.24.23.22" in ip_range_list


def test_nginx_conf(tmp_path: Path):
    from EDL import create_nginx_server_conf
    conf_file = str(tmp_path / "nginx-test-server.conf")
    create_nginx_server_conf(conf_file, 12345, params={})
    with open(conf_file, 'rt') as f:
        conf = f.read()
        assert 'listen 12345 default_server' in conf


NGINX_PROCESS: Optional[subprocess.Popen] = None


@pytest.fixture
def nginx_cleanup():
    yield
    from EDL import NGINX_SERVER_CONF_FILE
    Path(NGINX_SERVER_CONF_FILE).unlink(missing_ok=True)
    global NGINX_PROCESS
    if NGINX_PROCESS:
        NGINX_PROCESS.terminate()
        # let the process terminate
        NGINX_PROCESS.wait(1.0)
        NGINX_PROCESS = None


docker_only = pytest.mark.skipif('flask-nginx' not in os.getenv('DOCKER_IMAGE', ''), reason='test should run only within docker')


@docker_only
def test_nginx_start_fail(mocker: MockerFixture, nginx_cleanup):
    """Test that nginx fails when config is invalid
    """
    def nginx_bad_conf(file_path: str, port: int, params: dict):
        with open(file_path, 'wt') as f:
            f.write('server {bad_stuff test;}')
    import EDL as edl
    mocker.patch.object(edl, 'create_nginx_server_conf', side_effect=nginx_bad_conf)
    try:
        edl.start_nginx_server(12345, {})
        pytest.fail('nginx start should fail')
    except ValueError as e:
        assert 'bad_stuff' in str(e)


@docker_only
def test_nginx_start_fail_directive(nginx_cleanup):
    """Test that nginx fails when invalid global directive is passed
    """
    import EDL as edl
    try:
        edl.start_nginx_server(12345, {'nginx_global_directives': 'bad_directive test;'})
        pytest.fail('nginx start should fail')
    except ValueError as e:
        assert 'bad_directive' in str(e)


@docker_only
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('params', [
    {},
    {'certificate': SSL_TEST_CRT, 'key': SSL_TEST_KEY},
])
def test_nginx_test_start_valid(nginx_cleanup, params):
    import EDL as edl
    edl.test_nginx_server(11300, params)
    # check that nginx process is not up
    sleep(0.5)
    ps_out = subprocess.check_output(['ps', 'aux'], text=True)
    assert 'nginx' not in ps_out


@docker_only
def test_nginx_log_process(nginx_cleanup, mocker: MockerFixture):
    import EDL as edl
    # clear logs for test
    Path(edl.NGINX_SERVER_ACCESS_LOG).unlink(missing_ok=True)
    Path(edl.NGINX_SERVER_ERROR_LOG).unlink(missing_ok=True)
    NGINX_PROCESS = edl.start_nginx_server(12345, {})
    sleep(0.5)  # give nginx time to start
    # create a request to get a log line
    requests.get('http://localhost:12345/nginx-test?unit_testing')
    sleep(0.2)
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'error')
    edl.nginx_log_process(NGINX_PROCESS)
    # call_args is tuple (args list, kwargs). we only need the args
    arg = demisto.info.call_args[0][0]
    assert 'nginx access log' in arg
    assert 'unit_testing' in arg
    arg = demisto.error.call_args[0][0]
    assert '[warn]' in arg
    assert 'the master process runs with super-user privileges' in arg
    # make sure old file was removed
    assert not Path(edl.NGINX_SERVER_ACCESS_LOG + '.old').exists()
    assert not Path(edl.NGINX_SERVER_ERROR_LOG + '.old').exists()
    # make sure log was rolled over files should be of size 0
    assert not Path(edl.NGINX_SERVER_ACCESS_LOG).stat().st_size
    assert not Path(edl.NGINX_SERVER_ERROR_LOG).stat().st_size
