import pytest
import requests
import demistomock as demisto
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


def test_nginx_conf(tmp_path: Path, mocker):
    from NGINXApiModule import create_nginx_server_conf
    conf_file = str(tmp_path / "nginx-test-server.conf")
    mocker.patch.object(demisto, 'callingContext', return_value={'context': {}})
    create_nginx_server_conf(conf_file, 12345, params={})
    with open(conf_file, 'rt') as f:
        conf = f.read()
        assert 'listen 12345 default_server' in conf


def test_nginx_conf_taxii2(tmp_path: Path, mocker):
    from NGINXApiModule import create_nginx_server_conf
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': 'TAXII2 Server'}})
    conf_file = str(tmp_path / "nginx-test-server.conf")
    create_nginx_server_conf(conf_file, 12345, params={'version': '2.0', 'credentials': {'identifier': 'identifier'}})
    with open(conf_file, 'rt') as f:
        conf = f.read()
        assert '$http_authorization' in conf
        assert '$http_accept' in conf
        assert 'proxy_set_header Range $http_range;' in conf
        assert '$http_range' in conf


NGINX_PROCESS: Optional[subprocess.Popen] = None


@pytest.fixture
def nginx_cleanup():
    yield
    from NGINXApiModule import NGINX_SERVER_CONF_FILE
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
    import NGINXApiModule as module
    mocker.patch.object(module, 'create_nginx_server_conf', side_effect=nginx_bad_conf)
    try:
        module.start_nginx_server(12345, {})
        pytest.fail('nginx start should fail')
    except ValueError as e:
        assert 'bad_stuff' in str(e)


@docker_only
def test_nginx_start_fail_directive(nginx_cleanup, mocker):
    """Test that nginx fails when invalid global directive is passed
    """
    import NGINXApiModule as module
    try:
        mocker.patch.object(demisto, 'callingContext', return_value={'context': {}})
        module.start_nginx_server(12345, {'nginx_global_directives': 'bad_directive test;'})
        pytest.fail('nginx start should fail')
    except ValueError as e:
        assert 'bad_directive' in str(e)


@docker_only
@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('params', [
    {},
    {'certificate': SSL_TEST_CRT, 'key': SSL_TEST_KEY},
])
def test_nginx_test_start_valid(nginx_cleanup, params, mocker):
    import NGINXApiModule as module
    mocker.patch.object(demisto, 'callingContext', return_value={'context': {}})
    module.test_nginx_server(11300, params)
    # check that nginx process is not up
    sleep(0.5)
    ps_out = subprocess.check_output(['ps', 'aux'], text=True)
    assert 'nginx' not in ps_out


@docker_only
def test_nginx_log_process(nginx_cleanup, mocker: MockerFixture):
    import NGINXApiModule as module
    # clear logs for test
    Path(module.NGINX_SERVER_ACCESS_LOG).unlink(missing_ok=True)
    Path(module.NGINX_SERVER_ERROR_LOG).unlink(missing_ok=True)
    global NGINX_PROCESS
    mocker.patch.object(demisto, 'callingContext', return_value={'context': {}})
    NGINX_PROCESS = module.start_nginx_server(12345, {})
    sleep(0.5)  # give nginx time to start
    # create a request to get a log line
    requests.get('http://localhost:12345/nginx-test?unit_testing')
    sleep(0.2)
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'error')
    module.nginx_log_process(NGINX_PROCESS)
    # call_args is tuple (args list, kwargs). we only need the args
    arg = demisto.info.call_args[0][0]
    assert 'nginx access log' in arg
    assert 'unit_testing' in arg
    arg = demisto.error.call_args[0][0]
    assert '[warn]' in arg
    assert 'the master process runs with super-user privileges' in arg
    # make sure old file was removed
    assert not Path(module.NGINX_SERVER_ACCESS_LOG + '.old').exists()
    assert not Path(module.NGINX_SERVER_ERROR_LOG + '.old').exists()
    # make sure log was rolled over files should be of size 0
    assert not Path(module.NGINX_SERVER_ACCESS_LOG).stat().st_size
    assert not Path(module.NGINX_SERVER_ERROR_LOG).stat().st_size
