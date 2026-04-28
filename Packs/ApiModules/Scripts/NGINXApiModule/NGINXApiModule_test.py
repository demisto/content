import os
import subprocess
from pathlib import Path
from time import sleep

import demistomock as demisto
import pytest
import requests
from CommonServerPython import DemistoException
from pytest_mock import MockerFixture

SSL_TEST_KEY = """-----BEGIN PRIVATE KEY-----
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
"""

SSL_TEST_CRT = """-----BEGIN CERTIFICATE-----
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
"""


def test_nginx_conf(tmp_path: Path, mocker):
    from NGINXApiModule import create_nginx_server_conf

    conf_file = str(tmp_path / "nginx-test-server.conf")
    mocker.patch.object(demisto, "callingContext", return_value={"context": {}})
    create_nginx_server_conf(conf_file, 12345, params={})
    with open(conf_file) as f:
        conf = f.read()
        assert "listen 12345 default_server" in conf


def test_nginx_conf_taxii2(tmp_path: Path, mocker):
    from NGINXApiModule import create_nginx_server_conf

    mocker.patch.object(demisto, "callingContext", {"context": {"IntegrationBrand": "TAXII2 Server"}})
    conf_file = str(tmp_path / "nginx-test-server.conf")
    create_nginx_server_conf(conf_file, 12345, params={"version": "2.0", "credentials": {"identifier": "identifier"}})
    with open(conf_file) as f:
        conf = f.read()
        assert "$http_authorization" in conf
        assert "$http_accept" in conf
        assert "proxy_set_header Range $http_range;" in conf
        assert "$http_range" in conf


NGINX_PROCESS: subprocess.Popen | None = None


def _create_test_nginx_main_conf(tmp_path: Path):
    """Create a custom nginx main config that includes our test conf directory.

    Uses tmp_path for all writable resources so tests can run as non-root and ensure isolation.
    """
    nginx_test_conf_dir = tmp_path / "nginx-test-conf.d"
    nginx_test_cache_dir = tmp_path / "nginx-test-cache"
    nginx_test_tmp_dir = tmp_path / "nginx-test-tmp"
    nginx_test_pid_file = tmp_path / "nginx-test.pid"
    nginx_test_error_log = tmp_path / "nginx-test-error.log"
    nginx_test_access_log = tmp_path / "nginx-test-access.log"
    nginx_test_main_conf = tmp_path / "nginx-test-main.conf"

    nginx_test_conf_dir.mkdir(parents=True, exist_ok=True)
    nginx_test_cache_dir.mkdir(parents=True, exist_ok=True)
    nginx_test_tmp_dir.mkdir(parents=True, exist_ok=True)

    main_conf = f"""
pid {nginx_test_pid_file};
pcre_jit on;
error_log {nginx_test_error_log} crit;
include /etc/nginx/modules/*.conf;
events {{
    worker_connections 1024;
}}
http {{
    include /etc/nginx/mime.types;
    root /var/lib/nginx/html;
    server_tokens off;
    client_max_body_size 1m;
    keepalive_timeout 65;
    sendfile on;
    tcp_nodelay on;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:2m;
    gzip on;
    gzip_vary on;
    gzip_min_length 512;
    gzip_types text/javascript text/xml text/plain application/javascript application/x-javascript application/json;
    gzip_proxied any;
    proxy_http_version 1.1;
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
        '$status $body_bytes_sent "$http_referer" '
        '"$http_user_agent" "$http_x_forwarded_for"';
    access_log {nginx_test_access_log} main;
    client_body_temp_path {nginx_test_tmp_dir}/client_body;
    proxy_temp_path {nginx_test_tmp_dir}/proxy;
    fastcgi_temp_path {nginx_test_tmp_dir}/fastcgi;
    uwsgi_temp_path {nginx_test_tmp_dir}/uwsgi;
    scgi_temp_path {nginx_test_tmp_dir}/scgi;
    proxy_cache_path {nginx_test_cache_dir} levels=1:2 keys_zone=mycache:5m max_size=2g inactive=60m use_temp_path=off;
    proxy_cache mycache;
    proxy_cache_valid 5m;
    proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504 http_429;
    proxy_cache_background_update on;
    proxy_cache_lock on;
    proxy_cache_lock_age 60s;
    proxy_cache_lock_timeout 60s;
    proxy_cache_revalidate on;
    proxy_read_timeout 300s;
    include {nginx_test_conf_dir}/*.conf;
}}
"""
    with open(nginx_test_main_conf, "w") as f:
        f.write(main_conf)
    return {
        "main_conf": str(nginx_test_main_conf),
        "conf_dir": str(nginx_test_conf_dir),
        "access_log": str(nginx_test_access_log),
        "error_log": str(nginx_test_error_log),
    }


@pytest.fixture
def nginx_cleanup(monkeypatch, tmp_path):
    import NGINXApiModule as module

    # Create writable directories for nginx config and SSL files
    nginx_test_ssl_dir = tmp_path / "nginx-test-ssl"
    nginx_test_ssl_dir.mkdir(parents=True, exist_ok=True)

    # Create custom nginx main config pointing to our test conf directory
    paths = _create_test_nginx_main_conf(tmp_path)
    nginx_test_main_conf = paths["main_conf"]
    nginx_test_conf_dir = paths["conf_dir"]
    nginx_test_access_log = paths["access_log"]
    nginx_test_error_log = paths["error_log"]

    test_conf_file = f"{nginx_test_conf_dir}/default.conf"
    test_ssl_crt = str(nginx_test_ssl_dir / "ssl.crt")
    test_ssl_key = str(nginx_test_ssl_dir / "ssl.key")

    # Patch module constants to use writable paths
    monkeypatch.setattr(module, "NGINX_SERVER_CONF_FILE", test_conf_file)
    monkeypatch.setattr(module, "NGINX_SSL_CRT_FILE", test_ssl_crt)
    monkeypatch.setattr(module, "NGINX_SSL_KEY_FILE", test_ssl_key)
    monkeypatch.setattr(
        module,
        "NGINX_SSL_CERTS",
        f"\n    ssl_certificate {test_ssl_crt};\n    ssl_certificate_key {test_ssl_key};\n",
    )
    monkeypatch.setattr(module, "NGINX_SERVER_ACCESS_LOG", nginx_test_access_log)
    monkeypatch.setattr(module, "NGINX_SERVER_ERROR_LOG", nginx_test_error_log)

    # Wrap start_nginx_server to use our custom main config via -c flag
    def _patched_start_nginx_server(port: int, params: dict | None = None) -> subprocess.Popen:
        params = params if params is not None else demisto.params()
        module.create_nginx_server_conf(module.NGINX_SERVER_CONF_FILE, port, params)
        nginx_global_directives = "daemon off;"
        global_directives_conf = params.get("nginx_global_directives")
        if global_directives_conf:
            nginx_global_directives = f"{nginx_global_directives} {global_directives_conf}"
        directive_args = ["-g", nginx_global_directives]
        try:
            nginx_test_command = ["nginx", "-c", nginx_test_main_conf, "-T"]
            nginx_test_command.extend(directive_args)
            test_output = subprocess.check_output(nginx_test_command, stderr=subprocess.STDOUT, text=True)
            demisto.info(f"ngnix test passed. command: [{nginx_test_command}]")
            demisto.debug(f"nginx test ouput:\n{test_output}")
        except subprocess.CalledProcessError as err:
            raise ValueError(f"Failed testing nginx conf. Return code: {err.returncode}. Output: {err.output}")
        nginx_command = ["nginx", "-c", nginx_test_main_conf]
        nginx_command.extend(directive_args)
        res = subprocess.Popen(nginx_command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        demisto.info(f"done starting nginx with pid: {res.pid}")
        return res

    monkeypatch.setattr(module, "start_nginx_server", _patched_start_nginx_server)

    yield paths
    global NGINX_PROCESS
    if NGINX_PROCESS:
        NGINX_PROCESS.terminate()
        # let the process terminate
        NGINX_PROCESS.wait(1.0)
        NGINX_PROCESS = None


docker_only = pytest.mark.skipif("flask-nginx" not in os.getenv("DOCKER_IMAGE", ""), reason="test should run only within docker")


@docker_only
def test_nginx_start_fail(mocker: MockerFixture, nginx_cleanup):
    """Test that nginx fails when config is invalid"""
    import NGINXApiModule as module

    nginx_test_main_conf = nginx_cleanup["main_conf"]

    def nginx_bad_conf(file_path: str, port: int, params: dict):
        with open(file_path, "w") as f:
            f.write("server {bad_stuff test;}")

    # Override create_nginx_server_conf to write bad config, but keep the patched start_nginx_server
    def _start_with_bad_conf(port: int, params: dict | None = None) -> subprocess.Popen:
        params = params if params is not None else {}
        nginx_bad_conf(module.NGINX_SERVER_CONF_FILE, port, params)
        nginx_global_directives = "daemon off;"
        directive_args = ["-g", nginx_global_directives]
        try:
            nginx_test_command = ["nginx", "-c", nginx_test_main_conf, "-T"]
            nginx_test_command.extend(directive_args)
            subprocess.check_output(nginx_test_command, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as err:
            raise ValueError(f"Failed testing nginx conf. Return code: {err.returncode}. Output: {err.output}")
        nginx_command = ["nginx", "-c", nginx_test_main_conf]
        nginx_command.extend(directive_args)
        return subprocess.Popen(nginx_command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    mocker.patch.object(module, "start_nginx_server", side_effect=_start_with_bad_conf)
    with pytest.raises(ValueError) as e:
        module.start_nginx_server(12345, {})
        assert "bad_stuff" in str(e)


@docker_only
def test_nginx_start_fail_directive(nginx_cleanup, mocker):
    """Test that nginx fails when invalid global directive is passed"""
    import NGINXApiModule as module

    with pytest.raises(ValueError) as e:
        mocker.patch.object(demisto, "callingContext", return_value={"context": {}})
        module.start_nginx_server(12345, {"nginx_global_directives": "bad_directive test;"})
        assert "bad_directive" in str(e)


@docker_only
@pytest.mark.filterwarnings("ignore::urllib3.exceptions.InsecureRequestWarning")
@pytest.mark.parametrize(
    "params",
    [
        {},
        {"certificate": SSL_TEST_CRT, "key": SSL_TEST_KEY},
    ],
)
def test_nginx_test_start_valid(nginx_cleanup, params, mocker):
    import NGINXApiModule as module

    mocker.patch.object(demisto, "callingContext", return_value={"context": {}})
    module.test_nginx_server(11300, params)
    # check that nginx process is not up
    sleep(0.5)
    ps_out = subprocess.check_output(["ps", "aux"], text=True)
    assert "nginx" not in ps_out


@docker_only
def test_nginx_log_process(nginx_cleanup, mocker: MockerFixture):
    import NGINXApiModule as module

    # clear logs for test
    Path(module.NGINX_SERVER_ACCESS_LOG).unlink(missing_ok=True)
    Path(module.NGINX_SERVER_ERROR_LOG).unlink(missing_ok=True)
    global NGINX_PROCESS
    mocker.patch.object(demisto, "callingContext", return_value={"context": {}})
    NGINX_PROCESS = module.start_nginx_server(12345, {})
    sleep(0.5)  # give nginx time to start
    # create a request to get a log line
    requests.get("http://localhost:12345/nginx-test?unit_testing")
    sleep(0.2)
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "error")
    module.nginx_log_process(NGINX_PROCESS)
    # call_args is tuple (args list, kwargs). we only need the args
    arg = demisto.info.call_args[0][0]
    assert "nginx access log" in arg
    assert "unit_testing" in arg
    # make sure old file was removed
    assert not Path(module.NGINX_SERVER_ACCESS_LOG + ".old").exists()
    assert not Path(module.NGINX_SERVER_ERROR_LOG + ".old").exists()
    # make sure log was rolled over files should be of size 0
    assert not Path(module.NGINX_SERVER_ACCESS_LOG).stat().st_size
    assert not Path(module.NGINX_SERVER_ERROR_LOG).stat().st_size


def test_nginx_web_server_is_down(requests_mock, capfd):
    import NGINXApiModule as module

    with capfd.disabled():
        requests_mock.get("http://localhost:9009/nginx-test", status_code=404)
        with pytest.raises(
            DemistoException, match="Testing nginx server: 404 Client Error: None for url: http://localhost:9009/nginx-test"
        ):
            module.test_nginx_web_server(9009, {})


def test_nginx_web_server_is_up_running(requests_mock):
    import NGINXApiModule as module

    requests_mock.get("http://localhost:9009/nginx-test", status_code=200, text="Welcome to nginx")
    try:
        module.test_nginx_web_server(9009, {})
    except DemistoException as ex:
        pytest.fail(f"Failed to test nginx server. {ex}")


def test_lost_connection_engine_to_server(mocker):
    import NGINXApiModule as module
    from flask import Flask

    module.APP = Flask("demisto-edl")

    mocker.patch.object(demisto, "info", side_effect=ValueError("Try to write when connection closed"))
    mocker.patch.object(demisto, "error", side_effect=ValueError("Try to write when connection closed"))
    mocker.patch.object(demisto, "params", return_value={"longRunningPort": "8080"})
    mocker.patch.object(module, "start_nginx_server", side_effect=ValueError("Try to write when connection closed"))
    with pytest.raises(SystemExit) as e:
        module.run_long_running()
        assert e.value.code == 1


@pytest.mark.parametrize(
    "time_str, expected_seconds",
    [
        ("3600", 3600),
        ("1s", 1),
        ("30m", 1800),
        ("1h", 3600),
        ("1d", 86400),
        ("1w", 604800),
        ("1M", 2592000),
        ("1y", 31536000),
    ],
)
def test_parse_nginx_time_to_seconds(time_str, expected_seconds):
    from NGINXApiModule import parse_nginx_time_to_seconds

    assert parse_nginx_time_to_seconds(time_str) == expected_seconds


@pytest.mark.parametrize(
    "time_str",
    [
        "",
        "   ",
        "invalid",
        None,
    ],
)
def test_parse_nginx_time_to_seconds_fail(time_str):
    from NGINXApiModule import parse_nginx_time_to_seconds

    with pytest.raises(DemistoException, match="Invalid NGINX time format"):
        parse_nginx_time_to_seconds(time_str)
