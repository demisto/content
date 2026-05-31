import os
import subprocess
import traceback
from math import ceil
from multiprocessing import Process
from pathlib import Path
from signal import SIGUSR1
from string import Template
from typing import Any

import demistomock as demisto  # noqa: F401
import gevent
import requests
from CommonServerPython import *  # noqa: F401
from flask.logging import default_handler
from gevent.pywsgi import WSGIServer

from CommonServerUserPython import *


class Handler:
    @staticmethod
    def write(msg: str):
        demisto.info(msg)


class ErrorHandler:
    @staticmethod
    def write(msg: str):
        demisto.error(f"wsgi error: {msg}")


DEMISTO_LOGGER: Handler = Handler()
ERROR_LOGGER: ErrorHandler = ErrorHandler()


# nginx server params
NGINX_SERVER_ACCESS_LOG = "/var/log/nginx/access.log"
NGINX_SERVER_ERROR_LOG = "/var/log/nginx/error.log"
NGINX_SERVER_CONF_FILE = "/etc/nginx/conf.d/default.conf"
NGINX_SSL_KEY_FILE = "/etc/nginx/ssl/ssl.key"
NGINX_SSL_CRT_FILE = "/etc/nginx/ssl/ssl.crt"
NGINX_SSL_CERTS = f"""
    ssl_certificate {NGINX_SSL_CRT_FILE};
    ssl_certificate_key {NGINX_SSL_KEY_FILE};
"""
NGINX_SERVER_CONF = """
server {

    listen $port default_server $ssl;

    $sslcerts

    proxy_cache_key $scheme$proxy_host$request_uri$extra_cache_key;
    $proxy_set_range_header
    $extra_headers
# Thundering-herd protection
proxy_cache_lock on;
proxy_cache_lock_timeout $cache_lock_timeout;
proxy_cache_lock_age $cache_lock_age;

# Cache validity by status
proxy_cache_valid 200 301 302 $cache_refresh_rate;

# Optional: cache other responses briefly (helps absorb spikes)
proxy_cache_valid 404 $cache_404_ttl;
proxy_cache_valid any $cache_default_ttl;

# Revalidation (use conditional requests when expired)
proxy_cache_revalidate on;

# Serve stale content in failure/update scenarios
proxy_cache_use_stale
    updating
    error
    timeout
    invalid_header
    http_500
    http_502
    http_503
    http_504;

# Background refresh of expired cache
proxy_cache_background_update on;

    # Static test file
    location = /nginx-test {
        alias /var/lib/nginx/html/index.html;
        default_type text/html;
    }

    # Proxy everything to python
    location / {
        proxy_pass http://localhost:$serverport/;
        add_header X-Proxy-Cache $upstream_cache_status;
        $extra_headers
        # allow bypassing the cache with an arg of nocache=1 ie http://server:7000/?nocache=1
        proxy_cache_bypass $arg_nocache;
        proxy_read_timeout $timeout;
        proxy_connect_timeout 3600;
        proxy_send_timeout 3600;
        send_timeout 3600;
    }
}

"""
NGINX_MAX_POLLING_TRIES = 5


def create_nginx_server_conf(file_path: str, port: int, params: dict):
    """Create nginx conf file

    Args:
        file_path (str): path of server conf file
        port (int): listening port. server port to proxy to will be port+1
        params (Dict): additional nginx params

    Raises:
        DemistoException: raised if there is a detected config error
    """
    params = params if params else demisto.params()
    template_str = params.get("nginx_server_conf") or NGINX_SERVER_CONF
    certificate: str = params.get("certificate", "")
    private_key: str = params.get("key", "")
    # Normalize all five `cache_*` time params (plus `timeout`) through a single helper so the
    # rendered nginx directives are always a safe `<int>s` token.
    timeout = _normalize_nginx_time(params.get("timeout"), default="3600", param_name="timeout")
    cache_refresh_rate = _normalize_nginx_time(params.get("cache_refresh_rate"), default=timeout, param_name="cache_refresh_rate")

    # Ensure cache lock directives are at least as large as the upstream timeout. Otherwise, when an
    # upstream request takes longer than the lock timeout/age, waiting clients bypass the cache lock
    # and stampede the upstream (each waiter then produces an uncached response), defeating the purpose
    # of `proxy_cache_lock on`. Defaults match `timeout`; explicit smaller values are bumped up.
    cache_lock_timeout = _normalize_nginx_time(params.get("cache_lock_timeout"), default=timeout, param_name="cache_lock_timeout")
    cache_lock_age = _normalize_nginx_time(params.get("cache_lock_age"), default=timeout, param_name="cache_lock_age")
    cache_404_ttl = _normalize_nginx_time(params.get("cache_404_ttl"), default="1m", param_name="cache_404_ttl")
    cache_default_ttl = _normalize_nginx_time(params.get("cache_default_ttl"), default="1m", param_name="cache_default_ttl")

    # Ensure cache_refresh_rate is at least as large as timeout, and apply the same anti-stampede
    # floor to the cache lock directives. All values are now guaranteed to end in "s" (the helper
    # always returns `<int>s`), so an O(1) integer compare on the prefix is safe.
    timeout_seconds = int(timeout[:-1])
    if int(cache_refresh_rate[:-1]) < timeout_seconds:
        cache_refresh_rate = timeout
    if int(cache_lock_timeout[:-1]) < timeout_seconds:
        cache_lock_timeout = timeout
    if int(cache_lock_age[:-1]) < timeout_seconds:
        cache_lock_age = timeout

    ssl, extra_headers, sslcerts, proxy_set_range_header = "", "", "", ""
    serverport = port + 1
    extra_cache_keys = []
    if (certificate and not private_key) or (private_key and not certificate):
        raise DemistoException("If using HTTPS connection, both certificate and private key should be provided.")
    if certificate and private_key:
        demisto.debug("Using HTTPS for nginx conf")
        with open(NGINX_SSL_CRT_FILE, "w") as f:
            f.write(certificate)
        with open(NGINX_SSL_KEY_FILE, "w") as f:
            f.write(private_key)
        ssl = "ssl"  # to be included in the listen directive
        sslcerts = NGINX_SSL_CERTS
        if argToBoolean(params.get("hsts_header", False)):
            extra_headers = 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
    credentials = params.get("credentials") or {}
    if credentials.get("identifier"):
        extra_cache_keys.append("$http_authorization")
    if get_integration_name() == "TAXII2 Server":
        extra_cache_keys.append("$http_accept")
        if params.get("version") == "2.0":
            proxy_set_range_header = "proxy_set_header Range $http_range;"
            extra_cache_keys.extend(["$http_range", "$http_content_range"])

    extra_cache_keys_str = "".join(extra_cache_keys)
    server_conf = Template(template_str).safe_substitute(
        port=port,
        serverport=serverport,
        ssl=ssl,
        sslcerts=sslcerts,
        extra_cache_key=extra_cache_keys_str,
        proxy_set_range_header=proxy_set_range_header,
        timeout=timeout,
        cache_refresh_rate=cache_refresh_rate,
        cache_lock_timeout=cache_lock_timeout,
        cache_lock_age=cache_lock_age,
        cache_404_ttl=cache_404_ttl,
        cache_default_ttl=cache_default_ttl,
        extra_headers=extra_headers,
    )
    with open(file_path, mode="w+") as f:
        f.write(server_conf)


def start_nginx_server(port: int, params: dict = {}) -> subprocess.Popen:
    params = params if params else demisto.params()
    create_nginx_server_conf(NGINX_SERVER_CONF_FILE, port, params)
    nginx_global_directives = "daemon off;"
    global_directives_conf = params.get("nginx_global_directives")
    if global_directives_conf:
        nginx_global_directives = f"{nginx_global_directives} {global_directives_conf}"
    directive_args = ["-g", nginx_global_directives]
    # we first do a test that all config is good and log it
    try:
        nginx_test_command = ["nginx", "-T"]
        nginx_test_command.extend(directive_args)
        test_output = subprocess.check_output(nginx_test_command, stderr=subprocess.STDOUT, text=True)
        demisto.info(f"ngnix test passed. command: [{nginx_test_command}]")
        demisto.debug(f"nginx test ouput:\n{test_output}")
    except subprocess.CalledProcessError as err:
        raise ValueError(f"Failed testing nginx conf. Return code: {err.returncode}. Output: {err.output}")
    nginx_command = ["nginx"]
    nginx_command.extend(directive_args)
    res = subprocess.Popen(nginx_command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    demisto.info(f"done starting nginx with pid: {res.pid}")
    return res


def nginx_log_process(nginx_process: subprocess.Popen):
    old_access = NGINX_SERVER_ACCESS_LOG + ".old"
    old_error = NGINX_SERVER_ERROR_LOG + ".old"
    log_access = False
    log_error = False
    # first check if one of the logs are missing. This may happen on rare ocations that we renamed and deleted the file
    # before nginx completed the role over of the logs
    missing_log = False
    if not os.path.isfile(NGINX_SERVER_ACCESS_LOG):
        missing_log = True
        demisto.info(f"Missing access log: {NGINX_SERVER_ACCESS_LOG}. Will send roll signal to nginx.")
    if not os.path.isfile(NGINX_SERVER_ERROR_LOG):
        missing_log = True
        demisto.info(f"Missing error log: {NGINX_SERVER_ERROR_LOG}. Will send roll signal to nginx.")
    if missing_log:
        nginx_process.send_signal(int(SIGUSR1))
        demisto.info(
            f"Done sending roll signal to nginx (pid: {nginx_process.pid}) after detecting missing log file."
            " Will skip this iteration."
        )
        return
    if os.path.getsize(NGINX_SERVER_ACCESS_LOG):
        log_access = True
        Path(NGINX_SERVER_ACCESS_LOG).rename(old_access)
    if os.path.getsize(NGINX_SERVER_ERROR_LOG):
        log_error = True
        Path(NGINX_SERVER_ERROR_LOG).rename(old_error)
    if log_access or log_error:
        # nginx rolls the logs when getting sigusr1
        nginx_process.send_signal(int(SIGUSR1))
        gevent.sleep(0.5)  # sleep 0.5 to let nginx complete the roll
    if log_access:
        with open(old_access) as f:
            start = 1
            for lines in batch(f.readlines(), 100):
                end = start + len(lines)
                demisto.info(f"nginx access log ({start}-{end-1}): " + "".join(lines))
                start = end
        Path(old_access).unlink()
    if log_error:
        with open(old_error) as f:
            start = 1
            for lines in batch(f.readlines(), 100):
                end = start + len(lines)
                demisto.error(f"nginx error log ({start}-{end-1}): " + "".join(lines))
                start = end
        Path(old_error).unlink()


def nginx_log_monitor_loop(nginx_process: subprocess.Popen):
    """An endless loop to monitor nginx logs. Meant to be spawned as a greenlet.
    Will run every minute and if needed will dump the nginx logs and roll them if needed.

    Args:
        nginx_process (subprocess.Popen): the nginx process. Will send signal for log rolling.
    """
    while True:
        gevent.sleep(60)
        nginx_log_process(nginx_process)


def test_nginx_web_server(port: int, params: dict):
    polling_tries = 1
    is_test_done = False
    try:
        while polling_tries <= NGINX_MAX_POLLING_TRIES and not is_test_done:
            try:
                # let nginx startup
                time.sleep(0.5)
                protocol = "https" if params.get("key") else "http"
                res = requests.get(
                    f"{protocol}://localhost:{port}/nginx-test", verify=False, proxies={"http": "", "https": ""}
                )  # guardrails-disable-line # nosec
                res.raise_for_status()
                welcome = "Welcome to nginx"
                if welcome not in res.text:
                    raise ValueError(f'Unexpected response from nginx-test (does not contain "{welcome}"): {res.text}')
                is_test_done = True
            except Exception:
                if polling_tries == NGINX_MAX_POLLING_TRIES:
                    raise
                polling_tries += 1
    except Exception as ex:
        err_msg = f"Testing nginx server: {ex}"
        demisto.error(err_msg)
        raise DemistoException(err_msg) from ex


def test_nginx_server(port: int, params: dict):
    nginx_process = start_nginx_server(port, params)
    try:
        test_nginx_web_server(port, params)
    finally:
        try:
            nginx_process.terminate()
            nginx_process.wait(1.0)
        except Exception as ex:
            demisto.error(f"failed stopping test nginx process: {ex}")


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


def parse_nginx_time_to_seconds(time_str: str) -> int:
    """Parses an NGINX time string (or a human-readable equivalent) into seconds.

    NGINX uses suffixes to denote time units (e.g., ``"3600"``, ``"1h"``,
    ``"30m"``, ``"60s"``). Supported suffixes are ``s`` (seconds), ``m``
    (minutes), ``h`` (hours), ``d`` (days), ``w`` (weeks), ``M`` (30 days),
    and ``y`` (years). If no suffix is supplied, the value is treated as
    seconds.

    Additionally, human-readable values used by some integrations (e.g., EDL's
    ``cache_refresh_rate`` parameter such as ``"5 minutes"``, ``"1 hour"``,
    ``"2 days"``) are also supported by falling back to ``dateparser``.

    Args:
        time_str (str): The time string to parse.

    Returns:
        int: The time converted to seconds.

    Raises:
        DemistoException: If ``time_str`` is empty, whitespace-only, ``None``,
            or otherwise cannot be parsed as a valid time value.
    """
    if not time_str or not (time_str := time_str.strip()):
        raise DemistoException(f"Invalid NGINX time format: {time_str}")
    if time_str.isdigit():
        return int(time_str)

    units = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
        "M": 2592000,  # 30 days
        "y": 31536000,
    }

    unit = time_str[-1]
    value_str = time_str[:-1]

    if unit in units and value_str.isdigit():
        return int(value_str) * units[unit]

    # If it doesn't match the NGINX-native format, try parsing it as a
    # human-readable relative time (e.g., "5 minutes", "1 hour", "2 days").
    try:
        seconds = ceil((datetime.now() - dateparser.parse(time_str)).total_seconds())  # type: ignore[operator]
        if seconds > 0:
            return seconds
    except Exception:
        pass

    # Last resort: try to interpret the value as an integer number of seconds.
    try:
        return int(time_str)
    except (ValueError, TypeError):
        raise DemistoException(f"Invalid NGINX time format: {time_str}")


# Human-readable units accepted in the "<int> <unit>" form (e.g. "12 hours",
# "1 minute"). Anything outside this allow-list is rejected up-front so we do
# not silently inherit dateparser's permissive interpretation of unit-only
# tokens (e.g. "hours" -> midnight today) or compound expressions
# (e.g. "12 hours and 5 minutes" -> "12 hours ago at 23:25").
_NORMALIZE_NGINX_TIME_HUMAN_UNITS = frozenset(
    {
        "second",
        "seconds",
        "minute",
        "minutes",
        "hour",
        "hours",
        "day",
        "days",
        "week",
        "weeks",
        "month",
        "months",
        "year",
        "years",
    }
)


def _normalize_nginx_time(value: Any, default: str, param_name: str) -> str:
    """Normalize a user-supplied time value to an nginx-valid ``"<int>s"`` token.

    Accepts:
      * pure ints       : ``300``, ``"300"`` (must be non-negative)
      * nginx-native    : ``"12h"``, ``"30m"``, ``"1d"``, ``"2w"``, ``"1M"``,
                          ``"1y"``, ``"60s"``
      * human-readable  : strict ``"<positive-int> <unit>"`` form, where unit
                          is one of ``second(s)``, ``minute(s)``, ``hour(s)``,
                          ``day(s)``, ``week(s)``, ``month(s)``, ``year(s)``.

    Always returns ``f"{seconds}s"`` (e.g. ``"43200s"``) so the rendered nginx
    directive is unambiguous and unit-safe — the entire class of unit-string
    typo bugs in the template is eliminated.

    Falls back to ``default`` (which is itself normalized through the same
    helper) when ``value`` is ``None``, an empty string, or whitespace-only,
    so callers can pass either form for the default.

    Args:
        value: The user-supplied value (may be ``None``, ``int``, or ``str``).
        default: The fallback value used when ``value`` is empty/missing.
            Accepts the same formats as ``value``.
        param_name: Name of the originating parameter; included verbatim in
            error messages so users can pinpoint the offending field.

    Returns:
        An nginx-valid time token of the form ``"<int>s"``.

    Raises:
        DemistoException: If ``value`` (or, when ``value`` is empty,
            ``default``) is non-empty but cannot be parsed as a valid time
            value, or resolves to a non-positive number of seconds. The
            message includes ``param_name`` and the original ``value``.
    """
    raw = "" if value is None else str(value).strip()
    if not raw:
        raw = str(default).strip()

    # Pre-validate the shape before delegating.
    tokens = raw.split()
    accepted_shape = (
        # nginx-native single token: pure int, or <int><unit-letter>
        (len(tokens) == 1 and (raw.isdigit() or (raw[:-1].isdigit() and raw[-1] in "smhdwMy")))
        # strict "<int> <unit>" human-readable form
        or (len(tokens) == 2 and tokens[0].isdigit() and tokens[1].lower() in _NORMALIZE_NGINX_TIME_HUMAN_UNITS)
    )
    if not accepted_shape:
        raise DemistoException(
            f"Invalid value for parameter '{param_name}': {value!r}. "
            f"Expected an nginx-native value (e.g. '12h', '30m', '300') "
            f"or a human-readable value (e.g. '12 hours', '30 minutes')."
        )

    try:
        seconds = parse_nginx_time_to_seconds(raw)
    except DemistoException as e:
        raise DemistoException(
            f"Invalid value for parameter '{param_name}': {value!r}. "
            f"Expected an nginx-native value (e.g. '12h', '30m', '300') "
            f"or a human-readable value (e.g. '12 hours', '30 minutes'). "
            f"Original parser error: {e}"
        )
    if seconds <= 0:
        raise DemistoException(
            f"Invalid value for parameter '{param_name}': {value!r}. " f"Value must resolve to a positive number of seconds."
        )
    return f"{seconds}s"


def get_params_port(params: dict = None) -> int:
    """
    Gets port from the integration parameters
    """
    params = params if params else demisto.params()
    port_mapping: str = params.get("longRunningPort", "")
    err_msg: str
    port: int
    if port_mapping:
        err_msg = f"Listen Port must be an integer. {port_mapping} is not valid."
        if ":" in port_mapping:
            port = try_parse_integer(port_mapping.split(":")[1], err_msg)
        else:
            port = try_parse_integer(port_mapping, err_msg)
    else:
        raise ValueError("Please provide a Listen Port.")
    return port


def run_long_running(params: dict = None, is_test: bool = False):
    """
    Start the long running server
    :param params: Demisto params
    :param is_test: Indicates whether it's test-module run or regular run
    :return: None
    """
    params = params if params else demisto.params()
    nginx_process = None
    nginx_log_monitor = None

    try:
        nginx_port = get_params_port()
        server_port = nginx_port + 1
        # set our own log handlers
        APP.logger.removeHandler(default_handler)  # type: ignore[name-defined] # pylint: disable=E0602
        integration_logger = IntegrationLogger()
        integration_logger.buffering = False
        log_handler = DemistoHandler(integration_logger)
        log_handler.setFormatter(logging.Formatter("flask log: [%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
        APP.logger.addHandler(log_handler)  # type: ignore[name-defined] # pylint: disable=E0602
        demisto.debug("done setting demisto handler for logging")
        server = WSGIServer(
            ("0.0.0.0", server_port),
            APP,  # type: ignore[name-defined]    # pylint: disable=E0602
            log=DEMISTO_LOGGER,  # type: ignore[name-defined] # pylint: disable=E0602
            error_log=ERROR_LOGGER,
        )
        if is_test:
            test_nginx_server(nginx_port, params)
            server_process = Process(target=server.serve_forever)
            server_process.start()
            time.sleep(5)
            try:
                server_process.terminate()
                server_process.join(1.0)
            except Exception as ex:
                demisto.error(f"failed stopping test wsgi server process: {ex}")

        else:
            nginx_process = start_nginx_server(nginx_port, params)
            test_nginx_web_server(nginx_port, params)
            nginx_log_monitor = gevent.spawn(nginx_log_monitor_loop, nginx_process)
            demisto.updateModuleHealth("")
            server.serve_forever()
    except Exception as e:
        error_message = str(e)
        if isinstance(e, ValueError) and "Try to write when connection closed" in error_message:
            # This indicates that the XSOAR platform is unreachable, and there is no way to recover from this, so we need to exit.
            sys.exit(1)  # pylint: disable=E9001

        demisto.error(f"An error occurred: {error_message}. Exception: {traceback.format_exc()}")
        demisto.updateModuleHealth(f"An error occurred: {error_message}")
        raise ValueError(error_message)

    finally:
        if nginx_process:
            try:
                nginx_process.terminate()
            except Exception as ex:
                demisto.error(f"Failed stopping nginx process when exiting: {ex}")
        if nginx_log_monitor:
            try:
                nginx_log_monitor.kill(timeout=1.0)
            except Exception as ex:
                demisto.error(f"Failed stopping nginx_log_monitor when exiting: {ex}")
