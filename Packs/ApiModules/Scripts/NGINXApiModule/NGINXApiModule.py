
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from multiprocessing import Process
from gevent.pywsgi import WSGIServer
import subprocess
import gevent
from signal import SIGUSR1
import requests
from flask.logging import default_handler
from typing import Any, Dict
import os
import traceback
from string import Template


class Handler:
    @staticmethod
    def write(msg: str):
        demisto.info(msg)


class ErrorHandler:
    @staticmethod
    def write(msg: str):
        demisto.error(f'wsgi error: {msg}')


DEMISTO_LOGGER: Handler = Handler()
ERROR_LOGGER: ErrorHandler = ErrorHandler()


# nginx server params
NGINX_SERVER_ACCESS_LOG = '/var/log/nginx/access.log'
NGINX_SERVER_ERROR_LOG = '/var/log/nginx/error.log'
NGINX_SERVER_CONF_FILE = '/etc/nginx/conf.d/default.conf'
NGINX_SSL_KEY_FILE = '/etc/nginx/ssl/ssl.key'
NGINX_SSL_CRT_FILE = '/etc/nginx/ssl/ssl.crt'
NGINX_SSL_CERTS = f'''
    ssl_certificate {NGINX_SSL_CRT_FILE};
    ssl_certificate_key {NGINX_SSL_KEY_FILE};
'''
NGINX_SERVER_CONF = '''
server {

    listen $port default_server $ssl;

    $sslcerts

    proxy_cache_key $scheme$proxy_host$request_uri$extra_cache_key;
    $proxy_set_range_header

    # Static test file
    location = /nginx-test {
        alias /var/lib/nginx/html/index.html;
        default_type text/html;
    }

    # Proxy everything to python
    location / {
        proxy_pass http://localhost:$serverport/;
        add_header X-Proxy-Cache $upstream_cache_status;
        # allow bypassing the cache with an arg of nocache=1 ie http://server:7000/?nocache=1
        proxy_cache_bypass $arg_nocache;
        proxy_read_timeout $timeout;
        proxy_connect_timeout 1800;
        proxy_send_timeout 1800;
        send_timeout 1800;
    }
}

'''


def create_nginx_server_conf(file_path: str, port: int, params: Dict):
    """Create nginx conf file

    Args:
        file_path (str): path of server conf file
        port (int): listening port. server port to proxy to will be port+1
        params (Dict): additional nginx params

    Raises:
        DemistoException: raised if there is a detected config error
    """
    params = demisto.params() if not params else params
    template_str = params.get('nginx_server_conf') or NGINX_SERVER_CONF
    certificate: str = params.get('certificate', '')
    private_key: str = params.get('key', '')
    timeout: str = params.get('timeout') or '1800'
    ssl = ''
    sslcerts = ''
    serverport = port + 1
    proxy_set_range_header = ''
    extra_cache_keys = []
    if (certificate and not private_key) or (private_key and not certificate):
        raise DemistoException('If using HTTPS connection, both certificate and private key should be provided.')
    if certificate and private_key:
        demisto.debug('Using HTTPS for nginx conf')
        with open(NGINX_SSL_CRT_FILE, 'wt') as f:
            f.write(certificate)
        with open(NGINX_SSL_KEY_FILE, 'wt') as f:
            f.write(private_key)
        ssl = 'ssl'  # to be included in the listen directive
        sslcerts = NGINX_SSL_CERTS
    credentials = params.get('credentials') or {}
    if credentials.get('identifier'):
        extra_cache_keys.append("$http_authorization")
    if get_integration_name() == 'TAXII2 Server':
        extra_cache_keys.append("$http_accept")
        if params.get('version') == '2.0':
            proxy_set_range_header = 'proxy_set_header Range $http_range;'
            extra_cache_keys.extend(['$http_range', '$http_content_range'])

    extra_cache_keys_str = ''.join(extra_cache_keys)
    server_conf = Template(template_str).safe_substitute(port=port, serverport=serverport, ssl=ssl,
                                                         sslcerts=sslcerts, extra_cache_key=extra_cache_keys_str,
                                                         proxy_set_range_header=proxy_set_range_header, timeout=timeout)
    with open(file_path, mode='wt+') as f:
        f.write(server_conf)


def start_nginx_server(port: int, params: Dict = {}) -> subprocess.Popen:
    params = demisto.params() if not params else params
    create_nginx_server_conf(NGINX_SERVER_CONF_FILE, port, params)
    nginx_global_directives = 'daemon off;'
    global_directives_conf = params.get('nginx_global_directives')
    if global_directives_conf:
        nginx_global_directives = f'{nginx_global_directives} {global_directives_conf}'
    directive_args = ['-g', nginx_global_directives]
    # we first do a test that all config is good and log it
    try:
        nginx_test_command = ['nginx', '-T']
        nginx_test_command.extend(directive_args)
        test_output = subprocess.check_output(nginx_test_command, stderr=subprocess.STDOUT, text=True)
        demisto.info(f'ngnix test passed. command: [{nginx_test_command}]')
        demisto.debug(f'nginx test ouput:\n{test_output}')
    except subprocess.CalledProcessError as err:
        raise ValueError(f"Failed testing nginx conf. Return code: {err.returncode}. Output: {err.output}")
    nginx_command = ['nginx']
    nginx_command.extend(directive_args)
    res = subprocess.Popen(nginx_command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    demisto.info(f'done starting nginx with pid: {res.pid}')
    return res


def nginx_log_process(nginx_process: subprocess.Popen):
    try:
        old_access = NGINX_SERVER_ACCESS_LOG + '.old'
        old_error = NGINX_SERVER_ERROR_LOG + '.old'
        log_access = False
        log_error = False
        # first check if one of the logs are missing. This may happen on rare ocations that we renamed and deleted the file
        # before nginx completed the role over of the logs
        missing_log = False
        if not os.path.isfile(NGINX_SERVER_ACCESS_LOG):
            missing_log = True
            demisto.info(f'Missing access log: {NGINX_SERVER_ACCESS_LOG}. Will send roll signal to nginx.')
        if not os.path.isfile(NGINX_SERVER_ERROR_LOG):
            missing_log = True
            demisto.info(f'Missing error log: {NGINX_SERVER_ERROR_LOG}. Will send roll signal to nginx.')
        if missing_log:
            nginx_process.send_signal(int(SIGUSR1))
            demisto.info(f'Done sending roll signal to nginx (pid: {nginx_process.pid}) after detecting missing log file.'
                         ' Will skip this iteration.')
            return
        if os.path.getsize(NGINX_SERVER_ACCESS_LOG):
            log_access = True
            os.rename(NGINX_SERVER_ACCESS_LOG, old_access)
        if os.path.getsize(NGINX_SERVER_ERROR_LOG):
            log_error = True
            os.rename(NGINX_SERVER_ERROR_LOG, old_error)
        if log_access or log_error:
            # nginx rolls the logs when getting sigusr1
            nginx_process.send_signal(int(SIGUSR1))
            gevent.sleep(0.5)  # sleep 0.5 to let nginx complete the roll
        if log_access:
            with open(old_access, 'rt') as f:
                start = 1
                for lines in batch(f.readlines(), 100):
                    end = start + len(lines)
                    demisto.info(f'nginx access log ({start}-{end-1}): ' + ''.join(lines))
                    start = end
            os.unlink(old_access)
        if log_error:
            with open(old_error, 'rt') as f:
                start = 1
                for lines in batch(f.readlines(), 100):
                    end = start + len(lines)
                    demisto.error(f'nginx error log ({start}-{end-1}): ' + ''.join(lines))
                    start = end
            os.unlink(old_error)
    except Exception as e:
        demisto.error(f'Failed nginx log processing: {e}. Exception: {traceback.format_exc()}')


def nginx_log_monitor_loop(nginx_process: subprocess.Popen):
    """An endless loop to monitor nginx logs. Meant to be spawned as a greenlet.
    Will run every minute and if needed will dump the nginx logs and roll them if needed.

    Args:
        nginx_process (subprocess.Popen): the nginx process. Will send signal for log rolling.
    """
    while True:
        gevent.sleep(60)
        nginx_log_process(nginx_process)


def test_nginx_server(port: int, params: Dict):
    nginx_process = start_nginx_server(port, params)
    # let nginx startup
    time.sleep(0.5)
    try:
        protocol = 'https' if params.get('key') else 'http'
        res = requests.get(f'{protocol}://localhost:{port}/nginx-test',
                           verify=False, proxies={"http": "", "https": ""})  # nosec guardrails-disable-line
        res.raise_for_status()
        welcome = 'Welcome to nginx'
        if welcome not in res.text:
            raise ValueError(f'Unexpected response from nginx-text (does not contain "{welcome}"): {res.text}')
    finally:
        try:
            nginx_process.terminate()
            nginx_process.wait(1.0)
        except Exception as ex:
            demisto.error(f'failed stoping test nginx process: {ex}')


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


def get_params_port(params: Dict = None) -> int:
    """
    Gets port from the integration parameters
    """
    params = demisto.params() if not params else params
    port_mapping: str = params.get('longRunningPort', '')
    err_msg: str
    port: int
    if port_mapping:
        err_msg = f'Listen Port must be an integer. {port_mapping} is not valid.'
        if ':' in port_mapping:
            port = try_parse_integer(port_mapping.split(':')[1], err_msg)
        else:
            port = try_parse_integer(port_mapping, err_msg)
    else:
        raise ValueError('Please provide a Listen Port.')
    return port


def run_long_running(params: Dict = None, is_test: bool = False):
    """
    Start the long running server
    :param params: Demisto params
    :param is_test: Indicates whether it's test-module run or regular run
    :return: None
    """
    params = demisto.params() if not params else params
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
        log_handler.setFormatter(
            logging.Formatter("flask log: [%(asctime)s] %(levelname)s in %(module)s: %(message)s")
        )
        APP.logger.addHandler(log_handler)  # type: ignore[name-defined] # pylint: disable=E0602
        demisto.debug('done setting demisto handler for logging')
        server = WSGIServer(('0.0.0.0', server_port),
                            APP, log=DEMISTO_LOGGER,  # type: ignore[name-defined] # pylint: disable=E0602
                            error_log=ERROR_LOGGER)
        if is_test:
            test_nginx_server(nginx_port, params)
            server_process = Process(target=server.serve_forever)
            server_process.start()
            time.sleep(5)
            try:
                server_process.terminate()
                server_process.join(1.0)
            except Exception as ex:
                demisto.error(f'failed stoping test wsgi server process: {ex}')

        else:
            nginx_process = start_nginx_server(nginx_port, params)
            nginx_log_monitor = gevent.spawn(nginx_log_monitor_loop, nginx_process)
            demisto.updateModuleHealth('')
            server.serve_forever()
    except Exception as e:
        error_message = str(e)
        demisto.error(f'An error occurred: {error_message}. Exception: {traceback.format_exc()}')
        demisto.updateModuleHealth(f'An error occurred: {error_message}')
        raise ValueError(error_message)

    finally:
        if nginx_process:
            try:
                nginx_process.terminate()
            except Exception as ex:
                demisto.error(f'Failed stopping nginx process when exiting: {ex}')
        if nginx_log_monitor:
            try:
                nginx_log_monitor.kill(timeout=1.0)
            except Exception as ex:
                demisto.error(f'Failed stopping nginx_log_monitor when exiting: {ex}')
