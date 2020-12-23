import ast
import logging
from pprint import pformat
from functools import wraps
from typing import Callable

import demisto_client


def update_server_configuration(client, server_configuration, error_msg, logging_manager=None):
    """updates server configuration

    Args:
        client (demisto_client): The configured client to use.
        server_configuration (dict): The server configuration to be added
        error_msg (str): The error message
        logging_manager: Logging manager object

    Returns:
        response_data: The response data
        status_code: The response status code
    """
    if logging_manager:
        logging_manager.debug(f'Updating server configurations with {pformat(server_configuration)}')
    else:
        logging.debug(f'Updating server configurations with {pformat(server_configuration)}')
    system_conf_response = demisto_client.generic_request_func(
        self=client,
        path='/system/config',
        method='GET'
    )
    system_conf = ast.literal_eval(system_conf_response[0]).get('sysConf', {})
    if logging_manager:
        logging_manager.debug(f'Current server configurations are {pformat(system_conf)}')
    else:
        logging.debug(f'Current server configurations are {pformat(system_conf)}')
    system_conf.update(server_configuration)
    data = {
        'data': system_conf,
        'version': -1
    }
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path='/system/config',
                                                                        method='POST', body=data)

    try:
        result_object = ast.literal_eval(response_data)
        if logging_manager:
            logging_manager.debug(f'Updated server configurations with response: {pformat(result_object)}')
        else:
            logging.debug(f'Updated server configurations with response: {pformat(result_object)}')
    except ValueError as err:
        if logging_manager:
            logging_manager.exception(
                f'failed to parse response from demisto. response is {response_data}.\nError:\n{err}')
        else:
            logging.exception(f'failed to parse response from demisto. response is {response_data}.\nError:\n{err}')
        return

    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        if logging_manager:
            logging_manager.error(f'{error_msg} {status_code}\n{message}')
        else:
            logging.error(f'{error_msg} {status_code}\n{message}')
    return response_data, status_code


def run_with_proxy_configured(function: Callable) -> Callable:
    """
    This is a decorator for the 'instance_testing method`.
    This decorator configures the proxy in the server before the instance_testing execution and removes it afterwards.
    Args:
        function: Should be the instance_testing method.
    """
    @wraps(function)
    def decorated(build, *args, **kwargs):
        build.proxy.configure_proxy_in_demisto(proxy=build.proxy.ami.docker_ip + ':' + build.proxy.PROXY_PORT,
                                               username=build.username, password=build.password,
                                               server=build.servers[0].host)
        result = function(build, *args, **kwargs)
        build.proxy.configure_proxy_in_demisto(proxy='',
                                               username=build.username, password=build.password,
                                               server=build.servers[0].host)
        return result
    return decorated
