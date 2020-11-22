import ast
import logging
from pprint import pformat

import demisto_client


def update_server_configuration(client, server_configuration, error_msg):
    """updates server configuration

    Args:
        client (demisto_client): The configured client to use.
        server_configuration (dict): The server configuration to be added
        error_msg (str): The error message

    Returns:
        response_data: The response data
        status_code: The response status code
    """
    logging.debug(f'Updating server configurations with {pformat(server_configuration)}')
    system_conf_response = demisto_client.generic_request_func(
        self=client,
        path='/system/config',
        method='GET'
    )
    system_conf = ast.literal_eval(system_conf_response[0]).get('sysConf', {})
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
        logging.debug(f'Updated server configurations with response: {pformat(result_object)}')
    except ValueError as err:
        logging.exception('failed to parse response from demisto. response is {}.\nError:\n{}'.format(response_data, err))
        return

    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        logging.error(f'{error_msg} {status_code}\n{message}')
    return response_data, status_code
