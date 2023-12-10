from functools import wraps
from collections.abc import Callable

import requests
from demisto_sdk.commands.test_content.mock_server import MITMProxy
from demisto_sdk.commands.common.files.json_file import JsonFile


def run_with_proxy_configured(function: Callable) -> Callable:
    """
    This is a decorator for the 'instance_testing method`.
    This decorator configures the proxy in the server before the instance_testing execution and removes it afterwards.
    Args:
        function: Should be the instance_testing method.
    """

    @wraps(function)
    def decorated(build, *args, **kwargs):
        build.proxy.configure_proxy_in_demisto(proxy=build.servers[0].internal_ip + ':' + MITMProxy.PROXY_PORT,
                                               username=build.username, password=build.password,
                                               server=f'https://{build.servers[0].internal_ip}')
        result = function(build, *args, **kwargs)
        build.proxy.configure_proxy_in_demisto(proxy='',
                                               username=build.username, password=build.password,
                                               server=f'https://{build.servers[0].internal_ip}')
        return result

    return decorated


def get_integration_params(integration_secrets_path: str, instance_name: str) -> dict:
    """
    Returns the integration parameters by instance name or name.

    Args:
         integration_secrets_path (str): path to integration parameters
         instance_name (str): the name of the instance to retrieve

    Returns:
        dict: the params of the requested instance name
    """
    integrations_instance_data = JsonFile.read_from_local_path(integration_secrets_path).get("integrations") or []

    for integration_instance in integrations_instance_data:
        if integration_instance.get("instance_name") == instance_name or integration_instance.get("name") == instance_name:
            return integration_instance.get("params")

    raise ValueError(f'Could not find integration parameters for {instance_name}')


def get_json_response(_response: requests.Response) -> dict:
    try:
        return _response.json()
    except ValueError as e:
        raise ValueError(f'Could not parse {_response.text}, error: {e}')
